//! Management-RPC-driven federation setup mode.
//!
//! A fresh member started with `[federation.setup] enabled = true` serves only the
//! gRPC setup service plus the setup coordinator and DKG routes. After the operator
//! activates the finished setup, the final federation config is written to the
//! stored configuration and the daemon continues as a normal federation member in
//! the same process.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Router;
use cdk_common::database::DynMintDatabase;
use cdk_common::federation::{
    is_iroh_setup_url, FederationDkgCeremonyRecord, FederationSetupActivation,
    FederationSetupBitcoinNetwork, FederationSetupId, FederationSetupInvitation,
    FederationSetupLocalRole, FederationSetupParticipantPhase, FederationSetupProposalHash,
    FederationSetupProposalReview, MemberId,
};
use cdk_common::mint_url::MintUrl;
use cdk_mint_rpc::federation_setup as proto;
use cdk_mint_rpc::{
    DynFederationSetupProvider, FederationSetupProvider, FederationSetupRPCServer, ProviderError,
};
use tokio::sync::{Mutex, Notify};
use tower::ServiceExt;

use crate::config_service::ConfigurationService;
use crate::federation_dkg_status::FederationSetupDkgProgress;
use crate::federation_setup_command::{
    abort_setup, activate_setup_with_db, approve_setup, build_certified_dkg_router,
    build_setup_coordinator_router, create_setup, current_unix_time, fetch_and_review_proposal,
    join_setup, parse_mint_url, propose_setup, read_local_config, refresh_certified_manifest,
    replace_invitation, review_local_proposal, serve_setup_router, setup_status_with_db,
    setup_url_policy, FederationSetupActivationResult, FederationSetupCommandStatus,
    FederationSetupCreateParams, FederationSetupLocalConfig, HttpSetupCoordinator, SetupServeEnd,
};
use crate::{config, BdkWalletPolicy};

const SETUP_DIRECTORY: &str = "federation-setup";
const SETUP_CONFIG_FILE: &str = "setup.json";
const SETUP_STATE_DIRECTORY: &str = "state";
const ABORTED_DIRECTORY: &str = "aborted";
const SQLITE_DATABASE_FILE: &str = "cdk-mintd.sqlite";
const WATCH_INTERVAL: Duration = Duration::from_secs(2);
const WATCHER_STOP_TIMEOUT: Duration = Duration::from_secs(10);
const BACKUP_WARNING: &str = "Before using real funds, create and verify an encrypted backup of this member's setup state, database, and activated private config.";

/// How federation setup mode ended.
pub(crate) enum SetupModeExit {
    /// The operator stopped the daemon.
    Shutdown,
    /// The setup was activated; continue as a federation member.
    Activated {
        /// Iroh endpoint to reuse instead of binding the same identity again.
        iroh: crate::IrohHandover,
    },
}

/// Run setup mode until the daemon is stopped or the finished setup is activated.
pub(crate) async fn run_federation_setup_mode<S>(
    work_dir: &Path,
    settings: &config::Settings,
    database: DynMintDatabase,
    config_service: ConfigurationService,
    bdk_wallet_policy: BdkWalletPolicy,
    shutdown_signal: S,
) -> Result<SetupModeExit>
where
    S: Future<Output = ()> + Send,
{
    let federation = settings
        .federation
        .as_ref()
        .ok_or_else(|| anyhow!("federation setup mode requires [federation] settings"))?;
    let driver = crate::federation_dkg_driver_config(&federation.dkg)?;
    let endpoint = crate::management_rpc_endpoint(settings, work_dir)?
        .ok_or_else(|| anyhow!("federation setup mode requires the management RPC"))?;
    let setup_dir = work_dir.join(SETUP_DIRECTORY);
    create_private_dir(&setup_dir)?;

    #[cfg(feature = "iroh")]
    let transport = match crate::iroh_runtime::initialize(settings, work_dir).await? {
        Some(runtime) => cdk_axum::federation_transport_with_iroh_node(runtime.node),
        None => cdk_axum::default_federation_transport(),
    };
    #[cfg(not(feature = "iroh"))]
    let transport = {
        if !settings.info.http_enabled || settings.info.url.starts_with("iroh:") {
            bail!("Iroh listener configuration requires the iroh feature");
        }
        cdk_axum::default_federation_transport()
    };

    let mode = Arc::new(SetupMode {
        work_dir: work_dir.to_path_buf(),
        default_url: settings.info.url.clone(),
        database,
        config_path: setup_dir.join(SETUP_CONFIG_FILE),
        state_dir: setup_dir.join(SETUP_STATE_DIRECTORY),
        database_path: work_dir.join(SQLITE_DATABASE_FILE),
        coordinator_client: HttpSetupCoordinator::new(transport.clone()),
        transport,
        driver,
        routes: SetupRoutes::default(),
        workers: Mutex::new(SetupWorkers::default()),
        config_service,
        bdk_wallet_policy,
        activated: Notify::new(),
    });

    let listener = match settings.info.http_enabled {
        true => {
            let address = format!(
                "{}:{}",
                settings.info.listen_host, settings.info.listen_port
            );
            Some(
                tokio::net::TcpListener::bind(&address)
                    .await
                    .with_context(|| format!("failed to bind the setup listener on {address}"))?,
            )
        }
        false => None,
    };

    let provider: DynFederationSetupProvider = Arc::new(SetupModeProvider { mode: mode.clone() });
    let mut rpc = FederationSetupRPCServer::new(&endpoint.address, endpoint.port, provider)?;
    rpc.start(endpoint.tls_dir.clone())
        .await
        .context("failed to start the federation setup RPC server")?;
    tracing::info!(
        rpc = %rpc.local_addr(),
        "Federation setup mode ready; waiting for setup over the management RPC"
    );

    let watcher_stop = Arc::new(Notify::new());
    let watcher = tokio::spawn(mode.clone().watch(watcher_stop.clone()));

    // Activation keeps the Iroh endpoint bound so normal startup can reuse it.
    let served = serve_setup_router(
        listener,
        mode.routes.router(),
        mode.transport.clone(),
        "federation setup listener",
        async {
            tokio::select! {
                () = shutdown_signal => Ok(SetupServeEnd::Close),
                () = mode.activated.notified() => Ok(SetupServeEnd::KeepIrohEndpoint),
            }
        },
    )
    .await;

    if let Err(error) = rpc.stop().await {
        tracing::warn!(%error, "Federation setup RPC server did not stop cleanly");
    }
    watcher_stop.notify_one();
    if tokio::time::timeout(WATCHER_STOP_TIMEOUT, watcher)
        .await
        .is_err()
    {
        tracing::warn!("Federation setup watcher did not stop in time");
    }
    mode.stop_workers().await;

    Ok(match served? {
        (SetupServeEnd::Close, _) => SetupModeExit::Shutdown,
        (SetupServeEnd::KeepIrohEndpoint, iroh) => SetupModeExit::Activated { iroh },
    })
}

fn create_private_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("failed to restrict {}", path.display()))?;
    }
    Ok(())
}

/// Setup routes that change while setup mode runs, behind one stable listener.
#[derive(Clone, Default)]
struct SetupRoutes {
    coordinator: Arc<RwLock<Option<Router>>>,
    dkg: Arc<RwLock<Option<Router>>>,
}

impl SetupRoutes {
    /// A router that forwards each request to whichever setup routes are mounted.
    fn router(&self) -> Router {
        let routes = self.clone();
        Router::new().fallback(move |request: Request| {
            let routes = routes.clone();
            async move { routes.dispatch(request).await }
        })
    }

    async fn dispatch(&self, request: Request) -> Response {
        let slot = match request.uri().path().starts_with("/federation/setup/") {
            true => &self.coordinator,
            false => &self.dkg,
        };
        let router = match slot.read() {
            Ok(router) => router.clone(),
            Err(_) => None,
        };
        match router {
            Some(router) => match router.oneshot(request).await {
                Ok(response) => response,
                Err(never) => match never {},
            },
            None => StatusCode::SERVICE_UNAVAILABLE.into_response(),
        }
    }

    fn set_coordinator(&self, router: Option<Router>) {
        if let Ok(mut slot) = self.coordinator.write() {
            *slot = router;
        }
    }

    fn set_dkg(&self, router: Option<Router>) {
        if let Ok(mut slot) = self.dkg.write() {
            *slot = router;
        }
    }
}

/// Background work owned by setup mode, guarded by one lock so setup operations
/// and the watcher never race on the setup lifecycle.
#[derive(Default)]
struct SetupWorkers {
    coordinator: Option<Arc<cdk_axum::FederationSetupCoordinatorService>>,
    dkg: Option<RunningSetupDkg>,
}

struct RunningSetupDkg {
    services: Option<cdk_axum::RunningFederationServices>,
}

impl RunningSetupDkg {
    fn stopped(&self) -> bool {
        self.services
            .as_ref()
            .is_some_and(cdk_axum::RunningFederationServices::is_stopped)
    }

    async fn shutdown(self) {
        if let Some(services) = self.services {
            if let Err(error) = services.shutdown().await {
                tracing::warn!(%error, "Setup DKG services did not stop cleanly");
            }
        }
    }
}

struct SetupMode {
    work_dir: PathBuf,
    default_url: String,
    database: DynMintDatabase,
    config_path: PathBuf,
    state_dir: PathBuf,
    database_path: PathBuf,
    transport: cdk_axum::FederationTransport,
    coordinator_client: HttpSetupCoordinator,
    driver: cdk_axum::FederationDkgDriverRunConfig,
    routes: SetupRoutes,
    workers: Mutex<SetupWorkers>,
    config_service: ConfigurationService,
    bdk_wallet_policy: BdkWalletPolicy,
    activated: Notify,
}

impl SetupMode {
    fn local_config(&self) -> Result<Option<FederationSetupLocalConfig>> {
        match self.config_path.exists() {
            true => read_local_config(&self.config_path).map(Some),
            false => Ok(None),
        }
    }

    fn require_local_config(&self) -> Result<FederationSetupLocalConfig> {
        self.local_config()?
            .ok_or_else(|| anyhow!("no federation setup exists yet; create or join one first"))
    }

    async fn participant_phase(
        &self,
        config: &FederationSetupLocalConfig,
    ) -> Result<Option<FederationSetupParticipantPhase>> {
        Ok(self
            .database
            .get_federation_setup_session(config.setup_id())
            .await
            .context("failed to read the local setup lifecycle")?
            .map(|session| session.participant_phase))
    }

    async fn dkg_ceremony_complete(&self) -> Result<bool> {
        let ceremonies = self
            .database
            .get_federation_dkg_ceremonies()
            .await
            .context("failed to read the DKG ceremony lifecycle")?;
        Ok(FederationDkgCeremonyRecord::current_is_complete(
            &ceremonies,
        ))
    }

    /// Mount the creator's coordinator routes once.
    fn ensure_coordinator(&self, workers: &mut SetupWorkers) -> Result<()> {
        if workers.coordinator.is_some() {
            return Ok(());
        }
        let built = build_setup_coordinator_router(self.database.clone(), &self.config_path)?;
        self.routes.set_coordinator(Some(built.router));
        workers.coordinator = Some(built.service);
        tracing::info!("Federation setup coordinator routes mounted");
        Ok(())
    }

    /// Mount the certified DKG routes, restarting their services if they stopped
    /// before the ceremony completed.
    async fn ensure_dkg(&self, workers: &mut SetupWorkers) -> Result<()> {
        if let Some(dkg) = workers.dkg.as_ref() {
            if !dkg.stopped() || self.dkg_ceremony_complete().await? {
                return Ok(());
            }
            tracing::warn!("Setup DKG services stopped before the ceremony completed; restarting");
            if let Some(dkg) = workers.dkg.take() {
                dkg.shutdown().await;
            }
            self.routes.set_dkg(None);
        }
        let built = build_certified_dkg_router(
            self.database.clone(),
            &self.config_path,
            self.driver,
            self.transport.clone(),
        )
        .await?;
        self.routes.set_dkg(Some(built.router));
        workers.dkg = Some(RunningSetupDkg {
            services: built.services,
        });
        tracing::info!(
            setup_id = %built.setup_id,
            member_id = %built.member_id,
            ceremony_id = %built.ceremony_id,
            "Federation setup DKG routes mounted"
        );
        Ok(())
    }

    /// One watcher pass: mount routes for the current phase and fetch the
    /// certified manifest once every member has approved.
    async fn advance(&self) -> Result<()> {
        let mut workers = self.workers.lock().await;
        let Some(config) = self.local_config()? else {
            return Ok(());
        };
        if matches!(
            config.local_role(),
            FederationSetupLocalRole::Coordinator { .. }
        ) {
            self.ensure_coordinator(&mut workers)?;
        }
        let Some(phase) = self.participant_phase(&config).await? else {
            return Ok(());
        };
        if phase == FederationSetupParticipantPhase::Aborted {
            return Ok(());
        }
        if phase == FederationSetupParticipantPhase::Approved && !config.manifest_path().exists() {
            if let Err(error) = refresh_certified_manifest(
                &self.database,
                &self.config_path,
                &self.coordinator_client.0,
            )
            .await
            {
                tracing::debug!(error = %format!("{error:#}"), "Certified setup manifest not available yet");
            }
        }
        if config.manifest_path().exists() {
            self.ensure_dkg(&mut workers).await?;
        }
        Ok(())
    }

    async fn watch(self: Arc<Self>, stop: Arc<Notify>) {
        loop {
            if let Err(error) = self.advance().await {
                tracing::warn!(error = %format!("{error:#}"), "Federation setup watcher step failed");
            }
            tokio::select! {
                () = stop.notified() => break,
                () = tokio::time::sleep(WATCH_INTERVAL) => {}
            }
        }
    }

    async fn stop_workers(&self) {
        let mut workers = self.workers.lock().await;
        self.clear_workers(&mut workers).await;
    }

    async fn clear_workers(&self, workers: &mut SetupWorkers) {
        if let Some(dkg) = workers.dkg.take() {
            dkg.shutdown().await;
        }
        if let Some(coordinator) = workers.coordinator.take() {
            coordinator.shutdown().await;
        }
        self.routes.set_dkg(None);
        self.routes.set_coordinator(None);
    }

    /// Move an aborted setup's files aside so a new setup can start.
    ///
    /// The state directory moves first: a config without its state only fails to
    /// load, but state left without its config would be reused by the next setup.
    fn archive_setup(&self, setup_id: FederationSetupId) -> Result<()> {
        let archive = self
            .work_dir
            .join(SETUP_DIRECTORY)
            .join(ABORTED_DIRECTORY)
            .join(setup_id.to_string());
        create_private_dir(&archive)?;
        for (source, name) in [
            (&self.state_dir, SETUP_STATE_DIRECTORY),
            (&self.config_path, SETUP_CONFIG_FILE),
        ] {
            if source.exists() {
                std::fs::rename(source, archive.join(name))
                    .with_context(|| format!("failed to move {} aside", source.display()))?;
            }
        }
        Ok(())
    }

    fn url_or_default(&self, value: Option<&str>, fallback: &str, label: &str) -> Result<MintUrl> {
        parse_mint_url(
            value.filter(|value| !value.is_empty()).unwrap_or(fallback),
            label,
        )
    }

    /// The federation API URL must differ from the public mint URL unless both
    /// name the same Iroh endpoint, so it only defaults for Iroh members.
    fn federation_api_url(
        &self,
        value: Option<&str>,
        public_mint_url: &MintUrl,
    ) -> Result<MintUrl> {
        match value.filter(|value| !value.is_empty()) {
            Some(value) => parse_mint_url(value, "federation API URL"),
            None if is_iroh_setup_url(public_mint_url) => Ok(public_mint_url.clone()),
            None => bail!(
                "federation_api_url is required: it must differ from the public mint URL unless both are the same Iroh endpoint"
            ),
        }
    }

    fn create_params(
        &self,
        request: &proto::CreateSetupRequest,
    ) -> Result<FederationSetupCreateParams> {
        let members = u16::try_from(request.members).context("members is out of range")?;
        let threshold = u16::try_from(request.threshold).context("threshold is out of range")?;
        let network = parse_network(&request.network)?;
        let public_mint_url = self.url_or_default(
            request.public_mint_url.as_deref(),
            &self.default_url,
            "public mint URL",
        )?;
        let federation_api_url =
            self.federation_api_url(request.federation_api_url.as_deref(), &public_mint_url)?;
        let coordinator_url = self.url_or_default(
            request.coordinator_url.as_deref(),
            &federation_api_url.to_string(),
            "coordinator URL",
        )?;
        let mut params = FederationSetupCreateParams::with_defaults(
            members,
            threshold,
            network,
            public_mint_url,
            federation_api_url,
            coordinator_url,
        );
        params.payment_observation_threshold = request
            .payment_observation_threshold
            .map(u16::try_from)
            .transpose()
            .context("payment observation threshold is out of range")?;
        if let Some(lifetime) = request.invitation_lifetime_secs {
            params.invitation_lifetime_secs = lifetime;
        }
        if let Some(keyset) = request.keyset.as_ref() {
            if !keyset.unit.is_empty() {
                params.unit = keyset.unit.clone();
            }
            if !keyset.amounts.is_empty() {
                params.amounts = keyset.amounts.clone();
            }
            params.input_fee_ppk = keyset.input_fee_ppk;
            params.final_expiry = keyset.final_expiry;
        }
        params.allow_insecure_localhost = request.allow_insecure_localhost;
        Ok(params)
    }

    /// Point the stored configuration at the activated federation config pair.
    async fn store_member_config(&self, result: &FederationSetupActivationResult) -> Result<()> {
        let document = self
            .config_service
            .document()
            .await
            .context("failed to read the stored configuration")?;
        let mut settings = config::Settings::try_from_toml(&document)
            .context("failed to parse the stored configuration")?;
        let federation = settings
            .federation
            .get_or_insert_with(config::Federation::default);
        federation.enabled = true;
        federation.public_config_path = Some(result.public_config_path.clone());
        federation.private_config_path = Some(result.private_config_path.clone());
        federation.setup.enabled = false;
        crate::configured_federation_runtime(&settings)
            .context("the activated federation config does not load")?;
        let document = toml::to_string_pretty(&settings)
            .context("failed to serialize the activated configuration")?;
        self.config_service
            .apply(&document, false, &self.work_dir, self.bdk_wallet_policy)
            .await
            .context("failed to store the activated configuration")?;
        Ok(())
    }
}

struct SetupModeProvider {
    mode: Arc<SetupMode>,
}

#[async_trait]
impl FederationSetupProvider for SetupModeProvider {
    async fn create_setup(
        &self,
        request: proto::CreateSetupRequest,
    ) -> Result<proto::CreateSetupResponse, ProviderError> {
        let mode = &self.mode;
        let mut workers = mode.workers.lock().await;
        let spec = mode
            .create_params(&request)
            .and_then(|params| params.to_spec())
            .map_err(invalid_argument)?;
        let created = create_setup(
            mode.database.as_ref(),
            &mode.config_path,
            &mode.state_dir,
            &mode.database_path,
            &spec,
            current_unix_time().map_err(internal)?,
        )
        .await
        .map_err(failed_precondition)?;
        mode.ensure_coordinator(&mut workers).map_err(internal)?;
        Ok(proto::CreateSetupResponse {
            setup_id: created.setup_id.to_string(),
            member_id: 1,
            invitations: created.invitations.values().map(setup_invitation).collect(),
        })
    }

    async fn replace_invitation(
        &self,
        request: proto::ReplaceInvitationRequest,
    ) -> Result<proto::ReplaceInvitationResponse, ProviderError> {
        let mode = &self.mode;
        let _workers = mode.workers.lock().await;
        let member_id = u16::try_from(request.member_id)
            .ok()
            .and_then(|member| MemberId::new(member).ok())
            .ok_or_else(|| ProviderError::invalid_argument("member_id is not a member slot"))?;
        mode.require_local_config().map_err(failed_precondition)?;
        let invitation = replace_invitation(
            mode.database.as_ref(),
            &mode.config_path,
            &mode.state_dir,
            member_id,
            current_unix_time().map_err(internal)?,
        )
        .await
        .map_err(failed_precondition)?;
        Ok(proto::ReplaceInvitationResponse {
            invitation: Some(setup_invitation(&invitation)),
        })
    }

    async fn join_setup(
        &self,
        request: proto::JoinSetupRequest,
    ) -> Result<proto::JoinSetupResponse, ProviderError> {
        let mode = &self.mode;
        let _workers = mode.workers.lock().await;
        let invitation = FederationSetupInvitation::from_str(request.invitation.trim())
            .context("invalid federation setup invitation")
            .map_err(invalid_argument)?;
        let public_mint_url = mode
            .url_or_default(
                request.public_mint_url.as_deref(),
                &mode.default_url,
                "public mint URL",
            )
            .map_err(invalid_argument)?;
        let federation_api_url = mode
            .federation_api_url(request.federation_api_url.as_deref(), &public_mint_url)
            .map_err(invalid_argument)?;
        let enrollment = join_setup(
            mode.database.as_ref(),
            &mode.coordinator_client,
            &mode.config_path,
            &mode.state_dir,
            &mode.database_path,
            invitation,
            public_mint_url,
            federation_api_url,
            setup_url_policy(request.allow_insecure_localhost),
            current_unix_time().map_err(internal)?,
        )
        .await
        .map_err(failed_precondition)?;
        Ok(proto::JoinSetupResponse {
            setup_id: enrollment.setup_id.to_string(),
            member_id: u32::from(enrollment.member_id.get()),
        })
    }

    async fn propose_setup(
        &self,
        _request: proto::ProposeSetupRequest,
    ) -> Result<proto::ProposeSetupResponse, ProviderError> {
        let mode = &self.mode;
        let _workers = mode.workers.lock().await;
        let proposal = propose_setup(
            mode.database.as_ref(),
            &mode.config_path,
            current_unix_time().map_err(internal)?,
        )
        .await
        .map_err(failed_precondition)?;
        Ok(proto::ProposeSetupResponse {
            proposal_hash: proposal.proposal_hash.to_string(),
        })
    }

    async fn review_proposal(
        &self,
        _request: proto::ReviewProposalRequest,
    ) -> Result<proto::ReviewProposalResponse, ProviderError> {
        let mode = &self.mode;
        let _workers = mode.workers.lock().await;
        let config = mode.require_local_config().map_err(failed_precondition)?;
        let now_unix = current_unix_time().map_err(internal)?;
        let review = match config.local_role() {
            FederationSetupLocalRole::Coordinator { .. } => {
                let proposal = mode
                    .database
                    .get_federation_setup_proposal(config.setup_id())
                    .await
                    .context("failed to load the local setup proposal")
                    .map_err(internal)?
                    .ok_or_else(|| {
                        ProviderError::failed_precondition(
                            "no setup proposal exists yet; propose the setup first",
                        )
                    })?;
                review_local_proposal(
                    mode.database.as_ref(),
                    &mode.config_path,
                    proposal,
                    now_unix,
                )
                .await
            }
            FederationSetupLocalRole::Member { .. } => {
                fetch_and_review_proposal(
                    mode.database.as_ref(),
                    &mode.coordinator_client,
                    &mode.config_path,
                    now_unix,
                )
                .await
            }
        }
        .map_err(failed_precondition)?;
        review_response(&review).map_err(internal)
    }

    async fn approve_proposal(
        &self,
        request: proto::ApproveProposalRequest,
    ) -> Result<proto::ApproveProposalResponse, ProviderError> {
        let mode = &self.mode;
        let mut workers = mode.workers.lock().await;
        let hash = FederationSetupProposalHash::from_str(request.proposal_hash.trim())
            .context("invalid proposal hash")
            .map_err(invalid_argument)?;
        let config = mode.require_local_config().map_err(failed_precondition)?;
        // The creator records its approval through the mounted coordinator, so
        // it is serialized with members' approvals and certifies if it is last.
        if matches!(
            config.local_role(),
            FederationSetupLocalRole::Coordinator { .. }
        ) {
            mode.ensure_coordinator(&mut workers).map_err(internal)?;
        }
        let approval = approve_setup(
            mode.database.as_ref(),
            &mode.coordinator_client,
            workers.coordinator.as_deref(),
            &mode.config_path,
            hash,
            current_unix_time().map_err(internal)?,
        )
        .await
        .map_err(failed_precondition)?;
        Ok(proto::ApproveProposalResponse {
            proposal_hash: approval.proposal_hash.to_string(),
        })
    }

    async fn get_setup_status(
        &self,
        _request: proto::GetSetupStatusRequest,
    ) -> Result<proto::GetSetupStatusResponse, ProviderError> {
        let mode = &self.mode;
        let _workers = mode.workers.lock().await;
        let Some(config) = mode.local_config().map_err(internal)? else {
            return Ok(proto::GetSetupStatusResponse {
                initialized: false,
                ..Default::default()
            });
        };
        let status = setup_status_with_db(
            mode.database.clone(),
            &mode.config_path,
            &mode.coordinator_client.0,
        )
        .await
        .map_err(failed_precondition)?;
        Ok(status_response(&config, status))
    }

    async fn abort_setup(
        &self,
        request: proto::AbortSetupRequest,
    ) -> Result<proto::AbortSetupResponse, ProviderError> {
        let mode = &self.mode;
        let mut workers = mode.workers.lock().await;
        let setup_id = FederationSetupId::from_str(request.setup_id.trim())
            .context("invalid setup ID")
            .map_err(invalid_argument)?;
        mode.require_local_config().map_err(failed_precondition)?;
        abort_setup(
            mode.database.as_ref(),
            &mode.config_path,
            setup_id,
            current_unix_time().map_err(internal)?,
        )
        .await
        .map_err(failed_precondition)?;
        mode.clear_workers(&mut workers).await;
        mode.archive_setup(setup_id).map_err(internal)?;
        tracing::info!(%setup_id, "Federation setup aborted");
        Ok(proto::AbortSetupResponse {
            setup_id: setup_id.to_string(),
        })
    }

    async fn activate_setup(
        &self,
        _request: proto::ActivateSetupRequest,
    ) -> Result<proto::ActivateSetupResponse, ProviderError> {
        let mode = &self.mode;
        let _workers = mode.workers.lock().await;
        let result = activate_setup_with_db(
            mode.database.clone(),
            &mode.config_path,
            current_unix_time().map_err(internal)?,
        )
        .await
        .map_err(failed_precondition)?;
        mode.store_member_config(&result).await.map_err(internal)?;
        // Setup mode then stops the RPC server, which drains this response first.
        mode.activated.notify_one();
        tracing::info!(
            setup_id = %result.setup_id,
            member_id = %result.member_id,
            federation_id = %result.federation_id,
            "Federation setup activated"
        );
        Ok(proto::ActivateSetupResponse {
            setup_id: result.setup_id.to_string(),
            member_id: u32::from(result.member_id.get()),
            federation_id: result.federation_id.to_string(),
            final_config_digest: result.final_config_digest.to_string(),
            backup_warning: BACKUP_WARNING.to_string(),
            restart_pending: true,
        })
    }
}

fn invalid_argument(error: anyhow::Error) -> ProviderError {
    ProviderError::invalid_argument(format!("{error:#}"))
}

fn failed_precondition(error: anyhow::Error) -> ProviderError {
    ProviderError::failed_precondition(format!("{error:#}"))
}

fn internal(error: anyhow::Error) -> ProviderError {
    ProviderError::internal(format!("{error:#}"))
}

/// Parse a network name, accepting `mainnet` for `bitcoin` and any letter case.
fn parse_network(value: &str) -> Result<FederationSetupBitcoinNetwork> {
    match value.trim().to_ascii_lowercase().as_str() {
        "mainnet" => Ok(FederationSetupBitcoinNetwork::Bitcoin),
        name => Ok(FederationSetupBitcoinNetwork::from_str(name)?),
    }
}

fn setup_invitation(invitation: &FederationSetupInvitation) -> proto::SetupInvitation {
    proto::SetupInvitation {
        member_id: u32::from(invitation.member_id.get()),
        invitation: invitation.to_string(),
        expires_at_unix: invitation.expires_at_unix,
    }
}

fn review_response(
    review: &FederationSetupProposalReview,
) -> Result<proto::ReviewProposalResponse> {
    Ok(proto::ReviewProposalResponse {
        setup_id: review.setup_id.to_string(),
        proposed_federation_id: review.proposed_federation_id.to_string(),
        proposal_hash: review.proposal_hash.to_string(),
        network: review.network.to_string(),
        member_count: u32::from(review.threshold_params.member_count),
        signature_threshold: u32::from(review.threshold_params.signature_threshold),
        consensus_threshold: u32::from(review.threshold_params.consensus_threshold),
        members: review
            .members
            .iter()
            .map(|member| proto::ReviewMember {
                member_id: u32::from(member.member_id.get()),
                public_mint_url: member.public_mint_url.clone(),
                federation_api_url: member.federation_api_url.clone(),
                identity_fingerprint: member.identity_fingerprint.clone(),
            })
            .collect(),
        keysets: review
            .keysets
            .iter()
            .map(|keyset| proto::SetupKeyset {
                unit: keyset.unit.to_string(),
                amounts: keyset
                    .amounts
                    .iter()
                    .map(|amount| u64::from(*amount))
                    .collect(),
                input_fee_ppk: keyset.input_fee_ppk,
                final_expiry: keyset.final_expiry,
            })
            .collect(),
        details_json: review.to_pretty_json()?,
    })
}

fn status_response(
    config: &FederationSetupLocalConfig,
    status: FederationSetupCommandStatus,
) -> proto::GetSetupStatusResponse {
    let role = match config.local_role() {
        FederationSetupLocalRole::Coordinator { .. } => "coordinator",
        FederationSetupLocalRole::Member { .. } => "member",
    };
    let member_ids = |members: &[cdk_common::federation::MemberId]| {
        members
            .iter()
            .map(|member| u32::from(member.get()))
            .collect::<Vec<_>>()
    };
    proto::GetSetupStatusResponse {
        initialized: true,
        setup_id: Some(status.setup_id.to_string()),
        member_id: Some(u32::from(status.member_id.get())),
        identity_fingerprint: Some(status.identity_fingerprint),
        role: role.to_string(),
        participant_phase: status.participant_phase,
        coordinator_phase: status.coordinator_phase,
        member_count: u32::from(status.member_count),
        enrolled_members: member_ids(&status.enrolled_members),
        missing_enrollments: member_ids(&status.missing_enrollments),
        approved_members: member_ids(&status.approved_members),
        missing_approvals: member_ids(&status.missing_approvals),
        proposal_hash: status.proposal_hash,
        manifest_hash: status.manifest_hash,
        dkg: status.dkg.map(dkg_progress),
        activation: status.activation.map(activation_record),
    }
}

fn count(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn dkg_progress(progress: FederationSetupDkgProgress) -> proto::SetupDkgProgress {
    proto::SetupDkgProgress {
        phase: progress.phase,
        participant_states: count(progress.participant_states),
        commitments: count(progress.commitments),
        reveals: count(progress.reveals),
        secret_share_contributions: count(progress.secret_share_contributions),
        keyset_shares: count(progress.keyset_shares),
        transcript_signatures: count(progress.transcript_signatures),
        final_config_confirmations: count(progress.final_config_confirmations),
        frost_root_public_configs: count(progress.frost_root_public_configs),
        confirmed_members: progress
            .confirmed_members
            .iter()
            .map(|member| u32::from(member.get()))
            .collect(),
        finalized_ready: progress.finalized_ready,
        dkg_confirmation_digest: progress.dkg_confirmation_digest,
        final_config_digest: progress.final_config_digest,
        transcript_hash: progress.transcript_hash,
        error: progress.error,
    }
}

fn activation_record(activation: FederationSetupActivation) -> proto::SetupActivation {
    proto::SetupActivation {
        setup_id: activation.setup_id.to_string(),
        member_id: u32::from(activation.member_id.get()),
        manifest_hash: activation.manifest_hash.to_string(),
        federation_id: activation.federation_id.to_string(),
        final_config_digest: activation.final_config_digest.to_string(),
        activated_at_unix: activation.activated_at_unix,
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::routing::get;

    use super::*;

    fn request(path: &str) -> Request {
        let mut request = Request::builder()
            .uri(path)
            .body(Body::empty())
            .expect("valid request");
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 4242))));
        request
    }

    async fn body_text(response: Response) -> String {
        let bytes = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .expect("readable body");
        String::from_utf8(bytes.to_vec()).expect("utf-8 body")
    }

    #[tokio::test]
    async fn empty_slots_return_service_unavailable() {
        let routes = SetupRoutes::default();
        let router = routes.router();

        for path in [
            "/federation/setup/v1/status",
            "/federation/v1/dkg/commitments",
        ] {
            let response = router
                .clone()
                .oneshot(request(path))
                .await
                .expect("infallible router");
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        }
    }

    #[tokio::test]
    async fn routes_setup_and_dkg_paths_to_their_slots() {
        let routes = SetupRoutes::default();
        let router = routes.router();
        routes.set_coordinator(Some(Router::new().route(
            "/federation/setup/v1/status",
            get(|ConnectInfo(source): ConnectInfo<SocketAddr>| async move {
                format!("coordinator {source}")
            }),
        )));
        routes.set_dkg(Some(
            Router::new().route("/federation/v1/dkg/commitments", get(|| async { "dkg" })),
        ));

        let coordinator = router
            .clone()
            .oneshot(request("/federation/setup/v1/status"))
            .await
            .expect("infallible router");
        assert_eq!(coordinator.status(), StatusCode::OK);
        assert_eq!(body_text(coordinator).await, "coordinator 127.0.0.1:4242");

        let dkg = router
            .clone()
            .oneshot(request("/federation/v1/dkg/commitments"))
            .await
            .expect("infallible router");
        assert_eq!(dkg.status(), StatusCode::OK);
        assert_eq!(body_text(dkg).await, "dkg");

        routes.set_dkg(None);
        let removed = router
            .oneshot(request("/federation/v1/dkg/commitments"))
            .await
            .expect("infallible router");
        assert_eq!(removed.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn parses_networks() {
        assert_eq!(
            parse_network("regtest").expect("regtest"),
            FederationSetupBitcoinNetwork::Regtest
        );
        assert_eq!(
            parse_network(" Signet ").expect("signet"),
            FederationSetupBitcoinNetwork::Signet
        );
        assert_eq!(
            parse_network("mainnet").expect("mainnet"),
            FederationSetupBitcoinNetwork::Bitcoin
        );
        assert!(parse_network("liquid").is_err());
    }
}
