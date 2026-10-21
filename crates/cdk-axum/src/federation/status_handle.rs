//! Read-only member status for management interfaces.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use cdk::federation::{
    redact_federation_operator_message, FederationConfig, FederationError,
    FederationLocalStatusResponse, FederationRestMessageKind, MemberConfigPublic, MemberId,
};
use cdk::mint::FederationRuntimeConfig;
use cdk_http_client::Transport;
use tokio::sync::OnceCell;
use tracing::instrument;

use crate::MintState;

use super::peer_client::FederationRestPeerClient;
use super::status_routes::{
    build_custody_status, build_local_status, FederationCustodyStatus, FederationLocalStatusError,
    LocalStatusOptions, PaymentReportDetail,
};
use super::{try_acquire_private_rest_admission, FederationTransport};

/// One member's answer when members are asked for their status.
#[derive(Debug, Clone)]
pub struct FederationMemberLocalStatus {
    /// Member that was asked.
    pub member_id: MemberId,
    /// Whether this is the local member, read in process instead of over the
    /// network.
    pub local: bool,
    /// Time the request took.
    pub latency: Duration,
    /// The member's validated status, or why it could not be read, with
    /// secrets and paths removed.
    pub status: Result<FederationLocalStatusResponse, String>,
}

/// Read-only access to a federation member's status for management
/// interfaces running in the same process.
///
/// It reads the same state as the private `local-status` route and takes the
/// same admission permit, but needs no member identity key from the caller.
/// Take it from [`crate::FederationServices::status_handle`] before
/// starting the services; it works before the federation workers start.
#[derive(Clone)]
#[allow(missing_debug_implementations)]
pub struct FederationStatusHandle {
    state: MintState,
    peer_client: Arc<OnceCell<FederationRestPeerClient<FederationTransport>>>,
}

impl FederationStatusHandle {
    pub(crate) fn new(state: MintState) -> Self {
        Self {
            state,
            peer_client: Arc::new(OnceCell::new()),
        }
    }

    /// Returns the member's runtime config, or `None` when the mint is not a
    /// federation member.
    pub fn runtime_config(&self) -> Option<&FederationRuntimeConfig> {
        self.state.mint.federation_config()
    }

    /// Returns the runtime config after keyset rotations accepted by
    /// consensus, or `None` when the mint is not a federation member.
    pub async fn effective_config(&self) -> Result<Option<FederationRuntimeConfig>, cdk::Error> {
        self.state.mint.effective_federation_config().await
    }

    /// Builds this member's local status without materialized-state rows.
    ///
    /// Payment observation reports are read with fewer database queries than
    /// the private route uses; reports that reached quorum omit their quote
    /// age.
    #[instrument(skip_all)]
    pub async fn local_status(
        &self,
    ) -> Result<FederationLocalStatusResponse, FederationLocalStatusError> {
        self.runtime_config()
            .ok_or(FederationLocalStatusError::NotConfigured)?;
        let _permit =
            try_acquire_private_rest_admission(&self.state, FederationRestMessageKind::Status)?;
        build_local_status(
            &self.state,
            LocalStatusOptions {
                include_materialized_rows: false,
                payment_reports: PaymentReportDetail::UnresolvedQuoteAges,
            },
        )
        .await
    }

    /// Builds this member's custody status: on-chain wallet and application
    /// operator views.
    #[instrument(skip_all)]
    pub async fn custody_status(
        &self,
    ) -> Result<FederationCustodyStatus, FederationLocalStatusError> {
        let member_id = self
            .runtime_config()
            .ok_or(FederationLocalStatusError::NotConfigured)?
            .member_id();
        let _permit =
            try_acquire_private_rest_admission(&self.state, FederationRestMessageKind::Status)?;
        build_custody_status(&self.state, member_id).await
    }

    /// Asks members for their local status, one at a time, in member order.
    ///
    /// An empty `members` asks every member. The local member is read in
    /// process; the others are asked over the federation transport with this
    /// member's identity key. A member that cannot be reached or answers with
    /// an invalid status gets an error entry instead of failing the call.
    #[instrument(skip_all)]
    pub async fn member_local_statuses(
        &self,
        members: &[MemberId],
    ) -> Result<Vec<FederationMemberLocalStatus>, FederationLocalStatusError> {
        let client = self.peer_client().await?;
        member_local_statuses_with_client(self, client, members).await
    }

    async fn peer_client(
        &self,
    ) -> Result<&FederationRestPeerClient<FederationTransport>, FederationLocalStatusError> {
        let runtime = self
            .runtime_config()
            .ok_or(FederationLocalStatusError::NotConfigured)?;
        self.peer_client
            .get_or_try_init(|| async {
                FederationRestPeerClient::new_with_validated_config(
                    self.state.federation.transport.clone(),
                    runtime.public_config(),
                    runtime.private_config().clone(),
                    self.state.federation.peer_sync_config().unwrap_or_default(),
                )
                .map_err(FederationLocalStatusError::Internal)
            })
            .await
    }
}

/// Asks members for their local status with an explicit peer client.
pub(crate) async fn member_local_statuses_with_client<T>(
    handle: &FederationStatusHandle,
    client: &FederationRestPeerClient<T>,
    members: &[MemberId],
) -> Result<Vec<FederationMemberLocalStatus>, FederationLocalStatusError>
where
    T: Transport,
{
    let runtime = handle
        .runtime_config()
        .ok_or(FederationLocalStatusError::NotConfigured)?;
    let local_member = runtime.member_id();
    let targets = status_targets(runtime.public_config(), members)?;
    let mut statuses = Vec::with_capacity(targets.len());
    // One member at a time keeps a status request from adding load in bursts
    for member in targets {
        let started = Instant::now();
        let local = member.member_id == local_member;
        let status = match local {
            true => handle
                .local_status()
                .await
                .map_err(|error| error.public_message()),
            false => client
                .local_status(&member)
                .await
                .map_err(|error| redact_federation_operator_message(&error.to_string())),
        };
        statuses.push(FederationMemberLocalStatus {
            member_id: member.member_id,
            local,
            latency: started.elapsed(),
            status,
        });
    }

    Ok(statuses)
}

/// Resolves requested member IDs against the roster, in member order.
fn status_targets(
    public_config: &FederationConfig,
    members: &[MemberId],
) -> Result<Vec<MemberConfigPublic>, FederationLocalStatusError> {
    if members.is_empty() {
        return Ok(public_config.members.values().cloned().collect());
    }

    members
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|member_id| {
            public_config.member(member_id).cloned().ok_or_else(|| {
                FederationLocalStatusError::Mint(cdk::Error::Federation(
                    FederationError::UnknownMember { member_id },
                ))
            })
        })
        .collect()
}
