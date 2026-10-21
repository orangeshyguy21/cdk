use std::collections::BTreeMap;

use axum::extract::{Json, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use cdk::federation::{
    redact_federation_operator_message, FederationAlephBftBackupStatus, FederationCheckpointKind,
    FederationCheckpointQuorumSummary, FederationCheckpointStatus, FederationCheckpointSummary,
    FederationLocalStatusResponse, FederationOnchainWalletStatus, FederationPeerStatus,
    FederationPeerStatusRequest, FederationRestMessageKind, FederationSignedRequest,
    FederationWalletLivenessStatus, FederationWalletOperatorStatus, FederationWalletRecoveryStatus,
    MemberId, FEDERATION_REST_API_VERSION,
};
use tracing::instrument;

use crate::MintState;

use super::payment_observation::payment_observation_report_summaries_with_unresolved_ages;
use super::{
    admit_private_request, anyhow_response, cdk_error_response, federation_error_status,
    local_peer_status, local_peer_status_with_materialized_rows,
    payment_observation_report_summaries, PrivateRestAdmissionError,
};

#[instrument(skip_all)]
pub(super) async fn post_status(
    State(state): State<MintState>,
    Json(payload): Json<FederationSignedRequest<FederationPeerStatusRequest>>,
) -> Result<Json<FederationPeerStatus>, Response> {
    let verified =
        admit_private_request(&state, &payload, FederationRestMessageKind::Status).await?;
    state
        .record_federation_sequence(
            FederationRestMessageKind::Status,
            verified.sender(),
            verified.sequence(),
        )
        .await;
    let peer_status = local_peer_status(&state).await.map_err(anyhow_response)?;
    Ok(Json(peer_status))
}

#[instrument(skip_all)]
pub(super) async fn post_local_status(
    State(state): State<MintState>,
    Json(payload): Json<FederationSignedRequest<FederationPeerStatusRequest>>,
) -> Result<Json<FederationLocalStatusResponse>, Response> {
    let verified =
        admit_private_request(&state, &payload, FederationRestMessageKind::Status).await?;
    state
        .record_federation_sequence(
            FederationRestMessageKind::Status,
            verified.sender(),
            verified.sequence(),
        )
        .await;
    let options = LocalStatusOptions {
        include_materialized_rows: payload.payload.include_materialized_rows,
        payment_reports: PaymentReportDetail::Full,
    };
    let response = build_local_status(&state, options)
        .await
        .map_err(IntoResponse::into_response)?;
    Ok(Json(response))
}

/// Why a member's local status could not be built.
///
/// The private REST route answers with [`Self::http_status`]; management
/// interfaces can map the same value onto their own status codes.
#[derive(Debug, thiserror::Error)]
pub enum FederationLocalStatusError {
    /// The mint is not running as a federation member.
    #[error("mint is not configured as a federation member")]
    NotConfigured,
    /// Every private REST admission permit is in use.
    #[error("federation private REST inbound queue is full")]
    AdmissionFull,
    /// Private REST admission was closed during shutdown.
    #[error("federation private REST inbound admission is closed")]
    AdmissionClosed,
    /// Reading mint or federation state failed.
    #[error(transparent)]
    Mint(#[from] cdk::Error),
    /// Any other failure.
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl FederationLocalStatusError {
    /// HTTP status the private REST route answers with for this error.
    pub fn http_status(&self) -> StatusCode {
        match self {
            Self::NotConfigured => StatusCode::NOT_FOUND,
            Self::AdmissionFull => PrivateRestAdmissionError::Full.status(),
            Self::AdmissionClosed => PrivateRestAdmissionError::Closed.status(),
            Self::Mint(cdk::Error::Federation(error)) => federation_error_status(error),
            Self::Mint(_) | Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Message safe to show a caller: internal failures are hidden and other
    /// details have secrets and paths removed.
    pub fn public_message(&self) -> String {
        match (self.http_status(), self) {
            (StatusCode::INTERNAL_SERVER_ERROR, _) => "federation internal error".to_string(),
            (_, Self::Mint(cdk::Error::Federation(error))) => {
                redact_federation_operator_message(&error.to_string())
            }
            (_, error) => error.to_string(),
        }
    }
}

impl From<PrivateRestAdmissionError> for FederationLocalStatusError {
    fn from(error: PrivateRestAdmissionError) -> Self {
        match error {
            PrivateRestAdmissionError::Full => Self::AdmissionFull,
            PrivateRestAdmissionError::Closed => Self::AdmissionClosed,
        }
    }
}

impl IntoResponse for FederationLocalStatusError {
    fn into_response(self) -> Response {
        match self {
            Self::Mint(error) => cdk_error_response(error),
            Self::Internal(error) => anyhow_response(error),
            error => (error.http_status(), error.public_message()).into_response(),
        }
    }
}

/// How much work to spend on payment observation reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PaymentReportDetail {
    /// Read every quote's observations and age, as the private REST route does.
    Full,
    /// Read observations once and look up ages only for unresolved reports.
    UnresolvedQuoteAges,
}

/// What a local status build includes.
#[derive(Debug, Clone, Copy)]
pub(super) struct LocalStatusOptions {
    /// Compute the full materialized-state snapshot and its row fingerprints.
    pub(super) include_materialized_rows: bool,
    /// Payment observation report detail.
    pub(super) payment_reports: PaymentReportDetail,
}

/// Custody parts of a member's local status.
#[derive(Debug, Clone)]
pub struct FederationCustodyStatus {
    /// Active local federated on-chain wallet sources.
    pub onchain_wallets: Vec<FederationOnchainWalletStatus>,
    /// Recovery classification for the joint wallet.
    pub wallet_recovery: Option<FederationWalletRecoveryStatus>,
    /// Proposer and signing-coordinator liveness.
    pub wallet_liveness: Option<FederationWalletLivenessStatus>,
    /// Wallet state accepted by consensus.
    pub wallet_operator: Option<FederationWalletOperatorStatus>,
    /// Operator views of feature-gated applications, such as `bark`.
    pub application_operators: BTreeMap<String, serde_json::Value>,
}

/// Build a member's local status the way the private REST route does.
///
/// Admission and request verification are the caller's job. Records the
/// status metrics when built with Prometheus.
pub(super) async fn build_local_status(
    state: &MintState,
    options: LocalStatusOptions,
) -> Result<FederationLocalStatusResponse, FederationLocalStatusError> {
    let (peer_status, materialized_state_rows) = if options.include_materialized_rows {
        local_peer_status_with_materialized_rows(state).await?
    } else {
        (local_peer_status(state).await?, Vec::new())
    };
    let sync_status = state.federation_sync_status().await.unwrap_or_default();
    let checkpoint = federation_checkpoint_status(state).await?;
    let payment_observation_reports = match options.payment_reports {
        PaymentReportDetail::Full => payment_observation_report_summaries(state).await?,
        PaymentReportDetail::UnresolvedQuoteAges => {
            payment_observation_report_summaries_with_unresolved_ages(state).await?
        }
    };
    let pending_mempool_items = state.federation_pending_mempool_len().await;
    let notification_stats = state.federation_operation_notification_stats();
    let aleph_bft_status = state.federation_aleph_bft_status().await;
    let aleph_bft_live_session_active = state.federation_aleph_bft_live_session_active().await;
    let aleph_bft_network_inbound_active =
        state.federation_aleph_bft_network_inbound_active().await;
    let invalid_operation_alerts = state.federation_invalid_operation_alert_summaries().await;
    let custody = build_custody_status(state, peer_status.member_id).await?;
    let response = FederationLocalStatusResponse {
        version: FEDERATION_REST_API_VERSION,
        peer_status,
        sync_state: sync_status.state_name().to_string(),
        sync_ready: sync_status.is_ready(),
        sync_message: sync_status.not_ready_message(),
        sync_peer: sync_status.peer(),
        sync_local_operation_count: sync_status.local_operation_count(),
        sync_peer_operation_count: sync_status.peer_operation_count(),
        sync_operation_count: sync_status.operation_count(),
        pending_mempool_items: super::usize_to_u64_saturating(pending_mempool_items),
        pending_response_waiters: super::usize_to_u64_saturating(
            notification_stats.pending_response_waiters,
        ),
        response_cache_items: super::usize_to_u64_saturating(
            notification_stats.response_cache_items,
        ),
        response_cache_lookups: notification_stats.response_cache_lookups,
        response_cache_hits: notification_stats.response_cache_hits,
        response_cache_hit_rate_bps: response_cache_hit_rate_bps(
            notification_stats.response_cache_hits,
            notification_stats.response_cache_lookups,
        ),
        duplicate_submissions: notification_stats.duplicate_submissions,
        duplicate_pending_waiter_joins: notification_stats.duplicate_pending_waiter_joins,
        checkpoint,
        payment_observation_reports,
        aleph_bft_status,
        aleph_bft_live_session_active,
        aleph_bft_network_inbound_active,
        materialized_state_rows,
        invalid_operation_alerts,
        onchain_wallets: custody.onchain_wallets,
        wallet_recovery: custody.wallet_recovery,
        wallet_liveness: custody.wallet_liveness,
        wallet_operator: custody.wallet_operator,
        application_operators: custody.application_operators,
    };
    #[cfg(feature = "prometheus")]
    record_federation_local_status_metrics(&response);
    Ok(response)
}

/// Build the custody parts of a member's local status.
///
/// Records the Bark metrics when built with Prometheus and Bark.
pub(super) async fn build_custody_status(
    state: &MintState,
    member_id: MemberId,
) -> Result<FederationCustodyStatus, FederationLocalStatusError> {
    #[cfg(not(all(feature = "prometheus", feature = "federation-bark")))]
    let _ = member_id;
    #[cfg(not(any(feature = "federation-bdk", feature = "federation-bark")))]
    let _ = state;
    #[cfg(feature = "federation-bdk")]
    let onchain_wallets = state.federation_onchain_wallet_statuses().await;
    #[cfg(not(feature = "federation-bdk"))]
    let onchain_wallets = Vec::new();
    #[cfg(feature = "federation-bdk")]
    let wallet_recovery = federation_wallet_recovery_status(state).await?;
    #[cfg(not(feature = "federation-bdk"))]
    let wallet_recovery = None;
    #[cfg(feature = "federation-bdk")]
    let wallet_liveness = state
        .mint
        .federation_config()
        .and_then(|runtime| runtime.public_config().frost_wallet.as_ref())
        .is_some()
        .then(|| state.federation.wallet_liveness.clone());
    #[cfg(feature = "federation-bdk")]
    let wallet_liveness = match wallet_liveness {
        Some(worker) => Some(worker.status().await),
        None => None,
    };
    #[cfg(not(feature = "federation-bdk"))]
    let wallet_liveness = None;
    #[cfg(feature = "federation-bdk")]
    let wallet_operator =
        federation_wallet_operator_status(state, wallet_liveness.as_ref()).await?;
    #[cfg(not(feature = "federation-bdk"))]
    let wallet_operator = None;
    #[cfg(feature = "federation-bark")]
    let application_operators = {
        let mut application_operators = BTreeMap::new();
        if let Some(bark) = federation_bark_operator_status(state).await? {
            #[cfg(feature = "prometheus")]
            record_bark_operator_metrics(&member_id.to_string(), &bark);
            application_operators.insert(
                "bark".to_owned(),
                serde_json::to_value(bark).map_err(anyhow::Error::from)?,
            );
        }
        application_operators
    };
    #[cfg(not(feature = "federation-bark"))]
    let application_operators = BTreeMap::<String, serde_json::Value>::new();
    Ok(FederationCustodyStatus {
        onchain_wallets,
        wallet_recovery,
        wallet_liveness,
        wallet_operator,
        application_operators,
    })
}

#[cfg(feature = "federation-bark")]
async fn federation_bark_operator_status(
    state: &MintState,
) -> anyhow::Result<Option<cdk::federation::FederationBarkOperatorStatus>> {
    let Some(runtime) = state.federation.bark_runtime() else {
        return Ok(None);
    };
    let projection = state.mint.federation_bark_projection_snapshot().await?;
    let accepted_frontier = projection.frontier().unwrap_or(0);
    let protocols = match state.federation.frost_signing() {
        Some(signing) => {
            signing
                .operator_protocol_status(runtime.scope().root_key_epoch())
                .await?
        }
        None => cdk::federation::FederationBarkProtocolStatus::default(),
    };
    let chain_tip_height = runtime.chain_tip_height().await.ok();
    Ok(Some(
        runtime
            .operator_status(accepted_frontier, &projection, protocols, chain_tip_height)
            .await?,
    ))
}

async fn federation_checkpoint_status(
    state: &MintState,
) -> Result<FederationCheckpointStatus, cdk::Error> {
    let db = state.mint.localstore();
    let frontier = db.get_federation_checkpoint_frontier().await?;
    let latest_scheduled_checkpoint = db
        .get_latest_federation_checkpoint(FederationCheckpointKind::Scheduled)
        .await?
        .as_ref()
        .map(FederationCheckpointSummary::from_checkpoint)
        .transpose()?;
    let latest_scheduled_quorum = db
        .get_latest_federation_checkpoint_quorum(FederationCheckpointKind::Scheduled)
        .await?
        .as_ref()
        .map(FederationCheckpointQuorumSummary::from_stored_quorum)
        .transpose()?;
    let latest_recovery_quorum = db
        .get_latest_federation_checkpoint_quorum(FederationCheckpointKind::Recovery)
        .await?
        .as_ref()
        .map(FederationCheckpointQuorumSummary::from_stored_quorum)
        .transpose()?;
    let trusted_checkpoint = db
        .get_trusted_federation_checkpoint_quorum()
        .await?
        .as_ref()
        .map(FederationCheckpointQuorumSummary::from_stored_quorum)
        .transpose()?;
    let trusted_journal_next_index = trusted_checkpoint
        .as_ref()
        .map_or(0, |trusted| trusted.checkpoint.frontier.journal.next_index);
    let active_session_backup = match db.get_federation_aleph_bft_active_session().await? {
        Some(session) => {
            let metadata = db.get_federation_aleph_bft_backup_metadata(session).await?;
            Some(FederationAlephBftBackupStatus {
                session,
                chunk_count: metadata.chunk_count,
                total_bytes: metadata.total_bytes,
            })
        }
        None => None,
    };

    Ok(FederationCheckpointStatus {
        lag_from_trusted_checkpoint: frontier
            .journal_next_index
            .saturating_sub(trusted_journal_next_index),
        frontier,
        latest_scheduled_checkpoint,
        latest_scheduled_quorum,
        latest_recovery_quorum,
        trusted_checkpoint,
        retained_recovery_floor: Default::default(),
        active_session_backup,
    })
}

#[cfg(feature = "federation-bdk")]
async fn federation_wallet_operator_status(
    state: &MintState,
    liveness: Option<&cdk::federation::FederationWalletLivenessStatus>,
) -> Result<Option<cdk::federation::FederationWalletOperatorStatus>, cdk::Error> {
    let Some(runtime) = state.mint.effective_federation_config().await? else {
        return Ok(None);
    };
    let Some(wallet) = runtime.public_config().frost_wallet.as_ref() else {
        return Ok(None);
    };
    let addresses = state.mint.federation_address_allocation_state().await?;
    let chain = state.mint.federation_chain_observation_state().await?;
    let transactions = state.mint.federation_transaction_state().await?;
    let default_liveness = cdk::federation::FederationWalletLivenessStatus::default();
    Ok(Some(
        cdk::federation::FederationWalletOperatorStatus::from_states(
            wallet,
            &addresses,
            &chain,
            &transactions,
            liveness.unwrap_or(&default_liveness),
        )?,
    ))
}

#[cfg(feature = "federation-bdk")]
async fn federation_wallet_recovery_status(
    state: &MintState,
) -> Result<Option<FederationWalletRecoveryStatus>, cdk::Error> {
    let Some(runtime) = state.mint.federation_config() else {
        return Ok(None);
    };
    if runtime.public_config().frost_wallet.is_none() {
        return Ok(None);
    }
    let addresses = state.mint.federation_address_allocation_state().await?;
    let chain = state.mint.federation_chain_observation_state().await?;
    let transactions = state.mint.federation_transaction_state().await?;
    Ok(Some(FederationWalletRecoveryStatus::from_states(
        &addresses,
        &chain,
        &transactions,
    )?))
}

fn response_cache_hit_rate_bps(hits: u64, lookups: u64) -> u64 {
    if lookups == 0 {
        return 0;
    }

    let bounded_hits = hits.min(lookups);
    let rate = u128::from(bounded_hits) * 10_000 / u128::from(lookups);
    u64::try_from(rate).unwrap_or(10_000)
}

#[cfg(feature = "prometheus")]
fn record_federation_local_status_metrics(response: &FederationLocalStatusResponse) {
    const SYNC_STATES: &[&str] = &[
        "healthy",
        "awaiting_quorum",
        "lagging",
        "catching_up",
        "halted",
    ];
    const PAYMENT_REPORT_STATUSES: &[&str] =
        &["empty", "awaiting_quorum", "quorum_reached", "conflicting"];
    const PAYMENT_REPORT_ACTIONS: &[&str] = &["none", "inspect"];
    const BROADCAST_HEALTH: &[&str] = &[
        "idle",
        "awaiting_authorization",
        "broadcasting",
        "confirming",
        "degraded",
    ];

    let member = response.peer_status.member_id.to_string();
    cdk_prometheus::METRICS.set_federation_consensus_operation_count(
        &member,
        super::u64_to_i64_saturating(response.peer_status.operation_count),
    );
    cdk_prometheus::METRICS.set_federation_pending_mempool_items(
        &member,
        super::u64_to_i64_saturating(response.pending_mempool_items),
    );
    cdk_prometheus::METRICS.set_federation_sync_ready(&member, response.sync_ready);
    for state in SYNC_STATES {
        cdk_prometheus::METRICS.set_federation_sync_state(
            &member,
            state,
            *state == response.sync_state,
        );
    }
    cdk_prometheus::METRICS.set_federation_checkpoint_lag_operations(
        &member,
        super::u64_to_i64_saturating(response.checkpoint.lag_from_trusted_checkpoint),
    );
    for status in PAYMENT_REPORT_STATUSES {
        for action in PAYMENT_REPORT_ACTIONS {
            cdk_prometheus::METRICS
                .set_federation_payment_observation_report_count(&member, status, action, 0);
        }
    }

    let mut report_counts = BTreeMap::<(String, String), i64>::new();
    for report in &response.payment_observation_reports {
        let status = report.status.to_string();
        let action = report.recommended_action.to_string();
        match report_counts.get_mut(&(status.clone(), action.clone())) {
            Some(count) => *count += 1,
            None => {
                report_counts.insert((status, action), 1);
            }
        }
    }
    for ((status, action), count) in report_counts {
        cdk_prometheus::METRICS
            .set_federation_payment_observation_report_count(&member, &status, &action, count);
    }

    if let Some(wallet) = &response.wallet_operator {
        for utxo in &wallet.utxos {
            cdk_prometheus::METRICS.set_federation_wallet_utxos(
                &member,
                &utxo.state.to_string(),
                super::u64_to_i64_saturating(utxo.count),
                super::u64_to_i64_saturating(utxo.value_sat),
            );
        }
        for phase in &wallet.operation_phases {
            cdk_prometheus::METRICS.set_federation_wallet_operation_phase(
                &member,
                &phase.phase.to_string(),
                super::u64_to_i64_saturating(phase.count),
            );
        }
        cdk_prometheus::METRICS.set_federation_wallet_revealed_count(
            &member,
            "external",
            super::u64_to_i64_saturating(wallet.external_revealed_count),
        );
        cdk_prometheus::METRICS.set_federation_wallet_revealed_count(
            &member,
            "internal",
            super::u64_to_i64_saturating(wallet.internal_revealed_count),
        );
        cdk_prometheus::METRICS.set_federation_wallet_liveness(
            &member,
            super::u64_to_i64_saturating(wallet.pending_batches),
            super::u64_to_i64_saturating(wallet.signing_attempts),
            super::u64_to_i64_saturating(wallet.signing_failures),
        );
        for health in BROADCAST_HEALTH {
            cdk_prometheus::METRICS.set_federation_wallet_broadcast_health(
                &member,
                health,
                *health == wallet.broadcast_health.to_string(),
            );
        }
        cdk_prometheus::METRICS.set_federation_wallet_broadcast_failures(
            &member,
            super::u64_to_i64_saturating(wallet.broadcast_failures),
        );
    }
}

#[cfg(all(feature = "prometheus", feature = "federation-bark"))]
fn record_bark_operator_metrics(
    member: &str,
    bark: &cdk::federation::FederationBarkOperatorStatus,
) {
    for readiness in ["ready", "behind_consensus", "degraded"] {
        cdk_prometheus::METRICS.set_federation_bark_readiness(
            member,
            readiness,
            readiness == bark.readiness,
        );
    }
    cdk_prometheus::METRICS.set_federation_bark_projection_lag(
        member,
        super::u64_to_i64_saturating(bark.projection_lag_operations),
    );
    for vtxo in &bark.vtxos {
        cdk_prometheus::METRICS.set_federation_bark_vtxos(
            member,
            vtxo.state.as_str(),
            super::u64_to_i64_saturating(vtxo.count),
            super::u64_to_i64_saturating(vtxo.value_sat),
        );
    }
    let mut action_phases = BTreeMap::<&'static str, (u64, u64)>::new();
    for phase in cdk::federation::FederationBarkSemanticPhase::ALL {
        action_phases.insert(phase.as_str(), (0, 0));
    }
    for action in &bark.actions {
        let phase = action.phase.as_str();
        let (count, max_age) = action_phases.entry(phase).or_default();
        *count = count.saturating_add(1);
        *max_age = (*max_age).max(action.age_operations);
    }
    for (phase, (count, max_age)) in action_phases {
        cdk_prometheus::METRICS.set_federation_bark_action_phase(
            member,
            phase,
            super::u64_to_i64_saturating(count),
            super::u64_to_i64_saturating(max_age),
        );
    }
    cdk_prometheus::METRICS.set_federation_bark_exposure(
        member,
        "expiring",
        bark.expiring_vtxo_count
            .map(super::u64_to_i64_saturating)
            .unwrap_or(-1),
        bark.expiring_value_sat
            .map(super::u64_to_i64_saturating)
            .unwrap_or(-1),
    );
    cdk_prometheus::METRICS.set_federation_bark_exposure(
        member,
        "ambiguous",
        super::u64_to_i64_saturating(bark.ambiguous_action_count),
        super::u64_to_i64_saturating(bark.ambiguous_value_sat),
    );
    cdk_prometheus::METRICS.set_federation_bark_exposure(
        member,
        "recovery_required",
        super::u64_to_i64_saturating(bark.recovery_required_action_count),
        super::u64_to_i64_saturating(bark.recovery_required_value_sat),
    );
    cdk_prometheus::METRICS.set_federation_bark_exposure(
        member,
        "signer_retry",
        super::u64_to_i64_saturating(bark.signer_retry_action_count),
        0,
    );
    for (protocol, count) in [
        ("frost", bark.protocols.ordinary_frost_nonterminal),
        ("virtual_musig2", bark.protocols.virtual_musig2_nonterminal),
        ("threshold_dh", bark.protocols.threshold_dh_nonterminal),
        ("aggregate_result", bark.protocols.aggregate_results_cached),
    ] {
        cdk_prometheus::METRICS.set_federation_bark_protocol_records(
            member,
            protocol,
            super::u64_to_i64_saturating(count),
        );
    }
    for (coverage, count) in [
        ("accepted", bark.receive_secrets.accepted_actions),
        (
            "locally_acknowledged",
            bark.receive_secrets.acknowledged_by_local_member,
        ),
        ("locally_retained", bark.receive_secrets.locally_retained),
        (
            "missing_acknowledged_nonterminal",
            bark.receive_secrets.missing_acknowledged_nonterminal,
        ),
    ] {
        cdk_prometheus::METRICS.set_federation_bark_receive_secret_coverage(
            member,
            coverage,
            super::u64_to_i64_saturating(count),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::response_cache_hit_rate_bps;

    #[test]
    fn response_cache_hit_rate_handles_zero_and_fractional_lookups() {
        assert_eq!(response_cache_hit_rate_bps(0, 0), 0);
        assert_eq!(response_cache_hit_rate_bps(0, 7), 0);
        assert_eq!(response_cache_hit_rate_bps(3, 7), 4285);
        assert_eq!(response_cache_hit_rate_bps(7, 7), 10_000);
        assert_eq!(response_cache_hit_rate_bps(9, 7), 10_000);
    }
}
