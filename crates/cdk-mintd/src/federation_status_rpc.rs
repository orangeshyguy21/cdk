//! Read-only federation status over the management RPC.
//!
//! The provider reads the running member's state in process through
//! [`FederationStatusHandle`], so the RPC client needs only its mTLS
//! certificate, not the member's identity key.

use std::cmp::Reverse;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use axum::http::StatusCode;
use cdk::mint::FederationRuntimeConfig;
use cdk_axum::{
    FederationCustodyStatus, FederationLocalStatusError, FederationMemberLocalStatus,
    FederationStatusHandle,
};
use cdk_common::federation::{
    redact_federation_operator_message, FederationLocalStatusResponse,
    FederationOnchainWalletStatus, FederationPaymentObservationContext,
    FederationPaymentObservationReportAction, FederationPaymentObservationReportStatus,
    FederationPaymentObservationReportSummary, FederationPaymentVerificationPolicy,
    FederationRecoveryAction, FederationRecoveryPhase, FederationWalletBroadcastHealth,
    FederationWalletLivenessActivity, FederationWalletLivenessStatus,
    FederationWalletOperationPhase, FederationWalletOperatorStatus, FederationWalletRecoveryStatus,
    FederationWalletUtxoState, MemberId,
};
use cdk_mint_rpc::federation as proto;
use cdk_mint_rpc::{
    DynFederationStatusProvider, FederationStatusProvider, ProviderError, ProviderErrorKind,
};
use tokio::sync::Mutex;

use crate::federation_digest_agreement::{DigestAgreement, DigestConflictKind};
use crate::federation_status::encode_commitment;

/// How long one round of member status requests answers repeated calls.
const MEMBER_STATUS_CACHE_TTL: Duration = Duration::from_secs(5);

/// Builds the management RPC status provider for a running member.
pub(crate) fn federation_status_provider(
    handle: FederationStatusHandle,
) -> DynFederationStatusProvider {
    Arc::new(FederationStatusRpcProvider {
        handle,
        member_statuses: Mutex::new(None),
    })
}

struct FederationStatusRpcProvider {
    handle: FederationStatusHandle,
    /// Latest answers from every member. Holding the lock while asking keeps
    /// concurrent callers from asking members again.
    member_statuses: Mutex<Option<CachedMemberStatuses>>,
}

struct CachedMemberStatuses {
    fetched_at: Instant,
    queried_at_unix: u64,
    statuses: Arc<Vec<FederationMemberLocalStatus>>,
}

impl FederationStatusRpcProvider {
    fn runtime_config(&self) -> Result<&FederationRuntimeConfig, ProviderError> {
        self.handle.runtime_config().ok_or_else(not_a_member)
    }

    async fn member_statuses(
        &self,
    ) -> Result<(u64, Arc<Vec<FederationMemberLocalStatus>>), ProviderError> {
        let mut cache = self.member_statuses.lock().await;
        if let Some(cached) = cache.as_ref() {
            if cached.fetched_at.elapsed() < MEMBER_STATUS_CACHE_TTL {
                return Ok((cached.queried_at_unix, cached.statuses.clone()));
            }
        }

        let queried_at_unix = cdk::util::unix_time();
        let statuses = Arc::new(
            self.handle
                .member_local_statuses()
                .await
                .map_err(status_error)?,
        );
        *cache = Some(CachedMemberStatuses {
            fetched_at: Instant::now(),
            queried_at_unix,
            statuses: statuses.clone(),
        });
        Ok((queried_at_unix, statuses))
    }
}

#[async_trait]
impl FederationStatusProvider for FederationStatusRpcProvider {
    async fn get_federation_info(
        &self,
        _request: proto::GetFederationInfoRequest,
    ) -> Result<proto::GetFederationInfoResponse, ProviderError> {
        let runtime = self
            .handle
            .effective_config()
            .await
            .map_err(|error| status_error(error.into()))?
            .ok_or_else(not_a_member)?;
        Ok(federation_info(&runtime))
    }

    async fn get_local_status(
        &self,
        request: proto::GetLocalStatusRequest,
    ) -> Result<proto::GetLocalStatusResponse, ProviderError> {
        let status = self.handle.local_status().await.map_err(status_error)?;
        Ok(proto::GetLocalStatusResponse {
            status: Some(member_status(
                &status,
                report_limit(request.payment_report_limit),
            )),
        })
    }

    async fn get_member_statuses(
        &self,
        request: proto::GetMemberStatusesRequest,
    ) -> Result<proto::GetMemberStatusesResponse, ProviderError> {
        let roster = &self.runtime_config()?.public_config().members;
        let selected = request
            .member_ids
            .iter()
            .map(|member_id| {
                u16::try_from(*member_id)
                    .ok()
                    .and_then(|member_id| MemberId::new(member_id).ok())
                    .filter(|member_id| roster.contains_key(member_id))
                    .ok_or_else(|| {
                        ProviderError::invalid_argument(format!(
                            "The federation has no member {member_id}"
                        ))
                    })
            })
            .collect::<Result<BTreeSet<_>, _>>()?;

        let (queried_at_unix, statuses) = self.member_statuses().await?;
        let statuses = statuses
            .iter()
            .filter(|status| selected.is_empty() || selected.contains(&status.member_id))
            .collect::<Vec<_>>();
        Ok(member_statuses_response(
            &statuses,
            report_limit(request.payment_report_limit),
            queried_at_unix,
        ))
    }

    async fn get_custody_status(
        &self,
        _request: proto::GetCustodyStatusRequest,
    ) -> Result<proto::GetCustodyStatusResponse, ProviderError> {
        let custody = self.handle.custody_status().await.map_err(status_error)?;
        custody_status(&custody)
    }
}

fn not_a_member() -> ProviderError {
    ProviderError::failed_precondition("This daemon is not running as a federation member")
}

/// Maps a status failure onto the gRPC category matching its REST status.
fn status_error(error: FederationLocalStatusError) -> ProviderError {
    let kind = match error.http_status() {
        StatusCode::BAD_REQUEST => ProviderErrorKind::InvalidArgument,
        StatusCode::FORBIDDEN | StatusCode::NOT_FOUND | StatusCode::CONFLICT => {
            ProviderErrorKind::FailedPrecondition
        }
        StatusCode::TOO_MANY_REQUESTS => ProviderErrorKind::ResourceExhausted,
        StatusCode::SERVICE_UNAVAILABLE => ProviderErrorKind::Unavailable,
        _ => ProviderErrorKind::Internal,
    };
    if kind == ProviderErrorKind::Internal {
        tracing::error!(
            "Federation status failed: {}",
            redact_federation_operator_message(&error.to_string())
        );
    }
    ProviderError::new(kind, error.public_message())
}

fn report_limit(limit: u32) -> usize {
    usize::try_from(limit).unwrap_or(usize::MAX)
}

fn member_ids<'a, I>(members: I) -> Vec<u32>
where
    I: IntoIterator<Item = &'a MemberId>,
{
    members
        .into_iter()
        .map(|member| u32::from(member.get()))
        .collect()
}

fn u64_from_usize(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

pub(crate) fn federation_info(
    runtime: &FederationRuntimeConfig,
) -> proto::GetFederationInfoResponse {
    let config = runtime.public_config();
    let thresholds = config.threshold_params;
    proto::GetFederationInfoResponse {
        federation_id: config.federation_id.to_string(),
        local_member_id: u32::from(runtime.member_id().get()),
        config_digest: runtime.config_digest().to_string(),
        wallet_protocol_version: u32::from(config.wallet_protocol_version),
        threshold_params: Some(proto::ThresholdParams {
            member_count: u32::from(thresholds.member_count),
            signature_threshold: u32::from(thresholds.signature_threshold),
            consensus_threshold: u32::from(thresholds.consensus_threshold),
        }),
        members: config
            .members
            .values()
            .map(|member| proto::FederationMember {
                member_id: u32::from(member.member_id.get()),
                public_mint_url: member.public_mint_url.to_string(),
                federation_api_url: member.federation_api_url.to_string(),
                identity_public_key: member.identity_public_key.to_hex(),
            })
            .collect(),
        keysets: config
            .keysets
            .iter()
            .map(|keyset| proto::FederationKeyset {
                id: keyset.id.to_string(),
                unit: keyset.unit.to_string(),
                active: keyset.active,
                input_fee_ppk: keyset.input_fee_ppk,
                final_expiry: keyset.final_expiry,
            })
            .collect(),
        payment_observation_policy: Some(proto::PaymentObservationPolicy {
            mint_quotes: Some(verification_policy(
                config.payment_observation_policy.mint_quotes,
            )),
            melt_quotes: Some(verification_policy(
                config.payment_observation_policy.melt_quotes,
            )),
        }),
    }
}

fn verification_policy(
    policy: FederationPaymentVerificationPolicy,
) -> proto::PaymentVerificationPolicy {
    let kind = match policy {
        FederationPaymentVerificationPolicy::DevelopmentSingleObservation => {
            proto::PaymentVerificationPolicyKind::DevelopmentSingleObservation
        }
        FederationPaymentVerificationPolicy::MemberQuorum { .. } => {
            proto::PaymentVerificationPolicyKind::MemberQuorum
        }
    };
    proto::PaymentVerificationPolicy {
        kind: kind.into(),
        required_observations: u32::from(policy.required_matching_observations()),
    }
}

/// Map a sync state name. Peers report it over HTTP, so an unknown name from a
/// newer member stays unspecified.
fn sync_state(state: &str) -> proto::SyncState {
    match state {
        "healthy" => proto::SyncState::Healthy,
        "awaiting_quorum" => proto::SyncState::AwaitingQuorum,
        "lagging" => proto::SyncState::Lagging,
        "catching_up" => proto::SyncState::CatchingUp,
        "halted" => proto::SyncState::Halted,
        _ => proto::SyncState::Unspecified,
    }
}

pub(crate) fn member_status(
    status: &FederationLocalStatusResponse,
    payment_report_limit: usize,
) -> proto::MemberStatus {
    let peer = &status.peer_status;
    let checkpoint = &status.checkpoint;
    let trusted = checkpoint.trusted_checkpoint.as_ref();
    proto::MemberStatus {
        member_id: u32::from(peer.member_id.get()),
        federation_id: peer.federation_id.to_string(),
        sync: Some(proto::SyncStatus {
            state: sync_state(&status.sync_state).into(),
            ready: status.sync_ready,
            message: redact_federation_operator_message(&status.sync_message),
            peer_member_id: status.sync_peer.map(|member| u32::from(member.get())),
            local_operation_count: status.sync_local_operation_count,
            peer_operation_count: status.sync_peer_operation_count,
            operation_count: status.sync_operation_count,
        }),
        peer: Some(proto::PeerStatus {
            operation_count: peer.operation_count,
            latest_index: peer.latest_index,
            aleph_bft_session: peer.aleph_bft_session,
            aleph_bft_next_item_index: peer.aleph_bft_next_item_index,
            latest_order_digest: peer.latest_order_digest.to_string(),
            application_digest: peer.application_digest.map(|digest| digest.to_string()),
            latest_audited_checkpoint_id: peer
                .latest_audited_checkpoint_id
                .map(|checkpoint| checkpoint.to_string()),
            materialized_state_digest: peer
                .materialized_state_digest
                .map(|digest| digest.to_string()),
        }),
        queues: Some(proto::QueueCounters {
            pending_mempool_items: status.pending_mempool_items,
            pending_response_waiters: status.pending_response_waiters,
            response_cache_items: status.response_cache_items,
            response_cache_lookups: status.response_cache_lookups,
            response_cache_hits: status.response_cache_hits,
            response_cache_hit_rate_bps: status.response_cache_hit_rate_bps,
            duplicate_submissions: status.duplicate_submissions,
            duplicate_pending_waiter_joins: status.duplicate_pending_waiter_joins,
        }),
        consensus: Some(proto::ConsensusStatus {
            live_session_active: status.aleph_bft_live_session_active,
            network_inbound_active: status.aleph_bft_network_inbound_active,
            runtime: status
                .aleph_bft_status
                .as_ref()
                .map(|runtime| proto::ConsensusRuntime {
                    session: runtime.session,
                    next_item_index: runtime.next_item_index,
                    queued_item_count: runtime.queued_item_count,
                    pending_finalization_item_count: runtime.pending_finalization_item_count,
                    finalized_item_count: runtime.finalized_item_count,
                    accepted_operation_count: runtime.accepted_operation_count,
                    latest_accepted_operation_index: runtime.latest_accepted_operation_index,
                }),
        }),
        checkpoint: Some(proto::CheckpointStatus {
            journal_next_index: checkpoint.frontier.journal_next_index,
            finalized_next_item_index: checkpoint.frontier.finalized_next_item_index,
            application_next_index: checkpoint.frontier.application_next_index,
            audit_mismatch: checkpoint.frontier.materialized_state_audit_mismatch,
            trusted_checkpoint_id: trusted
                .map(|quorum| quorum.checkpoint.checkpoint_id.to_string()),
            trusted_checkpoint_signers: trusted
                .map(|quorum| member_ids(&quorum.signers))
                .unwrap_or_default(),
            trusted_checkpoint_operation_count: trusted
                .map(|quorum| quorum.checkpoint.frontier.journal.next_index),
            lag_from_trusted_checkpoint: checkpoint.lag_from_trusted_checkpoint,
            latest_scheduled_checkpoint_id: checkpoint
                .latest_scheduled_checkpoint
                .as_ref()
                .map(|summary| summary.checkpoint_id.to_string()),
            latest_scheduled_quorum_id: checkpoint
                .latest_scheduled_quorum
                .as_ref()
                .map(|quorum| quorum.checkpoint.checkpoint_id.to_string()),
            latest_recovery_quorum_id: checkpoint
                .latest_recovery_quorum
                .as_ref()
                .map(|quorum| quorum.checkpoint.checkpoint_id.to_string()),
            active_session_backup: checkpoint.active_session_backup.map(|backup| {
                proto::ActiveSessionBackup {
                    session: backup.session,
                    chunk_count: backup.chunk_count,
                    total_bytes: backup.total_bytes,
                }
            }),
        }),
        payment_observations: Some(payment_observation_summary(
            &status.payment_observation_reports,
            payment_report_limit,
        )),
        invalid_operation_alerts: status
            .invalid_operation_alerts
            .iter()
            .map(|alert| proto::InvalidOperationAlert {
                source: alert.source.clone(),
                alerting_buckets: alert.alerting_buckets,
                max_count: alert.max_count,
                threshold: alert.threshold,
                window_secs: alert.window_secs,
            })
            .collect(),
    }
}

/// Whether a report needs an operator's attention: not cleanly resolved.
fn payment_report_needs_attention(report: &FederationPaymentObservationReportSummary) -> bool {
    report.status != FederationPaymentObservationReportStatus::QuorumReached
        || report.stale
        || report.recommended_action != FederationPaymentObservationReportAction::None
        || !report.conflicting_observers.is_empty()
        || !report.competing_terminal_state_observers.is_empty()
}

/// Newest consensus index among a report's observations.
fn payment_report_latest_index(report: &FederationPaymentObservationReportSummary) -> u64 {
    report
        .groups
        .iter()
        .flat_map(|group| group.operation_indices.iter().copied())
        .max()
        .unwrap_or_default()
}

/// Counts every report and lists only those needing attention, newest
/// first, up to `limit`.
pub(crate) fn payment_observation_summary(
    reports: &[FederationPaymentObservationReportSummary],
    limit: usize,
) -> proto::PaymentObservationSummary {
    let mut summary = proto::PaymentObservationSummary {
        total_reports: u64_from_usize(reports.len()),
        ..Default::default()
    };
    for report in reports {
        let count = match report.status {
            FederationPaymentObservationReportStatus::Empty => &mut summary.empty,
            FederationPaymentObservationReportStatus::AwaitingQuorum => {
                &mut summary.awaiting_quorum
            }
            FederationPaymentObservationReportStatus::QuorumReached => &mut summary.quorum_reached,
            FederationPaymentObservationReportStatus::Conflicting => &mut summary.conflicting,
        };
        *count = count.saturating_add(1);
        if report.stale {
            summary.stale = summary.stale.saturating_add(1);
        }
        if report.recommended_action == FederationPaymentObservationReportAction::Inspect {
            summary.inspect = summary.inspect.saturating_add(1);
        }
    }

    let mut attention = reports
        .iter()
        .filter(|report| payment_report_needs_attention(report))
        .collect::<Vec<_>>();
    attention.sort_by_key(|report| {
        (
            Reverse(payment_report_latest_index(report)),
            report.quote.as_str(),
        )
    });
    summary.truncated = attention.len() > limit;
    summary.reports = attention
        .into_iter()
        .take(limit)
        .map(payment_observation_report)
        .collect();
    summary
}

fn payment_observation_report(
    report: &FederationPaymentObservationReportSummary,
) -> proto::PaymentObservationReport {
    let context = match report.context {
        FederationPaymentObservationContext::MintQuote => {
            proto::PaymentObservationContext::MintQuote
        }
        FederationPaymentObservationContext::MeltQuote => {
            proto::PaymentObservationContext::MeltQuote
        }
    };
    let status = match report.status {
        FederationPaymentObservationReportStatus::Empty => {
            proto::PaymentObservationReportStatus::Empty
        }
        FederationPaymentObservationReportStatus::AwaitingQuorum => {
            proto::PaymentObservationReportStatus::AwaitingQuorum
        }
        FederationPaymentObservationReportStatus::QuorumReached => {
            proto::PaymentObservationReportStatus::QuorumReached
        }
        FederationPaymentObservationReportStatus::Conflicting => {
            proto::PaymentObservationReportStatus::Conflicting
        }
    };
    let recommended_action = match report.recommended_action {
        FederationPaymentObservationReportAction::None => {
            proto::PaymentObservationReportAction::None
        }
        FederationPaymentObservationReportAction::Inspect => {
            proto::PaymentObservationReportAction::Inspect
        }
    };
    proto::PaymentObservationReport {
        context: context.into(),
        quote: report.quote.clone(),
        status: status.into(),
        recommended_action: recommended_action.into(),
        required: u32::from(report.required),
        total_observations: u64_from_usize(report.total_observations),
        quote_age_secs: report.quote_age_secs,
        stale: report.stale,
        conflicting_observers: member_ids(&report.conflicting_observers),
        competing_terminal_state_observers: member_ids(&report.competing_terminal_state_observers),
        groups: report
            .groups
            .iter()
            .map(|group| proto::PaymentObservationGroup {
                state: group.state.clone(),
                observers: member_ids(&group.observers),
                quorum_reached: group.quorum_reached,
                terminal_state: group.terminal_state,
                conflicting_observers: member_ids(&group.conflicting_observers),
                operation_indices: group.operation_indices.clone(),
            })
            .collect(),
    }
}

pub(crate) fn member_statuses_response(
    statuses: &[&FederationMemberLocalStatus],
    payment_report_limit: usize,
    queried_at_unix: u64,
) -> proto::GetMemberStatusesResponse {
    let agreement = DigestAgreement::from_statuses(
        statuses
            .iter()
            .filter_map(|member| member.status.as_ref().ok()),
    );
    proto::GetMemberStatusesResponse {
        members: statuses
            .iter()
            .map(|member| {
                let (status, error) = match &member.status {
                    Ok(status) => (Some(member_status(status, payment_report_limit)), None),
                    Err(error) => (None, Some(error.clone())),
                };
                proto::MemberStatusResult {
                    member_id: u32::from(member.member_id.get()),
                    local: member.local,
                    reachable: status.is_some(),
                    latency_ms: u64::try_from(member.latency.as_millis()).unwrap_or(u64::MAX),
                    error,
                    status,
                }
            })
            .collect(),
        digest_agreement: Some(digest_agreement(&agreement)),
        queried_at_unix,
    }
}

pub(crate) fn digest_agreement(agreement: &DigestAgreement) -> proto::DigestAgreement {
    // Unknown: nothing compared. Diverged: a digest alert or a contradiction.
    // Converging: members differ in height, session, or a missing digest.
    let state = if agreement.compared_members.is_empty() {
        proto::DigestAgreementState::Unknown
    } else if !agreement.digest_alert_members.is_empty() || !agreement.conflicts.is_empty() {
        proto::DigestAgreementState::Diverged
    } else if !agreement.missing_application_digest_members.is_empty()
        || !agreement.differing_members.is_empty()
    {
        proto::DigestAgreementState::Converging
    } else {
        proto::DigestAgreementState::Converged
    };
    let sorted = |members: &[MemberId]| {
        let mut members = member_ids(members);
        members.sort_unstable();
        members
    };
    proto::DigestAgreement {
        state: state.into(),
        compared_members: sorted(&agreement.compared_members),
        groups: agreement
            .groups
            .iter()
            .map(|group| proto::DigestGroup {
                operation_count: group.key.operation_count,
                aleph_bft_session: group.key.aleph_bft_session,
                order_digest: group.key.order_digest.to_string(),
                application_digest: group
                    .key
                    .application_digest
                    .map(|digest| digest.to_string()),
                members: member_ids(&group.members),
                ready_count: u32::try_from(group.ready_count).unwrap_or(u32::MAX),
            })
            .collect(),
        digest_alert_members: sorted(&agreement.digest_alert_members),
        missing_application_digest_members: sorted(&agreement.missing_application_digest_members),
        conflicts: agreement
            .conflicts
            .iter()
            .map(|conflict| {
                let kind = match conflict.kind {
                    DigestConflictKind::OrderDigest => proto::DigestConflictKind::OrderDigest,
                    DigestConflictKind::CheckpointAudit => {
                        proto::DigestConflictKind::CheckpointAudit
                    }
                    DigestConflictKind::ApplicationDigest => {
                        proto::DigestConflictKind::ApplicationDigest
                    }
                };
                proto::DigestConflict {
                    kind: kind.into(),
                    first_member_id: u32::from(conflict.first.get()),
                    second_member_id: u32::from(conflict.second.get()),
                    operation_count: conflict.operation_count,
                }
            })
            .collect(),
    }
}

pub(crate) fn custody_status(
    custody: &FederationCustodyStatus,
) -> Result<proto::GetCustodyStatusResponse, ProviderError> {
    Ok(proto::GetCustodyStatusResponse {
        onchain_wallets: custody
            .onchain_wallets
            .iter()
            .map(onchain_wallet_source)
            .collect(),
        wallet_operator: custody.wallet_operator.as_ref().map(wallet_operator),
        wallet_recovery: custody.wallet_recovery.as_ref().map(wallet_recovery),
        wallet_liveness: custody.wallet_liveness.as_ref().map(wallet_liveness),
        bark: bark_operator(custody)?,
    })
}

fn onchain_source_health(health: &str) -> proto::OnchainSourceHealth {
    match health {
        "never_synced" => proto::OnchainSourceHealth::NeverSynced,
        "healthy" => proto::OnchainSourceHealth::Healthy,
        "degraded" => proto::OnchainSourceHealth::Degraded,
        _ => proto::OnchainSourceHealth::Unspecified,
    }
}

fn onchain_wallet_source(source: &FederationOnchainWalletStatus) -> proto::OnchainWalletSource {
    proto::OnchainWalletSource {
        source: source.source.clone(),
        source_scope: source.source_scope.clone(),
        source_id: source.source_id.clone(),
        correlated_source_warning: source.correlated_source_warning,
        health: onchain_source_health(&source.health).into(),
        local_tip_height: source.local_tip_height,
        local_tip_hash: source.local_tip_hash.clone(),
        last_success_unix: source.last_success_unix,
        consecutive_failures: source.consecutive_failures,
    }
}

fn wallet_operator(wallet: &FederationWalletOperatorStatus) -> proto::WalletOperatorStatus {
    let broadcast_health = match wallet.broadcast_health {
        FederationWalletBroadcastHealth::Idle => proto::WalletBroadcastHealth::Idle,
        FederationWalletBroadcastHealth::AwaitingAuthorization => {
            proto::WalletBroadcastHealth::AwaitingAuthorization
        }
        FederationWalletBroadcastHealth::Broadcasting => proto::WalletBroadcastHealth::Broadcasting,
        FederationWalletBroadcastHealth::Confirming => proto::WalletBroadcastHealth::Confirming,
        FederationWalletBroadcastHealth::Degraded => proto::WalletBroadcastHealth::Degraded,
    };
    proto::WalletOperatorStatus {
        root_key_epoch: wallet.root_key_epoch,
        application_key_epoch: wallet.application_key_epoch,
        descriptor_commitment: encode_commitment(&wallet.descriptor_commitment),
        network: wallet.network.clone(),
        minimum_confirmations: wallet.minimum_confirmations,
        fee_policy_version: u32::from(wallet.fee_policy_version),
        external_revealed_count: wallet.external_revealed_count,
        internal_revealed_count: wallet.internal_revealed_count,
        utxos: wallet
            .utxos
            .iter()
            .map(|utxo| proto::WalletUtxoCount {
                state: wallet_utxo_state(utxo.state).into(),
                count: utxo.count,
                value_sat: utxo.value_sat,
            })
            .collect(),
        reserved_value_sat: wallet.reserved_value_sat,
        operation_phases: wallet
            .operation_phases
            .iter()
            .map(|phase| proto::WalletOperationPhaseCount {
                phase: wallet_operation_phase(phase.phase).into(),
                count: phase.count,
            })
            .collect(),
        pending_batches: wallet.pending_batches,
        signing_attempts: wallet.signing_attempts,
        signing_failures: wallet.signing_failures,
        broadcast_health: broadcast_health.into(),
        broadcast_failures: wallet.broadcast_failures,
    }
}

fn wallet_utxo_state(state: FederationWalletUtxoState) -> proto::WalletUtxoState {
    match state {
        FederationWalletUtxoState::Observed => proto::WalletUtxoState::Observed,
        FederationWalletUtxoState::Confirmed => proto::WalletUtxoState::Confirmed,
        FederationWalletUtxoState::Spendable => proto::WalletUtxoState::Spendable,
        FederationWalletUtxoState::Reserved => proto::WalletUtxoState::Reserved,
        FederationWalletUtxoState::Spent => proto::WalletUtxoState::Spent,
        FederationWalletUtxoState::Reorged => proto::WalletUtxoState::Reorged,
        FederationWalletUtxoState::Quarantined => proto::WalletUtxoState::Quarantined,
    }
}

fn wallet_operation_phase(phase: FederationWalletOperationPhase) -> proto::WalletOperationPhase {
    match phase {
        FederationWalletOperationPhase::ChainObservation => {
            proto::WalletOperationPhase::ChainObservation
        }
        FederationWalletOperationPhase::Proposal => proto::WalletOperationPhase::Proposal,
        FederationWalletOperationPhase::Signing => proto::WalletOperationPhase::Signing,
        FederationWalletOperationPhase::BroadcastAuthorization => {
            proto::WalletOperationPhase::BroadcastAuthorization
        }
        FederationWalletOperationPhase::Broadcast => proto::WalletOperationPhase::Broadcast,
        FederationWalletOperationPhase::Confirmation => proto::WalletOperationPhase::Confirmation,
        FederationWalletOperationPhase::Terminal => proto::WalletOperationPhase::Terminal,
    }
}

fn wallet_recovery(recovery: &FederationWalletRecoveryStatus) -> proto::WalletRecoveryStatus {
    proto::WalletRecoveryStatus {
        address_allocations: recovery.address_allocations,
        wallet_utxos: recovery.wallet_utxos,
        payment_intents: recovery.payment_intents,
        transactions: recovery.transactions,
        sticky_reservations: recovery.sticky_reservations,
        actions: recovery
            .actions
            .iter()
            .map(|action| proto::WalletRecoveryActionCount {
                phase: wallet_recovery_phase(action.phase).into(),
                state: action.state.clone(),
                action: wallet_recovery_action(action.action).into(),
                count: action.count,
            })
            .collect(),
    }
}

fn wallet_recovery_phase(phase: FederationRecoveryPhase) -> proto::WalletRecoveryPhase {
    match phase {
        FederationRecoveryPhase::Address => proto::WalletRecoveryPhase::Address,
        FederationRecoveryPhase::Observation => proto::WalletRecoveryPhase::Observation,
        FederationRecoveryPhase::Proposal => proto::WalletRecoveryPhase::Proposal,
        FederationRecoveryPhase::Reservation => proto::WalletRecoveryPhase::Reservation,
        FederationRecoveryPhase::Signing => proto::WalletRecoveryPhase::Signing,
        FederationRecoveryPhase::Signed => proto::WalletRecoveryPhase::Signed,
        FederationRecoveryPhase::Broadcast => proto::WalletRecoveryPhase::Broadcast,
        FederationRecoveryPhase::Confirmation => proto::WalletRecoveryPhase::Confirmation,
        FederationRecoveryPhase::Replacement => proto::WalletRecoveryPhase::Replacement,
        FederationRecoveryPhase::Terminal => proto::WalletRecoveryPhase::Terminal,
    }
}

fn wallet_recovery_action(action: FederationRecoveryAction) -> proto::WalletRecoveryAction {
    match action {
        FederationRecoveryAction::ReconcileBdkIndexes => {
            proto::WalletRecoveryAction::ReconcileBdkIndexes
        }
        FederationRecoveryAction::CollectChainEvidence => {
            proto::WalletRecoveryAction::CollectChainEvidence
        }
        FederationRecoveryAction::AwaitProposal => proto::WalletRecoveryAction::AwaitProposal,
        FederationRecoveryAction::PreserveStickyReservation => {
            proto::WalletRecoveryAction::PreserveStickyReservation
        }
        FederationRecoveryAction::StartFreshSigningAttempt => {
            proto::WalletRecoveryAction::StartFreshSigningAttempt
        }
        FederationRecoveryAction::ReapplyPersistedTransaction => {
            proto::WalletRecoveryAction::ReapplyPersistedTransaction
        }
        FederationRecoveryAction::PersistBroadcastIntent => {
            proto::WalletRecoveryAction::PersistBroadcastIntent
        }
        FederationRecoveryAction::RebroadcastPersistedTransaction => {
            proto::WalletRecoveryAction::RebroadcastPersistedTransaction
        }
        FederationRecoveryAction::CollectConfirmationEvidence => {
            proto::WalletRecoveryAction::CollectConfirmationEvidence
        }
        FederationRecoveryAction::OperatorReview => proto::WalletRecoveryAction::OperatorReview,
        FederationRecoveryAction::NoOp => proto::WalletRecoveryAction::NoOp,
    }
}

fn wallet_liveness(liveness: &FederationWalletLivenessStatus) -> proto::WalletLivenessStatus {
    let activity = match liveness.activity {
        FederationWalletLivenessActivity::Idle => proto::WalletLivenessActivity::Idle,
        FederationWalletLivenessActivity::WaitingForLease => {
            proto::WalletLivenessActivity::WaitingForLease
        }
        FederationWalletLivenessActivity::Proposing => proto::WalletLivenessActivity::Proposing,
        FederationWalletLivenessActivity::Signing => proto::WalletLivenessActivity::Signing,
        FederationWalletLivenessActivity::Backoff => proto::WalletLivenessActivity::Backoff,
    };
    proto::WalletLivenessStatus {
        pending_batches: liveness.pending_batches,
        awaiting_signatures: liveness.awaiting_signatures,
        proposal_attempts: liveness.proposal_attempts,
        signing_attempts: liveness.signing_attempts,
        signer_failures: liveness.signer_failures,
        activity: activity.into(),
    }
}

/// Maps the `bark` application operator view, present only when the daemon
/// runs Bark custody.
#[cfg(feature = "federation-bark")]
fn bark_operator(
    custody: &FederationCustodyStatus,
) -> Result<Option<proto::BarkOperatorStatus>, ProviderError> {
    let Some(value) = custody.application_operators.get("bark") else {
        return Ok(None);
    };
    let bark =
        <cdk_federation_bark::FederationBarkOperatorStatus as serde::Deserialize>::deserialize(
            value,
        )
        .map_err(|error| ProviderError::internal(format!("invalid Bark status: {error}")))?;
    let details_json = serde_json::to_string(value)
        .map_err(|error| ProviderError::internal(format!("invalid Bark status: {error}")))?;
    Ok(Some(proto::BarkOperatorStatus {
        readiness: bark_readiness(&bark.readiness).into(),
        degraded_reason: bark.degraded_reason,
        accepted_frontier: bark.accepted_frontier,
        local_frontier: bark.local_frontier,
        projection_lag_operations: bark.projection_lag_operations,
        network: bark.network,
        chain_tip_height: bark.chain_tip_height,
        vtxos: bark
            .vtxos
            .iter()
            .map(|vtxo| proto::BarkVtxoCount {
                state: vtxo.state.as_str().to_string(),
                count: vtxo.count,
                value_sat: vtxo.value_sat,
            })
            .collect(),
        expiring_vtxo_count: bark.expiring_vtxo_count,
        expiring_value_sat: bark.expiring_value_sat,
        ambiguous_action_count: bark.ambiguous_action_count,
        ambiguous_value_sat: bark.ambiguous_value_sat,
        recovery_required_action_count: bark.recovery_required_action_count,
        recovery_required_value_sat: bark.recovery_required_value_sat,
        signer_retry_action_count: bark.signer_retry_action_count,
        missing_acknowledged_receive_secrets: bark.receive_secrets.missing_acknowledged_nonterminal,
        details_json,
    }))
}

#[cfg(feature = "federation-bark")]
fn bark_readiness(readiness: &str) -> proto::BarkReadiness {
    match readiness {
        "ready" => proto::BarkReadiness::Ready,
        "behind_consensus" => proto::BarkReadiness::BehindConsensus,
        "degraded" => proto::BarkReadiness::Degraded,
        _ => proto::BarkReadiness::Unspecified,
    }
}

/// Without Bark support the daemon never runs Bark custody.
#[cfg(not(feature = "federation-bark"))]
fn bark_operator(
    _custody: &FederationCustodyStatus,
) -> Result<Option<proto::BarkOperatorStatus>, ProviderError> {
    Ok(None)
}

#[cfg(test)]
mod tests;
