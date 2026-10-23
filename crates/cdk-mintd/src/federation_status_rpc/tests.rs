use std::collections::BTreeMap;
use std::str::FromStr;

use cdk_common::federation::{
    generate_trusted_dealer_configs, FederationApplicationDigest, FederationCheckpointStatus,
    FederationConfig, FederationError, FederationJournalDigest,
    FederationPaymentObservationEvidenceGroupSummary, FederationPaymentObservationPolicy,
    FederationPeerStatus, FederationRecoveryActionCount, FederationWalletOperationPhaseCount,
    FederationWalletUtxoStatusCount, MemberConfigPrivate, ThresholdParams, TrustedDealerKeysetSpec,
    TrustedDealerMember, FEDERATION_REST_API_VERSION,
};
use cdk_common::mint_url::MintUrl;
use cdk_common::{Amount, CurrencyUnit, SecretKey};

use super::*;

fn member(id: u16) -> MemberId {
    MemberId::new(id).expect("member id")
}

fn federation_fixture() -> (FederationConfig, MemberConfigPrivate) {
    let members = (1..=3)
        .map(|id| {
            TrustedDealerMember::new(
                member(id),
                MintUrl::from_str(&format!("http://mint{id}.example.com")).expect("mint url"),
                MintUrl::from_str(&format!("http://fed{id}.example.com")).expect("fed url"),
                SecretKey::generate(),
            )
        })
        .collect::<Vec<_>>();
    let coefficients = BTreeMap::from([(
        Amount::from(1),
        vec![
            SecretKey::generate_bls().as_bls().expect("bls key").clone(),
            SecretKey::generate_bls().as_bls().expect("bls key").clone(),
        ],
    )]);
    let keyset = TrustedDealerKeysetSpec::new(CurrencyUnit::Sat, true, 5, None, coefficients);
    let bundle = generate_trusted_dealer_configs(
        ThresholdParams::with_bft_consensus(3, 2).expect("threshold"),
        members,
        vec![keyset],
    )
    .expect("trusted dealer bundle");
    let private = bundle
        .private_configs
        .get(&member(2))
        .expect("private config")
        .clone();
    (bundle.public_config, private)
}

fn local_status(
    config: &FederationConfig,
    member_id: u16,
    operation_count: u64,
) -> FederationLocalStatusResponse {
    let mut peer_status = FederationPeerStatus::new(
        config.federation_id,
        member(member_id),
        operation_count,
        operation_count.checked_sub(1),
        FederationJournalDigest::genesis(),
    );
    peer_status.application_digest = Some(FederationApplicationDigest::genesis());
    FederationLocalStatusResponse {
        version: FEDERATION_REST_API_VERSION,
        peer_status,
        sync_state: "healthy".to_string(),
        sync_ready: true,
        sync_message: "federation member is healthy".to_string(),
        sync_peer: None,
        sync_local_operation_count: None,
        sync_peer_operation_count: None,
        sync_operation_count: None,
        pending_mempool_items: 1,
        pending_response_waiters: 2,
        response_cache_items: 3,
        response_cache_lookups: 4,
        response_cache_hits: 5,
        response_cache_hit_rate_bps: 6,
        duplicate_submissions: 7,
        duplicate_pending_waiter_joins: 8,
        checkpoint: FederationCheckpointStatus::default(),
        payment_observation_reports: Vec::new(),
        aleph_bft_status: None,
        aleph_bft_live_session_active: true,
        aleph_bft_network_inbound_active: true,
        materialized_state_rows: Vec::new(),
        invalid_operation_alerts: Vec::new(),
        onchain_wallets: Vec::new(),
        wallet_recovery: None,
        wallet_liveness: None,
        wallet_operator: None,
        application_operators: BTreeMap::new(),
    }
}

fn payment_report(
    quote: &str,
    latest_index: u64,
    status: FederationPaymentObservationReportStatus,
    stale: bool,
) -> FederationPaymentObservationReportSummary {
    let conflicting = status == FederationPaymentObservationReportStatus::Conflicting;
    FederationPaymentObservationReportSummary {
        context: FederationPaymentObservationContext::MeltQuote,
        quote: quote.to_string(),
        required: 2,
        total_observations: 2,
        groups: vec![FederationPaymentObservationEvidenceGroupSummary {
            state: "PAID".to_string(),
            observers: vec![member(1), member(2)],
            observer_count: 2,
            operation_ids: Vec::new(),
            operation_indices: vec![latest_index.saturating_sub(1), latest_index],
            conflicting_observers: match conflicting {
                true => vec![member(3)],
                false => Vec::new(),
            },
            quorum_reached: status == FederationPaymentObservationReportStatus::QuorumReached,
            terminal_state: true,
        }],
        conflicting_observers: match conflicting {
            true => vec![member(3)],
            false => Vec::new(),
        },
        competing_terminal_state_observers: Vec::new(),
        status,
        quote_age_secs: Some(1_000),
        stale,
        recommended_action: match conflicting || stale {
            true => FederationPaymentObservationReportAction::Inspect,
            false => FederationPaymentObservationReportAction::None,
        },
    }
}

#[test]
fn federation_info_maps_the_effective_config() {
    let (mut config, private) = federation_fixture();
    config.payment_observation_policy = FederationPaymentObservationPolicy {
        mint_quotes: FederationPaymentVerificationPolicy::member_quorum(3),
        melt_quotes:
            FederationPaymentVerificationPolicy::development_single_observation_for_testing(),
    };
    let runtime = FederationRuntimeConfig::new(config.clone(), private).expect("runtime config");

    let info = federation_info(&runtime);

    assert_eq!(info.federation_id, config.federation_id.to_string());
    assert_eq!(info.local_member_id, 2);
    assert_eq!(info.config_digest, runtime.config_digest().to_string());
    assert_eq!(
        info.wallet_protocol_version,
        u32::from(config.wallet_protocol_version)
    );
    assert_eq!(
        info.threshold_params,
        Some(proto::ThresholdParams {
            member_count: 3,
            signature_threshold: 2,
            consensus_threshold: 3,
        })
    );
    assert_eq!(
        info.members
            .iter()
            .map(|member| member.member_id)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    let first = &info.members[0];
    let configured = config.member(member(1)).expect("member 1");
    assert_eq!(
        first.public_mint_url,
        configured.public_mint_url.to_string()
    );
    assert_eq!(
        first.federation_api_url,
        configured.federation_api_url.to_string()
    );
    assert_eq!(
        first.identity_public_key,
        configured.identity_public_key.to_hex()
    );
    assert_eq!(info.keysets.len(), 1);
    assert_eq!(info.keysets[0].id, config.keysets[0].id.to_string());
    assert_eq!(info.keysets[0].unit, "sat");
    assert!(info.keysets[0].active);
    assert_eq!(info.keysets[0].input_fee_ppk, 5);
    assert_eq!(info.keysets[0].final_expiry, None);
    let policy = info.payment_observation_policy.expect("policy");
    let mint_quotes = policy.mint_quotes.expect("mint quote policy");
    assert_eq!(
        mint_quotes.kind(),
        proto::PaymentVerificationPolicyKind::MemberQuorum
    );
    assert_eq!(mint_quotes.required_observations, 3);
    let melt_quotes = policy.melt_quotes.expect("melt quote policy");
    assert_eq!(
        melt_quotes.kind(),
        proto::PaymentVerificationPolicyKind::DevelopmentSingleObservation
    );
    assert_eq!(melt_quotes.required_observations, 1);
}

#[test]
fn member_status_maps_the_local_status_summary() {
    let (config, _) = federation_fixture();
    let mut status = local_status(&config, 2, 4);
    status.sync_state = "lagging".to_string();
    status.sync_ready = false;
    status.sync_message = "lagging: password=hunter2".to_string();
    status.sync_peer = Some(member(3));
    status.sync_peer_operation_count = Some(9);
    status.checkpoint.lag_from_trusted_checkpoint = 4;

    let mapped = member_status(&status, 10);

    assert_eq!(mapped.member_id, 2);
    assert_eq!(mapped.federation_id, config.federation_id.to_string());
    let sync = mapped.sync.expect("sync");
    assert_eq!(sync.state(), proto::SyncState::Lagging);
    assert!(!sync.ready);
    assert!(!sync.message.contains("hunter2"));
    assert_eq!(sync.peer_member_id, Some(3));
    assert_eq!(sync.peer_operation_count, Some(9));
    let peer = mapped.peer.expect("peer");
    assert_eq!(peer.operation_count, 4);
    assert_eq!(peer.latest_index, Some(3));
    assert_eq!(
        peer.latest_order_digest,
        FederationJournalDigest::genesis().to_string()
    );
    assert_eq!(
        peer.application_digest,
        Some(FederationApplicationDigest::genesis().to_string())
    );
    let queues = mapped.queues.expect("queues");
    assert_eq!(queues.pending_mempool_items, 1);
    assert_eq!(queues.duplicate_pending_waiter_joins, 8);
    let consensus = mapped.consensus.expect("consensus");
    assert!(consensus.live_session_active);
    assert!(consensus.network_inbound_active);
    assert!(consensus.runtime.is_none());
    let checkpoint = mapped.checkpoint.expect("checkpoint");
    assert_eq!(checkpoint.lag_from_trusted_checkpoint, 4);
    assert!(checkpoint.trusted_checkpoint_id.is_none());
    assert!(!checkpoint.audit_mismatch);
}

#[test]
fn payment_summary_counts_every_report_and_lists_the_newest_needing_attention() {
    let reports = vec![
        payment_report(
            "resolved",
            50,
            FederationPaymentObservationReportStatus::QuorumReached,
            false,
        ),
        payment_report(
            "waiting",
            30,
            FederationPaymentObservationReportStatus::AwaitingQuorum,
            false,
        ),
        payment_report(
            "conflict",
            90,
            FederationPaymentObservationReportStatus::Conflicting,
            false,
        ),
        payment_report(
            "stuck",
            70,
            FederationPaymentObservationReportStatus::AwaitingQuorum,
            true,
        ),
    ];

    let summary = payment_observation_summary(&reports, 2);

    assert_eq!(summary.total_reports, 4);
    assert_eq!(summary.empty, 0);
    assert_eq!(summary.quorum_reached, 1);
    assert_eq!(summary.awaiting_quorum, 2);
    assert_eq!(summary.conflicting, 1);
    assert_eq!(summary.stale, 1);
    assert_eq!(summary.inspect, 2);
    assert!(summary.truncated);
    assert_eq!(
        summary
            .reports
            .iter()
            .map(|report| report.quote.as_str())
            .collect::<Vec<_>>(),
        vec!["conflict", "stuck"]
    );
    let conflict = &summary.reports[0];
    assert_eq!(
        conflict.context(),
        proto::PaymentObservationContext::MeltQuote
    );
    assert_eq!(
        conflict.status(),
        proto::PaymentObservationReportStatus::Conflicting
    );
    assert_eq!(
        conflict.recommended_action(),
        proto::PaymentObservationReportAction::Inspect
    );
    assert_eq!(conflict.conflicting_observers, vec![3]);
    assert_eq!(conflict.groups[0].observers, vec![1, 2]);
    assert_eq!(conflict.groups[0].operation_indices, vec![89, 90]);
    assert_eq!(conflict.quote_age_secs, Some(1_000));

    let everything = payment_observation_summary(&reports, 10);
    assert!(!everything.truncated);
    assert_eq!(
        everything
            .reports
            .iter()
            .map(|report| report.quote.as_str())
            .collect::<Vec<_>>(),
        vec!["conflict", "stuck", "waiting"]
    );
}

#[test]
fn status_errors_map_to_grpc_categories() {
    let cases = [
        (
            FederationLocalStatusError::NotConfigured,
            ProviderErrorKind::FailedPrecondition,
        ),
        (
            FederationLocalStatusError::AdmissionFull,
            ProviderErrorKind::ResourceExhausted,
        ),
        (
            FederationLocalStatusError::AdmissionClosed,
            ProviderErrorKind::Unavailable,
        ),
        (
            FederationLocalStatusError::Mint(cdk::Error::Federation(
                FederationError::UnknownMember {
                    member_id: member(9),
                },
            )),
            ProviderErrorKind::InvalidArgument,
        ),
        (
            FederationLocalStatusError::Mint(cdk::Error::Federation(
                FederationError::ConflictingOperation {
                    conflict_key: "quote:test".to_string(),
                    existing_operation_id: "existing".to_string(),
                    attempted_operation_id: "attempted".to_string(),
                },
            )),
            ProviderErrorKind::FailedPrecondition,
        ),
        (
            FederationLocalStatusError::Mint(cdk::Error::Federation(
                FederationError::RuntimeUnavailable {
                    component: "consensus",
                },
            )),
            ProviderErrorKind::Unavailable,
        ),
        (
            FederationLocalStatusError::Internal(anyhow::anyhow!("secret=hidden")),
            ProviderErrorKind::Internal,
        ),
    ];

    for (error, kind) in cases {
        let mapped = status_error(error);
        assert_eq!(mapped.kind(), kind);
        assert!(!mapped.message().contains("hidden"));
    }
}

fn member_result(
    member_id: u16,
    local: bool,
    status: Result<FederationLocalStatusResponse, String>,
) -> FederationMemberLocalStatus {
    FederationMemberLocalStatus {
        member_id: member(member_id),
        local,
        latency: Duration::from_millis(12),
        status,
    }
}

#[test]
fn member_statuses_report_unreachable_members_and_compare_the_rest() {
    let (config, _) = federation_fixture();
    let members = [
        member_result(1, false, Ok(local_status(&config, 1, 4))),
        member_result(2, true, Ok(local_status(&config, 2, 4))),
        member_result(3, false, Err("connection refused".to_string())),
    ];
    let members = members.iter().collect::<Vec<_>>();

    let response = member_statuses_response(&members, 10, 1_700_000_000);

    assert_eq!(response.queried_at_unix, 1_700_000_000);
    assert_eq!(
        response
            .members
            .iter()
            .map(|member| (member.member_id, member.local, member.reachable))
            .collect::<Vec<_>>(),
        vec![(1, false, true), (2, true, true), (3, false, false)]
    );
    assert_eq!(response.members[0].latency_ms, 12);
    assert!(response.members[0].error.is_none());
    assert!(response.members[2].status.is_none());
    assert_eq!(
        response.members[2].error.as_deref(),
        Some("connection refused")
    );
    let agreement = response.digest_agreement.expect("digest agreement");
    assert_eq!(agreement.state(), proto::DigestAgreementState::Converged);
    assert_eq!(agreement.compared_members, vec![1, 2]);
    assert_eq!(agreement.groups.len(), 1);
    assert_eq!(agreement.groups[0].members, vec![1, 2]);
    assert_eq!(agreement.groups[0].ready_count, 2);
    assert!(agreement.conflicts.is_empty());
}

#[test]
fn digest_agreement_separates_lag_from_conflicts() {
    let (config, _) = federation_fixture();

    let nobody = digest_agreement(&DigestAgreement::from_statuses(&[]));
    assert_eq!(nobody.state(), proto::DigestAgreementState::Unknown);

    let behind = [local_status(&config, 1, 5), local_status(&config, 2, 4)];
    let behind = digest_agreement(&DigestAgreement::from_statuses(&behind));
    assert_eq!(behind.state(), proto::DigestAgreementState::Converging);
    assert_eq!(behind.groups.len(), 2);
    assert_eq!(behind.groups[0].operation_count, 4);
    assert!(behind.conflicts.is_empty());

    let mut forked = local_status(&config, 3, 5);
    forked.peer_status.latest_order_digest = FederationJournalDigest::from_bytes([9; 32]);
    let diverged = [local_status(&config, 1, 5), forked];
    let diverged = digest_agreement(&DigestAgreement::from_statuses(&diverged));
    assert_eq!(diverged.state(), proto::DigestAgreementState::Diverged);
    assert_eq!(diverged.conflicts.len(), 1);
    assert_eq!(
        diverged.conflicts[0].kind(),
        proto::DigestConflictKind::OrderDigest
    );
    assert_eq!(diverged.conflicts[0].first_member_id, 1);
    assert_eq!(diverged.conflicts[0].second_member_id, 3);
    assert_eq!(diverged.conflicts[0].operation_count, 5);

    let mut alerting = local_status(&config, 2, 5);
    alerting
        .checkpoint
        .frontier
        .materialized_state_audit_mismatch = true;
    let alerted = [local_status(&config, 1, 5), alerting];
    let alerted = digest_agreement(&DigestAgreement::from_statuses(&alerted));
    assert_eq!(alerted.state(), proto::DigestAgreementState::Diverged);
    assert_eq!(alerted.digest_alert_members, vec![2]);
}

#[test]
fn custody_status_maps_wallet_blocks() {
    let custody = FederationCustodyStatus {
        onchain_wallets: vec![FederationOnchainWalletStatus {
            source: "esplora".to_string(),
            source_scope: "independent".to_string(),
            source_id: "source-1".to_string(),
            correlated_source_warning: false,
            health: "healthy".to_string(),
            local_tip_height: 120,
            local_tip_hash: "00ff".to_string(),
            last_success_unix: Some(1_700_000_000),
            consecutive_failures: 0,
        }],
        wallet_recovery: Some(FederationWalletRecoveryStatus {
            version: 1,
            address_allocations: 2,
            wallet_utxos: 3,
            payment_intents: 0,
            transactions: 1,
            sticky_reservations: 0,
            actions: vec![FederationRecoveryActionCount {
                phase: FederationRecoveryPhase::Signing,
                state: "awaiting_signatures".to_string(),
                action: FederationRecoveryAction::StartFreshSigningAttempt,
                count: 1,
            }],
        }),
        wallet_liveness: Some(FederationWalletLivenessStatus {
            activity: FederationWalletLivenessActivity::Signing,
            signing_attempts: 4,
            ..Default::default()
        }),
        wallet_operator: Some(FederationWalletOperatorStatus {
            version: 1,
            root_key_epoch: 1,
            application_key_epoch: 2,
            descriptor_commitment: [0xab; 32],
            network: "regtest".to_string(),
            minimum_confirmations: 3,
            fee_policy_version: 1,
            external_revealed_count: 5,
            internal_revealed_count: 1,
            utxos: vec![FederationWalletUtxoStatusCount {
                state: FederationWalletUtxoState::Spendable,
                count: 2,
                value_sat: 21_000,
            }],
            reserved_value_sat: 0,
            operation_phases: vec![FederationWalletOperationPhaseCount {
                phase: FederationWalletOperationPhase::Confirmation,
                count: 1,
            }],
            pending_batches: 0,
            signing_attempts: 4,
            signing_failures: 1,
            broadcast_health: FederationWalletBroadcastHealth::Confirming,
            broadcast_failures: 0,
        }),
        application_operators: BTreeMap::new(),
    };

    let mapped = custody_status(&custody).expect("custody status");

    assert_eq!(mapped.onchain_wallets.len(), 1);
    assert_eq!(mapped.onchain_wallets[0].source, "esplora");
    assert_eq!(
        mapped.onchain_wallets[0].health(),
        proto::OnchainSourceHealth::Healthy
    );
    assert_eq!(mapped.onchain_wallets[0].local_tip_height, 120);
    let recovery = mapped.wallet_recovery.expect("recovery");
    assert_eq!(recovery.address_allocations, 2);
    assert_eq!(
        recovery.actions[0].phase(),
        proto::WalletRecoveryPhase::Signing
    );
    assert_eq!(
        recovery.actions[0].action(),
        proto::WalletRecoveryAction::StartFreshSigningAttempt
    );
    assert_eq!(recovery.actions[0].state, "awaiting_signatures");
    let liveness = mapped.wallet_liveness.expect("liveness");
    assert_eq!(liveness.activity(), proto::WalletLivenessActivity::Signing);
    assert_eq!(liveness.signing_attempts, 4);
    let wallet = mapped.wallet_operator.expect("wallet operator");
    assert_eq!(wallet.descriptor_commitment, "ab".repeat(32));
    assert_eq!(wallet.utxos[0].state(), proto::WalletUtxoState::Spendable);
    assert_eq!(wallet.utxos[0].value_sat, 21_000);
    assert_eq!(
        wallet.operation_phases[0].phase(),
        proto::WalletOperationPhase::Confirmation
    );
    assert_eq!(
        wallet.broadcast_health(),
        proto::WalletBroadcastHealth::Confirming
    );
    assert!(mapped.bark.is_none());
}
