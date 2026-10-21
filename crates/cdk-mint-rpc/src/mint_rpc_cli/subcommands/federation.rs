use anyhow::Result;
use cdk_common::terminal::escape_control;
use clap::{Args, Subcommand};
use serde_json::{json, Value};
use tonic::transport::Channel;
use tonic::Request;

use super::output::{list, number, text, OutputCommand};
use crate::federation::federation_service_client::FederationServiceClient;
use crate::federation::{
    BarkOperatorStatus, CheckpointStatus, DigestAgreement, GetCustodyStatusRequest,
    GetCustodyStatusResponse, GetFederationInfoRequest, GetFederationInfoResponse,
    GetLocalStatusRequest, GetMemberStatusesRequest, GetMemberStatusesResponse, MemberStatus,
    MemberStatusResult, OnchainWalletSource, PaymentObservationReport, PaymentObservationSummary,
    PaymentVerificationPolicy, WalletLivenessStatus, WalletOperatorStatus, WalletRecoveryStatus,
};

/// Read-only status commands for a running federation member.
#[derive(Debug, Subcommand)]
pub enum FederationCommand {
    /// Show the federation config this member runs
    Info(OutputCommand),
    /// Show this member's own status
    Status(FederationStatusCommand),
    /// Ask members for their status and compare their digests
    Members(FederationMembersCommand),
    /// Show on-chain wallet and Bark custody status
    Custody(OutputCommand),
}

/// Arguments for the local status command.
#[derive(Debug, Args)]
pub struct FederationStatusCommand {
    /// Maximum payment observation reports to list; zero uses the server default
    #[arg(long, default_value_t = 0)]
    payment_report_limit: u32,
    /// Print JSON instead of text
    #[arg(long, default_value_t = false)]
    json: bool,
}

/// Arguments for the member status command.
#[derive(Debug, Args)]
pub struct FederationMembersCommand {
    /// Member to query; repeat to query several. Queries every member when omitted
    #[arg(long = "member")]
    members: Vec<u32>,
    /// Maximum payment observation reports to list per member; zero uses the server default
    #[arg(long, default_value_t = 0)]
    payment_report_limit: u32,
    /// Print JSON instead of text
    #[arg(long, default_value_t = false)]
    json: bool,
}

/// Runs one federation status command.
pub async fn federation(
    client: &mut FederationServiceClient<Channel>,
    command: &FederationCommand,
) -> Result<()> {
    match command {
        FederationCommand::Info(args) => info(client, args).await,
        FederationCommand::Status(args) => status(client, args).await,
        FederationCommand::Members(args) => members(client, args).await,
        FederationCommand::Custody(args) => custody(client, args).await,
    }
}

async fn info(client: &mut FederationServiceClient<Channel>, args: &OutputCommand) -> Result<()> {
    let info = client
        .get_federation_info(Request::new(GetFederationInfoRequest {}))
        .await?
        .into_inner();

    match args.json {
        true => println!("{}", serde_json::to_string_pretty(&info_json(&info))?),
        false => print_info(&info),
    }

    Ok(())
}

async fn status(
    client: &mut FederationServiceClient<Channel>,
    args: &FederationStatusCommand,
) -> Result<()> {
    let response = client
        .get_local_status(Request::new(GetLocalStatusRequest {
            payment_report_limit: args.payment_report_limit,
        }))
        .await?
        .into_inner();
    let status = response.status.unwrap_or_default();

    match args.json {
        true => println!(
            "{}",
            serde_json::to_string_pretty(&member_status_json(&status))?
        ),
        false => print_member_status(&status),
    }

    Ok(())
}

async fn members(
    client: &mut FederationServiceClient<Channel>,
    args: &FederationMembersCommand,
) -> Result<()> {
    let response = client
        .get_member_statuses(Request::new(GetMemberStatusesRequest {
            member_ids: args.members.clone(),
            payment_report_limit: args.payment_report_limit,
        }))
        .await?
        .into_inner();

    match args.json {
        true => println!(
            "{}",
            serde_json::to_string_pretty(&members_json(&response))?
        ),
        false => print_members(&response),
    }

    Ok(())
}

async fn custody(
    client: &mut FederationServiceClient<Channel>,
    args: &OutputCommand,
) -> Result<()> {
    let response = client
        .get_custody_status(Request::new(GetCustodyStatusRequest {}))
        .await?
        .into_inner();

    match args.json {
        true => println!(
            "{}",
            serde_json::to_string_pretty(&custody_json(&response))?
        ),
        false => print_custody(&response),
    }

    Ok(())
}

/// Lowercases a proto enum name without its type prefix.
fn short_name(name: &str, prefix: &str) -> String {
    name.strip_prefix(prefix)
        .unwrap_or(name)
        .to_ascii_lowercase()
}

fn policy_text(policy: Option<&PaymentVerificationPolicy>) -> String {
    match policy {
        Some(policy) => format!(
            "{}({})",
            short_name(
                policy.kind().as_str_name(),
                "PAYMENT_VERIFICATION_POLICY_KIND_"
            ),
            policy.required_observations
        ),
        None => "none".to_string(),
    }
}

fn policy_json(policy: Option<&PaymentVerificationPolicy>) -> Value {
    match policy {
        Some(policy) => json!({
            "kind": short_name(policy.kind().as_str_name(), "PAYMENT_VERIFICATION_POLICY_KIND_"),
            "required_observations": policy.required_observations,
        }),
        None => Value::Null,
    }
}

fn print_info(info: &GetFederationInfoResponse) {
    println!("federation_id: {}", escape_control(&info.federation_id));
    println!("local_member_id: {}", info.local_member_id);
    println!("config_digest: {}", escape_control(&info.config_digest));
    println!("wallet_protocol_version: {}", info.wallet_protocol_version);
    let thresholds = info.threshold_params.unwrap_or_default();
    println!(
        "members: {} (signature threshold {}, consensus threshold {})",
        thresholds.member_count, thresholds.signature_threshold, thresholds.consensus_threshold
    );
    for member in &info.members {
        println!(
            "member {}: {} federation_api={} identity={}",
            member.member_id,
            escape_control(&member.public_mint_url),
            escape_control(&member.federation_api_url),
            escape_control(&member.identity_public_key)
        );
    }
    for keyset in &info.keysets {
        println!(
            "keyset {}: unit={} active={} input_fee_ppk={} final_expiry={}",
            escape_control(&keyset.id),
            escape_control(&keyset.unit),
            keyset.active,
            keyset.input_fee_ppk,
            number(keyset.final_expiry)
        );
    }
    let policy = info.payment_observation_policy.as_ref();
    println!(
        "payment_observation_policy: mint_quotes={} melt_quotes={}",
        policy_text(policy.and_then(|policy| policy.mint_quotes.as_ref())),
        policy_text(policy.and_then(|policy| policy.melt_quotes.as_ref()))
    );
}

fn info_json(info: &GetFederationInfoResponse) -> Value {
    let thresholds = info.threshold_params.unwrap_or_default();
    let policy = info.payment_observation_policy.as_ref();
    json!({
        "federation_id": info.federation_id,
        "local_member_id": info.local_member_id,
        "config_digest": info.config_digest,
        "wallet_protocol_version": info.wallet_protocol_version,
        "threshold_params": {
            "member_count": thresholds.member_count,
            "signature_threshold": thresholds.signature_threshold,
            "consensus_threshold": thresholds.consensus_threshold,
        },
        "members": info.members.iter().map(|member| json!({
            "member_id": member.member_id,
            "public_mint_url": member.public_mint_url,
            "federation_api_url": member.federation_api_url,
            "identity_public_key": member.identity_public_key,
        })).collect::<Vec<_>>(),
        "keysets": info.keysets.iter().map(|keyset| json!({
            "id": keyset.id,
            "unit": keyset.unit,
            "active": keyset.active,
            "input_fee_ppk": keyset.input_fee_ppk,
            "final_expiry": keyset.final_expiry,
        })).collect::<Vec<_>>(),
        "payment_observation_policy": {
            "mint_quotes": policy_json(policy.and_then(|policy| policy.mint_quotes.as_ref())),
            "melt_quotes": policy_json(policy.and_then(|policy| policy.melt_quotes.as_ref())),
        },
    })
}

fn member_status_line(status: &MemberStatus) -> String {
    let sync = status.sync.clone().unwrap_or_default();
    let peer = status.peer.clone().unwrap_or_default();
    let consensus = status.consensus.unwrap_or_default();
    let checkpoint = status.checkpoint.clone().unwrap_or_default();
    format!(
        "sync={} ready={} operations={} latest_index={} session={} order_digest={} application_digest={} live_session={} network_inbound={} audit_mismatch={} trusted_checkpoint={} checkpoint_lag_operations={}",
        escape_control(&sync.state),
        sync.ready,
        peer.operation_count,
        number(peer.latest_index),
        peer.aleph_bft_session,
        escape_control(&peer.latest_order_digest),
        text(peer.application_digest.as_deref()),
        consensus.live_session_active,
        consensus.network_inbound_active,
        checkpoint.audit_mismatch,
        text(checkpoint.trusted_checkpoint_id.as_deref()),
        checkpoint.lag_from_trusted_checkpoint
    )
}

fn print_member_status(status: &MemberStatus) {
    println!(
        "member {}: {}",
        status.member_id,
        member_status_line(status)
    );
    println!("federation_id: {}", escape_control(&status.federation_id));
    let sync = status.sync.clone().unwrap_or_default();
    println!("sync_message: {}", escape_control(&sync.message));
    if let Some(peer) = sync.peer_member_id {
        println!(
            "sync_peer: {} local_operations={} peer_operations={} operations={}",
            peer,
            number(sync.local_operation_count),
            number(sync.peer_operation_count),
            number(sync.operation_count)
        );
    }
    let queues = status.queues.unwrap_or_default();
    println!(
        "queues: pending_mempool_items={} pending_response_waiters={} response_cache_items={} response_cache_hits={}/{} response_cache_hit_rate_bps={} duplicate_submissions={} duplicate_pending_waiter_joins={}",
        queues.pending_mempool_items,
        queues.pending_response_waiters,
        queues.response_cache_items,
        queues.response_cache_hits,
        queues.response_cache_lookups,
        queues.response_cache_hit_rate_bps,
        queues.duplicate_submissions,
        queues.duplicate_pending_waiter_joins
    );
    if let Some(runtime) = status.consensus.and_then(|consensus| consensus.runtime) {
        println!(
            "consensus_runtime: session={} next_item={} queued={} pending_finalization={} finalized={} accepted={} latest_accepted={}",
            runtime.session,
            runtime.next_item_index,
            runtime.queued_item_count,
            runtime.pending_finalization_item_count,
            runtime.finalized_item_count,
            runtime.accepted_operation_count,
            number(runtime.latest_accepted_operation_index)
        );
    }
    print_checkpoint(&status.checkpoint.clone().unwrap_or_default());
    print_payment_observations(&status.payment_observations.clone().unwrap_or_default());
    for alert in &status.invalid_operation_alerts {
        println!(
            "invalid_operation_alert source={} alerting_buckets={} max_count={} threshold={} window_secs={}",
            escape_control(&alert.source),
            alert.alerting_buckets,
            alert.max_count,
            alert.threshold,
            alert.window_secs
        );
    }
}

fn print_checkpoint(checkpoint: &CheckpointStatus) {
    println!(
        "checkpoint: journal_next_index={} finalized_next_item_index={} application_next_index={} trusted={} trusted_signers={} trusted_operations={} latest_scheduled={} latest_scheduled_quorum={} latest_recovery_quorum={}",
        checkpoint.journal_next_index,
        checkpoint.finalized_next_item_index,
        checkpoint.application_next_index,
        text(checkpoint.trusted_checkpoint_id.as_deref()),
        list(&checkpoint.trusted_checkpoint_signers),
        number(checkpoint.trusted_checkpoint_operation_count),
        text(checkpoint.latest_scheduled_checkpoint_id.as_deref()),
        text(checkpoint.latest_scheduled_quorum_id.as_deref()),
        text(checkpoint.latest_recovery_quorum_id.as_deref())
    );
}

fn print_payment_observations(summary: &PaymentObservationSummary) {
    println!(
        "payment_reports: total={} empty={} awaiting_quorum={} quorum_reached={} conflicting={} stale={} inspect={} listed={} truncated={}",
        summary.total_reports,
        summary.empty,
        summary.awaiting_quorum,
        summary.quorum_reached,
        summary.conflicting,
        summary.stale,
        summary.inspect,
        summary.reports.len(),
        summary.truncated
    );
    for report in &summary.reports {
        println!("{}", payment_report_line(report));
    }
}

fn payment_report_line(report: &PaymentObservationReport) -> String {
    format!(
        "  payment_report context={} quote={} status={} action={} observations={} required={} quote_age_secs={} stale={} conflicts={} terminal_conflicts={}",
        short_name(report.context().as_str_name(), "PAYMENT_OBSERVATION_CONTEXT_"),
        escape_control(&report.quote),
        short_name(report.status().as_str_name(), "PAYMENT_OBSERVATION_REPORT_STATUS_"),
        short_name(
            report.recommended_action().as_str_name(),
            "PAYMENT_OBSERVATION_REPORT_ACTION_"
        ),
        report.total_observations,
        report.required,
        number(report.quote_age_secs),
        report.stale,
        list(&report.conflicting_observers),
        list(&report.competing_terminal_state_observers)
    )
}

fn member_status_json(status: &MemberStatus) -> Value {
    let sync = status.sync.clone().unwrap_or_default();
    let peer = status.peer.clone().unwrap_or_default();
    let queues = status.queues.unwrap_or_default();
    let consensus = status.consensus.unwrap_or_default();
    let checkpoint = status.checkpoint.clone().unwrap_or_default();
    json!({
        "member_id": status.member_id,
        "federation_id": status.federation_id,
        "sync": {
            "state": sync.state,
            "ready": sync.ready,
            "message": sync.message,
            "peer_member_id": sync.peer_member_id,
            "local_operation_count": sync.local_operation_count,
            "peer_operation_count": sync.peer_operation_count,
            "operation_count": sync.operation_count,
        },
        "peer": {
            "operation_count": peer.operation_count,
            "latest_index": peer.latest_index,
            "aleph_bft_session": peer.aleph_bft_session,
            "aleph_bft_next_item_index": peer.aleph_bft_next_item_index,
            "latest_order_digest": peer.latest_order_digest,
            "application_digest": peer.application_digest,
            "latest_audited_checkpoint_id": peer.latest_audited_checkpoint_id,
            "materialized_state_digest": peer.materialized_state_digest,
        },
        "queues": {
            "pending_mempool_items": queues.pending_mempool_items,
            "pending_response_waiters": queues.pending_response_waiters,
            "response_cache_items": queues.response_cache_items,
            "response_cache_lookups": queues.response_cache_lookups,
            "response_cache_hits": queues.response_cache_hits,
            "response_cache_hit_rate_bps": queues.response_cache_hit_rate_bps,
            "duplicate_submissions": queues.duplicate_submissions,
            "duplicate_pending_waiter_joins": queues.duplicate_pending_waiter_joins,
        },
        "consensus": {
            "live_session_active": consensus.live_session_active,
            "network_inbound_active": consensus.network_inbound_active,
            "runtime": consensus.runtime.map(|runtime| json!({
                "session": runtime.session,
                "next_item_index": runtime.next_item_index,
                "queued_item_count": runtime.queued_item_count,
                "pending_finalization_item_count": runtime.pending_finalization_item_count,
                "finalized_item_count": runtime.finalized_item_count,
                "accepted_operation_count": runtime.accepted_operation_count,
                "latest_accepted_operation_index": runtime.latest_accepted_operation_index,
            })),
        },
        "checkpoint": {
            "journal_next_index": checkpoint.journal_next_index,
            "finalized_next_item_index": checkpoint.finalized_next_item_index,
            "application_next_index": checkpoint.application_next_index,
            "audit_mismatch": checkpoint.audit_mismatch,
            "trusted_checkpoint_id": checkpoint.trusted_checkpoint_id,
            "trusted_checkpoint_signers": checkpoint.trusted_checkpoint_signers,
            "trusted_checkpoint_operation_count": checkpoint.trusted_checkpoint_operation_count,
            "lag_from_trusted_checkpoint": checkpoint.lag_from_trusted_checkpoint,
            "latest_scheduled_checkpoint_id": checkpoint.latest_scheduled_checkpoint_id,
            "latest_scheduled_quorum_id": checkpoint.latest_scheduled_quorum_id,
            "latest_recovery_quorum_id": checkpoint.latest_recovery_quorum_id,
            "active_session_backup": checkpoint.active_session_backup.map(|backup| json!({
                "session": backup.session,
                "chunk_count": backup.chunk_count,
                "total_bytes": backup.total_bytes,
            })),
        },
        "payment_observations": payment_observations_json(
            &status.payment_observations.clone().unwrap_or_default()
        ),
        "invalid_operation_alerts": status.invalid_operation_alerts.iter().map(|alert| json!({
            "source": alert.source,
            "alerting_buckets": alert.alerting_buckets,
            "max_count": alert.max_count,
            "threshold": alert.threshold,
            "window_secs": alert.window_secs,
        })).collect::<Vec<_>>(),
    })
}

fn payment_observations_json(summary: &PaymentObservationSummary) -> Value {
    json!({
        "total_reports": summary.total_reports,
        "empty": summary.empty,
        "awaiting_quorum": summary.awaiting_quorum,
        "quorum_reached": summary.quorum_reached,
        "conflicting": summary.conflicting,
        "stale": summary.stale,
        "inspect": summary.inspect,
        "truncated": summary.truncated,
        "reports": summary.reports.iter().map(|report| json!({
            "context": short_name(report.context().as_str_name(), "PAYMENT_OBSERVATION_CONTEXT_"),
            "quote": report.quote,
            "status": short_name(report.status().as_str_name(), "PAYMENT_OBSERVATION_REPORT_STATUS_"),
            "recommended_action": short_name(
                report.recommended_action().as_str_name(),
                "PAYMENT_OBSERVATION_REPORT_ACTION_"
            ),
            "required": report.required,
            "total_observations": report.total_observations,
            "quote_age_secs": report.quote_age_secs,
            "stale": report.stale,
            "conflicting_observers": report.conflicting_observers,
            "competing_terminal_state_observers": report.competing_terminal_state_observers,
            "groups": report.groups.iter().map(|group| json!({
                "state": group.state,
                "observers": group.observers,
                "quorum_reached": group.quorum_reached,
                "terminal_state": group.terminal_state,
                "conflicting_observers": group.conflicting_observers,
                "operation_indices": group.operation_indices,
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
    })
}

fn print_members(response: &GetMemberStatusesResponse) {
    println!("queried_at_unix: {}", response.queried_at_unix);
    for member in &response.members {
        println!("{}", member_result_line(member));
    }
    print_digest_agreement(&response.digest_agreement.clone().unwrap_or_default());
}

fn member_result_line(member: &MemberStatusResult) -> String {
    let label = match member.local {
        true => format!("member {} (local)", member.member_id),
        false => format!("member {}", member.member_id),
    };
    match (&member.status, member.reachable) {
        (Some(status), true) => format!(
            "{label}: reachable latency_ms={} {}",
            member.latency_ms,
            member_status_line(status)
        ),
        _ => format!(
            "{label}: unreachable latency_ms={} error={}",
            member.latency_ms,
            text(member.error.as_deref())
        ),
    }
}

fn digest_agreement_state(agreement: &DigestAgreement) -> String {
    short_name(agreement.state().as_str_name(), "DIGEST_AGREEMENT_STATE_")
}

fn print_digest_agreement(agreement: &DigestAgreement) {
    println!(
        "digest_agreement: {} compared={} digest_alerts={} missing_application_digest={}",
        digest_agreement_state(agreement),
        list(&agreement.compared_members),
        list(&agreement.digest_alert_members),
        list(&agreement.missing_application_digest_members)
    );
    for group in &agreement.groups {
        println!(
            "  digest_group operations={} session={} order_digest={} application_digest={} members={} ready={}/{}",
            group.operation_count,
            group.aleph_bft_session,
            escape_control(&group.order_digest),
            text(group.application_digest.as_deref()),
            list(&group.members),
            group.ready_count,
            group.members.len()
        );
    }
    for conflict in &agreement.conflicts {
        println!(
            "  digest_conflict kind={} members={},{} operations={}",
            short_name(conflict.kind().as_str_name(), "DIGEST_CONFLICT_KIND_"),
            conflict.first_member_id,
            conflict.second_member_id,
            conflict.operation_count
        );
    }
}

fn members_json(response: &GetMemberStatusesResponse) -> Value {
    let agreement = response.digest_agreement.clone().unwrap_or_default();
    json!({
        "queried_at_unix": response.queried_at_unix,
        "members": response.members.iter().map(|member| json!({
            "member_id": member.member_id,
            "local": member.local,
            "reachable": member.reachable,
            "latency_ms": member.latency_ms,
            "error": member.error,
            "status": member.status.as_ref().map(member_status_json),
        })).collect::<Vec<_>>(),
        "digest_agreement": {
            "state": digest_agreement_state(&agreement),
            "compared_members": agreement.compared_members,
            "digest_alert_members": agreement.digest_alert_members,
            "missing_application_digest_members": agreement.missing_application_digest_members,
            "groups": agreement.groups.iter().map(|group| json!({
                "operation_count": group.operation_count,
                "aleph_bft_session": group.aleph_bft_session,
                "order_digest": group.order_digest,
                "application_digest": group.application_digest,
                "members": group.members,
                "ready_count": group.ready_count,
            })).collect::<Vec<_>>(),
            "conflicts": agreement.conflicts.iter().map(|conflict| json!({
                "kind": short_name(conflict.kind().as_str_name(), "DIGEST_CONFLICT_KIND_"),
                "first_member_id": conflict.first_member_id,
                "second_member_id": conflict.second_member_id,
                "operation_count": conflict.operation_count,
            })).collect::<Vec<_>>(),
        },
    })
}

fn print_custody(response: &GetCustodyStatusResponse) {
    if response.onchain_wallets.is_empty()
        && response.wallet_operator.is_none()
        && response.wallet_recovery.is_none()
        && response.wallet_liveness.is_none()
        && response.bark.is_none()
    {
        println!("custody: none");
        return;
    }
    for source in &response.onchain_wallets {
        println!("{}", onchain_source_line(source));
    }
    if let Some(wallet) = &response.wallet_operator {
        println!("{}", wallet_operator_line(wallet));
    }
    if let Some(recovery) = &response.wallet_recovery {
        print_wallet_recovery(recovery);
    }
    if let Some(liveness) = &response.wallet_liveness {
        println!("{}", wallet_liveness_line(liveness));
    }
    if let Some(bark) = &response.bark {
        println!("{}", bark_line(bark));
    }
}

fn onchain_source_line(source: &OnchainWalletSource) -> String {
    format!(
        "chain_source source={} scope={} id={} correlated={} health={} tip_height={} tip_hash={} last_success_unix={} failures={}",
        escape_control(&source.source),
        escape_control(&source.source_scope),
        escape_control(&source.source_id),
        source.correlated_source_warning,
        escape_control(&source.health),
        source.local_tip_height,
        escape_control(&source.local_tip_hash),
        number(source.last_success_unix),
        source.consecutive_failures
    )
}

fn wallet_operator_line(wallet: &WalletOperatorStatus) -> String {
    let utxos = wallet
        .utxos
        .iter()
        .map(|utxo| {
            format!(
                "{}:{}/{}sat",
                short_name(utxo.state().as_str_name(), "WALLET_UTXO_STATE_"),
                utxo.count,
                utxo.value_sat
            )
        })
        .collect::<Vec<_>>();
    let phases = wallet
        .operation_phases
        .iter()
        .map(|phase| {
            format!(
                "{}:{}",
                short_name(phase.phase().as_str_name(), "WALLET_OPERATION_PHASE_"),
                phase.count
            )
        })
        .collect::<Vec<_>>();
    format!(
        "wallet root_epoch={} application_epoch={} descriptor_commitment={} network={} confirmations={} fee_policy_version={} external_revealed={} internal_revealed={} utxos={} reserved_value_sat={} phases={} pending_batches={} signing_attempts={} signing_failures={} broadcast_health={} broadcast_failures={}",
        wallet.root_key_epoch,
        wallet.application_key_epoch,
        escape_control(&wallet.descriptor_commitment),
        escape_control(&wallet.network),
        wallet.minimum_confirmations,
        wallet.fee_policy_version,
        wallet.external_revealed_count,
        wallet.internal_revealed_count,
        list(&utxos),
        wallet.reserved_value_sat,
        list(&phases),
        wallet.pending_batches,
        wallet.signing_attempts,
        wallet.signing_failures,
        short_name(
            wallet.broadcast_health().as_str_name(),
            "WALLET_BROADCAST_HEALTH_"
        ),
        wallet.broadcast_failures
    )
}

fn print_wallet_recovery(recovery: &WalletRecoveryStatus) {
    println!(
        "wallet_recovery address_allocations={} wallet_utxos={} payment_intents={} transactions={} sticky_reservations={}",
        recovery.address_allocations,
        recovery.wallet_utxos,
        recovery.payment_intents,
        recovery.transactions,
        recovery.sticky_reservations
    );
    for action in &recovery.actions {
        println!(
            "  recovery_action phase={} state={} action={} count={}",
            short_name(action.phase().as_str_name(), "WALLET_RECOVERY_PHASE_"),
            escape_control(&action.state),
            short_name(action.action().as_str_name(), "WALLET_RECOVERY_ACTION_"),
            action.count
        );
    }
}

fn wallet_liveness_line(liveness: &WalletLivenessStatus) -> String {
    format!(
        "wallet_liveness activity={} pending_batches={} awaiting_signatures={} proposal_attempts={} signing_attempts={} signer_failures={}",
        short_name(
            liveness.activity().as_str_name(),
            "WALLET_LIVENESS_ACTIVITY_"
        ),
        liveness.pending_batches,
        liveness.awaiting_signatures,
        liveness.proposal_attempts,
        liveness.signing_attempts,
        liveness.signer_failures
    )
}

fn bark_line(bark: &BarkOperatorStatus) -> String {
    let vtxos = bark
        .vtxos
        .iter()
        .map(|vtxo| {
            format!(
                "{}:{}/{}sat",
                escape_control(&vtxo.state),
                vtxo.count,
                vtxo.value_sat
            )
        })
        .collect::<Vec<_>>();
    format!(
        "bark readiness={} degraded_reason={} accepted_frontier={} local_frontier={} lag_operations={} network={} chain_tip={} vtxos={} expiring_vtxos={} expiring_value_sat={} ambiguous_actions={} ambiguous_value_sat={} recovery_actions={} recovery_value_sat={} signer_retry_actions={} missing_acknowledged_receive_secrets={}",
        escape_control(&bark.readiness),
        text(bark.degraded_reason.as_deref()),
        bark.accepted_frontier,
        bark.local_frontier,
        bark.projection_lag_operations,
        escape_control(&bark.network),
        number(bark.chain_tip_height),
        list(&vtxos),
        number(bark.expiring_vtxo_count),
        number(bark.expiring_value_sat),
        bark.ambiguous_action_count,
        bark.ambiguous_value_sat,
        bark.recovery_required_action_count,
        bark.recovery_required_value_sat,
        bark.signer_retry_action_count,
        bark.missing_acknowledged_receive_secrets
    )
}

fn custody_json(response: &GetCustodyStatusResponse) -> Value {
    json!({
        "onchain_wallets": response.onchain_wallets.iter().map(|source| json!({
            "source": source.source,
            "source_scope": source.source_scope,
            "source_id": source.source_id,
            "correlated_source_warning": source.correlated_source_warning,
            "health": source.health,
            "local_tip_height": source.local_tip_height,
            "local_tip_hash": source.local_tip_hash,
            "last_success_unix": source.last_success_unix,
            "consecutive_failures": source.consecutive_failures,
        })).collect::<Vec<_>>(),
        "wallet_operator": response.wallet_operator.as_ref().map(|wallet| json!({
            "root_key_epoch": wallet.root_key_epoch,
            "application_key_epoch": wallet.application_key_epoch,
            "descriptor_commitment": wallet.descriptor_commitment,
            "network": wallet.network,
            "minimum_confirmations": wallet.minimum_confirmations,
            "fee_policy_version": wallet.fee_policy_version,
            "external_revealed_count": wallet.external_revealed_count,
            "internal_revealed_count": wallet.internal_revealed_count,
            "utxos": wallet.utxos.iter().map(|utxo| json!({
                "state": short_name(utxo.state().as_str_name(), "WALLET_UTXO_STATE_"),
                "count": utxo.count,
                "value_sat": utxo.value_sat,
            })).collect::<Vec<_>>(),
            "reserved_value_sat": wallet.reserved_value_sat,
            "operation_phases": wallet.operation_phases.iter().map(|phase| json!({
                "phase": short_name(phase.phase().as_str_name(), "WALLET_OPERATION_PHASE_"),
                "count": phase.count,
            })).collect::<Vec<_>>(),
            "pending_batches": wallet.pending_batches,
            "signing_attempts": wallet.signing_attempts,
            "signing_failures": wallet.signing_failures,
            "broadcast_health": short_name(
                wallet.broadcast_health().as_str_name(),
                "WALLET_BROADCAST_HEALTH_"
            ),
            "broadcast_failures": wallet.broadcast_failures,
        })),
        "wallet_recovery": response.wallet_recovery.as_ref().map(|recovery| json!({
            "address_allocations": recovery.address_allocations,
            "wallet_utxos": recovery.wallet_utxos,
            "payment_intents": recovery.payment_intents,
            "transactions": recovery.transactions,
            "sticky_reservations": recovery.sticky_reservations,
            "actions": recovery.actions.iter().map(|action| json!({
                "phase": short_name(action.phase().as_str_name(), "WALLET_RECOVERY_PHASE_"),
                "state": action.state,
                "action": short_name(action.action().as_str_name(), "WALLET_RECOVERY_ACTION_"),
                "count": action.count,
            })).collect::<Vec<_>>(),
        })),
        "wallet_liveness": response.wallet_liveness.as_ref().map(|liveness| json!({
            "activity": short_name(liveness.activity().as_str_name(), "WALLET_LIVENESS_ACTIVITY_"),
            "pending_batches": liveness.pending_batches,
            "awaiting_signatures": liveness.awaiting_signatures,
            "proposal_attempts": liveness.proposal_attempts,
            "signing_attempts": liveness.signing_attempts,
            "signer_failures": liveness.signer_failures,
        })),
        "bark": response.bark.as_ref().map(|bark| {
            // Re-encoding escapes any control characters inside the server's strings.
            let details = serde_json::from_str::<Value>(&bark.details_json).unwrap_or(Value::Null);
            json!({
                "readiness": bark.readiness,
                "degraded_reason": bark.degraded_reason,
                "accepted_frontier": bark.accepted_frontier,
                "local_frontier": bark.local_frontier,
                "projection_lag_operations": bark.projection_lag_operations,
                "network": bark.network,
                "chain_tip_height": bark.chain_tip_height,
                "vtxos": bark.vtxos.iter().map(|vtxo| json!({
                    "state": vtxo.state,
                    "count": vtxo.count,
                    "value_sat": vtxo.value_sat,
                })).collect::<Vec<_>>(),
                "expiring_vtxo_count": bark.expiring_vtxo_count,
                "expiring_value_sat": bark.expiring_value_sat,
                "ambiguous_action_count": bark.ambiguous_action_count,
                "ambiguous_value_sat": bark.ambiguous_value_sat,
                "recovery_required_action_count": bark.recovery_required_action_count,
                "recovery_required_value_sat": bark.recovery_required_value_sat,
                "signer_retry_action_count": bark.signer_retry_action_count,
                "missing_acknowledged_receive_secrets": bark.missing_acknowledged_receive_secrets,
                "details": details,
            })
        }),
    })
}
