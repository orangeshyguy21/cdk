use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use cdk_common::terminal::escape_control;
use clap::{Args, Subcommand};
use tonic::transport::Channel;
use tonic::Request;

use super::output::{list, number, text, OutputCommand};
use crate::federation_setup::federation_setup_service_client::FederationSetupServiceClient;
use crate::federation_setup::{
    ActivateSetupRequest, ApproveProposalRequest, CreateSetupRequest, GetSetupStatusRequest,
    GetSetupStatusResponse, JoinSetupRequest, ProposeSetupRequest, ReviewProposalRequest,
    SetupKeyset,
};

/// Largest invitation file the CLI will read.
const MAX_INVITATION_FILE_BYTES: u64 = 64 * 1024;

/// Federation setup commands for a daemon running in setup mode.
#[derive(Debug, Subcommand)]
pub enum FederationSetupCommand {
    /// Create a new federation setup with this daemon as the coordinator
    Create(CreateSetupCommand),
    /// Join a federation setup using an invitation file
    Join(JoinSetupCommand),
    /// Freeze every enrollment into one proposal (coordinator only)
    Propose,
    /// Show the proposal this member is about to approve
    Review(OutputCommand),
    /// Approve the proposal with exactly this hash
    Approve(ApproveSetupCommand),
    /// Show setup and key generation progress
    Status(OutputCommand),
    /// Activate the finished federation and restart as a federation member
    Activate,
}

/// Arguments for creating a federation setup.
#[derive(Debug, Args)]
pub struct CreateSetupCommand {
    /// Total number of members, including this one
    #[arg(long)]
    members: u32,
    /// Number of members needed to sign
    #[arg(long)]
    threshold: u32,
    /// Bitcoin network: bitcoin, testnet, signet, or regtest
    #[arg(long)]
    network: String,
    /// Directory to write one invitation file per joining member
    #[arg(long)]
    output_dir: PathBuf,
    /// Members needed to observe a payment; defaults to the consensus threshold
    #[arg(long)]
    payment_observation_threshold: Option<u32>,
    /// Invitation lifetime in seconds; defaults to one day
    #[arg(long)]
    invitation_lifetime_secs: Option<u64>,
    /// Keyset currency unit; defaults to sat
    #[arg(long)]
    unit: Option<String>,
    /// Keyset denominations, comma separated; defaults to 1,2,4,...,128
    #[arg(long, value_delimiter = ',')]
    amounts: Vec<u64>,
    /// Keyset input fee in parts per thousand
    #[arg(long, default_value_t = 0)]
    input_fee_ppk: u64,
    /// Keyset final expiry as a unix timestamp
    #[arg(long)]
    final_expiry: Option<u64>,
    /// Public mint URL; defaults to the daemon's configured URL
    #[arg(long)]
    public_mint_url: Option<String>,
    /// Federation API URL; must differ from the public mint URL unless both are the same Iroh endpoint
    #[arg(long)]
    federation_api_url: Option<String>,
    /// Coordinator URL joining members dial; defaults to the federation API URL
    #[arg(long)]
    coordinator_url: Option<String>,
    /// Allow plain HTTP to localhost (development only)
    #[arg(long, default_value_t = false)]
    allow_insecure_localhost: bool,
}

/// Arguments for joining a federation setup.
#[derive(Debug, Args)]
pub struct JoinSetupCommand {
    /// File holding the invitation from the coordinator
    #[arg(long)]
    invitation_file: PathBuf,
    /// Public mint URL; defaults to the daemon's configured URL
    #[arg(long)]
    public_mint_url: Option<String>,
    /// Federation API URL; must differ from the public mint URL unless both are the same Iroh endpoint
    #[arg(long)]
    federation_api_url: Option<String>,
    /// Allow plain HTTP to localhost (development only)
    #[arg(long, default_value_t = false)]
    allow_insecure_localhost: bool,
}

/// Arguments for approving a proposal.
#[derive(Debug, Args)]
pub struct ApproveSetupCommand {
    /// Exact proposal hash shown by `review`
    #[arg(long)]
    proposal_hash: String,
}

/// Runs one federation setup command.
pub async fn federation_setup(
    client: &mut FederationSetupServiceClient<Channel>,
    command: &FederationSetupCommand,
) -> Result<()> {
    match command {
        FederationSetupCommand::Create(args) => create(client, args).await,
        FederationSetupCommand::Join(args) => join(client, args).await,
        FederationSetupCommand::Propose => propose(client).await,
        FederationSetupCommand::Review(args) => review(client, args).await,
        FederationSetupCommand::Approve(args) => approve(client, args).await,
        FederationSetupCommand::Status(args) => status(client, args).await,
        FederationSetupCommand::Activate => activate(client).await,
    }
}

async fn create(
    client: &mut FederationSetupServiceClient<Channel>,
    args: &CreateSetupCommand,
) -> Result<()> {
    // The server keeps its defaults for an empty unit or amount list
    let keyset = Some(SetupKeyset {
        unit: args.unit.clone().unwrap_or_default(),
        amounts: args.amounts.clone(),
        input_fee_ppk: args.input_fee_ppk,
        final_expiry: args.final_expiry,
    });
    let response = client
        .create_setup(Request::new(CreateSetupRequest {
            members: args.members,
            threshold: args.threshold,
            network: args.network.clone(),
            payment_observation_threshold: args.payment_observation_threshold,
            invitation_lifetime_secs: args.invitation_lifetime_secs,
            keyset,
            public_mint_url: args.public_mint_url.clone(),
            federation_api_url: args.federation_api_url.clone(),
            coordinator_url: args.coordinator_url.clone(),
            allow_insecure_localhost: args.allow_insecure_localhost,
        }))
        .await?
        .into_inner();

    std::fs::create_dir_all(&args.output_dir)
        .with_context(|| format!("failed to create {}", args.output_dir.display()))?;
    println!("setup_id: {}", escape_control(&response.setup_id));
    println!("member_id: {}", response.member_id);
    for invitation in &response.invitations {
        let path = args
            .output_dir
            .join(format!("member-{}.invite", invitation.member_id));
        write_private_file(&path, &format!("{}\n", invitation.invitation))?;
        println!(
            "member_{}_invitation: {}",
            invitation.member_id,
            path.display()
        );
    }

    Ok(())
}

async fn join(
    client: &mut FederationSetupServiceClient<Channel>,
    args: &JoinSetupCommand,
) -> Result<()> {
    let invitation = read_invitation_file(&args.invitation_file)?;
    let response = client
        .join_setup(Request::new(JoinSetupRequest {
            invitation,
            public_mint_url: args.public_mint_url.clone(),
            federation_api_url: args.federation_api_url.clone(),
            allow_insecure_localhost: args.allow_insecure_localhost,
        }))
        .await?
        .into_inner();

    println!("setup_id: {}", escape_control(&response.setup_id));
    println!("member_id: {}", response.member_id);

    Ok(())
}

async fn propose(client: &mut FederationSetupServiceClient<Channel>) -> Result<()> {
    let response = client
        .propose_setup(Request::new(ProposeSetupRequest {}))
        .await?
        .into_inner();

    println!("proposal_hash: {}", escape_control(&response.proposal_hash));

    Ok(())
}

async fn review(
    client: &mut FederationSetupServiceClient<Channel>,
    args: &OutputCommand,
) -> Result<()> {
    let review = client
        .review_proposal(Request::new(ReviewProposalRequest {}))
        .await?
        .into_inner();

    if args.json {
        // Re-encoding escapes any control characters inside the server's strings.
        let details: serde_json::Value = serde_json::from_str(&review.details_json)
            .context("server returned invalid review JSON")?;
        println!("{}", serde_json::to_string_pretty(&details)?);
        return Ok(());
    }

    println!("setup_id: {}", escape_control(&review.setup_id));
    println!(
        "proposed_federation_id: {}",
        escape_control(&review.proposed_federation_id)
    );
    println!("proposal_hash: {}", escape_control(&review.proposal_hash));
    println!("network: {}", escape_control(&review.network));
    println!(
        "members: {} (signature threshold {}, consensus threshold {})",
        review.member_count, review.signature_threshold, review.consensus_threshold
    );
    for member in &review.members {
        println!(
            "member {}: {} federation_api={} identity={}",
            member.member_id,
            escape_control(&member.public_mint_url),
            escape_control(&member.federation_api_url),
            escape_control(&member.identity_fingerprint)
        );
    }
    for keyset in &review.keysets {
        let amounts = keyset
            .amounts
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "keyset: unit={} amounts={} input_fee_ppk={}",
            escape_control(&keyset.unit),
            amounts,
            keyset.input_fee_ppk
        );
    }

    Ok(())
}

async fn approve(
    client: &mut FederationSetupServiceClient<Channel>,
    args: &ApproveSetupCommand,
) -> Result<()> {
    let response = client
        .approve_proposal(Request::new(ApproveProposalRequest {
            proposal_hash: args.proposal_hash.clone(),
        }))
        .await?
        .into_inner();

    println!(
        "approved_proposal_hash: {}",
        escape_control(&response.proposal_hash)
    );

    Ok(())
}

async fn status(
    client: &mut FederationSetupServiceClient<Channel>,
    args: &OutputCommand,
) -> Result<()> {
    let status = client
        .get_setup_status(Request::new(GetSetupStatusRequest {}))
        .await?
        .into_inner();

    match args.json {
        true => println!("{}", serde_json::to_string_pretty(&status_json(&status))?),
        false => print_status(&status),
    }

    Ok(())
}

async fn activate(client: &mut FederationSetupServiceClient<Channel>) -> Result<()> {
    let response = client
        .activate_setup(Request::new(ActivateSetupRequest {}))
        .await?
        .into_inner();

    eprintln!("{}", escape_control(&response.backup_warning));
    println!("activated: true");
    println!("setup_id: {}", escape_control(&response.setup_id));
    println!("member_id: {}", response.member_id);
    println!("federation_id: {}", escape_control(&response.federation_id));
    println!(
        "final_config_digest: {}",
        escape_control(&response.final_config_digest)
    );
    println!("restart_pending: {}", response.restart_pending);

    Ok(())
}

fn print_status(status: &GetSetupStatusResponse) {
    if !status.initialized {
        println!("initialized: false");
        return;
    }
    println!("setup_id: {}", text(status.setup_id.as_deref()));
    println!("member_id: {}", number(status.member_id));
    println!(
        "identity_fingerprint: {}",
        text(status.identity_fingerprint.as_deref())
    );
    println!("role: {}", escape_control(&status.role));
    println!(
        "participant_phase: {}",
        escape_control(&status.participant_phase)
    );
    if status.coordinator_phase.is_some() {
        println!(
            "coordinator_phase: {}",
            text(status.coordinator_phase.as_deref())
        );
    }
    println!(
        "enrollments: {}/{} missing={}",
        status.enrolled_members.len(),
        status.member_count,
        list(&status.missing_enrollments)
    );
    println!(
        "approvals: {}/{} missing={}",
        status.approved_members.len(),
        status.member_count,
        list(&status.missing_approvals)
    );
    println!("proposal_hash: {}", text(status.proposal_hash.as_deref()));
    println!("manifest_hash: {}", text(status.manifest_hash.as_deref()));
    if let Some(dkg) = status.dkg.as_ref() {
        println!(
            "dkg_phase: {} commitments={} reveals={} shares={} transcript_signatures={} final_confirmations={}/{} finalized_ready={}",
            escape_control(&dkg.phase),
            dkg.commitments,
            dkg.reveals,
            dkg.secret_share_contributions,
            dkg.transcript_signatures,
            dkg.final_config_confirmations,
            status.member_count,
            dkg.finalized_ready
        );
        if let Some(digest) = dkg.final_config_digest.as_deref() {
            println!("final_config_digest: {}", escape_control(digest));
        }
        if let Some(error) = dkg.error.as_deref() {
            println!("dkg_error: {}", escape_control(error));
        }
    }
    println!("activated: {}", status.activation.is_some());
}

fn status_json(status: &GetSetupStatusResponse) -> serde_json::Value {
    serde_json::json!({
        "initialized": status.initialized,
        "setup_id": status.setup_id,
        "member_id": status.member_id,
        "identity_fingerprint": status.identity_fingerprint,
        "role": status.role,
        "participant_phase": status.participant_phase,
        "coordinator_phase": status.coordinator_phase,
        "member_count": status.member_count,
        "enrolled_members": status.enrolled_members,
        "missing_enrollments": status.missing_enrollments,
        "approved_members": status.approved_members,
        "missing_approvals": status.missing_approvals,
        "proposal_hash": status.proposal_hash,
        "manifest_hash": status.manifest_hash,
        "dkg": status.dkg.as_ref().map(|dkg| serde_json::json!({
            "phase": dkg.phase,
            "commitments": dkg.commitments,
            "reveals": dkg.reveals,
            "secret_share_contributions": dkg.secret_share_contributions,
            "keyset_shares": dkg.keyset_shares,
            "transcript_signatures": dkg.transcript_signatures,
            "final_config_confirmations": dkg.final_config_confirmations,
            "frost_root_public_configs": dkg.frost_root_public_configs,
            "confirmed_members": dkg.confirmed_members,
            "finalized_ready": dkg.finalized_ready,
            "dkg_confirmation_digest": dkg.dkg_confirmation_digest,
            "final_config_digest": dkg.final_config_digest,
            "transcript_hash": dkg.transcript_hash,
            "error": dkg.error,
        })),
        "activation": status.activation.as_ref().map(|activation| serde_json::json!({
            "setup_id": activation.setup_id,
            "member_id": activation.member_id,
            "manifest_hash": activation.manifest_hash,
            "federation_id": activation.federation_id,
            "final_config_digest": activation.final_config_digest,
            "activated_at_unix": activation.activated_at_unix,
        })),
    })
}

fn read_invitation_file(path: &Path) -> Result<String> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("failed to read invitation file {}", path.display()))?;
    if metadata.len() > MAX_INVITATION_FILE_BYTES {
        bail!("invitation file {} is too large", path.display());
    }
    let invitation = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read invitation file {}", path.display()))?;
    let invitation = invitation.trim();
    if invitation.is_empty() {
        bail!("invitation file {} is empty", path.display());
    }
    Ok(invitation.to_string())
}

/// Writes a file readable only by the current user.
fn write_private_file(path: &Path, contents: &str) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to restrict {}", path.display()))?;
    }
    file.write_all(contents.as_bytes())
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}
