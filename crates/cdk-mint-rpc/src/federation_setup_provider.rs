//! Federation setup provider.

use std::sync::Arc;

use async_trait::async_trait;

use crate::federation_setup::{
    ActivateSetupRequest, ActivateSetupResponse, ApproveProposalRequest, ApproveProposalResponse,
    CreateSetupRequest, CreateSetupResponse, GetSetupStatusRequest, GetSetupStatusResponse,
    JoinSetupRequest, JoinSetupResponse, ProposeSetupRequest, ProposeSetupResponse,
    ReplaceInvitationRequest, ReplaceInvitationResponse, ReviewProposalRequest,
    ReviewProposalResponse,
};
use crate::ProviderError;

/// Supplies operations for the federation setup service.
#[async_trait]
pub trait FederationSetupProvider {
    /// Starts a new setup with this daemon as the coordinator.
    async fn create_setup(
        &self,
        request: CreateSetupRequest,
    ) -> Result<CreateSetupResponse, ProviderError>;

    /// Replaces the invitation for a member that has not joined yet.
    async fn replace_invitation(
        &self,
        request: ReplaceInvitationRequest,
    ) -> Result<ReplaceInvitationResponse, ProviderError>;

    /// Joins a setup using an invitation from the coordinator.
    async fn join_setup(
        &self,
        request: JoinSetupRequest,
    ) -> Result<JoinSetupResponse, ProviderError>;

    /// Builds the setup proposal once every member has enrolled.
    async fn propose_setup(
        &self,
        request: ProposeSetupRequest,
    ) -> Result<ProposeSetupResponse, ProviderError>;

    /// Returns the current proposal for review.
    async fn review_proposal(
        &self,
        request: ReviewProposalRequest,
    ) -> Result<ReviewProposalResponse, ProviderError>;

    /// Approves the proposal with the requested hash.
    async fn approve_proposal(
        &self,
        request: ApproveProposalRequest,
    ) -> Result<ApproveProposalResponse, ProviderError>;

    /// Returns the local setup state, including before a setup exists.
    async fn get_setup_status(
        &self,
        request: GetSetupStatusRequest,
    ) -> Result<GetSetupStatusResponse, ProviderError>;

    /// Activates the finished federation config.
    async fn activate_setup(
        &self,
        request: ActivateSetupRequest,
    ) -> Result<ActivateSetupResponse, ProviderError>;
}

/// Dynamically dispatched federation setup provider.
pub type DynFederationSetupProvider = Arc<dyn FederationSetupProvider + Send + Sync>;
