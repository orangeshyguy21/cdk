//! Federation setup provider.

use std::sync::Arc;

use async_trait::async_trait;
use thiserror::Error;

use crate::federation_setup::{
    ActivateSetupRequest, ActivateSetupResponse, ApproveProposalRequest, ApproveProposalResponse,
    CreateSetupRequest, CreateSetupResponse, GetSetupStatusRequest, GetSetupStatusResponse,
    JoinSetupRequest, JoinSetupResponse, ProposeSetupRequest, ProposeSetupResponse,
    ReviewProposalRequest, ReviewProposalResponse,
};

/// Category of a federation setup failure, mapped to a gRPC status code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FederationSetupErrorKind {
    /// The request is malformed. Maps to `INVALID_ARGUMENT`.
    InvalidArgument,
    /// The request conflicts with the current setup phase. Maps to
    /// `FAILED_PRECONDITION`.
    FailedPrecondition,
    /// The request failed for another reason. Maps to `INTERNAL`.
    Internal,
}

/// Error returned by a federation setup provider.
#[derive(Debug, Error)]
#[error("{message}")]
pub struct FederationSetupError {
    kind: FederationSetupErrorKind,
    message: String,
}

impl FederationSetupError {
    /// Creates an error for a malformed request.
    pub fn invalid_argument(message: impl Into<String>) -> Self {
        Self::new(FederationSetupErrorKind::InvalidArgument, message)
    }

    /// Creates an error for a request that conflicts with the setup phase.
    pub fn failed_precondition(message: impl Into<String>) -> Self {
        Self::new(FederationSetupErrorKind::FailedPrecondition, message)
    }

    /// Creates an error for any other failure.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(FederationSetupErrorKind::Internal, message)
    }

    /// Returns the failure category.
    pub fn kind(&self) -> FederationSetupErrorKind {
        self.kind
    }

    /// Returns the message sent to the client.
    pub fn message(&self) -> &str {
        &self.message
    }

    fn new(kind: FederationSetupErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

/// Supplies operations for the federation setup service.
#[async_trait]
pub trait FederationSetupProvider {
    /// Starts a new setup with this daemon as the coordinator.
    async fn create_setup(
        &self,
        request: CreateSetupRequest,
    ) -> Result<CreateSetupResponse, FederationSetupError>;

    /// Joins a setup using an invitation from the coordinator.
    async fn join_setup(
        &self,
        request: JoinSetupRequest,
    ) -> Result<JoinSetupResponse, FederationSetupError>;

    /// Builds the setup proposal once every member has enrolled.
    async fn propose_setup(
        &self,
        request: ProposeSetupRequest,
    ) -> Result<ProposeSetupResponse, FederationSetupError>;

    /// Returns the current proposal for review.
    async fn review_proposal(
        &self,
        request: ReviewProposalRequest,
    ) -> Result<ReviewProposalResponse, FederationSetupError>;

    /// Approves the proposal with the requested hash.
    async fn approve_proposal(
        &self,
        request: ApproveProposalRequest,
    ) -> Result<ApproveProposalResponse, FederationSetupError>;

    /// Returns the local setup state, including before a setup exists.
    async fn get_setup_status(
        &self,
        request: GetSetupStatusRequest,
    ) -> Result<GetSetupStatusResponse, FederationSetupError>;

    /// Activates the finished federation config.
    async fn activate_setup(
        &self,
        request: ActivateSetupRequest,
    ) -> Result<ActivateSetupResponse, FederationSetupError>;
}

/// Dynamically dispatched federation setup provider.
pub type DynFederationSetupProvider = Arc<dyn FederationSetupProvider + Send + Sync>;
