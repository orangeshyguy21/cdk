//! Federation status provider.

use std::sync::Arc;

use async_trait::async_trait;
use thiserror::Error;

use crate::federation::{
    GetCustodyStatusRequest, GetCustodyStatusResponse, GetFederationInfoRequest,
    GetFederationInfoResponse, GetLocalStatusRequest, GetLocalStatusResponse,
    GetMemberStatusesRequest, GetMemberStatusesResponse,
};

/// Category of a federation status failure, mapped to a gRPC status code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FederationStatusErrorKind {
    /// The request is malformed. Maps to `INVALID_ARGUMENT`.
    InvalidArgument,
    /// The daemon cannot answer in its current state. Maps to
    /// `FAILED_PRECONDITION`.
    FailedPrecondition,
    /// Too many status requests are in progress. Maps to
    /// `RESOURCE_EXHAUSTED`.
    ResourceExhausted,
    /// The status source is shutting down or not running. Maps to
    /// `UNAVAILABLE`.
    Unavailable,
    /// The request failed for another reason. Maps to `INTERNAL`.
    Internal,
}

/// Error returned by a federation status provider.
#[derive(Debug, Error)]
#[error("{message}")]
pub struct FederationStatusError {
    kind: FederationStatusErrorKind,
    message: String,
}

impl FederationStatusError {
    /// Creates an error with an explicit category.
    pub fn new(kind: FederationStatusErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// Creates an error for a malformed request.
    pub fn invalid_argument(message: impl Into<String>) -> Self {
        Self::new(FederationStatusErrorKind::InvalidArgument, message)
    }

    /// Creates an error for a request the daemon cannot answer in its state.
    pub fn failed_precondition(message: impl Into<String>) -> Self {
        Self::new(FederationStatusErrorKind::FailedPrecondition, message)
    }

    /// Creates an error for any other failure.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(FederationStatusErrorKind::Internal, message)
    }

    /// Returns the failure category.
    pub fn kind(&self) -> FederationStatusErrorKind {
        self.kind
    }

    /// Returns the message sent to the client.
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Supplies read-only status for the federation service.
///
/// The server has already replaced a zero `payment_report_limit` with its
/// default and rejected values above its maximum, so providers can use the
/// limit as given.
#[async_trait]
pub trait FederationStatusProvider {
    /// Returns the federation config this member runs.
    async fn get_federation_info(
        &self,
        request: GetFederationInfoRequest,
    ) -> Result<GetFederationInfoResponse, FederationStatusError>;

    /// Returns this member's own status.
    async fn get_local_status(
        &self,
        request: GetLocalStatusRequest,
    ) -> Result<GetLocalStatusResponse, FederationStatusError>;

    /// Asks members for their status and compares their digests.
    async fn get_member_statuses(
        &self,
        request: GetMemberStatusesRequest,
    ) -> Result<GetMemberStatusesResponse, FederationStatusError>;

    /// Returns this member's custody status.
    async fn get_custody_status(
        &self,
        request: GetCustodyStatusRequest,
    ) -> Result<GetCustodyStatusResponse, FederationStatusError>;
}

/// Dynamically dispatched federation status provider.
pub type DynFederationStatusProvider = Arc<dyn FederationStatusProvider + Send + Sync>;
