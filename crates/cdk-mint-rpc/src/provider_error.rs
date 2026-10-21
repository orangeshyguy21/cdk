//! Error type shared by the management RPC providers.

use thiserror::Error;
use tonic::Status;

/// Category of a provider failure, mapped to a gRPC status code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProviderErrorKind {
    /// The request is malformed. Maps to `INVALID_ARGUMENT`.
    InvalidArgument,
    /// The daemon cannot answer in its current state. Maps to
    /// `FAILED_PRECONDITION`.
    FailedPrecondition,
    /// Too many requests are in progress. Maps to `RESOURCE_EXHAUSTED`.
    ResourceExhausted,
    /// The source is shutting down or not running. Maps to `UNAVAILABLE`.
    Unavailable,
    /// The request failed for another reason. Maps to `INTERNAL`.
    Internal,
}

/// Error returned by a management RPC provider.
#[derive(Debug, Error)]
#[error("{message}")]
pub struct ProviderError {
    kind: ProviderErrorKind,
    message: String,
}

impl ProviderError {
    /// Creates an error with an explicit category.
    pub fn new(kind: ProviderErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// Creates an error for a malformed request.
    pub fn invalid_argument(message: impl Into<String>) -> Self {
        Self::new(ProviderErrorKind::InvalidArgument, message)
    }

    /// Creates an error for a request the daemon cannot answer in its state.
    pub fn failed_precondition(message: impl Into<String>) -> Self {
        Self::new(ProviderErrorKind::FailedPrecondition, message)
    }

    /// Creates an error for any other failure.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ProviderErrorKind::Internal, message)
    }

    /// Returns the failure category.
    pub fn kind(&self) -> ProviderErrorKind {
        self.kind
    }

    /// Returns the message sent to the client.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl From<ProviderError> for Status {
    fn from(error: ProviderError) -> Self {
        match error.kind {
            ProviderErrorKind::InvalidArgument => Status::invalid_argument(error.message),
            ProviderErrorKind::FailedPrecondition => Status::failed_precondition(error.message),
            ProviderErrorKind::ResourceExhausted => Status::resource_exhausted(error.message),
            ProviderErrorKind::Unavailable => Status::unavailable(error.message),
            ProviderErrorKind::Internal => {
                tracing::error!("Management RPC request failed: {}", error.message);
                Status::internal(error.message)
            }
        }
    }
}
