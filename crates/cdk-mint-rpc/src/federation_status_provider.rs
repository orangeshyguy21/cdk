//! Federation status provider.

use std::sync::Arc;

use async_trait::async_trait;

use crate::federation::{
    GetCustodyStatusRequest, GetCustodyStatusResponse, GetFederationInfoRequest,
    GetFederationInfoResponse, GetLocalStatusRequest, GetLocalStatusResponse,
    GetMemberStatusesRequest, GetMemberStatusesResponse,
};
use crate::ProviderError;

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
    ) -> Result<GetFederationInfoResponse, ProviderError>;

    /// Returns this member's own status.
    async fn get_local_status(
        &self,
        request: GetLocalStatusRequest,
    ) -> Result<GetLocalStatusResponse, ProviderError>;

    /// Asks members for their status and compares their digests.
    async fn get_member_statuses(
        &self,
        request: GetMemberStatusesRequest,
    ) -> Result<GetMemberStatusesResponse, ProviderError>;

    /// Returns this member's custody status.
    async fn get_custody_status(
        &self,
        request: GetCustodyStatusRequest,
    ) -> Result<GetCustodyStatusResponse, ProviderError>;
}

/// Dynamically dispatched federation status provider.
pub type DynFederationStatusProvider = Arc<dyn FederationStatusProvider + Send + Sync>;
