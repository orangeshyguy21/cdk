//! Read-only federation status service.

use tonic::{Request, Response, Status};

use super::MintRPCServer;
use crate::federation::federation_service_server::FederationService;
use crate::federation::{
    GetCustodyStatusRequest, GetCustodyStatusResponse, GetFederationInfoRequest,
    GetFederationInfoResponse, GetLocalStatusRequest, GetLocalStatusResponse,
    GetMemberStatusesRequest, GetMemberStatusesResponse,
};
use crate::{DynFederationStatusProvider, FederationStatusError, FederationStatusErrorKind};

const DEFAULT_PAYMENT_REPORT_LIMIT: u32 = 50;
const MAX_PAYMENT_REPORT_LIMIT: u32 = 500;

impl MintRPCServer {
    fn federation_status_provider(&self) -> Result<&DynFederationStatusProvider, Status> {
        self.federation_status_provider.as_ref().ok_or_else(|| {
            Status::failed_precondition("This daemon is not running as a federation member")
        })
    }
}

fn payment_report_limit(requested: u32) -> Result<u32, Status> {
    match requested {
        0 => Ok(DEFAULT_PAYMENT_REPORT_LIMIT),
        requested if requested <= MAX_PAYMENT_REPORT_LIMIT => Ok(requested),
        requested => Err(Status::invalid_argument(format!(
            "Requested payment report limit {requested} exceeds maximum {MAX_PAYMENT_REPORT_LIMIT}"
        ))),
    }
}

fn into_status(error: FederationStatusError) -> Status {
    match error.kind() {
        FederationStatusErrorKind::InvalidArgument => Status::invalid_argument(error.message()),
        FederationStatusErrorKind::FailedPrecondition => {
            Status::failed_precondition(error.message())
        }
        FederationStatusErrorKind::ResourceExhausted => Status::resource_exhausted(error.message()),
        FederationStatusErrorKind::Unavailable => Status::unavailable(error.message()),
        FederationStatusErrorKind::Internal => {
            tracing::error!("Federation status request failed: {}", error);
            Status::internal(error.message())
        }
    }
}

#[tonic::async_trait]
impl FederationService for MintRPCServer {
    /// Returns the federation config this member runs.
    async fn get_federation_info(
        &self,
        request: Request<GetFederationInfoRequest>,
    ) -> Result<Response<GetFederationInfoResponse>, Status> {
        self.federation_status_provider()?
            .get_federation_info(request.into_inner())
            .await
            .map(Response::new)
            .map_err(into_status)
    }

    /// Returns this member's own status.
    async fn get_local_status(
        &self,
        request: Request<GetLocalStatusRequest>,
    ) -> Result<Response<GetLocalStatusResponse>, Status> {
        let provider = self.federation_status_provider()?;
        let mut request = request.into_inner();
        request.payment_report_limit = payment_report_limit(request.payment_report_limit)?;
        provider
            .get_local_status(request)
            .await
            .map(Response::new)
            .map_err(into_status)
    }

    /// Asks members for their status and compares their digests.
    async fn get_member_statuses(
        &self,
        request: Request<GetMemberStatusesRequest>,
    ) -> Result<Response<GetMemberStatusesResponse>, Status> {
        let provider = self.federation_status_provider()?;
        let mut request = request.into_inner();
        request.payment_report_limit = payment_report_limit(request.payment_report_limit)?;
        provider
            .get_member_statuses(request)
            .await
            .map(Response::new)
            .map_err(into_status)
    }

    /// Returns this member's custody status.
    async fn get_custody_status(
        &self,
        request: Request<GetCustodyStatusRequest>,
    ) -> Result<Response<GetCustodyStatusResponse>, Status> {
        self.federation_status_provider()?
            .get_custody_status(request.into_inner())
            .await
            .map(Response::new)
            .map_err(into_status)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use tonic::{Code, Request};

    use super::super::test_utils::create_test_rpc_server;
    use super::*;
    use crate::federation::{MemberStatus, MemberStatusResult};
    use crate::FederationStatusProvider;

    /// Echoes the payment report limit it receives and fails custody.
    struct StubProvider;

    #[async_trait]
    impl FederationStatusProvider for StubProvider {
        async fn get_federation_info(
            &self,
            _request: GetFederationInfoRequest,
        ) -> Result<GetFederationInfoResponse, FederationStatusError> {
            Ok(GetFederationInfoResponse {
                federation_id: "federation".to_string(),
                local_member_id: 2,
                ..Default::default()
            })
        }

        async fn get_local_status(
            &self,
            request: GetLocalStatusRequest,
        ) -> Result<GetLocalStatusResponse, FederationStatusError> {
            Ok(GetLocalStatusResponse {
                status: Some(MemberStatus {
                    member_id: request.payment_report_limit,
                    ..Default::default()
                }),
            })
        }

        async fn get_member_statuses(
            &self,
            request: GetMemberStatusesRequest,
        ) -> Result<GetMemberStatusesResponse, FederationStatusError> {
            Ok(GetMemberStatusesResponse {
                members: request
                    .member_ids
                    .iter()
                    .map(|member_id| MemberStatusResult {
                        member_id: *member_id,
                        latency_ms: u64::from(request.payment_report_limit),
                        ..Default::default()
                    })
                    .collect(),
                ..Default::default()
            })
        }

        async fn get_custody_status(
            &self,
            _request: GetCustodyStatusRequest,
        ) -> Result<GetCustodyStatusResponse, FederationStatusError> {
            Err(FederationStatusError::new(
                FederationStatusErrorKind::ResourceExhausted,
                "too many status requests",
            ))
        }
    }

    #[tokio::test]
    async fn federation_service_requires_a_configured_provider() {
        let server = create_test_rpc_server().await;

        let error = server
            .get_federation_info(Request::new(GetFederationInfoRequest {}))
            .await
            .expect_err("federation provider should be required");
        assert_eq!(error.code(), Code::FailedPrecondition);

        let error = server
            .get_member_statuses(Request::new(GetMemberStatusesRequest::default()))
            .await
            .expect_err("federation provider should be required");
        assert_eq!(error.code(), Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn federation_service_passes_provider_answers_through() {
        let server = create_test_rpc_server()
            .await
            .with_federation_status_provider(Arc::new(StubProvider));

        let info = server
            .get_federation_info(Request::new(GetFederationInfoRequest {}))
            .await
            .expect("federation info")
            .into_inner();
        assert_eq!(info.federation_id, "federation");
        assert_eq!(info.local_member_id, 2);

        let local = server
            .get_local_status(Request::new(GetLocalStatusRequest {
                payment_report_limit: 0,
            }))
            .await
            .expect("local status")
            .into_inner();
        assert_eq!(
            local.status.expect("member status").member_id,
            DEFAULT_PAYMENT_REPORT_LIMIT
        );

        let members = server
            .get_member_statuses(Request::new(GetMemberStatusesRequest {
                member_ids: vec![1, 3],
                payment_report_limit: 7,
            }))
            .await
            .expect("member statuses")
            .into_inner();
        assert_eq!(
            members
                .members
                .iter()
                .map(|member| (member.member_id, member.latency_ms))
                .collect::<Vec<_>>(),
            vec![(1, 7), (3, 7)]
        );

        let custody = server
            .get_custody_status(Request::new(GetCustodyStatusRequest {}))
            .await
            .expect_err("stub fails custody");
        assert_eq!(custody.code(), Code::ResourceExhausted);
        assert_eq!(custody.message(), "too many status requests");
    }

    #[tokio::test]
    async fn federation_service_rejects_oversized_payment_report_limits() {
        let server = create_test_rpc_server()
            .await
            .with_federation_status_provider(Arc::new(StubProvider));

        let error = server
            .get_local_status(Request::new(GetLocalStatusRequest {
                payment_report_limit: MAX_PAYMENT_REPORT_LIMIT + 1,
            }))
            .await
            .expect_err("oversized limit should fail");
        assert_eq!(error.code(), Code::InvalidArgument);
    }
}
