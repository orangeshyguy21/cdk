//! Federation setup RPC server, served before a mint exists.

use core::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tonic::transport::server::TcpIncoming;
use tonic::{Request, Response, Status};
use tracing::instrument;

use super::{server_builder, Error};
use crate::federation_setup::federation_setup_service_server::{
    FederationSetupService, FederationSetupServiceServer,
};
use crate::federation_setup::{
    AbortSetupRequest, AbortSetupResponse, ActivateSetupRequest, ActivateSetupResponse,
    ApproveProposalRequest, ApproveProposalResponse, CreateSetupRequest, CreateSetupResponse,
    GetSetupStatusRequest, GetSetupStatusResponse, JoinSetupRequest, JoinSetupResponse,
    ProposeSetupRequest, ProposeSetupResponse, ReplaceInvitationRequest, ReplaceInvitationResponse,
    ReviewProposalRequest, ReviewProposalResponse,
};
use crate::DynFederationSetupProvider;

/// RPC server that serves only `FederationSetupService`.
///
/// It needs no mint, so a daemon in setup mode can serve it on the management
/// RPC address before the federation exists.
pub struct FederationSetupRPCServer {
    socket_addr: SocketAddr,
    provider: DynFederationSetupProvider,
    shutdown: Arc<Notify>,
    handle: Option<JoinHandle<Result<(), Error>>>,
}

impl FederationSetupRPCServer {
    /// Creates a server that answers setup requests with `provider`.
    ///
    /// # Arguments
    /// * `addr` - The address to bind to
    /// * `port` - The port to listen on, or 0 for any free port
    /// * `provider` - The setup operations to serve
    pub fn new(addr: &str, port: u16, provider: DynFederationSetupProvider) -> Result<Self, Error> {
        Ok(Self {
            socket_addr: format!("{addr}:{port}").parse()?,
            provider,
            shutdown: Arc::new(Notify::new()),
            handle: None,
        })
    }

    /// Returns the address the server listens on.
    ///
    /// After [`Self::start`] this is the bound address, so a server created
    /// with port 0 reports the port it was given.
    pub fn local_addr(&self) -> SocketAddr {
        self.socket_addr
    }

    /// Binds the listener and starts serving in the background.
    ///
    /// The listener is bound before this returns, so an address that is
    /// already in use fails here rather than in the background task.
    ///
    /// # Arguments
    /// * `tls_dir` - Optional directory containing TLS certificates
    ///
    /// If TLS directory is provided, it must contain:
    /// - server.pem: Server certificate
    /// - server.key: Server private key
    /// - ca.pem: CA certificate for client authentication
    #[instrument(skip_all)]
    pub async fn start(&mut self, tls_dir: Option<PathBuf>) -> Result<(), Error> {
        if self.handle.is_some() {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "federation setup RPC server is already running",
            )));
        }

        tracing::info!("Starting federation setup RPC server {}", self.socket_addr);

        let mut builder = server_builder(tls_dir)?;
        let incoming = TcpIncoming::bind(self.socket_addr)?.with_nodelay(Some(true));
        self.socket_addr = incoming.local_addr()?;

        let router = builder.add_service(FederationSetupServiceServer::new(SetupServiceHandler {
            provider: self.provider.clone(),
        }));
        // A fresh signal per run, so a permit left by an earlier stop cannot
        // end this run
        let shutdown = Arc::new(Notify::new());
        self.shutdown = shutdown.clone();

        self.handle = Some(tokio::spawn(async move {
            router
                .serve_with_incoming_shutdown(incoming, async move {
                    shutdown.notified().await;
                })
                .await?;
            Ok(())
        }));

        Ok(())
    }

    /// Stops the server and waits until it has finished.
    ///
    /// In-flight requests are drained first. When this returns the listener
    /// is closed and the port can be bound again. Stopping a server that is
    /// not running does nothing.
    #[instrument(skip_all)]
    pub async fn stop(&mut self) -> Result<(), Error> {
        let Some(handle) = self.handle.take() else {
            return Ok(());
        };

        self.shutdown.notify_one();
        let result = match handle.await {
            Ok(result) => result,
            Err(join_error) => Err(Error::Io(std::io::Error::other(join_error))),
        };

        tracing::info!("Federation setup RPC server stopped");
        result
    }
}

impl fmt::Debug for FederationSetupRPCServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FederationSetupRPCServer")
            .field("socket_addr", &self.socket_addr)
            .field("running", &self.handle.is_some())
            .finish_non_exhaustive()
    }
}

impl Drop for FederationSetupRPCServer {
    fn drop(&mut self) {
        // A server dropped without `stop` must not keep holding the port
        if let Some(handle) = self.handle.take() {
            tracing::debug!("Aborting federation setup RPC server dropped while running");
            handle.abort();
        }
    }
}

/// Tonic service that forwards every request to the provider.
#[derive(Clone)]
struct SetupServiceHandler {
    provider: DynFederationSetupProvider,
}

#[tonic::async_trait]
impl FederationSetupService for SetupServiceHandler {
    /// Starts a new setup with this daemon as the coordinator.
    async fn create_setup(
        &self,
        request: Request<CreateSetupRequest>,
    ) -> Result<Response<CreateSetupResponse>, Status> {
        self.provider
            .create_setup(request.into_inner())
            .await
            .map(Response::new)
            .map_err(Status::from)
    }

    /// Replaces the invitation for a member that has not joined yet.
    async fn replace_invitation(
        &self,
        request: Request<ReplaceInvitationRequest>,
    ) -> Result<Response<ReplaceInvitationResponse>, Status> {
        self.provider
            .replace_invitation(request.into_inner())
            .await
            .map(Response::new)
            .map_err(Status::from)
    }

    /// Joins a setup using an invitation from the coordinator.
    async fn join_setup(
        &self,
        request: Request<JoinSetupRequest>,
    ) -> Result<Response<JoinSetupResponse>, Status> {
        self.provider
            .join_setup(request.into_inner())
            .await
            .map(Response::new)
            .map_err(Status::from)
    }

    /// Builds the setup proposal once every member has enrolled.
    async fn propose_setup(
        &self,
        request: Request<ProposeSetupRequest>,
    ) -> Result<Response<ProposeSetupResponse>, Status> {
        self.provider
            .propose_setup(request.into_inner())
            .await
            .map(Response::new)
            .map_err(Status::from)
    }

    /// Returns the current proposal for review.
    async fn review_proposal(
        &self,
        request: Request<ReviewProposalRequest>,
    ) -> Result<Response<ReviewProposalResponse>, Status> {
        self.provider
            .review_proposal(request.into_inner())
            .await
            .map(Response::new)
            .map_err(Status::from)
    }

    /// Approves the proposal with the requested hash.
    async fn approve_proposal(
        &self,
        request: Request<ApproveProposalRequest>,
    ) -> Result<Response<ApproveProposalResponse>, Status> {
        self.provider
            .approve_proposal(request.into_inner())
            .await
            .map(Response::new)
            .map_err(Status::from)
    }

    /// Returns the local setup state.
    async fn get_setup_status(
        &self,
        request: Request<GetSetupStatusRequest>,
    ) -> Result<Response<GetSetupStatusResponse>, Status> {
        self.provider
            .get_setup_status(request.into_inner())
            .await
            .map(Response::new)
            .map_err(Status::from)
    }

    /// Abandons the current setup before key generation can have started.
    async fn abort_setup(
        &self,
        request: Request<AbortSetupRequest>,
    ) -> Result<Response<AbortSetupResponse>, Status> {
        self.provider
            .abort_setup(request.into_inner())
            .await
            .map(Response::new)
            .map_err(Status::from)
    }

    /// Activates the finished federation config.
    async fn activate_setup(
        &self,
        request: Request<ActivateSetupRequest>,
    ) -> Result<Response<ActivateSetupResponse>, Status> {
        self.provider
            .activate_setup(request.into_inner())
            .await
            .map(Response::new)
            .map_err(Status::from)
    }
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::sync::Arc;

    use async_trait::async_trait;
    use tokio::time::{timeout, Duration};
    use tonic::transport::Channel;
    use tonic::Code;

    use super::FederationSetupRPCServer;
    use crate::federation_setup::federation_setup_service_client::FederationSetupServiceClient;
    use crate::federation_setup::{
        AbortSetupRequest, AbortSetupResponse, ActivateSetupRequest, ActivateSetupResponse,
        ApproveProposalRequest, ApproveProposalResponse, CreateSetupRequest, CreateSetupResponse,
        GetSetupStatusRequest, GetSetupStatusResponse, JoinSetupRequest, JoinSetupResponse,
        ProposeSetupRequest, ProposeSetupResponse, ReplaceInvitationRequest,
        ReplaceInvitationResponse, ReviewProposalRequest, ReviewProposalResponse, SetupRole,
    };
    use crate::{FederationSetupProvider, ProviderError};

    /// Answers status as uninitialized and fails the other calls with one
    /// error kind each.
    struct StubProvider;

    #[async_trait]
    impl FederationSetupProvider for StubProvider {
        async fn create_setup(
            &self,
            _request: CreateSetupRequest,
        ) -> Result<CreateSetupResponse, ProviderError> {
            Err(ProviderError::invalid_argument("threshold too high"))
        }

        async fn replace_invitation(
            &self,
            _request: ReplaceInvitationRequest,
        ) -> Result<ReplaceInvitationResponse, ProviderError> {
            Err(ProviderError::failed_precondition("member already joined"))
        }

        async fn join_setup(
            &self,
            _request: JoinSetupRequest,
        ) -> Result<JoinSetupResponse, ProviderError> {
            Err(ProviderError::failed_precondition("already joined"))
        }

        async fn propose_setup(
            &self,
            _request: ProposeSetupRequest,
        ) -> Result<ProposeSetupResponse, ProviderError> {
            Err(ProviderError::internal("database unavailable"))
        }

        async fn review_proposal(
            &self,
            _request: ReviewProposalRequest,
        ) -> Result<ReviewProposalResponse, ProviderError> {
            Err(ProviderError::failed_precondition("no proposal"))
        }

        async fn approve_proposal(
            &self,
            _request: ApproveProposalRequest,
        ) -> Result<ApproveProposalResponse, ProviderError> {
            Err(ProviderError::failed_precondition("no proposal"))
        }

        async fn get_setup_status(
            &self,
            _request: GetSetupStatusRequest,
        ) -> Result<GetSetupStatusResponse, ProviderError> {
            Ok(GetSetupStatusResponse {
                initialized: false,
                ..Default::default()
            })
        }

        async fn abort_setup(
            &self,
            _request: AbortSetupRequest,
        ) -> Result<AbortSetupResponse, ProviderError> {
            Err(ProviderError::failed_precondition("no setup"))
        }

        async fn activate_setup(
            &self,
            _request: ActivateSetupRequest,
        ) -> Result<ActivateSetupResponse, ProviderError> {
            Err(ProviderError::failed_precondition("not finalized"))
        }
    }

    fn stub_server() -> FederationSetupRPCServer {
        FederationSetupRPCServer::new("127.0.0.1", 0, Arc::new(StubProvider))
            .expect("valid server address")
    }

    #[tokio::test]
    async fn test_serves_setup_requests_and_frees_port_on_stop() {
        let mut server = stub_server();
        server.start(None).await.expect("setup server should start");
        let addr = server.local_addr();
        assert_ne!(addr.port(), 0, "start should report the bound port");

        let channel = Channel::from_shared(format!("http://{addr}"))
            .expect("valid RPC endpoint")
            .connect()
            .await
            .expect("listener is bound once start returns");
        let mut client = FederationSetupServiceClient::new(channel);

        let status = client
            .get_setup_status(GetSetupStatusRequest {})
            .await
            .expect("status should succeed before setup exists")
            .into_inner();
        assert!(!status.initialized);
        assert!(status.setup_id.is_none());
        assert_eq!(status.role(), SetupRole::Unspecified);

        let invalid = client
            .create_setup(CreateSetupRequest::default())
            .await
            .expect_err("stub rejects create");
        assert_eq!(invalid.code(), Code::InvalidArgument);
        assert_eq!(invalid.message(), "threshold too high");

        let precondition = client
            .join_setup(JoinSetupRequest::default())
            .await
            .expect_err("stub rejects join");
        assert_eq!(precondition.code(), Code::FailedPrecondition);
        assert_eq!(precondition.message(), "already joined");

        let internal = client
            .propose_setup(ProposeSetupRequest {})
            .await
            .expect_err("stub rejects propose");
        assert_eq!(internal.code(), Code::Internal);
        assert_eq!(internal.message(), "database unavailable");

        // The client keeps its connection open while the server stops
        timeout(Duration::from_secs(5), server.stop())
            .await
            .expect("setup server should stop in time")
            .expect("setup server should stop cleanly");

        TcpListener::bind(addr).expect("port should be free after stop");

        server
            .stop()
            .await
            .expect("stopping a stopped server does nothing");
        drop(client);
    }

    #[tokio::test]
    async fn test_start_reports_address_in_use() {
        let occupied = TcpListener::bind("127.0.0.1:0").expect("bind test port");
        let port = occupied.local_addr().expect("test listener address").port();

        let mut server = FederationSetupRPCServer::new("127.0.0.1", port, Arc::new(StubProvider))
            .expect("valid server address");
        let error = server
            .start(None)
            .await
            .expect_err("start should fail when the port is taken");
        assert!(
            matches!(&error, super::Error::Io(io) if io.kind() == std::io::ErrorKind::AddrInUse),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn test_start_twice_is_rejected() {
        let mut server = stub_server();
        server.start(None).await.expect("setup server should start");
        let error = server
            .start(None)
            .await
            .expect_err("second start should fail");
        assert!(
            matches!(&error, super::Error::Io(io) if io.kind() == std::io::ErrorKind::AlreadyExists),
            "unexpected error: {error}"
        );
        server.stop().await.expect("setup server should stop");
    }
}
