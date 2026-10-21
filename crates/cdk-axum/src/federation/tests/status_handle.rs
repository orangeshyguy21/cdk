use cdk::federation::FederationPaymentObservationReportStatus;

use super::super::status_handle::member_local_statuses_with_client;
use super::super::status_routes::{build_local_status, LocalStatusOptions, PaymentReportDetail};
use super::*;

/// Request path and signed request seen by the transport.
type RecordedStatusRequest = (String, FederationSignedRequest<FederationPeerStatusRequest>);

/// Answers `local-status` for the hosts it knows and refuses the others, the
/// way a stopped member does.
#[derive(Debug, Clone, Default)]
struct LocalStatusTransport {
    responses: Arc<Mutex<BTreeMap<String, FederationLocalStatusResponse>>>,
    requests: Arc<Mutex<Vec<RecordedStatusRequest>>>,
}

impl LocalStatusTransport {
    fn with_response(self, host: &str, response: FederationLocalStatusResponse) -> Self {
        self.responses
            .lock()
            .expect("transport lock")
            .insert(host.to_string(), response);
        self
    }

    fn requests(&self) -> Vec<RecordedStatusRequest> {
        self.requests.lock().expect("transport lock").clone()
    }
}

#[async_trait]
impl Transport for LocalStatusTransport {
    fn with_proxy(
        &mut self,
        _proxy: url::Url,
        _host_matcher: Option<&str>,
        _accept_invalid_certs: bool,
    ) -> Result<(), HttpError> {
        Ok(())
    }

    async fn http_get(
        &self,
        url: url::Url,
        _auth: Option<AuthToken>,
    ) -> Result<RawResponse, HttpError> {
        Err(HttpError::Other(format!(
            "unexpected raw GET path {}",
            url.path()
        )))
    }

    async fn http_post<P>(
        &self,
        url: url::Url,
        _auth_token: Option<AuthToken>,
        payload: &P,
    ) -> Result<RawResponse, HttpError>
    where
        P: Serialize + Send + Sync,
    {
        let host = url.host_str().unwrap_or_default().to_string();
        let request = serde_json::from_value::<FederationSignedRequest<FederationPeerStatusRequest>>(
            serde_json::to_value(payload)?,
        )?;
        self.requests
            .lock()
            .expect("transport lock")
            .push((url.path().to_string(), request));
        let response = self
            .responses
            .lock()
            .expect("transport lock")
            .get(&host)
            .cloned();
        match response {
            Some(response) => json_response(response),
            None => Err(HttpError::Other(format!("connection refused by {host}"))),
        }
    }
}

fn clear_quote_ages(status: &mut FederationLocalStatusResponse) {
    for report in &mut status.payment_observation_reports {
        report.quote_age_secs = None;
    }
}

#[tokio::test]
async fn local_status_builder_matches_private_route() {
    let (mut public_config, local_private, peer_private) = transport_config();
    public_config.payment_observation_policy = FederationPaymentObservationPolicy::member_quorum(2);
    let state =
        federation_route_state_for_private(public_config.clone(), local_private.clone()).await;
    let local_member = local_private.member_id;
    let resolved_quote = QuoteId::new();
    let unresolved_quote = QuoteId::new();
    for quote in [&resolved_quote, &unresolved_quote] {
        state
            .submit_federation_envelope(mint_quote_envelope(&state, quote))
            .await
            .expect("submit mint quote");
    }
    for observer in [1, 2] {
        state
            .submit_federation_envelope(mint_payment_observation_envelope_for_member(
                &state,
                &resolved_quote,
                observer,
                1,
                "settled",
            ))
            .await
            .expect("submit matching payment observation");
    }
    state
        .submit_federation_envelope(mint_payment_observation_envelope_for_member(
            &state,
            &unresolved_quote,
            1,
            1,
            "settled",
        ))
        .await
        .expect("submit lone payment observation");

    let request = signed_status_request(&public_config, &peer_private, local_member, 1);
    let from_route = post_local_status(State(state.clone()), Json(request))
        .await
        .expect("local status route")
        .0;
    let from_builder = build_local_status(
        &state,
        LocalStatusOptions {
            include_materialized_rows: false,
            payment_reports: PaymentReportDetail::Full,
        },
    )
    .await
    .expect("local status builder");
    let bounded = build_local_status(
        &state,
        LocalStatusOptions {
            include_materialized_rows: false,
            payment_reports: PaymentReportDetail::UnresolvedQuoteAges,
        },
    )
    .await
    .expect("bounded local status builder");

    // Quote ages are read from the clock on every build
    let mut route_without_ages = from_route.clone();
    let mut builder_without_ages = from_builder;
    let mut bounded_without_ages = bounded.clone();
    clear_quote_ages(&mut route_without_ages);
    clear_quote_ages(&mut builder_without_ages);
    clear_quote_ages(&mut bounded_without_ages);
    assert_eq!(builder_without_ages, route_without_ages);
    assert_eq!(bounded_without_ages, route_without_ages);

    let reports = from_route
        .payment_observation_reports
        .iter()
        .zip(&bounded.payment_observation_reports)
        .map(|(full, bounded)| (full.quote.as_str(), (full, bounded)))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(reports.len(), 2);
    let (full, bounded) = reports[resolved_quote.to_string().as_str()];
    assert_eq!(
        full.status,
        FederationPaymentObservationReportStatus::QuorumReached
    );
    assert!(full.quote_age_secs.is_some());
    assert!(
        bounded.quote_age_secs.is_none(),
        "a resolved report needs no quote lookup"
    );
    let (full, bounded) = reports[unresolved_quote.to_string().as_str()];
    assert_eq!(
        full.status,
        FederationPaymentObservationReportStatus::AwaitingQuorum
    );
    assert!(full.stale);
    assert!(bounded.stale);
    assert!(bounded.quote_age_secs.is_some());
}

#[tokio::test]
async fn local_status_errors_keep_the_private_route_status_codes() {
    let cases = [
        (
            FederationLocalStatusError::NotConfigured,
            axum::http::StatusCode::NOT_FOUND,
        ),
        (
            FederationLocalStatusError::AdmissionFull,
            axum::http::StatusCode::TOO_MANY_REQUESTS,
        ),
        (
            FederationLocalStatusError::AdmissionClosed,
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
        ),
        (
            FederationLocalStatusError::Mint(cdk::Error::Federation(
                FederationError::RuntimeUnavailable {
                    component: "consensus",
                },
            )),
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
        ),
        (
            FederationLocalStatusError::Mint(cdk::Error::Federation(
                FederationError::PendingConsensusMempoolFull { pending: 4, max: 4 },
            )),
            axum::http::StatusCode::TOO_MANY_REQUESTS,
        ),
        (
            FederationLocalStatusError::Mint(cdk::Error::Federation(
                FederationError::ConflictingOperation {
                    conflict_key: "quote:test".to_string(),
                    existing_operation_id: "existing".to_string(),
                    attempted_operation_id: "attempted".to_string(),
                },
            )),
            axum::http::StatusCode::CONFLICT,
        ),
        (
            FederationLocalStatusError::Mint(cdk::Error::Federation(
                FederationError::InvalidMemberId(0),
            )),
            axum::http::StatusCode::BAD_REQUEST,
        ),
        (
            FederationLocalStatusError::Mint(cdk::Error::Internal),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        ),
        (
            FederationLocalStatusError::Internal(anyhow::anyhow!("secret=hidden")),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        ),
    ];

    for (error, expected) in cases {
        assert_eq!(error.http_status(), expected);
        let message = error.public_message();
        assert!(!message.contains("hidden"));
        let response = axum::response::IntoResponse::into_response(error);
        assert_eq!(response.status(), expected);
        assert_eq!(response_error_detail(response).await, message);
    }
}

#[tokio::test]
async fn member_local_statuses_report_an_unreachable_member_without_failing() {
    let (state, public_config, first_private, _, _) =
        federation_route_state_three_with_local_private().await;
    let handle = FederationStatusHandle::new(state);
    let mut second_status = handle.local_status().await.expect("local status");
    second_status.peer_status.member_id = member_id(2);
    let transport =
        LocalStatusTransport::default().with_response("fed2.example.com", second_status.clone());
    let client = FederationRestPeerClient::new(transport.clone(), &public_config, first_private)
        .expect("peer client");

    let statuses = member_local_statuses_with_client(&handle, &client)
        .await
        .expect("member statuses");

    assert_eq!(
        statuses
            .iter()
            .map(|status| status.member_id)
            .collect::<Vec<_>>(),
        vec![member_id(1), member_id(2), member_id(3)]
    );
    assert!(statuses[0].local);
    assert_eq!(
        statuses[0]
            .status
            .as_ref()
            .expect("local member status")
            .peer_status
            .member_id,
        member_id(1)
    );
    assert!(!statuses[1].local);
    assert_eq!(
        statuses[1].status.as_ref().expect("reachable member"),
        &second_status
    );
    assert!(!statuses[2].local);
    let error = statuses[2]
        .status
        .as_ref()
        .expect_err("stopped member is unreachable");
    assert!(error.contains("connection refused"), "{error}");

    // Only the other members are asked over the network
    let requests = transport.requests();
    assert_eq!(requests.len(), 2);
    for ((path, request), receiver) in requests.iter().zip([member_id(2), member_id(3)]) {
        assert!(path.ends_with("/federation/v1/local-status"), "{path}");
        assert_eq!(request.sender, member_id(1));
        assert_eq!(request.kind, FederationRestMessageKind::Status);
        request
            .verify(&public_config, receiver)
            .expect("signed status request");
    }
}

#[tokio::test]
async fn member_local_statuses_reject_a_status_for_another_member() {
    let (state, public_config, first_private, _, _) =
        federation_route_state_three_with_local_private().await;
    let handle = FederationStatusHandle::new(state);
    let mut wrong_member = handle.local_status().await.expect("local status");
    wrong_member.peer_status.member_id = member_id(2);
    let transport = LocalStatusTransport::default().with_response("fed3.example.com", wrong_member);
    let client = FederationRestPeerClient::new(transport, &public_config, first_private)
        .expect("peer client");

    let statuses = member_local_statuses_with_client(&handle, &client)
        .await
        .expect("member statuses");

    let error = statuses
        .iter()
        .find(|status| status.member_id == member_id(3))
        .expect("member three entry")
        .status
        .as_ref()
        .expect_err("status for another member is rejected");
    assert!(error.contains("mismatch"), "{error}");
}
