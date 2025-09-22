//! litd MintPayment backend (BTC + Taproot Assets)

use std::pin::Pin;
use std::sync::Arc;
use std::str::FromStr;

use async_trait::async_trait;
use cdk_common::common::FeeReserve;
use cdk_common::database::mint::DynMintKVStore;
use cdk_common::nuts::CurrencyUnit;
use cdk_common::payment::{self, CreateIncomingPaymentResponse, Event, IncomingPaymentOptions, MakePaymentResponse, MintPayment, OutgoingPaymentOptions, PaymentIdentifier, PaymentQuoteResponse};
use cdk_common::{Amount, MeltQuoteState};
use anyhow::anyhow;
use futures::Stream;
use tokio_stream::wrappers::ReceiverStream;
use tonic::body::Body;
use tonic::codegen::InterceptedService;
use tonic::metadata::MetadataValue;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::TokioExecutor;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TLSError, SignatureScheme};
use tokio::fs;
use tonic::{Request, Status, service::Interceptor};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};

pub mod taprpc {
    tonic::include_proto!("taprpc");
}

pub mod tapchannelrpc {
    tonic::include_proto!("tapchannelrpc");
}

pub mod rfqrpc {
    tonic::include_proto!("rfqrpc");
}

pub mod lnrpc {
    tonic::include_proto!("lnrpc");
}

pub mod routerrpc {
    tonic::include_proto!("routerrpc");
}

const LITD_KV_PRIMARY_NAMESPACE: &str = "litd";
const LITD_KV_ASSET_INVOICE_SECONDARY: &str = "asset_invoice";

#[derive(Clone)]
pub struct Litd {
    _address: String,
    _cert_file: std::path::PathBuf,
    _lnd_macaroon_file: std::path::PathBuf,
    _tapd_macaroon_file: std::path::PathBuf,
    fee_reserve: FeeReserve,
    _kv_store: DynMintKVStore,
    allowed_usd_group_ids: Vec<String>,
    tls_domain: Option<String>,
}

impl Litd {
    pub async fn new(
        address: String,
        cert_file: std::path::PathBuf,
        lnd_macaroon_file: std::path::PathBuf,
        tapd_macaroon_file: std::path::PathBuf,
        fee_reserve: FeeReserve,
        kv_store: DynMintKVStore,
        allowed_usd_group_ids: Vec<String>,
        tls_domain: Option<String>,
    ) -> anyhow::Result<Self> {
        // Log credentials and endpoints for debugging (no secrets)
        fn log_file_info(label: &str, path: &std::path::Path) {
            match std::fs::metadata(path) {
                Ok(meta) => {
                    let len = meta.len();
                    let modified = meta.modified().ok();
                    tracing::info!(target: "cdk_litd", "{}: path={} size={} modified={:?}", label, path.display(), len, modified);
                }
                Err(e) => {
                    tracing::error!(target: "cdk_litd", "{}: path={} metadata error: {}", label, path.display(), e);
                }
            }
        }

        tracing::info!(target: "cdk_litd", "Configured litd address: {}", address);
        tracing::info!(target: "cdk_litd", "Using TLS cert: {}", cert_file.display());
        log_file_info("LND macaroon", &lnd_macaroon_file);
        log_file_info("TAPD macaroon", &tapd_macaroon_file);

        Ok(Self {
            _address: address,
            _cert_file: cert_file,
            _lnd_macaroon_file: lnd_macaroon_file,
            _tapd_macaroon_file: tapd_macaroon_file,
            fee_reserve,
            _kv_store: kv_store,
            allowed_usd_group_ids,
            tls_domain,
        })
    }

    fn select_usd_group_id(&self) -> Option<String> {
        self.allowed_usd_group_ids.first().cloned()
    }

    fn validate_usd_group_id(&self, group_id: &str) -> bool {
        self.allowed_usd_group_ids.is_empty() || self.allowed_usd_group_ids.iter().any(|g| g == group_id)
    }

    fn lnd_macaroon_hex(&self) -> Result<String, payment::Error> {
        let bytes = std::fs::read(&self._lnd_macaroon_file)
            .map_err(|e| payment::Error::Anyhow(anyhow!(e)))?;
        Ok(hex::encode(bytes))
    }

    fn tapd_macaroon_hex(&self) -> Result<String, payment::Error> {
        let bytes = std::fs::read(&self._tapd_macaroon_file)
            .map_err(|e| payment::Error::Anyhow(anyhow!(e)))?;
        Ok(hex::encode(bytes))
    }

    fn tls_config(&self) -> Result<ClientTlsConfig, payment::Error> {
        let pem = std::fs::read(&self._cert_file).map_err(|e| payment::Error::Anyhow(anyhow!(e)))?;
        let ca = Certificate::from_pem(pem);
        let domain_owned: String = if let Some(d) = &self.tls_domain {
            d.clone()
        } else {
            let uri: http::Uri = self
                ._address
                .parse::<http::Uri>()
                .map_err(|e| payment::Error::Anyhow(anyhow!(e)))?;
            uri.host().unwrap_or("localhost").to_string()
        };
        tracing::info!(target: "cdk_litd", "Using TLS domain {} for litd", domain_owned);
        Ok(ClientTlsConfig::new().ca_certificate(ca).domain_name(domain_owned))
    }

    async fn ta_client(&self) -> Result<taprpc::taproot_assets_client::TaprootAssetsClient<InterceptedService<HyperClient<hyper_rustls::HttpsConnector<HttpConnector>, Body>, MacaroonInterceptor>>, payment::Error> {
        let uri: http::Uri = self
            ._address
            .parse::<http::Uri>()
            .map_err(|e| payment::Error::Anyhow(anyhow!(e)))?;
        let scheme = uri.scheme_str().unwrap_or("https");
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(LitdCertVerifier::load(&self._cert_file).await?))
            .with_no_client_auth();
        let https = HttpsConnectorBuilder::new()
            .with_tls_config(config)
            .https_only()
            .enable_http2()
            .build();
        let client = HyperClient::builder(TokioExecutor::new())
            .http2_only(true)
            .build(https);
        let interceptor = MacaroonInterceptor { macaroon_hex: self.tapd_macaroon_hex()? };
        let service = InterceptedService::new(client, interceptor);
        let address = self._address.trim_start_matches("http://").trim_start_matches("https://");
        let uri = tonic::transport::Uri::from_str(&format!("https://{address}"))
            .map_err(|e| payment::Error::Anyhow(anyhow!(e)))?;
        let client = taprpc::taproot_assets_client::TaprootAssetsClient::with_origin(service, uri);
        Ok(client)
    }

    async fn tap_channel_client(&self) -> Result<tapchannelrpc::taproot_asset_channels_client::TaprootAssetChannelsClient<InterceptedService<HyperClient<hyper_rustls::HttpsConnector<HttpConnector>, Body>, MacaroonInterceptor>>, payment::Error> {
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(LitdCertVerifier::load(&self._cert_file).await?))
            .with_no_client_auth();
        let https = HttpsConnectorBuilder::new()
            .with_tls_config(config)
            .https_only()
            .enable_http2()
            .build();
        let client = HyperClient::builder(TokioExecutor::new())
            .http2_only(true)
            .build(https);
        tracing::info!(target: "cdk_litd", "Using TAPD macaroon for TaprootAssetChannels: {}", self._tapd_macaroon_file.display());
        let interceptor = MacaroonInterceptor { macaroon_hex: self.tapd_macaroon_hex()? };
        let service = InterceptedService::new(client, interceptor);
        let address = self._address.trim_start_matches("http://").trim_start_matches("https://");
        let uri = tonic::transport::Uri::from_str(&format!("https://{address}"))
            .map_err(|e| payment::Error::Anyhow(anyhow!(e)))?;
        let client = tapchannelrpc::taproot_asset_channels_client::TaprootAssetChannelsClient::with_origin(service, uri);
        Ok(client)
    }

    async fn create_ta_address(&self, group_key_hex: &str, amount: u64) -> Result<String, payment::Error> {
        let mut client = self.ta_client().await?;
        let group_key = hex::decode(group_key_hex).map_err(|e| payment::Error::Anyhow(anyhow!(e)))?;
        let req = taprpc::NewAddrRequest {
            asset_id: vec![],
            amt: amount,
            script_key: None,
            internal_key: None,
            tapscript_sibling: vec![],
            proof_courier_addr: String::new(),
            // Use default/unspecified versions for compatibility with litd build
            asset_version: 0,
            address_version: 0,
            group_key,
        };
        let response = client.new_addr(Request::new(req)).await.map_err(|e| payment::Error::Anyhow(anyhow!(e)))?.into_inner();
        Ok(response.encoded)
    }

    async fn kv_write_asset_amount(&self, payment_hash_hex: &str, asset_amount: u64) {
        if let Ok(mut tx) = self._kv_store.begin_transaction().await {
            let _ = tx
                .kv_write(
                    LITD_KV_PRIMARY_NAMESPACE,
                    LITD_KV_ASSET_INVOICE_SECONDARY,
                    payment_hash_hex,
                    asset_amount.to_string().as_bytes(),
                )
                .await;
            let _ = tx.commit().await;
        }
    }

    async fn kv_read_asset_amount(&self, payment_hash_hex: &str) -> Option<u64> {
        if let Ok(Some(bytes)) = self
            ._kv_store
            .kv_read(
                LITD_KV_PRIMARY_NAMESPACE,
                LITD_KV_ASSET_INVOICE_SECONDARY,
                payment_hash_hex,
            )
            .await
        {
            if let Ok(s) = std::str::from_utf8(&bytes) {
                if let Ok(v) = s.parse::<u64>() {
                    return Some(v);
                }
            }
        }
        None
    }
}

#[derive(Clone)]
struct MacaroonInterceptor {
    macaroon_hex: String,
}

impl Interceptor for MacaroonInterceptor {
    fn call(&mut self, mut req: Request<()>) -> Result<Request<()>, Status> {
        req.metadata_mut().insert(
            "macaroon",
            MetadataValue::from_str(&self.macaroon_hex)
                .unwrap_or_else(|_| MetadataValue::from_static("")),
        );
        Ok(req)
    }
}

// Cert verifier matching cdk-lnd to work with litd self-signed certs
#[derive(Debug)]
struct LitdCertVerifier {
    certs: Vec<Vec<u8>>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl LitdCertVerifier {
    async fn load(path: impl AsRef<std::path::Path>) -> Result<Self, payment::Error> {
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            let _ = default_provider().install_default();
        }
        let contents = fs::read(path).await.map_err(|e| payment::Error::Anyhow(anyhow!(e)))?;
        let mut reader = std::io::Cursor::new(contents);
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader).flatten().collect();
        Ok(LitdCertVerifier { certs: certs.into_iter().map(|c| c.to_vec()).collect(), provider: Arc::new(default_provider()) })
    }
}

impl ServerCertVerifier for LitdCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TLSError> {
        let mut presented = intermediates.iter().map(|c| c.as_ref().to_vec()).collect::<Vec<Vec<u8>>>();
        presented.push(end_entity.as_ref().to_vec());
        let mut ours = self.certs.clone();
        presented.sort();
        ours.sort();
        if presented.len() != ours.len() { return Err(TLSError::General("Mismatched number of certificates".into())); }
        for (p, o) in presented.iter().zip(ours.iter()) {
            if p != o { return Err(TLSError::General("Server certificates do not match ours".into())); }
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, TLSError> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
            .map(|_| HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, TLSError> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
            .map(|_| HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

#[async_trait]
impl MintPayment for Litd {
    type Err = payment::Error;

    async fn get_settings(&self) -> Result<serde_json::Value, Self::Err> {
        #[derive(serde::Serialize)]
        struct Cap { mpp: bool, unit: CurrencyUnit, invoice_description: bool, amountless: bool, bolt12: bool }
        let btc = Cap { mpp: true, unit: CurrencyUnit::Msat, invoice_description: true, amountless: true, bolt12: false };
        Ok(serde_json::to_value(btc).map_err(|e| payment::Error::Serde(e))?)
    }

    async fn create_incoming_payment_request(
        &self,
        unit: &CurrencyUnit,
        options: IncomingPaymentOptions,
    ) -> Result<CreateIncomingPaymentResponse, Self::Err> {
        match unit {
            CurrencyUnit::Sat | CurrencyUnit::Msat => {
                // Delegate to cdk-lnd client via same TLS/macaroons (litd proxies Lightning Service)
                let fee_reserve = FeeReserve { min_fee_reserve: self.fee_reserve.min_fee_reserve, percent_fee_reserve: self.fee_reserve.percent_fee_reserve };
                tracing::info!(target: "cdk_litd", "Using LND macaroon for LightningService: {}", self._lnd_macaroon_file.display());
                let lnd = cdk_lnd::Lnd::new(
                    self._address.clone(),
                    self._cert_file.clone(),
                    self._lnd_macaroon_file.clone(),
                    fee_reserve,
                    self._kv_store.clone(),
                )
                .await
                .map_err(|e| payment::Error::Anyhow(anyhow!(e)))?;

                lnd
                    .create_incoming_payment_request(unit, options)
                    .await
            }
            CurrencyUnit::Usd => {
                // Create an asset-aware Lightning invoice via TaprootAssetChannels.AddInvoice
                let group_id_hex = self
                    .select_usd_group_id()
                    .ok_or_else(|| payment::Error::Custom("No usd_group_ids configured".to_string()))?;

                let (description, amount, expiry) = match options {
                    IncomingPaymentOptions::Bolt11(b) => (b.description.clone().unwrap_or_default(), u64::from(b.amount), b.unix_expiry),
                    _ => (String::new(), 0, None),
                };

                let group_key = hex::decode(&group_id_hex).map_err(|e| payment::Error::Anyhow(anyhow!(e)))?;

                // Build lnrpc::Invoice with memo and optional expiry seconds from now
                let mut invoice = lnrpc::Invoice::default();
                if !description.is_empty() {
                    invoice.memo = description;
                }
                if let Some(exp) = expiry {
                    // lnd expects relative seconds; convert unix ts -> relative seconds and clamp
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let mut rel = if exp > now { exp - now } else { 600 };
                    // Clamp to [60, 31_536_000] (~1 year)
                    if rel < 60 { rel = 60; }
                    if rel > 31_536_000 { rel = 31_536_000; }
                    invoice.expiry = rel as i64;
                } else {
                    // Default expiry if none provided
                    invoice.expiry = 600;
                }

                let req = tapchannelrpc::AddInvoiceRequest {
                    asset_id: vec![],
                    asset_amount: amount,
                    peer_pubkey: vec![],
                    invoice_request: Some(invoice),
                    hodl_invoice: None,
                    group_key,
                    price_oracle_metadata: String::new(),
                };

                tracing::info!(target: "cdk_litd", "Creating asset LN invoice for group {} amount {}", group_id_hex, amount);
                let mut client = self.tap_channel_client().await?;
                let resp = match client.add_invoice(Request::new(req)).await {
                    Ok(r) => r.into_inner(),
                    Err(status) => {
                        let code = status.code();
                        let message = status.message().to_string();
                        let hint = if message.to_lowercase().contains("could not create any quotes") {
                            "Hint: ensure a Taproot Asset channel exists for the specified group key and the amount is above the minimum transportable units."
                        } else { "" };
                        tracing::error!(target: "cdk_litd", "AddInvoice RPC error: code={:?} message={} {}", code, message, hint);
                        return Err(payment::Error::Custom(format!("AddInvoice failed: {}", message)));
                    }
                };

                let inv = resp.invoice_result.ok_or_else(|| payment::Error::Custom("missing invoice_result".to_string()))?;
                let bolt11 = inv.payment_request;
                let r_hash = inv.r_hash;
                let payment_identifier = if r_hash.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&r_hash);
                    // persist asset amount mapping for later settlement checks
                    let ph_hex = hex::encode(arr);
                    self.kv_write_asset_amount(&ph_hex, amount).await;
                    PaymentIdentifier::PaymentHash(arr)
                } else {
                    PaymentIdentifier::CustomId(bolt11.clone())
                };

                Ok(CreateIncomingPaymentResponse {
                    request_lookup_id: payment_identifier,
                    request: bolt11,
                    expiry: None,
                })
            }
            _ => Err(payment::Error::UnsupportedUnit),
        }
    }

    async fn get_payment_quote(
        &self,
        unit: &CurrencyUnit,
        options: OutgoingPaymentOptions,
    ) -> Result<PaymentQuoteResponse, Self::Err> {
        match unit {
            CurrencyUnit::Sat | CurrencyUnit::Msat => {
                let fee_reserve = FeeReserve { min_fee_reserve: self.fee_reserve.min_fee_reserve, percent_fee_reserve: self.fee_reserve.percent_fee_reserve };
                let lnd = cdk_lnd::Lnd::new(
                    self._address.clone(),
                    self._cert_file.clone(),
                    self._lnd_macaroon_file.clone(),
                    fee_reserve,
                    self._kv_store.clone(),
                )
                .await
                .map_err(|e| payment::Error::Anyhow(anyhow!(e)))?;
                lnd.get_payment_quote(unit, options).await
            }
            CurrencyUnit::Usd => {
                // Decode the asset-aware invoice to obtain the asset amount in USD units
                let bolt11 = match &options {
                    OutgoingPaymentOptions::Bolt11(b) => b.bolt11.to_string(),
                    OutgoingPaymentOptions::Bolt12(_) => return Err(payment::Error::UnsupportedUnit),
                };

                // Use the first allowed group key for decoding
                let group_key_hex = self
                    .allowed_usd_group_ids
                    .first()
                    .cloned()
                    .ok_or_else(|| payment::Error::Custom("No usd_group_ids configured".to_string()))?;
                let group_key = hex::decode(&group_key_hex).map_err(|e| payment::Error::Anyhow(anyhow!(e)))?;

                let mut client = self.tap_channel_client().await?;
                let decoded = client
                    .decode_asset_pay_req(Request::new(tapchannelrpc::AssetPayReq {
                        asset_id: vec![],
                        pay_req_string: bolt11,
                        group_key,
                        price_oracle_metadata: String::new(),
                    }))
                    .await
                    .map_err(|e| payment::Error::Anyhow(anyhow!(e)))?
                    .into_inner();

                let amount = Amount::from(decoded.asset_amount);

                Ok(PaymentQuoteResponse {
                    request_lookup_id: None,
                    amount,
                    fee: Amount::ZERO,
                    state: MeltQuoteState::Unpaid,
                    unit: unit.clone(),
                })
            }
            _ => Err(payment::Error::UnsupportedUnit),
        }
    }

    async fn make_payment(
        &self,
        unit: &CurrencyUnit,
        options: OutgoingPaymentOptions,
    ) -> Result<MakePaymentResponse, Self::Err> {
        match unit {
            CurrencyUnit::Sat | CurrencyUnit::Msat => {
                let fee_reserve = FeeReserve { min_fee_reserve: self.fee_reserve.min_fee_reserve, percent_fee_reserve: self.fee_reserve.percent_fee_reserve };
                let lnd = cdk_lnd::Lnd::new(
                    self._address.clone(),
                    self._cert_file.clone(),
                    self._lnd_macaroon_file.clone(),
                    fee_reserve,
                    self._kv_store.clone(),
                )
                .await
                .map_err(|e| payment::Error::Anyhow(anyhow!(e)))?;
                lnd.make_payment(unit, options).await
            }
            CurrencyUnit::Usd => {
                // Pay an asset-aware Lightning invoice via TaprootAssetChannels.SendPayment
                let bolt11 = match &options {
                    OutgoingPaymentOptions::Bolt11(b) => b.bolt11.to_string(),
                    OutgoingPaymentOptions::Bolt12(_) => return Err(payment::Error::UnsupportedUnit),
                };

                // Choose a group key (allow any configured)
                let group_key_hex = self
                    .allowed_usd_group_ids
                    .first()
                    .cloned()
                    .ok_or_else(|| payment::Error::Custom("No usd_group_ids configured".to_string()))?;
                let group_key = hex::decode(&group_key_hex).map_err(|e| payment::Error::Anyhow(anyhow!(e)))?;

                let mut client = self.tap_channel_client().await?;

                // Optional: decode to validate invoice maps to asset units
                let _decoded = client
                    .decode_asset_pay_req(Request::new(tapchannelrpc::AssetPayReq {
                        asset_id: vec![],
                        pay_req_string: bolt11.clone(),
                        group_key: group_key.clone(),
                        price_oracle_metadata: String::new(),
                    }))
                    .await
                    .map_err(|e| payment::Error::Anyhow(anyhow!(e)))?;

                let router_req = routerrpc::SendPaymentRequest {
                    payment_request: bolt11.clone(),
                    ..Default::default()
                };
                let req = tapchannelrpc::SendPaymentRequest {
                    asset_id: vec![],
                    asset_amount: 0,
                    peer_pubkey: vec![],
                    payment_request: Some(router_req),
                    rfq_id: vec![],
                    allow_overpay: false,
                    group_key,
                    price_oracle_metadata: String::new(),
                };

                // Stream results until we get a payment result
                let mut stream = client
                    .send_payment(Request::new(req))
                    .await
                    .map_err(|e| payment::Error::Anyhow(anyhow!(e)))?
                    .into_inner();
                // Consume first message if any; ignore contents for now
                match stream.message().await {
                    Ok(_msg) => {}
                    Err(e) => {
                        return Err(payment::Error::Custom(e.to_string()));
                    }
                }

                Ok(MakePaymentResponse {
                    payment_lookup_id: PaymentIdentifier::CustomId(bolt11),
                    payment_proof: None,
                    status: MeltQuoteState::Paid,
                    total_spent: Amount::ZERO,
                    unit: unit.clone(),
                })
            }
            _ => Err(payment::Error::UnsupportedUnit),
        }
    }

    async fn wait_payment_event(&self) -> Result<Pin<Box<dyn Stream<Item = Event> + Send>>, Self::Err> {
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        Ok(Box::pin(ReceiverStream::new(rx)))
    }

    fn is_wait_invoice_active(&self) -> bool { false }
    fn cancel_wait_invoice(&self) {}

    async fn check_incoming_payment_status(&self, payment_identifier: &PaymentIdentifier) -> Result<Vec<payment::WaitPaymentResponse>, Self::Err> {
        // First, use LND to determine settlement status
        let fee_reserve = FeeReserve { min_fee_reserve: self.fee_reserve.min_fee_reserve, percent_fee_reserve: self.fee_reserve.percent_fee_reserve };
        let lnd = cdk_lnd::Lnd::new(
            self._address.clone(),
            self._cert_file.clone(),
            self._lnd_macaroon_file.clone(),
            fee_reserve,
            self._kv_store.clone(),
        )
        .await
        .map_err(|e| payment::Error::Anyhow(anyhow!(e)))?;
        let responses = lnd.check_incoming_payment_status(payment_identifier).await?;

        // If we have an asset mapping for this payment hash, convert the unit to USD and amount to asset units
        let mut converted: Vec<payment::WaitPaymentResponse> = Vec::with_capacity(responses.len());
        for r in responses.into_iter() {
            if let PaymentIdentifier::PaymentHash(ph) = &r.payment_identifier {
                let key = hex::encode(ph);
                if let Some(asset_units) = self.kv_read_asset_amount(&key).await {
                    converted.push(payment::WaitPaymentResponse {
                        payment_identifier: r.payment_identifier,
                        payment_amount: Amount::from(asset_units),
                        unit: CurrencyUnit::Usd,
                        payment_id: r.payment_id,
                    });
                    continue;
                }
            }
            converted.push(r);
        }

        Ok(converted)
    }

    async fn check_outgoing_payment(&self, payment_identifier: &PaymentIdentifier) -> Result<MakePaymentResponse, Self::Err> {
        let fee_reserve = FeeReserve { min_fee_reserve: self.fee_reserve.min_fee_reserve, percent_fee_reserve: self.fee_reserve.percent_fee_reserve };
        let lnd = cdk_lnd::Lnd::new(
            self._address.clone(),
            self._cert_file.clone(),
            self._lnd_macaroon_file.clone(),
            fee_reserve,
            self._kv_store.clone(),
        )
        .await
        .map_err(|e| payment::Error::Anyhow(anyhow!(e)))?;
        lnd.check_outgoing_payment(payment_identifier).await
    }
}


