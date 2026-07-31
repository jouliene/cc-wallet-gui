use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use reqwest::redirect::Policy;
use reqwest::{Client, StatusCode, Url};
use serde::de::{self, DeserializeOwned, Deserializer};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tycho_types::boc::{Boc, BocRepr};
use tycho_types::cell::{Cell, DynCell, Load};
use tycho_types::models::account::Account;
use tycho_types::models::{BlockchainConfig, SignatureContext};

#[derive(Debug, Clone)]
pub struct Transport {
    inner: TransportInner,
}

#[derive(Debug, Clone)]
enum TransportInner {
    Jrpc(JrpcTransport),
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TransportKind {
    Jrpc,
}

impl fmt::Display for TransportKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Jrpc => f.write_str("jrpc"),
        }
    }
}

impl Transport {
    pub fn jrpc(endpoint: impl AsRef<str>) -> Result<Self> {
        Ok(Self {
            inner: TransportInner::Jrpc(JrpcTransport::new(endpoint)?),
        })
    }

    #[inline]
    pub fn kind(&self) -> TransportKind {
        match &self.inner {
            TransportInner::Jrpc(_) => TransportKind::Jrpc,
        }
    }

    #[inline]
    pub fn endpoint(&self) -> &str {
        match &self.inner {
            TransportInner::Jrpc(transport) => transport.endpoint(),
        }
    }

    pub async fn get_blockchain_config_observed(&self) -> Result<ObservedBlockchainConfigState> {
        match &self.inner {
            TransportInner::Jrpc(transport) => transport.get_blockchain_config_observed().await,
        }
    }

    pub async fn get_latest_key_block(&self) -> Result<Cell> {
        match &self.inner {
            TransportInner::Jrpc(transport) => transport.get_latest_key_block().await,
        }
    }

    pub async fn get_account_state(&self, address: impl AsRef<str>) -> Result<AccountState> {
        self.get_account_state_since(address, None).await
    }

    pub async fn get_account_state_since(
        &self,
        address: impl AsRef<str>,
        last_transaction_lt: Option<u64>,
    ) -> Result<AccountState> {
        match &self.inner {
            TransportInner::Jrpc(transport) => {
                transport
                    .get_account_state_since(address, last_transaction_lt)
                    .await
            }
        }
    }

    pub async fn get_account_state_observed(
        &self,
        address: impl AsRef<str>,
    ) -> Result<ObservedAccountState> {
        match &self.inner {
            TransportInner::Jrpc(transport) => transport.get_account_state_observed(address).await,
        }
    }

    pub async fn get_account_state_observed_since(
        &self,
        address: impl AsRef<str>,
        last_transaction_lt: Option<u64>,
    ) -> Result<ObservedAccountState> {
        match &self.inner {
            TransportInner::Jrpc(transport) => {
                transport
                    .get_account_state_observed_since(address, last_transaction_lt)
                    .await
            }
        }
    }

    pub async fn resolve_send_route(&self) -> Result<ResolvedSendRoute> {
        match &self.inner {
            TransportInner::Jrpc(transport) => transport.resolve_send_route().await,
        }
    }

    pub async fn send_message_cell_candidate_classified(
        &self,
        route: &ResolvedSendRoute,
        candidate_index: usize,
        message: impl AsRef<DynCell>,
    ) -> std::result::Result<BroadcastAcknowledgement, SendAttemptOutcome> {
        match &self.inner {
            TransportInner::Jrpc(transport) => {
                transport
                    .send_message_base64_candidate_classified(
                        route,
                        candidate_index,
                        Boc::encode_base64(message),
                    )
                    .await
            }
        }
    }

    pub async fn get_transaction(&self, hash: impl AsRef<str>) -> Result<Option<String>> {
        match &self.inner {
            TransportInner::Jrpc(transport) => transport.get_transaction(hash).await,
        }
    }

    pub async fn get_dst_transaction(
        &self,
        message_hash: impl AsRef<str>,
    ) -> Result<Option<String>> {
        match &self.inner {
            TransportInner::Jrpc(transport) => transport.get_dst_transaction(message_hash).await,
        }
    }

    pub async fn get_transactions_list(
        &self,
        account: impl AsRef<str>,
        limit: u32,
        before_lt: Option<u64>,
    ) -> Result<Vec<String>> {
        match &self.inner {
            TransportInner::Jrpc(transport) => {
                transport
                    .get_transactions_list(account, limit, before_lt)
                    .await
            }
        }
    }

    pub async fn get_transactions_list_observed(
        &self,
        account: impl AsRef<str>,
        limit: u32,
        before_lt: Option<u64>,
    ) -> Result<ObservedTransactionsList> {
        match &self.inner {
            TransportInner::Jrpc(transport) => {
                transport
                    .get_transactions_list_observed(account, limit, before_lt)
                    .await
            }
        }
    }
}

impl From<JrpcTransport> for Transport {
    fn from(value: JrpcTransport) -> Self {
        Self {
            inner: TransportInner::Jrpc(value),
        }
    }
}

impl From<&Transport> for Transport {
    fn from(value: &Transport) -> Self {
        value.clone()
    }
}

#[derive(Clone)]
pub struct ResolvedSendRoute {
    endpoint_identity: Arc<str>,
    candidates: Arc<[Url]>,
    probe_request_ids: Arc<[String]>,
    observed_at_mono: Instant,
}

impl fmt::Debug for ResolvedSendRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedSendRoute")
            .field(
                "endpoint_identity",
                &diagnostic_endpoint(&self.endpoint_identity),
            )
            .field("candidate_count", &self.candidates.len())
            .field("probe_count", &self.probe_request_ids.len())
            .field("observed_at_mono", &self.observed_at_mono)
            .finish()
    }
}

impl ResolvedSendRoute {
    pub fn candidate_count(&self) -> usize {
        self.candidates.len()
    }

    pub fn route_id(&self) -> String {
        self.candidates
            .iter()
            .map(Url::as_str)
            .collect::<Vec<_>>()
            .join("|")
    }

    pub fn probe_request_ids(&self) -> &[String] {
        &self.probe_request_ids
    }

    pub fn observed_at_mono(&self) -> Instant {
        self.observed_at_mono
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BroadcastAcknowledgement {
    pub request_id: String,
}

#[derive(Debug, Clone)]
pub struct ObservedTransactionsList {
    pub(crate) values: Vec<String>,
    pub(crate) request_id: String,
    pub(crate) observed_at_mono: Instant,
}

impl ObservedTransactionsList {
    pub fn values(&self) -> &[String] {
        &self.values
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn observed_at_mono(&self) -> Instant {
        self.observed_at_mono
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalReason {
    InvalidMessage(String),
    RouteEndpointMismatch(String),
    AllCandidatesFailedPreConnect(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteOrTransportReason {
    PostConnect(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseKind {
    HttpStatus {
        request_id: String,
        status: u16,
        detail: String,
    },
    Redirect {
        request_id: String,
        status: u16,
        location: Option<String>,
    },
    JsonRpcError {
        request_id: String,
        detail: String,
    },
    MalformedSuccess {
        request_id: String,
        detail: String,
    },
}

impl ResponseKind {
    pub fn request_id(&self) -> &str {
        match self {
            Self::HttpStatus { request_id, .. }
            | Self::Redirect { request_id, .. }
            | Self::JsonRpcError { request_id, .. }
            | Self::MalformedSuccess { request_id, .. } => request_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendAttemptOutcome {
    NotTransmitted(LocalReason),
    MayHaveBroadcast(RemoteOrTransportReason),
    NodeResponseObserved(ResponseKind),
}

impl SendAttemptOutcome {
    pub fn is_not_transmitted(&self) -> bool {
        matches!(self, Self::NotTransmitted(_))
    }

    pub fn may_have_broadcast(&self) -> bool {
        !self.is_not_transmitted()
    }
}

impl fmt::Display for SendAttemptOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotTransmitted(LocalReason::InvalidMessage(detail)) => {
                write!(f, "signed message was not transmitted: {detail}")
            }
            Self::NotTransmitted(LocalReason::RouteEndpointMismatch(detail)) => {
                write!(
                    f,
                    "signed message route was rejected before transmission: {detail}"
                )
            }
            Self::NotTransmitted(LocalReason::AllCandidatesFailedPreConnect(details)) => write!(
                f,
                "signed message was not transmitted; every pre-resolved route failed before connection: {}",
                details.join("; ")
            ),
            Self::MayHaveBroadcast(RemoteOrTransportReason::PostConnect(detail)) => {
                write!(f, "signed message may have reached the node: {detail}")
            }
            Self::NodeResponseObserved(ResponseKind::HttpStatus { status, detail, .. }) => {
                write!(
                    f,
                    "node/proxy returned HTTP {status}; delivery is unresolved: {detail}"
                )
            }
            Self::NodeResponseObserved(ResponseKind::Redirect {
                status, location, ..
            }) => write!(
                f,
                "node/proxy returned redirect HTTP {status} to {}; redirect was not followed and delivery is unresolved",
                location.as_deref().unwrap_or("<missing location>")
            ),
            Self::NodeResponseObserved(ResponseKind::JsonRpcError { detail, .. }) => write!(
                f,
                "node returned a JSON-RPC error; delivery is unresolved: {detail}"
            ),
            Self::NodeResponseObserved(ResponseKind::MalformedSuccess { detail, .. }) => write!(
                f,
                "node returned a malformed success response; delivery is unresolved: {detail}"
            ),
        }
    }
}

impl std::error::Error for SendAttemptOutcome {}

#[derive(Clone, PartialEq, Eq)]
pub struct ObservedNetworkTime {
    pub value: u32,
    pub source_endpoint: String,
    pub request_id: String,
    pub observed_at_mono: Instant,
}

impl fmt::Debug for ObservedNetworkTime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObservedNetworkTime")
            .field("value", &self.value)
            .field(
                "source_endpoint",
                &diagnostic_endpoint(&self.source_endpoint),
            )
            .field("request_id", &self.request_id)
            .field("observed_at_mono", &self.observed_at_mono)
            .finish()
    }
}

#[derive(Debug)]
struct ObservedRpc<R> {
    result: R,
    request_id: u64,
    observed_at_mono: Instant,
}

#[derive(Clone)]
pub(crate) struct JrpcTransport {
    inner: Arc<JrpcTransportInner>,
}

impl fmt::Debug for JrpcTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JrpcTransport")
            .field("endpoint", &diagnostic_endpoint(self.endpoint()))
            .finish_non_exhaustive()
    }
}

const MAX_JRPC_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

pub const MAX_EXTERNAL_MESSAGE_BOC_BYTES: usize = 64 * 1024;
pub const MAX_BLOCKCHAIN_CONFIG_BOC_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_ACCOUNT_STATE_BOC_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_KEY_BLOCK_BOC_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
pub(crate) struct HttpClientConfig {
    connect_timeout: Duration,
    request_timeout: Option<Duration>,
    read_timeout: Option<Duration>,
    #[cfg(test)]
    http2_prior_knowledge: bool,
}

impl HttpClientConfig {
    pub(crate) const fn request(connect_timeout: Duration, request_timeout: Duration) -> Self {
        Self {
            connect_timeout,
            request_timeout: Some(request_timeout),
            read_timeout: None,
            #[cfg(test)]
            http2_prior_knowledge: false,
        }
    }

    pub(crate) const fn streaming(connect_timeout: Duration, read_timeout: Duration) -> Self {
        Self {
            connect_timeout,
            request_timeout: None,
            read_timeout: Some(read_timeout),
            #[cfg(test)]
            http2_prior_knowledge: false,
        }
    }

    #[cfg(test)]
    const fn http2_capability_probe() -> Self {
        Self {
            connect_timeout: Duration::from_secs(1),
            request_timeout: Some(Duration::from_secs(1)),
            read_timeout: None,
            http2_prior_knowledge: true,
        }
    }
}

pub(crate) fn build_http_client(config: HttpClientConfig) -> reqwest::Result<Client> {
    let mut builder = Client::builder()
        .connect_timeout(config.connect_timeout)
        .redirect(Policy::none());
    if let Some(timeout) = config.request_timeout {
        builder = builder.timeout(timeout);
    }
    if let Some(timeout) = config.read_timeout {
        builder = builder.read_timeout(timeout);
    }
    #[cfg(test)]
    if config.http2_prior_knowledge {
        builder = builder.http2_prior_knowledge();
    }
    builder.build()
}

#[derive(Debug)]
struct JrpcTransportInner {
    client: Client,
    endpoint: String,
    url: Url,
    next_id: AtomicU64,
}

impl JrpcTransport {
    pub fn new(endpoint: impl AsRef<str>) -> Result<Self> {
        Self::with_timeouts(endpoint, Duration::from_secs(5), Duration::from_secs(10))
    }

    pub fn with_timeouts(
        endpoint: impl AsRef<str>,
        connect_timeout: Duration,
        request_timeout: Duration,
    ) -> Result<Self> {
        let endpoint = canonicalize_endpoint(endpoint.as_ref())?.to_string();
        let url = jrpc_url(&endpoint)?;
        let client = build_http_client(HttpClientConfig::request(connect_timeout, request_timeout))
            .context("failed to build JRPC HTTP client")?;

        Ok(Self {
            inner: Arc::new(JrpcTransportInner {
                client,
                endpoint,
                url,
                next_id: AtomicU64::new(1),
            }),
        })
    }

    #[inline]
    pub fn endpoint(&self) -> &str {
        &self.inner.endpoint
    }

    #[cfg(test)]
    pub fn url(&self) -> String {
        self.inner.url.to_string()
    }

    pub async fn call<P, R>(&self, method: &str, params: P) -> Result<R>
    where
        P: Serialize,
        R: DeserializeOwned,
    {
        Ok(self.call_observed(method, params).await?.result)
    }

    async fn call_observed<P, R>(&self, method: &str, params: P) -> Result<ObservedRpc<R>>
    where
        P: Serialize,
        R: DeserializeOwned,
    {
        match self.call_url(&self.inner.url, method, &params).await {
            Ok(result) => Ok(result),
            Err(JrpcCallError::Fallback(error) | JrpcCallError::Fatal(error)) => Err(error),
        }
    }

    pub async fn get_blockchain_config_observed(&self) -> Result<ObservedBlockchainConfigState> {
        let observed: ObservedRpc<RawBlockchainConfigState> =
            self.call_observed("getBlockchainConfig", json!({})).await?;
        Ok(ObservedBlockchainConfigState {
            state: observed.result.try_into()?,
            request_id: observed.request_id.to_string(),
            observed_at_mono: observed.observed_at_mono,
        })
    }

    pub async fn get_latest_key_block(&self) -> Result<Cell> {
        let raw: RawKeyBlock = self.call("getLatestKeyBlock", json!({})).await?;
        ensure_boc_base64_size(&raw.block, MAX_KEY_BLOCK_BOC_BYTES, "key block")?;
        let bytes = BASE64
            .decode(&raw.block)
            .context("key block is not canonical base64")?;
        if bytes.len() > MAX_KEY_BLOCK_BOC_BYTES {
            bail!("key block BOC exceeds {MAX_KEY_BLOCK_BOC_BYTES} decoded bytes");
        }
        Boc::decode(&bytes).context("failed to decode the latest key block")
    }

    pub async fn get_account_state_since(
        &self,
        address: impl AsRef<str>,
        last_transaction_lt: Option<u64>,
    ) -> Result<AccountState> {
        Ok(self
            .get_account_state_observed_since(address, last_transaction_lt)
            .await?
            .state)
    }

    pub async fn get_account_state_observed(
        &self,
        address: impl AsRef<str>,
    ) -> Result<ObservedAccountState> {
        self.get_account_state_observed_since(address, None).await
    }

    pub async fn get_account_state_observed_since(
        &self,
        address: impl AsRef<str>,
        last_transaction_lt: Option<u64>,
    ) -> Result<ObservedAccountState> {
        let params = match last_transaction_lt {
            Some(lt) => json!({ "address": address.as_ref(), "lastTransactionLt": lt.to_string() }),
            None => json!({ "address": address.as_ref() }),
        };
        let observed: ObservedRpc<RawAccountState> =
            self.call_observed("getContractState", params).await?;
        let state: AccountState = observed.result.try_into()?;
        let network_time = state.timings().map(|timings| ObservedNetworkTime {
            value: timings.gen_utime,
            source_endpoint: self.endpoint().to_owned(),
            request_id: observed.request_id.to_string(),
            observed_at_mono: observed.observed_at_mono,
        });
        Ok(ObservedAccountState {
            state,
            network_time,
            request_id: observed.request_id.to_string(),
            observed_at_mono: observed.observed_at_mono,
        })
    }

    pub async fn resolve_send_route(&self) -> Result<ResolvedSendRoute> {
        Ok(ResolvedSendRoute {
            endpoint_identity: Arc::from(self.endpoint()),
            candidates: vec![self.inner.url.clone()].into(),
            probe_request_ids: Vec::new().into(),
            observed_at_mono: Instant::now(),
        })
    }

    pub async fn send_message_base64_candidate_classified(
        &self,
        route: &ResolvedSendRoute,
        candidate_index: usize,
        message_boc_base64: impl AsRef<str>,
    ) -> std::result::Result<BroadcastAcknowledgement, SendAttemptOutcome> {
        if route.endpoint_identity.as_ref() != self.endpoint() {
            return Err(SendAttemptOutcome::NotTransmitted(
                LocalReason::RouteEndpointMismatch(
                    "route endpoint identity differs from the active transport".to_owned(),
                ),
            ));
        }
        validate_message_boc_base64(message_boc_base64.as_ref()).map_err(|error| {
            SendAttemptOutcome::NotTransmitted(LocalReason::InvalidMessage(error.to_string()))
        })?;
        let Some(candidate) = route.candidates.get(candidate_index) else {
            return Err(SendAttemptOutcome::NotTransmitted(
                LocalReason::RouteEndpointMismatch(
                    "route candidate index is outside the pre-resolved route".to_owned(),
                ),
            ));
        };
        self.broadcast_once(candidate, message_boc_base64.as_ref())
            .await
    }

    async fn broadcast_once(
        &self,
        url: &Url,
        message_boc_base64: &str,
    ) -> std::result::Result<BroadcastAcknowledgement, SendAttemptOutcome> {
        let diagnostic_url = diagnostic_url(url);
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        let request = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "sendMessage",
            "params": { "message": message_boc_base64 },
        });

        let response = self
            .inner
            .client
            .post(url.clone())
            .json(&request)
            .send()
            .await
            .map_err(|error| {
                let is_connect = error.is_connect();
                let error = error.without_url();
                if is_connect {
                    SendAttemptOutcome::NotTransmitted(LocalReason::AllCandidatesFailedPreConnect(
                        vec![format!(
                            "failed to connect for sendMessage to {diagnostic_url}: {error}"
                        )],
                    ))
                } else {
                    SendAttemptOutcome::MayHaveBroadcast(RemoteOrTransportReason::PostConnect(
                        format!("sendMessage to {diagnostic_url} did not complete: {error}"),
                    ))
                }
            })?;

        let status = response.status();
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let body = read_response_bytes_limited(response)
            .await
            .map_err(|error| {
                SendAttemptOutcome::NodeResponseObserved(ResponseKind::MalformedSuccess {
                    request_id: id.to_string(),
                    detail: error.to_string(),
                })
            })?;
        let detail = format!("{}-byte response body omitted", body.len());
        if status.is_redirection() {
            return Err(SendAttemptOutcome::NodeResponseObserved(
                ResponseKind::Redirect {
                    request_id: id.to_string(),
                    status: status.as_u16(),
                    location,
                },
            ));
        }
        if !status.is_success() {
            return Err(SendAttemptOutcome::NodeResponseObserved(
                ResponseKind::HttpStatus {
                    request_id: id.to_string(),
                    status: status.as_u16(),
                    detail,
                },
            ));
        }

        let value: Value = serde_json::from_slice(&body).map_err(|error| {
            SendAttemptOutcome::NodeResponseObserved(ResponseKind::MalformedSuccess {
                request_id: id.to_string(),
                detail: format!("sendMessage response at {diagnostic_url} was not JSON: {error}"),
            })
        })?;
        if let Err(error) = validate_jrpc_response_id(&value, "sendMessage", id) {
            return Err(SendAttemptOutcome::NodeResponseObserved(
                ResponseKind::MalformedSuccess {
                    request_id: id.to_string(),
                    detail: error.to_string(),
                },
            ));
        }
        if value.get("error").is_some_and(|error| !error.is_null()) {
            let error = parse_jrpc_result::<Value>(value, "sendMessage")
                .expect_err("a non-null JSON-RPC error cannot parse as success");
            return Err(SendAttemptOutcome::NodeResponseObserved(
                ResponseKind::JsonRpcError {
                    request_id: id.to_string(),
                    detail: error.to_string(),
                },
            ));
        }
        parse_jrpc_result::<Value>(value, "sendMessage")
            .map(|_| BroadcastAcknowledgement {
                request_id: id.to_string(),
            })
            .map_err(|error| {
                SendAttemptOutcome::NodeResponseObserved(ResponseKind::MalformedSuccess {
                    request_id: id.to_string(),
                    detail: error.to_string(),
                })
            })
    }

    pub async fn get_transaction(&self, hash: impl AsRef<str>) -> Result<Option<String>> {
        self.call("getTransaction", json!({ "id": hash.as_ref() }))
            .await
    }

    pub async fn get_dst_transaction(
        &self,
        message_hash: impl AsRef<str>,
    ) -> Result<Option<String>> {
        self.call(
            "getDstTransaction",
            json!({ "messageHash": message_hash.as_ref() }),
        )
        .await
    }

    pub async fn get_transactions_list(
        &self,
        account: impl AsRef<str>,
        limit: u32,
        before_lt: Option<u64>,
    ) -> Result<Vec<String>> {
        Ok(self
            .get_transactions_list_observed(account, limit, before_lt)
            .await?
            .values)
    }

    pub async fn get_transactions_list_observed(
        &self,
        account: impl AsRef<str>,
        limit: u32,
        before_lt: Option<u64>,
    ) -> Result<ObservedTransactionsList> {
        let params = match before_lt {
            Some(lt) => json!({
                "account": account.as_ref(),
                "limit": limit,
                "lastTransactionLt": lt.to_string(),
            }),
            None => json!({ "account": account.as_ref(), "limit": limit }),
        };
        let observed: ObservedRpc<Vec<String>> =
            self.call_observed("getTransactionsList", params).await?;
        Ok(ObservedTransactionsList {
            values: observed.result,
            request_id: observed.request_id.to_string(),
            observed_at_mono: observed.observed_at_mono,
        })
    }

    async fn call_url<P, R>(
        &self,
        url: &Url,
        method: &str,
        params: &P,
    ) -> std::result::Result<ObservedRpc<R>, JrpcCallError>
    where
        P: Serialize,
        R: DeserializeOwned,
    {
        let diagnostic_url = diagnostic_url(url);
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        let request = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });

        let response = self
            .inner
            .client
            .post(url.clone())
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                let e = e.without_url();
                JrpcCallError::Fallback(anyhow!(
                    "failed to send `{method}` to {diagnostic_url}: {e}"
                ))
            })?;

        let status = response.status();
        if !status.is_success() {
            let body = read_response_bytes_limited(response)
                .await
                .map(|bytes| format!("{}-byte response body omitted", bytes.len()))
                .unwrap_or_else(|error| format!("<unreadable bounded body: {error}>"));
            let error = anyhow!("HTTP error {status} for `{method}` at {diagnostic_url}: {body}");
            return if can_try_next_url(status) {
                Err(JrpcCallError::Fallback(error))
            } else {
                Err(JrpcCallError::Fatal(error))
            };
        }

        let body = read_response_bytes_limited(response).await.map_err(|e| {
            JrpcCallError::Fallback(anyhow!(
                "failed to read bounded JSON response for `{method}` at {diagnostic_url}: {e}"
            ))
        })?;
        let value = serde_json::from_slice::<Value>(&body).map_err(|e| {
            JrpcCallError::Fallback(anyhow!(
                "failed to parse JSON response for `{method}` at {diagnostic_url}: {e}"
            ))
        })?;

        parse_jrpc_result_for_id(value, method, id)
            .map(|result| ObservedRpc {
                result,
                request_id: id,
                observed_at_mono: Instant::now(),
            })
            .map_err(JrpcCallError::Fatal)
    }
}

#[derive(Debug)]
enum JrpcCallError {
    Fallback(anyhow::Error),
    Fatal(anyhow::Error),
}

#[derive(Debug, Clone)]
pub struct BlockchainConfigState {
    pub global_id: i32,
    pub seqno: u32,
    pub config_boc_base64: String,
    pub config: BlockchainConfig,
}

impl BlockchainConfigState {
    pub fn signature_context(&self) -> Result<SignatureContext> {
        Ok(SignatureContext {
            global_id: self.global_id,
            capabilities: self.config.get_global_version()?.capabilities,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ObservedBlockchainConfigState {
    pub(crate) state: BlockchainConfigState,
    pub(crate) request_id: String,
    pub(crate) observed_at_mono: Instant,
}

impl ObservedBlockchainConfigState {
    pub fn state(&self) -> &BlockchainConfigState {
        &self.state
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn observed_at_mono(&self) -> Instant {
        self.observed_at_mono
    }
}

#[derive(Deserialize)]
struct RawKeyBlock {
    block: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawBlockchainConfigState {
    global_id: i32,
    seqno: u32,
    config: String,
}

impl TryFrom<RawBlockchainConfigState> for BlockchainConfigState {
    type Error = anyhow::Error;

    fn try_from(value: RawBlockchainConfigState) -> Result<Self> {
        ensure_boc_base64_size(
            &value.config,
            MAX_BLOCKCHAIN_CONFIG_BOC_BYTES,
            "blockchain config",
        )?;
        let config: BlockchainConfig = decode_boc_base64_limited(
            &value.config,
            MAX_BLOCKCHAIN_CONFIG_BOC_BYTES,
            "blockchain config",
        )
        .context("failed to decode blockchain config")?;
        if let Ok(param19) = config.get_global_id()
            && param19 != value.global_id
        {
            bail!(
                "endpoint reports globalId {} but its blockchain config (param 19) says {} — \
                 the endpoint's network identity is inconsistent; refusing its config",
                value.global_id,
                param19
            );
        }
        Ok(Self {
            global_id: value.global_id,
            seqno: value.seqno,
            config,
            config_boc_base64: value.config,
        })
    }
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum AccountState {
    Exists {
        account: Account,
        account_boc_base64: String,
        last_transaction_id: Option<LastTransactionId>,
        timings: AccountTimings,
    },
    NotExists {
        timings: Option<AccountTimings>,
    },
    Unchanged {
        timings: AccountTimings,
    },
}

impl AccountState {
    #[inline]
    pub fn exists(&self) -> bool {
        matches!(self, Self::Exists { .. } | Self::Unchanged { .. })
    }

    #[inline]
    pub fn is_unchanged(&self) -> bool {
        matches!(self, Self::Unchanged { .. })
    }

    pub fn account(&self) -> Option<&Account> {
        match self {
            Self::Exists { account, .. } => Some(account),
            Self::NotExists { .. } | Self::Unchanged { .. } => None,
        }
    }

    pub fn timings(&self) -> Option<&AccountTimings> {
        match self {
            Self::Exists { timings, .. } | Self::Unchanged { timings } => Some(timings),
            Self::NotExists { timings } => timings.as_ref(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ObservedAccountState {
    pub(crate) state: AccountState,
    pub(crate) network_time: Option<ObservedNetworkTime>,
    pub(crate) request_id: String,
    pub(crate) observed_at_mono: Instant,
}

impl ObservedAccountState {
    pub fn state(&self) -> &AccountState {
        &self.state
    }

    pub fn network_time(&self) -> Option<&ObservedNetworkTime> {
        self.network_time.as_ref()
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn observed_at_mono(&self) -> Instant {
        self.observed_at_mono
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
enum RawAccountState {
    Exists {
        account: String,
        #[serde(default, rename = "lastTransactionId")]
        last_transaction_id: Option<LastTransactionId>,
        timings: AccountTimings,
    },
    NotExists {
        #[serde(default)]
        timings: Option<AccountTimings>,
    },
    Unchanged {
        timings: AccountTimings,
    },
}

impl TryFrom<RawAccountState> for AccountState {
    type Error = anyhow::Error;

    fn try_from(value: RawAccountState) -> Result<Self> {
        match value {
            RawAccountState::Exists {
                account,
                last_transaction_id,
                timings,
            } => Ok(Self::Exists {
                account: {
                    ensure_boc_base64_size(&account, MAX_ACCOUNT_STATE_BOC_BYTES, "account state")?;
                    decode_boc_base64_limited(
                        &account,
                        MAX_ACCOUNT_STATE_BOC_BYTES,
                        "account state",
                    )
                    .context("failed to decode account state")?
                },
                account_boc_base64: account,
                last_transaction_id,
                timings,
            }),
            RawAccountState::NotExists { timings } => Ok(Self::NotExists { timings }),
            RawAccountState::Unchanged { timings } => Ok(Self::Unchanged { timings }),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LastTransactionId {
    pub hash: String,
    #[serde(default = "default_true")]
    pub is_exact: bool,
    #[serde(deserialize_with = "de_u64_string_or_number")]
    pub lt: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountTimings {
    #[serde(deserialize_with = "de_u64_string_or_number")]
    pub gen_lt: u64,
    pub gen_utime: u32,
}

#[derive(Debug, Clone, Deserialize)]
struct JrpcError {
    code: i64,
    message: String,
}

impl fmt::Display for JrpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.message, self.code)
    }
}

pub(crate) fn parse_jrpc_result<R>(value: Value, method: &str) -> Result<R>
where
    R: DeserializeOwned,
{
    let result_present = value.get("result").is_some();
    let non_null_error = value.get("error").filter(|error| !error.is_null());
    if result_present && non_null_error.is_some() {
        bail!(
            "malformed JRPC response for `{method}`: both `result` and a non-null `error` are present"
        );
    }
    if let Some(error) = non_null_error {
        let error: JrpcError =
            serde_json::from_value(error.clone()).unwrap_or_else(|_| JrpcError {
                code: 0,
                message: "malformed JSON-RPC error object (detail omitted)".to_owned(),
            });
        bail!("JRPC error for `{method}`: {error}");
    }

    let result = value
        .get("result")
        .cloned()
        .ok_or_else(|| anyhow!("missing `result` field in JRPC response for `{method}`"))?;

    serde_json::from_value(result)
        .with_context(|| format!("failed to deserialize result for `{method}`"))
}

fn validate_jrpc_response_id(value: &Value, method: &str, expected_id: u64) -> Result<()> {
    if value.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        bail!("malformed JRPC response for `{method}`: `jsonrpc` must be exactly `2.0`");
    }
    if value.get("id").and_then(Value::as_u64) != Some(expected_id) {
        bail!(
            "malformed JRPC response for `{method}`: response id does not match request {expected_id}"
        );
    }
    Ok(())
}

pub(crate) fn parse_jrpc_result_for_id<R>(value: Value, method: &str, expected_id: u64) -> Result<R>
where
    R: DeserializeOwned,
{
    validate_jrpc_response_id(&value, method, expected_id)?;
    parse_jrpc_result(value, method)
}

pub(crate) async fn read_response_bytes_limited(
    mut response: reqwest::Response,
) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_JRPC_RESPONSE_BYTES as u64)
    {
        bail!("JSON-RPC response exceeds {MAX_JRPC_RESPONSE_BYTES} bytes");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| anyhow!("response body read failed: {}", error.without_url()))?
    {
        if bytes.len().saturating_add(chunk.len()) > MAX_JRPC_RESPONSE_BYTES {
            bail!("JSON-RPC response exceeds {MAX_JRPC_RESPONSE_BYTES} bytes");
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn validate_message_boc_base64(value: &str) -> Result<()> {
    if value.len() > MAX_EXTERNAL_MESSAGE_BOC_BYTES.saturating_mul(4).div_ceil(3) + 4 {
        bail!("external-message BOC exceeds {MAX_EXTERNAL_MESSAGE_BOC_BYTES} bytes");
    }
    let bytes = BASE64
        .decode(value)
        .context("external message is not canonical base64")?;
    if bytes.is_empty() || bytes.len() > MAX_EXTERNAL_MESSAGE_BOC_BYTES {
        bail!("external-message BOC must contain 1..={MAX_EXTERNAL_MESSAGE_BOC_BYTES} bytes");
    }
    let _: Cell = Boc::decode(&bytes).context("external message is not a valid BOC")?;
    Ok(())
}

fn ensure_boc_base64_size(value: &str, max_bytes: usize, label: &str) -> Result<()> {
    let max_encoded = max_bytes.saturating_mul(4).div_ceil(3) + 4;
    if value.len() > max_encoded {
        bail!("{label} BOC exceeds {max_bytes} decoded bytes");
    }
    Ok(())
}

fn decode_boc_base64_limited<T>(boc_base64: &str, max_bytes: usize, label: &str) -> Result<T>
where
    for<'a> T: Load<'a>,
{
    ensure_boc_base64_size(boc_base64, max_bytes, label)?;
    let bytes = BASE64
        .decode(boc_base64)
        .with_context(|| format!("{label} is not canonical base64"))?;
    if bytes.len() > max_bytes {
        bail!("{label} BOC exceeds {max_bytes} decoded bytes");
    }
    Ok(BocRepr::decode(&bytes)?)
}

fn can_try_next_url(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
    )
}

fn diagnostic_url(url: &Url) -> String {
    let mut redacted = url.clone();
    if redacted.query().is_some() {
        redacted.set_query(Some("redacted"));
    }
    redacted.to_string()
}

fn diagnostic_endpoint(endpoint: &str) -> String {
    Url::parse(endpoint)
        .map(|url| diagnostic_url(&url))
        .unwrap_or_else(|_| "<invalid endpoint>".to_owned())
}

pub fn canonicalize_endpoint(endpoint: &str) -> Result<Url> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        bail!("endpoint is empty");
    }
    let mut url = if endpoint.contains("://") {
        Url::parse(endpoint).context("invalid endpoint URL")?
    } else {
        let mut url = Url::parse(&format!("http://{endpoint}")).context("invalid endpoint URL")?;
        if !host_is_local(&url) {
            url.set_scheme("https")
                .map_err(|_| anyhow!("could not default endpoint {endpoint} to https"))?;
        }
        url
    };
    if !matches!(url.scheme(), "http" | "https") {
        bail!("endpoint scheme must be http or https");
    }
    if url.host_str().is_none() {
        bail!("endpoint must contain a host");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("endpoint credentials are forbidden; keep endpoint authentication out of URLs");
    }
    if url.fragment().is_some() {
        bail!("endpoint fragments are forbidden");
    }
    if url.scheme() == "http" && !host_is_local(&url) {
        bail!("public endpoint must use https");
    }
    if url.path().is_empty() {
        url.set_path("/");
    }
    Ok(url)
}

fn host_is_local(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let lower = host.to_ascii_lowercase();
    if lower == "localhost" || lower.ends_with(".localhost") {
        return true;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => ip.is_loopback() || ip.is_private() || ip.is_link_local(),
        Ok(std::net::IpAddr::V6(ip)) => {
            ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local()
        }
        Err(_) => false,
    }
}

fn jrpc_url(endpoint: &str) -> Result<Url> {
    let url = canonicalize_endpoint(endpoint)?;
    if url.as_str() == "https://rpc-testnet.tychoprotocol.com/" {
        return url
            .join("proto")
            .context("failed to build `/proto` JRPC URL");
    }
    Ok(url)
}

fn default_true() -> bool {
    true
}

fn de_u64_string_or_number<'de, D>(deserializer: D) -> std::result::Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    struct Visitor;

    impl de::Visitor<'_> for Visitor {
        type Value = u64;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a u64 as a JSON number or decimal string")
        }

        fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E> {
            Ok(value)
        }

        fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
        where
            E: de::Error,
        {
            value.parse::<u64>().map_err(E::custom)
        }
    }

    deserializer.deserialize_any(Visitor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use std::thread;
    use tycho_types::prelude::CellBuilder;

    enum MockReply {
        Bytes(Vec<u8>),
        Reset,
        Delay(Duration),
    }

    fn read_http_request(stream: &mut TcpStream) {
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut bytes = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match stream.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    bytes.extend_from_slice(&buf[..read]);
                    let Some(header_end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") else {
                        continue;
                    };
                    let header_end = header_end + 4;
                    let headers = String::from_utf8_lossy(&bytes[..header_end]);
                    let content_length = headers
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .and_then(|value| value.trim().parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    if bytes.len() >= header_end + content_length {
                        break;
                    }
                }
            }
        }
    }

    fn mock_server(reply: MockReply) -> (Url, Arc<AtomicUsize>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let thread_calls = Arc::clone(&calls);
        let handle = thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_millis(500);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if std::time::Instant::now() >= deadline {
                            return;
                        }
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => return,
                }
            };
            thread_calls.fetch_add(1, AtomicOrdering::SeqCst);
            read_http_request(&mut stream);
            match reply {
                MockReply::Bytes(bytes) => {
                    let _ = stream.write_all(&bytes);
                    let _ = stream.flush();
                }
                MockReply::Reset => {}
                MockReply::Delay(duration) => thread::sleep(duration),
            }
        });
        (
            Url::parse(&format!("http://{address}/send")).unwrap(),
            calls,
            handle,
        )
    }

    fn response(status: u16, body: &str, extra_headers: &str) -> Vec<u8> {
        let reason = if status == 200 { "OK" } else { "TEST" };
        format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n{extra_headers}\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    fn signed_boc() -> String {
        Boc::encode_base64(CellBuilder::build_from(0xabu8).unwrap())
    }

    fn transport_for_broadcast(timeout: Duration) -> JrpcTransport {
        JrpcTransport::with_timeouts("http://127.0.0.1:1", Duration::from_millis(100), timeout)
            .unwrap()
    }

    fn routes(urls: impl IntoIterator<Item = Url>) -> ResolvedSendRoute {
        ResolvedSendRoute {
            endpoint_identity: Arc::from("http://127.0.0.1:1/"),
            candidates: urls.into_iter().collect::<Vec<_>>().into(),
            probe_request_ids: vec!["probe-1".to_owned()].into(),
            observed_at_mono: Instant::now(),
        }
    }

    #[test]
    fn boc_adapter_round_trips_offline() -> Result<()> {
        let original = CellBuilder::build_from((0xfeed_beefu32, 7u8))?;
        let encoded = Boc::encode_base64(&original);
        let decoded: (u32, u8) = decode_boc_base64_limited(&encoded, 1024, "test BOC")?;

        assert_eq!(decoded, (0xfeed_beef, 7));
        Ok(())
    }

    #[test]
    fn endpoint_boc_limits_use_exact_decoded_size_before_protocol_parsing() {
        for (max, label) in [
            (MAX_BLOCKCHAIN_CONFIG_BOC_BYTES, "blockchain config"),
            (MAX_ACCOUNT_STATE_BOC_BYTES, "account state"),
        ] {
            let oversized = BASE64.encode(vec![0u8; max + 1]);
            let error = decode_boc_base64_limited::<Cell>(&oversized, max, label).unwrap_err();
            assert!(
                error.to_string().contains("exceeds"),
                "{label} must fail on decoded size before an invalid-BOC diagnostic: {error}"
            );
        }
    }

    #[test]
    fn rpc_client_retains_http2_capability() -> Result<()> {
        let _client = build_http_client(HttpClientConfig::http2_capability_probe())?;
        Ok(())
    }

    #[test]
    fn rpc_protocol_parity_vector() -> Result<()> {
        let transport = JrpcTransport::new("https://rpc-testnet.tychoprotocol.com")?;
        let request = json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "getTransactionsList",
            "params": {
                "account": "0:0000000000000000000000000000000000000000000000000000000000000000",
                "limit": 16,
                "lastTransactionLt": "42",
            },
        });
        assert_eq!(
            serde_json::to_string(&request)?,
            r#"{"id":7,"jsonrpc":"2.0","method":"getTransactionsList","params":{"account":"0:0000000000000000000000000000000000000000000000000000000000000000","lastTransactionLt":"42","limit":16}}"#
        );
        assert_eq!(
            transport.url(),
            "https://rpc-testnet.tychoprotocol.com/proto"
        );
        let response = json!({"jsonrpc": "2.0", "id": 7, "result": ["boc-a", "boc-b"]});
        assert_eq!(
            parse_jrpc_result::<Vec<String>>(response, "getTransactionsList")?,
            ["boc-a", "boc-b"]
        );
        Ok(())
    }

    #[test]
    fn built_in_tycho_endpoint_uses_only_the_exact_proto_path() -> Result<()> {
        let transport = JrpcTransport::new("https://rpc-testnet.tychoprotocol.com")?;

        assert_eq!(
            transport.url(),
            "https://rpc-testnet.tychoprotocol.com/proto"
        );
        Ok(())
    }

    #[tokio::test]
    async fn exact_route_needs_no_capability_call() -> Result<()> {
        let transport = JrpcTransport::with_timeouts(
            "http://127.0.0.1:9/proto",
            Duration::from_millis(20),
            Duration::from_millis(20),
        )?;

        let route = transport.resolve_send_route().await?;

        assert_eq!(route.candidate_count(), 1);
        assert!(route.probe_request_ids().is_empty());
        assert_eq!(route.route_id(), "http://127.0.0.1:9/proto");
        Ok(())
    }

    #[tokio::test]
    async fn custom_root_is_an_exact_route_without_capability_discovery() -> Result<()> {
        let transport = JrpcTransport::with_timeouts(
            "http://127.0.0.1:9",
            Duration::from_millis(20),
            Duration::from_millis(20),
        )?;

        let route = transport.resolve_send_route().await?;

        assert_eq!(transport.url(), "http://127.0.0.1:9/");
        assert_eq!(route.candidate_count(), 1);
        assert!(route.probe_request_ids().is_empty());
        assert_eq!(route.route_id(), "http://127.0.0.1:9/");
        Ok(())
    }

    #[test]
    fn canonicalize_prepends_scheme_for_bare_host_port() -> Result<()> {
        assert_eq!(
            canonicalize_endpoint("127.0.0.1:8001")?.as_str(),
            "http://127.0.0.1:8001/"
        );
        assert_eq!(
            canonicalize_endpoint("localhost:8001")?.as_str(),
            "http://localhost:8001/"
        );
        assert_eq!(
            canonicalize_endpoint("192.168.1.10:8001")?.as_str(),
            "http://192.168.1.10:8001/"
        );
        assert_eq!(
            canonicalize_endpoint("rpc.example.com")?.as_str(),
            "https://rpc.example.com/"
        );
        assert_eq!(
            canonicalize_endpoint("  https://rpc.example.com  ")?.as_str(),
            "https://rpc.example.com/"
        );
        assert!(canonicalize_endpoint("http://rpc.example.com").is_err());
        assert!(canonicalize_endpoint("https://user:pw@rpc.example.com").is_err());
        assert!(canonicalize_endpoint("https://rpc.example.com/#fragment").is_err());
        assert!(canonicalize_endpoint("   ").is_err());
        assert_eq!(
            JrpcTransport::new("127.0.0.1:8001")?.url(),
            "http://127.0.0.1:8001/"
        );
        Ok(())
    }

    #[test]
    fn endpoint_query_tokens_are_redacted_from_diagnostics() -> Result<()> {
        let endpoint = "https://rpc.example.com/path?token=super-secret";
        let transport = JrpcTransport::new(endpoint)?;
        let debug = format!("{transport:?}");
        assert!(!debug.contains("super-secret"));
        assert_eq!(transport.url(), endpoint);
        assert_eq!(
            diagnostic_endpoint(endpoint),
            "https://rpc.example.com/path?redacted"
        );
        Ok(())
    }

    #[test]
    fn regular_root_endpoint_is_used_exactly_as_entered() -> Result<()> {
        let transport = JrpcTransport::new("https://jrpc.everwallet.net")?;

        assert_eq!(transport.url(), "https://jrpc.everwallet.net/");
        Ok(())
    }

    #[test]
    fn parses_json_rpc_result() -> Result<()> {
        let value = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": ["boc-a", "boc-b"]
        });

        let result: Vec<String> = parse_jrpc_result(value, "getTransactionsList")?;

        assert_eq!(result, ["boc-a", "boc-b"]);
        Ok(())
    }

    #[test]
    fn parses_json_rpc_error() {
        let value = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32601,
                "message": "Method not found"
            }
        });

        let error = parse_jrpc_result::<Value>(value, "missingMethod").unwrap_err();

        assert!(error.to_string().contains("Method not found"));
    }

    #[test]
    fn a_null_error_field_is_treated_as_success() -> Result<()> {
        let value = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": null,
            "result": ["ok"]
        });

        let result: Vec<String> = parse_jrpc_result(value, "getTransactionsList")?;

        assert_eq!(result, ["ok"]);
        Ok(())
    }

    #[test]
    fn parses_not_exists_state_without_timings() -> Result<()> {
        let raw: RawAccountState = serde_json::from_value(json!({
            "type": "notExists"
        }))?;
        let state = AccountState::try_from(raw)?;

        assert!(!state.exists());
        assert!(state.timings().is_none());
        Ok(())
    }

    #[test]
    fn parses_unchanged_state_with_numeric_or_string_timings() -> Result<()> {
        let raw: RawAccountState = serde_json::from_value(json!({
            "type": "unchanged",
            "timings": {
                "genLt": "10072981000004",
                "genUtime": 1753445568
            }
        }))?;
        let state = AccountState::try_from(raw)?;

        assert!(state.exists());
        assert!(state.is_unchanged());
        assert_eq!(state.timings().unwrap().gen_lt, 10072981000004);
        Ok(())
    }

    #[test]
    fn parses_last_transaction_lt_as_u64() -> Result<()> {
        let tx: LastTransactionId = serde_json::from_value(json!({
            "isExact": true,
            "lt": "10072981000002",
            "hash": "d38aebb4b04a815309ea062bcbe817904fc3da4627e8abfcc779e49762ffcd12"
        }))?;

        assert!(tx.is_exact);
        assert_eq!(tx.lt, 10072981000002);
        Ok(())
    }

    #[test]
    fn parses_last_transaction_id_inside_account_state() -> Result<()> {
        let raw: RawAccountState = serde_json::from_value(json!({
            "type": "exists",
            "account": "unused-by-this-serde-test",
            "lastTransactionId": {
                "isExact": true,
                "lt": "10072981000002",
                "hash": "d38aebb4b04a815309ea062bcbe817904fc3da4627e8abfcc779e49762ffcd12"
            },
            "timings": {
                "genLt": "10072982000000",
                "genUtime": 1753445568
            }
        }))?;

        let RawAccountState::Exists {
            last_transaction_id: Some(transaction),
            ..
        } = raw
        else {
            bail!("exists state lost lastTransactionId during deserialization");
        };
        assert!(transaction.is_exact);
        assert_eq!(transaction.lt, 10072981000002);
        Ok(())
    }

    #[tokio::test]
    async fn pre_request_validation_is_the_only_local_non_transmission_class() {
        let (url, calls, handle) = mock_server(MockReply::Bytes(response(
            200,
            r#"{"jsonrpc":"2.0","id":1,"result":null}"#,
            "",
        )));
        let outcome = transport_for_broadcast(Duration::from_secs(1))
            .send_message_base64_candidate_classified(&routes([url]), 0, "not base64 or a BOC")
            .await
            .unwrap_err();
        assert!(matches!(
            outcome,
            SendAttemptOutcome::NotTransmitted(LocalReason::InvalidMessage(_))
        ));
        handle.join().unwrap();
        assert_eq!(calls.load(AtomicOrdering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_route_token_cannot_be_reused_with_another_endpoint() {
        let (url, calls, handle) = mock_server(MockReply::Bytes(response(
            200,
            r#"{"jsonrpc":"2.0","id":1,"result":null}"#,
            "",
        )));
        let mut route = routes([url]);
        route.endpoint_identity = Arc::from("https://different.example/");
        let outcome = transport_for_broadcast(Duration::from_secs(1))
            .send_message_base64_candidate_classified(&route, 0, signed_boc())
            .await
            .unwrap_err();
        assert!(matches!(
            outcome,
            SendAttemptOutcome::NotTransmitted(LocalReason::RouteEndpointMismatch(_))
        ));
        handle.join().unwrap();
        assert_eq!(calls.load(AtomicOrdering::SeqCst), 0);
    }

    #[tokio::test]
    async fn all_preconnect_failures_are_safe_only_in_the_live_attempt() {
        fn closed_url() -> Url {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            drop(listener);
            Url::parse(&format!("http://{address}/send")).unwrap()
        }
        let route = routes([closed_url(), closed_url()]);
        let transport = transport_for_broadcast(Duration::from_millis(200));
        let mut details = Vec::new();
        for candidate_index in 0..2 {
            let outcome = transport
                .send_message_base64_candidate_classified(&route, candidate_index, signed_boc())
                .await
                .unwrap_err();
            let SendAttemptOutcome::NotTransmitted(LocalReason::AllCandidatesFailedPreConnect(
                mut candidate_details,
            )) = outcome
            else {
                panic!("each same-live preconnect failure must be NotTransmitted");
            };
            details.append(&mut candidate_details);
        }
        assert_eq!(details.len(), 2);
    }

    #[tokio::test]
    async fn one_candidate_call_never_falls_back_after_an_http_response() {
        for status in [400, 404, 405, 429, 500, 503] {
            let (first_url, first_calls, first) =
                mock_server(MockReply::Bytes(response(status, "rejected", "")));
            let (second_url, second_calls, second) = mock_server(MockReply::Bytes(response(
                200,
                r#"{"jsonrpc":"2.0","id":1,"result":null}"#,
                "",
            )));
            let outcome = transport_for_broadcast(Duration::from_secs(1))
                .send_message_base64_candidate_classified(
                    &routes([first_url, second_url]),
                    0,
                    signed_boc(),
                )
                .await
                .unwrap_err();
            assert!(matches!(
                outcome,
                SendAttemptOutcome::NodeResponseObserved(ResponseKind::HttpStatus { status: got, .. })
                    if got == status
            ));
            first.join().unwrap();
            second.join().unwrap();
            assert_eq!(first_calls.load(AtomicOrdering::SeqCst), 1);
            assert_eq!(
                second_calls.load(AtomicOrdering::SeqCst),
                0,
                "HTTP {status} must not fall back with the signed body"
            );
        }
    }

    #[tokio::test]
    async fn redirects_are_disabled_and_never_followed_with_the_body() {
        let (target_url, target_calls, target) = mock_server(MockReply::Bytes(response(
            200,
            r#"{"jsonrpc":"2.0","id":1,"result":null}"#,
            "",
        )));
        let (redirect_url, redirect_calls, redirect) = mock_server(MockReply::Bytes(response(
            307,
            "",
            &format!("Location: {}\r\n", target_url),
        )));
        let outcome = transport_for_broadcast(Duration::from_secs(1))
            .send_message_base64_candidate_classified(&routes([redirect_url]), 0, signed_boc())
            .await
            .unwrap_err();
        assert!(matches!(
            outcome,
            SendAttemptOutcome::NodeResponseObserved(ResponseKind::Redirect { status: 307, .. })
        ));
        redirect.join().unwrap();
        target.join().unwrap();
        assert_eq!(redirect_calls.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(target_calls.load(AtomicOrdering::SeqCst), 0);
    }

    #[tokio::test]
    async fn json_rpc_error_and_malformed_200_are_never_not_transmitted() {
        for (body, expect_rpc_error) in [
            (
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"no"}}"#,
                true,
            ),
            (r#"{"jsonrpc":"2.0","id":1}"#, false),
            ("not-json", false),
        ] {
            let (url, calls, handle) = mock_server(MockReply::Bytes(response(200, body, "")));
            let outcome = transport_for_broadcast(Duration::from_secs(1))
                .send_message_base64_candidate_classified(&routes([url]), 0, signed_boc())
                .await
                .unwrap_err();
            if expect_rpc_error {
                assert!(matches!(
                    &outcome,
                    SendAttemptOutcome::NodeResponseObserved(ResponseKind::JsonRpcError { .. })
                ));
            } else {
                assert!(matches!(
                    &outcome,
                    SendAttemptOutcome::NodeResponseObserved(ResponseKind::MalformedSuccess { .. })
                ));
            }
            assert!(outcome.may_have_broadcast());
            handle.join().unwrap();
            assert_eq!(calls.load(AtomicOrdering::SeqCst), 1);
        }
    }

    #[tokio::test]
    async fn established_eof_and_wait_timeout_are_may_have_broadcast() {
        let (eof_url, _, eof) = mock_server(MockReply::Reset);
        let eof_outcome = transport_for_broadcast(Duration::from_secs(1))
            .send_message_base64_candidate_classified(&routes([eof_url]), 0, signed_boc())
            .await
            .unwrap_err();
        eof.join().unwrap();
        assert!(matches!(
            eof_outcome,
            SendAttemptOutcome::MayHaveBroadcast(_) | SendAttemptOutcome::NodeResponseObserved(_)
        ));

        let (timeout_url, _, timeout) = mock_server(MockReply::Delay(Duration::from_millis(300)));
        let timeout_outcome = transport_for_broadcast(Duration::from_millis(50))
            .send_message_base64_candidate_classified(&routes([timeout_url]), 0, signed_boc())
            .await
            .unwrap_err();
        timeout.join().unwrap();
        assert!(matches!(
            timeout_outcome,
            SendAttemptOutcome::MayHaveBroadcast(_)
        ));
    }

    #[test]
    fn shared_jrpc_parser_rejects_ambiguous_result_error_combinations() {
        assert!(
            parse_jrpc_result::<Value>(
                json!({"result": 1, "error": {"code": -1, "message": "bad"}}),
                "ambiguous"
            )
            .is_err()
        );
        assert_eq!(
            parse_jrpc_result::<u32>(json!({"result": 7, "error": null}), "ok").unwrap(),
            7
        );
        assert!(parse_jrpc_result::<Value>(json!({"error": null}), "missing").is_err());
        assert_eq!(
            parse_jrpc_result_for_id::<u32>(
                json!({"jsonrpc": "2.0", "id": 9, "result": 7}),
                "matched",
                9,
            )
            .unwrap(),
            7
        );
        assert!(
            parse_jrpc_result_for_id::<u32>(
                json!({"jsonrpc": "2.0", "id": 8, "result": 7}),
                "wrong-id",
                9,
            )
            .is_err()
        );
        assert!(
            parse_jrpc_result_for_id::<u32>(
                json!({"jsonrpc": "1.0", "id": 9, "result": 7}),
                "wrong-version",
                9,
            )
            .is_err()
        );
    }
}
