use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, LazyLock, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::task::JoinSet;

use crate::activity::activity_from_chain_tx;
use crate::explorer::{AccountTxPage, account_tx_from_chain_tx};
use crate::trace::{
    AccountTrace, ContractIndex, TRACE_MAX_CLIMB, TRACE_MAX_DEPTH, TRACE_MAX_TRANSACTIONS,
    TraceNode, account_of, flatten, pending_messages,
};
use cc_wallet_domain::{
    AssetAmount, AssetId, CcAmount, Digest32, EndpointAddressInputs, NetworkTimeProvenance,
    NodeResponseKind, ObservedNetworkTime as DomainObservedNetworkTime, PrepareProvenance,
    PreparedRecord, Reservation, ReservationKind, STORAGE_KEY_CONTEXT, SeedPhrase, SendRequest,
    SendTicket, StorageOp, StorageRecord, StorageSnapshot, SwapRequest, ValidatorCycle,
    WalletInputs, WalletSnapshot, canonicalize_recipient, decode_record, encode_record,
    evaluate_affordability, normalize_seed, record_aad, validate_seed, validate_workchain,
};
use cc_wallet_tycho::{
    AccountInspection, AccountState, AccountStatus, BlockchainConfigState,
    BroadcastAcknowledgement, CcdexAsset, ChainTransaction, CoinSupply, EmulationConfig,
    EverTransfer, EverWallet, KeyPair, LocalReason, MsgKind, ResponseKind, STORAGE_TARGET_BALANCE,
    Seed, SendAttemptOutcome, StdAddr, SubscriptionEvent, Transport, WalletState,
    account_subscription_loop, comment_aad, comment_payload, elector_election_stake,
    emulate_external_message, encrypted_comment_payload, key_block_supply, parse_transaction,
    pool_storage_from_account, prepare_emulation_config, shard_account_for_emulation,
    storage_address, storage_delete_body, storage_from_account, storage_put_body, swap_body,
    validate_emulation_input_sizes,
};
use cc_wallet_vault::{open_record, seal_record};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub use cc_wallet_domain::{LOCAL_SEND_FEE_CEILING_NANOS, LOCAL_SEND_FEE_HEADROOM_NANOS};

pub type ChainResult<T> = Result<T, ChainError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    InvalidInput(String),
    InsufficientFunds(String),
    Wallet(String),
}

impl ChainError {
    fn wallet(error: impl fmt::Display) -> Self {
        Self::Wallet(error.to_string())
    }

    fn invalid_input(error: impl fmt::Display) -> Self {
        Self::InvalidInput(error.to_string())
    }
}

impl fmt::Display for ChainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(message)
            | Self::InsufficientFunds(message)
            | Self::Wallet(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for ChainError {}

const FEE_ESTIMATE_STORAGE_LAG_SECS: u32 = 30;

const FEE_ESTIMATE_BALANCE_HEADROOM: u128 = 2_000_000_000;

const FEE_ESTIMATE_FLOOR_NANOS: u128 = 100_000;

pub const RISK_OVERRIDE_COOLING_SECS: u64 =
    cc_wallet_tycho::DEFAULT_TTL_SECS as u64 + 2 * cc_wallet_tycho::CLOCK_SKEW_MARGIN_SECS;

const CONFIG_CACHE_TTL: Duration = Duration::from_secs(60);

fn config_cache_age_is_fresh(age: Duration) -> bool {
    age < CONFIG_CACHE_TTL
}

const FEE_EMULATION_TIMEOUT: Duration = Duration::from_secs(5);

const SEND_EMULATION_HANDOFF_TIMEOUT: Duration = Duration::from_secs(10);

const SAFE_SEND_FLAGS: u8 = 1;

const SWAP_GAS_NATIVE: u128 = 200_000_000;

const SWAP_VALID_SECS: u32 = 300;

const STORAGE_DEPLOY_GAS: u128 = 50_000_000;

const STORAGE_OP_GAS: u128 = 60_000_000;

fn seal_comment(
    seal: &CommentSeal<'_>,
    recipient_key: &[u8; 32],
    request: &SendRequest,
) -> ChainResult<cc_wallet_tycho::Cell> {
    let key = seal
        .keys
        .comment_secret_for(recipient_key)
        .map_err(|error| ChainError::invalid_input(error.to_string()))?;
    let aad = comment_aad(seal.sender, request.destination());
    let sealed = seal_record(&key, &aad, request.comment().as_bytes())
        .map_err(|error| ChainError::wallet(error.to_string()))?;
    encrypted_comment_payload(&seal.keys.public_key_bytes(), &sealed)
        .map_err(|error| ChainError::invalid_input(error.to_string()))
}

fn emulation_balance_floor(transfer_native: u128) -> ChainResult<u128> {
    let min_balance = transfer_native
        .checked_add(FEE_ESTIMATE_BALANCE_HEADROOM)
        .ok_or_else(|| ChainError::Wallet("fee-emulation balance overflows u128".to_owned()))?;
    AssetAmount::native(min_balance).map_err(|error| {
        ChainError::Wallet(format!("fee-emulation balance is out of domain: {error}"))
    })?;
    Ok(min_balance)
}

static MONOTONIC_ORIGIN: LazyLock<Instant> = LazyLock::new(Instant::now);

/// What a recipient's account says about itself: whether it can be sent to at
/// all, and whether it publishes a key a comment could be encrypted to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DestinationReport {
    pub status: DestinationAccountStatus,
    pub encrypt_key: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DestinationAccountStatus {
    #[default]
    NonExist,
    Uninit,
    Frozen,
    Active,
}

impl DestinationAccountStatus {
    pub fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeEstimate {
    pub fee_nanos: u128,
    pub deploy: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolSnapshot {
    pub address: String,
    pub owner: String,
    pub fee_bps: u16,
    pub paused: bool,
    pub native_reserve: u128,
    pub cc_reserves: BTreeMap<u32, u128>,
}

impl PoolSnapshot {
    pub fn reserve_units(&self, asset: AssetId) -> u128 {
        match asset {
            AssetId::Native => self.native_reserve,
            AssetId::CurrencyCollection(id) => self.cc_reserves.get(&id).copied().unwrap_or(0),
        }
    }

    pub fn supports(&self, asset: AssetId) -> bool {
        self.reserve_units(asset) > 0
    }
}

pub struct PreparedSwap {
    endpoint: String,
    message: cc_wallet_tycho::Cell,
    route: cc_wallet_tycho::ResolvedSendRoute,
    external_hash: Digest32,
    expire_at: u32,
    request: SwapRequest,
    pool: String,
    deploy: bool,
    attached_native: u128,
    fee_nanos: u128,
}

impl fmt::Debug for PreparedSwap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedSwap")
            .field("endpoint", &self.endpoint)
            .field("pool", &self.pool)
            .field("external_hash", &self.external_hash)
            .field("expire_at", &self.expire_at)
            .field("deploy", &self.deploy)
            .field("attached_native", &self.attached_native)
            .field("fee_nanos", &self.fee_nanos)
            .finish_non_exhaustive()
    }
}

impl PreparedSwap {
    pub fn external_hash(&self) -> &Digest32 {
        &self.external_hash
    }

    pub fn expire_at(&self) -> u32 {
        self.expire_at
    }

    pub fn request(&self) -> &SwapRequest {
        &self.request
    }

    pub fn pool(&self) -> &str {
        &self.pool
    }

    pub fn deploy(&self) -> bool {
        self.deploy
    }

    pub fn attached_native(&self) -> u128 {
        self.attached_native
    }

    pub fn fee_nanos(&self) -> u128 {
        self.fee_nanos
    }

    pub fn candidate_count(&self) -> usize {
        self.route.candidate_count()
    }
}

pub struct PreparedStorageOp {
    endpoint: String,
    message: cc_wallet_tycho::Cell,
    route: cc_wallet_tycho::ResolvedSendRoute,
    external_hash: Digest32,
    expire_at: u32,
    storage_address: String,
    op: StorageOp,
    attached_native: u128,
    fee_nanos: u128,
}

impl fmt::Debug for PreparedStorageOp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedStorageOp")
            .field("endpoint", &self.endpoint)
            .field("storage_address", &self.storage_address)
            .field("op", &self.op.label())
            .field("record_id", &self.op.record_id())
            .field("external_hash", &self.external_hash)
            .field("expire_at", &self.expire_at)
            .field("attached_native", &self.attached_native)
            .field("fee_nanos", &self.fee_nanos)
            .finish_non_exhaustive()
    }
}

impl PreparedStorageOp {
    pub fn external_hash(&self) -> &Digest32 {
        &self.external_hash
    }

    pub fn expire_at(&self) -> u32 {
        self.expire_at
    }

    pub fn op(&self) -> &StorageOp {
        &self.op
    }

    pub fn storage_address(&self) -> &str {
        &self.storage_address
    }

    pub fn attached_native(&self) -> u128 {
        self.attached_native
    }

    pub fn fee_nanos(&self) -> u128 {
        self.fee_nanos
    }

    pub fn candidate_count(&self) -> usize {
        self.route.candidate_count()
    }
}

pub struct PreparedChainSend {
    prepared_record: PreparedRecord,
    route: Option<cc_wallet_tycho::ResolvedSendRoute>,
    message: Option<cc_wallet_tycho::Cell>,
    candidate_count: usize,
}

impl fmt::Debug for PreparedChainSend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedChainSend")
            .field("record_id", self.prepared_record.ticket().record_id())
            .field("external_hash", self.prepared_record.ext_msg_hash())
            .field("expire_at", &self.prepared_record.expire_at())
            .field("candidate_count", &self.candidate_count)
            .field("signed_body", &"<redacted runtime-only BOC>")
            .finish()
    }
}

impl PreparedChainSend {
    pub fn prepared_record(&self) -> &PreparedRecord {
        &self.prepared_record
    }

    pub fn record_id(&self) -> &cc_wallet_domain::RecordId {
        self.prepared_record.ticket().record_id()
    }

    pub fn external_hash(&self) -> &Digest32 {
        self.prepared_record.ext_msg_hash()
    }

    pub fn expire_at(&self) -> u32 {
        self.prepared_record.expire_at()
    }

    pub fn route_id(&self) -> &str {
        self.prepared_record.prepare_provenance().route_id()
    }

    pub fn candidate_count(&self) -> usize {
        self.candidate_count
    }

    pub fn request(&self) -> &SendRequest {
        self.prepared_record.ticket().request()
    }

    #[cfg(feature = "test-support")]
    pub fn for_test(prepared_record: PreparedRecord, candidate_count: usize) -> ChainResult<Self> {
        if candidate_count == 0 {
            return Err(ChainError::InvalidInput(
                "a prepared test send needs at least one route candidate".to_owned(),
            ));
        }
        Ok(Self {
            prepared_record,
            route: None,
            message: None,
            candidate_count,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CandidateBroadcastOutcome {
    NotTransmitted {
        detail: String,
        retry_next_candidate: bool,
    },
    MayHaveBroadcast {
        detail: String,
    },
    NodeResponseObserved {
        request_id: String,
        response: NodeResponseKind,
        detail: String,
    },
}

#[derive(Debug, Clone, Default)]
pub struct TransactionPage {
    pub transactions: Vec<ChainTransaction>,
    pub skipped: usize,
    pub source_endpoint: String,
    pub request_id: String,
}

#[derive(Clone)]
struct CachedConfig {
    state: Arc<BlockchainConfigState>,
    emulation: Arc<EmulationConfig>,
    fetched_at: Instant,
    request_id: String,
    observed_at_mono: Instant,
}

#[derive(Default)]
struct EmulationJobs {
    active: Mutex<HashSet<String>>,
    empty: Condvar,
}

impl EmulationJobs {
    fn acquire(self: &Arc<Self>, key: String) -> ChainResult<EmulationJobGuard> {
        let mut active = self.active.lock().expect("emulation job set poisoned");
        if !active.insert(key.clone()) {
            return Err(ChainError::Wallet(
                "a fee emulation is already running for this wallet and endpoint".to_owned(),
            ));
        }
        Ok(EmulationJobGuard {
            jobs: Arc::clone(self),
            key: Some(key),
        })
    }

    fn acquire_wait(
        self: &Arc<Self>,
        key: String,
        timeout: Duration,
    ) -> ChainResult<EmulationJobGuard> {
        let active = self.active.lock().expect("emulation job set poisoned");
        let (mut active, _) = self
            .empty
            .wait_timeout_while(active, timeout, |active| active.contains(&key))
            .expect("emulation job set poisoned while waiting for send priority");
        if active.contains(&key) {
            return Err(ChainError::Wallet(
                "the previous fee calculation did not finish in time; please send again".to_owned(),
            ));
        }
        active.insert(key.clone());
        Ok(EmulationJobGuard {
            jobs: Arc::clone(self),
            key: Some(key),
        })
    }

    fn wait_empty(&self, timeout: Duration) -> bool {
        let active = self.active.lock().expect("emulation job set poisoned");
        let (active, _) = self
            .empty
            .wait_timeout_while(active, timeout, |active| !active.is_empty())
            .expect("emulation job set poisoned while draining");
        active.is_empty()
    }
}

struct EmulationJobGuard {
    jobs: Arc<EmulationJobs>,
    key: Option<String>,
}

impl Drop for EmulationJobGuard {
    fn drop(&mut self) {
        let Some(key) = self.key.take() else {
            return;
        };
        let mut active = self.jobs.active.lock().expect("emulation job set poisoned");
        active.remove(&key);
        self.jobs.empty.notify_all();
    }
}

#[derive(Clone, Default)]
pub struct TychoWalletService {
    config_cache: Arc<Mutex<HashMap<String, CachedConfig>>>,
    transport_cache: Arc<Mutex<HashMap<String, Transport>>>,
    key_cache: Arc<Mutex<HashMap<[u8; 32], Arc<KeyPair>>>>,
    emulation_jobs: Arc<EmulationJobs>,
    key_ops_sealed: Arc<AtomicBool>,
}

fn locked_keys_error() -> ChainError {
    ChainError::Wallet("the wallet is locked; signing keys are unavailable".to_owned())
}

impl TychoWalletService {
    pub fn generate_seed(&self) -> ChainResult<SeedPhrase> {
        generate_seed()
    }

    pub fn derive_wallet_address(&self, inputs: &WalletInputs) -> ChainResult<String> {
        let seed = normalize_and_validate_inputs(inputs)?;
        let canonical_endpoint = cc_wallet_tycho::canonicalize_endpoint(&inputs.endpoint)
            .map_err(ChainError::invalid_input)?
            .to_string();
        if canonical_endpoint != inputs.endpoint {
            return Err(ChainError::InvalidInput(
                "wallet endpoint is not canonical".to_owned(),
            ));
        }
        let keys = self.keypair_for(seed)?;
        EverWallet::compute_address(inputs.workchain, keys.public_key())
            .map(|address| address.to_string())
            .map_err(ChainError::wallet)
    }

    pub async fn load_wallet(&self, inputs: &EndpointAddressInputs) -> ChainResult<WalletSnapshot> {
        let transport = self.transport_for(inputs.endpoint())?;
        let observed = transport
            .get_account_state_observed(inputs.address())
            .await
            .map_err(ChainError::wallet)?;
        let mut state = WalletState::from_account_state(observed.state())
            .map_err(ChainError::wallet)?
            .ok_or_else(|| {
                ChainError::Wallet("an initial account-state request returned Unchanged".to_owned())
            })?;
        state.observed_network_time = observed.network_time().cloned();
        let global_id = self.blockchain_config(&transport).await?.state.global_id;
        snapshot(inputs.address(), &state, global_id)
    }

    pub async fn prepare_transaction(
        &self,
        inputs: WalletInputs,
        ticket: SendTicket,
        active_reservations: Vec<Reservation>,
        authorized_overlap: Vec<Reservation>,
    ) -> ChainResult<PreparedChainSend> {
        LazyLock::force(&MONOTONIC_ORIGIN);

        let canonical_endpoint = cc_wallet_tycho::canonicalize_endpoint(&inputs.endpoint)
            .map_err(ChainError::invalid_input)?
            .to_string();
        if canonical_endpoint != inputs.endpoint
            || ticket.endpoint_identity() != inputs.endpoint
            || ticket.network_global_id() != inputs.network_id
        {
            return Err(ChainError::InvalidInput(
                "send ticket endpoint/network does not match the frozen wallet inputs".to_owned(),
            ));
        }
        let seed = normalize_and_validate_inputs(&inputs)?;
        validate_chain_request(ticket.request())?;

        let keys = self.keypair_for(seed)?;
        let (mut wallet, transport) = self.build_wallet(&inputs, seed)?;
        if wallet.address_string() != ticket.sender_address() {
            return Err(ChainError::InvalidInput(
                "send ticket sender does not match the wallet derived from its frozen key"
                    .to_owned(),
            ));
        }
        let config = self.blockchain_config(&transport).await?;
        let config_state = Arc::clone(&config.state);
        let signature_context = config_state
            .signature_context()
            .map_err(ChainError::wallet)?;
        let has_signature_id = cc_wallet_tycho::signature_context_has_id(&signature_context);
        validate_signature_context(
            signature_context.global_id,
            has_signature_id,
            inputs.network_id,
            inputs.require_signature_id,
        )
        .map_err(ChainError::Wallet)?;

        let observed_account = transport
            .get_account_state_observed(wallet.address_string())
            .await
            .map_err(ChainError::wallet)?;
        if observed_account.state().is_unchanged() {
            return Err(ChainError::Wallet(
                "fresh unfiltered account read unexpectedly returned Unchanged".to_owned(),
            ));
        }
        let account_state = observed_account.state().clone();
        let account_state_hash = account_state_digest(&account_state);
        let account_request_id = observed_account.request_id().to_owned();
        let account_observed_at = observed_account.observed_at_mono();
        let network_time = observed_account.network_time().cloned();
        wallet
            .apply_observed_account_state(observed_account)
            .map_err(ChainError::wallet)?;

        let extra_balance = parse_extra_balance(wallet.extra_balance().clone())?;
        let balances = typed_balances(wallet.balance(), &extra_balance)?;
        let state_init_required = !wallet.state().is_active();
        let emulation = Arc::clone(&config.emulation);
        let transfer_native = ticket.request().value().native_units().unwrap_or(0);
        let min_balance = emulation_balance_floor(transfer_native)?;
        let shard_account =
            shard_account_for_emulation(wallet.address(), &account_state, min_balance)
                .map_err(ChainError::wallet)?;

        let route = transport
            .resolve_send_route()
            .await
            .map_err(ChainError::wallet)?;
        let transfer = build_transfer(
            ticket.request(),
            ticket.bounce(),
            Some(CommentSeal {
                keys: &keys,
                sender: &wallet.address_string(),
            }),
        )?;
        let prepared = wallet
            .prepare_send_currency(&transfer, signature_context)
            .map_err(ChainError::wallet)?;
        let external_hash = Digest32::try_from_hex(&prepared.message_hash).map_err(|error| {
            ChainError::Wallet(format!(
                "prepared external-message hash is not canonical 32-byte hex: {error}"
            ))
        })?;

        validate_emulation_input_sizes(&config_state, &account_state, &prepared.message)
            .map_err(ChainError::wallet)?;
        let block_time = now_unix_secs()?.saturating_add(FEE_ESTIMATE_STORAGE_LAG_SECS);

        let emulation_key = format!("{}|{}", transport.endpoint(), wallet.address_string());
        let jobs = Arc::clone(&self.emulation_jobs);
        let job = tokio::task::spawn_blocking(move || {
            jobs.acquire_wait(emulation_key, SEND_EMULATION_HANDOFF_TIMEOUT)
        })
        .await
        .map_err(|error| {
            ChainError::Wallet(format!(
                "could not hand off fee emulation to send preparation: {error}"
            ))
        })??;

        let address = wallet.address().clone();
        let message_for_emulation = prepared.message.clone();
        let emulated = tokio::time::timeout(
            FEE_EMULATION_TIMEOUT,
            tokio::task::spawn_blocking(move || {
                let _job = job;
                emulate_external_message(
                    &emulation,
                    &address,
                    &shard_account,
                    &message_for_emulation,
                    block_time,
                )
            }),
        )
        .await
        .map_err(|_| {
            ChainError::Wallet(
                "send preparation emulation timed out on hostile chain data".to_owned(),
            )
        })?
        .map_err(|_| {
            ChainError::Wallet(
                "send preparation emulation crashed on invalid chain data".to_owned(),
            )
        })?
        .map_err(ChainError::wallet)?;
        if emulated.aborted || !emulated.compute_success {
            return Err(ChainError::Wallet(format!(
                "send preparation emulation failed (exit code {})",
                emulated.exit_code
            )));
        }
        let estimated_fee_native = activity_from_chain_tx(&emulated)?
            .into_iter()
            .next()
            .ok_or_else(|| ChainError::Wallet("send emulation produced no transfer".to_owned()))?
            .fee_native;
        if !fee_within_bounds(estimated_fee_native) {
            return Err(ChainError::Wallet(format!(
                "send fee {estimated_fee_native} nanos is outside the trustworthy local range"
            )));
        }
        let desired_fee_ceiling_native = estimated_fee_native
            .checked_add(LOCAL_SEND_FEE_HEADROOM_NANOS)
            .filter(|value| *value <= LOCAL_SEND_FEE_CEILING_NANOS)
            .ok_or_else(|| {
                ChainError::Wallet(
                    "the exact send fee plus its local headroom exceeds the policy ceiling"
                        .to_owned(),
                )
            })?;
        let (local_fee_ceiling_native, reservations) = select_affordable_fee_ceiling(
            &ticket,
            estimated_fee_native,
            desired_fee_ceiling_native,
            &balances,
            &active_reservations,
            &authorized_overlap,
        )?;

        let observed_at = config
            .observed_at_mono
            .max(account_observed_at)
            .max(route.observed_at_mono());
        let observed_at_mono_ms = monotonic_ms(observed_at)?;
        let mut request_ids = Vec::with_capacity(2 + route.probe_request_ids().len());
        request_ids.push(config.request_id.clone());
        request_ids.push(account_request_id);
        request_ids.extend(route.probe_request_ids().iter().cloned());

        let network_time = network_time
            .map(|observed| {
                NetworkTimeProvenance::new(
                    observed.value,
                    observed.source_endpoint,
                    observed.request_id,
                    monotonic_ms(observed.observed_at_mono)?,
                )
                .map_err(|error| ChainError::Wallet(error.to_string()))
            })
            .transpose()?;
        let signature_context_hash = provenance_digest(
            b"cc-wallet/prepare-signature-context/v1\0",
            &[
                &config_state.global_id.to_be_bytes(),
                &config_state.seqno.to_be_bytes(),
                &signature_context.capabilities.into_inner().to_be_bytes(),
                config_state.config_boc_base64.as_bytes(),
            ],
        );
        let fee_input_hash = provenance_digest(
            b"cc-wallet/prepare-fee-input/v1\0",
            &[
                config_state.config_boc_base64.as_bytes(),
                account_state_hash.as_bytes(),
                external_hash.as_bytes(),
            ],
        );
        let provenance = PrepareProvenance::new(
            transport.endpoint().to_owned(),
            route.route_id(),
            request_ids,
            observed_at_mono_ms,
            account_state_hash,
            state_init_required,
            balances,
            signature_context_hash,
            signature_context.global_id,
            has_signature_id,
            network_time,
            fee_input_hash,
            estimated_fee_native,
            local_fee_ceiling_native,
            authorized_overlap,
        )
        .map_err(|error| ChainError::Wallet(error.to_string()))?;
        let prepared_record = PreparedRecord::new(
            ticket,
            provenance,
            external_hash,
            prepared.expire_at,
            reservations,
        )
        .map_err(|error| ChainError::Wallet(error.to_string()))?;

        Ok(PreparedChainSend {
            prepared_record,
            candidate_count: route.candidate_count(),
            route: Some(route),
            message: Some(prepared.message),
        })
    }

    pub async fn broadcast_prepared_candidate(
        &self,
        prepared: &PreparedChainSend,
        candidate_index: usize,
    ) -> ChainResult<CandidateBroadcastOutcome> {
        let transport = self.transport_for(
            prepared
                .prepared_record
                .prepare_provenance()
                .source_endpoint(),
        )?;
        let route = prepared.route.as_ref().ok_or_else(|| {
            ChainError::Wallet(
                "a test-only prepared send reached the production broadcaster".to_owned(),
            )
        })?;
        let message = prepared.message.as_ref().ok_or_else(|| {
            ChainError::Wallet("a prepared send is missing its signed body".to_owned())
        })?;
        let outcome = transport
            .send_message_cell_candidate_classified(route, candidate_index, message)
            .await;
        Ok(match outcome {
            Ok(acknowledgement) => CandidateBroadcastOutcome::NodeResponseObserved {
                request_id: acknowledgement.request_id,
                response: NodeResponseKind::Acknowledged,
                detail: "node acknowledged the signed message; delivery remains unverified"
                    .to_owned(),
            },
            Err(SendAttemptOutcome::NotTransmitted(reason)) => {
                let retry_next_candidate =
                    matches!(reason, LocalReason::AllCandidatesFailedPreConnect(_));
                CandidateBroadcastOutcome::NotTransmitted {
                    detail: SendAttemptOutcome::NotTransmitted(reason).to_string(),
                    retry_next_candidate,
                }
            }
            Err(SendAttemptOutcome::MayHaveBroadcast(reason)) => {
                CandidateBroadcastOutcome::MayHaveBroadcast {
                    detail: SendAttemptOutcome::MayHaveBroadcast(reason).to_string(),
                }
            }
            Err(SendAttemptOutcome::NodeResponseObserved(response)) => {
                let response_kind = classify_node_response(&response);
                CandidateBroadcastOutcome::NodeResponseObserved {
                    request_id: response.request_id().to_owned(),
                    response: response_kind,
                    detail: SendAttemptOutcome::NodeResponseObserved(response).to_string(),
                }
            }
        })
    }

    pub async fn check_destination(
        &self,
        inputs: &EndpointAddressInputs,
        address: String,
    ) -> ChainResult<DestinationReport> {
        let address = canonicalize_recipient(&address).map_err(ChainError::invalid_input)?;
        let transport = self.transport_for(inputs.endpoint())?;
        let state = transport
            .get_account_state(&address)
            .await
            .map_err(ChainError::wallet)?;
        let status = match state.account() {
            None => DestinationAccountStatus::NonExist,
            Some(account) => match account.state.status() {
                AccountStatus::Active => DestinationAccountStatus::Active,
                AccountStatus::Frozen => DestinationAccountStatus::Frozen,
                AccountStatus::Uninit => DestinationAccountStatus::Uninit,
                AccountStatus::NotExists => DestinationAccountStatus::NonExist,
            },
        };
        // The same read already in flight answers both questions, so asking
        // whether a comment can be encrypted costs no second round trip.
        let encrypt_key = AccountInspection::from_account_state(&state, Some(&address))
            .ok()
            .flatten()
            .and_then(|inspection| inspection.signing_key);
        Ok(DestinationReport {
            status,
            encrypt_key,
        })
    }

    pub async fn load_transactions(
        &self,
        inputs: &EndpointAddressInputs,
        limit: u32,
        before_lt: Option<u64>,
    ) -> ChainResult<TransactionPage> {
        let transport = self.transport_for(inputs.endpoint())?;
        let observed = transport
            .get_transactions_list_observed(inputs.address(), limit, before_lt)
            .await
            .map_err(ChainError::wallet)?;
        let mut transactions = Vec::with_capacity(observed.values().len());
        let mut skipped = 0usize;
        for boc in observed.values() {
            match parse_transaction(boc) {
                Ok(tx) => transactions.push(tx),
                Err(_) => skipped += 1,
            }
        }
        Ok(TransactionPage {
            transactions,
            skipped,
            source_endpoint: transport.endpoint().to_owned(),
            request_id: observed.request_id().to_owned(),
        })
    }

    fn build_wallet(
        &self,
        inputs: &WalletInputs,
        seed: &str,
    ) -> ChainResult<(EverWallet, Transport)> {
        let transport = self.transport_for(&inputs.endpoint)?;
        let keys = self.keypair_for(seed)?;
        let wallet =
            EverWallet::with_shared_keys(keys, inputs.workchain).map_err(ChainError::wallet)?;
        Ok((wallet, transport))
    }

    fn transport_for(&self, endpoint: &str) -> ChainResult<Transport> {
        let endpoint = cc_wallet_tycho::canonicalize_endpoint(endpoint)
            .map_err(ChainError::invalid_input)?
            .to_string();
        if let Some(transport) = self
            .transport_cache
            .lock()
            .expect("transport cache poisoned")
            .get(&endpoint)
        {
            return Ok(transport.clone());
        }
        let transport = Transport::jrpc(&endpoint).map_err(ChainError::wallet)?;
        self.transport_cache
            .lock()
            .expect("transport cache poisoned")
            .insert(endpoint, transport.clone());
        Ok(transport)
    }

    pub async fn probe_endpoint(&self, endpoint: String) -> ChainResult<i32> {
        let transport = self.transport_for(&endpoint)?;
        Ok(self.blockchain_config(&transport).await?.state.global_id)
    }

    pub async fn validator_clock(&self, endpoint: String) -> ChainResult<ValidatorCycle> {
        let transport = self.transport_for(&endpoint)?;
        let config = self.blockchain_config(&transport).await?;
        let params = &config.state.config;
        let timings = params.get_election_timings().map_err(ChainError::wallet)?;
        let current = params
            .get_current_validator_set()
            .map_err(ChainError::wallet)?;
        let next = params
            .get_next_validator_set()
            .map_err(ChainError::wallet)?;
        Ok(ValidatorCycle {
            validators_elected_for: timings.validators_elected_for,
            elections_start_before: timings.elections_start_before,
            elections_end_before: timings.elections_end_before,
            current_utime_since: current.utime_since,
            current_utime_until: current.utime_until,
            next_utime_until: next.map(|set| set.utime_until),
        })
    }

    pub async fn network_stats(&self, endpoint: String) -> ChainResult<NetworkStats> {
        let transport = self.transport_for(&endpoint)?;
        let config = self.blockchain_config(&transport).await?;
        let params = &config.state.config;
        let current = params
            .get_current_validator_set()
            .map_err(ChainError::wallet)?;
        let elector = params.get_elector_address().map_err(ChainError::wallet)?;
        let elector = format!("-1:{elector:x}");

        Ok(NetworkStats {
            validators: current.list.len(),
            total_stake: self
                .election_stake(&transport, elector, current.utime_since)
                .await,
            supply: self.coin_supply(&transport).await,
        })
    }

    async fn election_stake(
        &self,
        transport: &Transport,
        elector: String,
        utime_since: u32,
    ) -> Option<u128> {
        let state = transport.get_account_state(&elector).await.ok()?;
        let account = state.account()?;
        elector_election_stake(account, Some(utime_since))
            .ok()
            .map(|stake| stake.total_stake)
    }

    async fn coin_supply(&self, transport: &Transport) -> Option<CoinSupply> {
        let block = transport.get_latest_key_block().await.ok()?;
        key_block_supply(&block).ok()
    }

    pub async fn inspect_account(
        &self,
        endpoint: String,
        address: String,
    ) -> ChainResult<AccountInspection> {
        let address = canonicalize_recipient(&address).map_err(ChainError::invalid_input)?;
        let transport = self.transport_for(&endpoint)?;
        let state = transport
            .get_account_state(&address)
            .await
            .map_err(ChainError::wallet)?;
        AccountInspection::from_account_state(&state, Some(&address))
            .map_err(ChainError::wallet)?
            .ok_or_else(|| ChainError::wallet("account state was unexpectedly unchanged"))
    }

    pub async fn trace_transaction(
        &self,
        endpoint: String,
        transaction_hash: String,
    ) -> ChainResult<AccountTrace> {
        let focus = Digest32::try_from_hex(transaction_hash.trim())
            .map_err(|error| ChainError::invalid_input(format!("transaction hash: {error}")))?;
        let hash = focus.to_string();
        let transport = self.transport_for(&endpoint)?;
        let root_boc = transport
            .get_transaction(&hash)
            .await
            .map_err(ChainError::wallet)?
            .ok_or_else(|| {
                ChainError::Wallet(
                    "this endpoint no longer keeps that transaction, so its trace cannot be read"
                        .to_owned(),
                )
            })?;
        let asked_for = parse_transaction(&root_boc).map_err(ChainError::wallet)?;

        let mut root = asked_for;
        let mut truncated = false;
        for _ in 0..TRACE_MAX_CLIMB {
            let Some(inbound) = root.in_msg.clone() else {
                break;
            };
            if inbound.kind != MsgKind::Int {
                break;
            }
            let Some(src) = inbound.src.clone().filter(|src| !src.is_empty()) else {
                break;
            };
            let candidates = transport
                .get_transactions_list(&src, 3, Some(inbound.created_lt.saturating_add(1)))
                .await
                .map_err(ChainError::wallet)?;
            let parent = candidates
                .iter()
                .filter_map(|boc| parse_transaction(boc).ok())
                .find(|candidate| {
                    candidate
                        .out_msgs
                        .iter()
                        .any(|message| message.hash == inbound.hash)
                });
            let Some(parent) = parent else {
                break;
            };
            root = parent;
        }

        let mut nodes = vec![TraceNode::new(root, 0)];
        let mut frontier = vec![0usize];

        for depth in 1..=TRACE_MAX_DEPTH {
            let mut requests: Vec<(usize, usize, String)> = Vec::new();
            for &parent in &frontier {
                for (message_index, message_hash) in pending_messages(&nodes[parent]) {
                    requests.push((parent, message_index, message_hash));
                }
            }
            if requests.is_empty() {
                frontier.clear();
                break;
            }
            let room = TRACE_MAX_TRANSACTIONS.saturating_sub(nodes.len());
            if requests.len() > room {
                requests.truncate(room);
                truncated = true;
            }
            if requests.is_empty() {
                break;
            }

            let mut workers = JoinSet::new();
            for (parent, message_index, message_hash) in requests {
                let transport = transport.clone();
                workers.spawn(async move {
                    let found = transport.get_dst_transaction(&message_hash).await;
                    (parent, message_index, found)
                });
            }
            let mut next = Vec::new();
            while let Some(joined) = workers.join_next().await {
                let (parent, message_index, found) = joined
                    .map_err(|error| ChainError::Wallet(format!("trace walk failed: {error}")))?;
                let Some(boc) = found.map_err(ChainError::wallet)? else {
                    continue;
                };
                let child = parse_transaction(&boc).map_err(ChainError::wallet)?;
                nodes.push(TraceNode::new(child, depth));
                let index = nodes.len() - 1;
                nodes[parent].children.insert(message_index, index);
                next.push(index);
            }
            frontier = next;
        }

        if frontier
            .iter()
            .any(|&index| !pending_messages(&nodes[index]).is_empty())
        {
            truncated = true;
        }

        let mut accounts: BTreeSet<String> = BTreeSet::new();
        for node in &nodes {
            let account = account_of(&node.tx);
            if !account.is_empty() {
                accounts.insert(account);
            }
            for message in &node.tx.out_msgs {
                if let Some(dst) = message.dst.as_deref().filter(|dst| !dst.is_empty()) {
                    accounts.insert(dst.to_owned());
                }
            }
        }
        let mut readers = JoinSet::new();
        for account in accounts {
            let transport = transport.clone();
            readers.spawn(async move {
                let state = transport.get_account_state(&account).await;
                (account, state)
            });
        }
        let mut contracts = ContractIndex::new();
        while let Some(joined) = readers.join_next().await {
            let (account, state) = joined
                .map_err(|error| ChainError::Wallet(format!("trace walk failed: {error}")))?;
            let Ok(state) = state else { continue };
            if let Ok(Some(inspection)) =
                AccountInspection::from_account_state(&state, Some(&account))
                && let Some(code_hash) = inspection.code_hash
            {
                contracts.insert(account, code_hash);
            }
        }

        flatten(&nodes, focus, truncated, &contracts)
    }

    pub async fn account_transactions(
        &self,
        endpoint: String,
        address: String,
        limit: u32,
    ) -> ChainResult<AccountTxPage> {
        let address = canonicalize_recipient(&address).map_err(ChainError::invalid_input)?;
        let transport = self.transport_for(&endpoint)?;
        let bocs = transport
            .get_transactions_list(&address, limit, None)
            .await
            .map_err(ChainError::wallet)?;
        let mut page = AccountTxPage {
            rows: Vec::with_capacity(bocs.len()),
            skipped: 0,
        };
        for boc in &bocs {
            match parse_transaction(boc).map_err(ChainError::wallet) {
                Ok(tx) => page.rows.push(account_tx_from_chain_tx(&tx)?),
                Err(_) => page.skipped += 1,
            }
        }
        page.rows.sort_by_key(|row| std::cmp::Reverse(row.lt));
        Ok(page)
    }

    fn keypair_for(&self, seed: &str) -> ChainResult<Arc<KeyPair>> {
        if self.key_ops_sealed.load(Ordering::SeqCst) {
            return Err(locked_keys_error());
        }
        let digest = *blake3::hash(seed.as_bytes()).as_bytes();
        if let Some(keys) = self
            .key_cache
            .lock()
            .expect("key cache poisoned")
            .get(&digest)
        {
            return Ok(keys.clone());
        }
        let keys = Arc::new(KeyPair::from_seed(seed).map_err(ChainError::wallet)?);
        let mut cache = self.key_cache.lock().expect("key cache poisoned");
        if self.key_ops_sealed.load(Ordering::SeqCst) {
            return Err(locked_keys_error());
        }
        cache.insert(digest, keys.clone());
        Ok(keys)
    }

    pub fn seal_key_ops(&self) {
        self.key_ops_sealed.store(true, Ordering::SeqCst);
    }

    pub fn unseal_key_ops(&self) {
        self.key_ops_sealed.store(false, Ordering::SeqCst);
    }

    pub async fn estimate_fee(
        &self,
        inputs: WalletInputs,
        request: SendRequest,
        bounce: bool,
    ) -> ChainResult<FeeEstimate> {
        let seed = normalize_and_validate_inputs(&inputs)?;
        validate_chain_request(&request)?;
        let keys = self.keypair_for(seed)?;
        let (mut wallet, transport) = self.build_wallet(&inputs, seed)?;

        let config = self.blockchain_config(&transport).await?;
        let signature_context = config
            .state
            .signature_context()
            .map_err(ChainError::wallet)?;
        let has_signature_id = cc_wallet_tycho::signature_context_has_id(&signature_context);
        validate_signature_context(
            signature_context.global_id,
            has_signature_id,
            inputs.network_id,
            inputs.require_signature_id,
        )
        .map_err(ChainError::Wallet)?;

        let observed_state = transport
            .get_account_state_observed(wallet.address_string())
            .await
            .map_err(ChainError::wallet)?;
        let account_state = observed_state.state().clone();
        wallet
            .apply_observed_account_state(observed_state)
            .map_err(ChainError::wallet)?;
        let deploy = !wallet.state().is_active();

        let transfer = build_transfer(
            &request,
            bounce,
            Some(CommentSeal {
                keys: &keys,
                sender: &wallet.address_string(),
            }),
        )?;
        let prepared = wallet
            .prepare_send_currency(&transfer, signature_context)
            .map_err(ChainError::wallet)?;

        validate_emulation_input_sizes(&config.state, &account_state, &prepared.message)
            .map_err(ChainError::wallet)?;

        let transfer_native = request.value().native_units().unwrap_or(0);
        let min_balance = emulation_balance_floor(transfer_native)?;
        let shard_account =
            shard_account_for_emulation(wallet.address(), &account_state, min_balance)
                .map_err(ChainError::wallet)?;
        let block_time = now_unix_secs()?.saturating_add(FEE_ESTIMATE_STORAGE_LAG_SECS);

        let job = self.emulation_jobs.acquire(format!(
            "{}|{}",
            transport.endpoint(),
            wallet.address_string()
        ))?;

        let emulation = config.emulation.clone();
        let address = wallet.address().clone();
        let message = prepared.message.clone();
        let emulated = tokio::time::timeout(
            FEE_EMULATION_TIMEOUT,
            tokio::task::spawn_blocking(move || {
                let _job = job;
                emulate_external_message(&emulation, &address, &shard_account, &message, block_time)
            }),
        )
        .await
        .map_err(|_| {
            ChainError::Wallet("fee emulation timed out on hostile chain data".to_owned())
        })?
        .map_err(|_| ChainError::Wallet("fee emulation crashed on invalid chain data".to_owned()))?
        .map_err(ChainError::wallet)?;
        if emulated.aborted || !emulated.compute_success {
            return Err(ChainError::Wallet(format!(
                "fee emulation failed (exit code {})",
                emulated.exit_code
            )));
        }

        let event = activity_from_chain_tx(&emulated)?
            .into_iter()
            .next()
            .ok_or_else(|| ChainError::Wallet("fee emulation produced no transfer".to_owned()))?;
        if !fee_within_bounds(event.fee_native) {
            return Err(ChainError::Wallet(format!(
                "fee estimate {} nanos is outside the trustworthy range — the endpoint's \
                 blockchain config may be wrong",
                event.fee_native
            )));
        }
        Ok(FeeEstimate {
            fee_nanos: event.fee_native,
            deploy,
        })
    }

    pub async fn load_pool_state(&self, endpoint: &str, pool: &str) -> ChainResult<PoolSnapshot> {
        let pool_address = canonicalize_recipient(pool).map_err(ChainError::invalid_input)?;
        let transport = self.transport_for(endpoint)?;
        let state = transport
            .get_account_state(&pool_address)
            .await
            .map_err(ChainError::wallet)?;
        let storage = pool_storage_from_account(&state).map_err(ChainError::wallet)?;
        Ok(PoolSnapshot {
            address: pool_address,
            owner: storage.owner,
            fee_bps: storage.fee_bps,
            paused: storage.paused,
            native_reserve: storage.native_vault,
            cc_reserves: storage.reserves,
        })
    }

    pub async fn prepare_swap(
        &self,
        inputs: WalletInputs,
        pool: String,
        request: SwapRequest,
    ) -> ChainResult<PreparedSwap> {
        let seed = normalize_and_validate_inputs(&inputs)?;
        let pool_address = canonicalize_recipient(&pool).map_err(ChainError::invalid_input)?;
        let (mut wallet, transport) = self.build_wallet(&inputs, seed)?;

        let config = self.blockchain_config(&transport).await?;
        let signature_context = config
            .state
            .signature_context()
            .map_err(ChainError::wallet)?;
        let has_signature_id = cc_wallet_tycho::signature_context_has_id(&signature_context);
        validate_signature_context(
            signature_context.global_id,
            has_signature_id,
            inputs.network_id,
            inputs.require_signature_id,
        )
        .map_err(ChainError::Wallet)?;

        let observed_state = transport
            .get_account_state_observed(wallet.address_string())
            .await
            .map_err(ChainError::wallet)?;
        let account_state = observed_state.state().clone();
        wallet
            .apply_observed_account_state(observed_state)
            .map_err(ChainError::wallet)?;
        let deploy = !wallet.state().is_active();

        let valid_until = now_unix_secs()?.saturating_add(SWAP_VALID_SECS);
        let (attached_native, transfer) =
            build_swap_transfer(&pool_address, &request, valid_until)?;

        let prepared = wallet
            .prepare_send_currency(&transfer, signature_context)
            .map_err(ChainError::wallet)?;
        let external_hash = Digest32::try_from_hex(&prepared.message_hash).map_err(|error| {
            ChainError::Wallet(format!(
                "prepared swap message hash is not canonical 32-byte hex: {error}"
            ))
        })?;

        validate_emulation_input_sizes(&config.state, &account_state, &prepared.message)
            .map_err(ChainError::wallet)?;

        let min_balance = emulation_balance_floor(attached_native)?;
        let shard_account =
            shard_account_for_emulation(wallet.address(), &account_state, min_balance)
                .map_err(ChainError::wallet)?;
        let block_time = now_unix_secs()?.saturating_add(FEE_ESTIMATE_STORAGE_LAG_SECS);

        let job = self.emulation_jobs.acquire(format!(
            "{}|{}",
            transport.endpoint(),
            wallet.address_string()
        ))?;
        let emulation = config.emulation.clone();
        let address = wallet.address().clone();
        let message = prepared.message.clone();
        let emulated = tokio::time::timeout(
            FEE_EMULATION_TIMEOUT,
            tokio::task::spawn_blocking(move || {
                let _job = job;
                emulate_external_message(&emulation, &address, &shard_account, &message, block_time)
            }),
        )
        .await
        .map_err(|_| {
            ChainError::Wallet(
                "swap preparation emulation timed out on hostile chain data".to_owned(),
            )
        })?
        .map_err(|_| {
            ChainError::Wallet(
                "swap preparation emulation crashed on invalid chain data".to_owned(),
            )
        })?
        .map_err(ChainError::wallet)?;
        if emulated.aborted || !emulated.compute_success {
            return Err(ChainError::Wallet(format!(
                "this swap would fail on your wallet before it reached the pool (exit code {})",
                emulated.exit_code
            )));
        }
        let fee_nanos = activity_from_chain_tx(&emulated)?
            .into_iter()
            .next()
            .map(|event| event.fee_native)
            .unwrap_or(0);

        let route = transport
            .resolve_send_route()
            .await
            .map_err(ChainError::wallet)?;

        Ok(PreparedSwap {
            endpoint: transport.endpoint().to_owned(),
            message: prepared.message,
            route,
            external_hash,
            expire_at: prepared.expire_at,
            request,
            pool: pool_address,
            deploy,
            attached_native,
            fee_nanos,
        })
    }

    pub async fn broadcast_swap(
        &self,
        prepared: &PreparedSwap,
        candidate_index: usize,
    ) -> ChainResult<CandidateBroadcastOutcome> {
        let transport = self.transport_for(&prepared.endpoint)?;
        let outcome = transport
            .send_message_cell_candidate_classified(
                &prepared.route,
                candidate_index,
                &prepared.message,
            )
            .await;
        Ok(classify_broadcast(outcome, "signed swap"))
    }

    fn storage_owner(&self, inputs: &WalletInputs) -> ChainResult<(Arc<KeyPair>, StdAddr)> {
        let seed = normalize_and_validate_inputs(inputs)?;
        let keys = self.keypair_for(seed)?;
        let owner = EverWallet::compute_address(inputs.workchain, keys.public_key())
            .map_err(ChainError::wallet)?;
        Ok((keys, owner))
    }

    pub fn storage_address_for(&self, inputs: &WalletInputs) -> ChainResult<String> {
        let (_, owner) = self.storage_owner(inputs)?;
        Ok(storage_address(&owner)
            .map_err(ChainError::wallet)?
            .0
            .to_string())
    }

    pub async fn load_storage(&self, inputs: WalletInputs) -> ChainResult<StorageSnapshot> {
        let (keys, owner) = self.storage_owner(&inputs)?;
        let (address, _) = storage_address(&owner).map_err(ChainError::wallet)?;
        let transport = self.transport_for(&inputs.endpoint)?;
        let state = transport
            .get_account_state(address.to_string())
            .await
            .map_err(ChainError::wallet)?;

        let mut snapshot = StorageSnapshot {
            address: address.to_string(),
            ..StorageSnapshot::default()
        };
        let Some(account) = state.account() else {
            return Ok(snapshot);
        };
        snapshot.balance = account.balance.tokens.into();

        let Some(stored) = storage_from_account(&state).map_err(ChainError::wallet)? else {
            return Ok(snapshot);
        };
        snapshot.exists = true;

        let owner_text = owner.to_string();
        if stored.owner != owner_text {
            return Err(ChainError::Wallet(
                "the storage at this wallet's address is owned by a different wallet".to_owned(),
            ));
        }

        let key = keys.derive_secret(STORAGE_KEY_CONTEXT);
        for (id, blob) in &stored.records {
            let aad = record_aad(&owner_text, *id);
            match open_record(&key, &aad, blob)
                .map_err(|_| ())
                .and_then(|plain| {
                    decode_record(&plain)
                        .map(|(title, data)| StorageRecord {
                            id: *id,
                            title,
                            data,
                        })
                        .map_err(|_| ())
                }) {
                Ok(record) => snapshot.records.push(record),
                Err(()) => snapshot.unreadable += 1,
            }
        }
        Ok(snapshot)
    }

    pub async fn prepare_storage_op(
        &self,
        inputs: WalletInputs,
        op: StorageOp,
    ) -> ChainResult<PreparedStorageOp> {
        let (keys, owner) = self.storage_owner(&inputs)?;
        let (address, init) = storage_address(&owner).map_err(ChainError::wallet)?;
        let (mut wallet, transport) =
            self.build_wallet(&inputs, normalize_and_validate_inputs(&inputs)?)?;

        let storage_balance = transport
            .get_account_state(address.to_string())
            .await
            .map_err(ChainError::wallet)?
            .account()
            .map_or(0u128, |account| account.balance.tokens.into());

        let config = self.blockchain_config(&transport).await?;
        let signature_context = config
            .state
            .signature_context()
            .map_err(ChainError::wallet)?;
        let has_signature_id = cc_wallet_tycho::signature_context_has_id(&signature_context);
        validate_signature_context(
            signature_context.global_id,
            has_signature_id,
            inputs.network_id,
            inputs.require_signature_id,
        )
        .map_err(ChainError::Wallet)?;

        let observed_state = transport
            .get_account_state_observed(wallet.address_string())
            .await
            .map_err(ChainError::wallet)?;
        let account_state = observed_state.state().clone();
        wallet
            .apply_observed_account_state(observed_state)
            .map_err(ChainError::wallet)?;

        let query_id = swap_query_id();
        let top_up = STORAGE_TARGET_BALANCE.saturating_sub(storage_balance);
        let op_native = STORAGE_OP_GAS.saturating_add(top_up);
        let deploy_native = STORAGE_TARGET_BALANCE.saturating_add(STORAGE_DEPLOY_GAS);
        let (attached_native, transfer) = match &op {
            StorageOp::Create => (
                deploy_native,
                EverTransfer::new(&address)
                    .map_err(ChainError::invalid_input)?
                    .native(deploy_native)
                    .map_err(ChainError::invalid_input)?
                    .bounce(false)
                    .flags(SAFE_SEND_FLAGS)
                    .dest_state_init(init),
            ),
            StorageOp::Put { id, title, data } => {
                let key = keys.derive_secret(STORAGE_KEY_CONTEXT);
                let plaintext = Zeroizing::new(
                    encode_record(title, data)
                        .map_err(|error| ChainError::InvalidInput(error.to_string()))?,
                );
                let blob = seal_record(&key, &record_aad(&owner.to_string(), *id), &plaintext)
                    .map_err(|error| ChainError::Wallet(error.to_string()))?;
                let body = storage_put_body(query_id, *id, &blob).map_err(ChainError::wallet)?;
                (
                    op_native,
                    EverTransfer::new(&address)
                        .map_err(ChainError::invalid_input)?
                        .native(op_native)
                        .map_err(ChainError::invalid_input)?
                        .bounce(true)
                        .flags(SAFE_SEND_FLAGS)
                        .payload(body),
                )
            }
            StorageOp::Delete { id } => {
                let body = storage_delete_body(query_id, *id).map_err(ChainError::wallet)?;
                (
                    op_native,
                    EverTransfer::new(&address)
                        .map_err(ChainError::invalid_input)?
                        .native(op_native)
                        .map_err(ChainError::invalid_input)?
                        .bounce(true)
                        .flags(SAFE_SEND_FLAGS)
                        .payload(body),
                )
            }
        };

        let prepared = wallet
            .prepare_send_currency(&transfer, signature_context)
            .map_err(ChainError::wallet)?;
        let external_hash = Digest32::try_from_hex(&prepared.message_hash).map_err(|error| {
            ChainError::Wallet(format!(
                "prepared storage message hash is not canonical 32-byte hex: {error}"
            ))
        })?;

        validate_emulation_input_sizes(&config.state, &account_state, &prepared.message)
            .map_err(ChainError::wallet)?;

        let min_balance = emulation_balance_floor(attached_native)?;
        let shard_account =
            shard_account_for_emulation(wallet.address(), &account_state, min_balance)
                .map_err(ChainError::wallet)?;
        let block_time = now_unix_secs()?.saturating_add(FEE_ESTIMATE_STORAGE_LAG_SECS);

        let job = self.emulation_jobs.acquire(format!(
            "{}|{}",
            transport.endpoint(),
            wallet.address_string()
        ))?;
        let emulation = config.emulation.clone();
        let wallet_address = wallet.address().clone();
        let message = prepared.message.clone();
        let emulated = tokio::time::timeout(
            FEE_EMULATION_TIMEOUT,
            tokio::task::spawn_blocking(move || {
                let _job = job;
                emulate_external_message(
                    &emulation,
                    &wallet_address,
                    &shard_account,
                    &message,
                    block_time,
                )
            }),
        )
        .await
        .map_err(|_| {
            ChainError::Wallet(
                "storage preparation emulation timed out on hostile chain data".to_owned(),
            )
        })?
        .map_err(|_| {
            ChainError::Wallet(
                "storage preparation emulation crashed on invalid chain data".to_owned(),
            )
        })?
        .map_err(ChainError::wallet)?;
        if emulated.aborted || !emulated.compute_success {
            return Err(ChainError::Wallet(format!(
                "this request would fail on your wallet before it reached the storage (exit code {})",
                emulated.exit_code
            )));
        }
        let fee_nanos = activity_from_chain_tx(&emulated)?
            .into_iter()
            .next()
            .map(|event| event.fee_native)
            .unwrap_or(0);

        let route = transport
            .resolve_send_route()
            .await
            .map_err(ChainError::wallet)?;

        Ok(PreparedStorageOp {
            endpoint: transport.endpoint().to_owned(),
            message: prepared.message,
            route,
            external_hash,
            expire_at: prepared.expire_at,
            storage_address: address.to_string(),
            op,
            attached_native,
            fee_nanos,
        })
    }

    pub async fn broadcast_storage_op(
        &self,
        prepared: &PreparedStorageOp,
        candidate_index: usize,
    ) -> ChainResult<CandidateBroadcastOutcome> {
        let transport = self.transport_for(&prepared.endpoint)?;
        let outcome = transport
            .send_message_cell_candidate_classified(
                &prepared.route,
                candidate_index,
                &prepared.message,
            )
            .await;
        Ok(classify_broadcast(outcome, "storage request"))
    }

    async fn blockchain_config(&self, transport: &Transport) -> ChainResult<CachedConfig> {
        let endpoint = transport.endpoint();
        if let Some(config) = self
            .config_cache
            .lock()
            .expect("config cache poisoned")
            .get(endpoint)
            .filter(|config| config_cache_age_is_fresh(config.fetched_at.elapsed()))
        {
            return Ok(config.clone());
        }
        let observed = transport
            .get_blockchain_config_observed()
            .await
            .map_err(ChainError::wallet)?;
        let state = Arc::new(observed.state().clone());
        let emulation = Arc::new(
            prepare_emulation_config(&state.config, now_unix_secs()?)
                .map_err(ChainError::wallet)?,
        );
        let config = CachedConfig {
            state,
            emulation,
            fetched_at: Instant::now(),
            request_id: observed.request_id().to_owned(),
            observed_at_mono: observed.observed_at_mono(),
        };
        self.config_cache
            .lock()
            .expect("config cache poisoned")
            .insert(endpoint.to_owned(), config.clone());
        Ok(config)
    }

    pub fn clear_config_cache(&self) {
        self.config_cache
            .lock()
            .expect("config cache poisoned")
            .clear();
        self.transport_cache
            .lock()
            .expect("transport cache poisoned")
            .clear();
        self.key_cache.lock().expect("key cache poisoned").clear();
    }

    pub fn drain_emulation_jobs(&self, timeout: Duration) -> bool {
        self.emulation_jobs.wait_empty(timeout)
    }
}

pub type ChainFuture<'a, T> = Pin<Box<dyn Future<Output = ChainResult<T>> + Send + 'a>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkStats {
    pub validators: usize,
    pub total_stake: Option<u128>,
    pub supply: Option<CoinSupply>,
}

pub trait ChainService: Send + Sync {
    fn generate_seed(&self) -> ChainResult<SeedPhrase>;
    fn clear_config_cache(&self);
    fn seal_key_ops(&self) {}
    fn unseal_key_ops(&self) {}
    fn drain_emulation_jobs(&self, _timeout: Duration) -> bool {
        true
    }
    fn derive_wallet_address(&self, inputs: &WalletInputs) -> ChainResult<String>;
    fn load_wallet<'a>(
        &'a self,
        inputs: &'a EndpointAddressInputs,
    ) -> ChainFuture<'a, WalletSnapshot>;
    fn prepare_transaction(
        &self,
        _inputs: WalletInputs,
        _ticket: SendTicket,
        _active_reservations: Vec<Reservation>,
        _authorized_overlap: Vec<Reservation>,
    ) -> ChainFuture<'_, PreparedChainSend> {
        Box::pin(async {
            Err(ChainError::Wallet(
                "this chain service does not implement the durable prepare pipeline".to_owned(),
            ))
        })
    }
    fn broadcast_prepared_candidate<'a>(
        &'a self,
        _prepared: &'a PreparedChainSend,
        _candidate_index: usize,
    ) -> ChainFuture<'a, CandidateBroadcastOutcome> {
        Box::pin(async {
            Err(ChainError::Wallet(
                "this chain service does not implement candidate broadcasting".to_owned(),
            ))
        })
    }
    fn estimate_fee(
        &self,
        inputs: WalletInputs,
        request: SendRequest,
        bounce: bool,
    ) -> ChainFuture<'_, FeeEstimate>;
    fn load_pool_state<'a>(
        &'a self,
        _endpoint: &'a str,
        _pool: &'a str,
    ) -> ChainFuture<'a, PoolSnapshot> {
        Box::pin(async {
            Err(ChainError::Wallet(
                "this chain service does not read DEX pool state".to_owned(),
            ))
        })
    }
    fn prepare_swap(
        &self,
        _inputs: WalletInputs,
        _pool: String,
        _request: SwapRequest,
    ) -> ChainFuture<'_, PreparedSwap> {
        Box::pin(async {
            Err(ChainError::Wallet(
                "this chain service does not implement swap preparation".to_owned(),
            ))
        })
    }
    fn broadcast_swap<'a>(
        &'a self,
        _prepared: &'a PreparedSwap,
        _candidate_index: usize,
    ) -> ChainFuture<'a, CandidateBroadcastOutcome> {
        Box::pin(async {
            Err(ChainError::Wallet(
                "this chain service does not implement swap broadcasting".to_owned(),
            ))
        })
    }
    fn storage_address_for(&self, _inputs: &WalletInputs) -> ChainResult<String> {
        Err(ChainError::Wallet(
            "this chain service does not derive storage addresses".to_owned(),
        ))
    }
    fn load_storage(&self, _inputs: WalletInputs) -> ChainFuture<'_, StorageSnapshot> {
        Box::pin(async {
            Err(ChainError::Wallet(
                "this chain service does not read storage state".to_owned(),
            ))
        })
    }
    fn prepare_storage_op(
        &self,
        _inputs: WalletInputs,
        _op: StorageOp,
    ) -> ChainFuture<'_, PreparedStorageOp> {
        Box::pin(async {
            Err(ChainError::Wallet(
                "this chain service does not implement storage preparation".to_owned(),
            ))
        })
    }
    fn broadcast_storage_op<'a>(
        &'a self,
        _prepared: &'a PreparedStorageOp,
        _candidate_index: usize,
    ) -> ChainFuture<'a, CandidateBroadcastOutcome> {
        Box::pin(async {
            Err(ChainError::Wallet(
                "this chain service does not implement storage broadcasting".to_owned(),
            ))
        })
    }
    fn check_destination<'a>(
        &'a self,
        inputs: &'a EndpointAddressInputs,
        address: String,
    ) -> ChainFuture<'a, DestinationReport>;
    fn load_transactions<'a>(
        &'a self,
        inputs: &'a EndpointAddressInputs,
        limit: u32,
        before_lt: Option<u64>,
    ) -> ChainFuture<'a, TransactionPage>;
    fn probe_endpoint(&self, endpoint: String) -> ChainFuture<'_, i32>;
    fn network_stats(&self, _endpoint: String) -> ChainFuture<'_, NetworkStats> {
        Box::pin(async {
            Err(ChainError::Wallet(
                "this chain service does not provide network stats".to_owned(),
            ))
        })
    }
    fn validator_clock(&self, _endpoint: String) -> ChainFuture<'_, ValidatorCycle> {
        Box::pin(async {
            Err(ChainError::Wallet(
                "this chain service does not provide validator-clock data".to_owned(),
            ))
        })
    }
    fn inspect_account(
        &self,
        _endpoint: String,
        _address: String,
    ) -> ChainFuture<'_, AccountInspection> {
        Box::pin(async {
            Err(ChainError::Wallet(
                "this chain service does not support account inspection".to_owned(),
            ))
        })
    }
    fn account_transactions(
        &self,
        _endpoint: String,
        _address: String,
        _limit: u32,
    ) -> ChainFuture<'_, AccountTxPage> {
        Box::pin(async {
            Err(ChainError::Wallet(
                "this chain service does not serve account history".to_owned(),
            ))
        })
    }
    fn trace_transaction(
        &self,
        _endpoint: String,
        _transaction_hash: String,
    ) -> ChainFuture<'_, AccountTrace> {
        Box::pin(async {
            Err(ChainError::Wallet(
                "this chain service does not walk message trees".to_owned(),
            ))
        })
    }
    fn subscribe(
        &self,
        inputs: EndpointAddressInputs,
        emit: Box<dyn FnMut(SubscriptionEvent) + Send>,
    ) -> ChainFuture<'_, ()>;
}

impl ChainService for TychoWalletService {
    fn generate_seed(&self) -> ChainResult<SeedPhrase> {
        TychoWalletService::generate_seed(self)
    }

    fn clear_config_cache(&self) {
        TychoWalletService::clear_config_cache(self);
    }

    fn seal_key_ops(&self) {
        TychoWalletService::seal_key_ops(self);
    }

    fn unseal_key_ops(&self) {
        TychoWalletService::unseal_key_ops(self);
    }

    fn derive_wallet_address(&self, inputs: &WalletInputs) -> ChainResult<String> {
        TychoWalletService::derive_wallet_address(self, inputs)
    }

    fn drain_emulation_jobs(&self, timeout: Duration) -> bool {
        TychoWalletService::drain_emulation_jobs(self, timeout)
    }

    fn load_wallet<'a>(
        &'a self,
        inputs: &'a EndpointAddressInputs,
    ) -> ChainFuture<'a, WalletSnapshot> {
        Box::pin(TychoWalletService::load_wallet(self, inputs))
    }

    fn prepare_transaction(
        &self,
        inputs: WalletInputs,
        ticket: SendTicket,
        active_reservations: Vec<Reservation>,
        authorized_overlap: Vec<Reservation>,
    ) -> ChainFuture<'_, PreparedChainSend> {
        Box::pin(TychoWalletService::prepare_transaction(
            self,
            inputs,
            ticket,
            active_reservations,
            authorized_overlap,
        ))
    }

    fn broadcast_prepared_candidate<'a>(
        &'a self,
        prepared: &'a PreparedChainSend,
        candidate_index: usize,
    ) -> ChainFuture<'a, CandidateBroadcastOutcome> {
        Box::pin(TychoWalletService::broadcast_prepared_candidate(
            self,
            prepared,
            candidate_index,
        ))
    }

    fn estimate_fee(
        &self,
        inputs: WalletInputs,
        request: SendRequest,
        bounce: bool,
    ) -> ChainFuture<'_, FeeEstimate> {
        Box::pin(TychoWalletService::estimate_fee(
            self, inputs, request, bounce,
        ))
    }

    fn load_pool_state<'a>(
        &'a self,
        endpoint: &'a str,
        pool: &'a str,
    ) -> ChainFuture<'a, PoolSnapshot> {
        Box::pin(TychoWalletService::load_pool_state(self, endpoint, pool))
    }

    fn prepare_swap(
        &self,
        inputs: WalletInputs,
        pool: String,
        request: SwapRequest,
    ) -> ChainFuture<'_, PreparedSwap> {
        Box::pin(TychoWalletService::prepare_swap(
            self, inputs, pool, request,
        ))
    }

    fn broadcast_swap<'a>(
        &'a self,
        prepared: &'a PreparedSwap,
        candidate_index: usize,
    ) -> ChainFuture<'a, CandidateBroadcastOutcome> {
        Box::pin(TychoWalletService::broadcast_swap(
            self,
            prepared,
            candidate_index,
        ))
    }

    fn storage_address_for(&self, inputs: &WalletInputs) -> ChainResult<String> {
        TychoWalletService::storage_address_for(self, inputs)
    }

    fn load_storage(&self, inputs: WalletInputs) -> ChainFuture<'_, StorageSnapshot> {
        Box::pin(TychoWalletService::load_storage(self, inputs))
    }

    fn prepare_storage_op(
        &self,
        inputs: WalletInputs,
        op: StorageOp,
    ) -> ChainFuture<'_, PreparedStorageOp> {
        Box::pin(TychoWalletService::prepare_storage_op(self, inputs, op))
    }

    fn broadcast_storage_op<'a>(
        &'a self,
        prepared: &'a PreparedStorageOp,
        candidate_index: usize,
    ) -> ChainFuture<'a, CandidateBroadcastOutcome> {
        Box::pin(TychoWalletService::broadcast_storage_op(
            self,
            prepared,
            candidate_index,
        ))
    }

    fn check_destination<'a>(
        &'a self,
        inputs: &'a EndpointAddressInputs,
        address: String,
    ) -> ChainFuture<'a, DestinationReport> {
        Box::pin(TychoWalletService::check_destination(self, inputs, address))
    }

    fn load_transactions<'a>(
        &'a self,
        inputs: &'a EndpointAddressInputs,
        limit: u32,
        before_lt: Option<u64>,
    ) -> ChainFuture<'a, TransactionPage> {
        Box::pin(TychoWalletService::load_transactions(
            self, inputs, limit, before_lt,
        ))
    }

    fn probe_endpoint(&self, endpoint: String) -> ChainFuture<'_, i32> {
        Box::pin(TychoWalletService::probe_endpoint(self, endpoint))
    }

    fn validator_clock(&self, endpoint: String) -> ChainFuture<'_, ValidatorCycle> {
        Box::pin(TychoWalletService::validator_clock(self, endpoint))
    }

    fn network_stats(&self, endpoint: String) -> ChainFuture<'_, NetworkStats> {
        Box::pin(TychoWalletService::network_stats(self, endpoint))
    }

    fn inspect_account(
        &self,
        endpoint: String,
        address: String,
    ) -> ChainFuture<'_, AccountInspection> {
        Box::pin(TychoWalletService::inspect_account(self, endpoint, address))
    }

    fn account_transactions(
        &self,
        endpoint: String,
        address: String,
        limit: u32,
    ) -> ChainFuture<'_, AccountTxPage> {
        Box::pin(TychoWalletService::account_transactions(
            self, endpoint, address, limit,
        ))
    }

    fn trace_transaction(
        &self,
        endpoint: String,
        transaction_hash: String,
    ) -> ChainFuture<'_, AccountTrace> {
        Box::pin(TychoWalletService::trace_transaction(
            self,
            endpoint,
            transaction_hash,
        ))
    }

    fn subscribe(
        &self,
        inputs: EndpointAddressInputs,
        emit: Box<dyn FnMut(SubscriptionEvent) + Send>,
    ) -> ChainFuture<'_, ()> {
        Box::pin(async move {
            account_subscription_loop(
                inputs.endpoint().to_owned(),
                inputs.address().to_owned(),
                emit,
            )
            .await
            .map_err(ChainError::wallet)
        })
    }
}

pub fn generate_seed() -> ChainResult<SeedPhrase> {
    Seed::generate()
        .map(Seed::into_zeroizing)
        .map(SeedPhrase::from_zeroizing)
        .map_err(ChainError::wallet)
}

fn now_unix_secs() -> ChainResult<u32> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(ChainError::wallet)?
        .as_secs();
    u32::try_from(seconds)
        .map_err(|_| ChainError::Wallet("system time exceeds the protocol u32 range".to_owned()))
}

fn monotonic_ms(observed: Instant) -> ChainResult<u64> {
    let millis = observed
        .checked_duration_since(*MONOTONIC_ORIGIN)
        .unwrap_or_default()
        .as_millis();
    u64::try_from(millis)
        .map_err(|_| ChainError::Wallet("monotonic prepare timestamp exceeds u64".to_owned()))
}

fn provenance_digest(domain: &[u8], fields: &[&[u8]]) -> Digest32 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for field in fields {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    Digest32::from_bytes(hasher.finalize().into())
}

fn account_state_digest(state: &AccountState) -> Digest32 {
    match state {
        AccountState::Exists {
            account_boc_base64,
            last_transaction_id,
            timings,
            ..
        } => {
            let last_hash = last_transaction_id
                .as_ref()
                .map(|id| id.hash.as_bytes())
                .unwrap_or_default();
            let last_lt = last_transaction_id
                .as_ref()
                .map(|id| id.lt)
                .unwrap_or_default()
                .to_be_bytes();
            provenance_digest(
                b"cc-wallet/account-state/exists/v1\0",
                &[
                    account_boc_base64.as_bytes(),
                    last_hash,
                    &last_lt,
                    &timings.gen_lt.to_be_bytes(),
                    &timings.gen_utime.to_be_bytes(),
                ],
            )
        }
        AccountState::NotExists { timings } => {
            let present = [u8::from(timings.is_some())];
            let gen_lt = timings
                .as_ref()
                .map(|value| value.gen_lt)
                .unwrap_or_default()
                .to_be_bytes();
            let gen_utime = timings
                .as_ref()
                .map(|value| value.gen_utime)
                .unwrap_or_default()
                .to_be_bytes();
            provenance_digest(
                b"cc-wallet/account-state/not-exists/v1\0",
                &[&present, &gen_lt, &gen_utime],
            )
        }
        AccountState::Unchanged { timings } => provenance_digest(
            b"cc-wallet/account-state/unchanged/v1\0",
            &[
                &timings.gen_lt.to_be_bytes(),
                &timings.gen_utime.to_be_bytes(),
            ],
        ),
    }
}

fn typed_balances(
    native_balance: u128,
    extra_balance: &BTreeMap<u32, CcAmount>,
) -> ChainResult<Vec<AssetAmount>> {
    let mut balances = Vec::with_capacity(extra_balance.len() + 1);
    balances.push(AssetAmount::native(native_balance).map_err(|error| {
        ChainError::Wallet(format!("fresh native balance is out of domain: {error}"))
    })?);
    balances.extend(
        extra_balance
            .iter()
            .map(|(&id, amount)| AssetAmount::currency_collection(id, amount.clone())),
    );
    Ok(balances)
}

fn reservations_for_ticket(
    ticket: &SendTicket,
    native_fee_ceiling: u128,
) -> ChainResult<Vec<Reservation>> {
    let fee = AssetAmount::native(native_fee_ceiling).map_err(|error| {
        ChainError::Wallet(format!(
            "local native fee ceiling is out of domain: {error}"
        ))
    })?;
    match ticket.request().value().asset_id() {
        AssetId::Native => {
            let total = ticket
                .request()
                .value()
                .checked_add_same_asset(&fee)
                .map_err(|error| {
                    ChainError::Wallet(format!(
                        "native transfer plus local fee ceiling is out of domain: {error}"
                    ))
                })?;
            Ok(vec![
                Reservation::new(ticket.record_id().clone(), total, ReservationKind::Transfer)
                    .map_err(|error| ChainError::Wallet(error.to_string()))?,
            ])
        }
        AssetId::CurrencyCollection(_) => Ok(vec![
            Reservation::new(
                ticket.record_id().clone(),
                ticket.request().value().clone(),
                ReservationKind::Transfer,
            )
            .map_err(|error| ChainError::Wallet(error.to_string()))?,
            Reservation::new(ticket.record_id().clone(), fee, ReservationKind::NativeFee)
                .map_err(|error| ChainError::Wallet(error.to_string()))?,
        ]),
    }
}

fn ensure_ticket_affordable(
    ticket: &SendTicket,
    native_fee_ceiling: u128,
    balances: &[AssetAmount],
    active_reservations: &[Reservation],
    authorized_overlap: &[Reservation],
) -> ChainResult<Vec<Reservation>> {
    affordable_ticket_reservations(
        ticket,
        native_fee_ceiling,
        balances,
        active_reservations,
        authorized_overlap,
    )?
    .ok_or_else(|| {
        ChainError::InsufficientFunds(
            "insufficient fresh balance for this amount plus the network fee".to_owned(),
        )
    })
}

fn affordable_ticket_reservations(
    ticket: &SendTicket,
    native_fee_ceiling: u128,
    balances: &[AssetAmount],
    active_reservations: &[Reservation],
    authorized_overlap: &[Reservation],
) -> ChainResult<Option<Vec<Reservation>>> {
    let reservations = reservations_for_ticket(ticket, native_fee_ceiling)?;
    let requested = reservations
        .iter()
        .map(|reservation| reservation.amount().clone())
        .collect::<Vec<_>>();
    let affordability = evaluate_affordability(
        balances,
        active_reservations,
        authorized_overlap,
        &requested,
    )
    .map_err(|error| {
        ChainError::Wallet(format!("cannot evaluate final send affordability: {error}"))
    })?;
    if affordability.is_affordable() {
        Ok(Some(reservations))
    } else {
        Ok(None)
    }
}

fn select_affordable_fee_ceiling(
    ticket: &SendTicket,
    exact_fee_native: u128,
    desired_fee_ceiling_native: u128,
    balances: &[AssetAmount],
    active_reservations: &[Reservation],
    authorized_overlap: &[Reservation],
) -> ChainResult<(u128, Vec<Reservation>)> {
    if desired_fee_ceiling_native < exact_fee_native {
        return Err(ChainError::Wallet(
            "desired native fee ceiling is below the exact emulated fee".to_owned(),
        ));
    }

    let exact_reservations = ensure_ticket_affordable(
        ticket,
        exact_fee_native,
        balances,
        active_reservations,
        authorized_overlap,
    )?;
    if desired_fee_ceiling_native == exact_fee_native {
        return Ok((exact_fee_native, exact_reservations));
    }
    if let Some(reservations) = affordable_ticket_reservations(
        ticket,
        desired_fee_ceiling_native,
        balances,
        active_reservations,
        authorized_overlap,
    )? {
        return Ok((desired_fee_ceiling_native, reservations));
    }

    let mut affordable = exact_fee_native;
    let mut reservations = exact_reservations;
    let mut unaffordable = desired_fee_ceiling_native;
    while affordable + 1 < unaffordable {
        let midpoint = affordable + (unaffordable - affordable) / 2;
        match affordable_ticket_reservations(
            ticket,
            midpoint,
            balances,
            active_reservations,
            authorized_overlap,
        )? {
            Some(candidate) => {
                affordable = midpoint;
                reservations = candidate;
            }
            None => unaffordable = midpoint,
        }
    }
    Ok((affordable, reservations))
}

fn validate_signature_context(
    reported_global_id: i32,
    has_signature_id: bool,
    expected_network_id: i32,
    require_signature_id: bool,
) -> Result<(), String> {
    if reported_global_id != expected_network_id {
        return Err(format!(
            "this endpoint serves network {reported_global_id} but the wallet is on network \
             {expected_network_id} — choose an endpoint for the wallet's network before sending"
        ));
    }
    if require_signature_id && !has_signature_id {
        return Err(format!(
            "this endpoint does not advertise replay-protected (signature-with-id) signing for \
             network {expected_network_id}; refusing to sign an unprotected transfer — switch to \
             a correct endpoint for this network before sending"
        ));
    }
    Ok(())
}

fn fee_within_bounds(fee: u128) -> bool {
    let maximum = LOCAL_SEND_FEE_CEILING_NANOS - LOCAL_SEND_FEE_HEADROOM_NANOS;
    (FEE_ESTIMATE_FLOOR_NANOS..=maximum).contains(&fee)
}

/// Our own side of a sealed comment: the keys to agree with, and the address
/// the ciphertext is bound to. The other side travels with the request.
struct CommentSeal<'a> {
    keys: &'a KeyPair,
    sender: &'a str,
}

fn build_transfer(
    request: &SendRequest,
    bounce: bool,
    seal: Option<CommentSeal<'_>>,
) -> ChainResult<EverTransfer> {
    let mut transfer = EverTransfer::new(request.destination())
        .map_err(ChainError::invalid_input)?
        .bounce(bounce)
        .flags(SAFE_SEND_FLAGS);
    if !request.comment().is_empty() {
        let payload = match (request.encrypt_to(), seal) {
            (Some(recipient), Some(seal)) => seal_comment(&seal, recipient, request)?,
            // Asking to seal with no way to seal would send in the clear what
            // was meant to be private, so it does not send at all.
            (Some(_), None) => {
                return Err(ChainError::wallet(
                    "this transfer asks for a sealed comment but carries no key to seal with"
                        .to_owned(),
                ));
            }
            (None, _) => comment_payload(request.comment())
                .map_err(|error| ChainError::invalid_input(error.to_string()))?,
        };
        transfer = transfer.payload(payload);
    }
    match request.value().asset_id() {
        AssetId::Native => transfer
            .native(
                request
                    .value()
                    .native_units()
                    .expect("native identity carries native units"),
            )
            .map_err(ChainError::invalid_input),
        AssetId::CurrencyCollection(id) => transfer
            .native(0)
            .and_then(|transfer| {
                transfer.cc_be_bytes(
                    id,
                    request
                        .value()
                        .cc_units()
                        .expect("CC identity carries CC units")
                        .to_be_bytes_31(),
                )
            })
            .map_err(ChainError::invalid_input),
    }
}

fn classify_broadcast(
    outcome: Result<BroadcastAcknowledgement, SendAttemptOutcome>,
    what: &str,
) -> CandidateBroadcastOutcome {
    match outcome {
        Ok(acknowledgement) => CandidateBroadcastOutcome::NodeResponseObserved {
            request_id: acknowledgement.request_id,
            response: NodeResponseKind::Acknowledged,
            detail: format!("node acknowledged the {what}; delivery remains unverified"),
        },
        Err(SendAttemptOutcome::NotTransmitted(reason)) => {
            let retry_next_candidate =
                matches!(reason, LocalReason::AllCandidatesFailedPreConnect(_));
            CandidateBroadcastOutcome::NotTransmitted {
                detail: SendAttemptOutcome::NotTransmitted(reason).to_string(),
                retry_next_candidate,
            }
        }
        Err(SendAttemptOutcome::MayHaveBroadcast(reason)) => {
            CandidateBroadcastOutcome::MayHaveBroadcast {
                detail: SendAttemptOutcome::MayHaveBroadcast(reason).to_string(),
            }
        }
        Err(SendAttemptOutcome::NodeResponseObserved(response)) => {
            let response_kind = classify_node_response(&response);
            CandidateBroadcastOutcome::NodeResponseObserved {
                request_id: response.request_id().to_owned(),
                response: response_kind,
                detail: SendAttemptOutcome::NodeResponseObserved(response).to_string(),
            }
        }
    }
}

fn ccdex_asset_of(asset: AssetId) -> CcdexAsset {
    match asset {
        AssetId::Native => CcdexAsset::NATIVE,
        AssetId::CurrencyCollection(id) => CcdexAsset::cc(id),
    }
}

fn swap_query_id() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos() as u64)
        .unwrap_or(0)
}

fn build_swap_transfer(
    pool: &str,
    request: &SwapRequest,
    valid_until: u32,
) -> ChainResult<(u128, EverTransfer)> {
    let in_units = request.in_units();
    let body = swap_body(
        swap_query_id(),
        ccdex_asset_of(request.in_asset()),
        in_units,
        ccdex_asset_of(request.output()),
        request.min_out_units(),
        valid_until,
        None,
    )
    .map_err(ChainError::wallet)?;

    let base = EverTransfer::new(pool)
        .map_err(ChainError::invalid_input)?
        .bounce(true)
        .flags(SAFE_SEND_FLAGS)
        .payload(body);

    match request.in_asset() {
        AssetId::Native => {
            let attached = in_units.checked_add(SWAP_GAS_NATIVE).ok_or_else(|| {
                ChainError::invalid_input("swap amount plus gas exceeds the native domain")
            })?;
            let transfer = base.native(attached).map_err(ChainError::invalid_input)?;
            Ok((attached, transfer))
        }
        AssetId::CurrencyCollection(id) => {
            let cc_bytes = CcAmount::from_u128(in_units).to_be_bytes_31();
            let transfer = base
                .native(SWAP_GAS_NATIVE)
                .map_err(ChainError::invalid_input)?
                .cc_be_bytes(id, cc_bytes)
                .map_err(ChainError::invalid_input)?;
            Ok((SWAP_GAS_NATIVE, transfer))
        }
    }
}

pub fn validate_seed_phrase(seed: &str) -> ChainResult<()> {
    let seed = Zeroizing::new(normalize_seed(seed));
    validate_seed(&seed).map_err(ChainError::invalid_input)?;
    Seed::parse(&seed).map_err(ChainError::wallet)?;
    Ok(())
}

fn normalize_and_validate_inputs(inputs: &WalletInputs) -> ChainResult<&str> {
    validate_workchain(inputs.workchain).map_err(ChainError::invalid_input)?;
    let seed = inputs.seed.expose_secret();
    if seed.trim() != seed
        || seed.split(' ').any(str::is_empty)
        || seed
            .chars()
            .any(|character| character.is_whitespace() && character != ' ')
    {
        return Err(ChainError::InvalidInput(
            "wallet seed owner is not in canonical single-space form".to_owned(),
        ));
    }
    validate_seed_phrase(seed)?;
    Ok(seed)
}

fn validate_chain_request(request: &SendRequest) -> ChainResult<()> {
    let canonical =
        canonicalize_recipient(request.destination()).map_err(ChainError::invalid_input)?;
    if canonical != request.destination() {
        return Err(ChainError::InvalidInput(
            "send destination is not in canonical standard-address form".to_owned(),
        ));
    }
    if request.value().is_zero() {
        return Err(ChainError::InvalidInput(
            "send amount must be greater than zero".to_owned(),
        ));
    }
    match request.value().asset_id() {
        AssetId::Native if request.value().native_units().is_some() => Ok(()),
        asset if asset.is_known_cc() && request.value().cc_units().is_some() => Ok(()),
        AssetId::Native => Err(ChainError::InvalidInput(
            "native send request has no native value".to_owned(),
        )),
        AssetId::CurrencyCollection(_) => Err(ChainError::InvalidInput(
            "only currency-collection ids 1, 2, and 3 can be sent".to_owned(),
        )),
    }
}

fn snapshot(address: &str, state: &WalletState, global_id: i32) -> ChainResult<WalletSnapshot> {
    let observed_network_time = state
        .observed_network_time
        .as_ref()
        .map(|observed| {
            DomainObservedNetworkTime::new(
                observed.value,
                observed.source_endpoint.clone(),
                observed.request_id.clone(),
                observed.observed_at_mono,
            )
            .map_err(ChainError::invalid_input)
        })
        .transpose()?;
    WalletSnapshot::new_with_network_time(
        address.to_owned(),
        global_id,
        account_status_label(state.status),
        state.balance,
        parse_extra_balance(state.extra_balance.clone())?,
        state.last_trans_lt,
        observed_network_time,
    )
    .map_err(ChainError::invalid_input)
}

pub fn account_status_label(status: AccountStatus) -> &'static str {
    match status {
        AccountStatus::Active => "Active",
        AccountStatus::Uninit => "Uninit",
        AccountStatus::Frozen => "Frozen",
        AccountStatus::NotExists => "Non-exist",
    }
}

fn parse_extra_balance(values: BTreeMap<u32, String>) -> ChainResult<BTreeMap<u32, CcAmount>> {
    values
        .into_iter()
        .map(|(cc_id, value)| {
            CcAmount::try_from_canonical_decimal(&value)
                .map(|amount| (cc_id, amount))
                .map_err(|error| {
                    ChainError::Wallet(format!(
                        "extra-currency {cc_id} balance {value:?} is invalid: {error}"
                    ))
                })
        })
        .collect()
}

fn classify_node_response(response: &ResponseKind) -> NodeResponseKind {
    match response {
        ResponseKind::MalformedSuccess { .. } => NodeResponseKind::Malformed,
        ResponseKind::JsonRpcError { .. } => NodeResponseKind::Rejected,
        ResponseKind::HttpStatus { .. } | ResponseKind::Redirect { .. } => {
            NodeResponseKind::TransportError
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cc_wallet_domain::{RecordId, SeedPhrase};

    const TEST_ADDRESS: &str = "0:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn node_response_classification_is_truthful() {
        let rid = || "req".to_owned();
        assert_eq!(
            classify_node_response(&ResponseKind::MalformedSuccess {
                request_id: rid(),
                detail: "d".to_owned(),
            }),
            NodeResponseKind::Malformed
        );
        assert_eq!(
            classify_node_response(&ResponseKind::JsonRpcError {
                request_id: rid(),
                detail: "d".to_owned(),
            }),
            NodeResponseKind::Rejected
        );
        assert_eq!(
            classify_node_response(&ResponseKind::HttpStatus {
                request_id: rid(),
                status: 502,
                detail: "d".to_owned(),
            }),
            NodeResponseKind::TransportError
        );
        assert_eq!(
            classify_node_response(&ResponseKind::Redirect {
                request_id: rid(),
                status: 302,
                location: None,
            }),
            NodeResponseKind::TransportError
        );
    }

    #[test]
    fn address_derivation_finishes_before_any_endpoint_transport_exists() {
        let service = TychoWalletService::default();
        let inputs = WalletInputs {
            endpoint: "https://rpc.example/".to_owned(),
            network_id: 0,
            workchain: -1,
            seed: SeedPhrase::shared(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
                    .to_owned(),
            ),
            require_signature_id: false,
        };

        let address = service.derive_wallet_address(&inputs).unwrap();

        assert!(address.starts_with("-1:"));
        assert_eq!(address.len(), 67);
        assert!(service.transport_cache.lock().unwrap().is_empty());
        assert_eq!(service.key_cache.lock().unwrap().len(), 1);
    }

    fn seed_inputs() -> WalletInputs {
        WalletInputs {
            endpoint: "https://rpc.example/".to_owned(),
            network_id: 0,
            workchain: -1,
            seed: SeedPhrase::shared(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
                    .to_owned(),
            ),
            require_signature_id: false,
        }
    }

    #[test]
    fn a_sealed_service_refuses_key_derivation_and_caches_nothing() {
        let service = TychoWalletService::default();
        let inputs = seed_inputs();

        service.seal_key_ops();
        let error = service.derive_wallet_address(&inputs).unwrap_err();
        assert!(
            matches!(&error, ChainError::Wallet(message) if message.contains("locked")),
            "a sealed service reports the wallet is locked, got {error:?}"
        );
        assert!(
            service.key_cache.lock().unwrap().is_empty(),
            "no key is derived or cached while sealed"
        );

        service.unseal_key_ops();
        service.derive_wallet_address(&inputs).unwrap();
        assert_eq!(service.key_cache.lock().unwrap().len(), 1);
    }

    #[test]
    fn clearing_the_config_cache_after_a_seal_evicts_the_cached_key() {
        let service = TychoWalletService::default();
        let inputs = seed_inputs();

        service.derive_wallet_address(&inputs).unwrap();
        assert_eq!(service.key_cache.lock().unwrap().len(), 1);

        service.seal_key_ops();
        service.clear_config_cache();
        assert!(service.key_cache.lock().unwrap().is_empty());
        assert!(service.derive_wallet_address(&inputs).is_err());
    }

    fn ticket(value: AssetAmount) -> SendTicket {
        SendTicket::new(
            RecordId::from_bytes([0x42; 32]),
            "wallet.ccwallet".to_owned(),
            TEST_ADDRESS.to_owned(),
            2000,
            "https://rpc.example/".to_owned(),
            SendRequest::new(TEST_ADDRESS, value).unwrap(),
            true,
            7,
            11,
        )
        .unwrap()
    }

    #[test]
    fn emulation_jobs_are_single_flight_and_drain_only_after_worker_exit() {
        let jobs = Arc::new(EmulationJobs::default());
        let guard = jobs.acquire("endpoint|wallet".to_owned()).unwrap();
        assert!(
            jobs.acquire("endpoint|wallet".to_owned()).is_err(),
            "the same wallet/endpoint cannot start a second blocking executor"
        );
        assert!(
            !jobs.wait_empty(Duration::ZERO),
            "an async timeout must not pretend the blocking worker has exited"
        );
        drop(guard);
        assert!(jobs.wait_empty(Duration::from_millis(10)));
    }

    #[test]
    fn send_emulation_waits_for_the_fee_worker_then_takes_ownership() {
        let jobs = Arc::new(EmulationJobs::default());
        let fee_guard = jobs.acquire("endpoint|wallet".to_owned()).unwrap();
        let waiting_jobs = Arc::clone(&jobs);
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(0);
        let waiter = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            waiting_jobs.acquire_wait("endpoint|wallet".to_owned(), Duration::from_millis(500))
        });

        started_rx.recv().unwrap();
        std::thread::sleep(Duration::from_millis(20));
        assert!(
            !waiter.is_finished(),
            "a user send waits instead of receiving the fee-preview single-flight error"
        );

        drop(fee_guard);
        let send_guard = waiter.join().unwrap().unwrap();
        assert!(
            !jobs.wait_empty(Duration::ZERO),
            "the send atomically owns the same single-flight slot after handoff"
        );
        drop(send_guard);
        assert!(jobs.wait_empty(Duration::from_millis(10)));
    }

    #[test]
    fn a_fee_is_trusted_only_inside_the_bounds() {
        assert!(
            !fee_within_bounds(0),
            "a config reporting ~zero fee is rejected"
        );
        assert!(!fee_within_bounds(FEE_ESTIMATE_FLOOR_NANOS - 1));
        assert!(fee_within_bounds(FEE_ESTIMATE_FLOOR_NANOS));
        assert!(
            fee_within_bounds(7_400_000),
            "a typical transfer fee is trusted"
        );
        let maximum = LOCAL_SEND_FEE_CEILING_NANOS - LOCAL_SEND_FEE_HEADROOM_NANOS;
        assert!(fee_within_bounds(maximum));
        assert!(!fee_within_bounds(maximum + 1), "an absurd fee is rejected");
    }

    #[test]
    fn blockchain_config_cache_expires_at_the_sixty_second_boundary() {
        assert!(config_cache_age_is_fresh(Duration::ZERO));
        assert!(config_cache_age_is_fresh(
            CONFIG_CACHE_TTL - Duration::from_nanos(1)
        ));
        assert!(!config_cache_age_is_fresh(CONFIG_CACHE_TTL));
        assert!(!config_cache_age_is_fresh(
            CONFIG_CACHE_TTL + Duration::from_secs(1)
        ));
    }

    #[test]
    fn native_and_full_width_cc_tickets_create_exact_distinct_reservations() {
        let native_ticket = ticket(AssetAmount::native(23).unwrap());
        let native = reservations_for_ticket(&native_ticket, 5).unwrap();
        assert_eq!(native.len(), 1);
        assert_eq!(native[0].kind(), ReservationKind::Transfer);
        assert_eq!(native[0].amount().native_units(), Some(28));

        let cc_max = CcAmount::try_from_canonical_decimal(
            "452312848583266388373324160190187140051835877600158453279131187530910662655",
        )
        .unwrap();
        let cc_ticket = ticket(AssetAmount::currency_collection(3, cc_max.clone()));
        let cc = reservations_for_ticket(&cc_ticket, 5).unwrap();
        assert_eq!(cc.len(), 2);
        assert_eq!(cc[0].kind(), ReservationKind::Transfer);
        assert_eq!(cc[0].amount().asset_id(), AssetId::CurrencyCollection(3));
        assert_eq!(cc[0].amount().cc_units(), Some(&cc_max));
        assert_eq!(cc[1].kind(), ReservationKind::NativeFee);
        assert_eq!(cc[1].amount().native_units(), Some(5));
    }

    #[test]
    fn fresh_affordability_uses_the_exact_emulated_fee_headroom_not_one_coin() {
        let ticket = ticket(AssetAmount::native(1_000_000_000).unwrap());
        let balances = [AssetAmount::native(1_991_508_965).unwrap()];
        let exact_fee_cap = 7_491_005 + LOCAL_SEND_FEE_HEADROOM_NANOS;

        assert!(
            ensure_ticket_affordable(&ticket, exact_fee_cap, &balances, &[], &[]).is_ok(),
            "the real fee plus shared headroom fits the fresh balance"
        );
        assert!(
            ensure_ticket_affordable(&ticket, LOCAL_SEND_FEE_CEILING_NANOS, &balances, &[], &[])
                .is_err(),
            "a fee cap at the ceiling leaves no headroom and must be refused"
        );
    }

    #[test]
    fn max_consumes_only_the_needed_headroom_when_the_fresh_fee_rises() {
        let balance = 9_984_433_990u128;
        let amount = 9_976_542_980u128;
        let preview_fee = balance - amount - LOCAL_SEND_FEE_HEADROOM_NANOS;
        assert_eq!(preview_fee, 7_491_010);

        let fresh_fee = preview_fee + 1;
        let desired_ceiling = fresh_fee + LOCAL_SEND_FEE_HEADROOM_NANOS;
        let ticket = ticket(AssetAmount::native(amount).unwrap());
        let balances = [AssetAmount::native(balance).unwrap()];

        let (chosen_ceiling, reservations) =
            select_affordable_fee_ceiling(&ticket, fresh_fee, desired_ceiling, &balances, &[], &[])
                .unwrap();

        assert_eq!(chosen_ceiling, balance - amount);
        assert_eq!(
            reservations[0].amount().native_units(),
            Some(balance),
            "the remaining 399,999 nanos are persisted instead of requiring a fresh full headroom"
        );
    }

    #[test]
    fn a_fee_beyond_the_entire_max_headroom_is_typed_insufficient_funds() {
        let balance = 9_984_433_990u128;
        let amount = 9_976_542_980u128;
        let preview_fee = balance - amount - LOCAL_SEND_FEE_HEADROOM_NANOS;
        let fresh_fee = preview_fee + LOCAL_SEND_FEE_HEADROOM_NANOS + 1;
        let ticket = ticket(AssetAmount::native(amount).unwrap());
        let balances = [AssetAmount::native(balance).unwrap()];

        let error = select_affordable_fee_ceiling(
            &ticket,
            fresh_fee,
            fresh_fee + LOCAL_SEND_FEE_HEADROOM_NANOS,
            &balances,
            &[],
            &[],
        )
        .unwrap_err();

        assert!(matches!(error, ChainError::InsufficientFunds(_)));
    }

    #[test]
    fn native_transfer_plus_fee_refuses_protocol_domain_overflow() {
        let near_max = ticket(AssetAmount::native(cc_wallet_domain::NATIVE_MAX_UNITS).unwrap());
        assert!(reservations_for_ticket(&near_max, 1).is_err());
    }

    #[test]
    fn signature_context_gate_matches_the_pin() {
        assert!(validate_signature_context(2000, true, 2000, true).is_ok());
        assert!(validate_signature_context(2000, true, 2000, false).is_ok());
        assert!(validate_signature_context(0, false, 0, false).is_ok());
        let downgraded = validate_signature_context(2000, false, 2000, true).unwrap_err();
        assert!(
            downgraded.contains("signature-with-id"),
            "the refusal names the missing protection: {downgraded}"
        );
        assert!(validate_signature_context(1, true, 2000, false).is_err());
        assert!(validate_signature_context(1, false, 2000, true).is_err());
    }

    #[test]
    fn maps_account_status_labels() {
        assert_eq!(account_status_label(AccountStatus::Active), "Active");
        assert_eq!(account_status_label(AccountStatus::Uninit), "Uninit");
        assert_eq!(account_status_label(AccountStatus::Frozen), "Frozen");
        assert_eq!(account_status_label(AccountStatus::NotExists), "Non-exist");
    }

    #[test]
    fn parses_extra_balances() {
        let balances = BTreeMap::from([(1_u32, "100".to_owned()), (2_u32, "200".to_owned())]);
        let parsed = parse_extra_balance(balances).unwrap();
        assert_eq!(
            parsed.get(&1).map(CcAmount::to_canonical_decimal),
            Some("100".to_owned())
        );
        assert_eq!(
            parsed.get(&2).map(CcAmount::to_canonical_decimal),
            Some("200".to_owned())
        );
    }

    #[test]
    fn an_unparseable_extra_balance_rejects_the_whole_snapshot() {
        let balances = BTreeMap::from([(1_u32, "42".to_owned()), (2_u32, "not-number".to_owned())]);
        let error = parse_extra_balance(balances).unwrap_err();
        assert!(error.to_string().contains("extra-currency 2"));
    }

    #[test]
    fn a_full_width_extra_balance_is_preserved_exactly() {
        let maximum = CcAmount::from_be_bytes_31(&[0xff; 31]).to_canonical_decimal();
        let parsed = parse_extra_balance(BTreeMap::from([(3_u32, maximum.clone())])).unwrap();
        assert_eq!(
            parsed.get(&3).map(CcAmount::to_canonical_decimal),
            Some(maximum)
        );
    }

    const DEST: &str = "0:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

    fn native_request(amount: u128) -> SendRequest {
        SendRequest::native(DEST, amount).unwrap()
    }

    #[test]
    fn the_budget_the_form_enforces_is_the_budget_the_builder_accepts() {
        // Two crates hold this figure — the domain, which cuts the field, and
        // the message builder, which refuses what will not fit. This is the one
        // place that sees both, and a disagreement here is a comment the user
        // is allowed to type and the wallet then cannot send.
        assert_eq!(
            cc_wallet_domain::MAX_COMMENT_BYTES,
            cc_wallet_tycho::MAX_COMMENT_BYTES,
        );
        assert_eq!(
            cc_wallet_domain::MAX_ENCRYPTED_COMMENT_BYTES,
            cc_wallet_tycho::MAX_ENCRYPTED_COMMENT_BYTES,
        );

        let sender = KeyPair::from_secret_bytes([9u8; 32]);
        let recipient = KeyPair::from_secret_bytes([11u8; 32]);
        let text = "x".repeat(cc_wallet_domain::MAX_ENCRYPTED_COMMENT_BYTES);
        let request = SendRequest::native(DEST, 1_000)
            .unwrap()
            .with_comment(&text)
            .sealed_to(Some(recipient.public_key_bytes()));
        assert_eq!(
            request.comment().len(),
            text.len(),
            "the form keeps it whole"
        );

        build_transfer(
            &request,
            true,
            Some(CommentSeal {
                keys: &sender,
                sender: "0:1111111111111111111111111111111111111111111111111111111111111111",
            }),
        )
        .expect("a comment cut to the budget is one the builder can carry");
    }

    #[test]
    fn a_sealed_comment_leaves_no_plaintext_in_the_message() {
        let sender = KeyPair::from_secret_bytes([9u8; 32]);
        let recipient = KeyPair::from_secret_bytes([11u8; 32]);
        let text = "rent for July, flat 4";
        let request = SendRequest::native(DEST, 1_000)
            .unwrap()
            .with_comment(text)
            .sealed_to(Some(recipient.public_key_bytes()));

        let transfer = build_transfer(
            &request,
            true,
            Some(CommentSeal {
                keys: &sender,
                sender: "0:1111111111111111111111111111111111111111111111111111111111111111",
            }),
        )
        .expect("a sealed transfer builds");
        let body = transfer.build_internal_message().unwrap();
        let raw = tycho_types::boc::Boc::encode(&body);
        assert!(
            !raw.windows(text.len()).any(|w| w == text.as_bytes()),
            "the comment must not appear in what goes on the wire"
        );

        let parsed = cc_wallet_tycho::parse_encrypted_comment(transfer.payload_cell().unwrap())
            .expect("the body parses")
            .expect("it is a sealed comment");
        assert_eq!(
            parsed.sender_key,
            sender.public_key_bytes(),
            "the recipient learns whose key to agree with from the message itself"
        );

        // The recipient reaches the same key from their own side and reads it.
        let key = recipient
            .comment_secret_for(&sender.public_key_bytes())
            .unwrap();
        let aad = comment_aad(
            "0:1111111111111111111111111111111111111111111111111111111111111111",
            request.destination(),
        );
        let opened = open_record(&key, &aad, &parsed.sealed).expect("it opens");
        assert_eq!(String::from_utf8(opened.to_vec()).unwrap(), text);
    }

    #[test]
    fn a_transfer_that_asks_to_seal_with_no_key_does_not_go_out_in_the_clear() {
        let request = SendRequest::native(DEST, 1_000)
            .unwrap()
            .with_comment("private")
            .sealed_to(Some([3u8; 32]));

        assert!(
            build_transfer(&request, true, None).is_err(),
            "sending it unsealed would publish what was meant to be private"
        );
    }

    #[test]
    fn transfers_use_safe_flags_and_the_requested_bounce() {
        let bounceable = build_transfer(&native_request(1_000), true, None).unwrap();
        let bounceable_cell = bounceable.build_internal_message().unwrap();

        let non_bounceable = build_transfer(&native_request(1_000), false, None).unwrap();
        let non_bounceable_cell = non_bounceable.build_internal_message().unwrap();

        assert_eq!(
            SAFE_SEND_FLAGS, 1,
            "ignore-action-errors must stay disabled"
        );
        assert_ne!(bounceable_cell.repr_hash(), non_bounceable_cell.repr_hash());
    }
}
