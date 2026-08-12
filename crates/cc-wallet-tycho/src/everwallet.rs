use crate::contracts::{
    ContractAt, ContractSpec, DecodedContract, DecodedField, decode_contract_data,
};
use crate::crypto::KeyPair;
use crate::transport::{AccountState, ObservedAccountState, ObservedNetworkTime};
use anyhow::{Context, Result, anyhow, bail, ensure};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::VerifyingKey;
use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::{Arc, LazyLock, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tycho_types::abi::{AbiHeaderType, AbiType, AbiVersion, Function, IntoAbi, WithAbiType};
use tycho_types::models::account::AccountStatus;
use tycho_types::models::{
    CurrencyCollection, ExtraCurrencyCollection, IntAddr, OwnedRelaxedMessage, RelaxedIntMsgInfo,
    RelaxedMsgInfo, SignatureContext, StateInit, StdAddr, StdAddrFormat,
};
use tycho_types::num::{Tokens, VarUint248};
use tycho_types::prelude::*;

pub const EVER_WALLET_CODE_BOC: &str = "te6cckEBBgEA/AABFP8A9KQT9LzyyAsBAgEgAgMABNIwAubycdcBAcAA8nqDCNcY7UTQgwfXAdcLP8j4KM8WI88WyfkAA3HXAQHDAJqDB9cBURO68uBk3oBA1wGAINcBgCDXAVQWdfkQ8qj4I7vyeWa++COBBwiggQPoqFIgvLHydAIgghBM7mRsuuMPAcjL/8s/ye1UBAUAmDAC10zQ+kCDBtcBcdcBeNcB10z4AHCAEASqAhSxyMsFUAXPFlAD+gLLaSLQIc8xIddJoIQJuZgzcAHLAFjPFpcwcQHLABLM4skB+wAAPoIQFp4+EbqOEfgAApMg10qXeNcB1AL7AOjRkzLyPOI+zYS/";

pub const DEFAULT_WORKCHAIN: i8 = 0;
pub const DEFAULT_TTL_SECS: u32 = 60;
pub const DEFAULT_SEND_FLAGS: u8 = 3;

pub const CLOCK_SKEW_MARGIN_SECS: u64 = 10;
const NETWORK_TIME_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(30);
pub const MAX_EVER_EXTRA_CURRENCY_ID: u32 = i32::MAX as u32;

static EVER_WALLET_CODE: LazyLock<Cell> = LazyLock::new(|| {
    Boc::decode_base64(EVER_WALLET_CODE_BOC).expect("invalid Ever Wallet code BOC")
});

pub fn ever_wallet_code_hash() -> String {
    format!("{:x}", EVER_WALLET_CODE.repr_hash())
}

static EMPTY_PAYLOAD: LazyLock<Cell> =
    LazyLock::new(|| CellBuilder::new().build().expect("empty cell must build"));

pub const COMMENT_OP: u32 = 0;

pub const COMMENT_ROOT_BYTES: usize = 123;

pub const COMMENT_CELL_BYTES: usize = 127;

pub const MAX_COMMENT_BYTES: usize = 1024;

pub fn comment_payload(text: &str) -> Result<Cell> {
    let bytes = text.as_bytes();
    ensure!(
        bytes.len() <= MAX_COMMENT_BYTES,
        "a comment of {} bytes exceeds the {MAX_COMMENT_BYTES}-byte budget",
        bytes.len()
    );

    let (head, mut rest) = bytes.split_at(bytes.len().min(COMMENT_ROOT_BYTES));
    let mut tail: Vec<&[u8]> = Vec::new();
    while !rest.is_empty() {
        let (chunk, remainder) = rest.split_at(rest.len().min(COMMENT_CELL_BYTES));
        tail.push(chunk);
        rest = remainder;
    }

    let mut cell: Option<Cell> = None;
    for chunk in tail.iter().rev() {
        let mut builder = CellBuilder::new();
        builder.store_raw(chunk, (chunk.len() * 8) as u16)?;
        if let Some(next) = cell.take() {
            builder.store_reference(next)?;
        }
        cell = Some(builder.build()?);
    }

    let mut root = CellBuilder::new();
    root.store_u32(COMMENT_OP)?;
    root.store_raw(head, (head.len() * 8) as u16)?;
    if let Some(next) = cell {
        root.store_reference(next)?;
    }
    root.build().context("failed to build the comment payload")
}

pub fn read_comment(body: &Cell) -> Option<String> {
    let mut slice = body.as_slice().ok()?;
    if slice.size_bits() < 32 || slice.load_u32().ok()? != COMMENT_OP {
        return None;
    }

    let mut text = Vec::new();
    let mut cell = body.clone();
    loop {
        let mut part = cell.as_slice().ok()?;
        if std::ptr::eq(cell.as_ref(), body.as_ref()) {
            part.skip_first(32, 0).ok()?;
        }
        let bits = part.size_bits();
        if !bits.is_multiple_of(8) {
            return None;
        }
        let mut chunk = vec![0u8; usize::from(bits / 8)];
        part.load_raw(&mut chunk, bits).ok()?;
        text.extend_from_slice(&chunk);
        if text.len() > MAX_COMMENT_BYTES {
            return None;
        }
        match cell.reference_cloned(0) {
            Some(next) => cell = next,
            None => break,
        }
    }

    String::from_utf8(text).ok()
}

pub trait IntoStdAddr {
    fn into_std_addr(self) -> Result<StdAddr>;
}

impl IntoStdAddr for StdAddr {
    fn into_std_addr(self) -> Result<StdAddr> {
        Ok(self)
    }
}

impl IntoStdAddr for &StdAddr {
    fn into_std_addr(self) -> Result<StdAddr> {
        Ok(self.clone())
    }
}

impl IntoStdAddr for &str {
    fn into_std_addr(self) -> Result<StdAddr> {
        parse_std_addr(self)
    }
}

impl IntoStdAddr for String {
    fn into_std_addr(self) -> Result<StdAddr> {
        parse_std_addr(&self)
    }
}

impl IntoStdAddr for &String {
    fn into_std_addr(self) -> Result<StdAddr> {
        parse_std_addr(self)
    }
}

pub fn parse_std_addr(address: impl AsRef<str>) -> Result<StdAddr> {
    let address = address.as_ref().trim();
    StdAddr::from_str_ext(address, StdAddrFormat::any())
        .map(|(addr, _)| addr)
        .or_else(|_| StdAddr::from_str(address))
        .with_context(|| format!("invalid standard address `{address}`"))
}

#[derive(WithAbiType, IntoAbi)]
struct SendTransactionRawInputs {
    flags: u8,
    message: Cell,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct WalletState {
    pub updated: bool,
    pub status: AccountStatus,
    pub balance: u128,
    pub extra_balance: BTreeMap<u32, String>,
    pub last_trans_lt: u64,
    pub last_message_ms: Option<u64>,
    pub gen_lt: Option<u64>,
    pub gen_utime: Option<u32>,
    pub observed_network_time: Option<ObservedNetworkTime>,
}

impl Default for WalletState {
    fn default() -> Self {
        Self {
            updated: false,
            status: AccountStatus::NotExists,
            balance: 0,
            extra_balance: BTreeMap::new(),
            last_trans_lt: 0,
            last_message_ms: None,
            gen_lt: None,
            gen_utime: None,
            observed_network_time: None,
        }
    }
}

impl WalletState {
    pub fn from_account_state(state: &AccountState) -> Result<Option<Self>> {
        Ok(match state {
            AccountState::Exists {
                account, timings, ..
            } => Some(Self {
                updated: true,
                status: account.state.status(),
                balance: account.balance.tokens.into(),
                extra_balance: crate::history::extra_currencies_to_strings(&account.balance.other)
                    .context("account extra-currency balance is undecodable")?,
                last_trans_lt: account.last_trans_lt,
                last_message_ms: account_replay_ms(account),
                gen_lt: Some(timings.gen_lt),
                gen_utime: Some(timings.gen_utime),
                observed_network_time: None,
            }),
            AccountState::NotExists { timings } => Some(Self {
                updated: true,
                gen_lt: timings.as_ref().map(|timings| timings.gen_lt),
                gen_utime: timings.as_ref().map(|timings| timings.gen_utime),
                observed_network_time: None,
                ..Self::default()
            }),
            AccountState::Unchanged { .. } => None,
        })
    }

    #[inline]
    pub fn exists(&self) -> bool {
        self.status != AccountStatus::NotExists
    }

    #[inline]
    pub fn is_active(&self) -> bool {
        self.status == AccountStatus::Active
    }
}

pub const EVER_WALLET_CONTRACT: &str = "Ever Wallet";

pub fn ever_wallet_spec() -> ContractSpec {
    ContractSpec {
        name: EVER_WALLET_CONTRACT,
        code_hash: Some(ever_wallet_code_hash),
        well_known_address: None,
        decode_data: decode_ever_wallet_data,
        external_method: ever_wallet_external_method,
        internal_method: ever_wallet_internal_method,
    }
}

pub fn ever_wallet_replay_ms(data: &Cell) -> Option<u64> {
    let mut slice = data.as_slice().ok()?;
    slice.load_u256().ok()?;
    slice.load_u64().ok()
}

fn account_replay_ms(account: &tycho_types::models::Account) -> Option<u64> {
    use tycho_types::models::account::AccountState as CoreAccountState;
    let CoreAccountState::Active(state_init) = &account.state else {
        return None;
    };
    let code_hash = state_init
        .code
        .as_ref()
        .map(|code| format!("{:x}", code.repr_hash()))?;
    if code_hash != ever_wallet_code_hash() {
        return None;
    }
    ever_wallet_replay_ms(state_init.data.as_ref()?)
}

fn decode_ever_wallet_data(data: &Cell) -> Option<DecodedContract> {
    let mut slice = data.as_slice().ok()?;
    let pubkey = slice.load_u256().ok()?;
    let last_message_ms = slice.load_u64().ok()?;
    Some(DecodedContract {
        kind: EVER_WALLET_CONTRACT,
        fields: vec![
            DecodedField::data("Public key", format!("{pubkey:x}")),
            DecodedField::moment("Last message", last_message_ms / 1000),
        ],
    })
}

fn ever_wallet_external_method(body: &Cell) -> Option<(&'static str, u32)> {
    let slice = body.as_slice().ok()?;
    for (name, function) in [
        ("sendTransactionRaw", send_transaction_raw_fn()),
        ("sendTransaction", send_transaction_fn()),
    ] {
        if function.decode_external_input(slice).is_ok() {
            return Some((name, function.input_id));
        }
    }
    None
}

fn ever_wallet_internal_method(_function_id: u32) -> Option<&'static str> {
    None
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AccountInspection {
    pub exists: bool,
    pub status: &'static str,
    pub balance: u128,
    pub due_payment: u128,
    pub extra_balance: BTreeMap<u32, String>,
    pub last_trans_lt: u64,
    pub last_paid: u32,
    pub storage_bits: u64,
    pub storage_cells: u64,
    pub code_hash: Option<String>,
    pub data_hash: Option<String>,
    pub code_boc: Option<String>,
    pub code_bytes: usize,
    pub data_boc: Option<String>,
    pub data_bytes: usize,
    pub decoded: Option<DecodedContract>,
    pub signing_key: Option<[u8; 32]>,
}

impl AccountInspection {
    fn not_deployed() -> Self {
        Self {
            signing_key: None,
            exists: false,
            status: "Non-exist",
            balance: 0,
            due_payment: 0,
            extra_balance: BTreeMap::new(),
            last_trans_lt: 0,
            last_paid: 0,
            storage_bits: 0,
            storage_cells: 0,
            code_hash: None,
            data_hash: None,
            code_boc: None,
            code_bytes: 0,
            data_boc: None,
            data_bytes: 0,
            decoded: None,
        }
    }

    pub fn from_account_state(state: &AccountState, address: Option<&str>) -> Result<Option<Self>> {
        use tycho_types::models::account::AccountState as CoreAccountState;
        let account = match state {
            AccountState::Exists { account, .. } => account,
            AccountState::NotExists { .. } => return Ok(Some(Self::not_deployed())),
            AccountState::Unchanged { .. } => return Ok(None),
        };

        let cell_parts = |cell: &Option<Cell>| match cell {
            Some(cell) => {
                let boc = Boc::encode(cell);
                let len = boc.len();
                (
                    Some(format!("{:x}", cell.repr_hash())),
                    Some(BASE64.encode(boc)),
                    len,
                )
            }
            None => (None, None, 0),
        };

        let mut signing_key = None;
        let (status, code_hash, data_hash, code_boc, code_bytes, data_boc, data_bytes, decoded) =
            match &account.state {
                CoreAccountState::Active(state_init) => {
                    let (code_hash, code_boc, code_bytes) = cell_parts(&state_init.code);
                    let (data_hash, data_boc, data_bytes) = cell_parts(&state_init.data);
                    let decoded = decode_contract_data(
                        ContractAt {
                            address,
                            code_hash: code_hash.as_deref(),
                        },
                        state_init.data.as_ref(),
                    );
                    if code_hash.as_deref() == Some(ever_wallet_code_hash().as_str()) {
                        signing_key = state_init
                            .data
                            .as_ref()
                            .and_then(|data| data.as_slice().ok())
                            .and_then(|mut slice| slice.load_u256().ok())
                            .map(|key| key.0);
                    }
                    (
                        "Active", code_hash, data_hash, code_boc, code_bytes, data_boc, data_bytes,
                        decoded,
                    )
                }
                CoreAccountState::Frozen(_) => ("Frozen", None, None, None, 0, None, 0, None),
                CoreAccountState::Uninit => ("Uninit", None, None, None, 0, None, 0, None),
            };

        Ok(Some(Self {
            signing_key,
            exists: true,
            status,
            balance: account.balance.tokens.into(),
            due_payment: account
                .storage_stat
                .due_payment
                .map_or(0, |tokens| tokens.into()),
            extra_balance: crate::history::extra_currencies_to_strings(&account.balance.other)
                .context("account extra-currency balance is undecodable")?,
            last_trans_lt: account.last_trans_lt,
            last_paid: account.storage_stat.last_paid,
            storage_bits: account.storage_stat.used.bits.into(),
            storage_cells: account.storage_stat.used.cells.into(),
            code_hash,
            data_hash,
            code_boc,
            code_bytes,
            data_boc,
            data_bytes,
            decoded,
        }))
    }
}

#[derive(Debug, Clone)]
pub struct PreparedMessage {
    pub message_hash: String,
    pub message: Cell,
    pub created_at_ms: u64,
    pub expire_at: u32,
}

impl PreparedMessage {
    pub fn boc(&self) -> Vec<u8> {
        Boc::encode(&self.message)
    }

    pub fn boc_base64(&self) -> String {
        Boc::encode_base64(&self.message)
    }
}

#[derive(Debug, Clone)]
pub struct EverTransfer {
    dest: StdAddr,
    native_amount: u128,
    extra_currencies: BTreeMap<u32, VarUint248>,
    bounce: bool,
    flags: u8,
    payload: Option<Cell>,
    dest_state_init: Option<StateInit>,
}

impl EverTransfer {
    pub fn new<A: IntoStdAddr>(dest: A) -> Result<Self> {
        Ok(Self {
            dest: dest.into_std_addr()?,
            native_amount: 0,
            extra_currencies: BTreeMap::new(),
            bounce: false,
            flags: DEFAULT_SEND_FLAGS,
            payload: None,
            dest_state_init: None,
        })
    }

    pub fn native(mut self, amount: u128) -> Result<Self> {
        if !Tokens::new(amount).is_valid() {
            bail!("native amount exceeds the protocol maximum (2^120 - 1)");
        }
        self.native_amount = amount;
        Ok(self)
    }

    pub fn cc_be_bytes(self, cc_id: u32, amount: [u8; 31]) -> Result<Self> {
        let mut hi_bytes = [0u8; 16];
        hi_bytes[1..].copy_from_slice(&amount[..15]);
        let hi = u128::from_be_bytes(hi_bytes);
        let lo = u128::from_be_bytes(
            amount[15..]
                .try_into()
                .expect("the low VarUint248 word is exactly 16 bytes"),
        );
        let value = VarUint248::from_words(hi, lo);
        debug_assert!(value.is_valid(), "31 bytes always fit VarUint248");
        self.cc_var(cc_id, value)
    }

    fn cc_var(mut self, cc_id: u32, amount: VarUint248) -> Result<Self> {
        if !(1..=MAX_EVER_EXTRA_CURRENCY_ID).contains(&cc_id) {
            bail!("extra-currency id must be from 1 to {MAX_EVER_EXTRA_CURRENCY_ID}");
        }
        if !amount.is_valid() {
            bail!("extra-currency amount exceeds VarUint248");
        }
        self.extra_currencies.insert(cc_id, amount);
        Ok(self)
    }

    pub fn bounce(mut self, bounce: bool) -> Self {
        self.bounce = bounce;
        self
    }

    pub fn flags(mut self, flags: u8) -> Self {
        self.flags = flags;
        self
    }

    pub fn payload(mut self, payload: Cell) -> Self {
        self.payload = Some(payload);
        self
    }

    pub fn payload_cell(&self) -> Option<&Cell> {
        self.payload.as_ref()
    }

    pub fn dest_state_init(mut self, state_init: StateInit) -> Self {
        self.dest_state_init = Some(state_init);
        self
    }

    pub fn build_internal_message(&self) -> Result<Cell> {
        let mut entries = Vec::new();
        for (&cc_id, amount) in &self.extra_currencies {
            if amount.is_zero() {
                continue;
            }
            ensure_supported_extra_currency_id(cc_id)?;
            entries.push((cc_id, *amount));
        }

        let value = CurrencyCollection {
            tokens: Tokens::new(self.native_amount),
            other: ExtraCurrencyCollection::try_from_iter(entries)
                .context("failed to build extra currency collection")?,
        };

        let message = OwnedRelaxedMessage {
            info: RelaxedMsgInfo::Int(RelaxedIntMsgInfo {
                dst: IntAddr::Std(self.dest.clone()),
                bounce: self.bounce,
                value,
                ..Default::default()
            }),
            init: self.dest_state_init.clone(),
            body: self
                .payload
                .clone()
                .unwrap_or_else(|| EMPTY_PAYLOAD.clone())
                .into(),
            layout: None,
        };

        CellBuilder::build_from(message).context("failed to build internal message cell")
    }
}

pub struct EverWallet {
    keys: Arc<KeyPair>,
    address: StdAddr,
    state: WalletState,
}

impl EverWallet {
    pub fn new(keys: KeyPair) -> Result<Self> {
        Self::with_workchain(keys, DEFAULT_WORKCHAIN)
    }

    pub fn with_workchain(keys: KeyPair, workchain: i8) -> Result<Self> {
        Self::with_shared_keys(Arc::new(keys), workchain)
    }

    pub fn with_shared_keys(keys: Arc<KeyPair>, workchain: i8) -> Result<Self> {
        let address = Self::compute_address(workchain, keys.public_key())?;

        Ok(Self {
            keys,
            address,
            state: WalletState::default(),
        })
    }

    pub fn from_seed(seed: &str) -> Result<Self> {
        Self::new(KeyPair::from_seed(seed)?)
    }

    #[inline]
    pub fn keys(&self) -> &KeyPair {
        self.keys.as_ref()
    }

    #[inline]
    pub fn address(&self) -> &StdAddr {
        &self.address
    }

    pub fn address_string(&self) -> String {
        self.address.to_string()
    }

    #[inline]
    pub fn state(&self) -> &WalletState {
        &self.state
    }

    #[inline]
    pub fn balance(&self) -> u128 {
        self.state.balance
    }

    #[inline]
    pub fn extra_balance(&self) -> &BTreeMap<u32, String> {
        &self.state.extra_balance
    }

    pub fn compute_address(workchain: i8, public_key: &VerifyingKey) -> Result<StdAddr> {
        Ok(StdAddr::new(
            workchain,
            Self::compute_address_hash(public_key)?,
        ))
    }

    pub fn compute_address_hash(public_key: &VerifyingKey) -> Result<HashBytes> {
        Ok(
            *CellBuilder::build_from(make_wallet_state_init(public_key)?)
                .context("failed to build wallet state init cell")?
                .repr_hash(),
        )
    }

    pub fn apply_observed_account_state(
        &mut self,
        observed: ObservedAccountState,
    ) -> Result<&WalletState> {
        self.apply_account_state(&observed.state)?;
        self.state.observed_network_time = observed.network_time;
        Ok(&self.state)
    }

    pub fn apply_account_state(&mut self, state: &AccountState) -> Result<&WalletState> {
        match WalletState::from_account_state(state)? {
            Some(parsed) => self.state = parsed,
            None => {
                if let Some(timings) = state.timings() {
                    self.state.gen_lt = Some(timings.gen_lt);
                    self.state.gen_utime = Some(timings.gen_utime);
                }
                self.state.updated = true;
            }
        }
        self.state.observed_network_time = None;
        Ok(&self.state)
    }

    fn checked_now_ms(&self) -> Result<u64> {
        let now = now_ms()?;
        validate_clock_skew(now / 1000, self.state.observed_network_time.as_ref())?;
        Ok(now)
    }

    pub fn prepare_send_currency(
        &self,
        transfer: &EverTransfer,
        signature_context: SignatureContext,
    ) -> Result<PreparedMessage> {
        self.prepare_send_currency_at(
            transfer,
            signature_context,
            !self.state.is_active(),
            self.checked_now_ms()?,
            DEFAULT_TTL_SECS,
        )
    }

    pub fn prepare_send_currency_at(
        &self,
        transfer: &EverTransfer,
        signature_context: SignatureContext,
        include_state_init: bool,
        created_at_ms: u64,
        ttl_secs: u32,
    ) -> Result<PreparedMessage> {
        let internal_message = transfer.build_internal_message()?;
        let expire_at = checked_expire_at(created_at_ms, ttl_secs)?;

        let inputs = SendTransactionRawInputs {
            flags: transfer.flags,
            message: internal_message,
        }
        .into_abi()
        .into_tuple_result()?;

        let deploy_state_init = include_state_init
            .then(|| make_wallet_state_init(self.keys.public_key()))
            .transpose()?;

        let unsigned_message = send_transaction_raw_fn()
            .encode_external(&inputs)
            .with_pubkey(self.keys.public_key())
            .with_time(created_at_ms)
            .with_expire_at(expire_at)
            .build_message(&self.address)?
            .with_state_init_opt(deploy_state_init);

        let signed_message = unsigned_message.sign(self.keys.secret_key(), signature_context)?;
        let message = CellBuilder::build_from(signed_message)?;
        let message_hash = format!("{}", *message.repr_hash());

        Ok(PreparedMessage {
            message_hash,
            message,
            created_at_ms,
            expire_at,
        })
    }
}

pub fn make_wallet_state_init(public_key: &VerifyingKey) -> Result<StateInit> {
    let data = CellBuilder::build_from((HashBytes(public_key.to_bytes()), 0u64))
        .context("failed to build wallet state data")?;

    Ok(StateInit {
        split_depth: None,
        special: None,
        code: Some(EVER_WALLET_CODE.clone()),
        data: Some(data),
        libraries: Dict::new(),
    })
}

fn now_ms() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time is before UNIX epoch")?
        .as_millis() as u64)
}

fn checked_expire_at(created_at_ms: u64, ttl_secs: u32) -> Result<u32> {
    let created_secs = u32::try_from(created_at_ms / 1_000)
        .context("message creation time is outside the protocol u32 range")?;
    created_secs
        .checked_add(ttl_secs)
        .ok_or_else(|| anyhow!("message expiry exceeds the protocol u32 range"))
}

fn validate_clock_skew(now_secs: u64, observed: Option<&ObservedNetworkTime>) -> Result<()> {
    let Some(observed) = observed else {
        bail!("network time unavailable; refusing to sign")
    };
    if observed.observed_at_mono.elapsed() > NETWORK_TIME_MAX_AGE {
        bail!("network time observation is stale; refresh the wallet before signing");
    }
    let chain = u64::from(observed.value);
    if now_secs > chain.saturating_add(CLOCK_SKEW_MARGIN_SECS) {
        bail!(
            "local clock is ~{}s ahead of endpoint time {}; set the system clock",
            now_secs.saturating_sub(chain),
            observed.value
        );
    }
    let expire_at = now_secs.saturating_add(DEFAULT_TTL_SECS as u64);
    if expire_at < chain + CLOCK_SKEW_MARGIN_SECS {
        bail!(
            "local clock is ~{}s behind endpoint time {}; a message signed now \
             would expire before validators accept it — set the system clock",
            chain.saturating_sub(now_secs),
            observed.value
        );
    }
    Ok(())
}

fn send_transaction_fn() -> &'static Function {
    static ABI: OnceLock<Function> = OnceLock::new();

    ABI.get_or_init(|| {
        Function::builder(AbiVersion::V2_3, "sendTransaction")
            .with_headers([
                AbiHeaderType::PublicKey,
                AbiHeaderType::Time,
                AbiHeaderType::Expire,
            ])
            .with_inputs([
                ("dest", AbiType::Address),
                ("value", AbiType::Uint(128)),
                ("bounce", AbiType::Bool),
                ("flags", AbiType::Uint(8)),
                ("payload", AbiType::Cell),
            ])
            .build()
    })
}

fn send_transaction_raw_fn() -> &'static Function {
    static ABI: OnceLock<Function> = OnceLock::new();

    ABI.get_or_init(|| {
        Function::builder(AbiVersion::V2_3, "sendTransactionRaw")
            .with_headers([
                AbiHeaderType::PublicKey,
                AbiHeaderType::Time,
                AbiHeaderType::Expire,
            ])
            .with_inputs(SendTransactionRawInputs::abi_type().named("").flatten())
            .build()
    })
}

pub fn ensure_supported_extra_currency_id(cc_id: u32) -> Result<()> {
    anyhow::ensure!(
        cc_id > 0 && cc_id <= MAX_EVER_EXTRA_CURRENCY_ID,
        "extra currency ids must be from 1 to {MAX_EVER_EXTRA_CURRENCY_ID}; got {cc_id}"
    );
    Ok(())
}

trait IntoTupleResult {
    fn into_tuple_result(self) -> Result<Vec<tycho_types::abi::NamedAbiValue>>;
}

impl IntoTupleResult for tycho_types::abi::AbiValue {
    fn into_tuple_result(self) -> Result<Vec<tycho_types::abi::NamedAbiValue>> {
        match self {
            tycho_types::abi::AbiValue::Tuple(values) => Ok(values),
            _ => Err(anyhow!("ABI value is not a tuple")),
        }
    }
}

#[cfg(test)]
mod tests {
    const COMMENT_CELLS: usize =
        (MAX_COMMENT_BYTES - COMMENT_ROOT_BYTES).div_ceil(COMMENT_CELL_BYTES);

    #[test]
    fn a_comment_fills_the_root_cell_then_chains_as_many_as_the_budget_needs() {
        let short = comment_payload("rent").unwrap();
        assert_eq!(short.reference_count(), 0);
        let mut slice = short.as_slice().unwrap();
        assert_eq!(slice.load_u32().unwrap(), COMMENT_OP);
        assert_eq!(slice.size_bits(), 4 * 8);

        let exactly_root = "x".repeat(COMMENT_ROOT_BYTES);
        assert_eq!(comment_payload(&exactly_root).unwrap().reference_count(), 0);

        let one_over = "x".repeat(COMMENT_ROOT_BYTES + 1);
        let chained = comment_payload(&one_over).unwrap();
        assert_eq!(chained.reference_count(), 1);

        let full = "x".repeat(MAX_COMMENT_BYTES);
        let deep = comment_payload(&full).unwrap();
        let mut depth = 0;
        let mut cell = deep.clone();
        while cell.reference_count() == 1 {
            depth += 1;
            cell = cell.reference_cloned(0).unwrap();
        }
        assert_eq!(
            depth, COMMENT_CELLS,
            "the root holds 123 bytes and each reference 127, chained until the budget is met"
        );

        assert!(
            comment_payload(&"x".repeat(MAX_COMMENT_BYTES + 1)).is_err(),
            "the builder refuses what the budget cannot hold; the caller truncates first"
        );
    }

    #[test]
    fn a_multibyte_comment_keeps_its_bytes() {
        let text = "аренда за июль";
        let payload = comment_payload(text).unwrap();
        let mut slice = payload.as_slice().unwrap();
        assert_eq!(slice.load_u32().unwrap(), COMMENT_OP);
        let mut bytes = vec![0u8; text.len()];
        slice.load_raw(&mut bytes, (text.len() * 8) as u16).unwrap();
        assert_eq!(String::from_utf8(bytes).unwrap(), text);
    }
    use super::*;
    use std::time::Instant;
    use tycho_types::models::Message;

    const TEST_SEED: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn cc_bytes(value: u128) -> [u8; 31] {
        let mut bytes = [0u8; 31];
        bytes[15..].copy_from_slice(&value.to_be_bytes());
        bytes
    }

    fn observed(value: u32) -> ObservedNetworkTime {
        ObservedNetworkTime {
            value,
            source_endpoint: "https://rpc.example".to_owned(),
            request_id: "7".to_owned(),
            observed_at_mono: Instant::now(),
        }
    }

    #[test]
    fn a_wallet_data_cell_decodes_back_into_the_key_and_replay_timestamp() -> Result<()> {
        let keys = crate::crypto::KeyPair::from_seed(TEST_SEED)?;
        let state_init = make_wallet_state_init(keys.public_key())?;
        let code_hash = ever_wallet_code_hash();

        let by_code =
            |data: Option<&Cell>| decode_contract_data(ContractAt::by_code(&code_hash), data);

        let fresh = by_code(state_init.data.as_ref()).expect("our own wallet code is recognised");
        assert_eq!(fresh.kind, EVER_WALLET_CONTRACT);
        assert_eq!(
            fresh.fields,
            vec![
                DecodedField::data(
                    "Public key",
                    format!("{:x}", HashBytes(keys.public_key().to_bytes()))
                ),
                DecodedField::moment("Last message", 0),
            ],
            "a wallet that has sent nothing carries a zero replay guard"
        );

        let used = CellBuilder::build_from((
            HashBytes(keys.public_key().to_bytes()),
            1_700_000_000_123u64,
        ))?;
        let decoded = by_code(Some(&used)).expect("same code, same layout");
        assert_eq!(
            decoded.fields[1],
            DecodedField::moment("Last message", 1_700_000_000)
        );

        assert!(
            decode_contract_data(
                ContractAt::by_code(
                    "0000000000000000000000000000000000000000000000000000000000000000"
                ),
                Some(&used)
            )
            .is_none(),
            "code we do not recognise is never decoded by guesswork"
        );
        assert!(
            by_code(None).is_none(),
            "a contract with no data cell decodes to nothing"
        );
        Ok(())
    }

    #[test]
    fn the_replay_guard_reads_back_exactly_what_a_message_would_store() -> Result<()> {
        let keys = crate::crypto::KeyPair::from_seed(TEST_SEED)?;
        let key = HashBytes(keys.public_key().to_bytes());
        let deployed = make_wallet_state_init(keys.public_key())?;

        assert_eq!(
            ever_wallet_replay_ms(deployed.data.as_ref().expect("a deployed wallet has data")),
            Some(0),
            "a wallet that has run nothing has run nothing at a time of zero"
        );

        let wallet = EverWallet::new(keys)?;
        let transfer = EverTransfer::new(wallet.address())?.native(1)?;
        let prepared = wallet.prepare_send_currency_at(
            &transfer,
            SignatureContext::empty(),
            true,
            1_700_000_000_123,
            DEFAULT_TTL_SECS,
        )?;
        let after = CellBuilder::build_from((key, prepared.created_at_ms))?;
        assert_eq!(
            ever_wallet_replay_ms(&after),
            Some(1_700_000_000_123),
            "the guard and the message agree to the millisecond, so one can \
             confirm the other"
        );

        assert_eq!(
            ever_wallet_replay_ms(&CellBuilder::build_from(key)?),
            None,
            "a cell without the timestamp confirms nothing"
        );
        Ok(())
    }

    #[test]
    fn symmetric_clock_boundaries_and_none_preservation() {
        let chain: u32 = 1_700_000_000;
        let c = u64::from(chain);
        let behind_limit = DEFAULT_TTL_SECS as u64 - CLOCK_SKEW_MARGIN_SECS;
        let time = observed(chain);
        assert!(validate_clock_skew(c, None).is_err());
        assert!(validate_clock_skew(c, Some(&time)).is_ok());
        assert!(validate_clock_skew(c + CLOCK_SKEW_MARGIN_SECS, Some(&time)).is_ok());
        assert!(validate_clock_skew(c + CLOCK_SKEW_MARGIN_SECS + 1, Some(&time)).is_err());
        assert!(validate_clock_skew(c - behind_limit, Some(&time)).is_ok());
        assert!(validate_clock_skew(c - behind_limit - 1, Some(&time)).is_err());
    }

    #[test]
    fn stale_observation_refuses_signing() {
        let chain = 1_700_000_000;
        let mut time = observed(chain);
        time.observed_at_mono =
            Instant::now() - NETWORK_TIME_MAX_AGE - std::time::Duration::from_secs(1);
        assert!(validate_clock_skew(u64::from(chain), Some(&time)).is_err());
    }

    #[test]
    fn matching_hostile_time_can_pass_but_is_not_trusted_time() {
        let false_time = 4_000_000_000u32;
        assert!(validate_clock_skew(u64::from(false_time), Some(&observed(false_time))).is_ok());
    }

    #[test]
    fn protocol_timestamp_overflow_is_rejected_without_wrap_or_panic() {
        assert_eq!(
            checked_expire_at((u64::from(u32::MAX) - 60) * 1_000, 60).unwrap(),
            u32::MAX
        );
        assert!(checked_expire_at((u64::from(u32::MAX) - 59) * 1_000, 60).is_err());
        assert!(checked_expire_at((u64::from(u32::MAX) + 1) * 1_000, 0).is_err());
    }

    #[test]
    fn computes_deterministic_address() -> Result<()> {
        let keys = KeyPair::from_seed(TEST_SEED)?;
        let address = EverWallet::compute_address(0, keys.public_key())?;
        let again = EverWallet::compute_address(0, keys.public_key())?;

        assert_eq!(address, again);
        assert_eq!(address.workchain, 0);
        assert_eq!(address.to_string().len(), 66);
        Ok(())
    }

    #[test]
    fn parses_raw_address() -> Result<()> {
        let address = "0:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let parsed = parse_std_addr(address)?;

        assert_eq!(parsed.to_string(), address);
        Ok(())
    }

    #[test]
    fn not_exists_account_state_maps_to_zero_balance() {
        let state = AccountState::NotExists { timings: None };
        let wallet_state = WalletState::from_account_state(&state)
            .unwrap()
            .expect("a NotExists state maps to a zero-balance wallet state");

        assert!(wallet_state.updated);
        assert_eq!(wallet_state.status, AccountStatus::NotExists);
        assert_eq!(wallet_state.balance, 0);
    }

    #[test]
    fn timed_not_exists_state_can_prepare_the_checked_first_deploy_path() -> Result<()> {
        let mut wallet = EverWallet::from_seed(TEST_SEED)?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let now = u32::try_from(now)?;
        wallet.apply_observed_account_state(ObservedAccountState {
            state: AccountState::NotExists {
                timings: Some(crate::transport::AccountTimings {
                    gen_lt: 1,
                    gen_utime: now,
                }),
            },
            network_time: Some(observed(now)),
            request_id: "state-first-deploy".to_owned(),
            observed_at_mono: Instant::now(),
        })?;
        let transfer = EverTransfer::new(wallet.address())?.native(1)?;
        let prepared = wallet.prepare_send_currency(&transfer, SignatureContext::empty())?;
        let message = prepared.message.parse::<Message>()?;
        assert!(
            message.init.is_some(),
            "first send carries wallet state-init"
        );
        Ok(())
    }

    #[test]
    fn currency_transfer_message_carries_native_and_extra_currencies() -> Result<()> {
        let dest = StdAddr::new(0, HashBytes([0x11; 32]));
        let transfer = EverTransfer::new(&dest)?
            .native(50_000_000)?
            .cc_be_bytes(1, cc_bytes(2_000_000_000))?
            .cc_be_bytes(2, cc_bytes(3))?
            .cc_be_bytes(5, cc_bytes(0))?
            .bounce(true);

        let cell = transfer.build_internal_message()?;
        let message = cell.parse::<OwnedRelaxedMessage>()?;

        match message.info {
            RelaxedMsgInfo::Int(int) => {
                assert_eq!(int.dst, IntAddr::Std(dest));
                assert!(int.bounce);
                assert_eq!(int.value.tokens.into_inner(), 50_000_000);
                let other = int.value.other.as_dict();
                assert_eq!(other.get(1u32)?.unwrap(), VarUint248::new(2_000_000_000));
                assert_eq!(other.get(2u32)?.unwrap(), VarUint248::new(3));
                assert!(other.get(5u32)?.is_none());
            }
            _ => panic!("expected an internal message"),
        }
        Ok(())
    }

    #[test]
    fn architecture_neutral_31_byte_max_reaches_varuint248_max_exactly() -> Result<()> {
        let dest = StdAddr::new(0, HashBytes([0x5a; 32]));
        let cell = EverTransfer::new(&dest)?
            .cc_be_bytes(1, [0xff; 31])?
            .build_internal_message()?;
        let message = cell.parse::<OwnedRelaxedMessage>()?;
        match message.info {
            RelaxedMsgInfo::Int(int) => {
                assert_eq!(
                    int.value.other.as_dict().get(1u32)?.unwrap(),
                    VarUint248::MAX,
                    "31-byte big-endian all-ones is exactly 2^248-1"
                );
            }
            _ => panic!("expected an internal message"),
        }
        Ok(())
    }

    #[test]
    fn a_transfer_can_carry_the_state_init_that_deploys_its_destination() -> Result<()> {
        let owner = StdAddr::new(0, HashBytes([0x44; 32]));
        let (address, init) = crate::storage::storage_address(&owner)?;

        let plain = EverTransfer::new(&address)?
            .native(1_000_000_000)?
            .build_internal_message()?
            .parse::<OwnedRelaxedMessage>()?;
        assert!(
            plain.init.is_none(),
            "an ordinary transfer never carries a state init"
        );

        let deploy = EverTransfer::new(&address)?
            .native(1_000_000_000)?
            .dest_state_init(init.clone())
            .build_internal_message()?
            .parse::<OwnedRelaxedMessage>()?;
        let carried = deploy.init.expect("the deploy carries a state init");
        assert_eq!(
            CellBuilder::build_from(&carried)?.repr_hash(),
            CellBuilder::build_from(&init)?.repr_hash()
        );
        assert_eq!(
            address.address.0,
            CellBuilder::build_from(&init)?.repr_hash().0,
            "the destination is the address that state init hashes to"
        );
        Ok(())
    }

    #[test]
    fn native_only_currency_transfer_has_empty_extra_collection() -> Result<()> {
        let dest = StdAddr::new(0, HashBytes([0x22; 32]));
        let cell = EverTransfer::new(&dest)?
            .native(1)?
            .build_internal_message()?;
        let message = cell.parse::<OwnedRelaxedMessage>()?;
        match message.info {
            RelaxedMsgInfo::Int(int) => {
                assert_eq!(int.value.tokens.into_inner(), 1);
                assert!(int.value.other.is_empty());
            }
            _ => panic!("expected an internal message"),
        }
        Ok(())
    }

    #[test]
    fn currency_transfer_rejects_unsupported_extra_currency_ids() -> Result<()> {
        let dest = StdAddr::new(0, HashBytes([0x33; 32]));

        let err = EverTransfer::new(&dest)?
            .cc_be_bytes(0, cc_bytes(1))
            .unwrap_err();
        assert!(err.to_string().contains("must be from 1 to"));

        EverTransfer::new(&dest)?
            .cc_be_bytes(MAX_EVER_EXTRA_CURRENCY_ID, cc_bytes(1))?
            .build_internal_message()?;
        let err = EverTransfer::new(&dest)?
            .cc_be_bytes(MAX_EVER_EXTRA_CURRENCY_ID + 1, cc_bytes(1))
            .unwrap_err();
        assert!(err.to_string().contains("must be from 1 to"));
        Ok(())
    }

    #[test]
    fn a_real_send_is_named_by_the_method_it_calls_not_by_its_signature_bits() -> Result<()> {
        let wallet = EverWallet::from_seed(TEST_SEED)?;
        let signature_context = SignatureContext::new_with_signature_domain(2000);
        let transfer = EverTransfer::new(wallet.address())?.native(50_000_000)?;

        let body_at = |created_at_ms: u64| -> Result<Cell> {
            let prepared = wallet.prepare_send_currency_at(
                &transfer,
                signature_context,
                false,
                created_at_ms,
                DEFAULT_TTL_SECS,
            )?;
            let message = prepared.message.parse::<Message>()?;
            Ok(CellBuilder::build_from(message.body)?)
        };
        let first_body = body_at(1_700_000_000_000)?;
        let second_body = body_at(1_700_000_001_000)?;

        assert_ne!(
            first_body.as_slice()?.load_u32()?,
            second_body.as_slice()?.load_u32()?,
            "the first bits of the body are a signature, which is why they cannot name a method"
        );
        assert_eq!(
            ever_wallet_external_method(&first_body),
            Some(("sendTransactionRaw", send_transaction_raw_fn().input_id))
        );
        assert_eq!(
            ever_wallet_external_method(&second_body),
            Some(("sendTransactionRaw", send_transaction_raw_fn().input_id)),
            "the same call, and the same id, whatever the signature happened to be"
        );
        Ok(())
    }

    #[test]
    fn the_wallets_two_spending_methods_are_told_apart_and_nothing_else_is_named() -> Result<()> {
        use tycho_types::abi::AbiValue;

        assert_ne!(
            send_transaction_fn().input_id,
            send_transaction_raw_fn().input_id,
            "two methods, two ids"
        );

        let dest =
            parse_std_addr("0:0000000000000000000000000000000000000000000000000000000000000000")?;
        let (_, body) = send_transaction_fn()
            .encode_external(&[
                AbiValue::Address(Box::new(dest.into())).named("dest"),
                AbiValue::uint(128, 1_000_000_000u64).named("value"),
                AbiValue::Bool(true).named("bounce"),
                AbiValue::uint(8, 3u8).named("flags"),
                AbiValue::Cell(Cell::default()).named("payload"),
            ])
            .with_time(1_700_000_000_000)
            .with_expire_at(1_700_000_060)
            .build_input_without_signature()?;
        assert_eq!(
            ever_wallet_external_method(&body),
            Some(("sendTransaction", send_transaction_fn().input_id))
        );

        assert_eq!(
            ever_wallet_external_method(&Cell::default()),
            None,
            "an empty body calls nothing we know"
        );
        assert_eq!(
            ever_wallet_internal_method(0),
            None,
            "an internal message to a wallet is a transfer, not a method call"
        );
        Ok(())
    }

    #[test]
    fn prepares_currency_transfer_and_deploys_on_first_send() -> Result<()> {
        use tycho_types::abi::AbiValue;

        let wallet = EverWallet::from_seed(TEST_SEED)?;
        let signature_context = SignatureContext::new_with_signature_domain(2000);

        let transfer = EverTransfer::new(wallet.address())?
            .native(50_000_000)?
            .cc_be_bytes(1, cc_bytes(1_000_000_000))?
            .payload(CellBuilder::build_from((0u32, 0xdead_beefu32))?);

        let deployed = wallet.prepare_send_currency_at(
            &transfer,
            signature_context,
            true,
            1_700_000_000_000,
            DEFAULT_TTL_SECS,
        )?;
        let message = deployed.message.parse::<Message>()?;
        assert!(message.info.is_external_in());
        assert!(message.init.is_some());
        assert_eq!(deployed.expire_at, 1_700_000_060);
        assert!(!deployed.boc().is_empty());

        let decoded = send_transaction_raw_fn().decode_external_input(message.body)?;
        assert_eq!(decoded.len(), 2);
        match &decoded[0].value {
            AbiValue::Uint(bits, flags) => {
                assert_eq!(*bits, 8);
                assert_eq!(flags.to_string(), DEFAULT_SEND_FLAGS.to_string());
            }
            other => panic!("expected uint8 flags, got {other:?}"),
        }
        match &decoded[1].value {
            AbiValue::Cell(cell) => {
                assert_eq!(
                    cell.repr_hash(),
                    transfer.build_internal_message()?.repr_hash()
                );
            }
            other => panic!("expected a cell message, got {other:?}"),
        }

        let plain = wallet.prepare_send_currency_at(
            &transfer,
            signature_context,
            false,
            1_700_000_000_000,
            DEFAULT_TTL_SECS,
        )?;
        let message = plain.message.parse::<Message>()?;
        assert!(message.init.is_none());
        Ok(())
    }
}
