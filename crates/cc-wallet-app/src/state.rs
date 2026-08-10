use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use cc_wallet_chain::MAX_STORAGE_RECORDS;
use cc_wallet_chain::{
    AccountInspection, AccountTrace, AccountTx, DestinationAccountStatus, FeeEstimate,
    LOCAL_SEND_FEE_CEILING_NANOS, LOCAL_SEND_FEE_HEADROOM_NANOS, NetworkStats, PoolSnapshot,
};
use cc_wallet_domain::{
    ActivityEvent, AddressBookEntry, AssetAmount, AssetId, CcAmount, DEFAULT_NETWORK_ID,
    DEFAULT_WORKCHAIN, Digest32, Reservation, SeedPhrase, SendForm, SendToken, StorageRecord,
    SwapForm, SwapQuote, SwapRequest, ValidatorCycle, WalletProfile, WalletSnapshot,
    all_supported_assets, base_units_u128, canonicalize_recipient, evaluate_affordability,
    format_slippage_percent, known_cc_assets, parse_send_amount, parse_slippage_percent,
    recipient_is_valid, validate_record,
};

pub const HARDCODED_SEND_FEE_NANOS: u128 = 7_400_000;

pub const SWAP_NATIVE_CUSHION: u128 = 300_000_000;

pub const SWAP_MAX_NATIVE_RESERVE: u128 = 1_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppTab {
    Wallet,
    Swap,
    Contacts,
    Explorer,
    Storage,
    Settings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deadline {
    monotonic: Instant,
    wall: SystemTime,
}

impl Deadline {
    pub fn after(duration: Duration) -> Self {
        Self {
            monotonic: Instant::now() + duration,
            wall: SystemTime::now() + duration,
        }
    }

    pub fn expired(&self) -> bool {
        Instant::now() >= self.monotonic || SystemTime::now() >= self.wall
    }

    pub fn remaining_secs(&self) -> u32 {
        let monotonic = self
            .monotonic
            .checked_duration_since(Instant::now())
            .unwrap_or_default();
        let wall = self
            .wall
            .duration_since(SystemTime::now())
            .unwrap_or_default();
        let remaining = monotonic.min(wall);
        u32::try_from(remaining.as_millis().div_ceil(1000)).unwrap_or(u32::MAX)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RecipientCheck {
    #[default]
    Unchecked,
    Pending,
    Failed,
    Known(DestinationAccountStatus),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppPhase {
    Selecting,
    Onboarding,
    Locked,
    Unlocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveStatus {
    Offline,
    Connecting,
    Live,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistenceHealth {
    Unavailable,
    QuarantineRequired,
    WritePending,
    Ready,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    Create,
    Enter,
    Confirm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthPurpose {
    Send,
    Swap,
    Storage,
    RevealRecords,
    ChangePassword,
    RevealSeed,
    DeleteWallet,
    ChangeSecuritySetting,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthModal {
    pub open: bool,
    pub mode: AuthMode,
    pub purpose: AuthPurpose,
    pub send_options_editable: bool,
    pub error: String,
}

impl Default for AuthModal {
    fn default() -> Self {
        Self {
            open: false,
            mode: AuthMode::Enter,
            purpose: AuthPurpose::Send,
            send_options_editable: false,
            error: String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapFigures {
    pub sent: AssetAmount,
    pub out_asset: AssetId,
    pub out_units: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapReceipt {
    pub sent: AssetAmount,
    pub out_asset: AssetId,
    pub expected_out_units: u128,
    pub min_out_units: u128,
    pub slippage_bps: u16,
    pub pool: String,
    pub ext_msg_hash: Option<Digest32>,
    pub submitted_unix: u64,
    pub received_units: Option<u128>,
    pub returned_units: Option<u128>,
    pub fee_native: u128,
}

impl SwapReceipt {
    pub fn settled(&self) -> bool {
        self.received_units.is_some() || self.returned_units.is_some()
    }

    pub fn returned(&self) -> bool {
        self.received_units.is_none() && self.returned_units.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapUi {
    pub form: SwapForm,
    pub pool: Option<PoolSnapshot>,
    pub pool_loading: bool,
    pub pool_error: String,
    pub quote: Option<SwapQuote>,
    pub swapping: bool,
    pub confirm: Option<SwapFigures>,
    pub slippage_input: String,
    pub receipt: Option<SwapReceipt>,
}

impl Default for SwapUi {
    fn default() -> Self {
        Self {
            form: SwapForm::default(),
            pool: None,
            pool_loading: false,
            pool_error: String::new(),
            quote: None,
            swapping: false,
            confirm: None,
            slippage_input: format_slippage_percent(SwapForm::default().slippage_bps),
            receipt: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StorageUi {
    pub address: String,
    pub exists: bool,
    pub balance: u128,
    pub records: Vec<StorageRecord>,
    pub unreadable: usize,
    pub loading: bool,
    pub loaded: bool,
    pub error: String,
    pub busy: bool,
    pub pending_label: String,
    pub title_input: String,
    pub data_input: String,
    pub form_error: String,
    pub notice: String,
    pub revealed: bool,
    pub reveal_ttl_secs: u32,
    pub pending_danger: bool,
}

impl StorageUi {
    pub fn taken_ids(&self) -> Vec<u32> {
        self.records.iter().map(|record| record.id).collect()
    }

    pub fn add_enabled(&self) -> bool {
        self.exists
            && !self.busy
            && !self.loading
            && validate_record(&self.title_input, &self.data_input).is_ok()
            && !self.is_full()
    }

    pub fn is_full(&self) -> bool {
        self.records.len() >= usize::from(MAX_STORAGE_RECORDS)
    }

    pub fn form_message(&self) -> String {
        if !self.form_error.is_empty() {
            return self.form_error.clone();
        }
        if self.title_input.trim().is_empty() && self.data_input.is_empty() {
            return String::new();
        }
        match validate_record(&self.title_input, &self.data_input) {
            Ok(()) if self.is_full() => {
                format!("The storage already holds {MAX_STORAGE_RECORDS} records")
            }
            Ok(()) => String::new(),
            Err(error) => error.to_string(),
        }
    }
}

#[derive(PartialEq, Eq)]
pub struct AppState {
    pub phase: AppPhase,
    pub key_busy: bool,
    pub lock_error: String,
    pub selected_tab: AppTab,
    pub network_id: i32,
    pub workchain: i8,
    pub network_mismatch: bool,
    pub network_name: String,
    pub default_endpoint: Option<String>,
    pub custom_endpoints: Vec<String>,
    pub selected_endpoint: usize,
    pub endpoint_test_result: String,
    pub seed: Arc<SeedPhrase>,
    pub confirmed_seed: Arc<SeedPhrase>,
    pub seed_saved: bool,
    pub seed_editing: bool,
    pub show_seed: bool,
    pub seed_reveal_deadline: Option<Deadline>,
    pub seed_unsaved: bool,
    pub seed_backup_confirmed: bool,
    pub clipboard_notice: String,
    pub seed_copy_ttl_secs: u32,
    pub onboard_import_valid: bool,
    pub autosign_mins: u8,
    pub screen_lock_mins: u8,
    pub autosign_until: Option<Deadline>,
    pub wallet_names: Vec<String>,
    pub active_wallet: String,
    pub auth: AuthModal,
    pub derived_wallet_address: String,
    pub wallet: Option<WalletSnapshot>,
    pub selected_asset: AssetId,
    pub send_form: SendForm,
    pub fee_estimate: Option<FeeEstimate>,
    pub fee_estimating: bool,
    pub fee_estimate_stale: bool,
    pub max_refining: bool,
    pub recipient_check: RecipientCheck,
    /// The key this recipient signs with, when their account publishes one. It
    /// is the whole of what makes an encrypted comment possible, so it is also
    /// the whole of what the toggle beside the comment waits for.
    pub recipient_encrypt_key: Option<[u8; 32]>,
    pub allow_unbounced: bool,
    pub journal_blocking: bool,
    pub active_reservations: Vec<Reservation>,
    pub risk_override_eligible: bool,
    pub journal_status: String,
    pub risk_review_open: bool,
    pub risk_review_details: String,
    pub risk_overlap_labels: Vec<String>,
    pub risk_overlap_selected: Vec<bool>,
    pub risk_requires_duplicate_confirmation: bool,
    pub contacts: Vec<AddressBookEntry>,
    pub visible_cc_assets: BTreeSet<u32>,
    pub activity: Vec<ActivityEvent>,
    pub busy: bool,
    pub sending: bool,
    pub auto_refreshing: bool,
    pub history_incomplete: bool,
    pub snapshot_refresh_error: Option<String>,
    pub history_integrity_error: Option<String>,
    pub history_corrupt: bool,
    pub persistence_health: PersistenceHealth,
    pub kdf_weak: bool,
    pub persistence_error: Option<String>,
    pub send_form_error: bool,
    #[doc(hidden)]
    pub send_form_prior_error: Option<String>,
    #[doc(hidden)]
    pub send_form_prior_status: Option<String>,
    #[doc(hidden)]
    pub send_form_error_message: Option<String>,
    pub error: Option<String>,
    pub status: String,
    pub live_status: LiveStatus,
    pub subscription_status: String,
    pub validator_cycle: Option<ValidatorCycle>,
    pub network_stats: Option<NetworkStats>,
    pub account_detail: Option<AccountInspection>,
    pub account_loading: bool,
    pub account_error: Option<String>,
    pub inspected_address: String,
    pub account_txs: Vec<AccountTx>,
    pub account_txs_loading: bool,
    pub account_txs_error: Option<String>,
    pub account_txs_skipped: usize,
    pub trace: Option<AccountTrace>,
    pub trace_loading: bool,
    pub trace_error: Option<String>,
    pub trace_hash: String,
    pub swap: SwapUi,
    pub storage: StorageUi,
    pub records_reveal_deadline: Option<Deadline>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            phase: AppPhase::Onboarding,
            key_busy: false,
            lock_error: String::new(),
            selected_tab: AppTab::Settings,
            network_id: DEFAULT_NETWORK_ID,
            workchain: DEFAULT_WORKCHAIN,
            network_mismatch: false,
            network_name: String::new(),
            default_endpoint: None,
            custom_endpoints: Vec::new(),
            selected_endpoint: 0,
            endpoint_test_result: String::new(),
            seed: SeedPhrase::empty_shared(),
            confirmed_seed: SeedPhrase::empty_shared(),
            seed_saved: false,
            seed_editing: false,
            show_seed: false,
            seed_reveal_deadline: None,
            seed_unsaved: false,
            seed_backup_confirmed: false,
            clipboard_notice: String::new(),
            seed_copy_ttl_secs: 0,
            onboard_import_valid: false,
            autosign_mins: cc_wallet_domain::DEFAULT_AUTOSIGN_MINS,
            screen_lock_mins: cc_wallet_domain::DEFAULT_SCREEN_LOCK_MINS,
            autosign_until: None,
            wallet_names: Vec::new(),
            active_wallet: String::new(),
            auth: AuthModal::default(),
            derived_wallet_address: String::new(),
            wallet: None,
            selected_asset: AssetId::Native,
            send_form: SendForm::default(),
            fee_estimate: None,
            fee_estimating: false,
            fee_estimate_stale: false,
            max_refining: false,
            recipient_check: RecipientCheck::Unchecked,
            recipient_encrypt_key: None,
            allow_unbounced: false,
            journal_blocking: false,
            active_reservations: Vec::new(),
            risk_override_eligible: false,
            journal_status: String::new(),
            risk_review_open: false,
            risk_review_details: String::new(),
            risk_overlap_labels: Vec::new(),
            risk_overlap_selected: Vec::new(),
            risk_requires_duplicate_confirmation: false,
            contacts: Vec::new(),
            visible_cc_assets: BTreeSet::new(),
            activity: Vec::new(),
            busy: false,
            sending: false,
            auto_refreshing: false,
            history_incomplete: false,
            snapshot_refresh_error: None,
            history_integrity_error: None,
            history_corrupt: false,
            persistence_health: PersistenceHealth::Unavailable,
            kdf_weak: false,
            persistence_error: None,
            send_form_error: false,
            send_form_prior_error: None,
            send_form_prior_status: None,
            send_form_error_message: None,
            error: None,
            status: "Settings required".to_owned(),
            live_status: LiveStatus::Offline,
            subscription_status: "not subscribed".to_owned(),
            validator_cycle: None,
            network_stats: None,
            account_detail: None,
            account_loading: false,
            account_error: None,
            inspected_address: String::new(),
            account_txs: Vec::new(),
            account_txs_loading: false,
            account_txs_error: None,
            account_txs_skipped: 0,
            trace: None,
            trace_loading: false,
            trace_error: None,
            trace_hash: String::new(),
            swap: SwapUi::default(),
            storage: StorageUi::default(),
            records_reveal_deadline: None,
        }
    }
}

impl AppState {
    pub fn swap_request(&self) -> Option<SwapRequest> {
        let form = &self.swap.form;
        let input = form.input().ok()?;
        let min_out = self
            .swap
            .quote
            .map(|quote| quote.min_out_units)
            .unwrap_or(0);
        SwapRequest::new(input, form.to_asset(), min_out, form.clamped_slippage_bps()).ok()
    }

    pub fn swap_pool_assets(&self) -> Vec<AssetId> {
        let Some(pool) = self.swap.pool.as_ref() else {
            return Vec::new();
        };
        all_supported_assets()
            .into_iter()
            .map(|meta| meta.id)
            .filter(|asset| pool.supports(*asset))
            .collect()
    }

    pub fn swap_slippage_typed_ok(&self) -> bool {
        parse_slippage_percent(&self.swap.slippage_input).is_some()
    }

    pub fn swap_button_enabled(&self) -> bool {
        if self.swap.swapping || self.wallet.is_none() {
            return false;
        }
        if !self.swap_slippage_typed_ok() {
            return false;
        }
        let Some(pool) = self.swap.pool.as_ref() else {
            return false;
        };
        if pool.paused {
            return false;
        }
        match self.swap_request() {
            Some(request) => self.can_afford_swap(&request),
            None => false,
        }
    }

    fn can_afford_swap(&self, request: &SwapRequest) -> bool {
        let Some(wallet) = self.wallet.as_ref() else {
            return false;
        };
        let in_asset = request.in_asset();
        let in_units = request.in_units();
        let have_input = base_units_u128(&wallet.balance_for(in_asset))
            .is_some_and(|balance| balance >= in_units);
        let native = wallet
            .balance_for(AssetId::Native)
            .native_units()
            .unwrap_or(0);
        let native_needed = if in_asset.is_native() {
            in_units.saturating_add(SWAP_NATIVE_CUSHION)
        } else {
            SWAP_NATIVE_CUSHION
        };
        have_input && native >= native_needed
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendBlockReason {
    PersistenceNotReady,
    RefreshInvalid,
    NetworkMismatch,
    NetworkTimeUnavailable,
    JournalBlocking,
}

impl SendBlockReason {
    pub fn message(&self) -> &'static str {
        match self {
            Self::PersistenceNotReady => {
                "Sending is blocked until the wallet journal is durably writable again"
            }
            Self::RefreshInvalid => {
                "Sending is blocked until balances and transaction history complete a valid refresh"
            }
            Self::NetworkMismatch => {
                "Sending is blocked because this endpoint serves a different network than the wallet"
            }
            Self::NetworkTimeUnavailable => {
                "Sending is blocked until the wallet has a valid network time from the current endpoint"
            }
            Self::JournalBlocking => {
                "An earlier transfer is unresolved. Ordinary signing remains blocked; use only the explicit duplicate-risk flow after its cooling period."
            }
        }
    }
}

impl AppState {
    pub fn send_safety_block_reason(&self) -> Option<SendBlockReason> {
        if self.persistence_health != PersistenceHealth::Ready {
            return Some(SendBlockReason::PersistenceNotReady);
        }
        if self.snapshot_refresh_error.is_some() || self.history_integrity_error.is_some() {
            return Some(SendBlockReason::RefreshInvalid);
        }
        if self.network_mismatch {
            return Some(SendBlockReason::NetworkMismatch);
        }
        let network_time_ok = self
            .wallet
            .as_ref()
            .and_then(WalletSnapshot::observed_network_time)
            .is_some_and(|observation| observation.source_endpoint() == self.resolved_endpoint());
        if !network_time_ok {
            return Some(SendBlockReason::NetworkTimeUnavailable);
        }
        if self.journal_blocking {
            return Some(SendBlockReason::JournalBlocking);
        }
        None
    }

    pub fn apply_profile(&mut self, profile: WalletProfile) {
        let profile = profile.normalized();
        self.network_id = profile.network_id;
        self.workchain = profile.workchain;
        self.network_mismatch = false;
        self.seed = profile.seed;
        self.confirmed_seed = Arc::clone(&self.seed);
        self.derived_wallet_address.clear();
        self.seed_saved = !self.seed.is_empty();
        self.contacts = profile.address_book;
        self.visible_cc_assets = profile.visible_cc_assets;
        self.autosign_mins = profile.autosign_mins;
        self.screen_lock_mins = profile.screen_lock_mins;
        self.custom_endpoints = profile.custom_endpoints;
        self.selected_endpoint = profile.selected_endpoint;
        self.selected_tab = if self.seed_saved {
            AppTab::Wallet
        } else {
            AppTab::Settings
        };
        self.status = if self.seed_saved {
            "Profile loaded".to_owned()
        } else {
            "Settings required".to_owned()
        };
        self.ensure_selected_asset_visible();
    }

    pub fn to_profile(&self) -> WalletProfile {
        let seed = if self.seed_unsaved {
            &self.confirmed_seed
        } else {
            &self.seed
        };
        WalletProfile {
            network_id: self.network_id,
            workchain: self.workchain,
            seed: Arc::clone(seed),
            visible_cc_assets: self.visible_cc_assets.clone(),
            address_book: self.contacts.clone(),
            autosign_mins: self.autosign_mins,
            screen_lock_mins: self.screen_lock_mins,
            custom_endpoints: self.custom_endpoints.clone(),
            selected_endpoint: self.selected_endpoint,
        }
    }

    pub fn wallet_address(&self) -> Option<&str> {
        if self.derived_wallet_address.is_empty() {
            self.wallet.as_ref().map(|wallet| wallet.address.as_str())
        } else {
            Some(self.derived_wallet_address.as_str())
        }
    }

    pub fn balance_or_zero(&self, asset: AssetId) -> AssetAmount {
        self.wallet
            .as_ref()
            .map(|wallet| wallet.balance_for(asset))
            .unwrap_or_else(|| match asset {
                AssetId::Native => AssetAmount::native(0).expect("zero native is in-domain"),
                AssetId::CurrencyCollection(id) => {
                    AssetAmount::currency_collection(id, CcAmount::zero())
                }
            })
    }

    pub fn endpoint_display_list(&self) -> Vec<String> {
        let mut list = Vec::with_capacity(self.custom_endpoints.len() + 1);
        if let Some(default) = &self.default_endpoint {
            list.push(default.clone());
        }
        list.extend(self.custom_endpoints.iter().cloned());
        list
    }

    pub fn selected_endpoint_index(&self) -> usize {
        match self.endpoint_display_list().len() {
            0 => 0,
            len => self.selected_endpoint.min(len - 1),
        }
    }

    pub fn resolved_endpoint(&self) -> String {
        let list = self.endpoint_display_list();
        if list.is_empty() {
            return String::new();
        }
        list[self.selected_endpoint.min(list.len() - 1)].clone()
    }

    pub fn set_error(&mut self, error: impl Into<String>) {
        self.status = "Error".to_owned();
        self.send_form_error = false;
        self.send_form_prior_error = None;
        self.send_form_prior_status = None;
        self.send_form_error_message = None;
        self.error = Some(error.into());
    }

    pub fn set_send_form_error(&mut self, error: impl Into<String>) {
        if !self.send_form_error {
            self.send_form_prior_error = self.error.take();
            self.send_form_prior_status = Some(self.status.clone());
        }
        let error = error.into();
        self.status = "Error".to_owned();
        self.send_form_error = true;
        self.send_form_error_message = Some(error.clone());
        self.error = Some(error);
    }

    pub fn clear_send_form_error(&mut self) {
        if self.send_form_error {
            self.send_form_error = false;
            let overlay_is_current = self.error.as_ref() == self.send_form_error_message.as_ref();
            self.send_form_error_message = None;
            let prior_error = self.send_form_prior_error.take();
            let prior_status = self.send_form_prior_status.take();
            if overlay_is_current {
                self.error = self.persistence_error.clone().or(prior_error);
                self.status = if self.persistence_error.is_some() {
                    "Error".to_owned()
                } else {
                    prior_status.unwrap_or_else(|| self.status.clone())
                };
            }
        }
    }

    pub fn clear_error(&mut self) {
        self.send_form_error = false;
        self.send_form_prior_error = None;
        self.send_form_prior_status = None;
        self.send_form_error_message = None;
        self.error = self.persistence_error.clone();
    }

    pub fn set_asset_visibility(&mut self, cc_id: u32, visible: bool) {
        if !known_cc_assets()
            .iter()
            .any(|asset| asset.id.cc_id() == Some(cc_id))
        {
            return;
        }

        if visible {
            self.visible_cc_assets.insert(cc_id);
        } else {
            self.visible_cc_assets.remove(&cc_id);
        }
        self.ensure_selected_asset_visible();
    }

    pub fn select_asset(&mut self, asset: AssetId) {
        if self.asset_is_visible(asset) {
            self.selected_asset = asset;
            self.send_form.token = match asset {
                AssetId::Native => SendToken::Native,
                AssetId::CurrencyCollection(id) => SendToken::Cc(id),
            };
        }
    }

    pub fn asset_is_visible(&self, asset: AssetId) -> bool {
        match asset {
            AssetId::Native => true,
            AssetId::CurrencyCollection(id) => {
                asset.is_known_cc() && self.visible_cc_assets.contains(&id)
            }
        }
    }

    pub fn ensure_selected_asset_visible(&mut self) {
        if !self.asset_is_visible(self.selected_asset) {
            self.selected_asset = AssetId::Native;
            self.send_form.token = SendToken::Native;
        }
        if let SendToken::Cc(id) = self.send_form.token
            && !self.visible_cc_assets.contains(&id)
        {
            self.selected_asset = AssetId::Native;
            self.send_form.token = SendToken::Native;
        }
    }

    pub fn save_contact_entry(
        &mut self,
        index: Option<usize>,
        name: impl Into<String>,
        address: impl Into<String>,
        tag: impl Into<String>,
    ) -> Result<(), String> {
        let name = name.into().trim().to_owned();
        let address = address.into().trim().to_owned();
        let tag = tag.into().trim().to_owned();
        if name.is_empty() {
            return Err("contact name is empty".to_owned());
        }
        let address = canonicalize_recipient(&address).map_err(|error| error.to_string())?;

        if let Some(conflict) = self.contact_conflict(index, &name, &address) {
            return Err(conflict);
        }

        if let Some(entry) = index.and_then(|i| self.contacts.get_mut(i)) {
            entry.name = name;
            entry.address = address;
            entry.tag = tag;
        } else {
            self.contacts.push(AddressBookEntry { name, address, tag });
        }
        Ok(())
    }

    pub fn contact_conflict(
        &self,
        index: Option<usize>,
        name: &str,
        address: &str,
    ) -> Option<String> {
        let others = self
            .contacts
            .iter()
            .enumerate()
            .filter(|(i, _)| Some(*i) != index)
            .map(|(_, entry)| entry);
        for entry in others {
            if entry.address == address {
                return Some("A contact with this address already exists.".to_owned());
            }
            if entry.name == name {
                return Some("A contact with this name already exists.".to_owned());
            }
        }
        None
    }

    pub fn within_autosign(&self) -> bool {
        self.autosign_until
            .map(|deadline| !deadline.expired())
            .unwrap_or(false)
    }

    pub fn extend_autosign(&mut self) {
        self.autosign_until = Some(Deadline::after(Duration::from_secs(
            u64::from(self.autosign_mins) * 60,
        )));
    }

    pub fn recipient_valid(&self) -> bool {
        recipient_is_valid(&self.send_form.destination)
    }

    pub fn send_bounce(&self) -> bool {
        !(self.allow_unbounced && self.recipient_known_inactive())
    }

    fn recipient_known_inactive(&self) -> bool {
        matches!(
            self.recipient_check,
            RecipientCheck::Known(status) if !status.is_active()
        )
    }

    pub fn recipient_inactive(&self) -> bool {
        self.recipient_valid() && self.recipient_known_inactive()
    }

    pub fn recipient_send_permitted(&self, risk_override: bool) -> bool {
        match self.recipient_check {
            RecipientCheck::Known(status) if status.is_active() => true,
            RecipientCheck::Known(_) => self.allow_unbounced || risk_override,
            _ => false,
        }
    }

    pub fn reset_recipient_status(&mut self) {
        self.recipient_check = RecipientCheck::Unchecked;
        self.allow_unbounced = false;
        // A key belongs to one recipient. Editing the address invalidates both
        // the key and the intention to use it, or the next transfer would be
        // sealed to whoever was in the field before.
        self.recipient_encrypt_key = None;
        self.send_form.encrypt = false;
    }

    /// The request this form stands for, sealed to the recipient when that is
    /// both possible and asked for. The form knows the intention and the state
    /// knows the key, and only here do the two meet.
    pub fn send_request(&self) -> cc_wallet_domain::WalletResult<cc_wallet_domain::SendRequest> {
        Ok(self
            .send_form
            .request()?
            .sealed_to(self.sealing_key_for_comment()))
    }

    fn sealing_key_for_comment(&self) -> Option<[u8; 32]> {
        if !self.send_form.encrypt || self.send_form.comment.is_empty() {
            return None;
        }
        self.recipient_encrypt_key
    }

    /// What a comment may run to right now. Sealing spends part of the budget,
    /// so the answer changes with the toggle and the field has to follow it.
    pub fn comment_limit(&self) -> usize {
        if self.send_form.encrypt {
            cc_wallet_domain::MAX_ENCRYPTED_COMMENT_BYTES
        } else {
            cc_wallet_domain::MAX_COMMENT_BYTES
        }
    }

    /// Whether this comment could be encrypted at all: the recipient's account
    /// has to be there, and it has to publish the key to encrypt to.
    pub fn encrypt_available(&self) -> bool {
        self.recipient_valid() && self.recipient_encrypt_key.is_some()
    }

    /// Why not, when it is worth saying. Before an address is entered there is
    /// nothing to explain, and while the answer is still coming, saying so
    /// would only flicker.
    pub fn encrypt_hint(&self) -> &'static str {
        if self.encrypt_available() || !self.recipient_valid() {
            return "";
        }
        match self.recipient_check {
            RecipientCheck::Unchecked | RecipientCheck::Pending => "",
            RecipientCheck::Failed => "could not read this recipient's account",
            RecipientCheck::Known(_) => "this recipient publishes no key to encrypt to",
        }
    }

    pub fn amount_positive(&self) -> bool {
        parse_send_amount(self.send_form.token.asset_id(), &self.send_form.amount).is_ok()
    }

    pub fn risk_override_form_ready(&self) -> bool {
        self.send_form.request().is_ok()
    }

    pub fn effective_send_fee(&self) -> u128 {
        self.fee_estimate
            .map(|estimate| estimate.fee_nanos)
            .unwrap_or(HARDCODED_SEND_FEE_NANOS)
    }

    pub(crate) fn pending_send_fee_bound(&self) -> u128 {
        self.effective_send_fee()
            .max(HARDCODED_SEND_FEE_NANOS)
            .saturating_add(LOCAL_SEND_FEE_HEADROOM_NANOS)
    }

    fn affordable_send_fee(&self) -> Option<u128> {
        let fee = self.effective_send_fee();
        (fee <= LOCAL_SEND_FEE_CEILING_NANOS).then_some(fee)
    }

    pub fn can_afford_send(&self) -> bool {
        let Ok(amount) = parse_send_amount(self.send_form.token.asset_id(), &self.send_form.amount)
        else {
            return false;
        };
        self.can_afford_amount(&amount, &[])
    }

    pub fn can_afford_request_with_overlap(
        &self,
        request: &cc_wallet_domain::SendRequest,
        overlap: &[Reservation],
    ) -> bool {
        self.can_afford_amount(request.value(), overlap)
    }

    fn can_afford_amount(&self, amount: &AssetAmount, overlap: &[Reservation]) -> bool {
        let Some(fee_units) = self.affordable_send_fee() else {
            return false;
        };
        self.can_afford_amount_at_fee(amount, overlap, fee_units)
    }

    fn can_afford_amount_at_fee(
        &self,
        amount: &AssetAmount,
        overlap: &[Reservation],
        fee_units: u128,
    ) -> bool {
        let Some(wallet) = self.wallet.as_ref() else {
            return false;
        };
        let Ok(fee) = AssetAmount::native(fee_units) else {
            return false;
        };

        let mut balances = Vec::with_capacity(wallet.extra_balance().len() + 1);
        balances.push(wallet.balance_for(AssetId::Native));
        balances.extend(
            wallet
                .extra_balance()
                .keys()
                .map(|&id| wallet.balance_for(AssetId::CurrencyCollection(id))),
        );
        let requested = match amount.asset_id() {
            AssetId::Native => match amount.checked_add_same_asset(&fee) {
                Ok(total) => vec![total],
                Err(_) => return false,
            },
            AssetId::CurrencyCollection(_) => vec![amount.clone(), fee],
        };
        evaluate_affordability(&balances, &self.active_reservations, overlap, &requested)
            .is_ok_and(|report| report.is_affordable())
    }

    pub fn amount_exceeds_balance(&self) -> bool {
        !self.sending && self.wallet.is_some() && self.amount_positive() && !self.can_afford_send()
    }

    pub fn send_enabled(&self) -> bool {
        self.send_safety_block_reason().is_none()
            && !self.busy
            && !self.sending
            && !self.max_refining
            && self.recipient_valid()
            && self.amount_positive()
            && self.comment_fits()
            && self.can_afford_send()
    }

    /// The field is cut to the budget as it is typed, so this should never be
    /// false. It is here because the alternative to catching it is a transfer
    /// the builder refuses after the user has already pressed Send.
    pub fn comment_fits(&self) -> bool {
        self.send_form.comment.len() <= self.comment_limit()
    }

    pub fn send_ready(&self) -> bool {
        if !self.fee_estimate_stale {
            return self.send_enabled();
        }
        let Ok(amount) = parse_send_amount(self.send_form.token.asset_id(), &self.send_form.amount)
        else {
            return false;
        };
        self.send_safety_block_reason().is_none()
            && !self.busy
            && !self.sending
            && !self.max_refining
            && self.recipient_valid()
            && self.can_afford_amount_at_fee(&amount, &[], self.pending_send_fee_bound())
    }

    pub fn delete_contact(&mut self, index: usize) {
        if index < self.contacts.len() {
            self.contacts.remove(index);
        }
    }

    pub fn reorder_contact(&mut self, from: usize, to: usize) {
        if from == to || from >= self.contacts.len() || to >= self.contacts.len() {
            return;
        }
        let entry = self.contacts.remove(from);
        self.contacts.insert(to, entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cc_wallet_domain::{CcAmount, ObservedNetworkTime};

    const ADDRESS_A: &str = "0:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ADDRESS_B: &str = "0:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const ADDRESS_C: &str = "0:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn timed_wallet() -> WalletSnapshot {
        WalletSnapshot::new_with_network_time(
            ADDRESS_A,
            0,
            "Active",
            0,
            Default::default(),
            0,
            Some(
                ObservedNetworkTime::new(
                    1_700_000_000,
                    "https://rpc.example/",
                    "state-test",
                    Instant::now(),
                )
                .unwrap(),
            ),
        )
        .unwrap()
    }

    #[test]
    fn a_past_deadline_is_expired_and_a_future_one_is_not() {
        assert!(Deadline::after(Duration::from_secs(0)).expired());
        assert!(!Deadline::after(Duration::from_secs(3600)).expired());
    }

    #[test]
    fn the_default_screen_lock_is_five_minutes() {
        assert_eq!(AppState::default().screen_lock_mins, 5);
    }

    #[test]
    fn balance_or_zero_returns_zero_per_asset_without_wallet() {
        let mut state = AppState::default();
        assert!(state.wallet.is_none());
        assert_eq!(
            state.balance_or_zero(AssetId::Native).native_units(),
            Some(0)
        );
        let cc_zero = state.balance_or_zero(AssetId::CurrencyCollection(2));
        assert_eq!(cc_zero.asset_id(), AssetId::CurrencyCollection(2));
        assert!(cc_zero.is_zero());

        let mut extra = std::collections::BTreeMap::new();
        extra.insert(2u32, CcAmount::from_u128(9));
        let wallet =
            WalletSnapshot::new_with_network_time(ADDRESS_A, 0, "Active", 12_345, extra, 0, None)
                .unwrap();
        let expected_native = wallet.balance_for(AssetId::Native);
        let expected_cc = wallet.balance_for(AssetId::CurrencyCollection(2));
        state.wallet = Some(wallet);
        assert_eq!(state.balance_or_zero(AssetId::Native), expected_native);
        assert_eq!(
            state.balance_or_zero(AssetId::CurrencyCollection(2)),
            expected_cc
        );
        assert_eq!(
            state.balance_or_zero(AssetId::Native).native_units(),
            Some(12_345)
        );
    }

    #[test]
    fn endpoint_display_list_is_derived_not_cached() {
        let mut state = AppState {
            default_endpoint: Some("https://default.test/".to_owned()),
            custom_endpoints: vec!["https://a.test/".to_owned()],
            selected_endpoint: 1,
            ..AppState::default()
        };
        assert_eq!(
            state.endpoint_display_list(),
            vec![
                "https://default.test/".to_owned(),
                "https://a.test/".to_owned()
            ]
        );
        assert_eq!(state.selected_endpoint_index(), 1);
        assert_eq!(state.resolved_endpoint(), "https://a.test/");

        state.custom_endpoints.push("https://b.test/".to_owned());
        state.selected_endpoint = 2;
        assert_eq!(state.endpoint_display_list().len(), 3);
        assert_eq!(state.selected_endpoint_index(), 2);
        assert_eq!(state.resolved_endpoint(), "https://b.test/");

        state.default_endpoint = None;
        state.selected_endpoint = 99;
        assert_eq!(state.endpoint_display_list().len(), 2);
        assert_eq!(state.selected_endpoint_index(), 1);
        assert_eq!(state.resolved_endpoint(), "https://b.test/");
    }

    #[test]
    fn autosign_window_opens_and_a_zero_window_is_never_within() {
        let mut state = AppState::default();
        assert!(!state.within_autosign());
        state.extend_autosign();
        assert!(state.within_autosign());
        state.autosign_mins = 0;
        state.extend_autosign();
        assert!(
            !state.within_autosign(),
            "a zero-minute window is immediately closed"
        );
    }

    #[test]
    fn hiding_selected_asset_falls_back_to_native() {
        let mut state = AppState::default();
        state.set_asset_visibility(1, true);
        state.select_asset(AssetId::CurrencyCollection(1));
        assert_eq!(state.selected_asset, AssetId::CurrencyCollection(1));

        state.set_asset_visibility(1, false);
        assert_eq!(state.selected_asset, AssetId::Native);
        assert_eq!(state.send_form.token, SendToken::Native);
    }

    #[test]
    fn unknown_currency_is_never_selectable_even_if_visibility_state_is_polluted() {
        let mut state = AppState::default();
        state.visible_cc_assets.insert(u32::MAX);
        state.select_asset(AssetId::CurrencyCollection(u32::MAX));

        assert!(!state.asset_is_visible(AssetId::CurrencyCollection(u32::MAX)));
        assert_eq!(state.selected_asset, AssetId::Native);
        assert_eq!(state.send_form.token, SendToken::Native);
    }

    #[test]
    fn rejects_duplicate_address_when_adding_new_contact() {
        let mut state = AppState::default();
        state
            .save_contact_entry(None, "Alice", ADDRESS_A, "")
            .unwrap();

        let result = state.save_contact_entry(None, "Alice 2", ADDRESS_A, "Friend");

        assert!(result.is_err());
        assert_eq!(state.contacts.len(), 1);
        assert_eq!(state.contacts[0].name, "Alice");
    }

    #[test]
    fn contacts_store_the_same_canonical_address_representation_as_send() {
        let mut state = AppState::default();
        state
            .save_contact_entry(None, "Alice", ADDRESS_A.to_ascii_uppercase(), "")
            .unwrap();
        assert_eq!(state.contacts[0].address, ADDRESS_A);
    }

    #[test]
    fn rejects_duplicate_name_when_adding_new_contact() {
        let mut state = AppState::default();
        state
            .save_contact_entry(None, "Alice", ADDRESS_A, "")
            .unwrap();

        let result = state.save_contact_entry(None, "Alice", ADDRESS_B, "");

        assert!(result.is_err());
        assert_eq!(state.contacts.len(), 1);
        assert_eq!(state.contacts[0].address, ADDRESS_A);
    }

    #[test]
    fn editing_by_index_updates_in_place_even_when_address_changes() {
        let mut state = AppState::default();
        state
            .save_contact_entry(None, "Alice", ADDRESS_A, "")
            .unwrap();
        state
            .save_contact_entry(None, "Bob", ADDRESS_B, "")
            .unwrap();

        state
            .save_contact_entry(Some(0), "Alice", ADDRESS_C, "Friend")
            .unwrap();

        assert_eq!(state.contacts.len(), 2);
        assert_eq!(state.contacts[0].name, "Alice");
        assert_eq!(state.contacts[0].address, ADDRESS_C);
        assert_eq!(state.contacts[0].tag, "Friend");
        assert_eq!(state.contacts[1].name, "Bob");
    }

    #[test]
    fn editing_does_not_conflict_with_its_own_unchanged_name_or_address() {
        let mut state = AppState::default();
        state
            .save_contact_entry(None, "Alice", ADDRESS_A, "")
            .unwrap();

        let result = state.save_contact_entry(Some(0), "Alice", ADDRESS_A, "Friend");

        assert!(result.is_ok());
        assert_eq!(state.contacts[0].tag, "Friend");
    }

    #[test]
    fn editing_rejects_collision_with_another_contacts_address_or_name() {
        let mut state = AppState::default();
        state
            .save_contact_entry(None, "Alice", ADDRESS_A, "")
            .unwrap();
        state
            .save_contact_entry(None, "Bob", ADDRESS_B, "")
            .unwrap();

        assert!(
            state
                .save_contact_entry(Some(1), "Bob", ADDRESS_A, "")
                .is_err()
        );
        assert!(
            state
                .save_contact_entry(Some(1), "Alice", ADDRESS_B, "")
                .is_err()
        );
        assert_eq!(state.contacts[1].name, "Bob");
        assert_eq!(state.contacts[1].address, ADDRESS_B);
    }

    #[test]
    fn reorder_contact_moves_entry_to_target_position() {
        let mut state = AppState::default();
        state
            .save_contact_entry(None, "Alice", ADDRESS_A, "")
            .unwrap();
        state
            .save_contact_entry(None, "Bob", ADDRESS_B, "")
            .unwrap();
        state
            .save_contact_entry(None, "Carol", ADDRESS_C, "")
            .unwrap();

        state.reorder_contact(0, 2);

        let names: Vec<&str> = state.contacts.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["Bob", "Carol", "Alice"]);
    }

    #[test]
    fn send_is_blocked_when_the_wallet_cannot_cover_amount_plus_fee() {
        let mut state = AppState {
            persistence_health: PersistenceHealth::Ready,
            default_endpoint: Some("https://rpc.example/".to_owned()),
            ..AppState::default()
        };
        state.send_form.destination =
            "0:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_owned();
        state.send_form.amount = "1.0".to_owned();
        state.send_form.token = SendToken::Native;

        let wallet = timed_wallet();
        state.wallet = Some(wallet);
        assert!(!state.can_afford_send());
        assert!(!state.send_enabled());
        assert!(state.amount_exceeds_balance());

        state
            .wallet
            .as_mut()
            .unwrap()
            .replace_balances(1_000_000_000, Default::default())
            .unwrap();
        assert!(!state.can_afford_send());
        state.sending = true;
        assert!(
            !state.amount_exceeds_balance(),
            "an in-flight amount is not a second unaffordable form submission"
        );
        state.sending = false;
        assert!(
            state.amount_exceeds_balance(),
            "a retained amount becomes a real retry warning after sending stops"
        );

        let exact_fee = state.effective_send_fee();
        state
            .wallet
            .as_mut()
            .unwrap()
            .replace_balances(1_000_000_000 + exact_fee - 1, Default::default())
            .unwrap();
        assert!(!state.can_afford_send());
        state
            .wallet
            .as_mut()
            .unwrap()
            .replace_balances(1_000_000_000 + exact_fee, Default::default())
            .unwrap();
        assert!(state.can_afford_send());
        assert!(state.send_enabled());
        assert!(!state.amount_exceeds_balance());

        state.default_endpoint = Some("https://another-rpc.example/".to_owned());
        assert!(
            !state.send_enabled(),
            "network time from a different endpoint must not enable authorization"
        );
    }

    #[test]
    fn send_enabled_agrees_with_safety_evaluator() {
        let sendable = || {
            let mut state = AppState {
                persistence_health: PersistenceHealth::Ready,
                default_endpoint: Some("https://rpc.example/".to_owned()),
                ..AppState::default()
            };
            state.send_form.destination =
                "0:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_owned();
            state.send_form.amount = "1.0".to_owned();
            state.send_form.token = SendToken::Native;
            let mut wallet = timed_wallet();
            wallet
                .replace_balances(10_000_000_000, Default::default())
                .unwrap();
            state.wallet = Some(wallet);
            state
        };

        let base = sendable();
        assert!(base.send_safety_block_reason().is_none());
        assert!(base.send_enabled(), "the baseline state is fully sendable");

        type Case = (fn(&mut AppState), SendBlockReason);
        let cases: [Case; 6] = [
            (
                |s| s.persistence_health = PersistenceHealth::Failed,
                SendBlockReason::PersistenceNotReady,
            ),
            (
                |s| s.snapshot_refresh_error = Some("refresh failed".to_owned()),
                SendBlockReason::RefreshInvalid,
            ),
            (
                |s| s.history_integrity_error = Some("history corrupt".to_owned()),
                SendBlockReason::RefreshInvalid,
            ),
            (
                |s| s.network_mismatch = true,
                SendBlockReason::NetworkMismatch,
            ),
            (
                |s| s.default_endpoint = Some("https://other.example/".to_owned()),
                SendBlockReason::NetworkTimeUnavailable,
            ),
            (
                |s| s.journal_blocking = true,
                SendBlockReason::JournalBlocking,
            ),
        ];
        for (apply, reason) in cases {
            let mut state = sendable();
            apply(&mut state);
            assert_eq!(state.send_safety_block_reason(), Some(reason));
            assert!(!state.send_enabled(), "{reason:?} must block send_enabled");
        }
    }

    #[test]
    fn ordinary_send_uses_the_emulated_fee_instead_of_a_one_coin_reserve() {
        let mut state = AppState::default();
        state.send_form.destination =
            "0:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_owned();
        state.send_form.amount = "1.0".to_owned();
        state.fee_estimate = Some(FeeEstimate {
            fee_nanos: 7_491_005,
            deploy: false,
        });
        let mut wallet = timed_wallet();
        wallet
            .replace_balances(1_007_491_005, Default::default())
            .unwrap();
        state.wallet = Some(wallet);

        assert!(
            state.can_afford_send(),
            "1 COIN is affordable from the reported balance when the exact fee fits"
        );
    }

    #[test]
    fn duplicate_risk_action_requires_a_valid_new_transfer_form() {
        let mut state = AppState::default();
        assert!(!state.risk_override_form_ready());

        state.send_form.destination =
            "0:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_owned();
        state.send_form.amount = "1.0".to_owned();
        assert!(state.risk_override_form_ready());

        state.send_form.destination = "not-an-address".to_owned();
        assert!(!state.risk_override_form_ready());
        state.send_form.destination =
            "0:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_owned();
        state.send_form.amount = "0.0".to_owned();
        assert!(!state.risk_override_form_ready());
        state.send_form.amount = "1,0".to_owned();
        assert!(!state.risk_override_form_ready());
    }

    #[test]
    fn clearing_a_send_form_error_restores_the_prior_error_and_status() {
        let mut state = AppState {
            status: "Snapshot unavailable".to_owned(),
            error: Some("The last balance refresh failed".to_owned()),
            ..AppState::default()
        };

        state.set_send_form_error("Enter a valid amount");
        assert_eq!(state.status, "Error");
        assert_eq!(state.error.as_deref(), Some("Enter a valid amount"));

        state.clear_send_form_error();
        assert_eq!(state.status, "Snapshot unavailable");
        assert_eq!(
            state.error.as_deref(),
            Some("The last balance refresh failed")
        );
        assert!(!state.send_form_error);
    }

    #[test]
    fn clearing_a_superseded_send_form_error_keeps_newer_background_state() {
        let mut state = AppState {
            status: "Refresh pending".to_owned(),
            ..AppState::default()
        };
        state.set_send_form_error("Enter a valid amount");

        state.status = "Wallet updated".to_owned();
        state.error = None;
        state.clear_send_form_error();

        assert_eq!(state.status, "Wallet updated");
        assert!(state.error.is_none());
        assert!(!state.send_form_error);
    }

    #[test]
    fn a_cc_send_needs_native_for_the_fee_even_with_enough_cc() {
        let mut state = AppState::default();
        state.send_form.destination =
            "0:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_owned();
        state.send_form.amount = "5.0".to_owned();
        state.send_form.token = SendToken::Cc(1);

        let mut wallet = timed_wallet();
        wallet
            .replace_balances(
                0,
                std::collections::BTreeMap::from([(1, CcAmount::from_u128(10_000_000_000))]),
            )
            .unwrap();
        state.wallet = Some(wallet);
        assert!(!state.can_afford_send());

        let exact_fee = state.effective_send_fee();
        state
            .wallet
            .as_mut()
            .unwrap()
            .replace_balances(
                exact_fee,
                std::collections::BTreeMap::from([(1, CcAmount::from_u128(10_000_000_000))]),
            )
            .unwrap();
        assert!(state.can_afford_send());
    }

    #[test]
    fn reorder_contact_ignores_out_of_range_or_noop_moves() {
        let mut state = AppState::default();
        state
            .save_contact_entry(None, "Alice", ADDRESS_A, "")
            .unwrap();
        state
            .save_contact_entry(None, "Bob", ADDRESS_B, "")
            .unwrap();

        state.reorder_contact(0, 0);
        state.reorder_contact(0, 5);
        state.reorder_contact(5, 0);

        let names: Vec<&str> = state.contacts.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["Alice", "Bob"]);
    }
}
