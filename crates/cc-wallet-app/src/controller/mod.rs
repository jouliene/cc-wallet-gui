mod contacts;
mod endpoints;
mod events;
mod journal;
mod live;
mod risk;
mod save;
mod seed_auth;
mod storage;
mod swap;
#[cfg(test)]
mod tests;
mod wallet_ops;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant, SystemTime};

use cc_wallet_chain::{AccountTrace, ChainService, TychoWalletService};
use cc_wallet_domain::{
    ActivityEvent, Digest32, EndpointAddressInputs, EndpointTransactionEvidence, JournalEnvelope,
    NetworkRegistry, RecordId, Reservation, RiskGrantConsumption, SeedPhrase, SendAuthorization,
    SendRequest, WalletProfile, truncate_comment,
};
use cc_wallet_storage::{
    DEFAULT_WALLET_NAME, InstanceLock, LockOutcome, SelectedCandidate, StartupCwd, VaultStore,
    VaultStoreResult, VaultWriter, WalletListing, WriteReceipt, acquire_single_instance_lock,
    list_wallet_entries,
};
use cc_wallet_vault::{KdfParams, Vault};
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use crate::clipboard::{ClipboardBackend, SystemClipboard};
use crate::command::AppCommand;
use crate::command::Password;
use crate::event::AppEvent;
use crate::state::{
    AppPhase, AppState, AppTab, AuthMode, AuthPurpose, Deadline, PersistenceHealth,
};

const SUBSCRIPTION_BACKOFF_MIN_SECS: u64 = 1;
const SUBSCRIPTION_BACKOFF_MAX_SECS: u64 = 30;

const JOURNAL_RECONCILE_MIN_DELAY: Duration = Duration::from_millis(250);
const JOURNAL_RECONCILE_MAX_DELAY: Duration = Duration::from_secs(30);
const JOURNAL_RECONCILE_POST_EXPIRY_SECS: u64 = cc_wallet_chain::RISK_OVERRIDE_COOLING_SECS;

const NETWORK_STATS_REFRESH: Duration = Duration::from_secs(120);

pub const EXPLORER_TX_LIMIT: u32 = 10;

const TRACE_MEMORY: usize = 16;

const SEED_CLIPBOARD_TTL: Duration = Duration::from_secs(60);

const CLIPBOARD_RETRY_DELAY: Duration = Duration::from_secs(5);
const CLIPBOARD_MAX_RETRIES: u8 = 3;

pub(super) const DEST_CHECK_RETRY_DELAY: Duration = Duration::from_secs(3);
const CLIPBOARD_EXHAUSTED_RETRY_DELAY: Duration = Duration::from_secs(30);

pub(super) const MAX_HISTORY: usize = 1000;

const MAX_AUTOMATIC_HISTORY_CONTINUATIONS: u8 = 1;

pub(super) const HISTORY_MAX_AGE_SECS: u64 = 30 * 24 * 60 * 60;

pub(super) const HISTORY_MIN_KEEP: usize = 10;

const MAX_EVENTS_PER_POLL: usize = 256;

const SUSPEND_MONOTONIC_GAP: Duration = Duration::from_secs(5);
const SUSPEND_WALL_SKEW: Duration = Duration::from_secs(5);

const EMULATION_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

pub(super) fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SecuritySetting {
    AutoSign(u8),
    ScreenLock(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyAction {
    Unlock,
    Create,
    ConfirmSend {
        remember: bool,
        auth_generation: u64,
        auth_nonce: u64,
    },
    ConfirmSwap {
        remember: bool,
        generation: u64,
    },
    ConfirmStorage {
        remember: bool,
        generation: u64,
    },
    RevealRecords,
    VerifyForChangePassword,
    ChangePassword,
    RevealSeed,
    DeleteWallet,
    ApplySecuritySetting(SecuritySetting),
    DeleteWalletFromPicker,
}

impl KeyAction {
    fn is_reauth(&self) -> bool {
        matches!(
            self,
            Self::ConfirmSend { .. }
                | Self::ConfirmSwap { .. }
                | Self::ConfirmStorage { .. }
                | Self::RevealRecords
                | Self::VerifyForChangePassword
                | Self::RevealSeed
                | Self::DeleteWallet
                | Self::ApplySecuritySetting(_)
        )
    }
}

struct PickerDeleteTarget {
    name: String,
    storage_id: String,
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum KeyMsg {
    Ok {
        generation: u64,
        action: KeyAction,
        vault: Vault,
        profile: WalletProfile,
        history: Vec<ActivityEvent>,
        history_corrupt: bool,
        journal: JournalEnvelope,
        selected: Option<SelectedCandidate>,
        writer: Option<VaultWriter>,
    },
    Verified {
        generation: u64,
        action: KeyAction,
    },
    WrongPassword {
        generation: u64,
        action: KeyAction,
    },
    Failed {
        generation: u64,
        action: KeyAction,
        error: String,
    },
}

struct AppEntry {
    profile: WalletProfile,
    history: Vec<ActivityEvent>,
    history_corrupt: bool,
    journal: JournalEnvelope,
    selected: Option<SelectedCandidate>,
    writer: VaultWriter,
}

struct PendingRiskReview {
    authorization: SendAuthorization,
    blocker_digest: Digest32,
    reservation_digest: Digest32,
    reservations: Vec<Reservation>,
    broad_duplicate: bool,
}

#[derive(Clone)]
struct PendingRiskConsumption {
    consumption: RiskGrantConsumption,
    overlap: Vec<Reservation>,
}

struct HistoryReconciliationScan {
    next_before_lt: u64,
    stop_at: Option<u64>,
    age_cutoff: Option<u64>,
    deepest_lt: Option<u64>,
    observations: Vec<EndpointTransactionEvidence>,
    automatic_continuations_remaining: u8,
}

#[derive(Default)]
struct LoadRuntime {
    wallet_load_id: Option<u64>,
    wallet_auto_refresh_id: Option<u64>,
    wallet_auto_refresh_again: bool,
    history_reconciliation_scan: Option<HistoryReconciliationScan>,
    fetch_in_flight: bool,
    fetch_in_flight_id: Option<u64>,
    fetch_again: bool,
    fetch_head_after_history_scan: bool,
}

#[derive(Default)]
struct SessionRuntime {
    pending_sends: Vec<(u64, Option<Instant>)>,
    pending_swaps: Vec<(Digest32, Instant)>,
    awaiting_send_lt: Option<u64>,
    in_flight_record_id: Option<RecordId>,
    dest_check_task: Option<tokio::task::JoinHandle<()>>,
    dest_check_retry_at: Option<Deadline>,
    risk_cooling_started_at: Option<Instant>,
    journal_reconcile_floor: Option<u64>,
    journal_reconcile_time_floor: Option<u64>,
    history_synced_floor: Option<u64>,
    history_has_gap: bool,
    fee_reestimate_at: Option<Instant>,
    activity_quarantine_pending: Option<SelectedCandidate>,
}

struct PendingLock {
    deadline: Instant,
    follow_up: LockFollowUp,
}

enum LockFollowUp {
    None,
    Picker,
    SwitchTo(String),
    DeleteWallet,
}

impl KeyMsg {
    fn generation(&self) -> u64 {
        match self {
            KeyMsg::Ok { generation, .. }
            | KeyMsg::Verified { generation, .. }
            | KeyMsg::WrongPassword { generation, .. }
            | KeyMsg::Failed { generation, .. } => *generation,
        }
    }
}

pub struct AppController {
    state: AppState,
    data_dir: PathBuf,
    networks: NetworkRegistry,
    wallet_entries: Vec<WalletListing>,
    store: VaultStore,
    vault: Option<Arc<Vault>>,
    writer: Option<VaultWriter>,
    kdf_params: KdfParams,
    chain: Arc<dyn ChainService>,
    runtime: Runtime,
    tx: Sender<AppEvent>,
    rx: Receiver<AppEvent>,
    key_tx: Sender<KeyMsg>,
    key_rx: Receiver<KeyMsg>,
    key_generation: u64,
    auth_generation: u64,
    pending_authorization: Option<SendAuthorization>,
    pending_swap: Option<swap::PendingSwap>,
    swap_in_flight: Option<swap::SwapIntent>,
    swap_pool_seq: u64,
    pending_storage: Option<storage::PendingStorage>,
    storage_seq: u64,
    storage_watch: Option<storage::StorageWatch>,
    pending_security_setting: Option<SecuritySetting>,
    pending_picker_delete: Option<PickerDeleteTarget>,
    pending_risk_reconciliation: bool,
    pending_risk_context: Option<Digest32>,
    pending_risk_review: Option<PendingRiskReview>,
    pending_risk_consumption: Option<PendingRiskConsumption>,
    subscription_task: Option<JoinHandle<()>>,
    subscription_key: Option<String>,
    subscription_generation: u64,
    session_generation: u64,
    subscription_addr: Option<String>,
    subscription_retry_at: Option<Instant>,
    subscription_backoff_secs: u64,
    wallet_load_seq: u64,
    load: LoadRuntime,
    session: SessionRuntime,
    pending_teardown: Option<PendingLock>,
    clipboard: Box<dyn ClipboardBackend>,
    clipboard_secret: Option<Zeroizing<String>>,
    clipboard_deadline: Option<Deadline>,
    clipboard_retries: u8,
    clipboard_copy_explicit: bool,
    pending_seq: u64,
    last_tick: Option<(Instant, SystemTime)>,
    journal_reconcile_at: Option<Instant>,
    journal_reconcile_delay: Duration,
    endpoint_test_url: Option<String>,
    fee_request_seq: u64,
    dest_check_seq: u64,
    clock_fetch_seq: u64,
    clock_refresh_at: Option<Deadline>,
    stats_fetch_seq: u64,
    stats_refresh_at: Option<Deadline>,
    account_fetch_seq: u64,
    trace_fetch_seq: u64,
    pending_explorer_trace: Option<String>,
    trace_cache: Vec<(String, AccountTrace)>,
    pending_max_seq: Option<u64>,
    queued_max_request: Option<SendRequest>,
    pending_max_balance: Option<u128>,
    max_filled: bool,
    last_activity: Instant,
    last_activity_wall: SystemTime,
    _instance_lock: Option<InstanceLock>,
    dirty: bool,
    save_deadline: Option<Instant>,
    save_task: Option<JoinHandle<(VaultWriter, VaultStoreResult<WriteReceipt>)>>,
    activity_payload_cache: Option<(u64, Option<Vec<u8>>)>,
    #[cfg(test)]
    activity_encode_count: std::cell::Cell<u64>,
    fetch_seq: u64,
    journal: JournalEnvelope,
}

impl AppController {
    pub fn from_startup_cwd(startup_cwd: StartupCwd) -> Result<Self, String> {
        let requested_root = startup_cwd.into_path();
        let lock = match acquire_single_instance_lock(&requested_root).map_err(|error| {
            format!(
                "Cannot acquire the mandatory wallet lock for {}: {error}",
                requested_root.display()
            )
        })? {
            LockOutcome::Acquired(lock) => lock,
            LockOutcome::AlreadyRunning => {
                return Err(format!(
                    "CC Wallet is already running for {}.",
                    requested_root.display()
                ));
            }
        };
        let data_dir = lock.root().to_path_buf();
        if data_dir != requested_root {
            return Err(
                "The launch folder changed while CC Wallet was starting; close it and start it again"
                    .to_owned(),
            );
        }
        lock.probe_storage_root().map_err(|error| {
            format!("The launch folder cannot safely store wallet files: {error}")
        })?;
        let mut me = Self::at_root(data_dir, test_kdf_override().unwrap_or(KdfParams::DEFAULT))?;
        me._instance_lock = Some(lock);
        Ok(me)
    }

    #[cfg(test)]
    pub(crate) fn at_dir(dir: impl Into<PathBuf>, kdf_params: KdfParams) -> Result<Self, String> {
        let dir = dir.into();
        if !dir.is_absolute() {
            return Err(format!(
                "test wallet root must be absolute: {}",
                dir.display()
            ));
        }
        let metadata = std::fs::symlink_metadata(&dir).map_err(|error| {
            format!(
                "test wallet root must already exist at {}: {error}",
                dir.display()
            )
        })?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(format!(
                "test wallet root must be a real directory: {}",
                dir.display()
            ));
        }
        Self::at_root(dir, kdf_params)
    }

    fn at_root(data_dir: PathBuf, kdf_params: KdfParams) -> Result<Self, String> {
        let runtime =
            Runtime::new().map_err(|error| format!("failed to create runtime: {error}"))?;
        let (tx, rx) = mpsc::channel();
        let (key_tx, key_rx) = mpsc::channel();
        let networks = NetworkRegistry::defaults();
        let wallet_entries = wallet_entries_in(&data_dir).map_err(|error| {
            format!("Could not list wallet files in the launch folder: {error}")
        })?;
        let first = wallet_entries
            .first()
            .map(|entry| entry.storage_id.clone())
            .unwrap_or_else(|| DEFAULT_WALLET_NAME.to_owned());
        let store = VaultStore::new(data_dir.clone(), first);
        let (phase, status) = if wallet_entries.is_empty() {
            (AppPhase::Onboarding, "Create your first wallet")
        } else {
            (AppPhase::Selecting, "Choose a wallet")
        };
        let state = AppState {
            phase,
            status: status.to_owned(),
            wallet_names: wallet_entries
                .iter()
                .map(|entry| entry.display_name.clone())
                .collect(),
            ..AppState::default()
        };
        Ok(Self {
            state,
            data_dir,
            networks,
            wallet_entries,
            store,
            vault: None,
            writer: None,
            kdf_params,
            chain: Arc::new(TychoWalletService::default()),
            runtime,
            tx,
            rx,
            key_tx,
            key_rx,
            key_generation: 0,
            auth_generation: 0,
            pending_authorization: None,
            pending_swap: None,
            swap_in_flight: None,
            swap_pool_seq: 0,
            pending_storage: None,
            storage_seq: 0,
            storage_watch: None,
            pending_security_setting: None,
            pending_picker_delete: None,
            pending_risk_reconciliation: false,
            pending_risk_context: None,
            pending_risk_review: None,
            pending_risk_consumption: None,
            subscription_task: None,
            subscription_key: None,
            subscription_generation: 0,
            session_generation: 0,
            subscription_addr: None,
            subscription_retry_at: None,
            subscription_backoff_secs: SUBSCRIPTION_BACKOFF_MIN_SECS,
            wallet_load_seq: 0,
            load: LoadRuntime::default(),
            session: SessionRuntime::default(),
            pending_teardown: None,
            clipboard: Box::new(SystemClipboard),
            clipboard_secret: None,
            clipboard_deadline: None,
            clipboard_retries: 0,
            clipboard_copy_explicit: false,
            pending_seq: 0,
            last_tick: None,
            journal_reconcile_at: None,
            journal_reconcile_delay: JOURNAL_RECONCILE_MIN_DELAY,
            endpoint_test_url: None,
            fee_request_seq: 0,
            dest_check_seq: 0,
            clock_fetch_seq: 0,
            clock_refresh_at: None,
            stats_fetch_seq: 0,
            stats_refresh_at: None,
            account_fetch_seq: 0,
            trace_fetch_seq: 0,
            pending_explorer_trace: None,
            trace_cache: Vec::new(),
            pending_max_seq: None,
            queued_max_request: None,
            pending_max_balance: None,
            max_filled: false,
            last_activity: Instant::now(),
            last_activity_wall: SystemTime::now(),
            _instance_lock: None,
            dirty: false,
            save_deadline: None,
            save_task: None,
            activity_payload_cache: None,
            #[cfg(test)]
            activity_encode_count: std::cell::Cell::new(0),
            fetch_seq: 0,
            journal: JournalEnvelope::empty(),
        })
    }

    pub fn state(&self) -> &AppState {
        &self.state
    }

    pub fn send_form_locked(&self) -> bool {
        self.pending_authorization.is_some() || self.state.sending
    }

    #[cfg(test)]
    pub(crate) fn state_mut(&mut self) -> &mut AppState {
        &mut self.state
    }

    #[cfg(test)]
    pub(crate) fn key_generation(&self) -> u64 {
        self.key_generation
    }

    fn bump_activity(&mut self) {
        self.last_activity = Instant::now();
        self.last_activity_wall = SystemTime::now();
    }

    pub fn note_activity(&mut self) {
        self.bump_activity();
    }

    pub fn surface_error(&mut self, message: String) {
        if self.state.phase == AppPhase::Unlocked {
            self.state.set_error(message);
        } else {
            self.state.lock_error = message;
        }
    }

    fn schedule_fee_reestimate(&mut self) {
        self.clear_pending_max();
        self.state.fee_estimate_stale = true;
        self.session.fee_reestimate_at = Some(Instant::now() + Duration::from_millis(600));
    }

    pub(super) fn clear_pending_max(&mut self) {
        self.pending_max_seq = None;
        self.queued_max_request = None;
        self.pending_max_balance = None;
        self.state.max_refining = false;
    }

    fn invalidate_key_ops(&mut self) {
        self.key_generation = self.key_generation.wrapping_add(1);
        self.state.key_busy = false;
        self.pending_authorization = None;
        self.pending_risk_reconciliation = false;
        self.pending_risk_context = None;
        self.pending_risk_review = None;
        self.pending_risk_consumption = None;
    }

    pub fn handle_command(&mut self, command: AppCommand) {
        self.bump_activity();

        if self.pending_teardown.is_some() {
            if matches!(command, AppCommand::ClearError) {
                self.state.lock_error.clear();
                self.state.error = None;
            }
            return;
        }

        if self.state.phase != AppPhase::Unlocked {
            match command {
                AppCommand::Init => self.probe_phase(),
                AppCommand::SelectWallet(name) => self.select_wallet(name),
                AppCommand::NewWalletRequest => self.new_wallet_request(),
                AppCommand::DeleteWalletFromPicker { name, pw } => {
                    self.delete_wallet_from_picker(name, pw)
                }
                AppCommand::BackToPicker => self.probe_phase(),
                AppCommand::CreateWallet {
                    name,
                    network_id,
                    workchain,
                    pw,
                    pw2,
                } => self.create_wallet(name, network_id, workchain, pw, pw2),
                AppCommand::Unlock(pw) => self.unlock(pw),
                AppCommand::GenerateSeed => self.generate_seed(),
                AppCommand::OnboardImportSeed(seed) => self.onboard_import_seed(seed),
                AppCommand::SetSeedBackupConfirmed(v) => self.state.seed_backup_confirmed = v,
                AppCommand::CopySeed(phrase) => self.copy_seed_to_clipboard(phrase),
                AppCommand::ClearError => {
                    self.state.lock_error.clear();
                    self.state.error = None;
                }
                _ => {}
            }
            return;
        }

        if self.state.show_seed
            && !matches!(
                command,
                AppCommand::RevealSeed | AppCommand::HideSeed | AppCommand::CopySeed(_)
            )
        {
            self.hide_seed();
        }
        if let AppCommand::SetAllowUnbounced(allow) = &command
            && self.update_pending_send_unbounced(*allow)
        {
            return;
        }
        if matches!(command, AppCommand::SetAllowUnbounced(_))
            && self.state.auth.open
            && self.state.auth.purpose == AuthPurpose::Send
            && self.pending_authorization.is_some()
        {
            return;
        }
        if (self.pending_authorization.is_some()
            || self.pending_risk_review.is_some()
            || self.state.sending)
            && command.frozen_while_authorization_pending()
        {
            let message = "Transfer controls are locked to the authorization snapshot";
            self.state.auth.error = message.to_owned();
            self.state.set_error(message);
            return;
        }
        if self.state.journal_blocking && command.changes_wallet_identity_or_endpoint() {
            self.state.set_error(
                "The wallet identity cannot change and the prepared endpoint cannot be replaced while this send journal has unresolved records; switch to a different vault instead",
            );
            return;
        }
        match command {
            AppCommand::Init
            | AppCommand::SelectWallet(_)
            | AppCommand::NewWalletRequest
            | AppCommand::DeleteWalletFromPicker { .. }
            | AppCommand::BackToPicker
            | AppCommand::CreateWallet { .. }
            | AppCommand::OnboardImportSeed(_)
            | AppCommand::SetSeedBackupConfirmed(_)
            | AppCommand::Unlock(_) => {}
            AppCommand::LockNow => {
                self.lock();
            }
            AppCommand::SwitchWallet => self.switch_wallet(),
            AppCommand::SwitchToWallet(name) => self.switch_to_wallet(name),
            AppCommand::DeleteWallet => self.delete_wallet(),
            AppCommand::SelectTab(tab) => {
                if self.state.selected_tab == AppTab::Storage && tab != AppTab::Storage {
                    self.hide_storage_records();
                }
                self.state.selected_tab = tab;
                if tab == AppTab::Explorer {
                    self.clock_refresh_at = None;
                    self.stats_refresh_at = None;
                }
                if tab == AppTab::Swap {
                    self.on_swap_tab_opened();
                }
                if tab == AppTab::Storage {
                    self.on_storage_tab_opened();
                }
            }
            AppCommand::GenerateSeed => self.generate_seed(),
            AppCommand::SaveSeed(seed) => self.save_seed(seed),
            AppCommand::ImportSeed(seed) => self.save_seed(seed),
            AppCommand::UseSeed => self.use_seed(),
            AppCommand::DiscardSeed => self.discard_seed(),
            AppCommand::RevealSeed => self.reveal_seed(),
            AppCommand::HideSeed => self.hide_seed(),
            AppCommand::CopySeed(phrase) => self.copy_seed_to_clipboard(phrase),
            AppCommand::CopyText(text) => self.copy_text(&text),
            AppCommand::RefreshWallet => self.manual_refresh_wallet(),
            AppCommand::SaveContact {
                index,
                name,
                address,
                tag,
            } => self.save_contact(index, name, address, tag),
            AppCommand::DeleteContact(index) => self.delete_contact(index),
            AppCommand::ReorderContacts { from, to } => self.reorder_contacts(from, to),
            AppCommand::QuickSend(address) => {
                self.state.clear_send_form_error();
                self.quick_send(address);
                self.state.reset_recipient_status();
                self.schedule_fee_reestimate();
            }
            AppCommand::SetAssetVisibility { cc_id, visible } => {
                let asset_before = self.state.selected_asset;
                self.state.set_asset_visibility(cc_id, visible);
                if self.state.selected_asset != asset_before {
                    self.max_filled = false;
                }
                self.save_profile();
            }
            AppCommand::SelectAsset(asset) => {
                self.state.clear_send_form_error();
                self.state.select_asset(asset);
                self.max_filled = false;
                self.schedule_fee_reestimate();
            }
            AppCommand::SetSendDestination(destination) => {
                self.state.clear_send_form_error();
                self.state.send_form.destination = destination;
                self.state.reset_recipient_status();
                self.schedule_fee_reestimate();
            }
            AppCommand::SetSendAmount(amount) => {
                self.state.clear_send_form_error();
                self.state.send_form.amount = amount;
                self.max_filled = false;
                self.schedule_fee_reestimate();
            }
            AppCommand::SetSendComment(comment) => {
                self.state.clear_send_form_error();
                self.state.send_form.comment = truncate_comment(&comment).to_owned();
                self.schedule_fee_reestimate();
            }
            AppCommand::SetMaxAmount => self.set_max_amount(),
            AppCommand::SetAllowUnbounced(allow) => self.state.allow_unbounced = allow,
            AppCommand::RequestSend => self.request_send(),
            AppCommand::SetSwapFromToken(asset) => self.set_swap_from_token(asset),
            AppCommand::SetSwapToToken(asset) => self.set_swap_to_token(asset),
            AppCommand::SetSwapAmount(amount) => self.set_swap_amount(amount),
            AppCommand::SetMaxSwapAmount => self.set_max_swap_amount(),
            AppCommand::SetSwapSlippage(bps) => self.set_swap_slippage(bps),
            AppCommand::StepSwapSlippage(up) => self.step_swap_slippage(up),
            AppCommand::EditSwapSlippage(text) => self.edit_swap_slippage(text),
            AppCommand::DismissSwapReceipt => self.state.swap.receipt = None,
            AppCommand::FlipSwap => self.flip_swap(),
            AppCommand::RequestSwap => self.request_swap(),
            AppCommand::RefreshStorage => self.refresh_storage(),
            AppCommand::CreateStorage => self.create_storage(),
            AppCommand::SetStorageTitle(title) => self.set_storage_title(title),
            AppCommand::SetStorageData(data) => self.set_storage_data(data),
            AppCommand::AddStorageRecord => self.add_storage_record(),
            AppCommand::ClearStorageForm => self.clear_storage_form(),
            AppCommand::RevealStorageRecords => self.reveal_storage_records(),
            AppCommand::HideStorageRecords => self.hide_storage_records(),
            AppCommand::DeleteStorageRecord(id) => self.delete_storage_record(id),
            AppCommand::CopyStorageRecord(id) => self.copy_storage_record(id),
            AppCommand::RequestRiskOverride => self.request_risk_override(),
            AppCommand::SetRiskOverlap { index, selected } => {
                self.set_risk_overlap(index, selected)
            }
            AppCommand::ConfirmRiskOverride {
                typed_confirmation,
                acknowledge_both_may_debit,
                acknowledge_duplicate,
            } => self.confirm_risk_override(
                typed_confirmation,
                acknowledge_both_may_debit,
                acknowledge_duplicate,
            ),
            AppCommand::CancelRiskOverride => self.cancel_risk_override(),
            AppCommand::ChangePasswordRequest => self.change_password_request(),
            AppCommand::AuthSubmit { pw, pw2, remember } => self.auth_submit(pw, pw2, remember),
            AppCommand::AuthCancel => self.cancel_auth(),
            AppCommand::SetAutosign(mins) => {
                self.request_security_setting(SecuritySetting::AutoSign(mins))
            }
            AppCommand::SetScreenLock(mins) => {
                self.request_security_setting(SecuritySetting::ScreenLock(mins))
            }
            AppCommand::InspectAccount(address) => self.inspect_account(address),
            AppCommand::OpenInExplorer {
                address,
                transaction_hash,
            } => self.open_in_explorer(address, transaction_hash),
            AppCommand::TraceTransaction(hash) => self.trace_transaction(hash),
            AppCommand::CloseTrace => self.close_trace(),
            AppCommand::AddEndpoint(url) => self.add_endpoint(url),
            AppCommand::SelectEndpoint(index) => self.select_endpoint(index),
            AppCommand::RemoveEndpoint(url) => self.remove_endpoint(url),
            AppCommand::TestEndpoint(url) => self.test_endpoint(url),
            AppCommand::ClearError => self.state.clear_error(),
        }
    }

    fn probe_phase(&mut self) {
        self.invalidate_key_ops();
        self.clear_seed_from_clipboard();
        self.clear_staged_onboarding_seed();
        self.state.lock_error.clear();
        let entries = match wallet_entries_in(&self.data_dir) {
            Ok(entries) => entries,
            Err(error) => {
                self.state
                    .set_error(format!("Could not list wallet files: {error}"));
                return;
            }
        };
        self.state.wallet_names = entries
            .iter()
            .map(|entry| entry.display_name.clone())
            .collect();
        self.wallet_entries = entries;
        self.state.phase = if self.wallet_entries.is_empty() {
            self.state.status = "Create your first wallet".to_owned();
            AppPhase::Onboarding
        } else {
            self.state.status = "Choose a wallet".to_owned();
            AppPhase::Selecting
        };
    }

    fn select_wallet(&mut self, name: String) {
        let Some(storage_id) = self
            .wallet_entries
            .iter()
            .find(|entry| entry.display_name == name)
            .map(|entry| entry.storage_id.clone())
        else {
            return;
        };
        self.invalidate_key_ops();
        self.store = VaultStore::new(self.data_dir.clone(), storage_id);
        self.state.active_wallet = name;
        self.state.lock_error.clear();
        self.state.phase = AppPhase::Locked;
        self.state.status = "Locked".to_owned();
    }

    fn delete_wallet_from_picker(&mut self, name: String, pw: Password) {
        let Some(storage_id) = self
            .wallet_entries
            .iter()
            .find(|entry| entry.display_name == name)
            .map(|entry| entry.storage_id.clone())
        else {
            return;
        };
        if pw.is_empty() {
            self.state.lock_error = "Enter this wallet's password to delete it".to_owned();
            return;
        }
        if self.state.key_busy {
            return;
        }
        self.state.key_busy = true;
        self.state.lock_error.clear();
        let store = VaultStore::new(self.data_dir.clone(), storage_id.clone());
        self.pending_picker_delete = Some(PickerDeleteTarget { name, storage_id });
        self.spawn_unlock_store(store, pw, KeyAction::DeleteWalletFromPicker);
    }

    fn finish_picker_delete(&mut self) {
        let Some(target) = self.pending_picker_delete.take() else {
            return;
        };
        self.invalidate_key_ops();
        let destroyed = VaultStore::new(self.data_dir.clone(), target.storage_id.clone()).destroy();
        let deleted = match destroyed {
            Ok(_) => true,
            Err(error) => {
                self.state.set_error(format!(
                    "The wallet \"{}\" could not be deleted and may still hold its seed: {error}",
                    target.name
                ));
                false
            }
        };
        self.probe_phase();
        if self.store.name() == target.storage_id {
            let first = self
                .wallet_entries
                .first()
                .map(|entry| entry.storage_id.clone())
                .unwrap_or_else(|| DEFAULT_WALLET_NAME.to_owned());
            self.store = VaultStore::new(self.data_dir.clone(), first);
        }
        if deleted && !self.wallet_entries.is_empty() {
            self.state.status = format!("Wallet \"{}\" deleted", target.name);
        }
    }

    fn clear_staged_onboarding_seed(&mut self) {
        self.state.seed = SeedPhrase::empty_shared();
        self.state.confirmed_seed = SeedPhrase::empty_shared();
        self.state.seed_saved = false;
        self.state.seed_editing = false;
        self.state.seed_unsaved = false;
        self.state.show_seed = false;
        self.state.seed_reveal_deadline = None;
        self.state.onboard_import_valid = false;
        self.state.seed_backup_confirmed = false;
    }

    fn new_wallet_request(&mut self) {
        self.invalidate_key_ops();
        self.clear_seed_from_clipboard();
        self.state.lock_error.clear();
        self.state.active_wallet = String::new();
        self.clear_staged_onboarding_seed();
        self.state.phase = AppPhase::Onboarding;
        self.state.status = "Create a new wallet".to_owned();
    }

    fn create_wallet(
        &mut self,
        name: String,
        network_id: i32,
        workchain: i8,
        pw: Password,
        pw2: Password,
    ) {
        let display_name = sanitize_wallet_name(&name);
        if display_name.is_empty() {
            self.state.lock_error = "Enter a wallet name".to_owned();
            return;
        }
        let storage_id = wallet_storage_id(&display_name);
        if storage_id.is_empty() || is_reserved_wallet_name(&storage_id) {
            self.state.lock_error = "Pick a different wallet name".to_owned();
            return;
        }
        let entries = match wallet_entries_in(&self.data_dir) {
            Ok(entries) => entries,
            Err(error) => {
                self.state.lock_error = format!("Could not list wallet files: {error}");
                return;
            }
        };
        if entries.iter().any(|entry| entry.storage_id == storage_id) {
            self.state.lock_error = format!(
                "A wallet using the file name \"{storage_id}.{}\" already exists",
                cc_wallet_storage::WALLET_EXT
            );
            return;
        }
        let target = VaultStore::new(self.data_dir.clone(), storage_id.clone());
        let exists = match target.exists() {
            Ok(exists) => exists,
            Err(error) => {
                self.state.lock_error = format!("Could not inspect the wallet file: {error}");
                return;
            }
        };
        if exists {
            self.state.lock_error = format!(
                "A wallet using the file name \"{storage_id}.{}\" already exists",
                cc_wallet_storage::WALLET_EXT
            );
            return;
        }
        if self.networks.get(network_id).is_none() {
            self.state.lock_error = "Choose a known network".to_owned();
            return;
        }
        if cc_wallet_domain::validate_workchain(workchain).is_err() {
            self.state.lock_error = "Workchain must be 0 or -1".to_owned();
            return;
        }
        if !crate::seed_phrase_is_valid(self.state.seed.expose_secret()) {
            self.state.lock_error = "Generate or import a recovery phrase first".to_owned();
            return;
        }
        if !self.state.seed_backup_confirmed {
            self.state.lock_error =
                "Confirm you have safely saved your recovery phrase first".to_owned();
            return;
        }
        self.store = VaultStore::new(self.data_dir.clone(), storage_id);
        self.state.active_wallet = display_name;
        self.state.network_id = network_id;
        self.state.workchain = workchain;
        self.state.custom_endpoints.clear();
        self.state.selected_endpoint = 0;
        self.refresh_network_view();
        self.state.confirmed_seed = Arc::clone(&self.state.seed);
        self.state.seed_saved = true;
        self.state.seed_unsaved = false;
        self.create_password(pw, pw2);
    }

    fn switch_wallet(&mut self) {
        self.request_lock(LockFollowUp::Picker);
    }

    fn switch_to_wallet(&mut self, name: String) {
        if name == self.state.active_wallet {
            return;
        }
        let entries = match wallet_entries_in(&self.data_dir) {
            Ok(entries) => entries,
            Err(error) => {
                self.state
                    .set_error(format!("Could not list wallet files: {error}"));
                return;
            }
        };
        if !entries.iter().any(|entry| entry.display_name == name) {
            return;
        }
        self.request_lock(LockFollowUp::SwitchTo(name));
    }

    fn delete_wallet(&mut self) {
        use crate::state::AuthModal;
        self.state.auth = AuthModal {
            open: true,
            mode: AuthMode::Enter,
            purpose: AuthPurpose::DeleteWallet,
            send_options_editable: false,
            error: String::new(),
        };
    }

    pub(crate) fn do_delete_wallet(&mut self) {
        if !self.drain_save_task() {
            return;
        }
        self.dirty = false;
        self.save_deadline = None;
        self.request_lock(LockFollowUp::DeleteWallet);
    }

    fn on_resume_from_suspend(&mut self) {
        if self.state.journal_blocking {
            self.session.risk_cooling_started_at = Some(Instant::now());
            self.state.risk_override_eligible = false;
        }
        if self.state.phase == AppPhase::Unlocked && self.state.journal_blocking {
            self.expedite_journal_reconciliation();
            self.fetch_transactions(self.subscription_generation);
        }
    }

    pub fn tick(&mut self) {
        let now_mono = Instant::now();
        let now_wall = SystemTime::now();
        let suspended = self.last_tick.is_some_and(|(prev_mono, prev_wall)| {
            let mono_delta = now_mono.saturating_duration_since(prev_mono);
            let wall_delta = now_wall.duration_since(prev_wall).unwrap_or_default();
            mono_delta >= SUSPEND_MONOTONIC_GAP
                || wall_delta.saturating_sub(mono_delta) >= SUSPEND_WALL_SKEW
        });
        self.last_tick = Some((now_mono, now_wall));
        if let Some(deadline) = self.pending_teardown.as_ref().map(|p| p.deadline) {
            if self.chain.drain_emulation_jobs(Duration::ZERO) {
                let follow_up = self
                    .pending_teardown
                    .take()
                    .map(|pending| pending.follow_up)
                    .unwrap_or(LockFollowUp::None);
                self.finish_lock();
                self.run_lock_follow_up(follow_up);
            } else if now_mono >= deadline {
                self.pending_teardown = None;
                self.chain.unseal_key_ops();
                self.state.busy = false;
                self.state.set_error(
                    "A bounded fee-emulation worker did not stop in time; the wallet remains open",
                );
            }
            return;
        }
        if suspended {
            self.on_resume_from_suspend();
        }
        self.poll_storage_settlement();
        self.expire_record_reveal();
        if let Some(deadline) = self.clipboard_deadline
            && deadline.expired()
        {
            self.clear_seed_from_clipboard();
        }
        if self.state.phase == AppPhase::Unlocked && self.state.screen_lock_mins > 0 {
            let idle = Duration::from_secs(u64::from(self.state.screen_lock_mins) * 60);
            let mono_idle = self.last_activity.elapsed() >= idle;
            let wall_idle = now_wall
                .duration_since(self.last_activity_wall)
                .unwrap_or_default()
                >= idle;
            if mono_idle || wall_idle {
                self.lock();
                return;
            }
        }
        if let Some(deadline) = self.state.autosign_until
            && deadline.expired()
        {
            self.state.autosign_until = None;
            if self.state.auth.open
                && self.state.auth.mode == AuthMode::Confirm
                && self.state.auth.purpose == AuthPurpose::Send
            {
                self.state.auth.mode = AuthMode::Enter;
                self.state.auth.error =
                    "Auto-sign expired — enter your password to confirm".to_owned();
            }
        }
        if let Some(deadline) = self.state.seed_reveal_deadline
            && deadline.expired()
        {
            self.hide_seed();
        }
        if self.state.auth.open && self.state.auth.purpose == AuthPurpose::Send {
            match self.state.recipient_check {
                crate::state::RecipientCheck::Unchecked => {
                    self.check_destination();
                    if !matches!(
                        self.state.recipient_check,
                        crate::state::RecipientCheck::Pending
                    ) {
                        self.state.recipient_check = crate::state::RecipientCheck::Failed;
                        self.session.dest_check_retry_at =
                            Some(crate::state::Deadline::after(DEST_CHECK_RETRY_DELAY));
                    }
                }
                crate::state::RecipientCheck::Failed => match self.session.dest_check_retry_at {
                    Some(deadline) if deadline.expired() => {
                        self.session.dest_check_retry_at = None;
                        self.check_destination();
                        if !matches!(
                            self.state.recipient_check,
                            crate::state::RecipientCheck::Pending
                        ) {
                            self.session.dest_check_retry_at =
                                Some(crate::state::Deadline::after(DEST_CHECK_RETRY_DELAY));
                        }
                    }
                    Some(_) => {}
                    None => {
                        self.session.dest_check_retry_at =
                            Some(crate::state::Deadline::after(DEST_CHECK_RETRY_DELAY));
                    }
                },
                _ => {}
            }
        }
        self.refresh_seed_copy_ttl();
        if self.state.phase == AppPhase::Unlocked
            && !self.state.fee_estimating
            && let Some(deadline) = self.session.fee_reestimate_at
            && Instant::now() >= deadline
        {
            self.session.fee_reestimate_at = None;
            if self.state.send_form.request().is_ok() {
                self.estimate_fee();
            }
        }
        if self.dirty
            && let Some(deadline) = self.save_deadline
            && Instant::now() >= deadline
        {
            self.flush_save();
        }
        if self
            .save_task
            .as_ref()
            .is_some_and(tokio::task::JoinHandle::is_finished)
        {
            self.drain_save_task();
        }
        if self.state.phase == AppPhase::Unlocked
            && self
                .subscription_task
                .as_ref()
                .is_none_or(|t| t.is_finished())
            && let Some(retry_at) = self.subscription_retry_at
            && Instant::now() >= retry_at
            && let Some(addr) = self.subscription_addr.clone()
        {
            self.subscription_retry_at = None;
            self.ensure_subscription(addr);
        }
        if self.state.phase == AppPhase::Unlocked {
            self.refresh_journal_policy();
            self.poll_journal_reconciliation(now_mono);
        }
        if self.state.phase == AppPhase::Unlocked
            && self.state.selected_tab == AppTab::Explorer
            && self
                .clock_refresh_at
                .is_none_or(|deadline| deadline.expired())
        {
            self.clock_refresh_at = Some(Deadline::after(Duration::from_secs(30)));
            self.refresh_validator_clock();
        }
        if self.state.phase == AppPhase::Unlocked
            && self.state.selected_tab == AppTab::Explorer
            && self
                .stats_refresh_at
                .is_none_or(|deadline| deadline.expired())
        {
            self.stats_refresh_at = Some(Deadline::after(NETWORK_STATS_REFRESH));
            self.refresh_network_stats();
        }
    }

    fn refresh_validator_clock(&mut self) {
        let endpoint = self.current_endpoint();
        if endpoint.is_empty() {
            return;
        }
        let generation = self.subscription_generation;
        self.clock_fetch_seq = self.clock_fetch_seq.wrapping_add(1);
        let seq = self.clock_fetch_seq;
        let tx = self.tx.clone();
        let chain = self.chain.clone();
        self.runtime.spawn(async move {
            let cycle =
                tokio::time::timeout(Duration::from_secs(12), chain.validator_clock(endpoint))
                    .await
                    .ok()
                    .and_then(Result::ok);
            let _ = tx.send(AppEvent::ValidatorClockLoaded {
                generation,
                seq,
                cycle,
            });
        });
    }

    fn refresh_network_stats(&mut self) {
        let endpoint = self.current_endpoint();
        if endpoint.is_empty() {
            return;
        }
        let generation = self.subscription_generation;
        self.stats_fetch_seq = self.stats_fetch_seq.wrapping_add(1);
        let seq = self.stats_fetch_seq;
        let tx = self.tx.clone();
        let chain = self.chain.clone();
        self.runtime.spawn(async move {
            let stats =
                tokio::time::timeout(Duration::from_secs(20), chain.network_stats(endpoint))
                    .await
                    .ok()
                    .and_then(Result::ok);
            let _ = tx.send(AppEvent::NetworkStatsLoaded {
                generation,
                seq,
                stats,
            });
        });
    }

    fn open_in_explorer(&mut self, address: String, transaction_hash: String) {
        self.state.selected_tab = AppTab::Explorer;
        let hash = transaction_hash.trim().to_owned();
        self.pending_explorer_trace = (!hash.is_empty()).then_some(hash);
        self.inspect_account(address);
    }

    fn inspect_account(&mut self, address: String) {
        let address = address.trim().to_owned();
        if address.is_empty() {
            self.state.account_detail = None;
            self.state.account_error = None;
            self.state.account_loading = false;
            self.state.inspected_address.clear();
            self.clear_account_transactions();
            return;
        }
        let endpoint = self.current_endpoint();
        if endpoint.is_empty() {
            self.state.account_detail = None;
            self.state.account_loading = false;
            self.state.inspected_address = address;
            self.state.account_error =
                Some("No network endpoint is configured for this wallet.".to_owned());
            self.clear_account_transactions();
            return;
        }
        self.state.account_loading = true;
        self.state.account_error = None;
        self.state.inspected_address = address.clone();
        self.clear_account_transactions();
        self.state.account_txs_loading = true;
        let generation = self.subscription_generation;
        self.account_fetch_seq = self.account_fetch_seq.wrapping_add(1);
        let seq = self.account_fetch_seq;
        let tx = self.tx.clone();
        let chain = self.chain.clone();
        let state_endpoint = endpoint.clone();
        let state_address = address.clone();
        self.runtime.spawn(async move {
            let result = match tokio::time::timeout(
                Duration::from_secs(15),
                chain.inspect_account(state_endpoint, state_address.clone()),
            )
            .await
            {
                Ok(Ok(detail)) => Ok(detail),
                Ok(Err(error)) => Err(error.to_string()),
                Err(_) => Err("Timed out while fetching the account state.".to_owned()),
            };
            let _ = tx.send(AppEvent::AccountInspected {
                generation,
                seq,
                address: state_address,
                result,
            });
        });

        let tx = self.tx.clone();
        let chain = self.chain.clone();
        self.runtime.spawn(async move {
            let result = match tokio::time::timeout(
                Duration::from_secs(20),
                chain.account_transactions(endpoint, address.clone(), EXPLORER_TX_LIMIT),
            )
            .await
            {
                Ok(Ok(page)) => Ok(page),
                Ok(Err(error)) => Err(error.to_string()),
                Err(_) => Err("Timed out while fetching the account's transactions.".to_owned()),
            };
            let _ = tx.send(AppEvent::AccountTransactionsLoaded {
                generation,
                seq,
                address,
                result,
            });
        });
    }

    fn cached_trace(&mut self, hash: &str) -> Option<AccountTrace> {
        let at = self.trace_cache.iter().position(|(key, _)| key == hash)?;
        let entry = self.trace_cache.remove(at);
        let trace = entry.1.clone();
        self.trace_cache.insert(0, entry);
        Some(trace)
    }

    fn remember_trace(&mut self, hash: &str, trace: &AccountTrace) {
        if trace.unexecuted > 0 {
            return;
        }
        self.trace_cache.retain(|(key, _)| key != hash);
        self.trace_cache.insert(0, (hash.to_owned(), trace.clone()));
        self.trace_cache.truncate(TRACE_MEMORY);
    }

    fn forget_traces(&mut self) {
        self.trace_cache.clear();
    }

    fn trace_transaction(&mut self, transaction_hash: String) {
        let hash = transaction_hash.trim().to_owned();
        if hash.is_empty() {
            self.close_trace();
            return;
        }
        if let Some(trace) = self.cached_trace(&hash) {
            self.trace_fetch_seq = self.trace_fetch_seq.wrapping_add(1);
            self.state.trace = Some(trace);
            self.state.trace_error = None;
            self.state.trace_loading = false;
            self.state.trace_hash = hash;
            return;
        }
        let endpoint = self.current_endpoint();
        if endpoint.is_empty() {
            self.state.trace = None;
            self.state.trace_loading = false;
            self.state.trace_hash = hash;
            self.state.trace_error =
                Some("No network endpoint is configured for this wallet.".to_owned());
            return;
        }
        self.state.trace = None;
        self.state.trace_error = None;
        self.state.trace_loading = true;
        self.state.trace_hash = hash.clone();
        let generation = self.subscription_generation;
        self.trace_fetch_seq = self.trace_fetch_seq.wrapping_add(1);
        let seq = self.trace_fetch_seq;
        let tx = self.tx.clone();
        let chain = self.chain.clone();
        self.runtime.spawn(async move {
            let result = match tokio::time::timeout(
                Duration::from_secs(30),
                chain.trace_transaction(endpoint, hash.clone()),
            )
            .await
            {
                Ok(Ok(trace)) => Ok(trace),
                Ok(Err(error)) => Err(error.to_string()),
                Err(_) => Err("Timed out while walking the message tree.".to_owned()),
            };
            let _ = tx.send(AppEvent::TraceLoaded {
                generation,
                seq,
                transaction_hash: hash,
                result,
            });
        });
    }

    fn close_trace(&mut self) {
        self.state.trace = None;
        self.state.trace_loading = false;
        self.state.trace_error = None;
        self.state.trace_hash.clear();
        self.trace_fetch_seq = self.trace_fetch_seq.wrapping_add(1);
    }

    fn clear_account_transactions(&mut self) {
        self.close_trace();
        self.state.account_txs.clear();
        self.state.account_txs_loading = false;
        self.state.account_txs_error = None;
        self.state.account_txs_skipped = 0;
    }

    pub fn poll_events(&mut self) {
        for _ in 0..MAX_EVENTS_PER_POLL {
            let Ok(msg) = self.key_rx.try_recv() else {
                break;
            };
            self.apply_key_msg(msg);
        }
        for _ in 0..MAX_EVENTS_PER_POLL {
            let Ok(event) = self.rx.try_recv() else { break };
            self.apply_event(event);
        }
    }

    #[cfg(test)]
    pub(crate) fn pump_key(&mut self) {
        if let Ok(msg) = self.key_rx.recv_timeout(Duration::from_secs(10)) {
            self.apply_key_msg(msg);
        }
        while let Ok(msg) = self.key_rx.try_recv() {
            self.apply_key_msg(msg);
        }
    }

    #[cfg(test)]
    pub(crate) fn pump_events(&mut self) {
        const QUIET: Duration = Duration::from_millis(150);
        const MAX: Duration = Duration::from_secs(3);
        let hard_deadline = Instant::now() + MAX;
        loop {
            if Instant::now() >= hard_deadline {
                break;
            }
            match self.rx.recv_timeout(QUIET) {
                Ok(event) => {
                    self.apply_event(event);
                    while let Ok(event) = self.rx.try_recv() {
                        self.apply_event(event);
                    }
                }
                Err(_) => break,
            }
        }
    }

    pub fn shutdown(&mut self) -> bool {
        self.clear_seed_from_clipboard();
        if self.clipboard_secret.is_some() {
            self.state.set_error(
                "Closing is paused while the wallet retries clearing a recovery phrase from the clipboard. Clear it manually if the warning persists.",
            );
            return false;
        }
        if !self.chain.drain_emulation_jobs(EMULATION_DRAIN_TIMEOUT) {
            self.state.set_error(
                "A bounded fee-emulation worker did not stop in time; the wallet remains open",
            );
            return false;
        }
        let _ = self.flush_save_blocking();
        if let Some(lock) = self._instance_lock.as_mut()
            && let Err(error) = lock.release()
        {
            self.state.set_error(format!(
                "Could not release the mandatory instance lock; the application will remain open: {error}"
            ));
            return false;
        }
        true
    }

    pub(crate) fn lock(&mut self) -> bool {
        self.request_lock(LockFollowUp::None)
    }

    fn request_lock(&mut self, follow_up: LockFollowUp) -> bool {
        if self.pending_teardown.is_some() {
            return false;
        }
        self.chain.seal_key_ops();
        if self.chain.drain_emulation_jobs(Duration::ZERO) {
            self.finish_lock();
            self.run_lock_follow_up(follow_up);
            return true;
        }
        self.pending_teardown = Some(PendingLock {
            deadline: Instant::now() + EMULATION_DRAIN_TIMEOUT,
            follow_up,
        });
        self.state.busy = true;
        self.state.status = "Locking — waiting for a fee calculation to finish…".to_owned();
        false
    }

    fn finish_lock(&mut self) {
        let flushed = self.flush_save_blocking();
        let lost_save_detail = (!flushed).then(|| {
            self.state
                .persistence_error
                .clone()
                .unwrap_or_else(|| "recent changes could not be saved".to_owned())
        });
        self.session_generation = self.session_generation.wrapping_add(1);
        self.clear_seed_from_clipboard();
        self.stop_subscription();
        self.vault = None;
        self.writer = None;
        let wallet_names = std::mem::take(&mut self.state.wallet_names);
        let active_wallet = std::mem::take(&mut self.state.active_wallet);
        let clipboard_notice = std::mem::take(&mut self.state.clipboard_notice);
        self.state = AppState {
            phase: AppPhase::Locked,
            status: "Locked".to_owned(),
            wallet_names,
            active_wallet,
            clipboard_notice,
            ..AppState::default()
        };
        if let Some(detail) = lost_save_detail {
            self.state.set_error(format!(
                "Locked. Recent changes could not be saved and were discarded: {detail}"
            ));
        }
        self.chain.clear_config_cache();
        self.forget_traces();
        self.reset_journal_reconciliation();
        self.clear_pending_max();
        self.swap_in_flight = None;
        self.max_filled = false;
        self.dirty = false;
        self.save_deadline = None;
        self.session = SessionRuntime::default();
        self.load = LoadRuntime::default();
        self.invalidate_key_ops();
    }

    fn run_lock_follow_up(&mut self, follow_up: LockFollowUp) {
        match follow_up {
            LockFollowUp::None => {}
            LockFollowUp::Picker => self.probe_phase(),
            LockFollowUp::SwitchTo(name) => {
                let entries = match wallet_entries_in(&self.data_dir) {
                    Ok(entries) => entries,
                    Err(error) => {
                        self.state
                            .set_error(format!("Could not list wallet files: {error}"));
                        self.probe_phase();
                        return;
                    }
                };
                if !entries.iter().any(|entry| entry.display_name == name) {
                    self.probe_phase();
                    return;
                }
                self.state.wallet_names = entries
                    .iter()
                    .map(|entry| entry.display_name.clone())
                    .collect();
                self.wallet_entries = entries;
                self.select_wallet(name);
            }
            LockFollowUp::DeleteWallet => match self.store.destroy() {
                Ok(_) => {
                    self.state.persistence_health = PersistenceHealth::Ready;
                    self.state.active_wallet = String::new();
                    self.probe_phase();
                    self.state.status = "Wallet deleted".to_owned();
                }
                Err(error) => self.state.set_error(format!(
                    "The wallet file could not be deleted and may still hold your seed: {error}"
                )),
            },
        }
    }

    pub(crate) fn apply_key_msg(&mut self, msg: KeyMsg) {
        if msg.generation() != self.key_generation {
            return;
        }
        self.key_generation = self.key_generation.wrapping_add(1);
        self.state.key_busy = false;
        match msg {
            KeyMsg::WrongPassword { action, .. } => match action {
                KeyAction::Unlock => self.state.lock_error = "Incorrect password".to_owned(),
                KeyAction::DeleteWalletFromPicker => {
                    self.pending_picker_delete = None;
                    self.state.lock_error = "Incorrect password".to_owned();
                }
                _ => self.state.auth.error = "Incorrect password".to_owned(),
            },
            KeyMsg::Failed { action, error, .. } => match action {
                KeyAction::Unlock | KeyAction::Create => self.state.lock_error = error,
                KeyAction::DeleteWalletFromPicker => {
                    self.pending_picker_delete = None;
                    self.state.lock_error =
                        "Could not verify the password; the file was not deleted".to_owned();
                }
                _ => self.state.auth.error = error,
            },
            KeyMsg::Verified { action, .. } => self.run_reauth_action(action),
            KeyMsg::Ok {
                action,
                vault,
                profile,
                history,
                history_corrupt,
                journal,
                selected,
                writer,
                ..
            } => match action {
                KeyAction::Unlock | KeyAction::Create => {
                    let Some(writer) = writer else {
                        self.state.lock_error =
                            "The authenticated wallet writer is unavailable".to_owned();
                        return;
                    };
                    let is_create = action == KeyAction::Create;
                    self.vault = Some(Arc::new(vault));
                    let entry = AppEntry {
                        profile,
                        history,
                        history_corrupt,
                        journal,
                        selected,
                        writer,
                    };
                    self.enter_app(entry);
                    if is_create {
                        self.persist_new_container();
                    }
                }
                KeyAction::ChangePassword => {
                    let previous_vault = self.vault.take();
                    self.vault = Some(Arc::new(vault));
                    self.state.auth.open = false;
                    self.state.error = None;
                    self.state.autosign_until = None;
                    self.dirty = true;
                    self.save_deadline = None;
                    if self.flush_save_blocking() {
                        match self.store.shred_foreign_keyslot_residue() {
                            Ok(_) => self.state.status = "Wallet password changed".to_owned(),
                            Err(error) => {
                                eprintln!(
                                    "cc-wallet: could not shred old-password wallet copies: {error}"
                                );
                                self.state.status =
                                    "Password changed, but old-password copies may \
                                    remain on disk — remove any *.orphan/*.tmp beside the wallet \
                                    file manually"
                                        .to_owned();
                            }
                        }
                    } else {
                        self.vault = previous_vault;
                        self.state.status = "Password NOT changed — could not save; \
                            your previous password is still active"
                            .to_owned();
                    }
                }
                KeyAction::DeleteWalletFromPicker => {
                    drop(writer);
                    drop(selected);
                    drop(vault);
                    drop(journal);
                    let _ = (profile, history, history_corrupt);
                    self.finish_picker_delete();
                }
                other => self.run_reauth_action(other),
            },
        }
    }

    fn run_reauth_action(&mut self, action: KeyAction) {
        match action {
            KeyAction::ConfirmSend {
                remember,
                auth_generation,
                auth_nonce,
            } => {
                if self.refuse_unpermitted_send() {
                    return;
                }
                let Some(authorization) = self.pending_authorization.take() else {
                    self.state.auth.error =
                        "The transfer authorization no longer exists".to_owned();
                    return;
                };
                if !authorization.matches(auth_generation, auth_nonce) {
                    self.state.auth.error = "Stale transfer authorization was rejected".to_owned();
                    return;
                }
                self.state.auth.open = false;
                self.state.auth.error = String::new();
                if remember {
                    self.state.extend_autosign();
                }
                self.send_authorized_transaction(authorization);
            }
            KeyAction::ConfirmStorage {
                remember,
                generation,
            } => {
                let matches = self
                    .pending_storage
                    .as_ref()
                    .is_some_and(|pending| pending.generation == generation);
                if !matches {
                    self.state.auth.error = "The storage authorization no longer exists".to_owned();
                    return;
                }
                self.state.auth.open = false;
                self.state.auth.error = String::new();
                if remember {
                    self.state.extend_autosign();
                }
                self.dispatch_authorized_storage();
            }
            KeyAction::ConfirmSwap {
                remember,
                generation,
            } => {
                let matches = self
                    .pending_swap
                    .as_ref()
                    .is_some_and(|pending| pending.generation == generation);
                if !matches {
                    self.state.auth.error = "The swap authorization no longer exists".to_owned();
                    return;
                }
                self.state.auth.open = false;
                self.state.auth.error = String::new();
                if remember {
                    self.state.extend_autosign();
                }
                self.dispatch_authorized_swap();
            }
            KeyAction::RevealRecords => {
                self.state.auth.open = false;
                self.state.auth.error = String::new();
                self.show_records_for_one_minute();
            }
            KeyAction::RevealSeed => {
                self.state.auth.open = false;
                self.state.auth.error = String::new();
                self.show_seed_for_one_minute();
            }
            KeyAction::DeleteWallet => {
                self.state.auth.open = false;
                self.state.auth.error = String::new();
                self.do_delete_wallet();
            }
            KeyAction::VerifyForChangePassword => {
                self.state.auth.mode = AuthMode::Create;
                self.state.auth.error = String::new();
            }
            KeyAction::ApplySecuritySetting(setting) => {
                self.state.auth.open = false;
                self.state.auth.error = String::new();
                self.pending_security_setting = None;
                self.apply_security_setting(setting);
            }
            _ => {}
        }
    }

    fn enter_app(&mut self, entry: AppEntry) {
        let AppEntry {
            profile,
            history,
            history_corrupt,
            journal,
            selected,
            writer,
        } = entry;
        self.session.activity_quarantine_pending = if history_corrupt { selected } else { None };
        self.chain.unseal_key_ops();
        self.writer = Some(writer);
        self.session_generation = self.session_generation.wrapping_add(1);
        self.state.apply_profile(profile);
        self.state.seed_editing = false;
        self.state.show_seed = false;
        self.state.seed_reveal_deadline = None;
        self.state.seed_unsaved = false;
        self.state.onboard_import_valid = false;
        self.state.seed_backup_confirmed = false;
        self.clear_seed_from_clipboard();
        self.journal = journal;
        self.state.kdf_weak = self.kdf_params.meets_floor()
            && self
                .vault
                .as_ref()
                .is_some_and(|vault| !vault.kdf_params().meets_floor());
        self.state.history_corrupt = history_corrupt;
        self.state.snapshot_refresh_error = None;
        self.state.history_integrity_error = None;
        self.state.persistence_health = if history_corrupt {
            PersistenceHealth::QuarantineRequired
        } else {
            PersistenceHealth::Ready
        };
        self.state.phase = AppPhase::Unlocked;
        let display_name = self
            .vault
            .as_ref()
            .map(|vault| vault.display_name().to_owned())
            .unwrap_or_else(|| self.store.name().to_owned());
        self.state.active_wallet = display_name.clone();
        if let Some(entry) = self
            .wallet_entries
            .iter_mut()
            .find(|entry| entry.storage_id == self.store.name())
        {
            entry.display_name = display_name;
        } else {
            self.wallet_entries.push(WalletListing {
                storage_id: self.store.name().to_owned(),
                display_name,
            });
        }
        self.wallet_entries
            .sort_by(|a, b| a.storage_id.cmp(&b.storage_id));
        self.state.wallet_names = self
            .wallet_entries
            .iter()
            .map(|entry| entry.display_name.clone())
            .collect();
        self.refresh_network_view();
        self.state.lock_error.clear();
        self.state.error = None;
        self.state.activity = history;
        self.sort_activity();
        self.cap_history();
        self.recover_restored_delivery_state();
        self.session.history_synced_floor = None;
        self.session.history_has_gap = true;
        self.load.history_reconciliation_scan = None;
        self.bump_activity();
        if self.state.seed_saved {
            self.refresh_wallet();
        } else {
            self.state.selected_tab = AppTab::Settings;
            self.state.status = "Add a seed phrase to finish setup".to_owned();
        }
        self.ensure_activity_quarantined();
    }

    fn wallet_inputs(&self) -> Result<cc_wallet_domain::WalletInputs, String> {
        let endpoint = self.current_endpoint();
        if endpoint.is_empty() {
            return Err(format!(
                "no endpoint configured for network {}, add one in Settings",
                self.state.network_id
            ));
        }
        let endpoint = crate::canonical_endpoint(&endpoint)?;
        let require_signature_id = self.networks.require_signature_id(self.state.network_id);
        let inputs = self
            .state
            .to_profile()
            .wallet_inputs(endpoint, require_signature_id)
            .map_err(|error| error.to_string())?;
        Ok(inputs)
    }

    fn endpoint_address_inputs(&self) -> Result<EndpointAddressInputs, String> {
        let endpoint = crate::canonical_endpoint(&self.current_endpoint())?;
        let address = self
            .state
            .wallet_address()
            .map(str::to_owned)
            .ok_or_else(|| "wallet address is unavailable".to_owned())?;
        EndpointAddressInputs::new(endpoint, address).map_err(|error| error.to_string())
    }

    fn wallet_load_inputs(&mut self) -> Result<EndpointAddressInputs, String> {
        if self.state.wallet_address().is_some() {
            return self.endpoint_address_inputs();
        }
        let inputs = self.wallet_inputs()?;
        let address = self
            .chain
            .derive_wallet_address(&inputs)
            .map_err(|error| error.to_string())?;
        let endpoint_inputs = EndpointAddressInputs::new(inputs.endpoint, address.clone())
            .map_err(|error| error.to_string())?;
        self.state.derived_wallet_address = address;
        Ok(endpoint_inputs)
    }

    fn verify_network_id(&mut self, gid: i32) -> bool {
        if gid == self.state.network_id {
            self.state.network_mismatch = false;
            true
        } else {
            self.state.network_mismatch = true;
            self.state.set_error(format!(
                "This endpoint serves network {gid}, but this wallet is on network {}. \
                 Choose an endpoint for the wallet's network in Settings — sending is blocked.",
                self.state.network_id
            ));
            false
        }
    }
}

#[cfg(test)]
impl AppController {
    pub(crate) fn has_pending_teardown(&self) -> bool {
        self.pending_teardown.is_some()
    }

    pub(crate) fn expire_pending_teardown(&mut self) {
        if let Some(pending) = self.pending_teardown.as_mut() {
            pending.deadline = Instant::now();
        }
    }
}

fn final_emulation_drain(chain: &dyn ChainService) -> bool {
    for _ in 0..3 {
        if chain.drain_emulation_jobs(EMULATION_DRAIN_TIMEOUT) {
            return true;
        }
    }
    false
}

impl Drop for AppController {
    fn drop(&mut self) {
        let _ = self.flush_save_blocking();
        if let Some(task) = self.subscription_task.take() {
            task.abort();
        }
        if !final_emulation_drain(self.chain.as_ref()) {
            eprintln!(
                "A gas-capped fee-emulation worker did not stop after bounded retries; exiting anyway"
            );
        }
    }
}

fn sanitize_wallet_name(name: &str) -> String {
    const MAX_CHARS: usize = 48;
    let mut out = String::new();
    let mut prev_space = false;
    for ch in name.trim().chars() {
        if ch.is_control() || matches!(ch, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') {
            continue;
        }
        if ch.is_whitespace() {
            if prev_space || out.is_empty() {
                continue;
            }
            out.push(' ');
            prev_space = true;
            continue;
        }
        if out.chars().count() >= MAX_CHARS {
            break;
        }
        prev_space = false;
        out.push(ch);
    }
    while out.ends_with(' ') || out.ends_with('.') {
        out.pop();
    }
    out
}

fn wallet_storage_id(display_name: &str) -> String {
    const MAX_CHARS: usize = 48;
    let mut out = String::new();
    let mut separator_pending = false;
    let mut chars = 0usize;

    for source in display_name.chars() {
        for ch in source.to_lowercase() {
            if ch.is_alphanumeric() {
                if separator_pending && !out.is_empty() && chars + 1 < MAX_CHARS {
                    out.push('-');
                    chars += 1;
                }
                separator_pending = false;
                if chars >= MAX_CHARS {
                    return out;
                }
                out.push(ch);
                chars += 1;
            } else if !out.is_empty() {
                separator_pending = true;
            }
        }
    }
    out
}

fn wallet_entries_in(dir: &std::path::Path) -> VaultStoreResult<Vec<WalletListing>> {
    let mut entries = list_wallet_entries(dir)?;
    for entry in &mut entries {
        if wallet_storage_id(&entry.display_name) != entry.storage_id {
            entry.display_name = entry.storage_id.clone();
        }
    }
    Ok(entries)
}

fn is_reserved_wallet_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    let ext_infix = format!(".{}", cc_wallet_storage::WALLET_EXT);
    if lower == "history" || lower.ends_with(".history") || lower.contains(&ext_infix) {
        return true;
    }
    let base = lower.split('.').next().unwrap_or(&lower);
    matches!(base, "con" | "prn" | "aux" | "nul")
        || (base.len() == 4
            && (base.starts_with("com") || base.starts_with("lpt"))
            && matches!(base.as_bytes()[3], b'1'..=b'9'))
}

#[cfg(debug_assertions)]
fn test_kdf_override() -> Option<KdfParams> {
    std::env::var_os("CC_WALLET_TEST_KDF").map(|_| KdfParams {
        m_kib: 16_384,
        t: 2,
        p: 1,
    })
}

#[cfg(not(debug_assertions))]
fn test_kdf_override() -> Option<KdfParams> {
    None
}
