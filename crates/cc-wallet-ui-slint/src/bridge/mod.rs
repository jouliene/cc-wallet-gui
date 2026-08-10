use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use cc_wallet_app::{
    ActivityDirection, ActivityEvent, AddressBookEntry, AppCommand, AppController, AssetAmount,
    AssetId, StartupCwd,
};
#[cfg(debug_assertions)]
use cc_wallet_app::{Password, SeedInput};
use slint::{ComponentHandle, Timer, TimerMode};

slint::include_modules!();

mod callbacks;
mod render;
mod sync;

use callbacks::connect_callbacks;
use sync::sync_ui;

#[cfg(debug_assertions)]
#[derive(Default)]
struct SwapDrive {
    pair: Option<String>,
    amount: Option<String>,
    slippage: Option<String>,
    go: Option<bool>,
}

#[cfg(debug_assertions)]
impl SwapDrive {
    fn from_env() -> Self {
        let var = |name: &str| {
            std::env::var(name)
                .ok()
                .filter(|value| !value.trim().is_empty())
        };
        Self {
            pair: var("CC_WALLET_TEST_SWAP_PAIR"),
            amount: var("CC_WALLET_TEST_SWAP_AMOUNT"),
            slippage: var("CC_WALLET_TEST_SWAP_SLIPPAGE"),
            go: var("CC_WALLET_TEST_SWAP_GO").map(|value| value.trim() != "ask"),
        }
    }

    fn idle(&self) -> bool {
        self.pair.is_none() && self.amount.is_none() && self.slippage.is_none() && self.go.is_none()
    }

    fn asset(name: &str) -> Option<AssetId> {
        match name.trim() {
            "native" | "coin" | "COIN" => Some(AssetId::Native),
            id => id.parse::<u32>().ok().map(AssetId::CurrencyCollection),
        }
    }

    fn apply(&mut self, controller: &mut AppController) {
        if controller.state().phase != cc_wallet_app::AppPhase::Unlocked
            || controller.state().swap.pool.is_none()
        {
            return;
        }
        if let Some(pair) = self.pair.take()
            && let Some((from, to)) = pair.split_once('>')
        {
            if let Some(asset) = Self::asset(from) {
                controller.handle_command(AppCommand::SetSwapFromToken(asset));
            }
            if let Some(asset) = Self::asset(to) {
                controller.handle_command(AppCommand::SetSwapToToken(asset));
            }
        }
        if let Some(slippage) = self.slippage.take() {
            match slippage.strip_prefix("own:") {
                Some(text) => {
                    controller.handle_command(AppCommand::EditSwapSlippage(text.to_owned()));
                }
                None => {
                    if let Ok(bps) = slippage.trim().parse::<u16>() {
                        controller.handle_command(AppCommand::SetSwapSlippage(bps));
                    }
                }
            }
        }
        if let Some(amount) = self.amount.take() {
            controller.handle_command(AppCommand::SetSwapAmount(amount));
        }
        if self.go.is_some() && controller.state().swap_button_enabled() {
            let sign = self.go.take() == Some(true);
            controller.handle_command(AppCommand::RequestSwap);
            if let (true, Ok(pw)) = (sign, std::env::var("CC_WALLET_TEST_PASSWORD")) {
                controller.handle_command(AppCommand::AuthSubmit {
                    pw: Password::new(pw),
                    pw2: Password::new(String::new()),
                    remember: false,
                });
            }
        }
    }
}

/// Drives the send form as far as the confirmation dialog and stops there.
///
/// The dialog is three interactions deep — an address, MAX, then Send — and
/// mouse events from a screenshot harness do not reach Slint at all. It never
/// submits: what it exists to show is the dialog itself.
#[cfg(debug_assertions)]
#[derive(Default)]
struct SendDrive {
    destination: Option<String>,
    comment: Option<String>,
    asked: bool,
}

#[cfg(debug_assertions)]
impl SendDrive {
    fn from_env() -> Self {
        let var = |name: &str| {
            std::env::var(name)
                .ok()
                .filter(|value| !value.trim().is_empty())
        };
        Self {
            destination: var("CC_WALLET_TEST_SEND_MAX"),
            comment: var("CC_WALLET_TEST_SEND_COMMENT"),
            asked: false,
        }
    }

    fn idle(&self) -> bool {
        self.destination.is_none()
    }

    fn apply(&mut self, controller: &mut AppController) {
        let Some(destination) = self.destination.clone() else {
            return;
        };
        // The balance is what MAX is a fraction of, so there is nothing to ask
        // until the wallet has answered.
        if controller.state().wallet.is_none() {
            return;
        }
        if !self.asked {
            controller.handle_command(AppCommand::SetSendDestination(destination));
            if let Some(comment) = self.comment.clone() {
                controller.handle_command(AppCommand::SetSendComment(comment));
            }
            controller.handle_command(AppCommand::SetMaxAmount);
            self.asked = true;
            return;
        }
        // MAX is refined against a live emulation, and asking to send before it
        // lands would be asking about an amount that is about to change.
        if controller.state().max_refining || controller.state().send_form.amount.is_empty() {
            return;
        }
        controller.handle_command(AppCommand::RequestSend);
        self.destination = None;
    }
}

#[cfg(debug_assertions)]
#[derive(Default)]
struct StorageDrive {
    create: bool,
    add: Vec<(String, String)>,
    delete: Vec<u32>,
    ask: bool,
    reveal: bool,
    settled_at: Option<std::time::Instant>,
}

#[cfg(debug_assertions)]
impl StorageDrive {
    fn from_env() -> Self {
        let var = |name: &str| {
            std::env::var(name)
                .ok()
                .filter(|value| !value.trim().is_empty())
        };
        Self {
            create: var("CC_WALLET_TEST_STORAGE_CREATE").is_some(),
            add: var("CC_WALLET_TEST_STORAGE_ADD")
                .map(|raw| {
                    raw.split(';')
                        .filter_map(|entry| entry.split_once('='))
                        .map(|(title, data)| (title.to_owned(), data.to_owned()))
                        .collect()
                })
                .unwrap_or_default(),
            delete: var("CC_WALLET_TEST_STORAGE_DELETE")
                .map(|raw| {
                    raw.split(',')
                        .filter_map(|id| id.trim().parse().ok())
                        .collect()
                })
                .unwrap_or_default(),
            ask: var("CC_WALLET_TEST_STORAGE_ASK").is_some(),
            reveal: var("CC_WALLET_TEST_STORAGE_REVEAL").is_some(),
            settled_at: None,
        }
    }

    fn idle(&self) -> bool {
        !self.create && !self.reveal && self.add.is_empty() && self.delete.is_empty()
    }

    fn authorize(&self, controller: &mut AppController) {
        if self.ask {
            return;
        }
        if let Ok(pw) = std::env::var("CC_WALLET_TEST_PASSWORD") {
            controller.handle_command(AppCommand::AuthSubmit {
                pw: Password::new(pw),
                pw2: Password::new(String::new()),
                remember: true,
            });
        }
    }

    fn apply(&mut self, controller: &mut AppController) {
        let state = controller.state();
        if state.phase != cc_wallet_app::AppPhase::Unlocked
            || !state.storage.loaded
            || state.storage.busy
            || state.auth.open
        {
            return;
        }

        let settled = match self.settled_at {
            Some(at) => at.elapsed() >= std::time::Duration::from_secs(2),
            None => true,
        };
        if !settled {
            return;
        }

        if self.create {
            if state.storage.exists {
                self.create = false;
            } else {
                controller.handle_command(AppCommand::CreateStorage);
                self.authorize(controller);
                self.create = false;
                self.settled_at = Some(std::time::Instant::now());
            }
            return;
        }
        if !controller.state().storage.exists {
            return;
        }
        if !self.add.is_empty() {
            let (title, data) = self.add.remove(0);
            controller.handle_command(AppCommand::SetStorageTitle(title));
            controller.handle_command(AppCommand::SetStorageData(data));
            controller.handle_command(AppCommand::AddStorageRecord);
            self.authorize(controller);
            self.settled_at = Some(std::time::Instant::now());
            return;
        }
        if !self.delete.is_empty() {
            let id = self.delete.remove(0);
            controller.handle_command(AppCommand::DeleteStorageRecord(id));
            self.authorize(controller);
            self.settled_at = Some(std::time::Instant::now());
            return;
        }
        if self.reveal {
            self.reveal = false;
            controller.handle_command(AppCommand::RevealStorageRecords);
            self.authorize(controller);
        }
    }
}

type SwapPoolKey = (Vec<(AssetId, u128)>, AssetId, AssetId);

#[derive(Default)]
struct UiCache {
    endpoint: String,
    assets_key: Option<(AssetId, Vec<AssetId>, Vec<AssetAmount>)>,
    contacts: Vec<AddressBookEntry>,
    contacts_rev: u64,
    activity_hash: u64,
    storage_rows_hash: u64,
    explorer_account_hash: u64,
    explorer_txs_hash: u64,
    explorer_trace_hash: u64,
    network_sig: String,
    inspected_address: String,
    swap_pool_key: Option<SwapPoolKey>,
    auth_was_open: bool,
    risk_was_open: bool,
    was_locked: bool,
    was_onboarding: bool,
    was_selecting: bool,
    was_settings: bool,
    wallet_names: Vec<String>,
    filters: ActivityFilters,
    active_wallet: String,
    risk_rows: (Vec<String>, Vec<bool>),
}

impl UiCache {
    fn sync_active_wallet(&mut self, wallet: &str) -> bool {
        if self.active_wallet == wallet {
            return false;
        }
        self.active_wallet.clear();
        self.active_wallet.push_str(wallet);
        self.filters = ActivityFilters::default();
        true
    }
}

struct ActivityFilters {
    dir: String,
    token: i32,
    party: String,
    party_label: String,
}

impl Default for ActivityFilters {
    fn default() -> Self {
        Self {
            dir: "all".to_owned(),
            token: -2,
            party: String::new(),
            party_label: String::new(),
        }
    }
}

impl ActivityFilters {
    fn any_active(&self) -> bool {
        !(self.dir.is_empty() || self.dir == "all") || self.token != -2 || !self.party.is_empty()
    }

    fn matches(&self, event: &ActivityEvent) -> bool {
        let dir_ok = match self.dir.as_str() {
            "in" => matches!(event.direction, ActivityDirection::In),
            "out" => matches!(event.direction, ActivityDirection::Out),
            _ => true,
        };
        let token_ok = match self.token {
            -1 => event.moves_asset(AssetId::Native),
            n if n >= 1 => event.moves_asset(AssetId::CurrencyCollection(n as u32)),
            _ => true,
        };
        let party_ok = self.party.is_empty() || event.counterparty == self.party;
        dir_ok && token_ok && party_ok
    }
}

pub(crate) fn show_startup_error(message: &str) {
    eprintln!("CC Wallet cannot start: {message}");
    let Ok(win) = StartupErrorWindow::new() else {
        return;
    };
    win.set_message(message.into());
    let weak = win.as_weak();
    win.on_dismiss(move || {
        if let Some(win) = weak.upgrade() {
            let _ = win.hide();
        }
    });
    let _ = win.run();
}

pub fn run(startup_cwd: StartupCwd) -> Result<(), slint::PlatformError> {
    let controller = match AppController::from_startup_cwd(startup_cwd) {
        Ok(controller) => Rc::new(RefCell::new(controller)),
        Err(message) => {
            show_startup_error(&message);
            std::process::exit(1);
        }
    };
    let ui = AppWindow::new()?;
    let cache = Rc::new(RefCell::new(UiCache::default()));

    connect_callbacks(&ui, controller.clone(), cache.clone());

    {
        let controller = controller.clone();
        ui.window().on_close_requested(move || {
            if controller.borrow_mut().shutdown() {
                slint::CloseRequestResponse::HideWindow
            } else {
                slint::CloseRequestResponse::KeepWindowShown
            }
        });
    }

    controller.borrow_mut().handle_command(AppCommand::Init);

    #[cfg(debug_assertions)]
    {
        use cc_wallet_app::AppPhase;
        if let Ok(pw) = std::env::var("CC_WALLET_TEST_PASSWORD")
            && !pw.is_empty()
        {
            let pw = Password::new(pw);
            let mut c = controller.borrow_mut();
            if c.state().phase == AppPhase::Selecting
                && let Some(name) = c.state().wallet_names.first().cloned()
            {
                c.handle_command(AppCommand::SelectWallet(name));
            }
            match c.state().phase {
                AppPhase::Onboarding => {
                    match std::env::var("CC_WALLET_TEST_SEED") {
                        Ok(seed) if !seed.is_empty() => {
                            c.handle_command(AppCommand::OnboardImportSeed(SeedInput::new(seed)))
                        }
                        _ => c.handle_command(AppCommand::GenerateSeed),
                    }
                    let network_id = std::env::var("CC_WALLET_TEST_NETWORK")
                        .ok()
                        .and_then(|v| v.parse::<i32>().ok())
                        .unwrap_or(0);
                    let workchain = std::env::var("CC_WALLET_TEST_WORKCHAIN")
                        .ok()
                        .and_then(|v| v.parse::<i8>().ok())
                        .unwrap_or(-1);
                    c.handle_command(AppCommand::SetSeedBackupConfirmed(true));
                    c.handle_command(AppCommand::CreateWallet {
                        name: "test".to_owned(),
                        network_id,
                        workchain,
                        pw: Password::new(
                            std::env::var("CC_WALLET_TEST_PASSWORD")
                                .expect("the debug password environment value still exists"),
                        ),
                        pw2: pw,
                    });
                }
                AppPhase::Locked => c.handle_command(AppCommand::Unlock(pw)),
                _ => {}
            }
        }
    }

    let form_locked = controller.borrow().send_form_locked();
    sync_ui(
        &ui,
        controller.borrow().state(),
        form_locked,
        &mut cache.borrow_mut(),
    );

    #[cfg(debug_assertions)]
    let pending_seed = std::rc::Rc::new(std::cell::RefCell::new(
        std::env::var("CC_WALLET_TEST_SEED")
            .ok()
            .filter(|s| !s.is_empty())
            .map(SeedInput::new),
    ));
    #[cfg(debug_assertions)]
    let pending_tab = std::rc::Rc::new(std::cell::RefCell::new(
        std::env::var("CC_WALLET_TEST_TAB").ok(),
    ));
    #[cfg(debug_assertions)]
    let pending_scan = std::rc::Rc::new(std::cell::RefCell::new(
        std::env::var("CC_WALLET_TEST_EXPLORER_ADDRESS")
            .ok()
            .filter(|s| !s.is_empty()),
    ));
    #[cfg(debug_assertions)]
    let pending_trace = std::rc::Rc::new(std::cell::RefCell::new(
        std::env::var("CC_WALLET_TEST_EXPLORER_TRACE")
            .ok()
            .filter(|s| !s.is_empty()),
    ));
    // The conversation is reached by clicking one icon in one activity row,
    // which is not something a screenshot harness can be relied on to hit.
    #[cfg(debug_assertions)]
    let pending_chat = std::rc::Rc::new(std::cell::RefCell::new(
        std::env::var("CC_WALLET_TEST_CHAT")
            .ok()
            .filter(|s| !s.is_empty()),
    ));
    // What to say once it is open, for the same reason: the composer cannot be
    // reached by a harness that has no way to click or type into it.
    #[cfg(debug_assertions)]
    let pending_contact = std::rc::Rc::new(std::cell::RefCell::new(
        std::env::var("CC_WALLET_TEST_CONTACT")
            .ok()
            .filter(|s| !s.is_empty()),
    ));
    #[cfg(debug_assertions)]
    let said_something = std::rc::Rc::new(std::cell::Cell::new(false));
    #[cfg(debug_assertions)]
    let pending_say = std::rc::Rc::new(std::cell::RefCell::new(
        std::env::var("CC_WALLET_TEST_CHAT_SAY")
            .ok()
            .filter(|s| !s.is_empty()),
    ));
    #[cfg(debug_assertions)]
    let pending_swap_drive = std::rc::Rc::new(std::cell::RefCell::new(SwapDrive::from_env()));
    #[cfg(debug_assertions)]
    let pending_storage_drive = std::rc::Rc::new(std::cell::RefCell::new(StorageDrive::from_env()));
    #[cfg(debug_assertions)]
    let pending_send_drive = std::rc::Rc::new(std::cell::RefCell::new(SendDrive::from_env()));
    #[cfg(debug_assertions)]
    if let Some(token) = std::env::var("CC_WALLET_TEST_TOKEN_FILTER")
        .ok()
        .and_then(|v| v.parse::<i32>().ok())
    {
        cache.borrow_mut().filters.token = token;
    }

    let timer = Timer::default();
    {
        let weak = ui.as_weak();
        let controller = controller.clone();
        let cache = cache.clone();
        #[cfg(debug_assertions)]
        let pending_seed = pending_seed.clone();
        #[cfg(debug_assertions)]
        let pending_tab = pending_tab.clone();
        #[cfg(debug_assertions)]
        let pending_scan = pending_scan.clone();
        #[cfg(debug_assertions)]
        let pending_trace = pending_trace.clone();
        let pending_chat = pending_chat.clone();
        let pending_contact = pending_contact.clone();
        let pending_say = pending_say.clone();
        let said_something = said_something.clone();
        #[cfg(debug_assertions)]
        let pending_swap_drive = pending_swap_drive.clone();
        #[cfg(debug_assertions)]
        let pending_storage_drive = pending_storage_drive.clone();
        timer.start(TimerMode::Repeated, Duration::from_millis(150), move || {
            let Some(ui) = weak.upgrade() else { return };
            {
                let mut c = controller.borrow_mut();
                c.tick();
                c.poll_events();
                #[cfg(debug_assertions)]
                {
                    let ready = c.state().phase == cc_wallet_app::AppPhase::Unlocked
                        && c.state().seed.is_empty();
                    if ready && let Some(seed) = pending_seed.borrow_mut().take() {
                        c.handle_command(AppCommand::ImportSeed(seed));
                        for cc_id in [1u32, 2, 3] {
                            c.handle_command(AppCommand::SetAssetVisibility {
                                cc_id,
                                visible: true,
                            });
                        }
                    }
                    if c.state().phase == cc_wallet_app::AppPhase::Unlocked
                        && let Some(tab) = pending_tab.borrow().as_deref()
                    {
                        let want = match tab {
                            "settings" => cc_wallet_app::AppTab::Settings,
                            "contacts" => cc_wallet_app::AppTab::Contacts,
                            "explorer" => cc_wallet_app::AppTab::Explorer,
                            "swap" => cc_wallet_app::AppTab::Swap,
                            "storage" => cc_wallet_app::AppTab::Storage,
                            _ => cc_wallet_app::AppTab::Wallet,
                        };
                        if c.state().selected_tab != want {
                            c.handle_command(AppCommand::SelectTab(want));
                        }
                    }
                    if c.state().phase == cc_wallet_app::AppPhase::Unlocked
                        && let Some(address) = pending_scan.borrow_mut().take()
                    {
                        match pending_trace.borrow_mut().take() {
                            Some(transaction_hash) => {
                                c.handle_command(AppCommand::OpenInExplorer {
                                    address,
                                    transaction_hash,
                                });
                            }
                            None => c.handle_command(AppCommand::InspectAccount(address)),
                        }
                    }
                    // "Name=address", so the contact-named side of a
                    // conversation header can be photographed too.
                    if c.state().phase == cc_wallet_app::AppPhase::Unlocked
                        && let Some(entry) = pending_contact.borrow_mut().take()
                        && let Some((name, address)) = entry.split_once('=')
                    {
                        c.handle_command(AppCommand::SaveContact {
                            index: None,
                            name: name.to_owned(),
                            address: address.to_owned(),
                            tag: String::new(),
                        });
                    }
                    if c.state().phase == cc_wallet_app::AppPhase::Unlocked
                        && !c.state().activity.is_empty()
                        && let Some(peer) = pending_chat.borrow_mut().take()
                    {
                        c.handle_command(AppCommand::OpenChat(peer));
                    }
                    if c.state().chat.open
                        && c.state().wallet.is_some()
                        && !c.state().chat.sending
                        && let Some(text) = pending_say.borrow_mut().take()
                    {
                        said_something.set(true);
                        c.handle_command(AppCommand::SetChatDraft(text));
                        c.handle_command(AppCommand::SendChatMessage);
                    }
                    // The reply stops at the signing dialog like any transfer,
                    // so the harness has to sign it the way a person would.
                    if c.state().auth.open
                        && c.state().auth.purpose == cc_wallet_app::AuthPurpose::Send
                        && said_something.get()
                        && let Ok(pw) = std::env::var("CC_WALLET_TEST_PASSWORD")
                    {
                        said_something.set(false);
                        c.handle_command(AppCommand::AuthSubmit {
                            pw: Password::new(pw),
                            pw2: Password::new(String::new()),
                            remember: true,
                        });
                    }
                    {
                        let mut drive = pending_swap_drive.borrow_mut();
                        if !drive.idle() {
                            drive.apply(&mut c);
                        }
                    }
                    {
                        let mut drive = pending_storage_drive.borrow_mut();
                        if !drive.idle() {
                            drive.apply(&mut c);
                        }
                    }
                    if c.state().phase == cc_wallet_app::AppPhase::Unlocked {
                        let mut drive = pending_send_drive.borrow_mut();
                        if !drive.idle() {
                            drive.apply(&mut c);
                        }
                    }
                    if c.state().phase == cc_wallet_app::AppPhase::Unlocked
                        && pending_scan.borrow().is_none()
                        && let Some(hash) = pending_trace.borrow_mut().take()
                    {
                        c.handle_command(AppCommand::TraceTransaction(hash));
                    }
                }
            }
            let form_locked = controller.borrow().send_form_locked();
            sync_ui(
                &ui,
                controller.borrow().state(),
                form_locked,
                &mut cache.borrow_mut(),
            );
            if controller
                .borrow()
                .state()
                .activity
                .iter()
                .any(|e| e.pending)
            {
                let spin = (ui.global::<Anim>().get_spin() + 45.0).rem_euclid(360.0);
                ui.global::<Anim>().set_spin(spin);
                ui.window().request_redraw();
            }
        });
    }

    let result = ui.run();
    let _ = controller.borrow_mut().shutdown();
    result
}

#[cfg(test)]
mod filter_tests {
    use super::*;

    fn event_moving(
        direction: ActivityDirection,
        assets: &[AssetId],
        counterparty: &str,
    ) -> ActivityEvent {
        ActivityEvent {
            direction,
            counterparty: counterparty.to_owned(),
            movements: assets
                .iter()
                .map(|&asset| cc_wallet_app::AssetMovement {
                    amount: match asset {
                        AssetId::Native => cc_wallet_app::AssetAmount::native(1).unwrap(),
                        AssetId::CurrencyCollection(id) => {
                            cc_wallet_app::AssetAmount::currency_collection(
                                id,
                                cc_wallet_app::CcAmount::from_u128(1),
                            )
                        }
                    },
                })
                .collect(),
            fee_native: 1,
            int_msg_hash: Some(cc_wallet_app::Digest32::from_bytes([0xbb; 32])),
            ..ActivityEvent::test_stub(1, 1)
        }
    }

    fn event(direction: ActivityDirection, asset: AssetId, counterparty: &str) -> ActivityEvent {
        event_moving(direction, &[asset], counterparty)
    }

    #[test]
    fn default_filter_is_inactive_and_matches_everything() {
        let f = ActivityFilters::default();
        assert!(!f.any_active());
        assert!(f.matches(&event(ActivityDirection::In, AssetId::Native, "0:x")));
        assert!(f.matches(&event(
            ActivityDirection::Out,
            AssetId::CurrencyCollection(2),
            "0:y"
        )));
    }

    #[test]
    fn direction_filter_selects_one_side() {
        let mut f = ActivityFilters {
            dir: "in".to_owned(),
            ..Default::default()
        };
        assert!(f.any_active());
        assert!(f.matches(&event(ActivityDirection::In, AssetId::Native, "0:x")));
        assert!(!f.matches(&event(ActivityDirection::Out, AssetId::Native, "0:x")));
        f.dir = "out".to_owned();
        assert!(f.matches(&event(ActivityDirection::Out, AssetId::Native, "0:x")));
        assert!(!f.matches(&event(ActivityDirection::In, AssetId::Native, "0:x")));
    }

    #[test]
    fn token_filter_matches_native_or_a_specific_cc() {
        let native = ActivityFilters {
            token: -1,
            ..Default::default()
        };
        assert!(native.matches(&event(ActivityDirection::In, AssetId::Native, "0:x")));
        assert!(!native.matches(&event(
            ActivityDirection::In,
            AssetId::CurrencyCollection(2),
            "0:x"
        )));
        let cc2 = ActivityFilters {
            token: 2,
            ..Default::default()
        };
        assert!(cc2.matches(&event(
            ActivityDirection::In,
            AssetId::CurrencyCollection(2),
            "0:x"
        )));
        assert!(!cc2.matches(&event(
            ActivityDirection::In,
            AssetId::CurrencyCollection(1),
            "0:x"
        )));
        assert!(!cc2.matches(&event(ActivityDirection::In, AssetId::Native, "0:x")));
    }

    #[test]
    fn token_filter_matches_any_movement_of_a_combined_transaction() {
        let combined = event_moving(
            ActivityDirection::In,
            &[AssetId::CurrencyCollection(2), AssetId::Native],
            "0:x",
        );
        let native = ActivityFilters {
            token: -1,
            ..Default::default()
        };
        assert!(native.matches(&combined));
        let cc2 = ActivityFilters {
            token: 2,
            ..Default::default()
        };
        assert!(cc2.matches(&combined));
        let unrelated = ActivityFilters {
            token: 3,
            ..Default::default()
        };
        assert!(!unrelated.matches(&combined));
        assert!(ActivityFilters::default().matches(&combined));
    }

    #[test]
    fn token_zero_is_not_a_cc_filter() {
        let zero = ActivityFilters {
            token: 0,
            ..Default::default()
        };
        assert!(zero.matches(&event(ActivityDirection::In, AssetId::Native, "0:x")));
        assert!(zero.matches(&event(
            ActivityDirection::In,
            AssetId::CurrencyCollection(2),
            "0:x"
        )));
    }

    #[test]
    fn party_filter_matches_the_exact_counterparty() {
        let f = ActivityFilters {
            party: "0:alice".to_owned(),
            ..Default::default()
        };
        assert!(f.any_active());
        assert!(f.matches(&event(ActivityDirection::In, AssetId::Native, "0:alice")));
        assert!(!f.matches(&event(ActivityDirection::In, AssetId::Native, "0:bob")));
    }

    fn active_cache(wallet: &str) -> UiCache {
        UiCache {
            active_wallet: wallet.to_owned(),
            filters: ActivityFilters {
                dir: "out".to_owned(),
                token: 2,
                party: "0:alice".to_owned(),
                party_label: "Alice".to_owned(),
            },
            ..UiCache::default()
        }
    }

    #[test]
    fn wallet_switch_resets_activity_filters() {
        let mut cache = active_cache("A");
        assert!(cache.filters.any_active());
        let reset = cache.sync_active_wallet("B");
        assert!(reset, "switching wallets is an identity change");
        assert_eq!(cache.active_wallet, "B");
        assert!(
            !cache.filters.any_active(),
            "wallet B must not inherit wallet A's filters"
        );
        assert!(cache.filters.party_label.is_empty());
    }

    #[test]
    fn same_wallet_relock_keeps_filters() {
        let mut cache = active_cache("A");
        let reset = cache.sync_active_wallet("A");
        assert!(!reset, "the same wallet identity is not a change");
        assert!(
            cache.filters.any_active(),
            "re-locking and unlocking the same wallet preserves filters"
        );
        assert_eq!(cache.filters.token, 2);
    }
}
