use std::cell::RefCell;
use std::rc::Rc;

use cc_wallet_app::{
    AppCommand, AppController, AppTab, AssetId, Password, SeedInput, contact_address_is_valid,
};
use slint::{ComponentHandle, Model, ModelRc, SharedString, VecModel};
use zeroize::Zeroizing;

use super::render::{fit_fraction, party_pill_label, regroup_amount, ungroup_amount};
use super::sync::sync_ui;
use super::{
    ActivityFilters, AmountFormat, AppWindow, ClipboardBridge, EditFmt, UiCache, UserActivity,
};

fn resync(ui: &AppWindow, controller: &RefCell<AppController>, cache: &RefCell<UiCache>) {
    let form_locked = controller.borrow().send_form_locked();
    sync_ui(
        ui,
        controller.borrow().state(),
        form_locked,
        &mut cache.borrow_mut(),
    );
}

pub(super) fn connect_callbacks(
    ui: &AppWindow,
    controller: Rc<RefCell<AppController>>,
    cache: Rc<RefCell<UiCache>>,
) {
    let apply = {
        let controller = controller.clone();
        let cache = cache.clone();
        move |ui: &AppWindow, cmd: AppCommand| {
            controller.borrow_mut().handle_command(cmd);
            resync(ui, &controller, &cache);
        }
    };

    macro_rules! on0 {
        ($setter:ident, $cmd:expr) => {{
            let weak = ui.as_weak();
            let apply = apply.clone();
            ui.$setter(move || {
                if let Some(ui) = weak.upgrade() {
                    apply(&ui, $cmd);
                }
            });
        }};
    }
    macro_rules! on1 {
        ($setter:ident, $arg:ident, $map:expr) => {{
            let weak = ui.as_weak();
            let apply = apply.clone();
            ui.$setter(move |$arg| {
                if let Some(ui) = weak.upgrade() {
                    apply(&ui, $map);
                }
            });
        }};
    }

    on0!(on_nav_wallet, AppCommand::SelectTab(AppTab::Wallet));
    on0!(on_nav_swap, AppCommand::SelectTab(AppTab::Swap));
    on0!(on_nav_contacts, AppCommand::SelectTab(AppTab::Contacts));
    on0!(on_nav_explorer, AppCommand::SelectTab(AppTab::Explorer));
    on0!(on_nav_storage, AppCommand::SelectTab(AppTab::Storage));
    on0!(on_nav_settings, AppCommand::SelectTab(AppTab::Settings));
    on0!(on_refresh_wallet, AppCommand::RefreshWallet);
    on0!(on_clear_error, AppCommand::ClearError);

    {
        let weak = ui.as_weak();
        let apply = apply.clone();
        ui.on_select_asset(move |id| {
            if let (Some(ui), Some(asset)) = (weak.upgrade(), asset_from_id(id)) {
                apply(&ui, AppCommand::SelectAsset(asset));
            }
        });
    }
    {
        let weak = ui.as_weak();
        let apply = apply.clone();
        ui.on_select_send_token(move |id| {
            if let (Some(ui), Some(asset)) = (weak.upgrade(), asset_from_id(id)) {
                apply(&ui, AppCommand::SelectAsset(asset));
            }
        });
    }
    on1!(
        on_recipient_edited,
        t,
        AppCommand::SetSendDestination(t.to_string())
    );
    on1!(
        on_amount_edited,
        t,
        AppCommand::SetSendAmount(ungroup_amount(&t))
    );
    on1!(
        on_comment_edited,
        t,
        AppCommand::SetSendComment(t.to_string())
    );
    on1!(on_set_encrypt, on, AppCommand::SetEncryptComment(on));
    ui.global::<AmountFormat>()
        .on_int_part(|text| match text.as_str().split_once('.') {
            Some((int, _)) => int.into(),
            None => text,
        });
    ui.global::<AmountFormat>()
        .on_fit_fraction(|frac, groups| fit_fraction(frac.as_str(), groups).into());
    ui.global::<AmountFormat>().on_regroup(|text, cursor| {
        let f = regroup_amount(text.as_str(), cursor);
        EditFmt {
            text: f.text.into(),
            cursor: f.cursor,
        }
    });
    ui.global::<ClipboardBridge>().on_copy_text({
        let weak = ui.as_weak();
        let apply = apply.clone();
        move |text| {
            if let Some(ui) = weak.upgrade() {
                apply(&ui, AppCommand::CopyText(text.to_string()));
            }
        }
    });
    ui.global::<UserActivity>().on_ping({
        let controller = controller.clone();
        move || controller.borrow_mut().note_activity()
    });
    on1!(
        on_pick_contact,
        a,
        AppCommand::SetSendDestination(a.to_string())
    );
    on0!(
        on_clear_recipient,
        AppCommand::SetSendDestination(String::new())
    );
    on0!(on_max_amount, AppCommand::SetMaxAmount);
    on1!(on_set_allow_unbounced, v, AppCommand::SetAllowUnbounced(v));
    on0!(on_request_send, AppCommand::RequestSend);
    {
        let weak = ui.as_weak();
        let apply = apply.clone();
        ui.on_swap_select_from(move |id| {
            if let (Some(ui), Some(asset)) = (weak.upgrade(), asset_from_id(id)) {
                apply(&ui, AppCommand::SetSwapFromToken(asset));
            }
        });
    }
    {
        let weak = ui.as_weak();
        let apply = apply.clone();
        ui.on_swap_select_to(move |id| {
            if let (Some(ui), Some(asset)) = (weak.upgrade(), asset_from_id(id)) {
                apply(&ui, AppCommand::SetSwapToToken(asset));
            }
        });
    }
    on1!(
        on_swap_amount_edited,
        t,
        AppCommand::SetSwapAmount(ungroup_amount(&t))
    );
    on0!(on_swap_max_amount, AppCommand::SetMaxSwapAmount);
    on0!(on_flip_swap, AppCommand::FlipSwap);
    on1!(on_step_slippage, up, AppCommand::StepSwapSlippage(up));
    on1!(
        on_slippage_edited,
        t,
        AppCommand::EditSwapSlippage(t.to_string())
    );
    on0!(on_request_swap, AppCommand::RequestSwap);
    on0!(on_dismiss_swap_receipt, AppCommand::DismissSwapReceipt);
    on0!(on_refresh_storage, AppCommand::RefreshStorage);
    on0!(on_create_storage, AppCommand::CreateStorage);
    on0!(on_add_storage_record, AppCommand::AddStorageRecord);
    on0!(on_clear_storage_form, AppCommand::ClearStorageForm);
    on0!(on_reveal_storage_records, AppCommand::RevealStorageRecords);
    on0!(on_hide_storage_records, AppCommand::HideStorageRecords);
    on1!(
        on_storage_title_edited,
        t,
        AppCommand::SetStorageTitle(t.to_string())
    );
    on1!(
        on_storage_data_edited,
        t,
        AppCommand::SetStorageData(t.to_string())
    );
    on1!(
        on_delete_storage_record,
        id,
        AppCommand::DeleteStorageRecord(id.max(0) as u32)
    );
    on1!(
        on_copy_storage_record,
        id,
        AppCommand::CopyStorageRecord(id.max(0) as u32)
    );
    on0!(on_request_risk_override, AppCommand::RequestRiskOverride);
    {
        let weak = ui.as_weak();
        let apply = apply.clone();
        ui.on_set_risk_overlap(move |index, selected| {
            if let Some(ui) = weak.upgrade() {
                apply(
                    &ui,
                    AppCommand::SetRiskOverlap {
                        index: index.max(0) as usize,
                        selected,
                    },
                );
            }
        });
    }
    {
        let weak = ui.as_weak();
        let apply = apply.clone();
        ui.on_confirm_risk_override(move || {
            if let Some(ui) = weak.upgrade() {
                apply(
                    &ui,
                    AppCommand::ConfirmRiskOverride {
                        typed_confirmation: ui.get_risk_typed_confirmation().to_string(),
                        acknowledge_both_may_debit: ui.get_risk_ack_both_may_debit(),
                        acknowledge_duplicate: ui.get_risk_ack_duplicate(),
                    },
                );
            }
        });
    }
    {
        let weak = ui.as_weak();
        let apply = apply.clone();
        ui.on_cancel_risk_override(move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_risk_typed_confirmation(SharedString::new());
                ui.set_risk_ack_both_may_debit(false);
                ui.set_risk_ack_duplicate(false);
                apply(&ui, AppCommand::CancelRiskOverride);
            }
        });
    }

    on1!(
        on_delete_contact,
        index,
        AppCommand::DeleteContact(index.max(0) as usize)
    );
    {
        let weak = ui.as_weak();
        let apply = apply.clone();
        ui.on_reorder_contacts(move |from, to| {
            if let Some(ui) = weak.upgrade() {
                apply(
                    &ui,
                    AppCommand::ReorderContacts {
                        from: from.max(0) as usize,
                        to: to.max(0) as usize,
                    },
                );
            }
        });
    }
    on1!(on_quick_send, a, AppCommand::QuickSend(a.to_string()));
    {
        let weak = ui.as_weak();
        let apply = apply.clone();
        ui.on_open_in_explorer(move |address, transaction_hash| {
            if let Some(ui) = weak.upgrade() {
                apply(
                    &ui,
                    AppCommand::OpenInExplorer {
                        address: address.to_string(),
                        transaction_hash: transaction_hash.to_string(),
                    },
                );
            }
        });
    }
    ui.on_contact_address_is_valid(move |a| contact_address_is_valid(&a));
    ui.on_contact_matches_search(move |name, address, tag, query| {
        contact_matches_search(&name, &address, &tag, &query)
    });
    {
        let weak = ui.as_weak();
        ui.on_matching_contact_count(move |query| {
            let Some(ui) = weak.upgrade() else {
                return 0;
            };
            let contacts = ui.get_contacts();
            let query = query.trim();
            if query.is_empty() {
                return contacts.row_count() as i32;
            }
            contacts
                .iter()
                .filter(|c| contact_matches_search(&c.name, &c.address, &c.tag, query))
                .count() as i32
        });
    }
    {
        let weak = ui.as_weak();
        ui.on_contact_search_rank(move |index, query, editing| {
            let Some(ui) = weak.upgrade() else {
                return 0;
            };
            let contacts = ui.get_contacts();
            let query = query.trim();
            if query.is_empty() {
                return index;
            }
            contacts
                .iter()
                .take(index.max(0) as usize)
                .enumerate()
                .filter(|(idx, c)| {
                    *idx as i32 == editing
                        || contact_matches_search(&c.name, &c.address, &c.tag, query)
                })
                .count() as i32
        });
    }
    {
        let controller = controller.clone();
        ui.on_contact_conflict(move |index, name, address| {
            let index = (index >= 0).then_some(index as usize);
            controller
                .borrow()
                .state()
                .contact_conflict(index, name.trim(), address.trim())
                .unwrap_or_default()
                .into()
        });
    }
    {
        let weak = ui.as_weak();
        let apply = apply.clone();
        ui.on_save_contact(move |index, name, address, tag| {
            if let Some(ui) = weak.upgrade() {
                apply(
                    &ui,
                    AppCommand::SaveContact {
                        index: (index >= 0).then_some(index as usize),
                        name: name.to_string(),
                        address: address.to_string(),
                        tag: tag.to_string(),
                    },
                );
            }
        });
    }

    ui.on_endpoint_is_valid(move |e| cc_wallet_app::endpoint_is_valid(&e));
    on0!(on_reveal_seed, AppCommand::RevealSeed);
    on0!(on_hide_seed, AppCommand::HideSeed);
    on1!(
        on_copy_seed,
        s,
        AppCommand::CopySeed(SeedInput::new(s.to_string()))
    );
    on0!(on_generate_seed, AppCommand::GenerateSeed);
    on1!(
        on_onboard_import_changed,
        s,
        AppCommand::OnboardImportSeed(SeedInput::new(s.to_string()))
    );
    on1!(on_confirm_backup, v, AppCommand::SetSeedBackupConfirmed(v));
    on0!(on_use_seed, AppCommand::UseSeed);
    on0!(on_discard_seed, AppCommand::DiscardSeed);
    on0!(on_delete_wallet, AppCommand::DeleteWallet);
    on1!(
        on_import_seed,
        s,
        AppCommand::ImportSeed(SeedInput::new(s.to_string()))
    );
    on0!(on_set_password, AppCommand::ChangePasswordRequest);
    on1!(on_set_autolock, m, AppCommand::SetAutosign(m.max(0) as u8));
    on1!(
        on_set_screen_lock,
        m,
        AppCommand::SetScreenLock(m.max(0) as u8)
    );
    on0!(on_lock_now, AppCommand::LockNow);
    on1!(
        on_select_endpoint,
        i,
        AppCommand::SelectEndpoint(i.max(0) as usize)
    );
    on1!(
        on_remove_endpoint,
        u,
        AppCommand::RemoveEndpoint(u.to_string())
    );
    on1!(on_add_endpoint, u, AppCommand::AddEndpoint(u.to_string()));
    on1!(on_test_endpoint, u, AppCommand::TestEndpoint(u.to_string()));
    on1!(
        on_inspect_account,
        a,
        AppCommand::InspectAccount(a.to_string())
    );
    on1!(
        on_trace_transaction,
        h,
        AppCommand::TraceTransaction(h.to_string())
    );
    on0!(on_close_trace, AppCommand::CloseTrace);
    on1!(on_open_chat, peer, AppCommand::OpenChat(peer.to_string()));
    on0!(on_close_chat, AppCommand::CloseChat);
    on1!(
        on_chat_draft_edited,
        t,
        AppCommand::SetChatDraft(t.to_string())
    );
    on0!(on_send_chat_message, AppCommand::SendChatMessage);
    on0!(on_switch_wallet, AppCommand::SwitchWallet);
    on1!(
        on_switch_to_wallet,
        name,
        AppCommand::SwitchToWallet(name.to_string())
    );
    on0!(on_new_wallet_request, AppCommand::NewWalletRequest);
    on0!(on_back_to_picker, AppCommand::BackToPicker);
    on1!(
        on_select_wallet,
        name,
        AppCommand::SelectWallet(name.to_string())
    );
    {
        let weak = ui.as_weak();
        let apply = apply.clone();
        ui.on_delete_wallet_from_picker(move |name, pw| {
            if let Some(ui) = weak.upgrade() {
                let pw = Password::new(pw.to_string());
                apply(
                    &ui,
                    AppCommand::DeleteWalletFromPicker {
                        name: name.to_string(),
                        pw,
                    },
                );
            }
        });
    }
    {
        let weak = ui.as_weak();
        let apply = apply.clone();
        ui.on_unlock(move |pw| {
            if let Some(ui) = weak.upgrade() {
                let pw = Password::new(pw.to_string());
                ui.set_lock_pw(SharedString::new());
                apply(&ui, AppCommand::Unlock(pw));
            }
        });
    }
    {
        let weak = ui.as_weak();
        let apply = apply.clone();
        ui.on_create_wallet(move |name, network_id, workchain, pw, pw2| {
            if let Some(ui) = weak.upgrade() {
                let command = AppCommand::CreateWallet {
                    name: name.to_string(),
                    network_id,
                    workchain: workchain as i8,
                    pw: Password::new(pw.to_string()),
                    pw2: Password::new(pw2.to_string()),
                };
                ui.set_lock_pw(SharedString::new());
                ui.set_lock_pw2(SharedString::new());
                apply(&ui, command);
            }
        });
    }
    {
        let weak = ui.as_weak();
        let apply = apply.clone();
        ui.on_toggle_asset(move |id, visible| {
            if id >= 1
                && let Some(ui) = weak.upgrade()
            {
                apply(
                    &ui,
                    AppCommand::SetAssetVisibility {
                        cc_id: id as u32,
                        visible,
                    },
                );
            }
        });
    }

    {
        let weak = ui.as_weak();
        ui.on_import_edited(move || {
            if let Some(ui) = weak.upgrade() {
                let words = ui.get_import_words();
                let filled = words.iter().all(|w| w.split_whitespace().count() == 1);
                let valid = filled && {
                    let phrase = SeedInput::from(join_seed_words(&words));
                    cc_wallet_app::seed_phrase_is_valid(phrase.expose_secret())
                };
                ui.set_import_filled(filled);
                ui.set_import_valid(valid);
            }
        });
    }
    {
        let weak = ui.as_weak();
        let apply = apply.clone();
        ui.on_import_submit(move || {
            if let Some(ui) = weak.upgrade() {
                let phrase = SeedInput::from(join_seed_words(&ui.get_import_words()));
                apply(&ui, AppCommand::ImportSeed(phrase));
                ui.set_import_words(ModelRc::from(Rc::new(VecModel::from(vec![
                    SharedString::new();
                    12
                ]))));
                ui.set_import_valid(false);
                ui.set_import_filled(false);
            }
        });
    }
    ui.on_distribute_seed(move |t| ModelRc::from(Rc::new(VecModel::from(distribute_words(&t)))));

    ui.on_import_cell_edited(move |index, text, current| {
        let grid = merge_cell_edit(index, &text, current.iter().collect());
        ModelRc::from(Rc::new(VecModel::from(grid)))
    });

    {
        let weak = ui.as_weak();
        let controller = controller.clone();
        let cache = cache.clone();
        ui.on_onboard_generate(move || match cc_wallet_app::generate_seed_phrase() {
            Ok(seed) => ModelRc::from(Rc::new(VecModel::from(distribute_words(
                seed.expose_secret(),
            )))),
            Err(error) => {
                controller
                    .borrow_mut()
                    .surface_error(format!("failed to generate seed: {error}"));
                if let Some(ui) = weak.upgrade() {
                    resync(&ui, &controller, &cache);
                }
                ModelRc::from(Rc::new(VecModel::from(distribute_words(""))))
            }
        });
    }
    {
        let weak = ui.as_weak();
        let apply = apply.clone();
        ui.on_onboard_stage_from_grid(move || {
            if let Some(ui) = weak.upgrade() {
                let phrase = SeedInput::from(join_seed_words(&ui.get_import_words()));
                apply(&ui, AppCommand::OnboardImportSeed(phrase));
            }
        });
    }
    {
        let weak = ui.as_weak();
        let apply = apply.clone();
        ui.on_copy_seed_from_grid(move || {
            if let Some(ui) = weak.upgrade() {
                let phrase = SeedInput::from(join_seed_words(&ui.get_import_words()));
                apply(&ui, AppCommand::CopySeed(phrase));
            }
        });
    }

    {
        let weak = ui.as_weak();
        let apply = apply.clone();
        ui.on_auth_cancel(move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_auth_pw(SharedString::new());
                ui.set_auth_pw2(SharedString::new());
                apply(&ui, AppCommand::AuthCancel);
            }
        });
    }
    {
        let weak = ui.as_weak();
        let apply = apply.clone();
        ui.on_auth_submit(move || {
            if let Some(ui) = weak.upgrade() {
                let cmd = AppCommand::AuthSubmit {
                    pw: Password::new(ui.get_auth_pw().to_string()),
                    pw2: Password::new(ui.get_auth_pw2().to_string()),
                    remember: ui.get_auth_remember(),
                };
                ui.set_auth_pw(SharedString::new());
                ui.set_auth_pw2(SharedString::new());
                apply(&ui, cmd);
            }
        });
    }

    let resync = {
        let controller = controller.clone();
        let cache = cache.clone();
        move |ui: &AppWindow| {
            resync(ui, &controller, &cache);
        }
    };
    {
        let weak = ui.as_weak();
        let controller = controller.clone();
        let cache = cache.clone();
        let resync = resync.clone();
        ui.on_activity_set_dir(move |dir| {
            if let Some(ui) = weak.upgrade() {
                controller.borrow_mut().note_activity();
                cache.borrow_mut().filters.dir = dir.to_string();
                resync(&ui);
            }
        });
    }
    {
        let weak = ui.as_weak();
        let controller = controller.clone();
        let cache = cache.clone();
        let resync = resync.clone();
        ui.on_activity_set_token(move |token| {
            if let Some(ui) = weak.upgrade() {
                controller.borrow_mut().note_activity();
                cache.borrow_mut().filters.token = token;
                resync(&ui);
            }
        });
    }
    {
        let weak = ui.as_weak();
        let controller = controller.clone();
        let cache = cache.clone();
        let resync = resync.clone();
        ui.on_activity_set_party(move |addr| {
            if let Some(ui) = weak.upgrade() {
                controller.borrow_mut().note_activity();
                let addr = addr.to_string();
                let label = party_pill_label(&addr, &controller.borrow().state().contacts);
                {
                    let mut cache = cache.borrow_mut();
                    cache.filters.party = addr;
                    cache.filters.party_label = label;
                }
                resync(&ui);
            }
        });
    }
    {
        let weak = ui.as_weak();
        let controller = controller.clone();
        let cache = cache.clone();
        ui.on_activity_clear_filters(move || {
            if let Some(ui) = weak.upgrade() {
                controller.borrow_mut().note_activity();
                cache.borrow_mut().filters = ActivityFilters::default();
                resync(&ui);
            }
        });
    }
}

fn contact_matches_search(name: &str, address: &str, tag: &str, query: &str) -> bool {
    let query = query.trim().to_lowercase();
    if query.is_empty() {
        return true;
    }
    name.to_lowercase().contains(&query)
        || address.to_lowercase().contains(&query)
        || tag.to_lowercase().contains(&query)
}

fn merge_cell_edit(index: i32, text: &str, current: Vec<SharedString>) -> Vec<SharedString> {
    let words: Vec<&str> = text.split_whitespace().collect();
    if words.len() <= 1 {
        let mut grid = current;
        if let Some(slot) = usize::try_from(index).ok().and_then(|i| grid.get_mut(i)) {
            *slot = SharedString::from(text);
        }
        return grid;
    }
    if current.iter().all(|w| w.trim().is_empty()) {
        return distribute_words(text);
    }
    let mut grid = current;
    if let Ok(start) = usize::try_from(index)
        && start + words.len() <= grid.len()
    {
        for (offset, word) in words.iter().enumerate() {
            grid[start + offset] = SharedString::from(*word);
        }
    }
    grid
}

fn distribute_words(text: &str) -> Vec<SharedString> {
    let words: Vec<&str> = text.split_whitespace().collect();
    if words.len() > 12 {
        return vec![SharedString::new(); 12];
    }
    let mut words: Vec<SharedString> = words.into_iter().map(SharedString::from).collect();
    while words.len() < 12 {
        words.push(SharedString::new());
    }
    words
}

fn join_seed_words(words: &ModelRc<SharedString>) -> Zeroizing<String> {
    let mut len = 0usize;
    let mut count = 0usize;
    for word in words.iter() {
        let trimmed = word.trim();
        if trimmed.is_empty() {
            continue;
        }
        if count > 0 {
            len += 1;
        }
        len += trimmed.len();
        count += 1;
    }
    let mut phrase = Zeroizing::new(String::with_capacity(len));
    let mut first = true;
    for word in words.iter() {
        let trimmed = word.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !first {
            phrase.push(' ');
        }
        phrase.push_str(trimmed);
        first = false;
    }
    phrase
}

fn asset_from_id(id: i32) -> Option<AssetId> {
    match id {
        -1 => Some(AssetId::Native),
        id if id >= 1 && AssetId::CurrencyCollection(id as u32).is_known_cc() => {
            Some(AssetId::CurrencyCollection(id as u32))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_seed_words_allocates_exactly_once() {
        let words: Vec<SharedString> = [
            "  abandon ",
            "ability",
            "able",
            "about",
            "above",
            "absent",
            "absorb ",
            "abstract",
            "absurd",
            "abuse",
            "",
            "",
        ]
        .into_iter()
        .map(SharedString::from)
        .collect();
        let model = ModelRc::from(Rc::new(VecModel::from(words)));

        let phrase = join_seed_words(&model);

        assert_eq!(
            phrase.as_str(),
            "abandon ability able about above absent absorb abstract absurd abuse"
        );
        assert_eq!(
            phrase.capacity(),
            phrase.len(),
            "join_seed_words must allocate exactly once"
        );
    }

    #[test]
    fn contact_matches_search_is_case_insensitive_across_fields() {
        assert!(contact_matches_search("Alice", "0:abc", "friend", "  "));
        assert!(contact_matches_search("Alice", "0:abc", "friend", "ALI"));
        assert!(contact_matches_search(
            "Alice", "0:ABCdef", "friend", "abcd"
        ));
        assert!(contact_matches_search(
            "Alice",
            "0:abc",
            "Work Friend",
            "friend"
        ));
        assert!(!contact_matches_search("Alice", "0:abc", "friend", "zzz"));
    }

    #[test]
    fn distribute_words_pads_short_and_rejects_overlong() {
        let three = distribute_words("one two three");
        assert_eq!(three.len(), 12);
        assert_eq!(three[0], "one");
        assert_eq!(three[2], "three");
        assert_eq!(three[3], "");

        let twelve = distribute_words(
            &(1..=12)
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(" "),
        );
        assert_eq!(twelve[11], "12", "exactly twelve words fill the grid");

        let many = distribute_words(
            &(1..=24)
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(" "),
        );
        assert_eq!(many.len(), 12);
        assert!(
            many.iter().all(|w| w.is_empty()),
            "an over-long paste is rejected, not silently truncated"
        );
    }

    fn grid(cells: &[&str]) -> Vec<SharedString> {
        cells.iter().map(|s| SharedString::from(*s)).collect()
    }

    fn as_strs(grid: &[SharedString]) -> Vec<&str> {
        grid.iter().map(|s| s.as_str()).collect()
    }

    #[test]
    fn multiword_paste_fills_from_edited_cell_preserving_others() {
        let current = grid(&[
            "w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7", "w8", "w9", "", "",
        ]);
        let out = merge_cell_edit(10, "eleven twelve", current);
        assert_eq!(
            as_strs(&out),
            vec![
                "w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7", "w8", "w9", "eleven", "twelve"
            ]
        );
    }

    #[test]
    fn multiword_paste_that_does_not_fit_leaves_grid_unchanged() {
        let current = grid(&["a", "b", "c", "", "", "", "", "", "", "", "", ""]);
        let thirteen = "n1 n2 n3 n4 n5 n6 n7 n8 n9 n10 n11 n12 n13";
        let out = merge_cell_edit(5, thirteen, current.clone());
        assert_eq!(as_strs(&out), as_strs(&current));
    }

    #[test]
    fn whole_phrase_paste_into_empty_grid_distributes_from_zero() {
        let empty = grid(&["", "", "", "", "", "", "", "", "", "", "", ""]);
        let phrase = "one two three four five six seven eight nine ten eleven twelve";
        let out = merge_cell_edit(3, phrase, empty);
        assert_eq!(out[0], "one");
        assert_eq!(out[11], "twelve");
    }

    #[test]
    fn typed_space_does_not_wipe_other_cells() {
        let current = grid(&["zoo", "", "", "", "", "", "", "", "", "", "", ""]);
        let out = merge_cell_edit(0, "zoo abandon", current);
        assert_eq!(out[0], "zoo");
        assert_eq!(out[1], "abandon");
        assert!(
            as_strs(&out)[2..].iter().all(|c| c.is_empty()),
            "the untouched trailing cells stay blank"
        );
    }

    #[test]
    fn seed_chips_resync_after_every_grid_rewrite() {
        let chip = include_str!("../../ui/pages/settings_components.slint");
        assert!(chip.contains("in property <int> resync_gen"));
        assert!(chip.contains("changed resync_gen => { fld.set_text(root.word); }"));
        for grid_src in [
            include_str!("../../ui/components/lock_screen.slint"),
            include_str!("../../ui/pages/settings_page.slint"),
        ] {
            assert!(grid_src.contains("resync_gen: root.import_gen;"));
            assert_eq!(
                grid_src.matches("root.import_gen += 1;").count(),
                4,
                "each of the four import_words rewrites bumps import_gen"
            );
        }
    }

    #[test]
    fn asset_from_id_accepts_only_supported_control_ids() {
        assert_eq!(asset_from_id(-1), Some(AssetId::Native));
        assert_eq!(asset_from_id(1), Some(AssetId::CurrencyCollection(1)));
        assert_eq!(asset_from_id(3), Some(AssetId::CurrencyCollection(3)));
        assert_eq!(asset_from_id(-2), None);
        assert_eq!(asset_from_id(0), None);
        assert_eq!(asset_from_id(4), None);
    }

    #[test]
    fn pointer_interactions_refresh_the_idle_lock_window() {
        let flick = "flicked => { UserActivity.ping(); }";
        let scroll = "scrolled => { UserActivity.ping(); }";

        let app = include_str!("../../ui/app.slint");
        assert!(
            app.contains(flick),
            "the main page Flickable pings on flick"
        );

        let sections = include_str!("../../ui/pages/wallet_sections.slint");
        assert!(
            sections.contains(scroll),
            "the asset/activity ScrollViews ping"
        );
        assert_eq!(
            sections.matches(scroll).count(),
            3,
            "every scrollable region of the wallet page keeps the session awake: assets, \
             activity, and the conversation read over it — a scroll that does not count as \
             use is a wallet that locks while it is being read"
        );

        let contacts = include_str!("../../ui/pages/contacts_page.slint");
        assert!(
            contacts.contains(scroll),
            "the contacts list pings on scroll"
        );
        assert_eq!(
            contacts.matches("UserActivity.ping();").count(),
            3,
            "the contacts list scroll and both drag handlers each ping"
        );

        let menus = include_str!("../../ui/pages/wallet_menus.slint");
        assert!(menus.contains(flick) && menus.contains(scroll));
        assert_eq!(
            menus.matches("UserActivity.ping();").count(),
            3,
            "the wallet-switch Flickable and both menu ScrollViews each ping"
        );

        let picker = include_str!("../../ui/components/wallet_picker.slint");
        assert!(
            picker.contains(flick),
            "the wallet-picker list pings on flick"
        );

        let page = include_str!("../../ui/pages/wallet_page.slint");
        for open in [
            "open_wallet_menu => { UserActivity.ping();",
            "open_book => { UserActivity.ping();",
            "open_token => { UserActivity.ping();",
            "open_token_filter => { UserActivity.ping();",
            "open_party_filter => { UserActivity.ping();",
        ] {
            assert!(
                page.contains(open),
                "wallet_page popup-open must ping: {open}"
            );
        }
    }

    #[test]
    fn activity_filter_callbacks_note_activity() {
        let src = include_str!("callbacks.rs");
        for reg in [
            "on_activity_set_dir(move",
            "on_activity_set_token(move",
            "on_activity_set_party(move",
            "on_activity_clear_filters(move",
        ] {
            let start = src
                .find(reg)
                .unwrap_or_else(|| panic!("callback {reg} exists"));
            let body = &src[start..(start + 400).min(src.len())];
            assert!(
                body.contains("note_activity()"),
                "callback {reg} must refresh the idle-lock window"
            );
        }
    }

    #[test]
    fn contacts_edit_row_is_counted_in_the_list_height() {
        let contacts = include_str!("../../ui/pages/contacts_page.slint");
        assert!(contacts.contains("property <bool> edited_row_matches:"));
        assert!(
            contacts.contains("root.editing >= 0 && !root.edited_row_matches ? 1 : 0"),
            "visible_row_count must reserve a slot for a non-matching edited row"
        );
    }

    #[test]
    fn contact_picker_sizes_from_the_filtered_count_with_a_no_matches_state() {
        let menus = include_str!("../../ui/pages/wallet_menus.slint");
        assert!(menus.contains("property <int> shown:"));
        assert!(
            menus.contains("height: min(root.shown * 48px - 2px, 240px);"),
            "the picker height sizes from the shown count"
        );
        assert!(
            menus.contains("viewport-height: max(0px, root.shown * 48px - 2px);"),
            "the picker viewport sizes from the same shown count"
        );
        assert!(menus.contains("No matching contacts"));
    }

    #[test]
    fn unhandled_escape_bubbles_out_of_fields() {
        let widgets = include_str!("../../ui/widgets.slint");
        assert!(widgets.contains("in property <bool> handles_escape: false;"));
        assert!(widgets.contains("if (root.handles_escape) {"));
        let esc = widgets
            .find("event.text == Key.Escape")
            .expect("the Escape branch exists");
        assert!(
            widgets[esc..(esc + 200).min(widgets.len())].contains("return reject;"),
            "an unhandled Escape is rejected so it bubbles"
        );
        for src in [
            include_str!("../../ui/components/auth_modal.slint"),
            include_str!("../../ui/pages/contacts_components.slint"),
        ] {
            assert_eq!(
                src.matches("escape_pressed =>").count(),
                src.matches("handles_escape: true;").count(),
                "each escape_pressed wiring site sets handles_escape: true"
            );
        }
    }

    #[test]
    fn activity_filter_pill_x_clears_instead_of_opening_the_dropdown() {
        let sections = include_str!("../../ui/pages/wallet_sections.slint");
        for (open, clear) in [
            ("root.open_party_filter()", "root.clear_party()"),
            ("root.open_token_filter()", "root.clear_token()"),
        ] {
            let o = sections
                .find(open)
                .unwrap_or_else(|| panic!("{open} present"));
            let c = sections
                .find(clear)
                .unwrap_or_else(|| panic!("{clear} present"));
            assert!(
                o < c,
                "the {open} pill TouchArea must be declared before {clear} so the × is clickable"
            );
        }
    }

    #[test]
    fn contact_menu_rows_elide_the_name_so_the_tag_stays_visible() {
        let menus = include_str!("../../ui/pages/wallet_menus.slint");
        let name_columns: Vec<&str> = menus.split("Text { text: c.name;").skip(1).collect();
        assert_eq!(
            name_columns.len(),
            2,
            "both the ContactPickerMenu and ActivityPartyMenu declare a c.name column"
        );
        for column in name_columns {
            let decl = &column[..column.find('}').expect("the name Text closes")];
            assert!(
                decl.contains("overflow: elide;"),
                "each name column elides so the tag chip stays visible"
            );
        }
    }

    #[test]
    fn checkbox_is_a_shared_widget_gated_on_busy() {
        let widgets = include_str!("../../ui/widgets.slint");
        assert!(widgets.contains("export component Checkbox inherits Rectangle {"));

        let auth = include_str!("../../ui/components/auth_modal.slint");
        let risk = include_str!("../../ui/components/risk_modal.slint");
        let lock = include_str!("../../ui/components/lock_screen.slint");
        assert_eq!(auth.matches("Checkbox {").count(), 2);
        assert_eq!(risk.matches("Checkbox {").count(), 3);
        assert_eq!(lock.matches("Checkbox {").count(), 1);

        for checked in ["checked: root.allow_unbounced;", "checked: root.remember;"] {
            let start = auth
                .find(checked)
                .unwrap_or_else(|| panic!("{checked} present"));
            let block = &auth[start..(start + 160).min(auth.len())];
            assert!(
                block.contains("enabled: !root.busy;"),
                "{checked} must gate on busy"
            );
        }
    }

    #[test]
    fn dead_and_twin_ui_properties_are_gone() {
        let app = include_str!("../../ui/app.slint");
        assert!(!app.contains("password_set"), "password_set is deleted");
        assert!(!app.contains("activity_count"), "activity_count is deleted");

        let sync = include_str!("sync.rs");
        assert_eq!(
            sync.matches("ui.set_contacts(").count(),
            1,
            "exactly one contacts model setter remains"
        );
        assert!(
            !sync.contains("set_address_book"),
            "the address_book twin setter is deleted"
        );
        assert!(
            !sync.contains("set_password_set") && !sync.contains("set_activity_count"),
            "the dead password_set/activity_count setters are deleted"
        );

        let page = include_str!("../../ui/pages/wallet_page.slint");
        assert!(!page.contains("paste_timer"), "dead paste_timer is deleted");
        assert!(
            !page.contains("expanded_hash"),
            "dead expanded_hash is deleted"
        );
        assert!(
            !page.contains("party_prefix"),
            "the uncalled party_prefix copy is deleted"
        );
    }

    #[test]
    fn endpoint_add_gate_and_typographic_minus() {
        let settings = include_str!("../../ui/pages/settings_page.slint");
        assert!(
            settings.contains("accepted => { if (root.new_endpoint != \"\")"),
            "the endpoint Field gates Enter-submit on a non-empty value"
        );
        let test_btn = settings
            .find("label: \"Test\"")
            .expect("the Test button exists");
        assert!(
            settings[test_btn..(test_btn + 160).min(settings.len())]
                .contains("enabled: root.new_endpoint != \"\""),
            "the Test button is disabled while the endpoint field is empty"
        );

        let components = include_str!("../../ui/pages/wallet_components.slint");
        assert!(
            components.contains("sign: root.item.is_in ? \"+\" : \"\u{2212}\""),
            "the on-screen sign keeps the typographic U+2212 minus"
        );
    }
}
