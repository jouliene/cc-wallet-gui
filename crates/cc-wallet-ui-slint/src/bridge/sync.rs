use std::rc::Rc;

use cc_wallet_app::{
    AccountInspection, AccountTrace, ActivityEvent, AppPhase, AppState, AppTab, AssetAmount,
    AssetId, AuthMode, AuthPurpose, CcAmount, CoinSupply, DecodedContract, DecodedValue,
    DestinationAccountStatus, LiveStatus, MAX_RECORD_DATA_BYTES, MAX_RECORD_TITLE_BYTES,
    MAX_SLIPPAGE_BPS, MAX_STORAGE_RECORDS, NetworkStats, RecipientCheck, all_supported_assets,
    asset_meta, canonicalize_recipient, fmt_duration, format_fixed9_amount, format_native_fixed9,
    known_cc_assets,
};
use slint::{ModelRc, SharedString, VecModel};

use super::render::{
    activity_rows, asset_row, asset_tone, contact_row, display_send_amount, explorer_tx_rows,
    fmt_datetime, group_digits, group_editable, movement_meta, pool_reserve_row, seed_exposure,
    short_addr, today_bucket, token_amount, token_units, trace_edges, trace_parties, units_exact,
};
use super::{
    AccountView, ActivityFilters, ActivityRow, AppWindow, AssetRow, ContactRow, CurrencyRow,
    FieldRow, NetworkStatsView, RiskOverlapRow, StorageRow, TokenAmount, TraceEdgeRow,
    TracePartyCol, UiCache,
};

fn empty_import_words() -> ModelRc<SharedString> {
    ModelRc::from(Rc::new(VecModel::from(vec![SharedString::new(); 12])))
}

fn clear_import_models(ui: &AppWindow) {
    ui.set_import_words(empty_import_words());
    ui.set_import_valid(false);
    ui.set_import_filled(false);
}

fn entering_unlocked_with_entry_secrets(phase: AppPhase, was_locked: bool) -> bool {
    phase == AppPhase::Unlocked && was_locked
}

fn leaving_onboarding_with_entry_secrets(phase: AppPhase, was_onboarding: bool) -> bool {
    phase != AppPhase::Onboarding && was_onboarding
}

fn leaving_settings_with_entry_secrets(tab: AppTab, was_settings: bool) -> bool {
    tab != AppTab::Settings && was_settings
}

fn seed_models_need_refresh(current_text: &str, desired_text: &str) -> bool {
    current_text != desired_text
}

fn activity_change_hash(
    filtered: &[&ActivityEvent],
    filters: &ActivityFilters,
    contacts_rev: u64,
    wallet_address: &str,
    today_bucket: i64,
) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for event in filtered {
        event.hash(&mut hasher);
    }
    filters.dir.hash(&mut hasher);
    filters.token.hash(&mut hasher);
    filters.party.hash(&mut hasher);
    contacts_rev.hash(&mut hasher);
    wallet_address.hash(&mut hasher);
    today_bucket.hash(&mut hasher);
    hasher.finish()
}

fn risk_rows_changed(
    cache: &(Vec<String>, Vec<bool>),
    labels: &[String],
    selected: &[bool],
) -> bool {
    cache.0.as_slice() != labels || cache.1.as_slice() != selected
}

fn error_banner(state: &AppState) -> (String, bool) {
    let banner = match (
        &state.persistence_error,
        &state.history_integrity_error,
        &state.error,
    ) {
        (Some(error), _, _) => error.clone(),
        (None, Some(error), _) => error.clone(),
        (None, None, Some(error)) => return (error.clone(), true),
        (None, None, None) if state.history_corrupt => {
            "Your saved transaction history could not be read and may be corrupt. \
             It will be rebuilt from the network; recent activity may be missing until then."
                .to_owned()
        }
        (None, None, None) if state.history_incomplete => {
            "Some transaction history could not be loaded, so the list may be incomplete. \
             Try again in a moment."
                .to_owned()
        }
        (None, None, None) if state.kdf_weak => {
            "This wallet uses weaker-than-recommended encryption settings. Change its password \
             in Settings to re-secure it with the current defaults."
                .to_owned()
        }
        (None, None, None) => String::new(),
    };
    (banner, false)
}

fn live_badge_enabled(state: &AppState) -> bool {
    matches!(state.live_status, LiveStatus::Live) && state.snapshot_refresh_error.is_none()
}

fn wallet_asset_ids(state: &AppState) -> Vec<AssetId> {
    std::iter::once(AssetId::Native)
        .chain(known_cc_assets().into_iter().filter_map(|meta| {
            let id = meta.id.cc_id()?;
            state.visible_cc_assets.contains(&id).then_some(meta.id)
        }))
        .collect()
}

fn boc_preview(boc: &str) -> String {
    if boc.chars().count() <= 31 {
        return boc.to_owned();
    }
    let head: String = boc.chars().take(17).collect();
    let tail: String = boc
        .chars()
        .rev()
        .take(12)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{head}…{tail}")
}

fn human_size(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    }
}

fn render_explorer_account(ui: &AppWindow, state: &AppState, cache: &mut UiCache, now: u64) {
    let arrived = state.account_detail.is_some() && !state.inspected_address.is_empty();
    if arrived && cache.inspected_address != state.inspected_address {
        cache.inspected_address.clone_from(&state.inspected_address);
        ui.set_expl_address(SharedString::new());
    }
    ui.set_expl_loading(state.account_loading);
    ui.set_expl_error(state.account_error.clone().unwrap_or_default().into());
    ui.set_expl_network(network_stats_view(state.network_stats.as_ref(), now as u32));

    ui.set_expl_txs_loading(state.account_txs_loading);
    ui.set_expl_txs_error(state.account_txs_error.clone().unwrap_or_default().into());
    ui.set_expl_txs_skipped(state.account_txs_skipped as i32);

    let wallet_address = state.wallet_address().unwrap_or_default();
    let txs_hash = explorer_change_hash(
        &state.account_txs,
        wallet_address,
        cache.contacts_rev,
        today_bucket(now),
    );
    if cache.explorer_txs_hash != txs_hash {
        cache.explorer_txs_hash = txs_hash;
        ui.set_expl_txs(ModelRc::from(Rc::new(VecModel::from(explorer_tx_rows(
            &state.account_txs,
            wallet_address,
            &state.contacts,
            now,
        )))));
    }
    render_explorer_trace(ui, state, cache);

    let account_hash = explorer_change_hash(
        &state.account_detail,
        &state.inspected_address,
        cache.contacts_rev,
        0,
    );
    if cache.explorer_account_hash == account_hash {
        return;
    }
    cache.explorer_account_hash = account_hash;

    let Some(detail) = &state.account_detail else {
        ui.set_expl_has_account(false);
        ui.set_expl_account(AccountView::default());
        ui.set_expl_currencies(ModelRc::from(Rc::new(VecModel::from(
            Vec::<CurrencyRow>::new(),
        ))));
        ui.set_expl_contract_fields(ModelRc::from(Rc::new(VecModel::from(
            Vec::<FieldRow>::new(),
        ))));
        return;
    };
    ui.set_expl_has_account(true);
    ui.set_expl_account(account_view(detail, &state.inspected_address));
    ui.set_expl_contract_fields(ModelRc::from(Rc::new(VecModel::from(contract_fields(
        detail.decoded.as_ref(),
    )))));

    let rows: Vec<CurrencyRow> = detail
        .extra_balance
        .iter()
        .map(|(&id, units)| CurrencyRow {
            label: format!("Currency #{id}").into(),
            amount: currency_amount(id, units),
        })
        .collect();
    ui.set_expl_currencies(ModelRc::from(Rc::new(VecModel::from(rows))));
}

fn explorer_change_hash<T: std::hash::Hash>(
    data: &T,
    wallet_address: &str,
    contacts_rev: u64,
    today_bucket: i64,
) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    data.hash(&mut hasher);
    wallet_address.hash(&mut hasher);
    contacts_rev.hash(&mut hasher);
    today_bucket.hash(&mut hasher);
    hasher.finish()
}

fn render_explorer_trace(ui: &AppWindow, state: &AppState, cache: &mut UiCache) {
    let open = state.trace_loading || state.trace.is_some() || state.trace_error.is_some();
    ui.set_expl_trace_open(open);
    ui.set_expl_trace_loading(state.trace_loading);
    ui.set_expl_trace_error(state.trace_error.clone().unwrap_or_default().into());
    ui.set_expl_trace_hash(state.trace_hash.clone().into());

    let trace_hash = explorer_change_hash(
        &state.trace,
        state.wallet_address().unwrap_or_default(),
        cache.contacts_rev,
        0,
    );
    if cache.explorer_trace_hash == trace_hash {
        return;
    }
    cache.explorer_trace_hash = trace_hash;

    let Some(trace) = &state.trace else {
        ui.set_expl_trace_parties(ModelRc::from(Rc::new(VecModel::from(
            Vec::<TracePartyCol>::new(),
        ))));
        ui.set_expl_trace_edges(ModelRc::from(Rc::new(VecModel::from(
            Vec::<TraceEdgeRow>::new(),
        ))));
        ui.set_expl_trace_summary(Default::default());
        return;
    };
    ui.set_expl_trace_parties(ModelRc::from(Rc::new(VecModel::from(trace_parties(
        trace,
        state.wallet_address().unwrap_or_default(),
        &state.contacts,
    )))));
    ui.set_expl_trace_edges(ModelRc::from(Rc::new(VecModel::from(trace_edges(trace)))));
    ui.set_expl_trace_summary(trace_summary(trace).into());
}

fn trace_summary(trace: &AccountTrace) -> String {
    let transactions = trace.transactions();
    let mut parts = vec![
        format!(
            "{transactions} {}",
            if transactions == 1 {
                "transaction"
            } else {
                "transactions"
            }
        ),
        format!(
            "{} {}",
            trace.edges.len(),
            if trace.edges.len() == 1 {
                "message"
            } else {
                "messages"
            }
        ),
        format!(
            "{} COIN in fees",
            group_digits(
                &format_native_fixed9(trace.total_fees_native)
                    .expect("a decoded trace fee is in the native domain")
            )
        ),
    ];
    if trace.failed > 0 {
        parts.push(format!("{} failed", trace.failed));
    }
    if trace.unexecuted > 0 {
        parts.push(format!("{} not executed", trace.unexecuted));
    }
    if trace.truncated {
        parts.push("cut off at the walk limit".to_owned());
    }
    parts.join(" · ")
}

fn network_stats_view(stats: Option<&NetworkStats>, now: u32) -> NetworkStatsView {
    let Some(stats) = stats else {
        return NetworkStatsView {
            validators: UNKNOWN_FIGURE.into(),
            stake_ratio: UNKNOWN_FIGURE.into(),
            supply_note: "Reading network figures…".into(),
            ..NetworkStatsView::default()
        };
    };
    let supply = stats.supply.as_ref();
    let ratio = stake_share(stats.total_stake, supply);
    NetworkStatsView {
        validators: stats.validators.to_string().into(),
        has_stake: stats.total_stake.is_some(),
        total_stake: native_amount(stats.total_stake.unwrap_or_default()),
        has_supply: supply.is_some(),
        total_supply: native_amount(supply.map_or(0, |supply| supply.total)),
        stake_ratio: ratio.unwrap_or_else(|| UNKNOWN_FIGURE.to_owned()).into(),
        supply_note: supply
            .map(|supply| supply_note(supply, now))
            .unwrap_or_else(|| "Supply could not be read from this endpoint".to_owned())
            .into(),
    }
}

const UNKNOWN_FIGURE: &str = "—";

fn stake_share(stake: Option<u128>, supply: Option<&CoinSupply>) -> Option<String> {
    let (stake, supply) = (stake?, supply?.total);
    if supply == 0 {
        return None;
    }
    let scaled = (stake.checked_mul(1_000_000)? + supply / 2) / supply;
    Some(format!("{}.{:04}%", scaled / 10_000, scaled % 10_000))
}

fn supply_note(supply: &CoinSupply, now: u32) -> String {
    let seqno = supply.seqno;
    let age = now.saturating_sub(supply.gen_utime);
    if supply.gen_utime == 0 || age < 60 {
        format!("Supply at key block {seqno} : just now")
    } else {
        format!("Supply at key block {seqno} : {} ago", fmt_duration(age))
    }
}

fn native_amount(units: u128) -> TokenAmount {
    let exact = format_native_fixed9(units).unwrap_or_else(|_| units.to_string());
    token_amount(AssetId::Native, &exact)
}

fn contract_fields(decoded: Option<&DecodedContract>) -> Vec<FieldRow> {
    let Some(contract) = decoded else {
        return Vec::new();
    };
    contract
        .fields
        .iter()
        .map(|field| FieldRow {
            label: field.label.clone().into(),
            value: match &field.value {
                DecodedValue::Text(text) => text.clone().into(),
                DecodedValue::Data(text) => text.clone().into(),
                DecodedValue::Moment(0) => "Never".into(),
                DecodedValue::Moment(seconds) => fmt_datetime(*seconds).into(),
                DecodedValue::Amount(decimal) => group_digits(decimal).into(),
            },
            mono: matches!(field.value, DecodedValue::Data(_)),
            copyable: matches!(field.value, DecodedValue::Data(_)),
        })
        .collect()
}

fn currency_amount(id: u32, units: &str) -> TokenAmount {
    let exact = CcAmount::try_from_canonical_decimal(units)
        .ok()
        .map(|amount| AssetAmount::currency_collection(id, amount))
        .and_then(|amount| format_fixed9_amount(&amount).ok())
        .unwrap_or_else(|| units.to_owned());
    token_amount(AssetId::CurrencyCollection(id), &exact)
}

fn account_view(detail: &AccountInspection, typed_address: &str) -> AccountView {
    let address =
        canonicalize_recipient(typed_address).unwrap_or_else(|_| typed_address.to_owned());
    let last_paid = if detail.last_paid == 0 {
        String::new()
    } else {
        fmt_datetime(detail.last_paid as u64)
    };
    let code_hash = detail.code_hash.clone().unwrap_or_default();
    let data_hash = detail.data_hash.clone().unwrap_or_default();
    let code_full = detail.code_boc.clone().unwrap_or_default();
    let data_full = detail.data_boc.clone().unwrap_or_default();

    let contract_kind = detail.decoded.as_ref().map_or("", |contract| contract.kind);

    AccountView {
        status: detail.status.into(),
        address: address.into(),
        balance: native_amount(detail.balance),
        has_due: detail.due_payment > 0,
        due_payment: native_amount(detail.due_payment),
        last_paid: last_paid.into(),
        exists: detail.exists,
        has_code: detail.code_hash.is_some(),
        storage_bits: group_digits(&detail.storage_bits.to_string()).into(),
        storage_cells: group_digits(&detail.storage_cells.to_string()).into(),
        code_hash: code_hash.into(),
        data_hash: data_hash.into(),
        code: boc_preview(&code_full).into(),
        code_size: human_size(detail.code_bytes).into(),
        code_full: code_full.into(),
        data: boc_preview(&data_full).into(),
        data_size: human_size(detail.data_bytes).into(),
        data_full: data_full.into(),
        contract_kind: contract_kind.into(),
    }
}

pub(super) fn sync_ui(ui: &AppWindow, state: &AppState, form_locked: bool, cache: &mut UiCache) {
    let now = super::render::now_unix();
    let now_u32 = now as u32;
    if leaving_settings_with_entry_secrets(state.selected_tab, cache.was_settings) {
        clear_import_models(ui);
    }
    cache.was_settings = state.selected_tab == AppTab::Settings;
    if leaving_onboarding_with_entry_secrets(state.phase, cache.was_onboarding) {
        clear_import_models(ui);
        ui.set_lock_name(SharedString::new());
        ui.set_lock_pw(SharedString::new());
        ui.set_lock_pw2(SharedString::new());
    }
    if entering_unlocked_with_entry_secrets(state.phase, cache.was_locked) {
        ui.set_lock_name(SharedString::new());
        ui.set_lock_pw(SharedString::new());
        ui.set_lock_pw2(SharedString::new());
        ui.set_auth_pw(SharedString::new());
        ui.set_auth_pw2(SharedString::new());
        ui.set_seed_text(SharedString::new());
        ui.set_seed_words(empty_import_words());
        clear_import_models(ui);
    }
    ui.set_locked(state.phase != AppPhase::Unlocked);
    ui.set_selecting(state.phase == AppPhase::Selecting);
    ui.set_onboarding(state.phase == AppPhase::Onboarding);
    ui.set_key_busy(state.key_busy);
    ui.set_lock_error(state.lock_error.clone().into());
    ui.set_active_wallet(state.active_wallet.clone().into());
    cache.sync_active_wallet(&state.active_wallet);
    if cache.wallet_names != state.wallet_names {
        cache.wallet_names.clone_from(&state.wallet_names);
        let names: Vec<SharedString> = state
            .wallet_names
            .iter()
            .map(|n| n.clone().into())
            .collect();
        ui.set_wallet_names(ModelRc::from(Rc::new(VecModel::from(names))));
    }
    if state.phase != AppPhase::Unlocked && !cache.was_locked {
        clear_import_models(ui);
    }
    cache.was_locked = state.phase != AppPhase::Unlocked;

    let selecting = state.phase == AppPhase::Selecting;
    if selecting && !cache.was_selecting {
        ui.set_lock_pw(SharedString::new());
        ui.set_lock_pw2(SharedString::new());
    }
    cache.was_selecting = selecting;

    let onboarding = state.phase == AppPhase::Onboarding;
    if onboarding && !cache.was_onboarding {
        clear_import_models(ui);
        ui.set_lock_name(SharedString::new());
        ui.set_lock_pw(SharedString::new());
        ui.set_lock_pw2(SharedString::new());
    }
    cache.was_onboarding = onboarding;

    ui.set_selected_tab(tab_label(state.selected_tab).into());
    let (banner, banner_dismissible) = error_banner(state);
    ui.set_error_text(banner.into());
    ui.set_error_dismissible(banner_dismissible);
    ui.set_live(live_badge_enabled(state));
    ui.set_has_wallet(state.seed_saved || state.wallet.is_some());

    let resolved_endpoint = state.resolved_endpoint();
    if cache.endpoint != resolved_endpoint {
        cache.endpoint.clone_from(&resolved_endpoint);
        ui.set_endpoint(resolved_endpoint.into());
    }

    let wallet_address = state.wallet_address().unwrap_or("");
    ui.set_wallet_address(wallet_address.into());
    if let Some(w) = state.wallet.as_ref() {
        ui.set_wallet_status(status_label(&w.status).into());
    } else if !wallet_address.is_empty() {
        ui.set_wallet_status("Unknown".into());
    } else {
        ui.set_wallet_status("Non-exist".into());
    }

    let selected = state.selected_asset;
    let all_ids: Vec<AssetId> = all_supported_assets()
        .into_iter()
        .map(|meta| meta.id)
        .collect();
    let wallet_ids = wallet_asset_ids(state);
    let balances: Vec<AssetAmount> = all_ids
        .iter()
        .map(|asset| state.balance_or_zero(*asset))
        .collect();
    ui.set_asset_count(wallet_ids.len() as i32);
    let assets_key = (selected, wallet_ids.clone(), balances);
    if cache.assets_key.as_ref() != Some(&assets_key) {
        cache.assets_key = Some(assets_key);
        let wallet_assets: Vec<AssetRow> = wallet_ids
            .iter()
            .map(|asset| asset_row(state, *asset, selected))
            .collect();
        ui.set_assets(ModelRc::from(Rc::new(VecModel::from(wallet_assets))));

        let all_assets: Vec<AssetRow> = all_ids
            .iter()
            .map(|a| asset_row(state, *a, selected))
            .collect();
        ui.set_all_assets(ModelRc::from(Rc::new(VecModel::from(all_assets))));
    }

    let meta = asset_meta(selected);
    ui.set_sel_symbol(meta.symbol.into());
    ui.set_sel_initial(meta.mark.into());
    ui.set_sel_color(asset_tone(meta.tone));

    ui.set_send_form_locked(form_locked);
    if ui.get_recipient().as_str() != state.send_form.destination {
        ui.set_recipient(state.send_form.destination.clone().into());
    }
    let desired_amount = group_editable(&state.send_form.amount);
    if ui.get_amount().as_str() != desired_amount {
        ui.set_amount(desired_amount.into());
    }
    if ui.get_comment().as_str() != state.send_form.comment {
        ui.set_comment(state.send_form.comment.clone().into());
    }
    ui.set_comment_bytes(state.send_form.comment.len() as i32);
    // Sealing costs bytes out of the same budget, so the limit the counter
    // shows is the limit that is actually left.
    ui.set_comment_limit(state.comment_limit() as i32);
    ui.set_encrypt_available(state.encrypt_available());
    ui.set_encrypt_on(state.send_form.encrypt);
    ui.set_encrypt_hint(state.encrypt_hint().into());
    ui.set_recipient_valid(state.recipient_valid());
    ui.set_send_enabled(state.send_ready());
    ui.set_insufficient_balance(state.amount_exceeds_balance());
    ui.set_journal_blocking(state.journal_blocking);
    ui.set_risk_override_eligible(state.risk_override_eligible);
    ui.set_risk_override_form_ready(state.risk_override_form_ready());
    ui.set_allow_unbounced(state.allow_unbounced);
    ui.set_unlock_hint(if state.within_autosign() {
        let mins_left = state
            .autosign_until
            .map(|deadline| deadline.remaining_secs().div_ceil(60))
            .unwrap_or(0);
        format!("Password remembered · {mins_left} min left").into()
    } else {
        SharedString::new()
    });

    if let Some(cycle) = state.validator_cycle {
        let display = cycle.display(now_u32);
        ui.set_clock_needle_angle(display.needle_deg);
        ui.set_clock_elect_start(display.elect_frac_start);
        ui.set_clock_elect_end(display.elect_frac_end);
        ui.set_clock_active_round(display.round_color.name().into());
        ui.set_clock_round_ends_in(display.round_ends_in.into());
        ui.set_clock_elections(display.elections_value.into());
        ui.set_clock_elections_countdown(display.elections_countdown.into());
        ui.set_clock_elections_open(display.elections_open);
        ui.set_clock_active_green(display.round_color.is_green());
    } else {
        ui.set_clock_needle_angle(-90.0);
        ui.set_clock_elect_start(0.68);
        ui.set_clock_elect_end(0.85);
        ui.set_clock_active_round("—".into());
        ui.set_clock_round_ends_in("—".into());
        ui.set_clock_elections("—".into());
        ui.set_clock_elections_countdown("—".into());
        ui.set_clock_elections_open(false);
        ui.set_clock_active_green(false);
    }

    render_explorer_account(ui, state, cache, now);
    sync_swap(ui, state, cache);
    sync_storage(ui, state, cache);

    if state.risk_review_open != cache.risk_was_open {
        ui.set_risk_typed_confirmation(SharedString::new());
        ui.set_risk_ack_both_may_debit(false);
        ui.set_risk_ack_duplicate(false);
    }
    cache.risk_was_open = state.risk_review_open;
    ui.set_risk_review_open(state.risk_review_open);
    ui.set_risk_review_details(state.risk_review_details.clone().into());
    ui.set_risk_requires_duplicate_confirmation(state.risk_requires_duplicate_confirmation);
    if risk_rows_changed(
        &cache.risk_rows,
        &state.risk_overlap_labels,
        &state.risk_overlap_selected,
    ) {
        cache.risk_rows = (
            state.risk_overlap_labels.clone(),
            state.risk_overlap_selected.clone(),
        );
        let risk_rows: Vec<RiskOverlapRow> = state
            .risk_overlap_labels
            .iter()
            .enumerate()
            .map(|(index, label)| RiskOverlapRow {
                label: label.clone().into(),
                selected: state
                    .risk_overlap_selected
                    .get(index)
                    .copied()
                    .unwrap_or(false),
            })
            .collect();
        ui.set_risk_overlap_rows(ModelRc::from(Rc::new(VecModel::from(risk_rows))));
    }

    ui.set_contact_count(state.contacts.len() as i32);
    if cache.contacts != state.contacts {
        cache.contacts.clone_from(&state.contacts);
        cache.contacts_rev = cache.contacts_rev.wrapping_add(1);
        let contacts: Vec<ContactRow> = state
            .contacts
            .iter()
            .map(|c| contact_row(&c.name, &c.address, &c.tag))
            .collect();
        ui.set_contacts(ModelRc::from(Rc::new(VecModel::from(contacts))));
    }

    let total = state.activity.len();
    let filtered: Vec<&ActivityEvent> = state
        .activity
        .iter()
        .filter(|event| cache.filters.matches(event))
        .collect();
    let shown = filtered.len();
    ui.set_activity_total(total as i32);
    ui.set_activity_shown(shown as i32);
    ui.set_af_active(cache.filters.any_active());
    ui.set_af_dir(cache.filters.dir.clone().into());
    ui.set_af_token(cache.filters.token);
    if cache.filters.token != -2 {
        let asset = if cache.filters.token == -1 {
            AssetId::Native
        } else {
            AssetId::CurrencyCollection(cache.filters.token.max(0) as u32)
        };
        let (mark, symbol, color) = movement_meta(asset);
        ui.set_af_token_mark(mark.into());
        ui.set_af_token_symbol(symbol.into());
        ui.set_af_token_color(color);
    }
    ui.set_af_party_addr(cache.filters.party.clone().into());
    ui.set_af_party_label(cache.filters.party_label.clone().into());

    let activity_hash = activity_change_hash(
        &filtered,
        &cache.filters,
        cache.contacts_rev,
        wallet_address,
        today_bucket(now),
    );
    if cache.activity_hash != activity_hash {
        cache.activity_hash = activity_hash;
        let activity: Vec<ActivityRow> =
            activity_rows(&filtered, wallet_address, &state.contacts, now);
        ui.set_activity(ModelRc::from(Rc::new(VecModel::from(activity))));
    }

    ui.set_chat_open(state.chat.open);
    ui.set_chat_peer(state.chat.peer.clone().into());
    // A conversation with someone in the address book is named for them, with
    // the same mark they carry on the Contacts page. With anyone else there is
    // nothing to add: the address is written out directly underneath, and
    // saying it twice, once abbreviated, tells nobody anything.
    let peer_contact = state
        .contacts
        .iter()
        .find(|entry| entry.address == state.chat.peer);
    ui.set_chat_peer_name(
        peer_contact
            .map(|entry| entry.name.clone())
            .unwrap_or_default()
            .into(),
    );
    ui.set_chat_peer_mark(
        peer_contact
            .map(|entry| crate::bridge::render::contact_row(&entry.name, &entry.address, ""))
            .map(|row| row.initial)
            .unwrap_or_default(),
    );
    ui.set_chat_peer_tone(
        peer_contact
            .map(|entry| crate::bridge::render::contact_row(&entry.name, &entry.address, ""))
            .map(|row| row.color)
            .unwrap_or(slint::Color::from_argb_u8(0, 0, 0, 0)),
    );
    ui.set_chat_loading(state.chat.loading);
    ui.set_chat_error(state.chat.error.clone().into());
    if ui.get_chat_draft() != state.chat.draft.as_str() {
        ui.set_chat_draft(state.chat.draft.clone().into());
    }
    ui.set_chat_draft_bytes(state.chat.draft.len() as i32);
    ui.set_chat_draft_limit(state.chat.draft_limit() as i32);
    ui.set_chat_can_encrypt(state.chat.peer_key_known);
    ui.set_chat_encrypt_on(state.chat.encrypt);
    ui.set_chat_busy(state.chat.sending || state.sending);
    ui.set_chat_can_send(state.chat.can_send() && !state.sending);
    if state.chat.open {
        let lines = crate::bridge::render::chat_line_rows(&state.chat.lines, now);
        ui.set_chat_lines(ModelRc::from(Rc::new(VecModel::from(lines))));
    }

    ui.set_workchain(state.workchain.to_string().into());
    ui.set_global_id(state.network_id.to_string().into());
    ui.set_network_name(state.network_name.clone().into());
    let selected_endpoint_index = state.selected_endpoint_index();
    ui.set_network_selected_endpoint(selected_endpoint_index as i32);
    ui.set_endpoint_test_result(state.endpoint_test_result.clone().into());
    let display_list = state.endpoint_display_list();
    let network_sig = format!(
        "{}|{}|{}",
        state.network_name,
        selected_endpoint_index,
        display_list.join("\u{1f}")
    );
    if cache.network_sig != network_sig {
        cache.network_sig = network_sig;
        let endpoints: Vec<slint::SharedString> =
            display_list.iter().map(|e| e.clone().into()).collect();
        ui.set_network_endpoints(ModelRc::from(Rc::new(VecModel::from(endpoints))));
    }
    ui.set_seed_saved(state.seed_saved);
    ui.set_seed_revealed(state.show_seed);
    ui.set_seed_unsaved(state.seed_unsaved);
    ui.set_clipboard_notice(state.clipboard_notice.as_str().into());
    ui.set_seed_copy_ttl(state.seed_copy_ttl_secs as i32);
    ui.set_onboard_import_valid(state.onboard_import_valid);
    ui.set_backup_confirmed(state.seed_backup_confirmed);
    ui.set_autolock_mins(state.autosign_mins as i32);
    ui.set_screen_lock_mins(state.screen_lock_mins as i32);
    let desired_seed_text = if state.show_seed || state.seed_unsaved {
        state.seed.expose_secret()
    } else {
        ""
    };
    let current_seed_text = ui.get_seed_text();
    if seed_models_need_refresh(current_seed_text.as_str(), desired_seed_text) {
        let exposure = seed_exposure(state.show_seed, state.seed_unsaved, &state.seed);
        ui.set_seed_text(SharedString::from(exposure.text.as_str()));
        let words: Vec<SharedString> = exposure
            .words
            .iter()
            .map(|word| SharedString::from(word.as_str()))
            .collect();
        ui.set_seed_words(ModelRc::from(Rc::new(VecModel::from(words))));
    }

    sync_auth(ui, state, cache);
}

fn sync_auth(ui: &AppWindow, state: &AppState, cache: &mut UiCache) {
    let auth_opened = state.auth.open && !cache.auth_was_open;
    if auth_opened {
        ui.set_auth_remember(false);
        ui.set_auth_pw(SharedString::new());
        ui.set_auth_pw2(SharedString::new());
    }
    if !state.auth.open && cache.auth_was_open {
        ui.set_auth_remember(false);
        ui.set_auth_pw(SharedString::new());
        ui.set_auth_pw2(SharedString::new());
    }
    cache.auth_was_open = state.auth.open;

    ui.set_auth_open(state.auth.open);
    ui.set_auth_error(state.auth.error.clone().into());
    ui.set_auth_send_options_editable(state.auth.send_options_editable);
    let mode = match state.auth.mode {
        AuthMode::Create => "create",
        AuthMode::Enter => "enter",
        AuthMode::Confirm => "confirm",
    };
    ui.set_auth_mode(mode.into());
    let purpose = match state.auth.purpose {
        AuthPurpose::Send => "send",
        AuthPurpose::Swap => "swap",
        AuthPurpose::Storage => "storage",
        AuthPurpose::RevealRecords => "revealrecords",
        AuthPurpose::ChangePassword => "changepassword",
        AuthPurpose::RevealSeed => "revealseed",
        AuthPurpose::DeleteWallet => "deletewallet",
        AuthPurpose::ChangeSecuritySetting => "changesetting",
    };
    ui.set_auth_purpose(purpose.into());
    ui.set_auth_danger(state.auth.purpose == AuthPurpose::Storage && state.storage.pending_danger);
    let confirm = state.swap.confirm.as_ref();
    ui.set_swap_confirm_in(match confirm {
        Some(figures) => token_amount(
            figures.sent.asset_id(),
            &format_fixed9_amount(&figures.sent).unwrap_or_else(|_| "0".to_owned()),
        ),
        None => TokenAmount::default(),
    });
    ui.set_swap_confirm_out(match confirm {
        Some(figures) => token_units(figures.out_asset, figures.out_units),
        None => TokenAmount::default(),
    });
    ui.set_swap_confirm_out_known(confirm.is_some_and(|figures| figures.out_units > 0));

    let show_summary = matches!(state.auth.mode, AuthMode::Enter | AuthMode::Confirm)
        && state.auth.purpose == AuthPurpose::Send;
    ui.set_auth_show_summary(show_summary);

    let (title, subtitle): (String, String) = match (state.auth.mode, state.auth.purpose) {
        (AuthMode::Enter, AuthPurpose::ChangePassword) => (
            "Confirm current password".into(),
            "Enter your current password to change it. This is always required, even while unlocked."
                .into(),
        ),
        (AuthMode::Create, AuthPurpose::ChangePassword) => (
            "Set a new password".into(),
            "Choose a new password. This re-encrypts your wallet. The old password stops working."
                .into(),
        ),
        (AuthMode::Create, _) => ("Set a new password".into(), "Choose a new password.".into()),
        (AuthMode::Enter, AuthPurpose::Send) => (
            "Sign transfer".into(),
            "Review the details, then enter your password to sign and submit.".into(),
        ),
        (AuthMode::Enter, AuthPurpose::Swap) => (
            "Sign swap".into(),
            "Review the swap, then enter your password to sign and submit.".into(),
        ),
        (AuthMode::Confirm, AuthPurpose::Swap) => (
            "Confirm swap".into(),
            "Review the swap, then confirm to submit.".into(),
        ),
        (_, AuthPurpose::Storage) if state.storage.pending_danger => (
            "Delete this record?".into(),
            "The record is removed from the chain and cannot be recovered from it.".into(),
        ),
        (AuthMode::Enter, AuthPurpose::Storage) => (
            format!("Sign — {}", state.storage.pending_label),
            "Your records are encrypted with this wallet's key. Enter your password to sign."
                .into(),
        ),
        (AuthMode::Confirm, AuthPurpose::Storage) => (
            format!("Confirm — {}", state.storage.pending_label),
            "Your records are encrypted with this wallet's key. Confirm to submit.".into(),
        ),
        (AuthMode::Enter, AuthPurpose::RevealRecords) => (
            "Enter password".into(),
            "Enter your password to show your records for a minute.".into(),
        ),
        (AuthMode::Enter, AuthPurpose::RevealSeed) => (
            "Enter password".into(),
            "Enter your password to reveal your seed phrase.".into(),
        ),
        (AuthMode::Enter, AuthPurpose::DeleteWallet) => (
            "Enter password".into(),
            "Enter your password to permanently delete this wallet.".into(),
        ),
        (AuthMode::Enter, AuthPurpose::ChangeSecuritySetting) => (
            "Enter password".into(),
            "Enter your password to change this security setting.".into(),
        ),
        (AuthMode::Confirm, _) => (
            "Confirm transfer".into(),
            "Review the details, then confirm to send.".into(),
        ),
    };
    ui.set_auth_title(title.into());
    ui.set_auth_subtitle(subtitle.into());

    if show_summary {
        if auth_opened {
            let amount = display_send_amount(state.selected_asset, &state.send_form.amount);
            ui.set_tx_amount(token_amount(state.selected_asset, &amount));
            let dest = state.send_form.destination.trim();
            let canonical = canonicalize_recipient(dest).unwrap_or_else(|_| dest.to_owned());
            let contact = state.contacts.iter().find(|c| c.address == canonical);
            let name = contact
                .map(|c| c.name.clone())
                .unwrap_or_else(|| "Unknown recipient".to_owned());
            ui.set_tx_to(name.into());
            ui.set_tx_in_contacts(contact.is_some());
            ui.set_tx_to_addr_full(canonical.into());
        }
        let (recipient_state, notice, ack_label) = recipient_advisory(state);
        ui.set_auth_recipient_state(recipient_state.into());
        ui.set_auth_recipient_notice(notice.into());
        ui.set_auth_recipient_ack_label(ack_label.into());
        let native_symbol = asset_meta(AssetId::Native).symbol;
        let deploy = state.fee_estimate.is_some_and(|estimate| estimate.deploy);
        let fee = group_digits(
            &format_native_fixed9(state.effective_send_fee())
                .expect("a validated fee estimate is in the native domain"),
        );
        ui.set_tx_fee(
            if state.fee_estimate.is_some() {
                format!(
                    "≈ {fee} {native_symbol}{}",
                    if deploy { " · incl. deploy" } else { "" }
                )
            } else if state.fee_estimating {
                "Estimating…".to_owned()
            } else {
                format!("≈ {fee} {native_symbol}")
            }
            .into(),
        );
    }
}

fn recipient_advisory(state: &AppState) -> (&'static str, String, &'static str) {
    match state.recipient_check {
        RecipientCheck::Known(status) if status.is_active() => ("active", String::new(), ""),
        RecipientCheck::Known(status) => {
            let native = state.selected_asset.is_native();
            let (state_key, status_word, ack_label) = match status {
                DestinationAccountStatus::NonExist => {
                    ("nonexist", "NON-EXIST", "Send to a new unfunded address")
                }
                DestinationAccountStatus::Frozen => {
                    ("frozen", "FROZEN", "Send to a frozen address")
                }
                _ => ("uninit", "UNINIT", "Send to a new address"),
            };
            let action = match (status, native) {
                (DestinationAccountStatus::Frozen, true) => "top up this frozen address",
                (DestinationAccountStatus::Frozen, false) => "send token to this frozen address",
                (_, true) => "fund a brand-new address",
                (_, false) => "send token to a brand-new address",
            };
            let consequence = if native {
                "the confirmed send is non-bounceable and cannot return"
            } else {
                "tokens cannot bounce back"
            };
            let notice =
                format!("Account is {status_word} on chain. Confirm below to {action} — {consequence}.");
            (state_key, notice, ack_label)
        }
        RecipientCheck::Failed => (
            "failed",
            "Could not verify the recipient account. Check your connection — retrying automatically."
                .to_owned(),
            "",
        ),
        RecipientCheck::Unchecked | RecipientCheck::Pending => ("pending", String::new(), ""),
    }
}

fn status_label(raw: &str) -> String {
    match raw.to_ascii_lowercase().as_str() {
        "active" => "Active".to_owned(),
        "uninit" => "Uninit".to_owned(),
        "frozen" => "Frozen".to_owned(),
        "non-exist" | "not_exists" | "notexists" => "Non-exist".to_owned(),
        other => other.to_owned(),
    }
}

fn tab_label(tab: AppTab) -> &'static str {
    match tab {
        AppTab::Wallet => "Wallet",
        AppTab::Swap => "Swap",
        AppTab::Contacts => "Contacts",
        AppTab::Explorer => "Explorer",
        AppTab::Storage => "Storage",
        AppTab::Settings => "Settings",
    }
}

fn sync_storage(ui: &AppWindow, state: &AppState, cache: &mut UiCache) {
    let storage = &state.storage;
    ui.set_storage_address(storage.address.clone().into());
    ui.set_storage_exists(storage.exists);
    ui.set_storage_loading(storage.loading);
    ui.set_storage_busy(storage.busy);
    ui.set_storage_pending_label(storage.pending_label.clone().into());
    ui.set_storage_error(storage.error.clone().into());
    ui.set_storage_notice(storage.notice.clone().into());
    ui.set_storage_balance(token_units(AssetId::Native, storage.balance));
    ui.set_storage_count(storage.records.len() as i32);
    ui.set_storage_limit(i32::from(MAX_STORAGE_RECORDS));
    ui.set_storage_unreadable(storage.unreadable as i32);
    ui.set_storage_revealed(storage.revealed);
    ui.set_storage_add_enabled(storage.add_enabled());
    ui.set_storage_form_error(storage.form_message().into());
    ui.set_storage_title_limit(MAX_RECORD_TITLE_BYTES as i32);
    ui.set_storage_data_limit(MAX_RECORD_DATA_BYTES as i32);
    ui.set_storage_title_bytes(storage.title_input.trim().len() as i32);
    ui.set_storage_data_bytes(storage.data_input.len() as i32);

    if ui.get_storage_title_input().as_str() != storage.title_input {
        ui.set_storage_title_input(storage.title_input.clone().into());
    }
    if ui.get_storage_data_input().as_str() != storage.data_input {
        ui.set_storage_data_input(storage.data_input.clone().into());
    }

    let rows_hash = storage_rows_hash(storage);
    if cache.storage_rows_hash != rows_hash {
        cache.storage_rows_hash = rows_hash;
        let rows: Vec<StorageRow> = storage
            .records
            .iter()
            .map(|record| StorageRow {
                id: record.id as i32,
                title: record.title.clone().into(),
                data: record.data.clone().into(),
            })
            .collect();
        ui.set_storage_records(ModelRc::from(Rc::new(VecModel::from(rows))));
    }
}

/// Rebuilding the row model recreates the rows, and with them any state the row
/// itself owns — the copy button's "copied" tick most visibly. So the model is
/// replaced only when what it would show actually changed.
fn storage_rows_hash(storage: &cc_wallet_app::StorageUi) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    storage.revealed.hash(&mut hasher);
    for record in &storage.records {
        record.id.hash(&mut hasher);
        record.title.hash(&mut hasher);
        record.data.hash(&mut hasher);
    }
    hasher.finish()
}

fn sync_swap(ui: &AppWindow, state: &AppState, cache: &mut UiCache) {
    let swap = &state.swap;
    let from = swap.form.from_asset();
    let to = swap.form.to_asset();

    ui.set_swap_pool_ready(swap.pool.is_some());
    ui.set_swap_pool_loading(swap.pool_loading);
    ui.set_swap_pool_message(
        if swap.pool_error.is_empty() {
            "This network has no swap pool configured.".to_string()
        } else {
            swap.pool_error.clone()
        }
        .into(),
    );
    ui.set_swap_paused(swap.pool.as_ref().is_some_and(|pool| pool.paused));
    let pool_address = swap
        .pool
        .as_ref()
        .map(|pool| pool.address.clone())
        .unwrap_or_default();
    ui.set_swap_pool_short(short_addr(&pool_address).into());
    ui.set_swap_pool_address(pool_address.into());
    ui.set_swap_pool_fee(
        swap.pool
            .as_ref()
            .map(|pool| percent_text(pool.fee_bps))
            .unwrap_or_default()
            .into(),
    );

    let pooled = state.swap_pool_assets();
    let reserves: Vec<(AssetId, u128)> = swap
        .pool
        .as_ref()
        .map(|pool| {
            pooled
                .iter()
                .map(|asset| (*asset, pool.reserve_units(*asset)))
                .collect()
        })
        .unwrap_or_default();
    let pickers_key = (reserves.clone(), from, to);
    if cache.swap_pool_key.as_ref() != Some(&pickers_key) {
        cache.swap_pool_key = Some(pickers_key);
        let reserve_rows: Vec<AssetRow> = reserves
            .iter()
            .map(|(asset, units)| pool_reserve_row(*asset, *units))
            .collect();
        ui.set_swap_reserves(ModelRc::from(Rc::new(VecModel::from(reserve_rows))));
        let side_rows = |selected: AssetId| -> Vec<AssetRow> {
            pooled
                .iter()
                .map(|asset| asset_row(state, *asset, selected))
                .collect()
        };
        ui.set_swap_from_assets(ModelRc::from(Rc::new(VecModel::from(side_rows(from)))));
        ui.set_swap_to_assets(ModelRc::from(Rc::new(VecModel::from(side_rows(to)))));
    }

    ui.set_swap_from_token(swap_balance(state, from));
    ui.set_swap_to_token(swap_balance(state, to));

    let desired_amount = group_editable(&swap.form.amount);
    if ui.get_swap_amount().as_str() != desired_amount {
        ui.set_swap_amount(desired_amount.into());
    }

    let quote = swap.quote;
    let available = quote.is_some_and(|value| !value.is_empty());
    ui.set_swap_quote_available(available);
    let unsupported = !swap.form.amount.is_empty()
        && swap.form.input().is_ok()
        && quote.is_some_and(|value| value.is_empty());
    ui.set_swap_unsupported(unsupported);
    ui.set_swap_quote_out(token_units(
        to,
        quote.map(|value| value.out_units).unwrap_or(0),
    ));
    ui.set_swap_min_received(token_units(
        to,
        quote.map(|value| value.min_out_units).unwrap_or(0),
    ));
    ui.set_swap_fee_text(
        swap.pool
            .as_ref()
            .map(|pool| percent_text(pool.fee_bps))
            .unwrap_or_default()
            .into(),
    );
    ui.set_swap_rate_text(swap_rate_text(state).into());
    ui.set_swap_slippage_bps(swap.form.clamped_slippage_bps() as i32);
    ui.set_swap_slippage_max_bps(i32::from(MAX_SLIPPAGE_BPS));
    if ui.get_swap_slippage_input().as_str() != swap.slippage_input {
        ui.set_swap_slippage_input(swap.slippage_input.clone().into());
    }
    ui.set_swap_slippage_valid(state.swap_slippage_typed_ok());
    ui.set_swap_enabled(state.swap_button_enabled());
    ui.set_swapping(swap.swapping);
    sync_swap_receipt(ui, state);
}

fn sync_swap_receipt(ui: &AppWindow, state: &AppState) {
    let Some(receipt) = state.swap.receipt.as_ref() else {
        ui.set_swap_receipt_open(false);
        ui.set_swap_receipt_state(SharedString::new());
        return;
    };
    let receipt_state = match (receipt.received_units, receipt.returned_units) {
        (Some(_), _) => "filled",
        (None, Some(_)) => "returned",
        (None, None) => "waiting",
    };
    ui.set_swap_receipt_open(true);
    ui.set_swap_receipt_state(receipt_state.into());
    ui.set_swap_receipt_time(fmt_datetime(receipt.submitted_unix).into());
    ui.set_swap_receipt_sent(token_amount(
        receipt.sent.asset_id(),
        &format_fixed9_amount(&receipt.sent).unwrap_or_else(|_| "0".to_owned()),
    ));
    let (paid_asset, paid_units) = match (receipt.received_units, receipt.returned_units) {
        (Some(units), _) => (receipt.out_asset, units),
        (None, Some(units)) => (receipt.sent.asset_id(), units),
        (None, None) => (receipt.out_asset, 0),
    };
    ui.set_swap_receipt_received(token_units(paid_asset, paid_units));
    ui.set_swap_receipt_expected(token_units(receipt.out_asset, receipt.expected_out_units));
    ui.set_swap_receipt_fee(token_units(AssetId::Native, receipt.fee_native));
}

fn percent_text(bps: u16) -> String {
    format!("{:.2}%", bps as f64 / 100.0)
}

fn swap_balance(state: &AppState, asset: AssetId) -> TokenAmount {
    token_amount(
        asset,
        &format_fixed9_amount(&state.balance_or_zero(asset)).unwrap_or_else(|_| "0".to_string()),
    )
}

fn swap_rate_text(state: &AppState) -> String {
    let swap = &state.swap;
    match swap.quote {
        Some(quote) if !quote.is_empty() && quote.in_units > 0 => {
            let from = asset_meta(swap.form.from_asset()).symbol;
            let to = asset_meta(swap.form.to_asset()).symbol;
            let per_one = quote
                .out_units
                .saturating_mul(1_000_000_000)
                .checked_div(quote.in_units)
                .unwrap_or(0);
            format!(
                "1 {from} ≈ {} {to}",
                group_digits(&units_exact(swap.form.to_asset(), per_one))
            )
        }
        _ => String::new(),
    }
}

#[cfg(test)]
mod explorer_tests {
    use super::{AccountInspection, DecodedContract, account_view, boc_preview, currency_amount};

    const HASH64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    const ACCOUNT_STATE_HEADER: &str =
        r#"icon: @image-url("../../assets/icons/account-state.svg");"#;
    const TRANSACTIONS_HEADER: &str = r#"icon: @image-url("../../assets/icons/activity.svg");"#;

    fn inspection(balance: u128, extra: &[(u32, &str)]) -> AccountInspection {
        AccountInspection {
            signing_key: None,
            exists: true,
            status: "Active",
            balance,
            due_payment: 0,
            extra_balance: extra
                .iter()
                .map(|(id, units)| (*id, (*units).to_owned()))
                .collect(),
            last_trans_lt: 7,
            last_paid: 0,
            storage_bits: 1_629,
            storage_cells: 9,
            code_hash: Some(HASH64.to_owned()),
            data_hash: Some(HASH64.to_owned()),
            code_boc: Some("te6ccgEBAQEATgABABBhbGwgb2YgdGhlIGNvZGU=".to_owned()),
            code_bytes: 89,
            data_boc: Some("te6ccg".to_owned()),
            data_bytes: 49,
            decoded: None,
        }
    }

    #[test]
    fn a_balance_splits_into_a_grouped_integer_and_a_fraction_with_its_coin_badge() {
        let view = account_view(&inspection(1_980_000_000_000, &[]), "-1:00");
        assert_eq!(view.balance.amount_int, "1\u{2019}980");
        assert_eq!(view.balance.amount_frac, ".000\u{2004}000\u{2004}000");
        assert_eq!(view.balance.symbol, "COIN");
        assert_eq!(view.balance.initial, "C");
    }

    #[test]
    fn currency_holdings_use_the_wallet_fixed9_display_and_the_token_badge() {
        let known = currency_amount(1, "1234500000");
        assert_eq!(known.amount_int, "1");
        assert_eq!(known.amount_frac, ".234\u{2004}500\u{2004}000");
        assert_eq!(known.symbol, "ONE");
        assert_eq!(known.initial, "1");

        let unknown = currency_amount(77, "1000000000000");
        assert_eq!(unknown.amount_int, "1\u{2019}000");
        assert_eq!(unknown.amount_frac, ".000\u{2004}000\u{2004}000");
        assert_eq!(unknown.symbol, "#77");
        assert_eq!(unknown.initial, "77");
    }

    #[test]
    fn an_out_of_domain_holding_falls_back_to_its_raw_units() {
        let broken = currency_amount(1, "not-a-number");
        assert_eq!(broken.amount_int, "not-a-number");
        assert_eq!(broken.amount_frac, "");
    }

    #[test]
    fn hashes_are_shown_whole_while_bocs_stay_a_preview() {
        let view = account_view(&inspection(0, &[]), "-1:00");
        assert_eq!(view.code_hash, HASH64);
        assert_eq!(view.data_hash, HASH64);
        assert_eq!(
            view.code, "te6ccgEBAQEATgABA…dGhlIGNvZGU=",
            "a long BOC keeps a head…tail preview"
        );
        assert_eq!(
            view.code_size, "89 B",
            "the size is a fact of its own, split off by the row's divider"
        );
        assert_eq!(view.code_full, "te6ccgEBAQEATgABABBhbGwgb2YgdGhlIGNvZGU=");
        assert_eq!(view.storage_bits, "1\u{2019}629");
        assert_eq!(view.storage_cells, "9");
    }

    #[test]
    fn a_short_boc_is_not_shortened() {
        assert_eq!(boc_preview("te6ccg"), "te6ccg");
    }

    #[test]
    fn storage_rent_owed_shows_only_when_the_account_actually_owes_it() {
        let clear = account_view(&inspection(0, &[]), "-1:00");
        assert!(!clear.has_due);

        let owing = account_view(
            &AccountInspection {
                due_payment: 12_500_000,
                ..inspection(0, &[])
            },
            "-1:00",
        );
        assert!(owing.has_due);
        assert_eq!(owing.due_payment.amount_int, "0");
        assert_eq!(owing.due_payment.amount_frac, ".012\u{2004}500\u{2004}000");
        assert_eq!(owing.due_payment.symbol, "COIN");
    }

    #[test]
    fn a_recognised_contract_reports_its_decoded_data_and_others_report_nothing() {
        let unknown = inspection(0, &[]);
        assert_eq!(account_view(&unknown, "-1:00").contract_kind, "");
        assert!(super::contract_fields(unknown.decoded.as_ref()).is_empty());

        let ever_wallet = AccountInspection {
            decoded: Some(DecodedContract {
                kind: "Ever Wallet",
                fields: vec![
                    cc_wallet_app::DecodedField::data("Public key", HASH64),
                    cc_wallet_app::DecodedField::moment("Last message", 1_700_000_000),
                ],
            }),
            ..inspection(0, &[])
        };
        assert_eq!(
            account_view(&ever_wallet, "-1:00").contract_kind,
            "Ever Wallet"
        );

        let fields = super::contract_fields(ever_wallet.decoded.as_ref());
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].label, "Public key");
        assert_eq!(fields[0].value, HASH64);
        assert!(fields[0].copyable, "a key is there to be copied");
        assert_eq!(fields[1].label, "Last message");
        assert_eq!(fields[1].value, super::fmt_datetime(1_700_000_000));
    }

    #[test]
    fn every_stat_line_is_present_before_the_first_read_so_the_card_cannot_jump() {
        let waiting = super::network_stats_view(None, 0);
        assert_eq!(waiting.validators, "—");
        assert_eq!(waiting.stake_ratio, "—");
        assert!(!waiting.has_stake);
        assert!(!waiting.has_supply);
        assert_eq!(waiting.supply_note, "Reading network figures…");

        let page = include_str!("../../ui/pages/explorer_page.slint");
        let card = page
            .split_once("title: \"Network Stats\";")
            .expect("the card exists")
            .1
            .split_once(TRANSACTIONS_HEADER)
            .expect("the card ends where the transactions card begins")
            .0;
        assert!(
            !card.contains("EmptyState"),
            "no swapped-in placeholder: every row is there from the start, dashed"
        );
        assert!(
            !card.contains("if root.network.supply_note"),
            "the note and its hairline hold their place from the first paint"
        );
    }

    #[test]
    fn network_stats_render_each_figure_on_its_own() {
        use cc_wallet_app::{CoinSupply, NetworkStats};

        let full = NetworkStats {
            validators: 17,
            total_stake: Some(9_532_221_000_000_000),
            supply: Some(CoinSupply {
                total: 7_074_806_721_778_674_964,
                extra: Some(std::collections::BTreeMap::from([(
                    1,
                    "21000000".to_owned(),
                )])),
                seqno: 23_197_707,
                gen_utime: 1_784_777_441,
            }),
        };
        let view = super::network_stats_view(Some(&full), 1_784_777_441 + 5_030);
        assert_eq!(view.validators, "17");
        assert!(view.has_stake);
        assert_eq!(view.total_stake.amount_int, "9\u{2019}532\u{2019}221");
        assert_eq!(view.total_stake.symbol, "COIN");
        assert!(view.has_supply);
        assert_eq!(
            view.total_supply.amount_int,
            "7\u{2019}074\u{2019}806\u{2019}721"
        );
        assert_eq!(view.total_supply.amount_frac, ".778\u{2004}674\u{2004}964");
        assert_eq!(view.stake_ratio, "0.1347%");
        assert_eq!(
            view.supply_note,
            "Supply at key block 23197707 : 1h 23m 50s ago"
        );
    }

    #[test]
    fn a_figure_the_network_would_not_give_up_leaves_the_others_standing() {
        use cc_wallet_app::NetworkStats;

        let view = super::network_stats_view(
            Some(&NetworkStats {
                validators: 13,
                total_stake: None,
                supply: None,
            }),
            1_784_777_441,
        );

        assert_eq!(view.validators, "13");
        assert!(!view.has_stake);
        assert!(!view.has_supply);
        assert_eq!(
            view.stake_ratio, "—",
            "a share of a supply nobody could read is not invented"
        );
        assert_eq!(
            view.supply_note, "Supply could not be read from this endpoint",
            "no key block is named when no supply was read"
        );

        let page = include_str!("../../ui/pages/explorer_page.slint");
        assert!(
            page.contains("if !root.known: Text {\n        text: \"—\";"),
            "an unread figure shows a dash rather than a zero"
        );
    }

    #[test]
    fn the_staked_share_is_rounded_in_integer_arithmetic_not_floated() {
        use cc_wallet_app::CoinSupply;

        fn supply(total: u128) -> CoinSupply {
            CoinSupply {
                total,
                extra: Some(std::collections::BTreeMap::new()),
                seqno: 1,
                gen_utime: 1,
            }
        }

        assert_eq!(
            super::stake_share(
                Some(9_532_221_000_000_000),
                Some(&supply(7_074_806_721_778_674_964))
            )
            .as_deref(),
            Some("0.1347%")
        );
        assert_eq!(
            super::stake_share(Some(500), Some(&supply(1_000))).as_deref(),
            Some("50.0000%")
        );
        assert_eq!(
            super::stake_share(Some(7), Some(&supply(7))).as_deref(),
            Some("100.0000%")
        );

        assert!(
            super::stake_share(Some(1), Some(&supply(0))).is_none(),
            "a chain with no supply yields no share instead of dividing by zero"
        );
        assert!(super::stake_share(None, Some(&supply(10))).is_none());
        assert!(super::stake_share(Some(10), None).is_none());
    }

    #[test]
    fn the_supply_says_how_stale_it_is_because_a_key_block_can_be_hours_old() {
        use cc_wallet_app::CoinSupply;

        let supply = CoinSupply {
            total: 1,
            extra: Some(std::collections::BTreeMap::new()),
            seqno: 23_197_707,
            gen_utime: 1_784_777_441,
        };

        assert_eq!(
            super::supply_note(&supply, 1_784_777_451),
            "Supply at key block 23197707 : just now",
            "a block sealed seconds ago does not need a countdown"
        );
        assert_eq!(
            super::supply_note(&supply, 1_784_777_441 + 5_030),
            "Supply at key block 23197707 : 1h 23m 50s ago"
        );
        assert_eq!(
            super::supply_note(&supply, 1_784_777_441 - 30),
            "Supply at key block 23197707 : just now",
            "a clock behind the chain never reads as a negative age"
        );
    }

    #[test]
    fn both_account_lists_cap_what_they_show_and_scroll_the_rest() {
        let page = include_str!("../../ui/pages/explorer_page.slint");
        assert_eq!(
            page.matches("ScrollView {").count(),
            2,
            "holdings and decoded fields each scroll on their own"
        );
        assert_eq!(
            page.matches(
                "height: min(root.currencies.length, Theme.account_list_max_rows) * Theme.account_list_row_h;"
            )
            .count(),
            1
        );
        assert_eq!(
            page.matches(
                "height: min(root.contract_fields.length, Theme.decoded_list_max_rows) * Theme.account_list_row_h;"
            )
            .count(),
            1,
            "a contract has more to say than an account has holdings, so its list \
             asks for more rows before it scrolls"
        );
        assert!(
            page.contains("* Theme.account_list_row_h;") && !page.contains("floor(parent.height"),
            "the list's height is a whole number of rows by construction, so nothing needs \
             to floor() a parent height it cannot predict"
        );
        assert_eq!(
            page.matches("lead_w: Theme.account_boc_w;").count(),
            2,
            "the Code and Data rows share one preview column so their dividers line up"
        );
    }

    #[test]
    fn a_contract_that_never_recorded_a_moment_reads_as_never_rather_than_the_epoch() {
        let never = DecodedContract {
            kind: "Ever Wallet",
            fields: vec![cc_wallet_app::DecodedField::moment("Last message", 0)],
        };
        let fields = super::contract_fields(Some(&never));
        assert_eq!(fields[0].value, "Never");
    }

    fn account_tx(
        kind: cc_wallet_app::AccountTxKind,
        counterparty: &str,
        extra_parties: usize,
        movements: Vec<cc_wallet_app::AssetMovement>,
    ) -> cc_wallet_app::AccountTx {
        cc_wallet_app::AccountTx {
            received: Vec::new(),
            hash: cc_wallet_app::Digest32::try_from_hex(HASH64).expect("canonical hash"),
            lt: 42,
            time_unix: 1_700_000_000,
            kind,
            counterparty: counterparty.to_owned(),
            extra_parties,
            movements,
            fee_native: 7_400_000,
            int_out_msgs: extra_parties + 1,
            ext_out_msgs: 0,
            success: true,
            bounced: false,
            exit_code: 0,
        }
    }

    #[test]
    fn a_transaction_row_carries_the_transaction_not_a_transfer_inside_it() {
        use cc_wallet_app::{AccountTxKind, AssetAmount, AssetMovement};
        use slint::Model;

        let sent = AssetMovement {
            amount: AssetAmount::native(2_500_000_000).expect("in domain"),
        };
        let counterparty = "-1:8f1d72dbc37c3e77d413867e5e846f35bbe0398699815fa079ec95301c119a4b";
        let rows = super::explorer_tx_rows(
            &[account_tx(AccountTxKind::Out, counterparty, 2, vec![sent])],
            "",
            &[],
            1_753_000_000,
        );
        let row = &rows[0];

        assert_eq!(row.kind, "OUT");
        assert!(!row.is_in);
        assert_eq!(
            row.party_extra, "+2 more",
            "a fanned-out send counts the recipients it could not name"
        );
        assert_eq!(
            row.party, counterparty,
            "the column is wide enough for the whole address, so it is not cut down"
        );
        assert_eq!(
            row.party_name, "",
            "an address we have no name for shows no name"
        );
        assert_eq!(row.movements.row_count(), 1);
        assert_eq!(row.fee, "0.007\u{2004}400\u{2004}000");
        assert_eq!(row.hash_full, HASH64, "the copy button gets the whole hash");
        assert!(
            row.hash_short.len() < row.hash_full.len() && row.hash_short.contains('…'),
            "the column shows a shortened hash: {}",
            row.hash_short
        );
    }

    #[test]
    fn a_transaction_with_no_counterparty_says_so_rather_than_showing_an_empty_column() {
        use cc_wallet_app::AccountTxKind;
        use slint::Model;

        let rows = super::explorer_tx_rows(
            &[account_tx(AccountTxKind::Special, "", 0, Vec::new())],
            "",
            &[],
            1_753_000_000,
        );

        assert_eq!(rows[0].kind, "TICK");
        assert_eq!(rows[0].party, "—");
        assert_eq!(rows[0].party_extra, "");
        assert_eq!(rows[0].movements.row_count(), 0);
    }

    fn trace_edge(
        op: &str,
        from: usize,
        to: usize,
        tx: Option<(bool, &str)>,
    ) -> cc_wallet_app::TraceEdge {
        use cc_wallet_app::{AssetAmount, AssetMovement, Digest32, TraceEdge, TraceTx};

        TraceEdge {
            from,
            to,
            op: op.to_owned(),
            raw_op: if op.starts_with("op 0x") {
                op.to_owned()
            } else if op == "event" {
                String::new()
            } else {
                "op 0x00000000".to_owned()
            },
            movements: vec![AssetMovement {
                amount: AssetAmount::native(if op == "event" { 0 } else { 2_500_000_000 })
                    .expect("in domain"),
            }],
            fwd_fee: 10,
            depth: 1,
            tx: tx.map(|(success, failure)| TraceTx {
                hash: Digest32::try_from_hex(HASH64).expect("canonical hash"),
                lt: 7,
                time_unix: 1_700_000_000,
                fee_native: 7_400_000,
                success,
                failure: failure.to_owned(),
            }),
        }
    }

    fn trace(
        edges: Vec<cc_wallet_app::TraceEdge>,
        parties: &[&str],
    ) -> cc_wallet_app::AccountTrace {
        use cc_wallet_app::{AccountTrace, Digest32, TraceParty};

        AccountTrace {
            root: Digest32::try_from_hex(HASH64).expect("canonical hash"),
            focus: Digest32::try_from_hex(HASH64).expect("canonical hash"),
            parties: parties
                .iter()
                .map(|address| TraceParty {
                    address: (*address).to_owned(),
                    contract: if address.is_empty() {
                        String::new()
                    } else {
                        "Ever Wallet".to_owned()
                    },
                })
                .collect(),
            edges,
            total_fees_native: 7_400_000,
            failed: 0,
            unexecuted: 0,
            truncated: false,
        }
    }

    #[test]
    fn a_trace_column_is_named_when_we_know_the_name_and_addressed_when_we_do_not() {
        use cc_wallet_app::AddressBookEntry;

        let contacts = vec![AddressBookEntry::new("Vault", "-1:3aeae180")];
        let trace = trace(Vec::new(), &["", "-1:3aeae180", "-1:0763b7f0"]);

        let columns = super::trace_parties(&trace, "-1:0763b7f0", &contacts);

        assert!(
            columns[0].is_external,
            "the outside world leads the diagram"
        );
        assert_eq!(columns[0].label, "External");
        assert_eq!(columns[1].label, "Vault", "a contact is drawn by name");
        assert!(columns[1].named);
        assert_eq!(
            columns[1].contract, "Ever Wallet",
            "and says what the account runs when we recognise its code"
        );
        assert_eq!(columns[0].contract, "", "the outside world runs nothing");
        assert_eq!(
            columns[2].label, "My Wallet",
            "and our own wallet says so rather than showing its address"
        );
    }

    #[test]
    fn an_event_is_not_accused_of_failing_to_run() {
        use slint::Model;

        let rows = super::trace_edges(&trace(
            vec![
                trace_edge("transfer", 1, 2, Some((true, ""))),
                trace_edge("event", 1, 0, None),
                trace_edge("op 0x02edf6b4", 1, 2, None),
            ],
            &["", "-1:a", "-1:b"],
        ));

        assert!(rows[0].executed && rows[0].ok);
        let carried = rows[0].movements.row_data(0).expect("a movement is drawn");
        assert_eq!(
            (
                carried.amount_int.as_str(),
                carried.amount_frac.as_str(),
                carried.symbol.as_str()
            ),
            ("2", ".500\u{2004}000\u{2004}000", "COIN"),
            "the arrow's amount is split for the app's own typography"
        );
        assert!(
            rows[1].is_event && !rows[1].executed,
            "an event leaves the chain and produces no transaction"
        );
        assert_eq!(
            rows[1].movements.row_count(),
            0,
            "and a message that moved nothing says nothing"
        );
        assert!(
            !rows[2].is_event && !rows[2].executed,
            "an internal message with no destination transaction is a real gap"
        );
    }

    #[test]
    fn a_failed_hop_says_what_went_wrong_rather_than_showing_a_bare_code() {
        let rows = super::trace_edges(&trace(
            vec![trace_edge("transfer", 1, 2, Some((false, "exit 37")))],
            &["", "-1:a", "-1:b"],
        ));

        assert!(rows[0].executed && !rows[0].ok);
        assert_eq!(rows[0].failure, "exit 37");
        assert_eq!(rows[0].fee, "0.007\u{2004}400\u{2004}000");
    }

    #[test]
    fn the_row_the_trace_was_opened_from_is_marked_even_when_the_story_starts_above_it() {
        use cc_wallet_app::Digest32;

        let mut trace = trace(
            vec![
                trace_edge("op 0x8786db21", 0, 1, Some((true, ""))),
                trace_edge("transfer", 1, 2, Some((true, ""))),
            ],
            &["", "-1:a", "-1:b"],
        );
        trace.focus = Digest32::try_from_hex(&"cd".repeat(32)).expect("canonical hash");
        assert!(
            super::trace_edges(&trace).iter().all(|row| !row.focus),
            "no row claims to be the one that was opened"
        );

        trace.focus = Digest32::try_from_hex(HASH64).expect("canonical hash");
        assert!(
            super::trace_edges(&trace).iter().all(|row| row.focus),
            "and the rows that carry that transaction do"
        );
    }

    #[test]
    fn the_diagram_is_framed_and_only_as_tall_as_it_has_rows() {
        let page = include_str!("../../ui/pages/explorer_page.slint");
        let diagram = include_str!("../../ui/components/trace_diagram.slint");

        assert!(
            page.contains("viewport_h: min(root.trace_edges.length * 66px,"),
            "a one-row trace draws no empty field under itself"
        );
        assert!(
            page.contains("max(330px, root.page_height - 250px));"),
            "and a long one is given as much of the window as the card can hold"
        );
        assert!(
            diagram.contains("border-width: 1px;")
                && diagram.contains("border-color: Palette.border_subtle;"),
            "the drawing is a framed panel, not a dark field bleeding into the card"
        );
    }

    #[test]
    fn the_clock_corners_centre_their_two_lines() {
        let page = include_str!("../../ui/pages/explorer_page.slint");
        let corner = page
            .split_once("component CornerText")
            .expect("the corner label component exists")
            .1
            .split_once("export component ExplorerPage")
            .expect("it ends before the page")
            .0;

        assert!(
            corner.contains("alignment: center;"),
            "the corner text sits in the middle of its frame, not against the top"
        );
        assert_eq!(
            page.matches(
                "width: parent.fw - parent.tpad_edge - parent.tpad_dial; height: parent.fh;"
            )
            .count(),
            4,
            "all four corner labels are drawn to the full height of their frame"
        );
    }

    #[test]
    fn the_clock_corners_take_their_room_from_the_dial_not_from_a_fitted_number() {
        let page = include_str!("../../ui/pages/explorer_page.slint");

        assert!(
            page.contains("border-radius: parent.dial / 2;") && page.contains("size: parent.dial;"),
            "the circle that bites the corner cards is the dial's own footprint, \
             so the cards keep every pixel the dial does not cover"
        );
        assert!(
            !page.contains("parent.cpad + 13px") && !page.contains("parent.fw - 26px"),
            "the corner text is placed by named padding, not by numbers fitted to one label"
        );
        assert_eq!(
            page.matches("parent.tpad_edge").count(),
            6,
            "both left corners and all four widths take one padding from the card edge"
        );
        assert_eq!(
            page.matches("parent.tpad_dial").count(),
            6,
            "both right corners and all four widths take one padding towards the dial"
        );
    }

    #[test]
    fn an_explorer_model_is_rebuilt_only_when_what_it_draws_changes() {
        let rows = vec![account_tx(
            cc_wallet_app::AccountTxKind::In,
            "-1:a",
            0,
            Vec::new(),
        )];
        let steady = super::explorer_change_hash(&rows, "-1:me", 7, 42);

        assert_eq!(
            steady,
            super::explorer_change_hash(&rows, "-1:me", 7, 42),
            "nothing changed, so nothing is rebuilt"
        );
        assert_ne!(
            steady,
            super::explorer_change_hash(&rows, "-1:other", 7, 42),
            "a different wallet renames the counterparties"
        );
        assert_ne!(
            steady,
            super::explorer_change_hash(&rows, "-1:me", 8, 42),
            "an edited contact renames them too"
        );
        assert_ne!(
            steady,
            super::explorer_change_hash(&rows, "-1:me", 7, 43),
            "and midnight rewrites the day bands"
        );

        let mut moved = rows.clone();
        moved[0].lt += 1;
        assert_ne!(steady, super::explorer_change_hash(&moved, "-1:me", 7, 42));
    }

    #[test]
    fn the_diagram_writes_amounts_the_way_the_rest_of_the_app_does() {
        let diagram = include_str!("../../ui/components/trace_diagram.slint");

        assert!(
            diagram.contains("for m in e.movements: Amount {"),
            "the diagram draws its amounts with the shared component"
        );
        assert!(
            include_str!("../../ui/widgets.slint").contains("initial: root.amount.initial;"),
            "and the token's own mark sits beside the number, in that component"
        );
        assert!(
            diagram.contains("if !p.is_external: VerticalLayout {")
                && diagram.contains("CopyButton { value: p.address; }"),
            "every account in the diagram can be copied from its column"
        );
    }

    #[test]
    fn the_trace_sheet_can_be_dragged_and_scrolled_in_both_directions() {
        let diagram = include_str!("../../ui/components/trace_diagram.slint");

        assert!(
            diagram.contains("moved =>") && diagram.contains("PointerEventKind.down"),
            "the sheet is grabbed and moved, not just scrolled"
        );
        assert!(
            diagram.contains("scroll-event"),
            "and the wheel pans it as well"
        );
        for axis in ["root.clamp_x", "root.clamp_y"] {
            assert!(
                diagram.contains(axis),
                "panning past the edge of the sheet is clamped on {axis}"
            );
        }
        assert!(
            diagram.contains("MouseCursor.grabbing : MouseCursor.grab"),
            "the cursor says the sheet can be taken hold of, and when it is held"
        );
    }

    #[test]
    fn a_trace_longer_than_its_window_can_be_crossed_in_one_gesture() {
        let diagram = include_str!("../../ui/components/trace_diagram.slint");
        let app = include_str!("../../ui/app.slint");

        assert!(
            app.contains("interactive: !PageScroll.held;"),
            "the page stands its own scrolling down while a sheet has the pointer"
        );
        assert!(
            diagram.contains("PageScroll.held = self.has-hover;"),
            "and the sheet is what says so"
        );
        assert!(
            diagram.contains("EventResult.reject"),
            "a wheel the sheet cannot spend goes back to the page behind it"
        );
        assert!(
            diagram.contains("function edge_pull("),
            "a drag that reaches the edge of the window carries on"
        );
        assert!(
            diagram.contains("root.vel_x *= 0.93;") && diagram.contains("root.vel_y *= 0.93;"),
            "and a thrown sheet settles rather than stopping dead"
        );
        assert!(
            diagram.contains("if root.roams_y: SheetBar {")
                && diagram.contains("if root.roams_x: SheetBar {"),
            "each axis with more drawing than window carries a bar"
        );
        for key in ["Key.PageDown", "Key.Home", "Key.End", "Key.DownArrow"] {
            assert!(
                diagram.contains(key),
                "the sheet can be walked from the keyboard with {key}"
            );
        }
    }

    #[test]
    fn the_trace_can_be_read_by_method_name_or_by_raw_op() {
        let diagram = include_str!("../../ui/components/trace_diagram.slint");
        let page = include_str!("../../ui/pages/explorer_page.slint");

        assert!(
            diagram.contains("root.raw_ops && raw_op != \"\" ? raw_op : op"),
            "a number replaces a name only when the reader asked and there is one"
        );
        for word in ["METHOD", "RAW OP"] {
            assert!(page.contains(word), "the toolbar offers `{word}`");
        }
        assert!(
            page.contains("raw_ops: root.trace_raw_ops;"),
            "and the page's choice reaches the diagram"
        );
        assert!(
            page.contains("property <bool> trace_raw_ops"),
            "the choice is the page's own, not the controller's — nothing is refetched"
        );
    }

    #[test]
    fn the_trace_panel_and_the_list_never_share_the_card() {
        let page = include_str!("../../ui/pages/explorer_page.slint");
        let list = page
            .split_once(TRANSACTIONS_HEADER)
            .expect("the transactions card opens with its header icon")
            .1;

        assert!(
            list.contains(r#"title: root.trace_open ? "Transaction Trace" : "Transactions";"#),
            "the card header says which of the two it is showing"
        );
        assert_eq!(
            list.matches("if !root.trace_open").count(),
            9,
            "every list state stands down while the diagram is open"
        );
        for state in ["Walking the message tree…", "Trace unavailable"] {
            assert!(
                list.contains(state),
                "the trace panel has no wording for `{state}`"
            );
        }
    }

    #[test]
    fn a_live_election_counts_itself_down_in_the_hands_colour_not_a_rounds() {
        let page = include_str!("../../ui/pages/explorer_page.slint");
        let clock = include_str!("../../ui/components/validator_clock.slint");

        assert!(
            page.contains(
                r#"title: root.clock_elections_open ? "ELECTION ENDS IN" : "NEXT ELECTION IN";"#
            ),
            "an open election counts down its own end, not the next election"
        );
        assert!(
            !page.contains("Palette.value_in : Palette.text_primary"),
            "OPEN must not borrow the green that names a round on this dial"
        );
        assert_eq!(
            page.matches("Palette.clock_now").count(),
            2,
            "both the phase word and its countdown take the hand's colour"
        );
        assert!(
            clock.contains("needle_fill: Palette.clock_now;"),
            "the hand and the words that say an election is live share one source"
        );
    }

    #[test]
    fn the_transaction_list_states_every_way_a_history_read_can_end() {
        let page = include_str!("../../ui/pages/explorer_page.slint");
        let list = page
            .split_once(TRANSACTIONS_HEADER)
            .expect("the transactions card opens with its header icon")
            .1;

        for state in [
            "No account selected",
            "Fetching transactions…",
            "History unavailable",
            "No transactions in reach",
        ] {
            assert!(
                list.contains(state),
                "the transaction card has no wording for `{state}`"
            );
        }
        assert!(
            list.contains("could not be decoded"),
            "a page the endpoint sent but we could not read is never silently shortened"
        );
        for column in [
            "\"TIME\"",
            "\"TYPE\"",
            "\"FROM / TO\"",
            "\"VALUE\"",
            "\"FEE\"",
            "\"TX HASH\"",
        ] {
            assert!(
                list.contains(column),
                "the list is missing its {column} column"
            );
        }
    }

    #[test]
    fn account_state_rows_use_the_hairline_divider_and_the_wallet_status_treatment() {
        let page = include_str!("../../ui/pages/explorer_page.slint");
        let panel = page
            .split_once(ACCOUNT_STATE_HEADER)
            .expect("the account state card opens with its header icon")
            .1
            .split_once(TRANSACTIONS_HEADER)
            .expect("the transactions card opens with its header icon")
            .0;

        assert!(page.contains("component FactDivider"));
        assert!(
            !page.contains("·"),
            "no row spells a separator as punctuation any more"
        );
        assert!(page.contains("lead_label: \"Bits\";"));
        assert!(page.contains("trail_label: \"Cells\";"));
        assert!(
            !panel.contains("Palette.positive_quiet"),
            "the status word is bare, without the chip fill the wallet header never had"
        );
        assert!(page.contains("StatusDot { tint: root.st_fg; pulse: false; }"));
        assert_eq!(
            panel.matches("amount_color: Palette.value_in;").count(),
            2,
            "the balance and the currency holdings carry Activity's incoming green"
        );
        assert!(
            page.contains("amount_color: Palette.warning;"),
            "a debt keeps its own tone"
        );
    }

    #[test]
    fn a_balance_the_native_domain_cannot_format_falls_back_to_base_units() {
        let view = account_view(&inspection(u128::MAX, &[]), "-1:00");
        assert_eq!(
            view.balance.amount_int,
            "340\u{2019}282\u{2019}366\u{2019}920\u{2019}938\u{2019}463\u{2019}463\u{2019}374\u{2019}607\u{2019}431\u{2019}768\u{2019}211\u{2019}455"
        );
        assert_eq!(view.balance.amount_frac, "");
        assert_eq!(view.balance.symbol, "COIN");
    }

    #[test]
    fn an_unparseable_typed_address_is_shown_as_typed() {
        let view = account_view(&inspection(0, &[]), "not-an-address");
        assert_eq!(view.address, "not-an-address");
        assert!(view.has_code);
    }

    #[test]
    fn clearing_wipes_the_field_and_the_looked_up_account() {
        let page = include_str!("../../ui/pages/explorer_page.slint");
        let clear = page
            .split_once("label: \"Clear\";")
            .expect("the Clear button exists")
            .1;
        assert!(clear.contains("clicked => { root.address_input = \"\"; root.lookup(\"\"); }"));
        assert!(clear.contains(
            "enabled: root.address_input != \"\" || root.has_account || root.loading || root.error != \"\";"
        ));
    }

    #[test]
    fn the_explorer_reads_at_the_same_volume_as_the_rest_of_the_app() {
        let page = include_str!("../../ui/pages/explorer_page.slint");

        let rows = page
            .split_once("component StatRow")
            .expect("the label/value rows are declared before the stats rows")
            .0;
        assert!(
            !rows.contains("color: Palette.text_primary;"),
            "the brightest tone belongs to titles, not to row values"
        );
        assert!(
            !rows.contains("font-size: Fonts.body;"),
            "account rows are set at Fonts.small like the rest of the dense surfaces"
        );

        let amounts = page
            .split_once("component AmountRow")
            .expect("the amount row exists")
            .1
            .split_once("\ncomponent ")
            .expect("the amount row ends before the next component")
            .0;
        assert!(
            amounts.contains("Amount {") && !amounts.contains("font_size:"),
            "AmountRow must take the shared amount's size, not set its own"
        );
        assert!(
            include_str!("../../ui/widgets.slint")
                .contains("in property <length> font_size: Fonts.body;"),
            "the shared amount's default size is what makes the Explorer's figures lead"
        );
    }

    #[test]
    fn hashes_and_addresses_are_actually_monospaced_not_merely_labelled_so() {
        let app = include_str!("../../ui/app.slint");
        let widgets = include_str!("../../ui/widgets.slint");

        assert!(
            include_str!("../../ui/design_tokens.slint").contains("mono: \"Chivo Mono\";"),
            "the mono face is named once, in the token layer"
        );
        assert!(
            app.contains("import \"../assets/fonts/ChivoMono-Regular.ttf\";")
                && app.contains("import \"../assets/fonts/ChivoMono-SemiBold.ttf\";"),
            "the face has to ship with the binary; a portable build has no system fonts to borrow"
        );
        assert!(
            widgets.contains("text: root.placeholder;")
                && widgets
                    .split_once("text: root.placeholder;")
                    .expect("the placeholder is rendered")
                    .1
                    .contains("font-family: Fonts.ui;"),
            "a hint is prose: it stays in the interface face even in a monospaced field"
        );
    }

    #[test]
    fn the_brand_mark_is_drawn_not_pasted() {
        let nav = include_str!("../../ui/components/top_nav.slint");
        let mark = include_str!("../../ui/components/brand_mark.slint");

        assert!(nav.contains("BrandMark { size: 38px; }"));
        assert!(
            !nav.contains("@image-url"),
            "the mark is geometry now, not a bitmap that blurs when scaled"
        );
        assert_eq!(
            mark.matches("ArcTo {").count(),
            4,
            "two C's, each an outer sweep and an inner sweep back"
        );
        assert!(mark.contains("viewbox-width: 100;"));
    }

    #[test]
    fn the_scanned_address_survives_a_trip_to_another_tab() {
        let app = include_str!("../../ui/app.slint");
        let page = include_str!("../../ui/pages/explorer_page.slint");

        assert!(
            page.contains("in-out property <string> address_input;"),
            "the page borrows the field's text rather than owning it"
        );
        assert!(
            app.contains("in-out property <string> expl_address: \"\";")
                && app.contains("address_input <=> root.expl_address;"),
            "the window holds it, so rebuilding the page on a tab switch keeps it"
        );
    }

    #[test]
    fn the_address_field_pastes_and_the_state_rows_copy_with_an_acknowledgement() {
        let page = include_str!("../../ui/pages/explorer_page.slint");
        let widgets = include_str!("../../ui/widgets.slint");

        assert!(page.contains("addr_field.paste_replace();"));
        assert!(page.contains(
            "icon: root.pasted ? @image-url(\"../../assets/icons/check.svg\") : @image-url(\"../../assets/icons/paste.svg\");"
        ));
        assert!(page.contains("CopyButton { value: root.copy_value; }"));
        assert!(widgets.contains("export component CopyButton inherits IconButton"));
        assert!(widgets.contains(
            "icon: root.copied ? @image-url(\"../assets/icons/check.svg\") : @image-url(\"../assets/icons/copy.svg\");"
        ));
        assert!(widgets.contains("tint: root.copied ? Palette.positive : root.idle_tint;"));
    }

    #[test]
    fn a_state_row_puts_copy_beside_its_value_and_refresh_at_the_row_edge() {
        let page = include_str!("../../ui/pages/explorer_page.slint");

        assert!(page.contains("max-width: value_text.preferred-width + 14px;"));
        let row = page
            .split_once("component KvRow inherits HorizontalLayout")
            .expect("the state row exists")
            .1
            .split_once("component FactDivider")
            .expect("the row ends before the divider component")
            .0;
        let copy_at = row.find("CopyButton").expect("the row can copy its value");
        let slack_at = row
            .find("Rectangle { horizontal-stretch: 1; min-width: 0px; }")
            .expect("the row's leftover room is a cell of its own");
        let refresh_at = row.find("RefreshButton").expect("the row can be re-read");
        assert!(
            copy_at < slack_at && slack_at < refresh_at,
            "copy beside the value, then the slack, then refresh on the edge"
        );

        let facts = page
            .split_once("component FactsRow inherits HorizontalLayout")
            .expect("the two-fact row exists")
            .1
            .split_once("component SectionLabel")
            .expect("the row ends before the section label")
            .0;
        assert!(
            facts.find("CopyButton").expect("it copies too")
                < facts
                    .find("FactDivider")
                    .expect("its facts are split by the hairline"),
            "the copy belongs to the fact before the hairline"
        );
    }

    #[test]
    fn an_account_reads_the_same_colour_in_the_strip_and_in_the_card() {
        let theme = include_str!("../../ui/theme.slint");
        let strip = include_str!("../../ui/pages/wallet_sections.slint");
        let page = include_str!("../../ui/pages/explorer_page.slint");

        assert!(theme.contains("pure public function account_fg(status: string) -> color {"));
        assert!(theme.contains(": Palette.text_tertiary;"));
        assert!(strip.contains("tint: Status.account_fg(root.wallet_status);"));
        assert!(strip.contains("color: Status.account_fg(root.wallet_status);"));
        assert!(page.contains("property <color> st_fg: Status.account_fg(root.account.status);"));
        assert!(
            !strip.contains("status_active"),
            "the strip coloured by a bool and so could not tell Uninit from Non-exist"
        );
    }

    #[test]
    fn the_account_card_scrolls_without_drawing_a_scrollbar() {
        let page = include_str!("../../ui/pages/explorer_page.slint");
        assert_eq!(
            page.matches("vertical-scrollbar-policy: ScrollBarPolicy.always-off;")
                .count(),
            2,
            "neither the holdings nor the decoded fields draw a bar over their values"
        );
        assert_eq!(
            page.matches("horizontal-scrollbar-policy: ScrollBarPolicy.always-off;")
                .count(),
            2
        );
    }

    #[test]
    fn a_refresh_is_acknowledged_from_outside_the_card_its_press_rebuilds() {
        let page = include_str!("../../ui/pages/explorer_page.slint");
        let widgets = include_str!("../../ui/widgets.slint");

        assert!(page.contains("account_refresh_ack := Timer {"));
        assert!(page.contains("refresh_acked: root.account_refresh_acked;"));
        assert!(page.contains(
            "RefreshButton { acknowledged: root.refresh_acked; refreshed => { root.refresh(); } }"
        ));
        assert!(page.contains("if (!root.loading && root.account_refresh_acked) {"));
        assert!(widgets.contains("in property <bool> acknowledged: false;"));
        assert!(widgets.contains("property <bool> ticked: root.asked || root.acknowledged;"));
    }
}

#[cfg(test)]
mod secret_lifetime_tests {
    use slint::Model;

    use super::{
        ActivityFilters, activity_change_hash, empty_import_words,
        entering_unlocked_with_entry_secrets, error_banner, leaving_onboarding_with_entry_secrets,
        leaving_settings_with_entry_secrets, live_badge_enabled, risk_rows_changed,
        seed_models_need_refresh, wallet_asset_ids,
    };
    use cc_wallet_app::{
        ActivityDirection, ActivityEvent, AddressBookEntry, AppPhase, AppState, AssetId, CcAmount,
        LiveStatus, WalletSnapshot,
    };

    #[test]
    fn cleared_import_model_has_twelve_empty_slots() {
        let model = empty_import_words();
        assert_eq!(model.row_count(), 12);
        for row in 0..model.row_count() {
            assert!(model.row_data(row).expect("slot exists").is_empty());
        }
    }

    #[test]
    fn onboarding_and_locked_entry_paths_clear_before_unlocked_render() {
        assert!(entering_unlocked_with_entry_secrets(
            AppPhase::Unlocked,
            true
        ));
        assert!(!entering_unlocked_with_entry_secrets(
            AppPhase::Onboarding,
            true
        ));
        assert!(!entering_unlocked_with_entry_secrets(
            AppPhase::Unlocked,
            false
        ));
        assert!(leaving_onboarding_with_entry_secrets(
            AppPhase::Selecting,
            true
        ));
        assert!(!leaving_onboarding_with_entry_secrets(
            AppPhase::Onboarding,
            true
        ));
        assert!(leaving_settings_with_entry_secrets(
            cc_wallet_app::AppTab::Wallet,
            true
        ));
        assert!(!leaving_settings_with_entry_secrets(
            cc_wallet_app::AppTab::Settings,
            true
        ));
    }

    #[test]
    fn unchanged_seed_exposure_does_not_rebuild_non_zeroizing_gui_models() {
        assert!(!seed_models_need_refresh("one two three", "one two three"));
        assert!(!seed_models_need_refresh("", ""));
        assert!(seed_models_need_refresh("one two three", ""));
        assert!(seed_models_need_refresh("one two three", "four five six"));
    }

    #[test]
    fn secret_fields_suppress_primary_selection_and_hidden_sink_retention() {
        let widgets = include_str!("../../ui/widgets.slint");
        assert!(widgets.contains("if (root.holds_secret) {\n            input.text = \"\";"));
        assert!(widgets.contains("if root.holds_secret: TouchArea"));
        assert!(widgets.contains("event.text == \"c\" || event.text == \"C\""));
        assert!(widgets.contains("event.text == \"a\" || event.text == \"A\""));

        for source in [
            include_str!("../../ui/components/lock_screen.slint"),
            include_str!("../../ui/pages/settings_page.slint"),
        ] {
            let sink = source
                .split("import_paste := Field")
                .nth(1)
                .expect("hidden import paste sink exists");
            assert!(sink[..sink.len().min(320)].contains("is_secret: true"));
            assert!(sink.contains("import_paste.set_text(\"\")"));
        }
        let settings = include_str!("../../ui/pages/settings_page.slint");
        assert!(settings.contains(
            "root.import_words = root.distribute_seed(\"\"); root.import_gen += 1; root.import_edited(); root.seed_mode = \"view\";"
        ));
    }

    #[test]
    fn seed_copy_countdown_renders_the_controller_clipboard_ttl() {
        let lock_screen = include_str!("../../ui/components/lock_screen.slint");
        let settings = include_str!("../../ui/pages/settings_page.slint");

        for source in [lock_screen, settings] {
            assert!(source.contains("root.seed_copy_ttl > 0 ? (root.seed_copy_ttl + \"s\")"));
            assert!(!source.contains("copy_countdown"));
            assert!(!source.contains("seed_copied"));
        }
    }

    #[test]
    fn rpc_banner_is_dismissible_without_rendering_the_safety_blocker_directly() {
        let snapshot_only = AppState {
            snapshot_refresh_error: Some("RPC unavailable".to_owned()),
            ..AppState::default()
        };
        assert_eq!(error_banner(&snapshot_only), (String::new(), false));

        let transient = AppState {
            snapshot_refresh_error: Some("RPC unavailable".to_owned()),
            error: Some("RPC unavailable".to_owned()),
            ..AppState::default()
        };
        assert_eq!(
            error_banner(&transient),
            ("RPC unavailable".to_owned(), true)
        );

        let sticky = AppState {
            persistence_error: Some("Wallet is read-only".to_owned()),
            error: Some("RPC unavailable".to_owned()),
            ..AppState::default()
        };
        assert_eq!(
            error_banner(&sticky),
            ("Wallet is read-only".to_owned(), false)
        );
    }

    #[test]
    fn live_badge_waits_for_the_snapshot_error_to_clear() {
        let healthy = AppState {
            live_status: LiveStatus::Live,
            ..AppState::default()
        };
        assert!(live_badge_enabled(&healthy));

        let stale_snapshot = AppState {
            live_status: LiveStatus::Live,
            snapshot_refresh_error: Some("RPC unavailable".to_owned()),
            ..AppState::default()
        };
        assert!(!live_badge_enabled(&stale_snapshot));
    }

    #[test]
    fn unknown_balances_never_enter_wallet_assets_or_send() {
        let wallet = WalletSnapshot::new(
            "0:me",
            0,
            "active",
            0,
            std::collections::BTreeMap::from([
                (4, CcAmount::from_u128(1_000_000_000_000_000_000)),
                (5, CcAmount::from_u128(1_000_000_000_000_000_000)),
            ]),
            0,
        )
        .unwrap();
        let mut state = AppState {
            wallet: Some(wallet),
            ..AppState::default()
        };

        assert_eq!(wallet_asset_ids(&state), vec![AssetId::Native]);

        state.visible_cc_assets.insert(2);
        state.visible_cc_assets.insert(4);
        assert_eq!(
            wallet_asset_ids(&state),
            vec![AssetId::Native, AssetId::CurrencyCollection(2)]
        );
    }

    #[test]
    fn error_banner_close_affordance_is_wired_only_for_dismissible_errors() {
        let app = include_str!("../../ui/app.slint");
        let callbacks = include_str!("callbacks.rs");

        assert!(app.contains("in property <bool> error_dismissible: false;"));
        assert!(app.contains("callback clear_error();"));
        assert!(app.contains("if root.error_dismissible: VerticalLayout"));
        assert!(app.contains("clicked => { root.clear_error(); }"));
        assert!(app.contains("@image-url(\"../assets/icons/x.svg\")"));
        assert!(callbacks.contains("on0!(on_clear_error, AppCommand::ClearError);"));
    }

    #[test]
    fn wallet_folder_is_not_exposed_as_ui_state() {
        let forbidden_property = concat!("wallet", "_root");
        let forbidden_label = concat!("WALLET", " ROOT");
        let forbidden_card = concat!("Wallet", " storage");
        let app = include_str!("../../ui/app.slint");
        assert!(!app.contains(forbidden_property));
        for source in [
            include_str!("../../ui/components/lock_screen.slint"),
            include_str!("../../ui/components/wallet_picker.slint"),
            include_str!("../../ui/pages/settings_page.slint"),
        ] {
            assert!(!source.contains(forbidden_property));
            assert!(!source.contains(forbidden_label));
            assert!(!source.contains(forbidden_card));
        }
    }

    #[test]
    fn risk_rows_change_guard_tracks_labels_and_selection() {
        let cache = (
            vec!["res A".to_owned(), "res B".to_owned()],
            vec![false, true],
        );
        assert!(!risk_rows_changed(&cache, &cache.0, &cache.1));
        assert!(risk_rows_changed(&cache, &cache.0, &[true, true]));
        assert!(risk_rows_changed(
            &cache,
            &["res A".to_owned(), "res C".to_owned()],
            &cache.1
        ));
        let empty: (Vec<String>, Vec<bool>) = (Vec::new(), Vec::new());
        assert!(!risk_rows_changed(&empty, &[], &[]));
    }

    #[test]
    fn risk_overlap_rows_are_set_only_behind_the_change_guard() {
        let src = include_str!("sync.rs");
        let set_call = concat!("ui.set_risk", "_overlap_rows(");
        let guard = src
            .find("risk_rows_changed(\n        &cache.risk_rows,")
            .expect("the guarded rebuild block exists");
        let set = src.find(set_call).expect("the model set exists");
        assert!(
            guard < set,
            "set_risk_overlap_rows must sit inside the risk_rows_changed guard"
        );
        assert_eq!(
            src.matches(set_call).count(),
            1,
            "exactly one risk-row model set, and it is inside the guard"
        );
    }

    fn ev(lt: u64, finality_ms: Option<u64>) -> ActivityEvent {
        ActivityEvent {
            direction: ActivityDirection::In,
            tx_hash: None,
            movements: Vec::new(),
            finality_ms,
            ..ActivityEvent::test_stub(lt, 1_700_000_000)
        }
    }

    fn hash_of(events: &[ActivityEvent], today: i64) -> u64 {
        let refs: Vec<&ActivityEvent> = events.iter().collect();
        activity_change_hash(&refs, &ActivityFilters::default(), 0, "0:me", today)
    }

    #[test]
    fn activity_hash_stable_when_nothing_changed() {
        let events = vec![ev(2, None), ev(1, Some(100))];
        assert_eq!(hash_of(&events, 5), hash_of(&events, 5));
    }

    #[test]
    fn activity_hash_changes_when_a_deep_row_gains_finality() {
        let before = vec![ev(2, None), ev(1, None)];
        let after = vec![ev(2, None), ev(1, Some(1500))];
        assert_ne!(hash_of(&before, 5), hash_of(&after, 5));
    }

    #[test]
    fn activity_hash_changes_on_equal_count_merge_evict() {
        let before = vec![ev(3, None), ev(2, None)];
        let after = vec![ev(3, None), ev(9, None)];
        assert_ne!(hash_of(&before, 5), hash_of(&after, 5));
    }

    #[test]
    fn activity_hash_changes_at_date_rollover() {
        let events = vec![ev(2, None), ev(1, None)];
        assert_ne!(hash_of(&events, 5), hash_of(&events, 6));
    }

    #[test]
    fn activity_hash_tracks_filters_contacts_and_wallet() {
        let events = [ev(2, None)];
        let refs: Vec<&ActivityEvent> = events.iter().collect();
        let base = activity_change_hash(&refs, &ActivityFilters::default(), 0, "0:me", 5);
        let filtered = ActivityFilters {
            dir: "in".to_owned(),
            ..Default::default()
        };
        assert_ne!(base, activity_change_hash(&refs, &filtered, 0, "0:me", 5));
        assert_ne!(
            base,
            activity_change_hash(&refs, &ActivityFilters::default(), 1, "0:me", 5)
        );
        assert_ne!(
            base,
            activity_change_hash(&refs, &ActivityFilters::default(), 0, "0:you", 5)
        );
    }

    #[test]
    fn contacts_compare_detects_field_edit() {
        let a = vec![AddressBookEntry {
            name: "Alice".to_owned(),
            address: "0:aaa".to_owned(),
            tag: "friend".to_owned(),
        }];
        let mut b = a.clone();
        assert_eq!(a, b, "identical books compare equal (no rebuild)");
        b[0].tag = "work".to_owned();
        assert_ne!(a, b, "a single-field edit is detected");
    }
}
