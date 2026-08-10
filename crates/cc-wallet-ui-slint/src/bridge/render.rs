use std::rc::Rc;

use cc_wallet_app::{
    AccountTrace, AccountTx, ActivityDirection, ActivityEvent, AddressBookEntry, AppState,
    AssetAmount, AssetId, AssetMovement, AssetTone, CcAmount, asset_meta, format_base_units,
    format_fixed9_amount, format_native_fixed9, parse_send_amount,
};
use slint::{Color, ModelRc, VecModel};
use zeroize::Zeroizing;

use super::{
    ActivityRow, AssetRow, ChatLineRow, ContactRow, ExplorerTxRow, TokenAmount, TraceEdgeRow,
    TracePartyCol,
};

fn rgb(v: u32) -> Color {
    Color::from_rgb_u8((v >> 16) as u8, (v >> 8) as u8, v as u8)
}

pub(super) fn asset_tone(tone: AssetTone) -> Color {
    rgb(match tone {
        AssetTone::Coin => 0x2B75D7,
        AssetTone::One => 0x1F855A,
        AssetTone::Two => 0xA06A1D,
        AssetTone::Three => 0x9B50B4,
        AssetTone::Unknown => 0x6D7786,
    })
}

pub(super) const CONTACT_TONES: [u32; 6] =
    [0x3472D8, 0x218560, 0xA46A07, 0x7D68BC, 0xB55487, 0x158191];

pub(super) fn contact_tone(index: usize) -> Color {
    rgb(CONTACT_TONES[index % CONTACT_TONES.len()])
}

pub(super) fn asset_row(state: &AppState, asset: AssetId, selected: AssetId) -> AssetRow {
    let meta = asset_meta(asset);
    let unknown_cc = matches!(asset, AssetId::CurrencyCollection(_)) && !asset.is_known_cc();
    let balance = state.balance_or_zero(asset);
    let fixed9 = meta.decimals == Some(9);
    let amount = if fixed9 {
        group_digits(
            &format_fixed9_amount(&balance)
                .expect("a supported asset has the fixed-9 display contract"),
        )
    } else {
        format_base_units(&balance)
    };
    let (amount_int, amount_frac) = split_amount(&amount);
    let sendable = asset.is_sendable();
    let (control_id, currency_id): (i32, String) = match asset {
        AssetId::Native => (-1, String::new()),
        AssetId::CurrencyCollection(id) if asset.is_known_cc() => (id as i32, id.to_string()),
        AssetId::CurrencyCollection(id) => (-2, id.to_string()),
    };
    AssetRow {
        control_id,
        currency_id: currency_id.into(),
        sendable,
        name: if let AssetId::CurrencyCollection(id) = asset
            && unknown_cc
        {
            format!("Currency Collection #{id}").into()
        } else {
            meta.display_name.into()
        },
        symbol: if let AssetId::CurrencyCollection(id) = asset
            && unknown_cc
        {
            format!("#{id}").into()
        } else {
            meta.symbol.into()
        },
        amount: amount.clone().into(),
        amount_int: amount_int.into(),
        amount_frac: amount_frac.into(),
        color: asset_tone(meta.tone),
        initial: meta.mark.into(),
        selected: sendable && asset == selected,
        status: if asset.is_native() {
            "Always visible".into()
        } else if unknown_cc {
            "Read-only".into()
        } else {
            "Shown".into()
        },
        always: asset.is_native(),
        visible: match asset {
            AssetId::Native => true,
            AssetId::CurrencyCollection(id) if asset.is_known_cc() => {
                state.visible_cc_assets.contains(&id)
            }
            AssetId::CurrencyCollection(_) => false,
        },
    }
}

pub(super) fn token_amount(asset: AssetId, exact: &str) -> TokenAmount {
    let (initial, symbol, color) = movement_meta(asset);
    let (amount_int, amount_frac) = split_amount(&group_digits(exact));
    TokenAmount {
        amount_int: amount_int.into(),
        amount_frac: amount_frac.into(),
        symbol: symbol.into(),
        initial: initial.into(),
        color,
    }
}

pub(super) fn units_exact(asset: AssetId, units: u128) -> String {
    let amount = match asset {
        AssetId::Native => AssetAmount::native(units).ok(),
        AssetId::CurrencyCollection(id) => Some(AssetAmount::currency_collection(
            id,
            CcAmount::from_u128(units),
        )),
    };
    amount
        .as_ref()
        .and_then(|value| format_fixed9_amount(value).ok())
        .unwrap_or_else(|| units.to_string())
}

pub(super) fn token_units(asset: AssetId, units: u128) -> TokenAmount {
    token_amount(asset, &units_exact(asset, units))
}

pub(super) fn pool_reserve_row(asset: AssetId, units: u128) -> AssetRow {
    let meta = asset_meta(asset);
    let amount = token_units(asset, units);
    AssetRow {
        control_id: match asset {
            AssetId::Native => -1,
            AssetId::CurrencyCollection(id) => id as i32,
        },
        currency_id: match asset {
            AssetId::Native => Default::default(),
            AssetId::CurrencyCollection(id) => id.to_string().into(),
        },
        sendable: false,
        name: meta.display_name.into(),
        symbol: amount.symbol.clone(),
        amount: units_exact(asset, units).into(),
        amount_int: amount.amount_int,
        amount_frac: amount.amount_frac,
        color: amount.color,
        initial: amount.initial,
        selected: false,
        status: Default::default(),
        always: false,
        visible: true,
    }
}

fn initials(name: &str) -> String {
    let mut words = name.split_whitespace();
    let out: String = match (words.next(), words.next()) {
        (Some(first), Some(second)) => first
            .chars()
            .next()
            .into_iter()
            .chain(second.chars().next())
            .collect(),
        (Some(single), None) => single.chars().take(2).collect(),
        (None, _) => String::new(),
    };
    let out: String = out.chars().flat_map(char::to_uppercase).collect();
    if out.is_empty() { "C".to_owned() } else { out }
}

pub(super) const INT_GROUP: &str = "\u{2019}";

pub(super) const FRAC_GROUP: &str = "\u{2004}";

pub(super) fn group_digits(amount: &str) -> String {
    group_editable(amount)
}

pub(super) fn ungroup_amount(text: &str) -> String {
    text.replace(INT_GROUP, "").replace(FRAC_GROUP, "")
}

pub(super) fn group_editable(amount: &str) -> String {
    let clean = amount.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        && amount.bytes().filter(|&b| b == b'.').count() <= 1;
    if !clean || amount.is_empty() {
        return amount.to_owned();
    }
    let group = |s: &str, from_right: bool| -> String {
        let bytes = s.as_bytes();
        let to_str = |c: &[u8]| {
            std::str::from_utf8(c)
                .expect("digit chunks are ascii")
                .to_owned()
        };
        let chunks: Vec<String> = if from_right {
            let mut c: Vec<String> = bytes.rchunks(3).map(to_str).collect();
            c.reverse();
            c
        } else {
            bytes.chunks(3).map(to_str).collect()
        };
        chunks.join(if from_right { INT_GROUP } else { FRAC_GROUP })
    };
    match amount.split_once('.') {
        Some((int, frac)) => format!("{}.{}", group(int, true), group(frac, false)),
        None => group(amount, true),
    }
}

pub(super) struct AmountFmt {
    pub text: String,
    pub cursor: i32,
}

const AMOUNT_MAX_INT_DIGITS: usize = 78;

const AMOUNT_MAX_FRAC_DIGITS: usize = 9;

fn sanitize_amount(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut seen_point = false;
    let mut int_digits = 0usize;
    let mut frac_digits = 0usize;
    for ch in text.chars() {
        match ch {
            '.' if !seen_point => {
                seen_point = true;
                out.push('.');
            }
            '0'..='9' if seen_point && frac_digits < AMOUNT_MAX_FRAC_DIGITS => {
                frac_digits += 1;
                out.push(ch);
            }
            '0'..='9' if !seen_point && int_digits < AMOUNT_MAX_INT_DIGITS => {
                int_digits += 1;
                out.push(ch);
            }
            _ => {}
        }
    }
    out
}

pub(super) fn regroup_amount(text: &str, cursor_byte: i32) -> AmountFmt {
    let mut at = (cursor_byte.max(0) as usize).min(text.len());
    while at > 0 && !text.is_char_boundary(at) {
        at -= 1;
    }
    let clean = sanitize_amount(text);
    let grouped = group_editable(&clean);
    if grouped == text {
        return AmountFmt {
            text: grouped,
            cursor: at as i32,
        };
    }
    let sig_before = text[..at]
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '.')
        .count();
    let mut seen = 0usize;
    let mut cursor = grouped.len();
    for (i, ch) in grouped.char_indices() {
        if seen == sig_before {
            cursor = i;
            break;
        }
        if ch.is_ascii_digit() || ch == '.' {
            seen += 1;
        }
    }
    AmountFmt {
        text: grouped,
        cursor: cursor as i32,
    }
}

pub(super) struct SeedExposure {
    pub text: Zeroizing<String>,
    pub words: Vec<Zeroizing<String>>,
}

pub(super) fn seed_exposure(show_seed: bool, seed_unsaved: bool, seed: &str) -> SeedExposure {
    let expose = show_seed || seed_unsaved;
    let text = if expose {
        Zeroizing::new(seed.to_owned())
    } else {
        Zeroizing::new(String::new())
    };
    let mut words: Vec<Zeroizing<String>> = if expose {
        seed.split_whitespace()
            .map(|word| Zeroizing::new(word.to_owned()))
            .collect()
    } else {
        Vec::new()
    };
    words.resize_with(12, || Zeroizing::new(String::new()));
    SeedExposure { text, words }
}

pub(super) fn display_send_amount(asset: AssetId, raw: &str) -> String {
    match parse_send_amount(asset, raw) {
        Ok(value) => group_editable(
            &format_fixed9_amount(&value)
                .expect("a sendable asset has the fixed-9 display contract"),
        ),
        Err(_) => group_editable(raw),
    }
}

pub(super) fn split_amount(grouped: &str) -> (String, String) {
    match grouped.split_once('.') {
        Some((int, frac)) => (int.to_owned(), format!(".{frac}")),
        None => (grouped.to_owned(), String::new()),
    }
}

pub(super) fn short_addr(addr: &str) -> String {
    let Some((wc, hash)) = addr.split_once(':') else {
        return addr.to_owned();
    };
    format!("{wc}:{}", middle_truncate(hash, 6, 6))
}

fn contact_color_index(address: &str) -> usize {
    let hash = address.bytes().fold(0u32, |acc, b| {
        acc.wrapping_mul(31).wrapping_add(u32::from(b))
    });
    (hash as usize) % CONTACT_TONES.len()
}

pub(super) fn contact_row(name: &str, address: &str, tag: &str) -> ContactRow {
    ContactRow {
        name: name.into(),
        address: address.into(),
        short: short_addr(address).into(),
        tag: tag.into(),
        color: contact_tone(contact_color_index(address)),
        initial: initials(name).into(),
    }
}

fn local_date(unix: u64) -> chrono::NaiveDate {
    chrono::DateTime::from_timestamp(unix as i64, 0)
        .unwrap_or_default()
        .with_timezone(&chrono::Local)
        .date_naive()
}

fn fmt_time(unix: u64) -> String {
    chrono::DateTime::from_timestamp(unix as i64, 0)
        .unwrap_or_default()
        .with_timezone(&chrono::Local)
        .format("%H:%M:%S")
        .to_string()
}

pub(super) fn fmt_datetime(unix: u64) -> String {
    chrono::DateTime::from_timestamp(unix as i64, 0)
        .unwrap_or_default()
        .with_timezone(&chrono::Local)
        .format("%b %-d, %Y, %H:%M:%S")
        .to_string()
}

pub(super) fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn day_bucket(unix: u64) -> i64 {
    use chrono::Datelike;
    local_date(unix).num_days_from_ce() as i64
}

pub(super) fn today_bucket(now: u64) -> i64 {
    day_bucket(now)
}

fn group_label(bucket: i64, today_bucket: i64) -> String {
    if bucket == today_bucket {
        return "TODAY".to_owned();
    }
    if bucket == today_bucket - 1 {
        return "YESTERDAY".to_owned();
    }
    let date = chrono::NaiveDate::from_num_days_from_ce_opt(bucket as i32).unwrap_or_default();
    date.format("%b %-d, %Y").to_string().to_uppercase()
}

pub(super) fn activity_rows(
    events: &[&ActivityEvent],
    my_address: &str,
    contacts: &[AddressBookEntry],
    now: u64,
) -> Vec<ActivityRow> {
    let today_bucket = day_bucket(now);
    let mut last_bucket: Option<i64> = None;
    events
        .iter()
        .map(|event| {
            let mut row = activity_row(event, my_address, contacts);
            let bucket = day_bucket(event.time_unix);
            if last_bucket != Some(bucket) {
                row.group = group_label(bucket, today_bucket).into();
                last_bucket = Some(bucket);
            }
            row
        })
        .collect()
}

pub(super) fn party_pill_label(addr: &str, contacts: &[AddressBookEntry]) -> String {
    if addr.is_empty() {
        return String::new();
    }
    contacts
        .iter()
        .find(|c| c.address == addr)
        .map(|c| c.name.clone())
        .unwrap_or_else(|| short_addr(addr))
}

fn counterparty_name(addr: &str, my_address: &str, contacts: &[AddressBookEntry]) -> String {
    if addr.is_empty() {
        return String::new();
    }
    if addr == my_address {
        return "My Wallet".to_owned();
    }
    contacts
        .iter()
        .find(|c| c.address == addr)
        .map(|c| c.name.clone())
        .unwrap_or_default()
}

fn middle_truncate(addr: &str, head: usize, tail: usize) -> String {
    let chars: Vec<char> = addr.chars().collect();
    if chars.len() <= head + tail + 1 {
        return addr.to_owned();
    }
    let start: String = chars[..head].iter().collect();
    let end: String = chars[chars.len() - tail..].iter().collect();
    format!("{start}…{end}")
}

fn format_finality(ms: Option<u64>) -> String {
    match ms {
        Some(ms) if ms < 1000 => format!("{ms}ms"),
        Some(ms) => format!("{:.1}s", ms as f64 / 1000.0),
        None => String::new(),
    }
}

pub(super) fn movement_meta(asset: AssetId) -> (String, String, Color) {
    let meta = asset_meta(asset);
    match asset {
        AssetId::CurrencyCollection(id) if !AssetId::CurrencyCollection(id).is_known_cc() => {
            (id.to_string(), format!("#{id}"), contact_tone(id as usize))
        }
        _ => (
            meta.mark.to_owned(),
            meta.symbol.to_owned(),
            asset_tone(meta.tone),
        ),
    }
}

pub(super) fn movement_rows(movements: &[AssetMovement]) -> Vec<TokenAmount> {
    movements
        .iter()
        .map(|movement| {
            let asset = movement.amount.asset_id();
            let (initial, symbol, color) = movement_meta(asset);
            let exact = if asset_meta(asset).decimals == Some(9) {
                group_digits(
                    &format_fixed9_amount(&movement.amount)
                        .expect("a supported movement has fixed-9 display"),
                )
            } else {
                format_base_units(&movement.amount)
            };
            let (amount_int, amount_frac) = split_amount(&exact);
            TokenAmount {
                amount_int: amount_int.into(),
                amount_frac: amount_frac.into(),
                symbol: symbol.into(),
                initial: initial.into(),
                color,
            }
        })
        .collect()
}

pub(super) fn explorer_tx_rows(
    transactions: &[AccountTx],
    my_address: &str,
    contacts: &[AddressBookEntry],
    now: u64,
) -> Vec<ExplorerTxRow> {
    let today_bucket = day_bucket(now);
    let mut last_bucket: Option<i64> = None;
    transactions
        .iter()
        .map(|tx| {
            let hash = tx.hash.to_string();
            let bucket = day_bucket(tx.time_unix);
            let group = if last_bucket == Some(bucket) {
                String::new()
            } else {
                last_bucket = Some(bucket);
                group_label(bucket, today_bucket)
            };
            ExplorerTxRow {
                time: fmt_time(tx.time_unix).into(),
                group: group.into(),
                kind: tx.kind.label().into(),
                is_in: tx.kind.is_in(),
                signed: tx.kind.is_signed_for_reader(),
                received: ModelRc::from(Rc::new(VecModel::from(movement_rows(&tx.received)))),
                success: tx.success,
                bounced: tx.bounced,
                party: if tx.counterparty.is_empty() {
                    "—".into()
                } else {
                    tx.counterparty.clone().into()
                },
                party_name: counterparty_name(&tx.counterparty, my_address, contacts).into(),
                party_extra: match tx.extra_parties {
                    0 => Default::default(),
                    n => format!("+{n} more").into(),
                },
                movements: ModelRc::from(Rc::new(VecModel::from(movement_rows(&tx.movements)))),
                fee: group_digits(
                    &format_native_fixed9(tx.fee_native)
                        .expect("a decoded transaction fee is in the native domain"),
                )
                .into(),
                hash_short: middle_truncate(&hash, 8, 6).into(),
                hash_full: hash.into(),
                exit_code: tx.exit_code,
            }
        })
        .collect()
}

pub(super) fn trace_parties(
    trace: &AccountTrace,
    my_address: &str,
    contacts: &[AddressBookEntry],
) -> Vec<TracePartyCol> {
    trace
        .parties
        .iter()
        .map(|party| {
            if party.is_external() {
                return TracePartyCol {
                    label: "External".into(),
                    address: Default::default(),
                    is_external: true,
                    named: true,
                    contract: Default::default(),
                };
            }
            let name = counterparty_name(&party.address, my_address, contacts);
            let named = !name.is_empty();
            TracePartyCol {
                label: if named {
                    name.into()
                } else {
                    short_addr(&party.address).into()
                },
                address: party.address.clone().into(),
                is_external: false,
                named,
                contract: party.contract.clone().into(),
            }
        })
        .collect()
}

pub(super) fn trace_edges(trace: &AccountTrace) -> Vec<TraceEdgeRow> {
    trace
        .edges
        .iter()
        .map(|edge| {
            let produced = edge.tx.as_ref();
            let hash = produced.map(|tx| tx.hash.to_string()).unwrap_or_default();
            TraceEdgeRow {
                hash_short: if hash.is_empty() {
                    Default::default()
                } else {
                    middle_truncate(&hash, 8, 6).into()
                },
                hash_full: hash.into(),
                from: edge.from as i32,
                to: edge.to as i32,
                op: edge.op.clone().into(),
                raw_op: edge.raw_op.clone().into(),
                movements: ModelRc::from(Rc::new(VecModel::from(movement_rows(
                    &edge
                        .movements
                        .iter()
                        .filter(|movement| !movement.amount.is_zero())
                        .cloned()
                        .collect::<Vec<_>>(),
                )))),
                fee: produced
                    .map(|tx| {
                        group_digits(
                            &format_native_fixed9(tx.fee_native)
                                .expect("a decoded transaction fee is in the native domain"),
                        )
                    })
                    .unwrap_or_default()
                    .into(),
                executed: produced.is_some(),
                ok: produced.is_some_and(|tx| tx.success),
                failure: produced
                    .map(|tx| tx.failure.clone())
                    .unwrap_or_default()
                    .into(),
                focus: produced.is_some_and(|tx| tx.hash == trace.focus),
                is_event: edge.op == "event",
            }
        })
        .collect()
}

fn activity_row(
    event: &ActivityEvent,
    my_address: &str,
    contacts: &[AddressBookEntry],
) -> ActivityRow {
    let movements = movement_rows(&event.movements);
    let fee = token_amount(
        AssetId::Native,
        &format_native_fixed9(event.fee_native)
            .expect("a decoded activity fee is in the native domain"),
    );
    let party_full = if event.counterparty.is_empty() {
        "—".to_owned()
    } else {
        event.counterparty.clone()
    };
    ActivityRow {
        time: fmt_time(event.time_unix).into(),
        is_in: matches!(event.direction, ActivityDirection::In),
        kind: event.direction.label().into(),
        party_name: counterparty_name(&event.counterparty, my_address, contacts).into(),
        party_full: party_full.clone().into(),
        party_mid: middle_truncate(&party_full, 14, 8).into(),
        movements: ModelRc::from(Rc::new(VecModel::from(movements))),
        fee,
        success: event.success,
        bounced: event.bounced,
        finality: format_finality(event.finality_ms).into(),
        pending: event.pending,
        tx_hash: event
            .tx_hash
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default()
            .into(),
        ext_hash: event
            .ext_msg_hash
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default()
            .into(),
        int_hash: event
            .int_msg_hash
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default()
            .into(),
        exit_code: event.exit_code,
        group: "".into(),
        has_party: !event.counterparty.is_empty(),
        has_message: event.message.is_some() && !event.counterparty.is_empty(),
    }
}

/// A conversation, ready to draw, with each day named once.
///
/// A bubble carries a time and nothing else, which reads fine until the thread
/// spans more than one day and yesterday's answer looks like this morning's.
/// The activity list already names its days; a conversation is the same history
/// and names them the same way.
pub(super) fn chat_line_rows(lines: &[cc_wallet_app::ChatLine], now: u64) -> Vec<ChatLineRow> {
    let today_bucket = day_bucket(now);
    let mut last_bucket: Option<i64> = None;
    lines
        .iter()
        .map(|line| {
            let bucket = day_bucket(line.time_unix);
            let day = if last_bucket == Some(bucket) {
                String::new()
            } else {
                last_bucket = Some(bucket);
                group_label(bucket, today_bucket)
            };
            ChatLineRow {
                outgoing: line.outgoing,
                time: fmt_time(line.time_unix).into(),
                day: day.into(),
                text: line.text.clone().into(),
                sealed: line.sealed,
                locked: line.locked,
                pending: line.pending,
            }
        })
        .collect()
}

#[cfg(test)]
mod number_grouping_tests {
    use cc_wallet_app::AssetId;

    use super::group_digits;

    #[test]
    fn groups_both_sides_of_the_point() {
        assert_eq!(
            group_digits("999999999999.999999999"),
            "999\u{2019}999\u{2019}999\u{2019}999.999\u{2004}999\u{2004}999"
        );
    }

    #[test]
    fn what_the_amount_field_shows_still_parses_as_an_amount() {
        use super::{parse_send_amount, regroup_amount, ungroup_amount};
        use cc_wallet_app::AssetId;

        let typed = "1023.565656565";
        let shown = regroup_amount(typed, typed.len() as i32).text;
        assert_eq!(shown, "1\u{2019}023.565\u{2004}656\u{2004}565");
        assert_eq!(
            ungroup_amount(&shown),
            typed,
            "both separators have to come back off before the domain sees the amount, \
             not just the integer's apostrophe"
        );
        assert!(parse_send_amount(AssetId::Native, &ungroup_amount(&shown)).is_ok());
    }

    #[test]
    fn the_two_sides_of_the_point_are_separated_by_different_marks() {
        use super::{FRAC_GROUP, INT_GROUP};
        assert_eq!(INT_GROUP, "\u{2019}");
        assert_eq!(
            FRAC_GROUP, "\u{2004}",
            "a fraction is grouped by a third-em space, not by the integer's apostrophe: \
             the two runs read as one number otherwise. Every bundled face carries this \
             glyph — see assets/fonts/README.md before re-subsetting one"
        );

        let grouped = group_digits("1000.123456789");
        assert_eq!(grouped.matches(INT_GROUP).count(), 1);
        assert_eq!(grouped.matches(FRAC_GROUP).count(), 2);
    }

    #[test]
    fn small_values_get_no_stray_separators() {
        assert_eq!(group_digits("0.000000007"), "0.000\u{2004}000\u{2004}007");
        assert_eq!(group_digits("94.774302911"), "94.774\u{2004}302\u{2004}911");
    }

    #[test]
    fn grouping_is_single_sourced() {
        use super::group_editable;
        for s in [
            "0.000000000",
            "12345.678900000",
            "1000000000.000000000",
            "999999999999.999999999",
        ] {
            assert_eq!(group_digits(s), group_editable(s));
        }
    }

    #[test]
    fn editable_groups_integer_even_without_a_point() {
        use super::group_editable;
        assert_eq!(group_editable("1000000"), "1\u{2019}000\u{2019}000");
        assert_eq!(group_editable("1000000.5"), "1\u{2019}000\u{2019}000.5");
        assert_eq!(group_editable("1.000000000"), "1.000\u{2004}000\u{2004}000");
        assert_eq!(group_editable("1000."), "1\u{2019}000.");
        assert_eq!(group_editable(".5"), ".5");
        assert_eq!(group_editable(""), "");
        assert_eq!(group_editable("abc"), "abc");
        assert_eq!(group_editable("1.2.3"), "1.2.3");
    }

    #[test]
    fn regroup_amount_keeps_caret_next_to_the_typed_digit() {
        use super::regroup_amount;
        let f = regroup_amount("1\u{2019}2345", 6);
        assert_eq!(f.text, "12\u{2019}345");
        assert_eq!(f.cursor, 6);

        let f = regroup_amount("912\u{2019}345", 1);
        assert_eq!(f.text, "912\u{2019}345");
        assert_eq!(f.cursor, 1);

        let f = regroup_amount("1234", 4);
        assert_eq!(f.text, "1\u{2019}234");
        assert_eq!(f.cursor, 7);

        let f = regroup_amount("1000.123456", 11);
        assert_eq!(f.text, "1\u{2019}000.123\u{2004}456");
        assert_eq!(
            f.cursor, 17,
            "the caret is a byte offset and both separators are three bytes wide"
        );
    }

    #[test]
    fn regroup_amount_leaves_the_caret_mid_string() {
        use super::regroup_amount;
        let f = regroup_amount("1234", 1);
        assert_eq!(f.text, "1\u{2019}234");
        assert_eq!(f.cursor, 1);
        let f = regroup_amount("1234", 2);
        assert_eq!(f.text, "1\u{2019}234");
        assert_eq!(
            f.cursor, 5,
            "one digit, then a three-byte separator, then the caret: byte offsets, not \
             character counts"
        );
    }

    #[test]
    fn an_amount_field_takes_only_what_an_amount_is_made_of() {
        use super::{AMOUNT_MAX_FRAC_DIGITS, AMOUNT_MAX_INT_DIGITS, regroup_amount};
        let typed = |text: &str| regroup_amount(text, text.len() as i32).text;

        assert_eq!(typed("12ab"), "12", "letters never enter the field");
        assert_eq!(typed("0.000000dsdssdsdsds00"), "0.000\u{2004}000\u{2004}00");
        assert_eq!(typed("-1"), "1", "a sign is not part of an amount");
        assert_eq!(typed("1,5"), "15");
        assert_eq!(typed("1.2.3"), "1.23", "the second point is dropped");
        assert_eq!(typed("1€"), "1");
        assert_eq!(typed("abc"), "");
        assert_eq!(typed(""), "");

        assert_eq!(typed("0.1234567891"), "0.123\u{2004}456\u{2004}789");
        let long = format!("1.{}", "1".repeat(20));
        assert_eq!(
            typed(&long)
                .split_once('.')
                .unwrap()
                .1
                .chars()
                .filter(char::is_ascii_digit)
                .count(),
            AMOUNT_MAX_FRAC_DIGITS
        );

        let huge = "9".repeat(AMOUNT_MAX_INT_DIGITS + 20);
        assert_eq!(
            typed(&huge).chars().filter(char::is_ascii_digit).count(),
            AMOUNT_MAX_INT_DIGITS
        );
    }

    #[test]
    fn regroup_amount_never_panics_on_hostile_input() {
        use super::regroup_amount;
        let f = regroup_amount("1€", 2);
        assert!(f.cursor >= 0);
        let f = regroup_amount("123", 99);
        assert_eq!(f.text, "123");
        assert_eq!(f.cursor, 3);
        let f = regroup_amount("12ab", 4);
        assert_eq!(f.text, "12");
        assert!(f.cursor >= 0 && f.cursor as usize <= f.text.len());
    }

    #[test]
    fn display_send_amount_normalizes_to_the_canonical_grouped_form() {
        use super::display_send_amount;
        assert_eq!(
            display_send_amount(AssetId::Native, "49.5"),
            "49.500\u{2004}000\u{2004}000"
        );
        assert_eq!(
            display_send_amount(AssetId::Native, "1000000049.5"),
            "1\u{2019}000\u{2019}000\u{2019}049.500\u{2004}000\u{2004}000"
        );
        assert_eq!(
            display_send_amount(AssetId::Native, "0.000000001"),
            "0.000\u{2004}000\u{2004}001"
        );
        assert_eq!(
            display_send_amount(AssetId::Native, "1"),
            "1.000\u{2004}000\u{2004}000"
        );
        assert_eq!(display_send_amount(AssetId::Native, ""), "");
    }
}

#[cfg(test)]
mod activity_group_tests {
    use super::{ActivityEvent, activity_rows, day_bucket, group_label};

    fn event_at(time_unix: u64) -> ActivityEvent {
        ActivityEvent {
            counterparty: "0:other".to_owned(),
            fee_native: 4_400,
            int_msg_hash: Some(cc_wallet_app::Digest32::from_bytes([0xbb; 32])),
            ..ActivityEvent::test_stub(time_unix, time_unix)
        }
    }

    #[test]
    fn day_bucket_matches_the_local_calendar_day() {
        use chrono::Datelike;
        for unix in [0u64, 86_399, 86_400, 1_700_000_000, 1_700_086_400] {
            let expected = chrono::DateTime::from_timestamp(unix as i64, 0)
                .unwrap()
                .with_timezone(&chrono::Local)
                .date_naive()
                .num_days_from_ce() as i64;
            assert_eq!(day_bucket(unix), expected);
        }
    }

    #[test]
    fn a_conversation_names_each_day_once_and_only_at_its_first_line() {
        let day = 86_400u64;
        let now = 10 * day + 4_000;
        let line = |time_unix: u64| cc_wallet_app::ChatLine {
            outgoing: false,
            time_unix,
            lt: time_unix,
            text: "said".to_owned(),
            sealed: false,
            locked: false,
            pending: false,
        };
        let rows = super::chat_line_rows(
            &[
                line(8 * day + 100),
                line(8 * day + 200),
                line(9 * day + 100),
                line(10 * day + 100),
            ],
            now,
        );

        assert_eq!(rows[0].day, "JAN 9, 1970");
        assert_eq!(
            rows[1].day, "",
            "a second message the same day says nothing"
        );
        assert_eq!(rows[2].day, "YESTERDAY");
        assert_eq!(rows[3].day, "TODAY");
    }

    #[test]
    fn group_label_today_and_yesterday() {
        let today = 19_000;
        assert_eq!(group_label(today, today), "TODAY");
        assert_eq!(group_label(today - 1, today), "YESTERDAY");
    }

    #[test]
    fn group_label_older_date_is_formatted_and_uppercased() {
        use chrono::Datelike;
        let date = chrono::NaiveDate::from_ymd_opt(1970, 1, 1).unwrap();
        let bucket = date.num_days_from_ce() as i64;
        assert_eq!(group_label(bucket, bucket + 5_000), "JAN 1, 1970");
    }

    #[test]
    fn activity_rows_only_label_the_first_row_of_each_day() {
        let same_day_a = event_at(1_000);
        let same_day_b = event_at(2_000);
        let next_day = event_at(86_400 + 500);
        let rows = activity_rows(
            &[&same_day_a, &same_day_b, &next_day],
            "0:me",
            &[],
            1_753_000_000,
        );
        assert_ne!(rows[0].group, "");
        assert_eq!(rows[1].group, "");
        assert_ne!(rows[2].group, "");
        assert_ne!(rows[2].group, rows[0].group);
    }
}

#[cfg(test)]
mod helper_tests {

    #[test]
    fn both_transaction_lists_take_their_row_height_from_one_place() {
        let theme = include_str!("../../ui/theme.slint");
        assert!(theme.contains("tx_row_line_h: 20px;"));
        assert!(
            theme.contains("tx_row_pad_v: 5px;"),
            "the density knob lives here, and nowhere else"
        );
        for name in ["pages/wallet_components.slint", "pages/explorer_page.slint"] {
            let src = ui_sources()
                .into_iter()
                .find(|(n, _)| *n == name)
                .unwrap_or_else(|| panic!("{name} is not in ui_sources()"))
                .1;
            assert!(
                src.contains("Theme.tx_row_line_h") && src.contains("Theme.tx_row_pad_v"),
                "{name} must read the shared row height, not spell its own"
            );
        }
        for (name, src) in &ui_sources() {
            let code: String = src
                .lines()
                .map(|line| line.split("//").next().unwrap_or(""))
                .collect::<Vec<_>>()
                .join("\n");
            assert!(
                !code.contains("38px + ("),
                "{name} spells a transaction row height by hand again"
            );
        }
    }

    #[test]
    fn one_transaction_is_one_row_carrying_both_halves() {
        use cc_wallet_app::{AccountTx, AccountTxKind, AssetAmount, AssetMovement};
        use slint::Model;

        let two = AssetMovement {
            amount: AssetAmount::currency_collection(
                2,
                cc_wallet_app::CcAmount::from_u128(3_000_000_000),
            ),
        };
        let one = AssetMovement {
            amount: AssetAmount::currency_collection(
                1,
                cc_wallet_app::CcAmount::from_u128(11_926_289_658),
            ),
        };
        let tx = AccountTx {
            hash: cc_wallet_app::Digest32::try_from_hex(&"ab".repeat(32)).expect("hash"),
            lt: 1,
            time_unix: 1_700_000_000,
            kind: AccountTxKind::Fwd,
            counterparty: "0:them".to_owned(),
            extra_parties: 0,
            movements: vec![one],
            received: vec![two],
            fee_native: 16_696_950,
            int_out_msgs: 1,
            ext_out_msgs: 0,
            success: true,
            bounced: false,
            exit_code: 0,
        };

        let rows = explorer_tx_rows(&[tx], "0:me", &[], 1_700_000_000);
        assert_eq!(rows.len(), 1, "one transaction, one row");
        assert_eq!(
            rows[0].received.row_count(),
            1,
            "what arrived is on the row"
        );
        assert_eq!(rows[0].movements.row_count(), 1, "and so is what left");
        assert!(
            !rows[0].fee.is_empty(),
            "one transaction, one fee, on its row"
        );
        assert!(!rows[0].hash_short.is_empty(), "one transaction, one hash");
    }
    use super::*;
    use cc_wallet_app::{AssetAmount, CcAmount};
    use slint::{Color, Model};

    const HASH64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const CC_MAX: &str =
        "452312848583266388373324160190187140051835877600158453279131187530910662655";

    #[test]
    fn activity_summary_amount_keeps_fixed_right_aligned_columns() {
        const COLUMN_WIDTH: &str = "root.col_w - (Theme.activity_amount_token_gap_w + Theme.activity_amount_token_avatar_w + Theme.activity_amount_token_symbol_w)";
        let rows = include_str!("../../ui/pages/wallet_components.slint");
        let header = include_str!("../../ui/pages/wallet_sections.slint");
        let theme = include_str!("../../ui/theme.slint");

        let summary = rows
            .split_once("component ActivityMovementAmount inherits Rectangle")
            .expect("activity summary amount component exists")
            .1
            .split_once("export component ActivityListRow")
            .expect("activity summary amount component ends before the row")
            .0;

        assert!(summary.contains("in property <length> col_w: Theme.activity_amount_w;"));
        assert!(summary.contains("width: root.col_w;"));
        assert!(summary.contains(&format!("width: {COLUMN_WIDTH};")));
        assert!(header.contains("width: Theme.activity_amount_value_w,"));
        assert!(
            theme.contains("activity_amount_value_w: 22 * root.mono_char + 2 * root.mono_group;"),
            "the amount column is derived from its longest figure, not fitted: \
             +100'000'000.999 999 999 is 22 monospaced characters and two group spaces"
        );
        assert!(theme.contains("activity_amount_w: root.activity_amount_value_w"));
        assert!(theme.contains("activity_amount_token_avatar_w: 18px;"));
        assert!(theme.contains("activity_amount_token_symbol_w: 44px;"));
        assert!(
            !theme.contains("activity_money_gap") && !theme.contains("activity_fee_gap"),
            "one gutter separates every column; a per-pair gap is a fitted number"
        );
        assert!(rows.contains("spacing: Theme.activity_col_gap;"));
        assert!(summary.contains("ActivityAmountValue {"));

        let value_column = summary
            .split_once("amount_value_column := Rectangle")
            .expect("activity value subcolumn exists")
            .1
            .split_once("token_symbol_column := Rectangle")
            .expect("token subcolumn follows the value subcolumn")
            .0;
        assert!(value_column.contains("width: parent.width;"));

        let token_column = summary
            .split_once("token_symbol_column := Rectangle")
            .expect("activity token subcolumn exists")
            .1;
        assert!(token_column.contains("alignment: start;"));
    }

    #[test]
    fn an_activity_amount_is_content_sized_and_right_anchored() {
        let rows = include_str!("../../ui/pages/wallet_components.slint");
        let amount_value = rows
            .split_once("component ActivityAmountValue inherits Rectangle")
            .expect("shared amount value component exists")
            .1
            .split_once("component ActivityMovementAmount inherits Rectangle")
            .expect("shared amount value component ends before summary amount")
            .0;

        assert!(amount_value.contains("preferred-width: amount_value_line.preferred-width;"));
        assert!(amount_value.contains("alignment: end;"));
        let shared = include_str!("../../ui/widgets.slint")
            .split_once("export component Amount inherits HorizontalLayout")
            .expect("the shared amount component exists")
            .1
            .split_once("\nexport component ")
            .expect("it ends before the next exported component")
            .0;
        assert!(shared.contains("font-weight: root.int_weight;"));
        assert!(shared.contains("in property <int> int_weight: Fonts.bold;"));
        assert!(shared.contains("opacity: Fade.muted;"));
    }

    #[test]
    fn unknown_cc_row_uses_fixed9_without_becoming_sendable() {
        let amount = CcAmount::try_from_canonical_decimal(CC_MAX).unwrap();
        let state = AppState {
            wallet: Some(
                cc_wallet_app::WalletSnapshot::new(
                    "0:me",
                    0,
                    "active",
                    0,
                    std::collections::BTreeMap::from([(77, amount)]),
                    0,
                )
                .unwrap(),
            ),
            ..AppState::default()
        };

        let row = asset_row(&state, AssetId::CurrencyCollection(77), AssetId::Native);
        assert_eq!(row.control_id, -2);
        assert_eq!(row.currency_id.as_str(), "77");
        assert_eq!(row.name.as_str(), "Currency Collection #77");
        assert_eq!(row.symbol.as_str(), "#77");
        assert_eq!(
            row.amount.as_str(),
            "452\u{2019}312\u{2019}848\u{2019}583\u{2019}266\u{2019}388\u{2019}373\u{2019}324\u{2019}160\u{2019}190\u{2019}187\u{2019}140\u{2019}051\u{2019}835\u{2019}877\u{2019}600\u{2019}158\u{2019}453\u{2019}279\u{2019}131\u{2019}187\u{2019}530.910\u{2004}662\u{2004}655"
        );
        assert_eq!(row.status.as_str(), "Read-only");
        assert!(!row.selected, "an unknown CC cannot become the send asset");
        assert!(
            !row.visible,
            "unknown CCs are never user-enabled send assets"
        );
        assert!(!row.sendable);
    }

    #[test]
    fn maximum_unknown_currency_id_never_narrows_to_native() {
        let state = AppState {
            wallet: Some(
                cc_wallet_app::WalletSnapshot::new(
                    "0:me",
                    0,
                    "active",
                    0,
                    std::collections::BTreeMap::from([(u32::MAX, CcAmount::from_u128(1))]),
                    0,
                )
                .unwrap(),
            ),
            ..AppState::default()
        };

        let row = asset_row(
            &state,
            AssetId::CurrencyCollection(u32::MAX),
            AssetId::CurrencyCollection(u32::MAX),
        );
        assert_eq!(row.control_id, -2);
        assert_eq!(row.currency_id.as_str(), u32::MAX.to_string());
        assert_eq!(row.name.as_str(), "Currency Collection #4294967295");
        assert!(!row.selected);
        assert!(!row.visible);
        assert!(!row.sendable);
    }

    #[test]
    fn activity_row_formats_unknown_cc_as_fixed9_without_losing_precision() {
        let event = ActivityEvent {
            direction: ActivityDirection::In,
            tx_hash: Some(cc_wallet_app::Digest32::from_bytes([0x11; 32])),
            counterparty: "0:other".to_owned(),
            movements: vec![cc_wallet_app::AssetMovement {
                amount: AssetAmount::currency_collection(
                    4,
                    CcAmount::try_from_canonical_decimal("1000000000000000000").unwrap(),
                ),
            }],
            finality_ms: Some(1),
            ..ActivityEvent::test_stub(1, 1)
        };

        let row = activity_row(&event, "0:me", &[]);
        let movement = row.movements.row_data(0).expect("one movement row");
        assert_eq!(
            movement.amount_int.as_str(),
            "1\u{2019}000\u{2019}000\u{2019}000"
        );
        assert_eq!(movement.amount_frac.as_str(), ".000\u{2004}000\u{2004}000");
        assert!(row.movements.row_data(1).is_none());
    }

    #[test]
    fn an_activity_fee_is_an_amount_of_nine_decimals_split_like_every_other_figure() {
        let event = ActivityEvent {
            fee_native: 2_804_671,
            ..ActivityEvent::test_stub(1, 1)
        };

        let row = activity_row(&event, "0:me", &[]);
        assert_eq!(row.fee.amount_int.as_str(), "0");
        assert_eq!(row.fee.amount_frac.as_str(), ".002\u{2004}804\u{2004}671");

        let whole = ActivityEvent {
            fee_native: 1_234_567_890_123,
            ..ActivityEvent::test_stub(1, 1)
        };
        let row = activity_row(&whole, "0:me", &[]);
        assert_eq!(row.fee.amount_int.as_str(), "1\u{2019}234");
        assert_eq!(
            row.fee.amount_frac.as_str(),
            ".567\u{2004}890\u{2004}123",
            "a fee carries the same nine decimals as the amount beside it, grouped the \
             same way; shown to six it reads as a different kind of number"
        );
    }

    #[test]
    fn a_pool_reserve_reads_like_a_holding_but_cannot_be_picked() {
        let row = pool_reserve_row(AssetId::CurrencyCollection(2), 107_251_702_625);
        assert_eq!(row.name.as_str(), "Two Token");
        assert_eq!(row.symbol.as_str(), "TWO");
        assert_eq!(row.initial.as_str(), "2");
        assert_eq!(row.amount_int.as_str(), "107");
        assert_eq!(row.amount_frac.as_str(), ".251\u{2004}702\u{2004}625");
        assert!(
            !row.sendable && !row.selected,
            "a reserve is a fact about the pool, not a choice"
        );

        let native = pool_reserve_row(AssetId::Native, 216 * 1_000_000_000);
        assert_eq!(native.control_id, -1);
        assert_eq!(native.symbol.as_str(), "COIN");
        assert_eq!(native.amount_int.as_str(), "216");
        assert_eq!(native.amount_frac.as_str(), ".000\u{2004}000\u{2004}000");
    }

    #[test]
    fn base_units_render_as_the_wallets_own_fixed_nine_decimal() {
        assert_eq!(units_exact(AssetId::Native, 0), "0.000000000");
        assert_eq!(units_exact(AssetId::Native, 1), "0.000000001");
        assert_eq!(
            units_exact(AssetId::CurrencyCollection(1), 9_066_108_938),
            "9.066108938"
        );
        let token = token_units(AssetId::CurrencyCollection(1), 9_066_108_938);
        assert_eq!(token.amount_int.as_str(), "9");
        assert_eq!(token.amount_frac.as_str(), ".066\u{2004}108\u{2004}938");
        assert_eq!(token.symbol.as_str(), "ONE");
    }

    #[test]
    fn short_addr_truncates_only_long_hashes() {
        assert_eq!(short_addr(&format!("0:{HASH64}")), "0:012345…abcdef");
        assert_eq!(short_addr("0:abcdef"), "0:abcdef");
        assert_eq!(short_addr("no-colon"), "no-colon");
    }

    #[test]
    fn short_addr_uses_middle_truncate_threshold() {
        assert_eq!(short_addr("0:0123456789abc"), "0:0123456789abc");
        assert_eq!(short_addr("0:0123456789abcd"), "0:012345…89abcd");
    }

    #[test]
    fn middle_truncate_keeps_head_and_tail() {
        let addr = format!("0:{HASH64}");
        let out = middle_truncate(&addr, 14, 8);
        assert_eq!(out, "0:0123456789ab…89abcdef");
        assert_eq!(middle_truncate("0:abcd", 14, 8), "0:abcd");
    }

    #[test]
    fn truncation_never_panics_on_non_ascii_input() {
        let cyrillic = format!("0:{}", "д".repeat(40));
        let _ = short_addr(&cyrillic);
        let _ = middle_truncate(&cyrillic, 14, 8);
        let mixed = "0:aд🦀bcdef0123456789abcdef0123456789";
        assert_eq!(short_addr(mixed).chars().next(), Some('0'));
        let _ = middle_truncate(mixed, 6, 6);
    }

    #[test]
    fn fmt_time_renders_local_wall_clock() {
        for unix in [0u64, 3661, 86_399, 86_400 + 3661] {
            let expected = chrono::DateTime::from_timestamp(unix as i64, 0)
                .unwrap()
                .with_timezone(&chrono::Local)
                .format("%H:%M:%S")
                .to_string();
            assert_eq!(fmt_time(unix), expected);
        }
        assert_eq!(fmt_time(3661), fmt_time(86_400 + 3661));
    }

    #[test]
    fn format_finality_uses_ms_then_seconds() {
        assert_eq!(format_finality(None), "");
        assert_eq!(format_finality(Some(850)), "850ms");
        assert_eq!(format_finality(Some(999)), "999ms");
        assert_eq!(format_finality(Some(1000)), "1.0s");
        assert_eq!(format_finality(Some(1200)), "1.2s");
    }

    #[test]
    fn counterparty_name_resolves_self_then_contacts() {
        let contacts = [AddressBookEntry::new("Alice", "0:alice")];
        assert_eq!(counterparty_name("", "0:me", &contacts), "");
        assert_eq!(counterparty_name("0:me", "0:me", &contacts), "My Wallet");
        assert_eq!(counterparty_name("0:alice", "0:me", &contacts), "Alice");
        assert_eq!(counterparty_name("0:stranger", "0:me", &contacts), "");
    }

    #[test]
    fn party_pill_label_prefers_a_contact_name_else_short_address() {
        let contacts = [AddressBookEntry::new("Alice", "0:alice")];
        assert_eq!(party_pill_label("", &contacts), "");
        assert_eq!(party_pill_label("0:alice", &contacts), "Alice");
        let long = format!("0:{HASH64}");
        assert_eq!(party_pill_label(&long, &contacts), short_addr(&long));
    }

    #[test]
    fn initials_are_unicode_aware_two_letter_marks() {
        assert_eq!(initials("Evgeny Nazarenko"), "EN");
        assert_eq!(initials("Jouliene"), "JO");
        assert_eq!(initials("Грамобрила"), "ГР");
        assert_eq!(initials(""), "C");
        assert_eq!(initials("   "), "C");
    }

    #[test]
    fn contact_color_index_is_deterministic_and_in_range() {
        let a = contact_color_index("0:alice");
        assert_eq!(a, contact_color_index("0:alice"));
        assert!(a < CONTACT_TONES.len());
        assert!(contact_color_index("0:bob") < CONTACT_TONES.len());
    }

    #[test]
    fn the_max_chip_exists_once_and_both_pages_use_it() {
        let sections = include_str!("../../ui/pages/wallet_sections.slint");
        let swap = include_str!("../../ui/pages/swap_page.slint");
        let widgets = include_str!("../../ui/widgets.slint");
        assert!(widgets.contains("export component MaxChip inherits Rectangle {"));
        assert!(
            sections.contains("MaxChip {"),
            "the Wallet page takes the shared chip"
        );
        assert!(
            swap.contains("MaxChip {"),
            "the Swap page takes the shared chip"
        );
        assert_eq!(
            sections.matches("text: \"MAX\"").count(),
            0,
            "the inline copy is gone"
        );
        assert_eq!(
            swap.matches("text: \"MAX\"").count(),
            0,
            "the Swap page's local component moved to widgets.slint"
        );
        assert_eq!(
            widgets.matches("text: \"MAX\"").count(),
            1,
            "and there is exactly one MAX label in the tree"
        );
    }

    fn ui_sources() -> Vec<(&'static str, &'static str)> {
        vec![
            ("app.slint", include_str!("../../ui/app.slint")),
            ("theme.slint", include_str!("../../ui/theme.slint")),
            ("widgets.slint", include_str!("../../ui/widgets.slint")),
            ("models.slint", include_str!("../../ui/models.slint")),
            (
                "components/auth_modal.slint",
                include_str!("../../ui/components/auth_modal.slint"),
            ),
            (
                "components/brand_mark.slint",
                include_str!("../../ui/components/brand_mark.slint"),
            ),
            (
                "components/lock_screen.slint",
                include_str!("../../ui/components/lock_screen.slint"),
            ),
            (
                "components/risk_modal.slint",
                include_str!("../../ui/components/risk_modal.slint"),
            ),
            (
                "components/top_nav.slint",
                include_str!("../../ui/components/top_nav.slint"),
            ),
            (
                "components/trace_diagram.slint",
                include_str!("../../ui/components/trace_diagram.slint"),
            ),
            (
                "components/validator_clock.slint",
                include_str!("../../ui/components/validator_clock.slint"),
            ),
            (
                "components/wallet_picker.slint",
                include_str!("../../ui/components/wallet_picker.slint"),
            ),
            (
                "pages/contacts_components.slint",
                include_str!("../../ui/pages/contacts_components.slint"),
            ),
            (
                "pages/contacts_page.slint",
                include_str!("../../ui/pages/contacts_page.slint"),
            ),
            (
                "pages/explorer_page.slint",
                include_str!("../../ui/pages/explorer_page.slint"),
            ),
            (
                "pages/settings_components.slint",
                include_str!("../../ui/pages/settings_components.slint"),
            ),
            (
                "pages/settings_page.slint",
                include_str!("../../ui/pages/settings_page.slint"),
            ),
            (
                "pages/swap_page.slint",
                include_str!("../../ui/pages/swap_page.slint"),
            ),
            (
                "pages/wallet_components.slint",
                include_str!("../../ui/pages/wallet_components.slint"),
            ),
            (
                "pages/wallet_menus.slint",
                include_str!("../../ui/pages/wallet_menus.slint"),
            ),
            (
                "pages/wallet_page.slint",
                include_str!("../../ui/pages/wallet_page.slint"),
            ),
            (
                "pages/wallet_sections.slint",
                include_str!("../../ui/pages/wallet_sections.slint"),
            ),
        ]
    }

    #[test]
    fn every_animation_takes_its_timing_from_the_token_layer() {
        let mut animate_blocks = 0usize;
        let mut with_easing = 0usize;
        let mut literal_durations: Vec<u32> = Vec::new();

        for (_name, src) in ui_sources() {
            for line in src.lines() {
                let code = line.split("//").next().unwrap_or("");
                animate_blocks += code.matches("animate ").count();
                if code.contains("easing:") {
                    with_easing += 1;
                }
                if let Some(rest) = code.split("duration:").nth(1) {
                    let value = rest.trim_start();
                    if value.starts_with(|c: char| c.is_ascii_digit()) {
                        let digits: String =
                            value.chars().take_while(|c| c.is_ascii_digit()).collect();
                        literal_durations.push(digits.parse().expect("digits"));
                    }
                }
            }
        }
        literal_durations.sort_unstable();

        assert_eq!(
            animate_blocks, with_easing,
            "{} of {animate_blocks} animate blocks declare an easing — an animation \
             without one takes Slint's default curve, which is the divergence MOTION-01 \
             was about",
            with_easing
        );
        assert_eq!(
            literal_durations,
            Vec::<u32>::new(),
            "a duration written as a number is a duration outside the token layer, \
             and the pixel baseline cannot see it change"
        );
        let mut literal_dwells = Vec::new();
        for (name, src) in ui_sources() {
            for line in src.lines() {
                let code = line.split("//").next().unwrap_or("");
                if let Some(rest) = code.split("interval:").nth(1) {
                    let value = rest.trim_start();
                    if value.starts_with(|c: char| c.is_ascii_digit()) {
                        literal_dwells.push(format!("{name}: {}", value.trim()));
                    }
                }
            }
        }
        assert!(
            literal_dwells.is_empty(),
            "an acknowledgement dwell outside the token layer: {literal_dwells:?}"
        );
    }

    #[test]
    fn every_amount_is_drawn_by_the_shared_component_or_a_named_outlier() {
        let allowed: &[(&str, usize, &str)] =
            &[("widgets.slint", 1, "the shared Amount component itself")];
        let sources = ui_sources();
        for &(name, limit, why) in allowed {
            let src = sources
                .iter()
                .find(|(n, _)| *n == name)
                .unwrap_or_else(|| panic!("{name} is not in ui_sources()"))
                .1;
            let runs = src
                .lines()
                .filter(|l| l.contains("text:") && l.contains("_frac"))
                .count();
            assert_eq!(
                runs, limit,
                "{name} draws {runs} fraction runs, expected {limit} ({why}); a new \
                 embedded amount is exactly what the shared component exists to prevent"
            );
        }
        for (name, src) in &sources {
            if allowed.iter().any(|(a, _, _)| a == name) {
                continue;
            }
            assert_eq!(
                src.lines()
                    .filter(|l| l.contains("text:") && l.contains("_frac"))
                    .count(),
                0,
                "{name} draws an amount of its own; use the shared Amount component"
            );
        }
    }

    #[test]
    fn every_group_of_tokens_sharing_a_value_is_declared() {
        let declared: &[(&str, &[&str], &str)] = &[
            (
                "#06070A",
                &["surface_base", "clock_seam", "cover"],
                "the page itself; the seam that is the page showing between the clock's \
                 arcs; and the fully opaque cover over the seed phrase. Three concerns \
                 that happen to arrive at the same colour — the cover is opaque because a \
                 90% wash leaks the block shape of twelve words, not because it wants to \
                 match the page",
            ),
            (
                "#34D399",
                &["positive", "value_in"],
                "a state that is good, versus money coming in",
            ),
            (
                "#3B82F6",
                &["focus_ring", "accent"],
                "the ring around a focused control, versus the accent itself",
            ),
            (
                "#3B82F621",
                &["accent_quiet", "info_quiet"],
                "an accent wash, versus an informational notice's fill",
            ),
            (
                "#8FB6FB",
                &["accent_text", "info"],
                "accent-coloured text, versus an informational notice's tone",
            ),
            (
                "#C7CEDB",
                &["text_secondary", "value_out", "value_neutral"],
                "prose, money going out, and money that is neither — ROLE-02's split, \
                 the one where all five value_neutral sites landed on text_secondary",
            ),
        ];
        let src = include_str!("../../ui/design_tokens.slint");
        let mut found: std::collections::BTreeMap<String, Vec<String>> = Default::default();
        for line in src.lines() {
            let Some(rest) = line.trim().strip_prefix("out property <color> ") else {
                continue;
            };
            let Some((name, value)) = rest.split_once(": ") else {
                continue;
            };
            let value = value.trim_end_matches(';').trim();
            if !value.starts_with('#') {
                continue;
            }
            found
                .entry(value.to_uppercase())
                .or_default()
                .push(name.to_owned());
        }
        let groups: Vec<_> = found.into_iter().filter(|(_, n)| n.len() > 1).collect();
        assert_eq!(
            groups.len(),
            declared.len(),
            "the token layer has {} groups sharing a value and {} are declared: {:?}",
            groups.len(),
            declared.len(),
            groups
        );
        for (value, names) in &groups {
            let (_, expect, why) = declared
                .iter()
                .find(|(v, _, _)| v.eq_ignore_ascii_case(value))
                .unwrap_or_else(|| {
                    panic!(
                        "{value} is shared by {names:?} and is not declared — say which \
                            role is which, or give one of them its own value"
                    )
                });
            let mut expect = expect.to_vec();
            let mut got: Vec<&str> = names.iter().map(String::as_str).collect();
            expect.sort_unstable();
            got.sort_unstable();
            assert_eq!(expect, got, "{value} ({why})");
        }
    }

    #[test]
    fn a_token_serves_one_semantic_family() {
        let families: &[(&str, &str, &[&str])] = &[
            (
                "Elevation.scrim",
                "modal",
                &[
                    "components/wallet_picker.slint",
                    "components/auth_modal.slint",
                    "components/risk_modal.slint",
                ],
            ),
            ("Elevation.cover", "secret", &["pages/settings_page.slint"]),
        ];
        let defaults: &[(&str, &str, &str)] = &[(
            "Palette.warning_border",
            "warning",
            "NoticeBlock's frame default is border_subtle now; putting a semantic tone back \
             there gives it every instance that does not opt in",
        )];
        for &(token, family, why) in defaults {
            for (name, src) in &ui_sources() {
                for line in src.lines() {
                    let code = line.split("//").next().unwrap_or("");
                    if code.contains("in property") && code.contains(token) {
                        panic!(
                            "{name}: `{token}` is the default of a shared input, so it \
                             reaches every instance that does not override it — a `{family}` \
                             tone cannot be inherited by consumers that never asked for it. \
                             {why}: {code}"
                        );
                    }
                }
            }
        }

        for &(token, family, allowed) in families {
            let mut seen = Vec::new();
            for (name, src) in &ui_sources() {
                for line in src.lines() {
                    if line.split("//").next().unwrap_or("").contains(token) {
                        seen.push(*name);
                    }
                }
            }
            seen.sort_unstable();
            seen.dedup();
            let mut expect = allowed.to_vec();
            expect.sort_unstable();
            assert_eq!(
                seen, expect,
                "{token} is meant for the `{family}` family only. A consumer outside it is \
                 a merge of two roles into one token, which no pixel diff can see because \
                 the values agree by construction."
            );
        }
    }

    #[test]
    fn a_balance_gives_up_its_fraction_before_a_digit_of_the_integer() {
        let widgets = include_str!("../../ui/widgets.slint");
        let rows = include_str!("../../ui/pages/wallet_components.slint");

        let amount = widgets
            .split_once("export component Amount inherits HorizontalLayout")
            .expect("the shared Amount component exists")
            .1
            .split_once("export component MaxChip")
            .expect("Amount ends before MaxChip")
            .0;
        let (integer, fraction) = amount
            .split_once("text: root.frac_groups < 0")
            .expect("the fraction run follows the integer run");
        assert!(
            !integer.contains("overflow:"),
            "the integer run must never elide — a balance that loses a digit before the \
             point is a different number"
        );
        assert!(
            fraction.contains("AmountFormat.fit_fraction("),
            "the fraction gives way by whole groups, decided by whoever owns the width; \
             letting the Text elide instead cuts a group in half and reads as another number"
        );
        assert!(fraction.contains("min-width: root.elide_fraction ? 0px : self.preferred-width;"));

        let asset_row = rows
            .split_once("export component AssetListRow")
            .expect("the asset row exists")
            .1
            .split_once("component ActivityAmountValue")
            .expect("the asset row ends before the activity amount")
            .0;
        assert!(asset_row.contains("elide_fraction: true;"));
        assert!(
            asset_row.contains("name_min_w: 96px;"),
            "the name column shrinks, but not past being a name; below this the row reads \
             as a balance with no owner"
        );
        assert!(
            asset_row.contains("frac_groups: root.frac_groups;"),
            "the row owns the width, so the row is what counts the groups"
        );
        assert!(asset_row.contains("font_size: Fonts.balance;"));
    }

    #[test]
    fn an_address_on_screen_can_always_be_opened_in_the_explorer() {
        let sources = ui_sources();
        let src_of = |name: &str| {
            sources
                .iter()
                .find(|(n, _)| *n == name)
                .unwrap_or_else(|| panic!("{name} is not in ui_sources()"))
                .1
        };

        for (name, needle) in [
            (
                "pages/wallet_sections.slint",
                "root.open_in_explorer(root.address, \"\")",
            ),
            ("pages/contacts_components.slint", "root.open_in_explorer()"),
        ] {
            assert!(
                src_of(name).contains(needle),
                "{name} draws an address without a way into the Explorer"
            );
        }

        let activity = src_of("pages/wallet_components.slint");
        assert!(
            !activity.contains("has_party && root.item.tx_hash != \"\""),
            "the jump is gated on a transaction hash again — a pending transfer has no \
             hash yet, but the account on the other side is already on chain, so the \
             button stays and only its destination changes"
        );
        assert!(activity.contains("if root.item.has_party: VerticalLayout"));
    }

    #[test]
    fn a_money_figure_reads_a_money_role_not_the_prose_tone() {
        let money: &[(&str, &str)] = &[
            (
                "pages/wallet_components.slint",
                "amount_color: Palette.value_neutral",
            ),
            ("pages/wallet_components.slint", "amount: root.item.fee;"),
            ("pages/explorer_page.slint", "tint: Palette.value_neutral"),
            ("pages/explorer_page.slint", "text: root.item.fee;"),
        ];
        let sources = ui_sources();
        let src_of = |name: &str| {
            sources
                .iter()
                .find(|(n, _)| *n == name)
                .unwrap_or_else(|| panic!("{name} is not in ui_sources()"))
                .1
        };
        for &(name, needle) in money {
            assert!(
                src_of(name).contains(needle),
                "{name} no longer contains `{needle}` — if a money figure moved, point it \
                 at a value_* role, not at text_secondary"
            );
        }
        for (name, src) in &sources {
            for line in src.lines() {
                if line.contains("amount_color") {
                    assert!(
                        !line.contains("Palette.text_secondary"),
                        "{name}: a money figure on the prose tone — the two share \
                         #C7CEDB, so this is invisible in a pixel diff: {line}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_state_tone_and_a_money_tone_do_not_trade_places() {
        for (name, src) in &ui_sources() {
            for line in src.lines() {
                if line.contains("Palette.value_in") {
                    assert!(
                        line.contains("amount_color")
                            || line.contains("property <color> tone")
                            || line.contains("fg:"),
                        "{name}: value_in outside a money figure — it shares #34D399 with \
                         positive, so a swap is invisible: {line}"
                    );
                }
                if line.contains("Palette.positive") {
                    assert!(
                        !line.contains("amount_color"),
                        "{name}: a money figure on the state tone: {line}"
                    );
                }
            }
        }
    }

    #[test]
    fn the_informational_tokens_appear_only_on_a_notice() {
        let mut sites = 0;
        for (name, src) in &ui_sources() {
            for stmt in src.split(';') {
                if !(stmt.contains("Palette.info")) {
                    continue;
                }
                let flat = stmt.split_whitespace().collect::<Vec<_>>().join(" ");
                assert!(
                    flat.contains("tint:") || flat.contains("fill:") || flat.contains("frame:"),
                    "{name}: an info token outside a notice's tint/fill/frame — it shares \
                     a value with an accent token, so a swap is invisible: {flat}"
                );
                sites += 1;
            }
        }
        assert_eq!(
            sites, 6,
            "expected two notices x three inputs; a new one must be a deliberate choice"
        );
    }

    #[test]
    fn a_field_label_is_the_shared_component_or_a_site_with_its_own_reason() {
        let mut embedded = Vec::new();
        for (name, src) in &ui_sources() {
            if *name == "widgets.slint" {
                continue;
            }
            let lines: Vec<&str> = src.lines().collect();
            for w in lines.windows(3) {
                if w[0].trim() == "color: Palette.text_quiet;"
                    && w[1].trim() == "font-family: Fonts.ui;"
                    && w[2].trim() == "font-size: Fonts.small;"
                {
                    embedded.push(*name);
                }
            }
        }
        assert_eq!(
            embedded.len(),
            6,
            "the field-label triple is spelled out at {} sites outside widgets.slint \
             ({embedded:?}); six keep it for a stated reason — two of them are prose \
             rather than labels: the line a sealed message shows in place of its words, \
             and the note that says a fee includes a deployment — and a seventh should \
             be FieldLabel",
            embedded.len()
        );
    }

    #[test]
    fn every_inline_error_is_the_shared_component_or_a_named_outlier() {
        let allowed: &[(&str, usize, &str)] = &[
            ("widgets.slint", 1, "InlineError itself"),
            ("app.slint", 1, "the shell's global error line"),
            (
                "pages/swap_page.slint",
                2,
                "the two pool messages, which are DetailRow values rather than \
                 messages with an icon",
            ),
            (
                "pages/contacts_components.slint",
                1,
                "the Delete button's text_color — not a message",
            ),
        ];
        let sources = ui_sources();
        let mut total = 0;
        for &(name, limit, why) in allowed {
            let src = sources
                .iter()
                .find(|(n, _)| *n == name)
                .unwrap_or_else(|| panic!("{name} is not in ui_sources()"))
                .1;
            let n = src.matches("color: Palette.negative;").count();
            assert_eq!(
                n, limit,
                "{name} holds {n} red-text sites, expected {limit} ({why})"
            );
            total += n;
        }
        for (name, src) in &sources {
            if allowed.iter().any(|(a, _, _)| a == name) {
                continue;
            }
            assert_eq!(
                src.matches("color: Palette.negative;").count(),
                0,
                "{name} draws an error of its own; use InlineError"
            );
        }
        assert_eq!(
            total, 5,
            "ERR-01 was 13 red-text sites before step 3.22; six became InlineError, so \
             seven remain, and only InlineError itself draws a message"
        );
    }

    #[test]
    fn a_hover_token_is_only_read_in_a_hover_state() {
        for (name, src) in &ui_sources() {
            for stmt in src.split(';') {
                if !stmt.contains("Palette.hover_") {
                    continue;
                }
                let flat = stmt.split_whitespace().collect::<Vec<_>>().join(" ");
                assert!(
                    flat.contains("has-hover")
                        || flat.contains("has_hover")
                        || flat.contains("lit"),
                    "{name}: a hover token with no hover state in its statement — that \
                     is the borrow step 1.5 already made twice: {flat}"
                );
            }
        }
    }

    #[test]
    fn a_focus_border_and_a_selected_border_use_different_tokens() {
        let sources = ui_sources();
        let mut ring_components = 0;
        for (name, src) in &sources {
            for block in src.split("component ") {
                if !block.contains("Palette.focus_ring") {
                    continue;
                }
                ring_components += 1;
                assert!(
                    block.contains("has-focus") || block.contains("has_focus"),
                    "{name}: a component draws focus_ring with no focus state in it — \
                     focus_ring and selected_border share a value, so a swap is \
                     invisible in a pixel diff"
                );
            }
            for line in src.lines() {
                if line.contains("Palette.selected_border") {
                    assert!(
                        !line.contains("has-focus") && !line.contains("has_focus"),
                        "{name}: a focus state reading selected_border — that is the \
                         collapse step 1.3 already made once: {line}"
                    );
                }
            }
        }
        let silent: &[(&str, bool, &str)] = &[
            (
                "pages/contacts_page.slint",
                true,
                "the search field's wrapper rings",
            ),
            (
                "pages/settings_components.slint",
                true,
                "the settings field's wrapper rings",
            ),
            (
                "pages/explorer_page.slint",
                true,
                "the address bar's wrapper rings",
            ),
            (
                "pages/swap_page.slint",
                false,
                "DELIBERATE EXCEPTION: the Swap amount field has no box of its own — \
                 field_bg and border_normal are both transparent — so a ring would be a \
                 stray rectangle round a bare 26px figure. It is the one keyboard-reachable \
                 control in the app with no visible focus, which reopens FOCUS-01/02 for \
                 that field alone; the panel is expected to carry the state instead.",
            ),
        ];
        for &(name, wrapper_rings, why) in silent {
            let src = ui_sources()
                .into_iter()
                .find(|(n, _)| *n == name)
                .unwrap_or_else(|| panic!("{name} is not in ui_sources()"))
                .1;
            assert!(
                src.contains("show_focus_border: false;"),
                "{name} no longer silences a field; drop its entry here ({why})"
            );
            assert_eq!(
                src.contains("Palette.focus_border"),
                wrapper_rings,
                "{name}: a silenced field must have a wrapper that rings, or be the stated \
                 exception ({why})"
            );
        }

        assert_eq!(
            ring_components, 8,
            "expected 8 components to draw the accent focus ring (PrimaryButton, \
             GhostButton, IconButton, Checkbox, MaxChip, SegBtn, SegChoice, Tab) — a \
             control you activate. A Field and its wrappers ring in focus_border, \
             which is a resting border made lighter, not the accent"
        );
    }

    #[test]
    fn the_token_layer_declares_no_identity_colour() {
        let tokens = include_str!("../../ui/design_tokens.slint");
        for line in tokens.lines() {
            let code = line.split("//").next().unwrap_or("");
            for name in [
                "identity_",
                "asset_coin",
                "asset_one",
                "asset_two",
                "asset_three",
                "asset_unknown",
                "asset_fallback",
            ] {
                assert!(
                    !code.contains(name),
                    "identity colour is owned by render.rs; `{name}` reappeared in the \
                     token layer, which puts eleven values in two places with nothing \
                     comparing them: {code}"
                );
            }
        }
    }

    #[test]
    fn every_identity_tone_is_pinned_so_the_palette_move_cannot_change_a_colour() {
        let asset_tones: [(AssetId, (u8, u8, u8)); 5] = [
            (AssetId::Native, (0x2B, 0x75, 0xD7)),
            (AssetId::CurrencyCollection(1), (0x1F, 0x85, 0x5A)),
            (AssetId::CurrencyCollection(2), (0xA0, 0x6A, 0x1D)),
            (AssetId::CurrencyCollection(3), (0x9B, 0x50, 0xB4)),
            (AssetId::CurrencyCollection(9_999), (0x6D, 0x77, 0x86)),
        ];
        for (asset, (r, g, b)) in asset_tones {
            assert_eq!(
                asset_tone(asset_meta(asset).tone),
                Color::from_rgb_u8(r, g, b),
                "asset tone for {asset:?} moved"
            );
        }

        let contact_tones: [(u8, u8, u8); 6] = [
            (0x34, 0x72, 0xD8),
            (0x21, 0x85, 0x60),
            (0xA4, 0x6A, 0x07),
            (0x7D, 0x68, 0xBC),
            (0xB5, 0x54, 0x87),
            (0x15, 0x81, 0x91),
        ];
        assert_eq!(
            CONTACT_TONES.len(),
            contact_tones.len(),
            "the contact palette changed size; every avatar in Contacts is affected"
        );
        for (i, (r, g, b)) in contact_tones.iter().copied().enumerate() {
            assert_eq!(
                contact_tone(i),
                Color::from_rgb_u8(r, g, b),
                "contact tone {i} moved; step 1.6 must preserve it byte for byte"
            );
        }

        let mut reached = [false; 6];
        for n in 0..600u32 {
            let idx = contact_color_index(&format!("0:{n:064x}"));
            assert!(
                idx < contact_tones.len(),
                "index {idx} is outside the palette"
            );
            reached[idx] = true;
        }
        assert!(
            reached.iter().all(|hit| *hit),
            "not every tone is reachable by some address, so the enumeration above \
             does not actually cover the palette: {reached:?}"
        );
    }
}

#[cfg(test)]
mod seed_exposure_tests {
    use super::*;

    const SEED: &str = "one two three four five six seven eight nine ten eleven twelve";

    #[test]
    fn a_revealed_seed_is_exposed_as_text_and_twelve_words() {
        let e = seed_exposure(true, false, SEED);
        assert_eq!(e.text.as_str(), SEED);
        assert_eq!(e.words.len(), 12);
        assert_eq!(e.words[0].as_str(), "one");
        assert_eq!(e.words[11].as_str(), "twelve");
    }

    #[test]
    fn an_unsaved_seed_is_exposed_even_without_an_explicit_reveal() {
        let e = seed_exposure(false, true, SEED);
        assert_eq!(e.text.as_str(), SEED);
        assert_eq!(e.words[0].as_str(), "one");
        assert_eq!(e.words[11].as_str(), "twelve");
    }

    #[test]
    fn a_hidden_seed_leaks_nothing() {
        let e = seed_exposure(false, false, SEED);
        assert_eq!(e.text.as_str(), "", "no seed text is exposed while hidden");
        assert_eq!(e.words.len(), 12, "the grid keeps its fixed shape");
        assert!(
            e.words.iter().all(|w| w.is_empty()),
            "not one word may leak into the grid while the seed is hidden"
        );
    }

    #[test]
    fn the_grid_is_always_exactly_twelve_slots() {
        let short = seed_exposure(true, false, "alpha beta gamma");
        assert_eq!(short.words.len(), 12);
        assert_eq!(short.words[0].as_str(), "alpha");
        assert!(
            short.words[3..].iter().all(|w| w.is_empty()),
            "the unused slots of a short seed are blank"
        );

        let sixteen = "a b c d e f g h i j k l m n o p";
        let long = seed_exposure(true, false, sixteen);
        assert_eq!(
            long.words.len(),
            12,
            "a longer seed still fills exactly 12 slots"
        );
        assert_eq!(
            long.words[11].as_str(),
            "l",
            "the grid stops at the twelfth word"
        );
    }

    #[test]
    fn an_exposed_but_empty_seed_stays_blank_without_panicking() {
        let e = seed_exposure(true, false, "");
        assert_eq!(e.text.as_str(), "");
        assert_eq!(e.words.len(), 12);
        assert!(e.words.iter().all(|w| w.is_empty()));

        let ws = seed_exposure(true, true, "   \t  ");
        assert_eq!(ws.words.len(), 12);
        assert!(ws.words.iter().all(|w| w.is_empty()));
    }

    #[test]
    fn extra_whitespace_between_words_is_collapsed() {
        let e = seed_exposure(true, false, "  one   two\tthree \n four ");
        assert_eq!(e.words[0].as_str(), "one");
        assert_eq!(e.words[1].as_str(), "two");
        assert_eq!(e.words[2].as_str(), "three");
        assert_eq!(e.words[3].as_str(), "four");
        assert!(e.words[4..].iter().all(|w| w.is_empty()));
    }
}

/// A fraction cut to whole groups. The caller says how many three-digit groups
/// it has room for; anything dropped is owed an ellipsis, so a reader can tell
/// a rounded figure from a complete one. Cutting mid-group would read as a
/// different number.
pub(super) fn fit_fraction(frac: &str, groups: i32) -> String {
    let Some(digits) = frac.strip_prefix('.') else {
        return frac.to_owned();
    };
    let all: Vec<&str> = digits.split(FRAC_GROUP).collect();
    let keep = groups.max(0) as usize;
    if keep >= all.len() {
        return frac.to_owned();
    }
    if keep == 0 {
        return "…".to_owned();
    }
    format!(".{}…", all[..keep].join(FRAC_GROUP))
}

#[cfg(test)]
mod fraction_fit_tests {
    use super::*;

    const FRAC: &str = ".704\u{2004}769\u{2004}361";

    #[test]
    fn a_fraction_that_fits_is_left_alone() {
        assert_eq!(fit_fraction(FRAC, 3), FRAC);
        assert_eq!(fit_fraction(FRAC, 9), FRAC);
    }

    #[test]
    fn a_fraction_is_cut_at_a_group_and_says_so() {
        assert_eq!(fit_fraction(FRAC, 2), ".704\u{2004}769…");
        assert_eq!(fit_fraction(FRAC, 1), ".704…");
    }

    #[test]
    fn no_room_for_a_group_leaves_the_integer_alone_and_nothing_else() {
        assert_eq!(fit_fraction(FRAC, 0), "…");
        assert_eq!(fit_fraction(FRAC, -1), "…");
    }

    #[test]
    fn something_that_is_not_a_fraction_is_not_touched() {
        assert_eq!(fit_fraction("", 1), "");
        assert_eq!(fit_fraction("704", 1), "704");
    }
}
