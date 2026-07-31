use std::collections::BTreeMap;

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use tycho_types::boc::Boc;
use tycho_types::models::{
    ComputePhase, ComputePhaseSkipReason, ExtraCurrencyCollection, MsgInfo, OwnedMessage,
    StateInit, Transaction, TxInfo,
};
use tycho_types::prelude::*;

pub const MAX_TRANSACTION_BOC_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgKind {
    ExtIn,
    Int,
    ExtOut,
}

#[derive(Debug, Clone)]
pub struct ChainMessage {
    pub kind: MsgKind,
    pub hash: String,
    pub src: Option<String>,
    pub dst: Option<String>,
    pub value_native: u128,
    pub value_extra: BTreeMap<u32, String>,
    pub fwd_fee: u128,
    pub bounce: bool,
    pub bounced: bool,
    pub created_lt: u64,
    pub created_at: u32,
    pub state_init: Option<StateInit>,
    pub state_init_hash: Option<String>,
    pub body: Cell,
    pub body_boc_base64: String,
}

#[derive(Debug, Clone)]
pub struct ChainTransaction {
    pub hash: String,
    pub lt: u64,
    pub now: u32,
    pub prev_trans_lt: u64,
    pub total_fees_native: u128,
    pub aborted: bool,
    pub compute_success: bool,
    pub compute_skipped: bool,
    pub compute_skip_reason: Option<ComputePhaseSkipReason>,
    pub exit_code: i32,
    pub action_success: Option<bool>,
    pub action_result_code: Option<i32>,
    pub action_no_funds: Option<bool>,
    pub bounce_phase_present: bool,
    pub in_msg: Option<ChainMessage>,
    pub out_msgs: Vec<ChainMessage>,
}

pub fn parse_transaction(boc_base64: &str) -> Result<ChainTransaction> {
    let max_encoded = MAX_TRANSACTION_BOC_BYTES.saturating_mul(4).div_ceil(3) + 4;
    if boc_base64.len() > max_encoded {
        anyhow::bail!(
            "transaction BOC exceeds the {MAX_TRANSACTION_BOC_BYTES}-byte decoded ceiling"
        );
    }
    let bytes = BASE64
        .decode(boc_base64)
        .context("transaction BOC is not canonical base64")?;
    if bytes.len() > MAX_TRANSACTION_BOC_BYTES {
        anyhow::bail!(
            "transaction BOC exceeds the {MAX_TRANSACTION_BOC_BYTES}-byte decoded ceiling"
        );
    }
    let cell = Boc::decode(&bytes).context("failed to decode transaction BOC")?;
    parse_transaction_cell(&cell)
}

pub(crate) fn parse_transaction_cell(cell: &Cell) -> Result<ChainTransaction> {
    let hash = cell.repr_hash().to_string();

    let mut slice = cell.as_slice().context("failed to read transaction cell")?;
    let tx = Transaction::load_from(&mut slice).context("failed to parse transaction")?;

    let total_fees_native = tx.total_fees.tokens.into_inner();

    let (
        aborted,
        compute_success,
        compute_skipped,
        compute_skip_reason,
        exit_code,
        action_success,
        action_result_code,
        action_no_funds,
        bounce_phase_present,
    ) = match tx.load_info()? {
        TxInfo::Ordinary(info) => {
            let (success, skipped, skip_reason, exit_code) = match &info.compute_phase {
                ComputePhase::Executed(phase) => (phase.success, false, None, phase.exit_code),
                ComputePhase::Skipped(phase) => (true, true, Some(phase.reason), 0),
            };
            let (action_success, action_result_code, action_no_funds) = info
                .action_phase
                .as_ref()
                .map_or((None, None, None), |phase| {
                    (
                        Some(phase.success),
                        Some(phase.result_code),
                        Some(phase.no_funds),
                    )
                });
            (
                info.aborted,
                success,
                skipped,
                skip_reason,
                exit_code,
                action_success,
                action_result_code,
                action_no_funds,
                info.bounce_phase.is_some(),
            )
        }
        TxInfo::TickTock(_) => (false, true, false, None, 0, None, None, None, false),
    };

    let in_msg = match &tx.in_msg {
        Some(cell) => Some(parse_message(cell)?),
        None => None,
    };

    let mut out_msgs = Vec::new();
    for entry in tx.out_msgs.values() {
        let cell = entry.context("failed to read out message")?;
        out_msgs.push(parse_message(&cell)?);
    }

    Ok(ChainTransaction {
        hash,
        lt: tx.lt,
        now: tx.now,
        prev_trans_lt: tx.prev_trans_lt,
        total_fees_native,
        aborted,
        compute_success,
        compute_skipped,
        compute_skip_reason,
        exit_code,
        action_success,
        action_result_code,
        action_no_funds,
        bounce_phase_present,
        in_msg,
        out_msgs,
    })
}

fn parse_message(cell: &Cell) -> Result<ChainMessage> {
    let hash = cell.repr_hash().to_string();
    let mut slice = cell.as_slice().context("failed to read message cell")?;
    let message = OwnedMessage::load_from(&mut slice).context("failed to parse message")?;
    let body_slice = CellSlice::apply(&message.body).context("failed to read message body")?;
    let body = CellBuilder::build_from(body_slice).context("failed to materialize message body")?;
    let body_boc_base64 = Boc::encode_base64(&body);
    let state_init = message.init.clone();
    let state_init_hash = state_init
        .as_ref()
        .map(|state_init| {
            CellBuilder::build_from(state_init)
                .map(|cell| cell.repr_hash().to_string())
                .context("failed to materialize message state init")
        })
        .transpose()?;

    Ok(match message.info {
        MsgInfo::Int(info) => ChainMessage {
            kind: MsgKind::Int,
            hash,
            src: Some(info.src.to_string()),
            dst: Some(info.dst.to_string()),
            value_native: info.value.tokens.into_inner(),
            value_extra: extra_currencies_to_strings(&info.value.other)?,
            fwd_fee: info.fwd_fee.into_inner(),
            bounce: info.bounce,
            bounced: info.bounced,
            created_lt: info.created_lt,
            created_at: info.created_at,
            state_init,
            state_init_hash,
            body,
            body_boc_base64,
        },
        MsgInfo::ExtIn(info) => ChainMessage {
            kind: MsgKind::ExtIn,
            hash,
            src: None,
            dst: Some(info.dst.to_string()),
            value_native: 0,
            value_extra: BTreeMap::new(),
            fwd_fee: 0,
            bounce: false,
            bounced: false,
            created_lt: 0,
            created_at: 0,
            state_init,
            state_init_hash,
            body,
            body_boc_base64,
        },
        MsgInfo::ExtOut(info) => ChainMessage {
            kind: MsgKind::ExtOut,
            hash,
            src: Some(info.src.to_string()),
            dst: None,
            value_native: 0,
            value_extra: BTreeMap::new(),
            fwd_fee: 0,
            bounce: false,
            bounced: false,
            created_lt: info.created_lt,
            created_at: info.created_at,
            state_init,
            state_init_hash,
            body,
            body_boc_base64,
        },
    })
}

pub(crate) fn extra_currencies_to_strings(
    other: &ExtraCurrencyCollection,
) -> Result<BTreeMap<u32, String>> {
    let mut result = BTreeMap::new();
    for entry in other.as_dict().iter() {
        let (currency_id, amount) =
            entry.context("failed to decode an extra-currency dictionary entry")?;
        result.insert(currency_id, amount.to_string());
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tycho_types::dict::Dict;
    use tycho_types::models::{IntAddr, IntMsgInfo, StateInit, StdAddr};
    use tycho_types::num::VarUint248;

    const SAMPLE_TX: &str = "te6ccgECDgEAAlQAA7VwzzhGQlR3sl+wKYzKg5koqj2AnfeL7BBKJsobaROsRBAAAACK7GwwGgcwWFKMa8g66ETBeeRt4c79JAfyFUe1eNHxlXNeOZRQAAAAiuLiyBakn0sQADRwEpVoBQQBAg8MQYYatTzEQAMCAG/JiGRwTBZhFAAAAAAAAgAAAAAAAukK7RGaZSwH/agd9NxiT57Z4ZZD4TbYukvxsWBojuFWQJAVDACdQsXjE4gAAAAAAAAAACFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIACCcmlvgB7nHr8Wj5J+/J0ToF8Kci6qDR5xzygO8/XJyzjVll1zOCkik1erJGrKLt6HZUDMceiBI/DK6YN15z3sWsgCAeAJBgEB3wcCqUgAGecIyEqO9kv2BTGZUHMlFUewE77xfYIJRNlDbSJ1iIMABI0VniXh4eJeYVGVGR1iUWEWHRXR1RUVFVFRVRVRUVFCBhZhNgAAABFdjYYE1JPpYsAIDQAToAAAAAMgU6cRNAFFiAAZ5wjISo72S/YFMZlQcyUVR7ATvvF9gglE2UNtInWIggwKAYBPrqUvmbcaZSAV9NpJvQtZGL5oyDmsSfPGM+LZZZTTIsNYbjZPTk/kv/Rd7cdzaim7GE7CF/+pJHNQ2FjSUZYOCwEggACAAGpJ9O0AAAAVneWKAwwBVYACRorPEvDw8S8wqMqMjrEosIsOiujqioqKqKiqiqioqKAAAAAGQKdOImQNAAA=";

    #[test]
    fn parses_a_real_transaction_boc() {
        let tx = parse_transaction(SAMPLE_TX).expect("parse");
        assert_eq!(tx.hash.len(), 64, "tx hash is a 32-byte hex string");
        assert!(tx.lt > 0, "logical time is set");
        assert!(tx.now > 0, "block time is set");
        assert!(tx.in_msg.is_some(), "has an inbound message");
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_transaction("not-a-boc").is_err());
    }

    #[test]
    fn rejects_an_oversized_transaction_before_boc_parsing() {
        let oversized = BASE64.encode(vec![0u8; MAX_TRANSACTION_BOC_BYTES + 1]);
        let error = parse_transaction(&oversized).unwrap_err();
        assert!(error.to_string().contains("decoded ceiling"));
    }

    #[test]
    fn sample_is_an_outgoing_cc_transfer() {
        let tx = parse_transaction(SAMPLE_TX).expect("parse");
        assert!(!tx.aborted && tx.compute_success && tx.exit_code == 0);
        assert!(tx.total_fees_native > 0, "real gas charged");
        assert_eq!(tx.in_msg.as_ref().unwrap().kind, MsgKind::ExtIn);
        let out = &tx.out_msgs[0];
        assert_eq!(out.kind, MsgKind::Int);
        assert!(out.dst.is_some(), "recipient address present");
        assert!(
            out.value_extra.contains_key(&3),
            "carries extra-currency id 3"
        );
        assert_eq!(
            Boc::decode_base64(&out.body_boc_base64)
                .expect("body BOC")
                .repr_hash(),
            out.body.repr_hash()
        );
        assert_eq!(tx.action_success, Some(true));
        assert_eq!(tx.action_result_code, Some(0));
        assert!(!tx.compute_skipped);
        assert_eq!(tx.compute_skip_reason, None);
    }

    #[test]
    fn extra_currency_history_preserves_the_full_varuint248_domain() {
        let extra = ExtraCurrencyCollection::try_from_iter([(7, VarUint248::MAX)]).unwrap();
        assert_eq!(
            extra_currencies_to_strings(&extra).unwrap().get(&7),
            Some(&VarUint248::MAX.to_string())
        );
    }

    #[test]
    fn a_corrupt_extra_currency_dict_is_a_loud_error_not_a_truncated_map() {
        use tycho_types::dict::Dict;

        let mut raw: Dict<u32, u8> = Dict::new();
        raw.set(7u32, 0xFF_u8).unwrap();
        let corrupt = ExtraCurrencyCollection::from_raw(raw.into_root());

        let error = extra_currencies_to_strings(&corrupt).unwrap_err();
        assert!(
            error.to_string().contains("extra-currency"),
            "the error names the extra-currency context, got: {error}"
        );
    }

    #[test]
    fn parsed_message_retains_state_init_and_its_hash() {
        let state_init = StateInit {
            split_depth: None,
            special: None,
            code: Some(CellBuilder::build_from(0x11_u8).unwrap()),
            data: Some(CellBuilder::build_from(0x22_u8).unwrap()),
            libraries: Dict::new(),
        };
        let expected_hash = CellBuilder::build_from(&state_init)
            .unwrap()
            .repr_hash()
            .to_string();
        let cell = CellBuilder::build_from(OwnedMessage {
            info: MsgInfo::Int(IntMsgInfo {
                src: IntAddr::Std(StdAddr::new(0, HashBytes([0x11; 32]))),
                dst: IntAddr::Std(StdAddr::new(0, HashBytes([0x22; 32]))),
                ..Default::default()
            }),
            init: Some(state_init.clone()),
            body: Cell::default().into(),
            layout: None,
        })
        .unwrap();
        let parsed = parse_message(&cell).unwrap();
        assert_eq!(parsed.state_init, Some(state_init));
        assert_eq!(
            parsed.state_init_hash.as_deref(),
            Some(expected_hash.as_str())
        );
    }
}
