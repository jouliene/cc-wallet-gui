use cc_wallet_domain::{AssetMovement, Digest32};
use cc_wallet_tycho::{ChainMessage, ChainTransaction, MsgKind};

use crate::activity::message_movements;
use crate::wallet_service::{ChainError, ChainResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccountTxKind {
    In,
    Out,
    Fwd,
    Ext,
    Special,
}

impl AccountTxKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::In => "IN",
            Self::Out => "OUT",
            Self::Fwd => "FWD",
            Self::Ext => "EXT",
            Self::Special => "TICK",
        }
    }

    pub fn is_in(self) -> bool {
        matches!(self, Self::In)
    }

    pub fn is_signed_for_reader(self) -> bool {
        matches!(self, Self::In | Self::Out)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AccountTx {
    pub hash: Digest32,
    pub lt: u64,
    pub time_unix: u64,
    pub kind: AccountTxKind,
    pub counterparty: String,
    pub extra_parties: usize,
    pub movements: Vec<AssetMovement>,
    pub received: Vec<AssetMovement>,
    pub fee_native: u128,
    pub int_out_msgs: usize,
    pub ext_out_msgs: usize,
    pub success: bool,
    pub bounced: bool,
    pub exit_code: i32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct AccountTxPage {
    pub rows: Vec<AccountTx>,
    pub skipped: usize,
}

pub fn failure_reason(tx: &ChainTransaction) -> String {
    if !tx.compute_success {
        return format!("exit {}", tx.exit_code);
    }
    if tx.action_success == Some(false) {
        return match tx.action_no_funds {
            Some(true) => "no funds for actions".to_owned(),
            _ => format!("action {}", tx.action_result_code.unwrap_or_default()),
        };
    }
    let returned = tx.bounce_phase_present
        && tx
            .in_msg
            .as_ref()
            .is_some_and(|message| message.value_extra.is_empty());
    if returned {
        return "value returned".to_owned();
    }
    String::new()
}

pub fn account_tx_from_chain_tx(tx: &ChainTransaction) -> ChainResult<AccountTx> {
    let hash = Digest32::try_from_hex(&tx.hash).map_err(|error| {
        ChainError::Wallet(format!(
            "transaction hash is not canonical 32-byte hex: {error}"
        ))
    })?;
    let internal_out: Vec<&ChainMessage> = tx
        .out_msgs
        .iter()
        .filter(|message| message.kind == MsgKind::Int)
        .collect();
    let ext_out_msgs = tx.out_msgs.len() - internal_out.len();

    let mut fee_native = tx.total_fees_native;
    for message in &internal_out {
        fee_native = fee_native.checked_add(message.fwd_fee).ok_or_else(|| {
            ChainError::Wallet("native transaction fee overflows u128".to_owned())
        })?;
    }

    let (kind, counterparty, movements, received, bounced) = match tx.in_msg.as_ref() {
        None => (
            AccountTxKind::Special,
            String::new(),
            Vec::new(),
            Vec::new(),
            false,
        ),
        Some(in_msg) => match in_msg.kind {
            MsgKind::Int if internal_out.is_empty() => (
                AccountTxKind::In,
                in_msg.src.clone().unwrap_or_default(),
                message_movements(in_msg)?,
                Vec::new(),
                in_msg.bounced,
            ),
            MsgKind::Int => (
                AccountTxKind::Fwd,
                internal_out[0].dst.clone().unwrap_or_default(),
                sum_movements(&internal_out)?,
                message_movements(in_msg)?,
                in_msg.bounced,
            ),
            MsgKind::ExtIn if internal_out.is_empty() => (
                AccountTxKind::Ext,
                String::new(),
                Vec::new(),
                Vec::new(),
                false,
            ),
            MsgKind::ExtIn => (
                AccountTxKind::Out,
                internal_out[0].dst.clone().unwrap_or_default(),
                sum_movements(&internal_out)?,
                Vec::new(),
                false,
            ),
            MsgKind::ExtOut => (
                AccountTxKind::Special,
                String::new(),
                Vec::new(),
                Vec::new(),
                false,
            ),
        },
    };

    Ok(AccountTx {
        hash,
        lt: tx.lt,
        time_unix: u64::from(tx.now),
        kind,
        counterparty,
        extra_parties: internal_out.len().saturating_sub(1),
        movements,
        received,
        fee_native,
        int_out_msgs: internal_out.len(),
        ext_out_msgs,
        success: failure_reason(tx).is_empty(),
        bounced,
        exit_code: tx.exit_code,
    })
}

fn sum_movements(messages: &[&ChainMessage]) -> ChainResult<Vec<AssetMovement>> {
    let mut totals: Vec<AssetMovement> = Vec::new();
    for message in messages {
        for movement in message_movements(message)? {
            match totals
                .iter_mut()
                .find(|total| total.amount.asset_id() == movement.amount.asset_id())
            {
                Some(total) => {
                    total.amount = total
                        .amount
                        .checked_add_same_asset(&movement.amount)
                        .map_err(|error| {
                            ChainError::Wallet(format!(
                                "transaction moves more than the asset's domain allows: {error}"
                            ))
                        })?;
                }
                None => totals.push(movement),
            }
        }
    }
    Ok(totals)
}

#[cfg(test)]
mod tests {

    #[test]
    fn a_relay_says_what_arrived_as_well_as_what_left() {
        let mut two = BTreeMap::new();
        two.insert(2u32, "1123000000".to_owned());
        let mut one = BTreeMap::new();
        one.insert(1u32, "251416023".to_owned());

        let tx = transaction(
            Some(message(
                MsgKind::Int,
                Some(ME),
                Some(OTHER),
                200_000_000,
                two,
            )),
            vec![message(
                MsgKind::Int,
                Some(OTHER),
                Some(ME),
                183_303_476,
                one,
            )],
        );
        let row = account_tx_from_chain_tx(&tx).expect("the pool's transaction parses");
        assert_eq!(row.kind, AccountTxKind::Fwd);

        let left: Vec<AssetId> = row.movements.iter().map(|m| m.amount.asset_id()).collect();
        assert!(
            left.contains(&AssetId::CurrencyCollection(1)),
            "what left should be the ONE: {left:?}"
        );
        let arrived: Vec<AssetId> = row.received.iter().map(|m| m.amount.asset_id()).collect();
        assert!(
            arrived.contains(&AssetId::CurrencyCollection(2)),
            "the 1.123 TWO that arrived is missing from the row: received = {arrived:?}"
        );
    }

    #[test]
    fn a_relay_that_paid_us_is_not_signed_as_our_own_outflow() {
        let mut two = BTreeMap::new();
        two.insert(2u32, "10000000000".to_owned());
        let mut one = BTreeMap::new();
        one.insert(1u32, "2341241645".to_owned());

        let tx = transaction(
            Some(message(
                MsgKind::Int,
                Some(ME),
                Some(OTHER),
                200_000_000,
                two,
            )),
            vec![message(
                MsgKind::Int,
                Some(OTHER),
                Some(ME),
                183_303_795,
                one,
            )],
        );

        let row = account_tx_from_chain_tx(&tx).expect("the pool's transaction parses");
        assert_eq!(row.kind, AccountTxKind::Fwd);
        assert_eq!(
            row.counterparty, ME,
            "the forward's destination is us, which is what makes the sign wrong"
        );
        assert!(
            !row.kind.is_signed_for_reader(),
            "a forward whose destination is {} is presented with a sign, so {:?} reads as the \
             reader's own outflow to the reader's own wallet",
            row.counterparty,
            row.movements
        );
    }
    use std::collections::BTreeMap;

    use cc_wallet_domain::{AssetId, NATIVE_MAX_UNITS};
    use cc_wallet_tycho::Cell;

    use super::*;

    const ME: &str = "0:me";
    const OTHER: &str = "0:other";
    const THIRD: &str = "0:third";
    const TX_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn message(
        kind: MsgKind,
        src: Option<&str>,
        dst: Option<&str>,
        native: u128,
        extra: BTreeMap<u32, String>,
    ) -> ChainMessage {
        ChainMessage {
            kind,
            hash: "1".repeat(64),
            src: src.map(str::to_owned),
            dst: dst.map(str::to_owned),
            value_native: native,
            value_extra: extra,
            fwd_fee: 100,
            bounce: true,
            bounced: false,
            created_lt: 1,
            created_at: 1,
            state_init: None,
            state_init_hash: None,
            body: Cell::default(),
            body_boc_base64: String::new(),
        }
    }

    fn transaction(in_msg: Option<ChainMessage>, out_msgs: Vec<ChainMessage>) -> ChainTransaction {
        ChainTransaction {
            hash: TX_HASH.to_owned(),
            lt: 42,
            now: 1_000,
            prev_trans_lt: 40,
            total_fees_native: 5_000,
            aborted: false,
            compute_success: true,
            compute_skipped: false,
            compute_skip_reason: None,
            exit_code: 0,
            action_success: Some(true),
            action_result_code: Some(0),
            action_no_funds: Some(false),
            bounce_phase_present: false,
            in_msg,
            out_msgs,
        }
    }

    #[test]
    fn an_inbound_transfer_reads_from_the_sender() {
        let deposit = message(MsgKind::Int, Some(OTHER), Some(ME), 7_000, BTreeMap::new());
        let row = account_tx_from_chain_tx(&transaction(Some(deposit), Vec::new())).unwrap();

        assert_eq!(row.kind, AccountTxKind::In);
        assert_eq!(row.counterparty, OTHER);
        assert_eq!(row.movements[0].amount.native_units(), Some(7_000));
        assert_eq!(row.fee_native, 5_000, "nothing was forwarded out");
        assert!(row.success);
    }

    #[test]
    fn an_internal_message_the_account_passes_on_is_a_forward_not_a_plain_in() {
        let arrival = message(MsgKind::Int, Some(OTHER), Some(ME), 9_000, BTreeMap::new());
        let forward = message(MsgKind::Int, Some(ME), Some(THIRD), 8_800, BTreeMap::new());
        let row = account_tx_from_chain_tx(&transaction(Some(arrival), vec![forward])).unwrap();

        assert_eq!(row.kind, AccountTxKind::Fwd);
        assert!(
            !row.kind.is_in(),
            "a forward reads as leaving, not arriving"
        );
        assert_eq!(row.kind.label(), "FWD");
        assert_eq!(
            row.counterparty, THIRD,
            "named by where it was sent, not its source"
        );
        assert_eq!(
            row.movements[0].amount.native_units(),
            Some(8_800),
            "the row totals what left, not what arrived"
        );
        assert_eq!(row.int_out_msgs, 1);
        assert_eq!(
            row.fee_native,
            5_000 + 100,
            "the forward's own fee counts too"
        );
    }

    #[test]
    fn a_fanned_out_send_stays_one_row_and_totals_what_left() {
        let extra = BTreeMap::from([(3, "40".to_owned())]);
        let out_a = message(MsgKind::Int, Some(ME), Some(OTHER), 10, extra.clone());
        let out_b = message(MsgKind::Int, Some(ME), Some(THIRD), 25, extra);
        let ext_in = message(MsgKind::ExtIn, None, Some(ME), 0, BTreeMap::new());

        let row = account_tx_from_chain_tx(&transaction(Some(ext_in), vec![out_a, out_b])).unwrap();

        assert_eq!(row.kind, AccountTxKind::Out);
        assert_eq!(row.counterparty, OTHER, "the first recipient names the row");
        assert_eq!(row.extra_parties, 1, "and the rest are counted, not hidden");
        assert_eq!(row.int_out_msgs, 2);
        assert_eq!(
            row.movements[0].amount.asset_id(),
            AssetId::CurrencyCollection(3)
        );
        assert_eq!(
            row.movements[0]
                .amount
                .cc_units()
                .unwrap()
                .to_canonical_decimal(),
            "80",
            "both messages' currency is summed"
        );
        assert_eq!(row.movements[1].amount.native_units(), Some(35));
        assert_eq!(row.fee_native, 5_000 + 100 + 100, "both forwards are paid");
    }

    #[test]
    fn an_external_call_that_moved_nothing_is_not_a_send() {
        let ext_in = message(MsgKind::ExtIn, None, Some(ME), 0, BTreeMap::new());
        let row = account_tx_from_chain_tx(&transaction(Some(ext_in), Vec::new())).unwrap();

        assert_eq!(row.kind, AccountTxKind::Ext);
        assert!(row.movements.is_empty());
        assert_eq!(row.counterparty, "");
    }

    #[test]
    fn a_transaction_with_no_inbound_message_is_kept_as_a_special() {
        let row = account_tx_from_chain_tx(&transaction(None, Vec::new())).unwrap();

        assert_eq!(
            row.kind,
            AccountTxKind::Special,
            "an explorer shows storage and tick-tock work too — activity drops it"
        );
        assert_eq!(row.fee_native, 5_000);
    }

    #[test]
    fn an_event_only_transaction_counts_its_external_output() {
        let ext_in = message(MsgKind::ExtIn, None, Some(ME), 0, BTreeMap::new());
        let event = message(MsgKind::ExtOut, Some(ME), None, 0, BTreeMap::new());
        let row = account_tx_from_chain_tx(&transaction(Some(ext_in), vec![event])).unwrap();

        assert_eq!(row.kind, AccountTxKind::Ext);
        assert_eq!(row.ext_out_msgs, 1);
        assert_eq!(row.int_out_msgs, 0);
    }

    #[test]
    fn a_bounced_arrival_is_flagged_even_though_the_transaction_ran() {
        let mut bounced = message(MsgKind::Int, Some(OTHER), Some(ME), 7_000, BTreeMap::new());
        bounced.bounced = true;
        let row = account_tx_from_chain_tx(&transaction(Some(bounced), Vec::new())).unwrap();

        assert!(row.bounced);
        assert!(row.success, "the transaction itself did not fail");
    }

    #[test]
    fn a_deposit_into_an_account_with_no_code_is_delivered_not_failed() {
        let deposit = message(MsgKind::Int, Some(OTHER), Some(ME), 7_000, BTreeMap::new());
        let mut tx = transaction(Some(deposit), Vec::new());
        tx.aborted = true;
        tx.compute_skipped = true;

        let row = account_tx_from_chain_tx(&tx).unwrap();

        assert!(row.success, "an aborted first deposit still arrived");
    }

    #[test]
    fn value_that_bounced_home_is_a_failure_but_currency_that_stayed_is_not() {
        let deposit = message(MsgKind::Int, Some(OTHER), Some(ME), 7_000, BTreeMap::new());
        let mut returned = transaction(Some(deposit), Vec::new());
        returned.aborted = true;
        returned.bounce_phase_present = true;
        assert!(!account_tx_from_chain_tx(&returned).unwrap().success);
        assert_eq!(failure_reason(&returned), "value returned");

        let with_currency = message(
            MsgKind::Int,
            Some(OTHER),
            Some(ME),
            0,
            BTreeMap::from([(1u32, "5".to_owned())]),
        );
        let mut kept = transaction(Some(with_currency), Vec::new());
        kept.aborted = true;
        kept.bounce_phase_present = true;
        assert!(account_tx_from_chain_tx(&kept).unwrap().success);
    }

    #[test]
    fn an_aborted_transaction_reports_its_exit_code() {
        let ext_in = message(MsgKind::ExtIn, None, Some(ME), 0, BTreeMap::new());
        let mut tx = transaction(Some(ext_in), Vec::new());
        tx.aborted = true;
        tx.compute_success = false;
        tx.exit_code = 37;

        let row = account_tx_from_chain_tx(&tx).unwrap();

        assert!(!row.success);
        assert_eq!(row.exit_code, 37);
    }

    #[test]
    fn value_and_fee_beyond_the_domain_are_refused_not_wrapped() {
        let ext_in = message(MsgKind::ExtIn, None, Some(ME), 0, BTreeMap::new());
        let huge = message(
            MsgKind::Int,
            Some(ME),
            Some(OTHER),
            NATIVE_MAX_UNITS,
            BTreeMap::new(),
        );
        let mut second = huge.clone();
        second.dst = Some(THIRD.to_owned());
        assert!(
            account_tx_from_chain_tx(&transaction(Some(ext_in.clone()), vec![huge, second]))
                .is_err(),
            "two domain-max sends cannot silently total to something smaller"
        );

        let mut tx = transaction(
            Some(ext_in),
            vec![message(
                MsgKind::Int,
                Some(ME),
                Some(OTHER),
                1,
                BTreeMap::new(),
            )],
        );
        tx.total_fees_native = u128::MAX;
        assert!(account_tx_from_chain_tx(&tx).is_err());
    }

    #[test]
    fn a_hash_that_is_not_canonical_hex_is_refused() {
        let mut tx = transaction(None, Vec::new());
        tx.hash = "not-a-hash".to_owned();
        assert!(account_tx_from_chain_tx(&tx).is_err());
    }
}
