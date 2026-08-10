use cc_wallet_domain::{
    ActivityDirection, ActivityEvent, AssetAmount, AssetMovement, CcAmount, Digest32,
};
use cc_wallet_tycho::{BounceOutcome, ChainMessage, ChainTransaction, MsgKind};

use crate::explorer::failure_reason;
use crate::wallet_service::{ChainError, ChainResult};

pub fn activity_from_chain_tx(tx: &ChainTransaction) -> ChainResult<Vec<ActivityEvent>> {
    let Some(in_msg) = tx.in_msg.as_ref() else {
        return Ok(Vec::new());
    };

    match in_msg.kind {
        MsgKind::ExtIn => {
            let ext_msg_hash = parse_hash(&in_msg.hash, "external inbound message")?;
            let internal: Vec<&ChainMessage> = tx
                .out_msgs
                .iter()
                .filter(|message| message.kind == MsgKind::Int)
                .collect();
            if internal.is_empty() {
                return Ok(vec![no_transfer_send(tx, ext_msg_hash)?]);
            }
            let tx_hash = parse_hash(&tx.hash, "transaction")?;
            let success = failure_reason(tx).is_empty();
            let mut events = Vec::with_capacity(internal.len());
            for (index, message) in internal.iter().enumerate() {
                let movements = message_movements(message)?;
                let fee_native = if index == 0 {
                    tx.total_fees_native
                        .checked_add(message.fwd_fee)
                        .ok_or_else(|| {
                            ChainError::Wallet("native transaction fee overflows u128".to_owned())
                        })?
                } else {
                    message.fwd_fee
                };
                AssetAmount::native(fee_native).map_err(|error| {
                    ChainError::Wallet(format!("native transaction fee is out of domain: {error}"))
                })?;
                events.push(ActivityEvent {
                    direction: ActivityDirection::Out,
                    lt: tx.lt,
                    time_unix: u64::from(tx.now),
                    tx_hash: Some(tx_hash.clone()),
                    counterparty: message.dst.clone().unwrap_or_default(),
                    movements,
                    fee_native,
                    success,
                    bounced: message.bounced,
                    exit_code: tx.exit_code,
                    ext_msg_hash: Some(ext_msg_hash.clone()),
                    int_msg_hash: Some(parse_hash(&message.hash, "internal message")?),
                    finality_ms: None,
                    pending: false,
                });
            }
            Ok(events)
        }
        MsgKind::Int => {
            let movements = message_movements(in_msg)?;
            let native_was_returned =
                tx.bounce == Some(BounceOutcome::Returned) && in_msg.value_extra.is_empty();
            let success = !in_msg.bounced && !native_was_returned;
            AssetAmount::native(tx.total_fees_native).map_err(|error| {
                ChainError::Wallet(format!("native transaction fee is out of domain: {error}"))
            })?;
            Ok(vec![ActivityEvent {
                direction: ActivityDirection::In,
                lt: tx.lt,
                time_unix: u64::from(tx.now),
                tx_hash: Some(parse_hash(&tx.hash, "transaction")?),
                counterparty: in_msg.src.clone().unwrap_or_default(),
                movements,
                fee_native: tx.total_fees_native,
                success,
                bounced: in_msg.bounced,
                exit_code: tx.exit_code,
                ext_msg_hash: None,
                int_msg_hash: Some(parse_hash(&in_msg.hash, "internal message")?),
                finality_ms: None,
                pending: false,
            }])
        }
        MsgKind::ExtOut => Ok(Vec::new()),
    }
}

fn no_transfer_send(tx: &ChainTransaction, ext_msg_hash: Digest32) -> ChainResult<ActivityEvent> {
    AssetAmount::native(tx.total_fees_native).map_err(|error| {
        ChainError::Wallet(format!("native transaction fee is out of domain: {error}"))
    })?;
    Ok(ActivityEvent {
        direction: ActivityDirection::Out,
        lt: tx.lt,
        time_unix: u64::from(tx.now),
        tx_hash: Some(parse_hash(&tx.hash, "transaction")?),
        counterparty: String::new(),
        movements: vec![AssetMovement {
            amount: AssetAmount::native(0).expect("zero native units are in-domain"),
        }],
        fee_native: tx.total_fees_native,
        success: false,
        bounced: false,
        exit_code: tx.exit_code,
        ext_msg_hash: Some(ext_msg_hash),
        int_msg_hash: None,
        finality_ms: None,
        pending: false,
    })
}

fn parse_hash(value: &str, context: &str) -> ChainResult<Digest32> {
    Digest32::try_from_hex(value).map_err(|error| {
        ChainError::Wallet(format!(
            "{context} hash is not canonical 32-byte hex: {error}"
        ))
    })
}

pub(crate) fn message_movements(message: &ChainMessage) -> ChainResult<Vec<AssetMovement>> {
    let mut movements = Vec::with_capacity(message.value_extra.len() + 1);
    for (&id, text) in &message.value_extra {
        let amount = CcAmount::try_from_canonical_decimal(text).map_err(|error| {
            ChainError::Wallet(format!(
                "transaction extra-currency {id} has invalid amount {text:?}: {error}"
            ))
        })?;
        if !amount.is_zero() {
            movements.push(AssetMovement {
                amount: AssetAmount::currency_collection(id, amount),
            });
        }
    }
    if message.value_native > 0 || movements.is_empty() {
        let amount = AssetAmount::native(message.value_native).map_err(|error| {
            ChainError::Wallet(format!(
                "transaction native movement is out of domain: {error}"
            ))
        })?;
        movements.push(AssetMovement { amount });
    }
    Ok(movements)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use cc_wallet_domain::{AssetId, NATIVE_MAX_UNITS};
    use cc_wallet_tycho::Cell;

    use super::*;

    const ME: &str = "0:me";
    const OTHER: &str = "0:other";
    const THIRD: &str = "0:third";
    const FOURTH: &str = "0:fourth";
    const CC_MAX: &str =
        "452312848583266388373324160190187140051835877600158453279131187530910662655";
    const EXT_HASH: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    const INT_HASH: &str = "1111111111111111111111111111111111111111111111111111111111111111";
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
            hash: if kind == MsgKind::ExtIn {
                EXT_HASH.to_owned()
            } else {
                INT_HASH.to_owned()
            },
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

    fn ext_in() -> ChainMessage {
        message(MsgKind::ExtIn, None, Some(ME), 0, BTreeMap::new())
    }

    fn internal(native: u128, extra: BTreeMap<u32, String>) -> ChainMessage {
        message(MsgKind::Int, Some(ME), Some(OTHER), native, extra)
    }

    fn transaction(
        in_msg: ChainMessage,
        out_msgs: Vec<ChainMessage>,
        aborted: bool,
        exit_code: i32,
    ) -> ChainTransaction {
        ChainTransaction {
            hash: TX_HASH.to_owned(),
            lt: 42,
            now: 1_000,
            prev_trans_lt: 40,
            total_fees_native: 5_000,
            aborted,
            compute_success: exit_code == 0,
            compute_skipped: false,
            compute_skip_reason: None,
            exit_code,
            action_success: None,
            action_result_code: None,
            action_no_funds: None,
            bounce: None,
            in_msg: Some(in_msg),
            out_msgs,
        }
    }

    fn event(tx: &ChainTransaction) -> ActivityEvent {
        activity_from_chain_tx(tx)
            .unwrap()
            .into_iter()
            .next()
            .expect("activity event")
    }

    fn incoming_deposit(native: u128) -> ChainMessage {
        message(MsgKind::Int, Some(OTHER), Some(ME), native, BTreeMap::new())
    }

    #[test]
    fn a_bounced_incoming_deposit_is_classified_as_failed() {
        let mut tx = transaction(incoming_deposit(5_000_000_000), Vec::new(), true, 0);
        tx.compute_skipped = true;
        tx.bounce = Some(BounceOutcome::Returned);

        let event = event(&tx);

        assert_eq!(event.direction, ActivityDirection::In);
        assert!(
            !event.success,
            "a receive whose value bounced back to the sender is not a success"
        );
    }

    #[test]
    fn a_clean_incoming_deposit_to_an_uninitialized_account_is_successful() {
        let mut tx = transaction(incoming_deposit(5_000_000_000), Vec::new(), true, 0);
        tx.compute_skipped = true;

        let event = event(&tx);

        assert_eq!(event.direction, ActivityDirection::In);
        assert!(event.success, "a non-bounced first deposit is a success");
    }

    #[test]
    fn a_cc_receive_that_bounced_the_zero_native_but_kept_the_currency_is_successful() {
        let deposit = message(
            MsgKind::Int,
            Some(OTHER),
            Some(ME),
            0,
            BTreeMap::from([(1u32, "1000000000".to_owned())]),
        );
        let mut tx = transaction(deposit, Vec::new(), true, 0);
        tx.compute_skipped = true;
        tx.bounce = Some(BounceOutcome::Returned);

        let event = event(&tx);

        assert_eq!(event.direction, ActivityDirection::In);
        assert!(
            event.success,
            "a CC receive is a success — credited extra currency survives the bounce of the zero native"
        );
    }

    #[test]
    fn outgoing_native_preserves_effect_hash_status_and_checked_fee() {
        let event = event(&transaction(
            ext_in(),
            vec![internal(1_000_000_000, BTreeMap::new())],
            false,
            0,
        ));
        assert_eq!(event.direction, ActivityDirection::Out);
        assert_eq!(event.counterparty, OTHER);
        assert_eq!(
            event.movements[0].amount.native_units(),
            Some(1_000_000_000)
        );
        assert_eq!(event.fee_native, 5_100);
        assert!(event.success);
        assert_eq!(
            event.ext_msg_hash,
            Some(Digest32::try_from_hex(EXT_HASH).unwrap())
        );
        assert_eq!(
            event.int_msg_hash,
            Some(Digest32::try_from_hex(INT_HASH).unwrap())
        );
    }

    #[test]
    fn full_width_cc_and_native_movements_survive_atomically() {
        let extra = BTreeMap::from([(1, CC_MAX.to_owned()), (2, "0".to_owned())]);
        let event = event(&transaction(
            ext_in(),
            vec![internal(7_000_000, extra)],
            false,
            0,
        ));
        assert_eq!(event.movements.len(), 2);
        assert_eq!(
            event.movements[0].amount.asset_id(),
            AssetId::CurrencyCollection(1)
        );
        assert_eq!(
            event.movements[0]
                .amount
                .cc_units()
                .unwrap()
                .to_canonical_decimal(),
            CC_MAX
        );
        assert_eq!(event.movements[1].amount.native_units(), Some(7_000_000));
    }

    #[test]
    fn one_malformed_or_out_of_range_movement_rejects_the_whole_transaction() {
        for invalid in [
            "01",
            "-1",
            "not-a-number",
            "452312848583266388373324160190187140051835877600158453279131187530910662656",
        ] {
            let extra = BTreeMap::from([(1, "42".to_owned()), (2, invalid.to_owned())]);
            let tx = transaction(ext_in(), vec![internal(0, extra)], false, 0);
            assert!(
                activity_from_chain_tx(&tx).is_err(),
                "must reject {invalid}"
            );
        }
    }

    #[test]
    fn incoming_bounce_and_uninitialized_compute_skip_are_classified_honestly() {
        let incoming = message(MsgKind::Int, Some(OTHER), Some(ME), 5, BTreeMap::new());
        let mut bounced = incoming.clone();
        bounced.bounced = true;
        assert!(!event(&transaction(bounced, vec![], false, 0)).success);

        let mut first_deposit = transaction(incoming, vec![], true, 0);
        first_deposit.compute_skipped = true;
        assert!(event(&first_deposit).success);
    }

    #[test]
    fn aborted_send_without_internal_message_is_retained_as_failed() {
        let event = event(&transaction(ext_in(), vec![], true, 37));
        assert_eq!(event.direction, ActivityDirection::Out);
        assert!(!event.success);
        assert_eq!(event.exit_code, 37);
        assert_eq!(
            event.ext_msg_hash,
            Some(Digest32::try_from_hex(EXT_HASH).unwrap())
        );
        assert_eq!(event.movements[0].amount.native_units(), Some(0));
    }

    #[test]
    fn native_domain_and_fee_overflow_are_refused() {
        let oversized = internal(NATIVE_MAX_UNITS + 1, BTreeMap::new());
        assert!(activity_from_chain_tx(&transaction(ext_in(), vec![oversized], false, 0)).is_err());

        let mut tx = transaction(ext_in(), vec![internal(1, BTreeMap::new())], false, 0);
        tx.total_fees_native = u128::MAX;
        assert!(activity_from_chain_tx(&tx).is_err());
    }

    #[test]
    fn storage_only_transaction_is_not_activity() {
        let mut tx = transaction(ext_in(), vec![], false, 0);
        tx.in_msg = None;
        assert!(activity_from_chain_tx(&tx).unwrap().is_empty());
    }

    #[test]
    fn multi_transfer_send_yields_one_event_per_internal_message() {
        let mut out_a = message(MsgKind::Int, Some(ME), Some(OTHER), 10, BTreeMap::new());
        out_a.hash = "0".repeat(64);
        out_a.fwd_fee = 11;
        let mut out_b = message(MsgKind::Int, Some(ME), Some(THIRD), 25, BTreeMap::new());
        out_b.hash = "1".repeat(64);
        out_b.fwd_fee = 22;
        let mut out_c = message(MsgKind::Int, Some(ME), Some(FOURTH), 5, BTreeMap::new());
        out_c.hash = "2".repeat(64);
        out_c.fwd_fee = 33;

        let tx = transaction(ext_in(), vec![out_a, out_b, out_c], false, 0);
        let events = activity_from_chain_tx(&tx).unwrap();

        assert_eq!(events.len(), 3, "one event per internal out-message");
        let counterparties: Vec<&str> = events.iter().map(|e| e.counterparty.as_str()).collect();
        assert_eq!(counterparties, vec![OTHER, THIRD, FOURTH]);
        assert_eq!(events[0].movements[0].amount.native_units(), Some(10));
        assert_eq!(events[1].movements[0].amount.native_units(), Some(25));
        assert_eq!(events[2].movements[0].amount.native_units(), Some(5));
        for event in &events {
            assert_eq!(event.lt, tx.lt);
            assert_eq!(event.tx_hash, events[0].tx_hash);
            assert_eq!(event.ext_msg_hash, events[0].ext_msg_hash);
            assert!(event.success);
        }
        assert_ne!(events[0].int_msg_hash, events[1].int_msg_hash);
        assert_ne!(events[1].int_msg_hash, events[2].int_msg_hash);
        assert_eq!(events[0].fee_native, tx.total_fees_native + 11);
        assert_eq!(events[1].fee_native, 22);
        assert_eq!(events[2].fee_native, 33);
    }

    #[test]
    fn a_send_reads_the_same_here_as_it_does_in_the_explorer() {
        use crate::explorer::account_tx_from_chain_tx;

        let cases: Vec<(&str, ChainTransaction)> = vec![
            (
                "a clean send",
                transaction(ext_in(), vec![internal(10, BTreeMap::new())], false, 0),
            ),
            ("a rejected send", {
                let mut tx = transaction(ext_in(), vec![internal(10, BTreeMap::new())], true, 37);
                tx.compute_success = false;
                tx
            }),
            ("a send whose actions could not be applied", {
                let mut tx = transaction(ext_in(), vec![internal(10, BTreeMap::new())], true, 0);
                tx.action_success = Some(false);
                tx.action_no_funds = Some(true);
                tx
            }),
        ];

        for (label, tx) in cases {
            let activity = event(&tx).success;
            let explorer = account_tx_from_chain_tx(&tx).unwrap().success;
            assert_eq!(
                activity, explorer,
                "{label} must not be a success in one view and a failure in the other"
            );
        }
    }

    #[test]
    fn one_malformed_movement_in_any_sibling_rejects_the_whole_transaction() {
        let good = message(MsgKind::Int, Some(ME), Some(OTHER), 10, BTreeMap::new());
        let mut bad = message(MsgKind::Int, Some(ME), Some(THIRD), 5, BTreeMap::new());
        bad.hash = "1".repeat(64);
        bad.value_extra = BTreeMap::from([(7, "not-a-number".to_owned())]);

        let tx = transaction(ext_in(), vec![good, bad], false, 0);
        assert!(
            activity_from_chain_tx(&tx).is_err(),
            "a malformed movement in a later sibling rejects the whole transaction"
        );
    }
}
