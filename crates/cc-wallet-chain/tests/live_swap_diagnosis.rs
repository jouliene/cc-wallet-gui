use cc_wallet_chain::{AccountTxKind, TychoWalletService, activity_from_chain_tx};
use cc_wallet_domain::{EndpointAddressInputs, SeedPhrase, WalletInputs};

const ENDPOINT: &str = "http://127.0.0.1:8001/";
const SEED: &str = "bronze leg renew parent horn boost swim run coast tuition quality element";

fn inputs() -> WalletInputs {
    WalletInputs {
        endpoint: ENDPOINT.to_owned(),
        network_id: 0,
        workchain: 0,
        seed: SeedPhrase::shared(SEED.to_owned()),
        require_signature_id: false,
    }
}

#[tokio::test]
#[ignore = "requires the local network with the pool deployed and swap_user funded"]
async fn both_history_views_over_the_same_live_transactions() {
    let service = TychoWalletService::default();
    let address = service
        .derive_wallet_address(&inputs())
        .expect("derive swap_user address");
    println!("\nwallet: {address}\n");

    let explorer = service
        .account_transactions(ENDPOINT.to_owned(), address.clone(), 40)
        .await
        .expect("account_transactions");
    println!(
        "EXPLORER: {} rows, {} SKIPPED",
        explorer.rows.len(),
        explorer.skipped
    );
    for tx in &explorer.rows {
        let kind = match tx.kind {
            AccountTxKind::In => "In",
            AccountTxKind::Out => "Out",
            AccountTxKind::Fwd => "Fwd",
            AccountTxKind::Ext => "Ext",
            AccountTxKind::Special => "Special",
        };
        let moved: Vec<String> = tx
            .movements
            .iter()
            .map(|m| format!("{:?}", m.amount))
            .collect();
        println!(
            "  {} lt={} {:>7} party={} moved={:?} int_out={} ok={}",
            &tx.hash.to_string()[..16],
            tx.lt,
            kind,
            if tx.counterparty.is_empty() {
                "-"
            } else {
                &tx.counterparty
            },
            moved,
            tx.int_out_msgs,
            tx.success
        );
    }

    let addr_inputs =
        EndpointAddressInputs::new(ENDPOINT.to_owned(), address.clone()).expect("endpoint inputs");
    let page = service
        .load_transactions(&addr_inputs, 40, None)
        .await
        .expect("load_transactions");
    let mut events = Vec::new();
    let mut activity_skipped = Vec::new();
    for tx in &page.transactions {
        match activity_from_chain_tx(tx) {
            Ok(mut produced) => events.append(&mut produced),
            Err(error) => activity_skipped.push(format!("{}: {error}", &tx.hash[..16])),
        }
    }
    println!(
        "\nACTIVITY: {} events from {} transactions ({} raw-page skipped), parser errors: {:?}",
        events.len(),
        page.transactions.len(),
        page.skipped,
        activity_skipped
    );
    for event in &events {
        let moved: Vec<String> = event
            .movements
            .iter()
            .map(|m| format!("{:?}", m.amount))
            .collect();
        println!(
            "  {} lt={} {:?} party={} moved={:?} ok={}",
            event
                .tx_hash
                .as_ref()
                .map(|h| h.to_string()[..16].to_owned())
                .unwrap_or_else(|| "-".to_owned()),
            event.lt,
            event.direction,
            if event.counterparty.is_empty() {
                "-"
            } else {
                &event.counterparty
            },
            moved,
            event.success
        );
    }

    println!("\nRAW: in_msg kind and out_msg shape per transaction");
    for tx in &page.transactions {
        let kind = tx
            .in_msg
            .as_ref()
            .map(|m| format!("{:?}", m.kind))
            .unwrap_or_else(|| "none".to_owned());
        let outs: Vec<String> = tx
            .out_msgs
            .iter()
            .map(|m| {
                format!(
                    "{:?}(native={},extra={:?})",
                    m.kind, m.value_native, m.value_extra
                )
            })
            .collect();
        let in_extra = tx
            .in_msg
            .as_ref()
            .map(|m| format!("native={},extra={:?}", m.value_native, m.value_extra))
            .unwrap_or_default();
        println!(
            "  {} lt={} in={kind}[{in_extra}] out={outs:?}",
            &tx.hash[..16],
            tx.lt
        );
    }
}

#[tokio::test]
#[ignore = "requires the local network with the pool deployed"]
async fn what_the_pool_account_looks_like_in_the_explorer() {
    const POOL: &str = "0:4273920c193f325e2db7d77b5668c8ac60f4d2ac37bc239b9aeea5a27924ccf4";
    let service = TychoWalletService::default();
    let wallet = service
        .derive_wallet_address(&inputs())
        .expect("derive swap_user address");
    let page = service
        .account_transactions(ENDPOINT.to_owned(), POOL.to_owned(), 8)
        .await
        .expect("account_transactions for the pool");
    println!("\nPOOL {POOL}");
    println!("our wallet is {wallet}\n");
    for tx in &page.rows {
        let kind = match tx.kind {
            AccountTxKind::In => "In",
            AccountTxKind::Out => "Out",
            AccountTxKind::Fwd => "Fwd",
            AccountTxKind::Ext => "Ext",
            AccountTxKind::Special => "Special",
        };
        let moved: Vec<String> = tx
            .movements
            .iter()
            .map(|m| format!("{:?}", m.amount))
            .collect();
        let ours = tx.counterparty == wallet;
        let arrived: Vec<String> = tx
            .received
            .iter()
            .map(|m| format!("{:?}", m.amount))
            .collect();
        println!(
            "  {} {:>7} party={}{}\n      IN  {:?}\n      OUT {:?}",
            &tx.hash.to_string()[..16],
            kind,
            &tx.counterparty[..std::cmp::min(18, tx.counterparty.len())],
            if ours { "  <-- OUR ADDRESS" } else { "" },
            arrived,
            moved
        );
    }
}

#[tokio::test]
#[ignore = "requires the local network with the pool deployed"]
async fn the_account_that_did_the_two_to_one_swap() {
    const POOL: &str = "0:4273920c193f325e2db7d77b5668c8ac60f4d2ac37bc239b9aeea5a27924ccf4";
    let service = TychoWalletService::default();
    let pool_page = service
        .account_transactions(ENDPOINT.to_owned(), POOL.to_owned(), 3)
        .await
        .expect("pool page");
    let user = pool_page.rows[0].counterparty.clone();
    println!("\nthe swapping wallet: {user}\n");

    let page = service
        .account_transactions(ENDPOINT.to_owned(), user.clone(), 12)
        .await
        .expect("user page");
    println!("EXPLORER rows for that wallet ({} skipped):", page.skipped);
    for tx in &page.rows {
        let kind = match tx.kind {
            AccountTxKind::In => "In",
            AccountTxKind::Out => "Out",
            AccountTxKind::Fwd => "Fwd",
            AccountTxKind::Ext => "Ext",
            AccountTxKind::Special => "Special",
        };
        let moved: Vec<String> = tx
            .movements
            .iter()
            .map(|m| format!("{:?}", m.amount))
            .collect();
        println!(
            "  {} lt={} {:>7} moved={:?}",
            &tx.hash.to_string()[..16],
            tx.lt,
            kind,
            moved
        );
    }

    let addr = EndpointAddressInputs::new(ENDPOINT.to_owned(), user).expect("inputs");
    let raw = service
        .load_transactions(&addr, 12, None)
        .await
        .expect("load_transactions");
    println!("\nACTIVITY parser over the same transactions:");
    for tx in &raw.transactions {
        match activity_from_chain_tx(tx) {
            Ok(events) => {
                for e in events {
                    let moved: Vec<String> = e
                        .movements
                        .iter()
                        .map(|m| format!("{:?}", m.amount))
                        .collect();
                    println!("  {} {:?} moved={:?}", &tx.hash[..16], e.direction, moved);
                }
            }
            Err(error) => println!("  {} PARSER ERROR: {error}", &tx.hash[..16]),
        }
    }
}

#[tokio::test]
#[ignore = "requires the local network with the pool deployed"]
async fn where_a_relays_fee_comes_from() {
    const POOL: &str = "0:4273920c193f325e2db7d77b5668c8ac60f4d2ac37bc239b9aeea5a27924ccf4";
    let service = TychoWalletService::default();
    let addr = EndpointAddressInputs::new(ENDPOINT.to_owned(), POOL.to_owned()).expect("inputs");
    let raw = service
        .load_transactions(&addr, 4, None)
        .await
        .expect("load_transactions for the pool");
    let parsed = service
        .account_transactions(ENDPOINT.to_owned(), POOL.to_owned(), 4)
        .await
        .expect("account_transactions");

    println!("\nPOOL fees: chain components vs what the row shows");
    for (tx, row) in raw.transactions.iter().zip(parsed.rows.iter()) {
        let out_fwd: u128 = tx
            .out_msgs
            .iter()
            .filter(|m| m.kind == cc_wallet_chain::MsgKind::Int)
            .map(|m| m.fwd_fee)
            .sum();
        let in_fwd = tx.in_msg.as_ref().map(|m| m.fwd_fee).unwrap_or(0);
        println!(
            "  {}\n      total_fees_native = {:>12}\n      out fwd_fee sum   = {:>12}\n                   in  fwd_fee       = {:>12}\n      row.fee_native    = {:>12}   (= total + out fwd)",
            &tx.hash[..16],
            tx.total_fees_native,
            out_fwd,
            in_fwd,
            row.fee_native
        );
        assert_eq!(
            row.fee_native,
            tx.total_fees_native + out_fwd,
            "the row's fee is the account's own fees plus the forwarding it bought"
        );
    }
}

#[tokio::test]
#[ignore = "requires the local network with the pool deployed"]
async fn the_trace_fee_total_counts_every_part_once() {
    let service = TychoWalletService::default();
    let pool_page = service
        .account_transactions(
            ENDPOINT.to_owned(),
            "0:4273920c193f325e2db7d77b5668c8ac60f4d2ac37bc239b9aeea5a27924ccf4".to_owned(),
            1,
        )
        .await
        .expect("pool page");
    let hash = pool_page.rows[0].hash.to_string();
    let trace = service
        .trace_transaction(ENDPOINT.to_owned(), hash.clone())
        .await
        .expect("trace");

    let mut parts = 0u128;
    println!("\ntrace of {}", &hash[..16]);
    for edge in &trace.edges {
        let tx_fee = edge.tx.as_ref().map(|tx| tx.fee_native).unwrap_or(0);
        println!(
            "  edge fwd_fee = {:>9}   produced tx total_fees = {:>9}",
            edge.fwd_fee, tx_fee
        );
        parts += edge.fwd_fee + tx_fee;
    }
    println!("  parts summed  = {parts}");
    println!("  trace reports = {}", trace.total_fees_native);
    assert_eq!(
        parts, trace.total_fees_native,
        "every fwd_fee and every transaction fee must appear exactly once"
    );
}
