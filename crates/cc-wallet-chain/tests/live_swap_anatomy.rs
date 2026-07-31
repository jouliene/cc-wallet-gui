use std::time::Duration;

use cc_wallet_chain::{MsgKind, TychoWalletService};
use cc_wallet_domain::{
    AssetAmount, AssetId, CcAmount, EndpointAddressInputs, SeedPhrase, SwapRequest, WalletInputs,
    quote_swap,
};

const ENDPOINT: &str = "http://127.0.0.1:8001/";
const POOL: &str = "0:4273920c193f325e2db7d77b5668c8ac60f4d2ac37bc239b9aeea5a27924ccf4";
const SEED: &str = "bronze leg renew parent horn boost swim run coast tuition quality element";
const UNIT: u128 = 1_000_000_000;

fn inputs() -> WalletInputs {
    WalletInputs {
        endpoint: ENDPOINT.to_owned(),
        network_id: 0,
        workchain: 0,
        seed: SeedPhrase::shared(SEED.to_owned()),
        require_signature_id: false,
    }
}

async fn dump_account(service: &TychoWalletService, label: &str, address: &str, limit: u32) {
    let addr = EndpointAddressInputs::new(ENDPOINT.to_owned(), address.to_owned()).expect("inputs");
    let page = service
        .load_transactions(&addr, limit, None)
        .await
        .expect("load_transactions");
    println!("\n=== {label}  {address}");
    for tx in &page.transactions {
        println!("  TRANSACTION {}", tx.hash);
        println!("    lt={}  now={}", tx.lt, tx.now);
        println!(
            "    total_fees_native = {}   (storage + compute + action of THIS account's work)",
            tx.total_fees_native
        );
        match tx.in_msg.as_ref() {
            None => println!("    in_msg: none (tick/tock)"),
            Some(m) => println!(
                "    in  MESSAGE {}\n        kind={:?} src={:?}\n        value_native={} value_extra={:?} fwd_fee={}",
                m.hash, m.kind, m.src, m.value_native, m.value_extra, m.fwd_fee
            ),
        }
        if tx.out_msgs.is_empty() {
            println!("    out messages: none");
        }
        for m in &tx.out_msgs {
            println!(
                "    out MESSAGE {}\n        kind={:?} dst={:?}\n        value_native={} value_extra={:?} fwd_fee={}",
                m.hash, m.kind, m.dst, m.value_native, m.value_extra, m.fwd_fee
            );
        }
    }
}

#[tokio::test]
#[ignore = "performs a real swap on the localnet; requires the pool deployed and swap_user funded"]
async fn the_anatomy_of_one_swap() {
    let service = TychoWalletService::default();
    let wallet = service
        .derive_wallet_address(&inputs())
        .expect("derive address");
    let one = AssetId::CurrencyCollection(1);
    let two = AssetId::CurrencyCollection(2);

    let before = service
        .load_pool_state(ENDPOINT, POOL)
        .await
        .expect("pool state");
    let in_units = 3 * UNIT;
    let quote = quote_swap(
        in_units,
        before.reserve_units(one),
        before.reserve_units(two),
        before.fee_bps,
        50,
    )
    .expect("quote");
    println!(
        "\nSWAPPING 3 ONE -> ~{} TWO (min {})",
        quote.out_units, quote.min_out_units
    );

    let request = SwapRequest::new(
        AssetAmount::currency_collection(1, CcAmount::from_u128(in_units)),
        two,
        quote.min_out_units,
        50,
    )
    .expect("valid request");
    let prepared = service
        .prepare_swap(inputs(), POOL.to_owned(), request)
        .await
        .expect("prepare_swap");
    let outcome = service
        .broadcast_swap(&prepared, 0)
        .await
        .expect("broadcast_swap");
    println!("broadcast: {outcome:?}");

    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let now = service
            .load_pool_state(ENDPOINT, POOL)
            .await
            .expect("pool state");
        if now.reserve_units(one) >= before.reserve_units(one) + in_units {
            break;
        }
    }

    dump_account(&service, "WALLET (swap_user)", &wallet, 2).await;
    dump_account(&service, "POOL (CC-DEX)", POOL, 1).await;

    let wallet_addr =
        EndpointAddressInputs::new(ENDPOINT.to_owned(), wallet.clone()).expect("inputs");
    let page = service
        .load_transactions(&wallet_addr, 2, None)
        .await
        .expect("load_transactions");
    let ext_tx = page
        .transactions
        .iter()
        .find(|tx| tx.in_msg.as_ref().is_some_and(|m| m.kind == MsgKind::ExtIn))
        .expect("the wallet's own send");
    let trace = service
        .trace_transaction(ENDPOINT.to_owned(), ext_tx.hash.clone())
        .await
        .expect("trace");
    println!("\n=== TRACE rooted at {}", ext_tx.hash);
    println!("    total_fees_native = {}", trace.total_fees_native);
    for (i, edge) in trace.edges.iter().enumerate() {
        println!(
            "  edge {i}: MESSAGE from party {} to party {}\n      fwd_fee={}  produced TRANSACTION {:?}  its own fees={:?}",
            edge.from,
            edge.to,
            edge.fwd_fee,
            edge.tx.as_ref().map(|t| t.hash.to_string()),
            edge.tx.as_ref().map(|t| t.fee_native)
        );
    }
    for (i, party) in trace.parties.iter().enumerate() {
        println!(
            "  party {i}: {}",
            if party.address.is_empty() {
                "(external)"
            } else {
                &party.address
            }
        );
    }
}
