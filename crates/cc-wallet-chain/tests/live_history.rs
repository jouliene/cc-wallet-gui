use cc_wallet_chain::TychoWalletService;
use cc_wallet_domain::{EndpointAddressInputs, SeedPhrase, WalletInputs};

const SEED: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
fn inputs() -> WalletInputs {
    WalletInputs {
        endpoint: std::env::var("CC_WALLET_ENDPOINT")
            .unwrap_or_else(|_| "http://127.0.0.1:8001/".to_owned()),
        network_id: 0,
        workchain: -1,
        seed: SeedPhrase::shared(SEED.to_owned()),
        require_signature_id: false,
    }
}

#[tokio::test]
#[ignore = "requires the local network + a funded seed-index-0 / wc -1 wallet with history"]
async fn gui_chain_layer_loads_real_transactions() {
    let service = TychoWalletService::default();
    let inputs = inputs();
    let address = service
        .derive_wallet_address(&inputs)
        .expect("local wallet address derivation failed");
    let public_inputs = EndpointAddressInputs::new(inputs.endpoint, address)
        .expect("derived wallet has canonical endpoint/address inputs");

    let snapshot = service
        .load_wallet(&public_inputs)
        .await
        .expect("load_wallet failed");
    println!(
        "[head] address={} last_trans_lt={}",
        snapshot.address, snapshot.last_trans_lt
    );
    assert!(snapshot.last_trans_lt > 0, "account has transactions");

    let txs = service
        .load_transactions(&public_inputs, 10, None)
        .await
        .expect("load_transactions failed")
        .transactions;
    assert!(!txs.is_empty(), "got real transactions");
    for pair in txs.windows(2) {
        assert!(pair[0].lt > pair[1].lt, "descending lt order");
    }
    let newest = &txs[0];
    println!(
        "[tx0] hash={} lt={} now={} fee={} ok={} in={:?} out={}",
        newest.hash,
        newest.lt,
        newest.now,
        newest.total_fees_native,
        newest.compute_success,
        newest.in_msg.as_ref().map(|m| m.kind),
        newest.out_msgs.len()
    );
    assert!(
        newest.lt <= snapshot.last_trans_lt,
        "list head never exceeds account head"
    );
    assert!(newest.now > 0 && newest.hash.len() == 64);
}
