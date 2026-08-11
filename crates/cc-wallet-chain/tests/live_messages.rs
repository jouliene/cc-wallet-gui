use std::time::{Duration, Instant};

use cc_wallet_chain::{SealedComment, TychoWalletService, activity_from_chain_tx};
use cc_wallet_domain::{
    ActivityMessage, EndpointAddressInputs, RecordId, SeedPhrase, SendRequest, SendTicket,
    WalletInputs,
};

fn fresh_inputs() -> WalletInputs {
    WalletInputs {
        endpoint: std::env::var("CC_WALLET_ENDPOINT")
            .expect("CC_WALLET_ENDPOINT names the network to spend on"),
        network_id: 2000,
        workchain: 0,
        seed: SeedPhrase::shared(
            std::env::var("CC_WALLET_TEST_SEED").expect("CC_WALLET_TEST_SEED funds the test"),
        ),
        require_signature_id: true,
    }
}

async fn send(
    service: &TychoWalletService,
    inputs: WalletInputs,
    address: &str,
    request: SendRequest,
    nonce: u64,
) {
    let ticket = SendTicket::new(
        RecordId::from_bytes([nonce as u8; 32]),
        "live-messages".to_owned(),
        address.to_owned(),
        inputs.network_id,
        inputs.endpoint.clone(),
        request,
        true,
        1,
        nonce,
    )
    .expect("the ticket is well formed");

    let prepared = service
        .prepare_transaction(inputs, ticket, Vec::new(), Vec::new())
        .await
        .expect("prepare failed");
    service
        .broadcast_prepared_candidate(&prepared, 0)
        .await
        .expect("broadcast failed");
}

#[tokio::test]
#[ignore = "spends real testnet coins"]
async fn a_plain_and_a_sealed_comment_survive_the_round_trip_through_a_real_chain() {
    let service = TychoWalletService::default();
    let inputs = fresh_inputs();
    let address = service
        .derive_wallet_address(&inputs)
        .expect("address derivation");
    println!("[wallet] {address}");

    let public = EndpointAddressInputs::new(inputs.endpoint.clone(), address.clone())
        .expect("canonical inputs");
    let before = service
        .load_transactions(&public, 20, None)
        .await
        .expect("history")
        .transactions
        .first()
        .map(|tx| tx.lt)
        .unwrap_or(0);

    let key = service
        .check_destination(&public, address.clone())
        .await
        .expect("destination check")
        .encrypt_key
        .expect("an active Ever Wallet publishes its signing key");

    let plain = "plain words on a real chain";
    let secret = "sealed words on a real chain";
    send(
        &service,
        fresh_inputs(),
        &address,
        SendRequest::native(&address, 20_000_000)
            .unwrap()
            .with_comment(plain),
        1,
    )
    .await;
    println!("[sent] plain");

    let deadline = Instant::now() + Duration::from_secs(90);
    while Instant::now() < deadline {
        tokio::time::sleep(Duration::from_secs(3)).await;
        let head = service
            .load_transactions(&public, 5, None)
            .await
            .expect("history")
            .transactions
            .first()
            .map(|tx| tx.lt)
            .unwrap_or(0);
        if head > before {
            break;
        }
    }

    send(
        &service,
        fresh_inputs(),
        &address,
        SendRequest::native(&address, 20_000_000)
            .unwrap()
            .with_comment(secret)
            .sealed_to(Some(key)),
        2,
    )
    .await;
    println!("[sent] sealed");

    let deadline = Instant::now() + Duration::from_secs(120);
    let mut found_plain = false;
    let mut found_sealed = false;
    while Instant::now() < deadline && !(found_plain && found_sealed) {
        tokio::time::sleep(Duration::from_secs(4)).await;
        let page = service
            .load_transactions(&public, 20, None)
            .await
            .expect("history");
        for tx in &page.transactions {
            for event in activity_from_chain_tx(tx).expect("activity parses") {
                match event.message.as_ref() {
                    Some(ActivityMessage::Plain { text }) if text == plain => {
                        found_plain = true;
                        println!("[read] plain, {:?}", event.direction);
                    }
                    Some(ActivityMessage::Sealed { sender_key, blob }) => {
                        let outgoing =
                            matches!(event.direction, cc_wallet_domain::ActivityDirection::Out);
                        let opened = service
                            .open_conversation(
                                &inputs,
                                &event.counterparty,
                                Some(&key),
                                &[SealedComment {
                                    outgoing,
                                    sender_key: sender_key.as_bytes(),
                                    blob,
                                }],
                            )
                            .expect("opening runs");
                        println!("[read] sealed, {:?} -> {:?}", event.direction, opened[0]);
                        assert!(
                            opened[0].is_some(),
                            "a sealed comment that came off the chain did not open at all, \
                             going {:?}",
                            event.direction
                        );
                        if opened[0].as_deref() == Some(secret) {
                            found_sealed = true;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    assert!(found_plain, "the plain comment never came back");
    assert!(found_sealed, "the sealed comment never came back");
}
