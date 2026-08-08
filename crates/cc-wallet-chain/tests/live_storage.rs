use std::sync::Arc;
use std::time::{Duration, Instant};

use cc_wallet_chain::{TychoWalletService, generate_seed};
use cc_wallet_domain::{SeedPhrase, StorageOp, StorageSnapshot, WalletInputs};
use cc_wallet_tycho::{Cell, CellBuilder, EverWallet, KeyPair, StdAddr, Transport};

const ENDPOINT: &str = "http://127.0.0.1:8001";
const NETWORK_ID: i32 = 0;
const WORKCHAIN: i8 = 0;
const CC_VAULT: &str = "-1:3aeae180f1eadf8970b9103cb212b25fbc6f9d6b94e2481643529c940932e153";
const FUND_NATIVE: u128 = 5_000_000_000;
const SETTLE_TIMEOUT: Duration = Duration::from_secs(180);

const TITLE: &str = "Inna's phone";
const DATA: &str = "86594423664";

fn inputs(seed: &Arc<SeedPhrase>) -> WalletInputs {
    WalletInputs {
        endpoint: ENDPOINT.to_owned(),
        network_id: NETWORK_ID,
        workchain: WORKCHAIN,
        seed: Arc::clone(seed),
        require_signature_id: false,
    }
}

fn wallet_address(seed: &SeedPhrase) -> StdAddr {
    let keys = KeyPair::from_seed(seed.expose_secret()).expect("the generated seed derives a key");
    EverWallet::compute_address(WORKCHAIN, keys.public_key()).expect("an address is derivable")
}

async fn fund(transport: &Transport, dest: &StdAddr) {
    use num_bigint::BigUint;
    use tycho_types::abi::{AbiHeaderType, AbiType, AbiValue, AbiVersion, Function};

    let function = Function::builder(AbiVersion::V2_7, "sendCurrency")
        .with_id(0x02ed_f6b4)
        .with_headers([AbiHeaderType::Time])
        .with_inputs([
            AbiType::Address.named("dest"),
            AbiType::varuint(16).named("nativeValue"),
            AbiType::uint(32).named("currencyId"),
            AbiType::uint(128).named("amount"),
            AbiType::Bool.named("bounce"),
        ])
        .build();
    let vault: StdAddr = CC_VAULT.parse().expect("the vault address is canonical");
    let (_expire, message) = function
        .encode_external(&[
            AbiValue::address(dest.clone()).named("dest"),
            AbiValue::varuint(16, FUND_NATIVE).named("nativeValue"),
            AbiValue::Uint(32, BigUint::from(0u32)).named("currencyId"),
            AbiValue::Uint(128, BigUint::from(0u32)).named("amount"),
            AbiValue::Bool(false).named("bounce"),
        ])
        .build_message_without_signature(&vault)
        .expect("the unsigned faucet call encodes");
    let cell: Cell = CellBuilder::build_from(message).expect("the faucet message serializes");

    let route = transport
        .resolve_send_route()
        .await
        .expect("the local node answers a route probe");
    transport
        .send_message_cell_candidate_classified(&route, 0, &cell)
        .await
        .expect("the local node accepts the unsigned faucet call");
}

async fn wait_for<F>(
    service: &TychoWalletService,
    seed: &Arc<SeedPhrase>,
    what: &str,
    mut done: F,
) -> StorageSnapshot
where
    F: FnMut(&StorageSnapshot) -> bool,
{
    let deadline = Instant::now() + SETTLE_TIMEOUT;
    loop {
        let snapshot = service
            .load_storage(inputs(seed))
            .await
            .expect("the wallet can always read its own storage address");
        if done(&snapshot) {
            return snapshot;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {what}; last snapshot was {snapshot:?}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

async fn run(service: &TychoWalletService, seed: &Arc<SeedPhrase>, op: StorageOp) {
    let prepared = service
        .prepare_storage_op(inputs(seed), op.clone())
        .await
        .unwrap_or_else(|error| panic!("preparing {} failed: {error}", op.label()));
    let candidates = prepared.candidate_count().max(1);
    let mut sent = false;
    for index in 0..candidates {
        let outcome = service
            .broadcast_storage_op(&prepared, index)
            .await
            .unwrap_or_else(|error| panic!("broadcasting {} failed: {error}", op.label()));
        if !matches!(
            outcome,
            cc_wallet_chain::CandidateBroadcastOutcome::NotTransmitted {
                retry_next_candidate: true,
                ..
            }
        ) {
            sent = true;
            break;
        }
    }
    assert!(sent, "{} never reached the node", op.label());
}

#[tokio::test]
#[ignore = "requires the local network: ~/RUST_CODE/cc_transfer/scripts/launch_network.sh"]
async fn the_wallet_creates_a_storage_and_round_trips_a_record_through_the_chain() {
    let seed = Arc::new(generate_seed().expect("in-process RNG produces a seed"));
    let address = wallet_address(&seed);
    let service = TychoWalletService::default();
    let transport = Transport::jrpc(ENDPOINT).expect("the local endpoint parses");

    fund(&transport, &address).await;
    let deadline = Instant::now() + SETTLE_TIMEOUT;
    loop {
        let state = transport
            .get_account_state(address.to_string())
            .await
            .expect("the node answers an account read");
        if state.account().is_some() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the faucet never funded {address}"
        );
        tokio::time::sleep(Duration::from_millis(400)).await;
    }

    let before = service
        .load_storage(inputs(&seed))
        .await
        .expect("a wallet with no storage still reads cleanly");
    assert!(!before.exists, "a fresh wallet starts without a storage");
    assert!(before.records.is_empty());
    assert!(
        !before.address.is_empty(),
        "the storage address is derived even before it is deployed"
    );
    let storage_address = before.address.clone();

    run(&service, &seed, StorageOp::Create).await;
    let created = wait_for(&service, &seed, "the storage to deploy", |snapshot| {
        snapshot.exists
    })
    .await;
    assert_eq!(
        created.address, storage_address,
        "the deploy landed on the address the wallet derived before sending"
    );
    assert!(created.records.is_empty());

    run(
        &service,
        &seed,
        StorageOp::Put {
            id: 1,
            title: TITLE.to_owned(),
            data: DATA.to_owned(),
        },
    )
    .await;
    let saved = wait_for(&service, &seed, "the record to be saved", |snapshot| {
        !snapshot.records.is_empty()
    })
    .await;
    assert_eq!(saved.records.len(), 1);
    assert_eq!(saved.records[0].id, 1);
    assert_eq!(
        saved.records[0].title, TITLE,
        "the wallet decrypts back exactly what it wrote"
    );
    assert_eq!(saved.records[0].data, DATA);
    assert_eq!(saved.unreadable, 0);

    let account = transport
        .get_account_state(&storage_address)
        .await
        .expect("the node answers a read of the storage account");
    let stored = cc_wallet_tycho::storage_from_account(&account)
        .expect("the storage account decodes")
        .expect("the storage account is active");
    let raw = stored
        .records
        .get(&1)
        .expect("record 1 is on chain")
        .clone();
    for secret in [TITLE.as_bytes(), DATA.as_bytes()] {
        assert!(
            !raw.windows(secret.len()).any(|window| window == secret),
            "the plaintext must never appear in what the chain stores"
        );
    }

    run(&service, &seed, StorageOp::Delete { id: 1 }).await;
    let deleted = wait_for(&service, &seed, "the record to be deleted", |snapshot| {
        snapshot.records.is_empty()
    })
    .await;
    assert!(deleted.exists, "deleting a record keeps the storage itself");
    assert_eq!(deleted.unreadable, 0);
}
