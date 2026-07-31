use std::time::{Duration, Instant};

use cc_wallet_chain::{PoolSnapshot, TychoWalletService};
use cc_wallet_domain::{
    AssetAmount, AssetId, CcAmount, EndpointAddressInputs, SeedPhrase, SwapRequest, WalletInputs,
    base_units_u128, quote_swap,
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

async fn user_balance(service: &TychoWalletService, asset: AssetId) -> u128 {
    let address = service
        .derive_wallet_address(&inputs())
        .expect("derive swap_user address");
    let addr_inputs =
        EndpointAddressInputs::new(ENDPOINT.to_owned(), address).expect("endpoint inputs");
    let snapshot = service
        .load_wallet(&addr_inputs)
        .await
        .expect("load swap_user wallet");
    base_units_u128(&snapshot.balance_for(asset)).expect("balance fits u128")
}

async fn wait_for_pool(
    service: &TychoWalletService,
    settled: impl Fn(&PoolSnapshot) -> bool,
) -> PoolSnapshot {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let snapshot = service
            .load_pool_state(ENDPOINT, POOL)
            .await
            .expect("load pool state");
        if settled(&snapshot) {
            return snapshot;
        }
        assert!(Instant::now() < deadline, "the swap did not settle in time");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

#[tokio::test]
#[ignore = "requires the running localnet + deployed pool + funded swap_user"]
async fn a_swap_moves_the_users_tokens_and_the_pools_reserves() {
    let service = TychoWalletService::default();
    let (one, two) = (
        AssetId::CurrencyCollection(1),
        AssetId::CurrencyCollection(2),
    );

    let before = service.load_pool_state(ENDPOINT, POOL).await.unwrap();
    println!(
        "[pool before] fee_bps={} native={} ONE={} TWO={}",
        before.fee_bps,
        before.native_reserve,
        before.reserve_units(one),
        before.reserve_units(two),
    );
    assert_eq!(before.fee_bps, 30, "the deployed pool charges 0.3%");
    assert!(
        before.supports(one) && before.supports(two),
        "ONE/TWO are pooled"
    );

    let user_one_before = user_balance(&service, one).await;
    let user_two_before = user_balance(&service, two).await;
    println!("[user before] ONE={user_one_before} TWO={user_two_before}");

    let in_units = 5 * UNIT;
    let quote = quote_swap(
        in_units,
        before.reserve_units(one),
        before.reserve_units(two),
        before.fee_bps,
        50,
    )
    .expect("quote");
    println!(
        "[quote] 5 ONE -> {} TWO (min {})",
        quote.out_units, quote.min_out_units
    );
    assert!(quote.out_units > 0, "the pair is quotable");

    let input = AssetAmount::currency_collection(1, CcAmount::from_u128(in_units));
    let request =
        SwapRequest::new(input, two, quote.min_out_units, 50).expect("valid swap request");

    let prepared = service
        .prepare_swap(inputs(), POOL.to_owned(), request)
        .await
        .expect("prepare_swap");
    let outcome = service
        .broadcast_swap(&prepared, 0)
        .await
        .expect("broadcast_swap");
    println!("[broadcast] {outcome:?}");

    let after = wait_for_pool(&service, |pool| {
        pool.reserve_units(one) >= before.reserve_units(one) + in_units
    })
    .await;
    println!(
        "[pool after] ONE={} TWO={}",
        after.reserve_units(one),
        after.reserve_units(two)
    );
    assert_eq!(
        after.reserve_units(one),
        before.reserve_units(one) + in_units,
        "the full input joined the ONE reserve"
    );
    assert_eq!(
        after.reserve_units(two),
        before.reserve_units(two) - quote.out_units,
        "TWO reserve fell by exactly the quoted output"
    );

    tokio::time::sleep(Duration::from_secs(3)).await;
    let user_one_after = user_balance(&service, one).await;
    let user_two_after = user_balance(&service, two).await;
    println!("[user after] ONE={user_one_after} TWO={user_two_after}");
    assert_eq!(
        user_one_before - user_one_after,
        in_units,
        "the user spent exactly 5 ONE"
    );
    assert_eq!(
        user_two_after - user_two_before,
        quote.out_units,
        "the user received exactly the quoted TWO"
    );
    println!("[ok] the wallet's swap filled at the pool, reserves and balances moved");
}

#[tokio::test]
#[ignore = "requires the running localnet + deployed pool + funded swap_user"]
async fn an_unsupported_token_is_returned_not_kept() {
    let service = TychoWalletService::default();
    let (three, one) = (
        AssetId::CurrencyCollection(3),
        AssetId::CurrencyCollection(1),
    );

    let before = service.load_pool_state(ENDPOINT, POOL).await.unwrap();
    assert!(
        !before.supports(three),
        "THREE is deliberately not in the pool"
    );
    let user_three_before = user_balance(&service, three).await;
    println!("[user before] THREE={user_three_before}");
    assert!(user_three_before >= UNIT, "swap_user holds THREE to try");

    let in_units = 3 * UNIT;
    let input = AssetAmount::currency_collection(3, CcAmount::from_u128(in_units));
    let request = SwapRequest::new(input, one, 0, 50).expect("valid request even if unsupported");

    let prepared = service
        .prepare_swap(inputs(), POOL.to_owned(), request)
        .await
        .expect("prepare_swap builds the message even for an unsupported pair");
    let outcome = service
        .broadcast_swap(&prepared, 0)
        .await
        .expect("broadcast");
    println!("[broadcast] {outcome:?}");

    let sent_deadline = Instant::now() + Duration::from_secs(60);
    let address = service.derive_wallet_address(&inputs()).unwrap();
    let addr_inputs = EndpointAddressInputs::new(ENDPOINT.to_owned(), address).unwrap();
    let lt_before = service
        .load_wallet(&addr_inputs)
        .await
        .unwrap()
        .last_trans_lt;
    loop {
        let lt_now = service
            .load_wallet(&addr_inputs)
            .await
            .unwrap()
            .last_trans_lt;
        if lt_now != lt_before {
            break;
        }
        assert!(
            Instant::now() < sent_deadline,
            "the wallet never sent the swap"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    tokio::time::sleep(Duration::from_secs(8)).await;
    let pool = service.load_pool_state(ENDPOINT, POOL).await.unwrap();
    assert!(!pool.supports(three), "the pool never took the THREE input");
    let user_three_after = user_balance(&service, three).await;
    println!("[user after] THREE={user_three_after} (was {user_three_before})");
    assert_eq!(
        user_three_after, user_three_before,
        "the unsupported THREE input was bounced back to the user in full"
    );
    println!("[ok] the pool bounced the unsupported token back to the user");
}
