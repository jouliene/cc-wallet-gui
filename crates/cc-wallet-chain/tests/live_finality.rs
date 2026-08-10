//! Takes the wallet's own finality number apart on a real chain.
//!
//! The status line quotes one figure — broadcast to the moment the account
//! subscription says the account reached that transaction — and one figure
//! cannot say whether the wait belongs to the network, to the node's index, or
//! to the stream that carries the news. This sends real transfers and stamps
//! every stage of each one:
//!
//! * how long the signed message took to prepare (before the clock starts),
//! * how long the `sendMessage` call itself took,
//! * when the block carrying the transaction was generated,
//! * when a poll of the transaction list could first see it,
//! * when the subscription announced it — the number the wallet shows.
//!
//! Run with:
//! ```text
//! CC_WALLET_ENDPOINT=https://rpc-testnet.tychoprotocol.com/ \
//! CC_WALLET_TEST_SEED="…" \
//! cargo test -p cc-wallet-chain --test live_finality -- --ignored --nocapture
//! ```

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cc_wallet_chain::{SubscriptionEvent, TychoWalletService, account_subscription_loop};
use cc_wallet_domain::{
    EndpointAddressInputs, RecordId, SeedPhrase, SendRequest, SendTicket, WalletInputs,
};

const ROUNDS: usize = 5;
const POLL_EVERY: Duration = Duration::from_millis(200);

fn inputs() -> WalletInputs {
    WalletInputs {
        endpoint: std::env::var("CC_WALLET_ENDPOINT")
            .expect("CC_WALLET_ENDPOINT names the network to spend on"),
        network_id: 2000,
        // Blocks are collated per shard, so which chain the wallet lives on is
        // part of the answer rather than a detail of the setup.
        workchain: std::env::var("CC_WALLET_TEST_WORKCHAIN")
            .map(|value| value.parse().expect("workchain is a number"))
            .unwrap_or(0),
        seed: SeedPhrase::shared(
            std::env::var("CC_WALLET_TEST_SEED").expect("CC_WALLET_TEST_SEED funds the test"),
        ),
        require_signature_id: true,
    }
}

fn unix_now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the clock is after 1970")
        .as_secs_f64()
}

fn median(values: &mut [f64]) -> f64 {
    values.sort_by(|a, b| a.partial_cmp(b).expect("no NaN in a measurement"));
    values[values.len() / 2]
}

/// One transaction as the transaction list showed it, and when we saw it.
#[derive(Clone, Copy)]
struct Sighting {
    lt: u64,
    block_utime: u32,
    seen_at: Instant,
}

#[tokio::test]
#[ignore = "spends real testnet coins"]
async fn finality_comes_apart_into_network_index_and_stream() {
    let base = inputs();
    let service = Arc::new(TychoWalletService::default());
    let address = service
        .derive_wallet_address(&base)
        .expect("address derivation");
    let public = EndpointAddressInputs::new(base.endpoint.clone(), address.clone())
        .expect("canonical inputs");
    println!("[wallet]   {address}");
    println!("[endpoint] {}", base.endpoint);

    // Everything the subscription says, stamped on arrival. This is the exact
    // source the wallet's own finality number is read from.
    let announcements: Arc<Mutex<Vec<(u64, Instant)>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = announcements.clone();
    let stream_endpoint = base.endpoint.clone();
    let stream_address = address.clone();
    let subscription = tokio::spawn(async move {
        let _ = account_subscription_loop(stream_endpoint, stream_address, |event| {
            if let SubscriptionEvent::Update(update) = event {
                sink.lock()
                    .expect("announcement lock")
                    .push((update.max_lt, Instant::now()));
            }
        })
        .await;
    });

    // And everything a fast poll of the transaction list could have known,
    // stamped the same way, so the stream can be compared against the index it
    // is supposed to be announcing.
    let sightings: Arc<Mutex<Vec<Sighting>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = sightings.clone();
    let poller_service = service.clone();
    let poller_inputs = public.clone();
    let poller = tokio::spawn(async move {
        loop {
            if let Ok(page) = poller_service
                .load_transactions(&poller_inputs, 5, None)
                .await
            {
                let seen_at = Instant::now();
                let mut held = sink.lock().expect("sighting lock");
                for transaction in &page.transactions {
                    if !held.iter().any(|held| held.lt == transaction.lt) {
                        held.push(Sighting {
                            lt: transaction.lt,
                            block_utime: transaction.now,
                            seen_at,
                        });
                    }
                }
            }
            tokio::time::sleep(POLL_EVERY).await;
        }
    });

    // The subscription needs to be up before the first send, or the first round
    // measures the handshake instead of the chain.
    tokio::time::sleep(Duration::from_secs(3)).await;

    let mut prepare_ms = Vec::new();
    let mut broadcast_ms = Vec::new();
    let mut block_s = Vec::new();
    let mut index_ms = Vec::new();
    let mut stream_ms = Vec::new();

    for round in 0..ROUNDS {
        let known: Vec<u64> = sightings
            .lock()
            .expect("sighting lock")
            .iter()
            .map(|held| held.lt)
            .collect();

        let request = SendRequest::native(&address, 1).expect("one nano to ourselves");
        let ticket = SendTicket::new(
            RecordId::from_bytes([round as u8 + 1; 32]),
            "live-finality".to_owned(),
            address.clone(),
            base.network_id,
            base.endpoint.clone(),
            request,
            true,
            1,
            round as u64 + 1,
        )
        .expect("the ticket is well formed");

        let prepare_started = Instant::now();
        let prepared = service
            .prepare_transaction(inputs(), ticket, Vec::new(), Vec::new())
            .await
            .expect("prepare failed");
        let prepared_in = prepare_started.elapsed();

        // The wallet starts its finality clock here: signed, about to go out.
        let sent_at = Instant::now();
        let sent_unix = unix_now();
        service
            .broadcast_prepared_candidate(&prepared, 0)
            .await
            .expect("broadcast failed");
        let broadcast_in = sent_at.elapsed();

        let deadline = Instant::now() + Duration::from_secs(60);
        let landed = loop {
            if Instant::now() > deadline {
                panic!("round {round}: the transfer never appeared in the transaction list");
            }
            let fresh = sightings
                .lock()
                .expect("sighting lock")
                .iter()
                .filter(|held| !known.contains(&held.lt))
                .min_by_key(|held| held.lt)
                .copied();
            if let Some(fresh) = fresh {
                break fresh;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        };

        let deadline = Instant::now() + Duration::from_secs(60);
        let announced_at = loop {
            if Instant::now() > deadline {
                println!("[round {round}] the subscription never announced this transaction");
                break None;
            }
            let announced = announcements
                .lock()
                .expect("announcement lock")
                .iter()
                .filter(|(max_lt, _)| *max_lt >= landed.lt)
                .map(|(_, at)| *at)
                .min();
            if let Some(announced) = announced {
                break Some(announced);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        };

        let to_block = f64::from(landed.block_utime) - sent_unix;
        let to_index = landed.seen_at.duration_since(sent_at).as_secs_f64() * 1000.0;
        let to_stream = announced_at.map(|at| at.duration_since(sent_at).as_secs_f64() * 1000.0);

        println!(
            "[round {round}] prepare {:.0} ms | sendMessage {:.0} ms | \
             block generated +{to_block:.0} s | list shows it +{to_index:.0} ms | \
             subscription announces it {} | lt {}",
            prepared_in.as_secs_f64() * 1000.0,
            broadcast_in.as_secs_f64() * 1000.0,
            to_stream.map_or_else(|| "never".to_owned(), |ms| format!("+{ms:.0} ms")),
            landed.lt,
        );

        prepare_ms.push(prepared_in.as_secs_f64() * 1000.0);
        broadcast_ms.push(broadcast_in.as_secs_f64() * 1000.0);
        block_s.push(to_block);
        index_ms.push(to_index);
        if let Some(to_stream) = to_stream {
            stream_ms.push(to_stream);
        }

        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    println!("\n[medians over {ROUNDS} rounds]");
    println!(
        "  prepare (before the clock starts) {:.0} ms",
        median(&mut prepare_ms)
    );
    println!(
        "  sendMessage round trip            {:.0} ms",
        median(&mut broadcast_ms)
    );
    println!(
        "  broadcast -> block generated      {:.1} s",
        median(&mut block_s)
    );
    println!(
        "  broadcast -> visible to a poll    {:.0} ms",
        median(&mut index_ms)
    );
    if !stream_ms.is_empty() {
        println!(
            "  broadcast -> subscription says so {:.0} ms   <- what the wallet shows",
            median(&mut stream_ms)
        );
    }

    let all_announcements = announcements.lock().expect("announcement lock").len();
    println!("  subscription updates seen in total: {all_announcements}");

    poller.abort();
    subscription.abort();
}
