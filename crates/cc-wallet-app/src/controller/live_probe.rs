//! Times the wallet's own finality accounting against a real chain.
//!
//! `live_finality` in the chain crate measures what the network does. This
//! measures what the wallet makes of it: the same controller the window drives,
//! ticked at the same 150 ms the UI timer ticks at, sending through the same
//! authorization, so the number the status line would have shown can be put
//! beside the moment the subscription actually announced the transaction.
//!
//! Run with:
//! ```text
//! CC_WALLET_ENDPOINT=https://rpc-testnet.tychoprotocol.com/ \
//! CC_WALLET_TEST_SEED="…" CC_WALLET_TEST_WORKCHAIN=-1 \
//! cargo test -p cc-wallet-app --lib -- --ignored --nocapture live_probe
//! ```

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cc_wallet_domain::{SeedPhrase, WalletProfile};
use cc_wallet_vault::{KdfParams, Vault};

use super::{AppController, KeyAction, KeyMsg};
use crate::command::{AppCommand, Password};
use crate::state::LiveStatus;

const CHEAP: KdfParams = KdfParams {
    m_kib: 32,
    t: 2,
    p: 1,
};
const PW: &[u8] = b"a-test-password";
const UI_TICK: Duration = Duration::from_millis(150);

fn temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the clock is after 1970")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "cc-wallet-live-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir(&dir).expect("the probe creates its own launch folder");
    dir
}

/// The controller the window would have, opened on a real network.
fn opened(dir: &Path) -> AppController {
    let profile = WalletProfile {
        network_id: 2000,
        workchain: std::env::var("CC_WALLET_TEST_WORKCHAIN")
            .map(|value| value.parse().expect("workchain is a number"))
            .unwrap_or(0),
        seed: SeedPhrase::shared(
            std::env::var("CC_WALLET_TEST_SEED").expect("CC_WALLET_TEST_SEED funds the probe"),
        ),
        // Long enough that the send is confirmed rather than re-authenticated,
        // which is how a wallet in use behaves for everything after the first.
        autosign_mins: 30,
        ..WalletProfile::default()
    };
    let mut c = AppController::at_dir(dir, CHEAP).expect("controller opens");
    let vault = Vault::create_with(PW, CHEAP).expect("vault");
    let writer = c.store.writer_for_new().expect("writer");
    let generation = c.key_generation();
    c.apply_key_msg(KeyMsg::Ok {
        history_corrupt: false,
        journal: cc_wallet_domain::JournalEnvelope::empty(),
        selected: None,
        writer: Some(writer),
        generation,
        history: Vec::new(),
        action: KeyAction::Create,
        vault,
        profile,
    });
    c.drain_save_task();
    c
}

/// Everything that decides whether a send can move, in one line.
fn dump(c: &AppController, label: &str) {
    println!(
        "[state {label}] status {:?} | error {:?} | auth open {} mode {:?} err {:?} | \
         sending {} | key_busy {} | authorization held {} | recipient {:?} | \
         activity {} ({} pending) | journal_blocking {}",
        c.state().status,
        c.state().error,
        c.state().auth.open,
        c.state().auth.mode,
        c.state().auth.error,
        c.state().sending,
        c.state().key_busy,
        c.pending_authorization.is_some(),
        c.state().recipient_check,
        c.state().activity.len(),
        c.state().activity.iter().filter(|e| e.pending).count(),
        c.state().journal_blocking,
    );
}

/// Runs the loop the UI timer runs, until the wallet says what we are waiting
/// for or the patience runs out.
fn pump_until(
    c: &mut AppController,
    what: &str,
    limit: Duration,
    mut ready: impl FnMut(&AppController) -> bool,
) -> bool {
    let deadline = Instant::now() + limit;
    loop {
        c.tick();
        c.poll_events();
        if ready(c) {
            return true;
        }
        if Instant::now() >= deadline {
            println!("[timeout] waited {limit:?} for {what}");
            return false;
        }
        std::thread::sleep(UI_TICK);
    }
}

#[test]
#[ignore = "spends real testnet coins"]
fn what_the_status_line_would_have_shown() {
    let dir = temp_dir("finality");
    let mut c = opened(&dir);

    assert!(
        pump_until(
            &mut c,
            "the subscription to go live",
            Duration::from_secs(30),
            |c| { c.state().live_status == LiveStatus::Live && c.state().wallet.is_some() }
        ),
        "the wallet never came online"
    );
    let address = c
        .state()
        .wallet
        .as_ref()
        .expect("a live wallet has a snapshot")
        .address
        .clone();
    println!("[wallet]   {address}");
    println!("[endpoint] {}", c.state().resolved_endpoint());

    for round in 0..3 {
        c.handle_command(AppCommand::SetSendDestination(address.clone()));
        c.handle_command(AppCommand::SetSendAmount("0.000000001".to_owned()));
        pump_until(
            &mut c,
            "the recipient check",
            Duration::from_secs(20),
            |c| {
                !matches!(
                    c.state().recipient_check,
                    crate::state::RecipientCheck::Pending
                )
            },
        );

        let clicked = Instant::now();
        c.handle_command(AppCommand::RequestSend);
        pump_until(&mut c, "the signing dialog", Duration::from_secs(20), |c| {
            c.state().auth.open
        });
        // The dialog re-checks the recipient as it opens, and confirming before
        // that lands is refused — so this waits exactly as a person would.
        pump_until(
            &mut c,
            "the recipient check inside the dialog",
            Duration::from_secs(20),
            |c| {
                !matches!(
                    c.state().recipient_check,
                    crate::state::RecipientCheck::Pending
                )
            },
        );
        let confirmed = Instant::now();
        c.handle_command(AppCommand::AuthSubmit {
            pw: Password::new(String::from_utf8_lossy(PW).into_owned()),
            pw2: Password::new(String::new()),
            remember: false,
        });
        dump(&c, "submitted");

        let mut armed_at = None;
        let mut announced_at = None;
        let mut account_lt_at = None;
        let mut unblocked_at = None;
        let mut stopped_spinning_at = None;
        let mut blocked = false;
        let account_lt_before = c.state().wallet.as_ref().map_or(0, |w| w.last_trans_lt);
        // One character per UI tick: '#' while a history fetch is in flight,
        // 'A' on the tick the row stopped spinning (the stream's frame), 'L' on
        // the tick the account state moved past its old last transaction,
        // '.' idle.
        let mut trace = String::new();
        let settled = pump_until(
            &mut c,
            "the transfer to settle",
            Duration::from_secs(90),
            |c| {
                // The frame from the stream is now observable exactly as the
                // moment the row stops spinning — that is the whole point.
                let announced_now = announced_at.is_none()
                    && armed_at.is_some()
                    && c.state()
                        .activity
                        .iter()
                        .any(|event| event.tx_hash.is_none() && !event.pending);
                let account_moved = c
                    .state()
                    .wallet
                    .as_ref()
                    .is_some_and(|w| w.last_trans_lt > account_lt_before);
                trace.push(if announced_now {
                    'A'
                } else if account_lt_at.is_none() && account_moved {
                    'L'
                } else if c.load.fetch_in_flight {
                    '#'
                } else {
                    '.'
                });
                if armed_at.is_none() {
                    armed_at = c
                        .session
                        .pending_sends
                        .iter()
                        .filter_map(|(_, started_at)| *started_at)
                        .min();
                }
                if announced_now {
                    announced_at = Some(Instant::now());
                }
                if account_lt_at.is_none() && armed_at.is_some() && account_moved {
                    account_lt_at = Some(Instant::now());
                }
                blocked |= c.state().journal_blocking;
                if unblocked_at.is_none() && blocked && !c.state().journal_blocking {
                    unblocked_at = Some(Instant::now());
                }
                if stopped_spinning_at.is_none()
                    && armed_at.is_some()
                    && c.state()
                        .activity
                        .iter()
                        .any(|event| event.tx_hash.is_none() && !event.pending)
                {
                    stopped_spinning_at = Some(Instant::now());
                }
                // The round ends when the chain's own row lands, which is what
                // the wallet used to wait for before showing anything at all.
                c.state()
                    .activity
                    .iter()
                    .any(|event| event.tx_hash.is_some() && event.finality_ms.is_some())
            },
        );

        if armed_at.is_none() {
            dump(&c, "never armed");
            panic!("the send never reached the wire");
        }
        let armed_at = armed_at.expect("the send armed its clock");
        let reported = c
            .state()
            .activity
            .iter()
            .filter(|event| event.tx_hash.is_some())
            .filter_map(|event| event.finality_ms)
            .max();

        println!(
            "[round {round}] Send -> dialog usable {:.0} ms | confirm -> broadcast {:.0} ms | \
             broadcast -> announcement {} | broadcast -> chain row arrived {} | \
             status line says {}",
            confirmed.duration_since(clicked).as_secs_f64() * 1000.0,
            armed_at.duration_since(confirmed).as_secs_f64() * 1000.0,
            announced_at.map_or_else(
                || "never".to_owned(),
                |at| format!(
                    "{:.0} ms",
                    at.duration_since(armed_at).as_secs_f64() * 1000.0
                )
            ),
            if settled {
                format!(
                    "{:.0} ms",
                    Instant::now().duration_since(armed_at).as_secs_f64() * 1000.0
                )
            } else {
                "never".to_owned()
            },
            reported.map_or_else(|| "nothing".to_owned(), |ms| format!("{ms} ms")),
        );
        let since_armed = |at: Option<Instant>| {
            at.map_or_else(
                || "never".to_owned(),
                |at| {
                    format!(
                        "{:.0} ms",
                        at.duration_since(armed_at).as_secs_f64() * 1000.0
                    )
                },
            )
        };
        println!(
            "[round {round}] account state moved {} | row stopped spinning {} | \
             send form released {}",
            since_armed(account_lt_at),
            since_armed(stopped_spinning_at),
            since_armed(unblocked_at),
        );
        println!("[round {round}] ticks after confirm: {trace}");

        // Clear the settled row so the next round's search is unambiguous.
        c.state_mut().activity.clear();
        std::thread::sleep(Duration::from_secs(2));
    }

    c.shutdown();
    let _ = std::fs::remove_dir_all(&dir);
}
