use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cc_wallet_chain::{
    AccountInspection, AccountTx, AccountTxKind, AccountTxPage, AccountUpdate,
    CandidateBroadcastOutcome, ChainError, ChainFuture, ChainResult, ChainService,
    ChainTransaction, DestinationAccountStatus, FeeEstimate, LOCAL_SEND_FEE_CEILING_NANOS,
    PoolSnapshot, PreparedChainSend, SubscriptionEvent, TransactionPage,
    parse_transaction_for_test,
};
use cc_wallet_domain::{
    ActivityDirection, ActivityEvent, AddressBookEntry, AssetAmount, AssetId, AssetMovement,
    BlockerRow, CcAmount, DEFAULT_ENDPOINT, DEFAULT_SLIPPAGE_BPS, DeliveryEvidence, Digest32,
    EndpointAddressInputs, EndpointTransactionEvidence, EvidenceTag, LOCAL_SEND_FEE_HEADROOM_NANOS,
    ObservedNetworkTime, PrepareProvenance, PreparedRecord, RISK_WARNING_VERSION, RecordId,
    Reservation, ReservationKind, RiskGrant, RiskGrantConsumption, RiskNonce, SeedPhrase,
    SendAuthorization, SendRequest, SendTicket, StorageOp, StorageRecord, StorageSnapshot,
    TerminalOutcome, WalletInputs, WalletProfile, WalletSnapshot, blocker_set_digest,
    overlap_set_digest, reservation_set_digest,
};
use cc_wallet_vault::{KdfParams, Vault};

use super::{
    AppController, HistoryReconciliationScan, KeyAction, KeyMsg, PendingRiskConsumption,
    PendingRiskReview, SecuritySetting,
};
use crate::clipboard::MemoryClipboard;
use crate::command::{AppCommand, Password, SeedInput};
use crate::event::AppEvent;
use crate::state::{
    AppPhase, AppTab, AuthModal, AuthMode, AuthPurpose, Deadline, LiveStatus, PersistenceHealth,
    RecipientCheck,
};

const CHEAP: KdfParams = KdfParams {
    m_kib: 32,
    t: 2,
    p: 1,
};
const PW: &[u8] = b"a-test-password";
const TEST_SEED: &str = "one two three four five six seven eight nine ten eleven twelve";
const SECOND_TEST_SEED: &str = "alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu";
const SAMPLE_OUTGOING_TX_BOC: &str = "te6ccgECDgEAAlQAA7VwzzhGQlR3sl+wKYzKg5koqj2AnfeL7BBKJsobaROsRBAAAACK7GwwGgcwWFKMa8g66ETBeeRt4c79JAfyFUe1eNHxlXNeOZRQAAAAiuLiyBakn0sQADRwEpVoBQQBAg8MQYYatTzEQAMCAG/JiGRwTBZhFAAAAAAAAgAAAAAAAukK7RGaZSwH/agd9NxiT57Z4ZZD4TbYukvxsWBojuFWQJAVDACdQsXjE4gAAAAAAAAAACFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIACCcmlvgB7nHr8Wj5J+/J0ToF8Kci6qDR5xzygO8/XJyzjVll1zOCkik1erJGrKLt6HZUDMceiBI/DK6YN15z3sWsgCAeAJBgEB3wcCqUgAGecIyEqO9kv2BTGZUHMlFUewE77xfYIJRNlDbSJ1iIMABI0VniXh4eJeYVGVGR1iUWEWHRXR1RUVFVFRVRVRUVFCBhZhNgAAABFdjYYE1JPpYsAIDQAToAAAAAMgU6cRNAFFiAAZ5wjISo72S/YFMZlQcyUVR7ATvvF9gglE2UNtInWIggwKAYBPrqUvmbcaZSAV9NpJvQtZGL5oyDmsSfPGM+LZZZTTIsNYbjZPTk/kv/Rd7cdzaim7GE7CF/+pJHNQ2FjSUZYOCwEggACAAGpJ9O0AAAAVneWKAwwBVYACRorPEvDw8S8wqMqMjrEosIsOiujqioqKqKiqiqioqKAAAAAGQKdOImQNAAA=";

fn fresh_sample_transaction() -> ChainTransaction {
    let mut transaction = parse_transaction_for_test(SAMPLE_OUTGOING_TX_BOC).unwrap();
    transaction.now = u32::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    transaction
}

fn test_seed() -> Arc<SeedPhrase> {
    SeedPhrase::shared(TEST_SEED.to_owned())
}

fn seed_input(value: impl Into<String>) -> SeedInput {
    SeedInput::new(value.into())
}

fn generated_seed_phrase() -> String {
    crate::generate_seed_phrase()
        .expect("in-process RNG succeeds")
        .expose_secret()
        .to_owned()
}

fn amount(asset: AssetId, units: u128) -> AssetAmount {
    match asset {
        AssetId::Native => AssetAmount::native(units).unwrap(),
        AssetId::CurrencyCollection(id) => {
            AssetAmount::currency_collection(id, CcAmount::from_u128(units))
        }
    }
}

fn movement(asset: AssetId, units: u128) -> AssetMovement {
    AssetMovement {
        amount: amount(asset, units),
    }
}

fn digest(label: &str) -> Digest32 {
    let mut bytes = [0u8; 32];
    for (index, byte) in label.bytes().enumerate() {
        let slot = index % bytes.len();
        bytes[slot] = bytes[slot].wrapping_add(byte).wrapping_add(index as u8);
    }
    bytes[31] ^= label.len() as u8;
    Digest32::from_bytes(bytes)
}

fn optional_digest(label: &str) -> Option<Digest32> {
    (!label.is_empty()).then(|| digest(label))
}

fn native_request(destination: &str, units: u128) -> SendRequest {
    SendRequest::native(destination, units).unwrap()
}

fn send_authorization(generation: u64, nonce: u64) -> SendAuthorization {
    SendAuthorization::new(
        RecordId::from_bytes([generation as u8; 32]),
        cc_wallet_storage::DEFAULT_WALLET_NAME.to_owned(),
        SEND_DEST.to_owned(),
        WalletInputs {
            endpoint: "https://rpc.example/".to_owned(),
            network_id: 0,
            workchain: -1,
            seed: test_seed(),
            require_signature_id: false,
        },
        native_request(SEND_DEST, 1),
        true,
        generation,
        nonce,
    )
    .unwrap()
}

fn set_native_balance(wallet: &mut WalletSnapshot, units: u128) {
    wallet
        .replace_balances(units, wallet.extra_balance().clone())
        .unwrap();
}

fn timed_wallet(_address: &str) -> WalletSnapshot {
    WalletSnapshot::new_with_network_time(
        SEND_DEST,
        0,
        "Active",
        0,
        Default::default(),
        0,
        Some(
            ObservedNetworkTime::new(
                1_700_000_000,
                DEFAULT_ENDPOINT,
                "test-request",
                Instant::now(),
            )
            .unwrap(),
        ),
    )
    .unwrap()
}

fn wallet_with_native(address: &str, units: u128) -> WalletSnapshot {
    let mut wallet = timed_wallet(address);
    set_native_balance(&mut wallet, units);
    wallet
}

fn apply_owned_auto_load(
    controller: &mut AppController,
    generation: u64,
    snapshot: WalletSnapshot,
) {
    controller.wallet_load_seq = controller.wallet_load_seq.wrapping_add(1).max(1);
    let request_id = controller.wallet_load_seq;
    controller.load.wallet_auto_refresh_id = Some(request_id);
    controller.state_mut().auto_refreshing = true;
    controller.apply_event(AppEvent::WalletAutoLoaded {
        generation,
        request_id,
        snapshot,
    });
}

fn arm_manual_load(controller: &mut AppController) -> u64 {
    controller.wallet_load_seq = controller.wallet_load_seq.wrapping_add(1).max(1);
    let request_id = controller.wallet_load_seq;
    controller.load.wallet_load_id = Some(request_id);
    controller.state_mut().busy = true;
    request_id
}

fn apply_owned_load(controller: &mut AppController, generation: u64, snapshot: WalletSnapshot) {
    let request_id = arm_manual_load(controller);
    controller.apply_event(AppEvent::WalletLoaded {
        generation,
        request_id,
        snapshot,
    });
}

fn apply_owned_load_failed(controller: &mut AppController, generation: u64, error: String) {
    let request_id = arm_manual_load(controller);
    controller.apply_event(AppEvent::WalletLoadFailed {
        generation,
        request_id,
        error,
    });
}

fn temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "cc-wallet-ctl-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir(&dir).expect("test fixture creates its injected startup CWD");
    dir
}

fn cleanup(dir: &Path) {
    let _ = std::fs::remove_dir_all(dir);
}

fn controller(dir: &Path) -> AppController {
    AppController::at_dir(dir, CHEAP).unwrap()
}

fn unlocked(dir: &Path, profile: WalletProfile) -> AppController {
    let mut c = controller(dir);
    let vault = Vault::create_with(PW, CHEAP).unwrap();
    let writer = c.store.writer_for_new().unwrap();
    c.apply_key_msg(KeyMsg::Ok {
        history_corrupt: false,
        journal: cc_wallet_domain::JournalEnvelope::empty(),
        selected: None,
        writer: Some(writer),
        generation: c.key_generation(),
        history: Vec::new(),
        action: KeyAction::Create,
        vault,
        profile,
    });
    assert!(c.drain_save_task());
    c.save_profile();
    c
}

#[test]
fn rejected_create_passwords_run_both_zeroizing_drop_paths() {
    let dir = temp_dir("password-drop-error");
    let mut c = controller(&dir);
    let probe = Arc::new(AtomicUsize::new(0));

    c.create_password(
        Password::with_drop_probe("short".to_owned(), Arc::clone(&probe)),
        Password::with_drop_probe("different".to_owned(), Arc::clone(&probe)),
    );

    assert_eq!(probe.load(Ordering::SeqCst), 2);
    assert!(c.state().lock_error.contains("at least 8"));
    cleanup(&dir);
}

#[test]
fn an_incompatible_wallet_or_journal_refuses_the_unlock_not_a_read_only_viewer() {
    let dir = temp_dir("incompatible-refuse");
    let store = cc_wallet_storage::VaultStore::new(
        dir.to_path_buf(),
        cc_wallet_storage::DEFAULT_WALLET_NAME,
    );
    let vault = Vault::create_with(PW, CHEAP).unwrap();
    let good_profile = serde_json::to_vec(&WalletProfile::default()).unwrap();
    let good_journal = cc_wallet_domain::JournalEnvelope::empty().encode();
    let mut writer = store.writer_for_new().unwrap();

    let newer_journal =
        br#"{"schema_version":9999,"writer_version":1,"records":[],"risk_events":[]}"#;
    writer
        .save_sync(&vault, &good_profile, newer_journal, None)
        .unwrap();
    let opened = store.unlock(PW).unwrap();
    assert!(serde_json::from_slice::<WalletProfile>(&opened.wallet).is_ok());
    assert!(
        cc_wallet_domain::JournalEnvelope::decode(&opened.journal).is_err(),
        "a newer-schema journal is refused (worker emits Failed), never opened read-only"
    );

    let newer_profile = String::from_utf8(good_profile.clone())
        .unwrap()
        .replace("\"schema_version\":1", "\"schema_version\":9999");
    writer
        .save_sync(&vault, newer_profile.as_bytes(), &good_journal, None)
        .unwrap();
    let opened = store.unlock(PW).unwrap();
    assert!(
        serde_json::from_slice::<WalletProfile>(&opened.wallet).is_err(),
        "a newer-schema profile is refused, never opened read-only"
    );
    cleanup(&dir);
}

#[test]
fn every_incompatible_activity_refuses_the_unlock_through_the_worker_with_no_side_effects() {
    let missing_finality = br#"{"schema_version":1,"writer_version":1,"events":[
        {"direction":"In","lt":7,"time_unix":1,"tx_hash":"a","counterparty":"0:b",
         "movements":[],"fee_native":0,"success":true,"bounced":false,"exit_code":0,
         "ext_msg_hash":"","int_msg_hash":"","pending":false}]}"#
        .as_slice();
    let cases: [(&str, &[u8]); 4] = [
        ("legacy-bare-vec", br#"[{"lt":1,"tx_hash":"a"}]"#),
        (
            "older-schema",
            br#"{"schema_version":0,"writer_version":1,"events":[]}"#,
        ),
        (
            "newer-schema",
            br#"{"schema_version":9999,"writer_version":1,"events":[]}"#,
        ),
        ("missing-required-field", missing_finality),
    ];

    for (label, activity) in cases {
        let dir = temp_dir(&format!("incompat-activity-{label}"));
        let store = cc_wallet_storage::VaultStore::new(
            dir.to_path_buf(),
            cc_wallet_storage::DEFAULT_WALLET_NAME,
        );
        let vault = Vault::create_with(PW, CHEAP).unwrap();
        let profile = serde_json::to_vec(&WalletProfile::default()).unwrap();
        let journal = cc_wallet_domain::JournalEnvelope::empty().encode();
        store
            .writer_for_new()
            .unwrap()
            .save_sync(&vault, &profile, &journal, Some(activity))
            .unwrap();
        let bytes_before = std::fs::read(store.main_path()).unwrap();

        let fake = FakeChain::default();
        let mut c = controller(&dir);
        c.chain = Arc::new(fake.clone());
        c.handle_command(AppCommand::Unlock(Password::new(
            String::from_utf8(PW.to_vec()).unwrap(),
        )));
        c.pump_key();

        assert_ne!(
            c.state().phase,
            AppPhase::Unlocked,
            "[{label}] an incompatible Activity must be refused, not opened"
        );
        assert!(
            !c.state().lock_error.is_empty(),
            "[{label}] an actionable error is surfaced"
        );
        assert_eq!(
            std::fs::read(store.main_path()).unwrap(),
            bytes_before,
            "[{label}] the on-disk bytes are preserved unchanged"
        );
        assert_eq!(fake.prepare_calls(), 0, "[{label}] no signing/broadcast");
        assert_eq!(fake.transaction_calls(), 0, "[{label}] no network fetch");
        cleanup(&dir);
    }
}

#[test]
fn every_save_writes_a_decodable_mandatory_journal_and_activity_envelope() {
    let dir = temp_dir("journal-on-save");
    let mut c = unlocked(&dir, WalletProfile::default());
    const CC_MAX: &str =
        "452312848583266388373324160190187140051835877600158453279131187530910662655";
    c.state_mut().activity.push(ActivityEvent {
        direction: ActivityDirection::In,
        tx_hash: Some(digest("full-width-tx")),
        counterparty: "0:other".to_owned(),
        movements: vec![AssetMovement {
            amount: AssetAmount::currency_collection(
                u32::MAX,
                CcAmount::try_from_canonical_decimal(CC_MAX).unwrap(),
            ),
        }],
        fee_native: 1,
        int_msg_hash: Some(digest("full-width-int-msg")),
        finality_ms: Some(5),
        ..ActivityEvent::test_stub(7, 1)
    });
    c.save_history();
    c.flush_save_blocking();

    let store =
        cc_wallet_storage::VaultStore::new(dir.clone(), cc_wallet_storage::DEFAULT_WALLET_NAME);
    let opened = store.unlock(PW).unwrap();
    let journal = cc_wallet_domain::JournalEnvelope::decode(&opened.journal)
        .expect("the sealed journal decodes as a valid envelope");
    assert_eq!(
        journal,
        cc_wallet_domain::JournalEnvelope::empty(),
        "a wallet with no send records seals an empty (not missing) journal"
    );
    let cc_wallet_vault::ActivitySection::Present(bytes) = &opened.activity else {
        panic!("confirmed full-width history must be present after the save");
    };
    let activity = cc_wallet_domain::ActivityEnvelope::decode(bytes)
        .expect("the sealed activity is a versioned envelope, not a bare Vec");
    let restored = &activity.events()[0].movements[0].amount;
    assert_eq!(
        restored.asset_id(),
        AssetId::CurrencyCollection(u32::MAX),
        "the unsigned currency identity survives save/restart"
    );
    assert_eq!(
        restored.cc_units().unwrap().to_canonical_decimal(),
        CC_MAX,
        "all 248 amount bits survive app -> envelope -> vault -> unlock"
    );
    cleanup(&dir);
}

#[test]
fn a_profile_only_save_does_not_reencode_activity() {
    let dir = temp_dir("activity-cache-hit");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.state_mut()
        .activity
        .push(history_event(5, 100, AssetId::Native));
    c.save_history();
    assert!(c.flush_save_blocking());
    let after_history = c.activity_encode_count.get();
    assert!(
        after_history >= 1,
        "the confirmed row was encoded at least once"
    );

    c.save_profile();
    assert!(c.flush_save_blocking());
    assert_eq!(
        c.activity_encode_count.get(),
        after_history,
        "a profile-only save reuses the cached Activity encoding"
    );
}

#[test]
fn a_history_mutation_invalidates_the_activity_cache() {
    let dir = temp_dir("activity-cache-invalidate");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.state_mut()
        .activity
        .push(history_event(5, 100, AssetId::Native));
    c.save_history();
    assert!(c.flush_save_blocking());

    c.state_mut()
        .activity
        .push(history_event(9, 200, AssetId::Native));
    c.save_history();
    assert!(c.lock());

    let opened = c.store.unlock(PW).unwrap();
    let cc_wallet_vault::ActivitySection::Present(bytes) = &opened.activity else {
        panic!("the persisted history must be present after the mutation");
    };
    let activity = cc_wallet_domain::ActivityEnvelope::decode(bytes).unwrap();
    assert!(
        activity.events().iter().any(|event| event.lt == 9),
        "the newly confirmed event was durably persisted (cache was invalidated)"
    );
}

#[cfg(unix)]
#[test]
fn a_failed_final_save_is_surfaced_not_silently_dropped() {
    use std::os::unix::fs::PermissionsExt;
    let dir = temp_dir("save-fail-visible");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.flush_save_blocking();
    c.save_profile();

    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let writes_blocked = std::fs::write(dir.join(".probe"), b"x").is_err();
    c.flush_save_blocking();
    let surfaced = c.state().error.is_some();
    let _ = std::fs::remove_file(dir.join(".probe"));
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();

    if writes_blocked {
        assert!(
            surfaced,
            "a failed final save must surface an error, not be silently dropped"
        );
    }
    cleanup(&dir);
}

#[cfg(target_os = "linux")]
#[test]
fn shutdown_refuses_to_hide_the_window_when_instance_lock_cleanup_is_uncertain() {
    let dir = temp_dir("lock-release-fail-visible");
    let mut c = unlocked(&dir, WalletProfile::default());
    assert!(c.flush_save_blocking());
    c._instance_lock = Some(
        match cc_wallet_storage::acquire_single_instance_lock(&dir).unwrap() {
            cc_wallet_storage::LockOutcome::Acquired(lock) => lock,
            cc_wallet_storage::LockOutcome::AlreadyRunning => {
                panic!("fresh test directory unexpectedly locked")
            }
        },
    );
    let lock_path = dir.join(cc_wallet_storage::LOCK_FILE);
    let owner_record = std::fs::read(&lock_path).unwrap();
    std::fs::write(&lock_path, b"pid=1\nstart_ticks=1\n").unwrap();

    assert!(!c.shutdown(), "uncertain lock cleanup must refuse shutdown");
    assert!(
        c.state()
            .error
            .as_deref()
            .is_some_and(|error| error.contains("mandatory instance lock"))
    );
    assert!(matches!(
        cc_wallet_storage::acquire_single_instance_lock(&dir).unwrap(),
        cc_wallet_storage::LockOutcome::AlreadyRunning
    ));

    std::fs::write(&lock_path, owner_record).unwrap();
    assert!(c.shutdown());
    assert!(!lock_path.exists());
    cleanup(&dir);
}

#[test]
fn an_external_main_change_blocks_signing_but_lock_and_shutdown_fail_secure() {
    let dir = temp_dir("writer-poison-lifecycle");
    let mut c = unlocked(&dir, WalletProfile::default());
    assert!(c.flush_save_blocking());
    c.save_profile();
    std::fs::write(c.store.main_path(), b"externally replaced").unwrap();

    assert!(!c.flush_save_blocking());
    assert_eq!(
        c.state().persistence_health,
        crate::state::PersistenceHealth::Failed
    );
    assert!(c.state().persistence_error.is_some());
    assert!(!c.state().send_enabled());

    assert!(c.lock(), "lock must fail secure on a save failure");
    assert_eq!(c.state().phase, AppPhase::Locked);
    assert!(
        c.vault.is_none(),
        "the decrypted session is wiped, not retained"
    );
    assert!(
        c.state()
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("discarded"),
        "the lock screen reports the discarded save, got {:?}",
        c.state().error
    );

    assert!(c.shutdown(), "shutdown must complete after a save failure");

    drop(c);
    cleanup(&dir);
}

#[test]
fn lock_now_fails_secure_and_reports_data_loss_after_an_injected_save_failure() {
    let dir = temp_dir("lock-now-fail-secure");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.persistence_failed("injected save failure");
    assert_eq!(
        c.state().persistence_health,
        crate::state::PersistenceHealth::Failed
    );

    assert!(c.lock(), "LockNow locks despite the failed save");
    assert_eq!(c.state().phase, AppPhase::Locked);
    assert!(c.vault.is_none());
    assert!(
        c.state()
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("injected save failure"),
        "the discarded-save detail is carried to the lock screen"
    );
    cleanup(&dir);
}

#[test]
fn lock_with_healthy_persistence_still_flushes_the_pending_edit() {
    let dir = temp_dir("lock-healthy-flush");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.state_mut()
        .contacts
        .push(cc_wallet_domain::AddressBookEntry::new("Alice", "0:aaa"));
    c.save_profile();

    assert!(c.lock());
    assert_eq!(c.state().phase, AppPhase::Locked);

    let reopened = c.store.unlock(PW).unwrap();
    let profile = cc_wallet_domain::WalletProfile::decode(&reopened.wallet).unwrap();
    assert!(
        profile
            .address_book
            .iter()
            .any(|entry| entry.name == "Alice"),
        "a healthy lock still flushes the pending contact edit"
    );
    cleanup(&dir);
}

#[test]
fn a_debounced_save_checks_the_writer_out_and_back_in() {
    let dir = temp_dir("save-checkout");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.state_mut()
        .contacts
        .push(cc_wallet_domain::AddressBookEntry::new("Zoe", "0:abc"));
    c.save_profile();
    c.flush_save();

    assert!(c.save_task.is_some(), "a save is in flight");
    assert!(
        c.writer.is_none(),
        "the writer is checked out into the worker during the write"
    );

    assert!(c.drain_save_task());
    assert!(
        c.writer.is_some(),
        "the writer is checked back in after the write"
    );
    assert_eq!(c.state().persistence_health, PersistenceHealth::Ready);

    let reopened = c.store.unlock(PW).unwrap();
    let profile = cc_wallet_domain::WalletProfile::decode(&reopened.wallet).unwrap();
    assert!(
        profile.address_book.iter().any(|entry| entry.name == "Zoe"),
        "the off-thread debounced save durably persisted the contact"
    );
    cleanup(&dir);
}

#[test]
fn a_lock_during_an_in_flight_save_completes_the_write_first() {
    let dir = temp_dir("lock-inflight-save");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.state_mut()
        .contacts
        .push(cc_wallet_domain::AddressBookEntry::new("Bea", "0:bbb"));
    c.save_profile();
    c.flush_save();
    assert!(c.save_task.is_some(), "a save is in flight");
    assert!(c.writer.is_none(), "the writer is checked out");

    assert!(c.lock());
    assert_eq!(c.state().phase, AppPhase::Locked);

    let reopened = c.store.unlock(PW).unwrap();
    let profile = cc_wallet_domain::WalletProfile::decode(&reopened.wallet).unwrap();
    assert!(
        profile.address_book.iter().any(|entry| entry.name == "Bea"),
        "the in-flight write completed before lock; the contact is durable"
    );
    cleanup(&dir);
}

#[test]
fn two_dirty_intents_during_one_flight_coalesce_into_one_follow_up_save() {
    let dir = temp_dir("save-coalesce");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.save_profile();
    c.flush_save();
    assert!(c.save_task.is_some(), "the first save is in flight");

    c.state_mut()
        .contacts
        .push(cc_wallet_domain::AddressBookEntry::new("A", "0:a"));
    c.save_profile();
    c.state_mut()
        .contacts
        .push(cc_wallet_domain::AddressBookEntry::new("B", "0:b"));
    c.save_profile();
    c.flush_save();
    assert!(c.writer.is_none(), "still exactly one writer checked out");

    assert!(c.drain_save_task());
    assert!(c.dirty, "the coalesced follow-up is queued");
    assert!(
        c.save_task.is_none(),
        "no second concurrent writer was started"
    );

    c.flush_save();
    assert!(c.save_task.is_some());
    assert!(c.drain_save_task());
    let reopened = c.store.unlock(PW).unwrap();
    let profile = cc_wallet_domain::WalletProfile::decode(&reopened.wallet).unwrap();
    assert!(profile.address_book.iter().any(|entry| entry.name == "A"));
    assert!(profile.address_book.iter().any(|entry| entry.name == "B"));
    cleanup(&dir);
}

#[test]
fn a_started_save_blocks_send_until_its_correlated_receipt_is_consumed() {
    let dir = temp_dir("save-receipt-send-gate");
    let (mut c, _fake) = ready_to_send(&dir);
    c.save_profile();
    c.flush_save();
    assert!(c.save_task.is_some());
    assert_eq!(
        c.state().persistence_health,
        crate::state::PersistenceHealth::WritePending
    );
    assert!(
        !c.state().send_enabled(),
        "signing cannot race a started whole-container writer"
    );
    assert!(c.drain_save_task());
    assert_eq!(
        c.state().persistence_health,
        crate::state::PersistenceHealth::Ready
    );
    assert!(c.state().send_enabled());
    cleanup(&dir);
}

#[test]
fn a_latched_failure_during_an_in_flight_save_is_not_cleared_by_that_saves_success() {
    let dir = temp_dir("sticky-failed-latch");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.save_profile();
    c.flush_save();
    assert!(c.save_task.is_some(), "a save is in flight");
    assert!(
        c.writer.is_none(),
        "the writer is checked out for that save"
    );

    c.persistence_failed("injected evidence failure during an in-flight save");
    assert_eq!(c.state().persistence_health, PersistenceHealth::Failed);

    assert!(
        !c.drain_save_task(),
        "drain reports unhealthy while the Failed latch is set"
    );
    assert_eq!(
        c.state().persistence_health,
        PersistenceHealth::Failed,
        "a concurrent save success must not clear the fail-closed latch"
    );
    assert!(
        c.writer.as_ref().is_some_and(|writer| !writer.is_healthy()),
        "the returned writer is poisoned so it cannot resume signing or saving"
    );
    cleanup(&dir);
}

#[test]
fn authorized_send_refused_when_network_time_lost_during_auth() {
    let dir = temp_dir("send-refuse-network-time");
    let (mut c, _fake) = ready_to_send(&dir);
    assert!(c.state().send_enabled(), "the wallet starts sendable");

    let mut untimed = WalletSnapshot::new_with_network_time(
        SEND_DEST,
        0,
        "Active",
        0,
        Default::default(),
        0,
        None,
    )
    .unwrap();
    set_native_balance(&mut untimed, 5_000_000_000);
    c.state_mut().wallet = Some(untimed);

    let auth = send_authorization(c.session_generation, 1);
    c.send_authorized_transaction(auth);

    assert!(!c.state().sending, "the send is refused, not started");
    assert_eq!(
        c.state().error.as_deref(),
        Some(crate::state::SendBlockReason::NetworkTimeUnavailable.message()),
        "the choke point names the network-time block, not a chain error"
    );
    cleanup(&dir);
}

#[test]
fn a_corrupt_activity_is_quarantined_before_the_first_commit_omits_it() {
    let dir = temp_dir("s15-quarantine");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.state_mut()
        .activity
        .push(history_event(1, HISTORY_NOW, AssetId::Native));
    c.flush_save_blocking();

    let main = c.store.main_path();
    let mut bytes = std::fs::read(&main).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    std::fs::write(&main, &bytes).unwrap();
    let corrupt_container = std::fs::read(&main).unwrap();

    let opened = c.store.unlock(PW).unwrap();
    assert!(
        matches!(opened.activity, cc_wallet_vault::ActivitySection::Corrupt),
        "the damaged activity opens as Corrupt"
    );
    let counter = opened.selected.save_counter();
    c.session.activity_quarantine_pending = Some(opened.selected);
    c.writer = Some(opened.writer);
    c.state_mut().history_corrupt = true;
    c.state_mut().persistence_health = crate::state::PersistenceHealth::QuarantineRequired;
    c.state_mut().activity.clear();

    c.save_profile();
    c.flush_save_blocking();

    let orphan = main
        .parent()
        .unwrap()
        .join(format!("wallet.ccwallet.v1.{counter}.orphan"));
    assert!(orphan.exists(), "the corrupt container is quarantined");
    assert_eq!(
        std::fs::read(&orphan).unwrap(),
        corrupt_container,
        "the orphan is a byte copy of the selected corrupt container"
    );
    assert!(c.state().history_corrupt);
    assert!(c.session.activity_quarantine_pending.is_none());
    let reopened = c.store.unlock(PW).unwrap();
    assert!(
        matches!(reopened.activity, cc_wallet_vault::ActivitySection::Absent),
        "the resealed main omits the corrupt Activity (never synthesizes empty)"
    );

    c.save_profile();
    c.flush_save_blocking();
    let orphan_count = std::fs::read_dir(main.parent().unwrap())
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().ends_with(".orphan"))
        .count();
    assert_eq!(orphan_count, 1, "no second orphan is created");
    cleanup(&dir);
}

#[test]
fn fresh_data_dir_starts_in_onboarding() {
    let dir = temp_dir("onboarding");
    let c = controller(&dir);
    assert_eq!(c.state().phase, AppPhase::Onboarding);
    assert_eq!(c.data_dir, dir);
    cleanup(&dir);
}

#[test]
fn injected_test_root_must_exist_and_be_absolute_without_creation() {
    let relative = PathBuf::from("relative-wallet-root");
    assert!(AppController::at_dir(&relative, CHEAP).is_err());
    assert!(!relative.exists());

    let parent = temp_dir("missing-root-parent");
    let missing = parent.join("missing");
    let error = match AppController::at_dir(&missing, CHEAP) {
        Ok(_) => panic!("missing injected root was accepted"),
        Err(error) => error,
    };
    assert!(error.contains(&missing.display().to_string()));
    assert!(
        !missing.exists(),
        "constructor injection must not create a root"
    );
    cleanup(&parent);
}

#[cfg(unix)]
#[test]
fn injected_test_root_refuses_a_symlink_instead_of_escaping() {
    use std::os::unix::fs::symlink;

    let parent = temp_dir("symlink-root-parent");
    let target = temp_dir("symlink-root-target");
    let link = parent.join("root-link");
    symlink(&target, &link).unwrap();
    let error = match AppController::at_dir(&link, CHEAP) {
        Ok(_) => panic!("symlink injected root was accepted"),
        Err(error) => error,
    };
    assert!(error.contains(&link.display().to_string()));
    assert!(std::fs::read_dir(&target).unwrap().next().is_none());
    cleanup(&parent);
    cleanup(&target);
}

#[test]
fn startup_never_deletes_an_unrelated_plaintext_networks_file() {
    let dir = temp_dir("unrelated-networks-file");
    let unrelated = dir.join("networks.json");
    std::fs::write(&unrelated, b"unrelated user data").unwrap();
    let c = controller(&dir);
    assert_eq!(c.data_dir, dir);
    assert_eq!(std::fs::read(&unrelated).unwrap(), b"unrelated user data");
    drop(c);
    cleanup(&dir);
}

#[test]
fn create_completion_enters_unlocked_empty_wallet() {
    let dir = temp_dir("create");
    let mut c = controller(&dir);
    let vault = Vault::create_with(PW, CHEAP).unwrap();
    let writer = c.store.writer_for_new().unwrap();
    c.apply_key_msg(KeyMsg::Ok {
        history_corrupt: false,
        journal: cc_wallet_domain::JournalEnvelope::empty(),
        selected: None,
        writer: Some(writer),
        generation: c.key_generation(),
        history: Vec::new(),
        action: KeyAction::Create,
        vault,
        profile: WalletProfile::default(),
    });
    assert_eq!(c.state().phase, AppPhase::Unlocked);
    assert_eq!(c.state().selected_tab, AppTab::Settings);
    assert!(!c.state().seed_saved);
    cleanup(&dir);
}

#[test]
fn removing_an_unselected_endpoint_shifts_the_selection_without_a_restart() {
    let dir = temp_dir("endpoint-shift-down");
    let mut c = unlocked(&dir, WalletProfile::default());
    let start_len = c.state().endpoint_display_list().len();

    c.handle_command(AppCommand::AddEndpoint("https://a.test:8001".to_owned()));
    c.handle_command(AppCommand::AddEndpoint("https://b.test:8001".to_owned()));
    assert_eq!(c.state().endpoint_display_list().len(), start_len + 2);
    let b_idx = start_len + 1;

    c.handle_command(AppCommand::SelectEndpoint(b_idx));
    assert_eq!(c.state().selected_endpoint_index(), b_idx);
    assert_eq!(c.state().resolved_endpoint(), "https://b.test:8001/");
    let generation = c.subscription_generation;

    c.handle_command(AppCommand::RemoveEndpoint("https://a.test:8001".to_owned()));
    assert_eq!(c.state().endpoint_display_list().len(), start_len + 1);
    assert_eq!(c.state().selected_endpoint_index(), b_idx - 1);
    assert_eq!(c.state().resolved_endpoint(), "https://b.test:8001/");
    assert_eq!(
        c.subscription_generation, generation,
        "removing an unselected endpoint must not restart the subscription"
    );
    cleanup(&dir);
}

#[test]
fn monotonic_counters_survive_a_lock_teardown() {
    let dir = temp_dir("counters-survive-teardown");
    let (mut c, _fake) = ready_to_send(&dir);
    c.fetch_seq += 5;
    c.pending_seq += 3;
    c.wallet_load_seq += 7;
    c.fee_request_seq += 2;
    let (fetch_seq, pending_seq, wallet_load_seq, fee_request_seq) = (
        c.fetch_seq,
        c.pending_seq,
        c.wallet_load_seq,
        c.fee_request_seq,
    );

    c.handle_command(AppCommand::LockNow);

    assert_eq!(c.fetch_seq, fetch_seq, "fetch_seq must survive teardown");
    assert_eq!(
        c.pending_seq, pending_seq,
        "pending_seq must survive teardown"
    );
    assert_eq!(
        c.wallet_load_seq, wallet_load_seq,
        "wallet_load_seq must survive teardown"
    );
    assert_eq!(
        c.fee_request_seq, fee_request_seq,
        "fee_request_seq must survive teardown"
    );
    cleanup(&dir);
}

#[test]
fn lock_resets_the_load_runtime_wholesale() {
    let dir = temp_dir("lock-resets-load-runtime");
    let (mut c, _fake) = ready_to_send(&dir);
    c.load.fetch_in_flight = true;
    c.load.fetch_in_flight_id = Some(42);
    c.load.fetch_again = true;
    c.load.wallet_load_id = Some(9);

    c.handle_command(AppCommand::LockNow);

    assert!(
        !c.load.fetch_in_flight,
        "lock clears the fetch coalescing guard"
    );
    assert_eq!(c.load.fetch_in_flight_id, None);
    assert!(!c.load.fetch_again);
    assert_eq!(
        c.load.wallet_load_id, None,
        "lock drops the manual-load owner token"
    );
    cleanup(&dir);
}

#[test]
fn seed_switch_resets_the_session_runtime() {
    let dir = temp_dir("seed-switch-session-reset");
    let profile = WalletProfile {
        seed: test_seed(),
        ..WalletProfile::default()
    };
    let mut c = unlocked(&dir, profile);
    c.session.pending_sends.push((5, None));
    c.session.awaiting_send_lt = Some(5);
    c.session.history_synced_floor = Some(1_000);
    c.session.history_has_gap = false;

    c.handle_command(AppCommand::ImportSeed(seed_input(
        "twelve eleven ten nine eight seven six five four three two one",
    )));

    assert!(
        c.session.pending_sends.is_empty(),
        "a seed switch clears optimistic send rows"
    );
    assert_eq!(c.session.awaiting_send_lt, None);
    assert_eq!(c.session.history_synced_floor, None);
    assert!(
        c.session.history_has_gap,
        "a seed switch forces a full first history walk"
    );
    cleanup(&dir);
}

#[test]
fn command_freeze_classifiers_match_the_documented_denylists() {
    use AppCommand::*;
    let pw = || Password::new("p".to_owned());
    let cases: Vec<(&str, AppCommand, bool, bool)> = vec![
        ("Init", Init, false, false),
        ("SelectWallet", SelectWallet("w".to_owned()), false, false),
        ("NewWalletRequest", NewWalletRequest, false, false),
        (
            "DeleteWalletFromPicker",
            DeleteWalletFromPicker {
                name: "w".to_owned(),
                pw: pw(),
            },
            false,
            false,
        ),
        ("BackToPicker", BackToPicker, false, false),
        (
            "CreateWallet",
            CreateWallet {
                name: "n".to_owned(),
                network_id: 0,
                workchain: 0,
                pw: pw(),
                pw2: pw(),
            },
            false,
            false,
        ),
        ("Unlock", Unlock(pw()), false, false),
        ("LockNow", LockNow, false, false),
        ("SwitchWallet", SwitchWallet, false, false),
        (
            "SwitchToWallet",
            SwitchToWallet("w".to_owned()),
            false,
            false,
        ),
        ("DeleteWallet", DeleteWallet, true, false),
        ("SelectTab", SelectTab(AppTab::Wallet), false, false),
        ("GenerateSeed", GenerateSeed, true, true),
        (
            "OnboardImportSeed",
            OnboardImportSeed(seed_input("x")),
            false,
            false,
        ),
        (
            "SetSeedBackupConfirmed",
            SetSeedBackupConfirmed(true),
            false,
            false,
        ),
        ("SaveSeed", SaveSeed(seed_input("x")), true, true),
        ("ImportSeed", ImportSeed(seed_input("x")), true, true),
        ("UseSeed", UseSeed, true, true),
        ("DiscardSeed", DiscardSeed, true, false),
        ("RevealSeed", RevealSeed, true, false),
        ("HideSeed", HideSeed, false, false),
        ("CopySeed", CopySeed(seed_input("x")), false, false),
        ("CopyText", CopyText("x".to_owned()), false, false),
        ("RefreshWallet", RefreshWallet, false, false),
        (
            "SaveContact",
            SaveContact {
                index: None,
                name: "n".to_owned(),
                address: "a".to_owned(),
                tag: "t".to_owned(),
            },
            false,
            false,
        ),
        ("DeleteContact", DeleteContact(0), false, false),
        (
            "ReorderContacts",
            ReorderContacts { from: 0, to: 1 },
            false,
            false,
        ),
        ("QuickSend", QuickSend("a".to_owned()), true, false),
        (
            "SetAssetVisibility",
            SetAssetVisibility {
                cc_id: 1,
                visible: true,
            },
            true,
            false,
        ),
        ("SelectAsset", SelectAsset(AssetId::Native), true, false),
        (
            "SetSendDestination",
            SetSendDestination("d".to_owned()),
            true,
            false,
        ),
        ("SetSendAmount", SetSendAmount("1".to_owned()), true, false),
        ("SetMaxAmount", SetMaxAmount, true, false),
        ("SetAllowUnbounced", SetAllowUnbounced(true), true, false),
        ("RequestSend", RequestSend, false, false),
        (
            "SetSwapFromToken",
            SetSwapFromToken(AssetId::Native),
            true,
            false,
        ),
        (
            "SetSwapToToken",
            SetSwapToToken(AssetId::CurrencyCollection(1)),
            true,
            false,
        ),
        ("SetSwapAmount", SetSwapAmount("1".to_owned()), true, false),
        ("SetMaxSwapAmount", SetMaxSwapAmount, true, false),
        ("SetSwapSlippage", SetSwapSlippage(50), true, false),
        ("StepSwapSlippage", StepSwapSlippage(true), true, false),
        (
            "EditSwapSlippage",
            EditSwapSlippage("0.5".to_owned()),
            true,
            false,
        ),
        ("FlipSwap", FlipSwap, true, false),
        ("RequestSwap", RequestSwap, false, false),
        ("DismissSwapReceipt", DismissSwapReceipt, true, false),
        ("RequestRiskOverride", RequestRiskOverride, true, false),
        (
            "SetRiskOverlap",
            SetRiskOverlap {
                index: 0,
                selected: true,
            },
            false,
            false,
        ),
        (
            "ConfirmRiskOverride",
            ConfirmRiskOverride {
                typed_confirmation: "c".to_owned(),
                acknowledge_both_may_debit: true,
                acknowledge_duplicate: true,
            },
            false,
            false,
        ),
        ("CancelRiskOverride", CancelRiskOverride, false, false),
        ("ChangePasswordRequest", ChangePasswordRequest, true, false),
        (
            "AuthSubmit",
            AuthSubmit {
                pw: pw(),
                pw2: pw(),
                remember: false,
            },
            false,
            false,
        ),
        ("AuthCancel", AuthCancel, false, false),
        ("SetAutosign", SetAutosign(5), false, false),
        ("SetScreenLock", SetScreenLock(5), false, false),
        (
            "InspectAccount",
            InspectAccount("0:1".to_owned()),
            false,
            false,
        ),
        (
            "OpenInExplorer",
            OpenInExplorer {
                address: "0:1".to_owned(),
                transaction_hash: "hash".to_owned(),
            },
            false,
            false,
        ),
        (
            "TraceTransaction",
            TraceTransaction("hash".to_owned()),
            false,
            false,
        ),
        ("CloseTrace", CloseTrace, false, false),
        ("AddEndpoint", AddEndpoint("e".to_owned()), true, false),
        ("SelectEndpoint", SelectEndpoint(0), true, true),
        ("RemoveEndpoint", RemoveEndpoint("e".to_owned()), true, true),
        ("TestEndpoint", TestEndpoint("e".to_owned()), false, false),
        ("ClearError", ClearError, false, false),
    ];

    assert_eq!(
        cases.len(),
        63,
        "every AppCommand variant is classified exactly once"
    );
    assert_eq!(
        cases.iter().filter(|(_, _, f, _)| *f).count(),
        28,
        "the authorization-snapshot freeze list has exactly 28 commands"
    );
    assert_eq!(
        cases.iter().filter(|(_, _, _, i)| *i).count(),
        6,
        "the identity freeze list has exactly 6 commands"
    );
    for (label, command, frozen, identity) in &cases {
        assert_eq!(
            command.frozen_while_authorization_pending(),
            *frozen,
            "authorization-freeze classification for {label}"
        );
        assert_eq!(
            command.changes_wallet_identity_or_endpoint(),
            *identity,
            "identity-freeze classification for {label}"
        );
    }
}

#[test]
fn remove_endpoint_without_registry_default_keeps_selection() {
    let dir = temp_dir("endpoint-no-default-shift");
    let mut c = unlocked(&dir, WalletProfile::default());

    c.state_mut().network_id = 424_242;
    c.state_mut().custom_endpoints = vec![
        "https://a.test:8001/".to_owned(),
        "https://b.test:8001/".to_owned(),
        "https://c.test:8001/".to_owned(),
    ];
    c.state_mut().selected_endpoint = 2;
    c.refresh_network_view();
    assert!(
        c.state().default_endpoint.is_none(),
        "precondition: this network id is not in the registry"
    );
    assert_eq!(c.state().resolved_endpoint(), "https://c.test:8001/");
    let generation = c.subscription_generation;

    c.handle_command(AppCommand::RemoveEndpoint(
        "https://b.test:8001/".to_owned(),
    ));
    assert_eq!(c.state().resolved_endpoint(), "https://c.test:8001/");
    assert_eq!(c.state().selected_endpoint_index(), 1);
    assert_eq!(
        c.subscription_generation, generation,
        "removing an unselected endpoint must not restart the subscription"
    );
    cleanup(&dir);
}

#[test]
fn endpoint_registry_add_select_remove_and_test_verdicts() {
    let dir = temp_dir("endpoints");
    let mut c = unlocked(&dir, WalletProfile::default());
    assert!(!c.state().network_name.is_empty());
    let start_len = c.state().endpoint_display_list().len();
    assert!(start_len >= 1);

    let built_in_without_trailing_slash = c.state().endpoint_display_list()[0]
        .trim_end_matches('/')
        .to_owned();
    c.handle_command(AppCommand::AddEndpoint(built_in_without_trailing_slash));
    assert_eq!(
        c.state().endpoint_display_list().len(),
        start_len,
        "a noncanonical spelling of the built-in endpoint deduplicates after canonicalization"
    );

    c.handle_command(AppCommand::AddEndpoint(
        "https://example.test:8001".to_owned(),
    ));
    assert_eq!(c.state().endpoint_display_list().len(), start_len + 1);
    assert!(
        !dir.join("networks.json").exists(),
        "no plaintext networks.json is ever written"
    );

    assert!(!crate::endpoint_is_valid("http://has spaces"));
    c.handle_command(AppCommand::AddEndpoint("http://has spaces".to_owned()));
    assert_eq!(c.state().endpoint_display_list().len(), start_len + 1);
    assert!(!c.state().endpoint_test_result.is_empty());

    let new_idx = c.state().endpoint_display_list().len() - 1;
    c.handle_command(AppCommand::SelectEndpoint(new_idx));
    assert_eq!(c.state().selected_endpoint_index(), new_idx);
    assert_eq!(c.state().resolved_endpoint(), "https://example.test:8001/");

    c.handle_command(AppCommand::RemoveEndpoint(
        "https://example.test:8001".to_owned(),
    ));
    assert_eq!(c.state().endpoint_display_list().len(), start_len);
    assert_eq!(
        c.state().selected_endpoint_index(),
        0,
        "removing the selected endpoint falls back to the built-in default"
    );
    c.handle_command(AppCommand::RemoveEndpoint("http://nope.test".to_owned()));
    assert_eq!(c.state().endpoint_display_list().len(), start_len);

    let net = c.state().network_id;
    c.endpoint_test_url = Some("u".to_owned());
    c.apply_endpoint_tested(net, "u", true, Some(net), true, None);
    assert!(c.state().endpoint_test_result.contains("OK"));
    c.endpoint_test_url = Some("u".to_owned());
    c.apply_endpoint_tested(net, "u", true, Some(net + 1), false, None);
    assert!(c.state().endpoint_test_result.contains("Wrong network"));
    c.endpoint_test_url = Some("u".to_owned());
    c.apply_endpoint_tested(net, "u", false, None, false, Some("boom".to_owned()));
    assert!(c.state().endpoint_test_result.contains("Unreachable"));
    c.endpoint_test_url = Some("u".to_owned());
    c.apply_endpoint_tested(net, "other-url", true, Some(net), true, None);
    assert!(
        c.state().endpoint_test_result.contains("Unreachable"),
        "a superseded probe's verdict for a different URL is ignored"
    );
    c.state_mut().endpoint_test_result.clear();
    c.endpoint_test_url = Some("u".to_owned());
    c.apply_endpoint_tested(net + 999, "u", true, Some(net), true, None);
    assert!(c.state().endpoint_test_result.is_empty());
    cleanup(&dir);
}

#[test]
fn custom_endpoints_persist_encrypted_and_write_no_plaintext_file() {
    let dir = temp_dir("endpoints-encrypted");
    let mut c = unlocked(&dir, WalletProfile::default());
    let input = "https://my.private.rpc:443".to_owned();
    let custom = "https://my.private.rpc/".to_owned();
    c.handle_command(AppCommand::AddEndpoint(input));
    let idx = c.state().endpoint_display_list().len() - 1;
    c.handle_command(AppCommand::SelectEndpoint(idx));
    assert_eq!(c.state().resolved_endpoint(), custom);
    c.flush_save_blocking();

    assert!(
        !dir.join("networks.json").exists(),
        "custom endpoints must not leak to a plaintext file"
    );

    let store =
        cc_wallet_storage::VaultStore::new(dir.clone(), cc_wallet_storage::DEFAULT_WALLET_NAME);
    let opened = store.unlock(PW).unwrap();
    let reloaded: WalletProfile = serde_json::from_slice(&opened.wallet).unwrap();
    assert_eq!(reloaded.custom_endpoints, vec![custom]);
    assert_eq!(reloaded.selected_endpoint, idx);
    cleanup(&dir);
}

fn mem_clipboard(c: &mut AppController) -> MemoryClipboard {
    let mem = MemoryClipboard::default();
    c.clipboard = Box::new(mem.clone());
    mem
}

fn clipboard_of(mem: &MemoryClipboard) -> String {
    mem.board.borrow().clipboard.clone()
}

#[test]
fn copying_the_seed_places_it_and_arms_a_deadline() {
    let dir = temp_dir("clipcopy");
    let mut c = unlocked(&dir, WalletProfile::default());
    let mem = mem_clipboard(&mut c);

    c.copy_seed_to_clipboard(seed_input(TEST_SEED));

    assert_eq!(clipboard_of(&mem), TEST_SEED);
    assert!(c.clipboard_deadline.is_some(), "the wipe must be armed");
    assert!(c.state().clipboard_notice.is_empty());
    cleanup(&dir);
}

#[test]
fn the_copy_deadline_wipes_the_phrase_from_tick() {
    let dir = temp_dir("clipttl");
    let mut c = unlocked(&dir, WalletProfile::default());
    let mem = mem_clipboard(&mut c);
    c.copy_seed_to_clipboard(seed_input(TEST_SEED));

    c.clipboard_deadline = Some(crate::state::Deadline::after(std::time::Duration::ZERO));
    c.tick();

    assert_eq!(clipboard_of(&mem), "", "an expired copy must be wiped");
    assert!(c.clipboard_deadline.is_none());
    cleanup(&dir);
}

#[test]
fn the_copy_deadline_wipes_during_onboarding_too() {
    let dir = temp_dir("clipttlonboard");
    let mut c = controller(&dir);
    let mem = mem_clipboard(&mut c);
    c.state_mut().phase = AppPhase::Onboarding;
    c.copy_seed_to_clipboard(seed_input(TEST_SEED));

    c.clipboard_deadline = Some(crate::state::Deadline::after(std::time::Duration::ZERO));
    c.tick();

    assert_eq!(clipboard_of(&mem), "");
    cleanup(&dir);
}

#[test]
fn the_wipe_never_clobbers_an_unrelated_later_copy() {
    let dir = temp_dir("clipguard");
    let mut c = unlocked(&dir, WalletProfile::default());
    let mem = mem_clipboard(&mut c);
    c.copy_seed_to_clipboard(seed_input(TEST_SEED));

    mem.board.borrow_mut().clipboard = "an address the user copied".to_owned();
    c.lock();

    assert_eq!(clipboard_of(&mem), "an address the user copied");
    cleanup(&dir);
}

#[test]
fn copying_non_secret_text_writes_without_arming_a_wipe() {
    let dir = temp_dir("copytext");
    let mut c = unlocked(&dir, WalletProfile::default());
    let mem = mem_clipboard(&mut c);

    c.copy_text("0:deadbeef");

    assert_eq!(clipboard_of(&mem), "0:deadbeef");
    assert!(
        c.clipboard_deadline.is_none(),
        "a public address copy must not arm a timed wipe"
    );
    assert!(c.clipboard_secret.is_none());
    cleanup(&dir);
}

#[test]
fn pasting_a_seed_during_onboarding_arms_the_wipe() {
    let dir = temp_dir("clippaste");
    let mut c = controller(&dir);
    let mem = mem_clipboard(&mut c);
    c.state_mut().phase = AppPhase::Onboarding;

    let phrase = generated_seed_phrase();
    mem.board.borrow_mut().clipboard = phrase.clone();
    c.handle_command(AppCommand::OnboardImportSeed(seed_input(phrase.clone())));

    assert!(
        c.clipboard_deadline.is_some(),
        "a pasted phrase still on the clipboard must arm the wipe"
    );
    assert_eq!(
        c.clipboard_secret.as_ref().map(|s| s.as_str()),
        Some(phrase.as_str())
    );

    c.clipboard_deadline = Some(crate::state::Deadline::after(std::time::Duration::ZERO));
    c.tick();
    assert_eq!(
        clipboard_of(&mem),
        "",
        "the pasted phrase must be wiped once the TTL expires"
    );
    cleanup(&dir);
}

#[test]
fn whitespace_equivalent_seed_uses_the_same_arm_and_clear_predicate() {
    let dir = temp_dir("clipequivalent");
    let mut c = controller(&dir);
    let mem = mem_clipboard(&mut c);
    c.state_mut().phase = AppPhase::Onboarding;
    let phrase = generated_seed_phrase();
    let clipboard_form = phrase.split(' ').collect::<Vec<_>>().join(" \n  ");
    mem.board.borrow_mut().clipboard = clipboard_form;

    c.handle_command(AppCommand::OnboardImportSeed(seed_input(phrase)));
    assert!(c.clipboard_secret.is_some(), "equivalent paste must arm");

    c.clipboard_deadline = Some(crate::state::Deadline::after(std::time::Duration::ZERO));
    c.tick();
    assert_eq!(clipboard_of(&mem), "", "the same predicate must clear it");
    cleanup(&dir);
}

#[test]
fn settings_seed_save_registers_and_clears_a_pasted_phrase() {
    let dir = temp_dir("clipsettingspaste");
    let mut c = unlocked(&dir, WalletProfile::default());
    let mem = mem_clipboard(&mut c);
    let phrase = generated_seed_phrase();
    mem.board.borrow_mut().clipboard = phrase.clone();

    c.handle_command(AppCommand::SaveSeed(seed_input(phrase)));

    assert_eq!(
        clipboard_of(&mem),
        "",
        "Settings save hides the seed and must clear the registered paste"
    );
    assert!(c.clipboard_secret.is_none());
    cleanup(&dir);
}

#[test]
fn a_typed_seed_not_on_the_clipboard_never_touches_it() {
    let dir = temp_dir("cliptyped");
    let mut c = controller(&dir);
    let mem = mem_clipboard(&mut c);
    c.state_mut().phase = AppPhase::Onboarding;
    mem.board.borrow_mut().clipboard = "https://example.com".to_owned();

    let phrase = generated_seed_phrase();
    c.handle_command(AppCommand::OnboardImportSeed(seed_input(phrase)));

    assert!(
        c.clipboard_deadline.is_none(),
        "a hand-typed phrase must not register a clipboard wipe"
    );
    assert!(c.clipboard_secret.is_none());
    assert_eq!(
        clipboard_of(&mem),
        "https://example.com",
        "an unrelated clipboard must be left untouched"
    );
    cleanup(&dir);
}

#[test]
fn abandoning_onboarding_wipes_a_copied_phrase() {
    let dir = temp_dir("clipabandon");
    let mut c = controller(&dir);
    let mem = mem_clipboard(&mut c);
    c.state_mut().phase = AppPhase::Onboarding;
    c.state_mut().seed = test_seed();
    c.copy_seed_to_clipboard(seed_input(TEST_SEED));
    assert_eq!(clipboard_of(&mem), TEST_SEED);

    c.handle_command(AppCommand::NewWalletRequest);

    assert_eq!(
        clipboard_of(&mem),
        "",
        "a phrase copied during abandoned onboarding must not survive"
    );
    assert!(c.clipboard_secret.is_none());
    cleanup(&dir);
}

#[test]
fn regenerating_wipes_the_previously_copied_phrase() {
    let dir = temp_dir("clipregen");
    let mut c = unlocked(&dir, WalletProfile::default());
    let mem = mem_clipboard(&mut c);
    c.copy_seed_to_clipboard(seed_input(TEST_SEED));

    c.handle_command(AppCommand::GenerateSeed);

    assert_eq!(clipboard_of(&mem), "");
    cleanup(&dir);
}

#[test]
fn shutdown_wipes_a_copied_phrase() {
    let dir = temp_dir("clipexit");
    let mut c = unlocked(&dir, WalletProfile::default());
    let mem = mem_clipboard(&mut c);
    c.copy_seed_to_clipboard(seed_input(TEST_SEED));

    c.shutdown();

    assert_eq!(clipboard_of(&mem), "");
    cleanup(&dir);
}

#[test]
fn shutdown_waits_for_a_failed_clipboard_wipe_retry() {
    let dir = temp_dir("clipexitretry");
    let mut c = unlocked(&dir, WalletProfile::default());
    let mem = mem_clipboard(&mut c);
    c.copy_seed_to_clipboard(seed_input(TEST_SEED));
    mem.board.borrow_mut().fail_set = true;

    assert!(
        !c.shutdown(),
        "a recoverable wipe failure keeps the UI open"
    );
    assert!(c.clipboard_secret.is_some());
    assert!(c.clipboard_deadline.is_some());
    assert!(c.state().clipboard_notice.contains("retrying"));

    mem.board.borrow_mut().fail_set = false;
    c.clipboard_deadline = Some(crate::state::Deadline::after(Duration::ZERO));
    c.tick();
    assert_eq!(clipboard_of(&mem), "");
    assert!(c.clipboard_secret.is_none());
    assert!(c.shutdown(), "closing resumes after the retry succeeds");
    cleanup(&dir);
}

#[test]
fn the_primary_selection_is_swept_only_when_it_holds_seed_words() {
    let dir = temp_dir("clipprimary");
    let mut c = unlocked(&dir, WalletProfile::default());
    let mem = mem_clipboard(&mut c);

    c.copy_seed_to_clipboard(seed_input(TEST_SEED));
    mem.board.borrow_mut().primary = "seven eight".to_owned();
    c.lock();
    assert_eq!(mem.board.borrow().primary, "");

    c.handle_command(AppCommand::Unlock(Password::new(
        String::from_utf8(PW.to_vec()).unwrap(),
    )));
    c.pump_key();
    assert_eq!(c.state().phase, AppPhase::Unlocked);
    c.clipboard = Box::new(mem.clone());
    c.copy_seed_to_clipboard(seed_input(TEST_SEED));
    mem.board.borrow_mut().primary = "some prose the user selected".to_owned();
    c.lock();
    assert_eq!(mem.board.borrow().primary, "some prose the user selected");
    cleanup(&dir);
}

#[test]
fn a_failed_wipe_is_reported_not_swallowed() {
    let dir = temp_dir("clipfail");
    let mut c = unlocked(&dir, WalletProfile::default());
    let mem = mem_clipboard(&mut c);
    c.copy_seed_to_clipboard(seed_input(TEST_SEED));

    mem.board.borrow_mut().fail_set = true;
    c.hide_seed();

    assert!(
        !c.state().clipboard_notice.is_empty(),
        "a failed wipe must surface to the user"
    );
    cleanup(&dir);
}

#[test]
fn a_failed_wipe_keeps_the_phrase_and_re_arms_a_retry() {
    let dir = temp_dir("clipretry");
    let mut c = unlocked(&dir, WalletProfile::default());
    let mem = mem_clipboard(&mut c);
    c.copy_seed_to_clipboard(seed_input(TEST_SEED));

    mem.board.borrow_mut().fail_set = true;
    c.hide_seed();

    assert!(
        c.clipboard_secret.is_some(),
        "the phrase must be retained so a retry can still recognise it"
    );
    assert!(c.clipboard_deadline.is_some(), "a retry must be armed");

    mem.board.borrow_mut().fail_set = false;
    c.clipboard_deadline = Some(crate::state::Deadline::after(std::time::Duration::ZERO));
    c.tick();

    assert_eq!(clipboard_of(&mem), "", "the retry must clear the phrase");
    assert!(c.clipboard_secret.is_none());
    cleanup(&dir);
}

#[test]
fn a_primary_read_error_retains_the_secret_and_retries_symmetrically() {
    let dir = temp_dir("clipprimaryreadretry");
    let mut c = unlocked(&dir, WalletProfile::default());
    let mem = mem_clipboard(&mut c);
    c.copy_seed_to_clipboard(seed_input(TEST_SEED));
    mem.board.borrow_mut().fail_get_selection = Some(crate::clipboard::Selection::Primary);

    c.hide_seed();

    assert!(c.clipboard_secret.is_some());
    assert!(c.clipboard_deadline.is_some());
    assert!(c.state().clipboard_notice.contains("retrying"));

    mem.board.borrow_mut().fail_get_selection = None;
    c.clipboard_deadline = Some(crate::state::Deadline::after(std::time::Duration::ZERO));
    c.tick();
    assert_eq!(clipboard_of(&mem), "");
    assert!(c.clipboard_secret.is_none());
    assert!(c.state().clipboard_notice.is_empty());
    cleanup(&dir);
}

#[test]
fn a_primary_write_error_retries_after_clipboard_was_already_cleared() {
    let dir = temp_dir("clipprimarywriteretry");
    let mut c = unlocked(&dir, WalletProfile::default());
    let mem = mem_clipboard(&mut c);
    c.copy_seed_to_clipboard(seed_input(TEST_SEED));
    mem.board.borrow_mut().primary = "seven eight".to_owned();
    mem.board.borrow_mut().fail_set_selection = Some(crate::clipboard::Selection::Primary);

    c.hide_seed();

    assert_eq!(clipboard_of(&mem), "", "Clipboard selection cleared");
    assert_eq!(mem.board.borrow().primary, "seven eight");
    assert!(c.clipboard_secret.is_some());
    assert!(c.clipboard_deadline.is_some());

    mem.board.borrow_mut().fail_set_selection = None;
    c.clipboard_deadline = Some(crate::state::Deadline::after(std::time::Duration::ZERO));
    c.tick();
    assert_eq!(mem.board.borrow().primary, "");
    assert!(c.clipboard_secret.is_none());
    assert!(c.state().clipboard_notice.is_empty());
    cleanup(&dir);
}

#[test]
fn a_second_copy_retains_both_secrets_when_the_prior_primary_wipe_failed() {
    let dir = temp_dir("cliptwosecrets");
    let mut c = unlocked(&dir, WalletProfile::default());
    let mem = mem_clipboard(&mut c);
    c.copy_seed_to_clipboard(seed_input(TEST_SEED));
    mem.board.borrow_mut().primary = "seven eight".to_owned();
    mem.board.borrow_mut().fail_set_selection = Some(crate::clipboard::Selection::Primary);

    c.copy_seed_to_clipboard(seed_input(SECOND_TEST_SEED));

    assert_eq!(clipboard_of(&mem), SECOND_TEST_SEED);
    assert_eq!(mem.board.borrow().primary, "seven eight");
    assert!(c.clipboard_secret.is_some());
    assert!(c.state().clipboard_notice.contains("every tracked phrase"));

    mem.board.borrow_mut().fail_set_selection = None;
    c.clipboard_deadline = Some(crate::state::Deadline::after(Duration::ZERO));
    c.tick();
    assert_eq!(clipboard_of(&mem), "");
    assert_eq!(mem.board.borrow().primary, "");
    assert!(c.clipboard_secret.is_none());
    cleanup(&dir);
}

#[test]
fn words_from_different_tracked_phrases_never_form_a_false_clipboard_match() {
    let dir = temp_dir("clipcrossphrase");
    let mut c = unlocked(&dir, WalletProfile::default());
    let mem = mem_clipboard(&mut c);
    c.copy_seed_to_clipboard(seed_input(TEST_SEED));
    mem.board.borrow_mut().primary = "one".to_owned();
    mem.board.borrow_mut().fail_set_selection = Some(crate::clipboard::Selection::Primary);
    c.copy_seed_to_clipboard(seed_input(SECOND_TEST_SEED));

    mem.board.borrow_mut().fail_set_selection = None;
    mem.board.borrow_mut().clipboard = "one alpha".to_owned();
    mem.board.borrow_mut().primary.clear();
    c.hide_seed();

    assert_eq!(clipboard_of(&mem), "one alpha");
    assert!(c.clipboard_secret.is_none());
    cleanup(&dir);
}

#[test]
fn a_failed_second_copy_never_discards_the_prior_wipe_tracker() {
    let dir = temp_dir("clipsecondfailure");
    let mut c = unlocked(&dir, WalletProfile::default());
    let mem = mem_clipboard(&mut c);
    c.copy_seed_to_clipboard(seed_input(TEST_SEED));
    mem.board.borrow_mut().fail_set = true;

    c.copy_seed_to_clipboard(seed_input(SECOND_TEST_SEED));

    assert_eq!(clipboard_of(&mem), TEST_SEED);
    assert!(c.clipboard_secret.is_some());
    assert!(c.state().clipboard_notice.contains("prior recovery phrase"));

    mem.board.borrow_mut().fail_set = false;
    c.clipboard_deadline = Some(crate::state::Deadline::after(Duration::ZERO));
    c.tick();
    assert_eq!(clipboard_of(&mem), "");
    assert!(c.clipboard_secret.is_none());
    cleanup(&dir);
}

#[test]
fn failed_wipes_keep_retrying_and_recover_when_the_clipboard_returns() {
    let dir = temp_dir("clipretryrecover");
    let mut c = unlocked(&dir, WalletProfile::default());
    let mem = mem_clipboard(&mut c);
    c.copy_seed_to_clipboard(seed_input(TEST_SEED));
    mem.board.borrow_mut().fail_set = true;

    for _ in 0..10 {
        assert!(
            c.clipboard_deadline.is_some(),
            "the automatic wipe must keep retrying while the phrase is exposed"
        );
        c.clipboard_deadline = Some(crate::state::Deadline::after(std::time::Duration::ZERO));
        c.tick();
    }

    assert!(
        c.clipboard_deadline.is_some(),
        "an unresponsive clipboard must not permanently stop the automatic wipe"
    );
    assert!(
        c.clipboard_secret.is_some(),
        "the matcher remains available to verify the clear"
    );
    assert!(!c.state().clipboard_notice.is_empty());
    assert!(
        !c.shutdown(),
        "exit must still refuse while the phrase may be on the clipboard"
    );

    mem.board.borrow_mut().fail_set = false;
    c.clipboard_deadline = Some(crate::state::Deadline::after(std::time::Duration::ZERO));
    c.tick();

    assert_eq!(
        clipboard_of(&mem),
        "",
        "the recovered wipe clears the selection"
    );
    assert!(
        c.clipboard_secret.is_none(),
        "the matcher is dropped after a clean wipe"
    );
    assert!(c.clipboard_deadline.is_none(), "no further retry is armed");
    assert!(c.state().clipboard_notice.is_empty());
    cleanup(&dir);
}

#[test]
fn a_failed_wipe_notice_survives_the_lock_state_reconstruction() {
    let dir = temp_dir("clipnoticelock");
    let mut c = unlocked(&dir, WalletProfile::default());
    let mem = mem_clipboard(&mut c);
    c.copy_seed_to_clipboard(seed_input(TEST_SEED));

    mem.board.borrow_mut().fail_set = true;
    c.lock();

    assert_eq!(c.state().phase, AppPhase::Locked);
    assert!(
        !c.state().clipboard_notice.is_empty(),
        "the lock screen must still warn that the phrase is on the clipboard"
    );
    cleanup(&dir);
}

#[test]
fn a_failed_copy_is_reported_and_arms_nothing() {
    let dir = temp_dir("clipnocopy");
    let mut c = unlocked(&dir, WalletProfile::default());
    let mem = mem_clipboard(&mut c);
    mem.board.borrow_mut().fail_set = true;

    c.copy_seed_to_clipboard(seed_input(TEST_SEED));

    assert!(!c.state().clipboard_notice.is_empty());
    assert!(c.clipboard_deadline.is_none());
    assert!(c.clipboard_secret.is_none());
    cleanup(&dir);
}

#[test]
fn copying_does_not_hide_the_revealed_seed_or_wipe_its_own_copy() {
    let dir = temp_dir("clipreveal");
    let mut c = unlocked(&dir, WalletProfile::default());
    let mem = mem_clipboard(&mut c);
    c.state_mut().seed = test_seed();
    c.show_seed_for_one_minute();

    c.handle_command(AppCommand::CopySeed(seed_input(TEST_SEED)));

    assert!(c.state().show_seed, "copying must not close the seed view");
    assert_eq!(clipboard_of(&mem), TEST_SEED);
    cleanup(&dir);
}

#[test]
fn hiding_the_seed_wipes_the_clipboard() {
    let dir = temp_dir("cliphide");
    let mut c = unlocked(&dir, WalletProfile::default());
    let mem = mem_clipboard(&mut c);
    c.state_mut().seed = test_seed();
    c.show_seed_for_one_minute();
    c.handle_command(AppCommand::CopySeed(seed_input(TEST_SEED)));

    c.handle_command(AppCommand::HideSeed);

    assert_eq!(clipboard_of(&mem), "");
    cleanup(&dir);
}

#[test]
fn a_wallet_load_superseded_by_a_switch_is_dropped() {
    let dir = temp_dir("staleload");
    let mut c = unlocked(&dir, WalletProfile::default());
    let load_gen = c.subscription_generation;
    apply_owned_load(&mut c, load_gen, wallet_with_native("0:me", 111));
    assert_eq!(c.state().wallet.as_ref().unwrap().native_balance(), 111);
    let stale = c.subscription_generation.wrapping_sub(1);
    apply_owned_load(&mut c, stale, wallet_with_native("0:other", 999));
    assert_eq!(
        c.state().wallet.as_ref().unwrap().native_balance(),
        111,
        "a superseded (stale-generation) wallet load must be dropped"
    );
    cleanup(&dir);
}

#[test]
fn stale_manual_load_completion_does_not_clear_busy_of_newer_load() {
    let dir = temp_dir("stale-manual-busy");
    let mut c = unlocked(&dir, WalletProfile::default());
    let old_gen = c.subscription_generation;
    let id1 = arm_manual_load(&mut c);
    let id2 = arm_manual_load(&mut c);
    assert_ne!(id1, id2);
    assert!(c.state().busy);
    c.apply_event(AppEvent::WalletLoaded {
        generation: old_gen,
        request_id: id1,
        snapshot: wallet_with_native("0:stale", 999),
    });
    assert!(
        c.state().busy,
        "a superseded manual completion must not clear the newer load's busy"
    );
    assert_ne!(
        c.state().wallet.as_ref().map(|w| w.native_balance()),
        Some(999),
        "the stale snapshot is not installed"
    );
    let new_gen = c.subscription_generation;
    c.apply_event(AppEvent::WalletLoaded {
        generation: new_gen,
        request_id: id2,
        snapshot: wallet_with_native("0:me", 111),
    });
    assert!(!c.state().busy);
    assert_eq!(c.state().wallet.as_ref().unwrap().native_balance(), 111);
    cleanup(&dir);
}

#[test]
fn load_failed_owned_by_a_stale_request_is_ignored() {
    let dir = temp_dir("stale-failed-ignored");
    let mut c = unlocked(&dir, WalletProfile::default());
    let current = arm_manual_load(&mut c);
    let load_gen = c.subscription_generation;
    c.apply_event(AppEvent::WalletLoadFailed {
        generation: load_gen,
        request_id: current.wrapping_add(1000),
        error: "a stale endpoint error".to_owned(),
    });
    assert!(c.state().busy, "a non-owning failure must not clear busy");
    assert!(
        c.state().snapshot_refresh_error.is_none(),
        "a non-owning failure must not set the send-guard error"
    );
    cleanup(&dir);
}

#[test]
fn manual_and_auto_loads_apply_identical_snapshot_state() {
    let snapshot = || wallet_with_native("0:me", 4242);

    let dir_m = temp_dir("apply-manual");
    let mut cm = unlocked(&dir_m, WalletProfile::default());
    cm.state_mut().selected_tab = AppTab::Settings;
    let gen_m = cm.subscription_generation;
    apply_owned_load(&mut cm, gen_m, snapshot());

    let dir_a = temp_dir("apply-auto");
    let mut ca = unlocked(&dir_a, WalletProfile::default());
    ca.state_mut().selected_tab = AppTab::Settings;
    let gen_a = ca.subscription_generation;
    apply_owned_auto_load(&mut ca, gen_a, snapshot());

    assert_eq!(
        cm.state().wallet.as_ref().unwrap().native_balance(),
        ca.state().wallet.as_ref().unwrap().native_balance()
    );
    assert_eq!(
        cm.state().derived_wallet_address,
        ca.state().derived_wallet_address
    );
    assert_eq!(cm.state().status, ca.state().status);
    assert_eq!(
        cm.state().snapshot_refresh_error,
        ca.state().snapshot_refresh_error
    );
    assert_eq!(cm.state().selected_tab, AppTab::Wallet);
    assert_eq!(ca.state().selected_tab, AppTab::Settings);
    cleanup(&dir_m);
    cleanup(&dir_a);
}

#[test]
fn auto_load_inputs_error_still_surfaces_refresh_error() {
    let dir = temp_dir("auto-inputs-error");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.state_mut().wallet = Some(wallet_with_native("0:me", 5_000_000_000));
    c.state_mut().send_form.destination =
        "0:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_owned();
    c.state_mut().send_form.amount = "1.0".to_owned();
    assert!(c.state().send_enabled());
    c.state_mut().custom_endpoints = vec![" ".to_owned()];
    c.state_mut().selected_endpoint = 99;

    let load_gen = c.subscription_generation;
    c.auto_refresh_wallet(load_gen);

    assert!(
        c.state().snapshot_refresh_error.is_some(),
        "an auto-load inputs error must surface, not be silently swallowed"
    );
    assert!(
        !c.state().send_enabled(),
        "the unresolved snapshot keeps sending blocked"
    );
    cleanup(&dir);
}

#[test]
fn a_persisted_wallet_shows_the_picker_then_the_unlock_screen() {
    let dir = temp_dir("relaunch");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.handle_command(AppCommand::ImportSeed(seed_input(TEST_SEED)));
    let name = c.state().active_wallet.clone();
    drop(c);

    let mut c2 = controller(&dir);
    assert_eq!(c2.state().phase, AppPhase::Selecting);
    assert_eq!(c2.state().wallet_names, vec![name.clone()]);

    c2.handle_command(AppCommand::SelectWallet(name));
    assert_eq!(c2.state().phase, AppPhase::Locked);
    cleanup(&dir);
}

#[test]
fn wrong_password_surfaces_a_lock_error() {
    let dir = temp_dir("wrongpw");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.lock();
    assert_eq!(c.state().phase, AppPhase::Locked);
    c.apply_key_msg(KeyMsg::WrongPassword {
        generation: c.key_generation(),
        action: KeyAction::Unlock,
    });
    assert!(!c.state().key_busy);
    assert!(c.state().lock_error.contains("Incorrect"));
    cleanup(&dir);
}

#[test]
fn lock_wipes_the_session_key_and_decrypted_secrets() {
    let dir = temp_dir("lockwipe");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.state_mut().seed = SeedPhrase::shared("super secret seed phrase".to_owned());
    c.state_mut().wallet = Some(timed_wallet("0:me"));
    c.state_mut()
        .contacts
        .push(AddressBookEntry::new("Bob", "0:bob"));

    c.lock();

    assert_eq!(c.state().phase, AppPhase::Locked);
    assert!(c.state().seed.is_empty());
    assert!(c.state().wallet.is_none());
    assert!(c.state().contacts.is_empty());
    assert!(!c.state().show_seed);
    cleanup(&dir);
}

#[test]
fn commands_are_ignored_while_locked() {
    let dir = temp_dir("lockedcmds");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.lock();
    c.handle_command(AppCommand::SaveContact {
        index: None,
        name: "Mallory".to_owned(),
        address: "0:evil".to_owned(),
        tag: String::new(),
    });
    assert!(c.state().contacts.is_empty());
    assert_eq!(c.state().phase, AppPhase::Locked);
    cleanup(&dir);
}

#[test]
fn change_password_always_reverifies_the_current_password_first() {
    let dir = temp_dir("changepw-reauth");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.state_mut().extend_autosign();
    assert!(c.state().within_autosign());

    c.handle_command(AppCommand::ChangePasswordRequest);
    assert!(c.state().auth.open);
    assert_eq!(c.state().auth.mode, AuthMode::Enter);
    assert_eq!(c.state().auth.purpose, AuthPurpose::ChangePassword);

    c.apply_key_msg(KeyMsg::WrongPassword {
        generation: c.key_generation(),
        action: KeyAction::VerifyForChangePassword,
    });
    assert!(c.state().auth.open);
    assert_eq!(c.state().auth.mode, AuthMode::Enter);
    assert!(!c.state().auth.error.is_empty());

    let vault = Vault::create_with(PW, CHEAP).unwrap();
    c.apply_key_msg(KeyMsg::Ok {
        history_corrupt: false,
        journal: cc_wallet_domain::JournalEnvelope::empty(),
        selected: None,
        writer: None,
        generation: c.key_generation(),
        history: Vec::new(),
        action: KeyAction::VerifyForChangePassword,
        vault,
        profile: WalletProfile::default(),
    });
    assert!(c.state().auth.open);
    assert_eq!(c.state().auth.mode, AuthMode::Create);
    cleanup(&dir);
}

#[test]
fn revealing_the_seed_requires_the_password_even_when_unlocked() {
    let dir = temp_dir("reveal-reauth");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.state_mut().seed = test_seed();
    c.state_mut().seed_saved = true;

    c.handle_command(AppCommand::RevealSeed);
    assert!(c.state().auth.open);
    assert_eq!(c.state().auth.purpose, AuthPurpose::RevealSeed);
    assert!(!c.state().show_seed);

    let vault = Vault::create_with(PW, CHEAP).unwrap();
    c.apply_key_msg(KeyMsg::Ok {
        history_corrupt: false,
        journal: cc_wallet_domain::JournalEnvelope::empty(),
        selected: None,
        writer: None,
        generation: c.key_generation(),
        history: Vec::new(),
        action: KeyAction::RevealSeed,
        vault,
        profile: WalletProfile::default(),
    });
    assert!(c.state().show_seed);
    assert!(!c.state().auth.open);
    cleanup(&dir);
}

#[test]
fn a_reauth_verification_runs_the_action_via_the_in_memory_verify_path() {
    let dir = temp_dir("m3-verified-reveal");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.state_mut().seed = test_seed();
    c.state_mut().seed_saved = true;

    c.handle_command(AppCommand::RevealSeed);
    assert!(c.state().auth.open);
    assert!(!c.state().show_seed);

    c.apply_key_msg(KeyMsg::Verified {
        generation: c.key_generation(),
        action: KeyAction::RevealSeed,
    });
    assert!(c.state().show_seed);
    assert!(!c.state().auth.open);
    cleanup(&dir);
}

#[test]
fn a_late_max_refinement_does_not_rewrite_the_amount_frozen_for_signing() {
    let dir = temp_dir("m5-frozen-amount");
    let mut c = unlocked(&dir, WalletProfile::default());
    let mut wallet = timed_wallet("0:me");
    set_native_balance(&mut wallet, 10_000_000_000);
    c.state_mut().wallet = Some(wallet);
    c.state_mut().send_form.amount = "5.0".to_owned();

    c.fee_request_seq = 7;
    c.pending_max_seq = Some(7);
    c.pending_max_balance = Some(10_000_000_000);
    c.state_mut().sending = true;

    c.apply_event(AppEvent::MaxFeeEstimated {
        generation: c.subscription_generation,
        seq: 7,
        estimate: cc_wallet_chain::FeeEstimate {
            fee_nanos: 7_000_000,
            deploy: false,
        },
    });

    assert_eq!(
        c.state().send_form.amount,
        "5.0",
        "a late max refinement must not overwrite the amount frozen for signing"
    );
    assert!(
        c.pending_max_seq.is_none(),
        "the pending-max bookkeeping is still cleared"
    );
}

#[test]
fn reauth_submit_drains_an_inflight_save_before_unlocking() {
    let dir = temp_dir("reauth-drain");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.state_mut().seed = test_seed();
    c.state_mut().seed_saved = true;
    c.save_profile();
    c.flush_save();
    assert!(c.save_task.is_some(), "a save is in flight");

    c.handle_command(AppCommand::RevealSeed);
    c.handle_command(AppCommand::AuthSubmit {
        pw: Password::new("a-test-password".to_owned()),
        pw2: Password::new(String::new()),
        remember: false,
    });

    assert!(
        c.save_task.is_none(),
        "the in-flight save was drained before the unlock"
    );
    assert!(c.state().key_busy, "the re-auth unlock is now in progress");
    cleanup(&dir);
}

#[test]
fn deleting_the_wallet_requires_the_password_then_returns_to_onboarding() {
    let dir = temp_dir("delete-reauth");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.state_mut().seed = test_seed();
    c.state_mut().seed_saved = true;

    c.handle_command(AppCommand::DeleteWallet);
    assert!(c.state().auth.open);
    assert_eq!(c.state().auth.purpose, AuthPurpose::DeleteWallet);
    assert_eq!(c.state().seed.expose_secret(), TEST_SEED);
    assert_eq!(c.state().phase, AppPhase::Unlocked);
    c.state_mut().lock_error = "This wallet uses an unsupported older format".to_owned();

    let vault = Vault::create_with(PW, CHEAP).unwrap();
    c.apply_key_msg(KeyMsg::Ok {
        history_corrupt: false,
        journal: cc_wallet_domain::JournalEnvelope::empty(),
        selected: None,
        writer: None,
        generation: c.key_generation(),
        history: Vec::new(),
        action: KeyAction::DeleteWallet,
        vault,
        profile: WalletProfile::default(),
    });
    assert!(c.state().seed.is_empty());
    assert_eq!(c.state().phase, AppPhase::Onboarding);
    assert!(c.state().wallet_names.is_empty());
    assert!(
        c.state().lock_error.is_empty(),
        "a prior unlock warning must not linger on the onboarding page after delete"
    );
    cleanup(&dir);
}

#[test]
fn sanitize_wallet_name_preserves_case_spaces_and_unicode() {
    use super::sanitize_wallet_name;
    assert_eq!(sanitize_wallet_name("My Wallet"), "My Wallet");
    assert_eq!(sanitize_wallet_name("  Trip fund!! "), "Trip fund!!");
    assert_eq!(sanitize_wallet_name("a__b--c"), "a__b--c");
    assert_eq!(sanitize_wallet_name("MY   WALLET"), "MY WALLET");
    assert_eq!(sanitize_wallet_name("Мой Кошелёк"), "Мой Кошелёк");
    assert_eq!(sanitize_wallet_name("a/b:c*?"), "abc");
    assert_eq!(sanitize_wallet_name("***"), "");
    assert_eq!(sanitize_wallet_name("   "), "");
}

#[test]
fn wallet_storage_id_is_lowercase_hyphenated_and_deterministic() {
    use super::wallet_storage_id;

    let cases = [
        ("My TON Wallet", "my-ton-wallet"),
        ("  MY\t\nWallet  ", "my-wallet"),
        ("Мой Кошелёк", "мой-кошелёк"),
        ("Trip__fund!!", "trip-fund"),
        ("--a___b---c!!", "a-b-c"),
        ("My 💰 Wallet", "my-wallet"),
        ("!!!", ""),
        ("💰", ""),
    ];

    for (display_name, expected) in cases {
        assert_eq!(
            wallet_storage_id(display_name),
            expected,
            "unexpected storage id for {display_name:?}"
        );
    }
}

#[test]
fn named_wallet_round_trip_keeps_its_display_name_and_uses_the_slug_as_identity() {
    const DISPLAY_NAME: &str = "My TON Wallet";
    const STORAGE_ID: &str = "my-ton-wallet";

    let dir = temp_dir("display-name-round-trip");
    let mut created = controller(&dir);
    created.handle_command(AppCommand::GenerateSeed);
    assert!(!created.state().seed.is_empty());
    created.handle_command(AppCommand::SetSeedBackupConfirmed(true));
    created.handle_command(AppCommand::CreateWallet {
        name: DISPLAY_NAME.to_owned(),
        network_id: 0,
        workchain: -1,
        pw: Password::new(String::from_utf8(PW.to_vec()).unwrap()),
        pw2: Password::new(String::from_utf8(PW.to_vec()).unwrap()),
    });
    created.pump_key();
    assert!(created.drain_save_task());

    assert_eq!(created.state().phase, AppPhase::Unlocked);
    assert_eq!(created.state().active_wallet, DISPLAY_NAME);
    assert_eq!(created.store.name(), STORAGE_ID);
    assert!(dir.join(format!("{STORAGE_ID}.ccwallet")).is_file());
    assert!(
        !dir.join(format!("{DISPLAY_NAME}.ccwallet")).exists(),
        "the user-facing label must never leak back into the canonical filename"
    );
    drop(created);

    let fake = FakeChain::default();
    let mut reopened = controller(&dir);
    reopened.chain = Arc::new(fake);
    assert_eq!(reopened.state().phase, AppPhase::Selecting);
    assert_eq!(reopened.state().wallet_names, vec![DISPLAY_NAME]);

    reopened.handle_command(AppCommand::SelectWallet(DISPLAY_NAME.to_owned()));
    assert_eq!(reopened.state().phase, AppPhase::Locked);
    assert_eq!(reopened.state().active_wallet, DISPLAY_NAME);
    assert_eq!(reopened.store.name(), STORAGE_ID);

    reopened.handle_command(AppCommand::Unlock(Password::new(
        String::from_utf8(PW.to_vec()).unwrap(),
    )));
    reopened.pump_key();
    reopened.pump_events();
    assert_eq!(reopened.state().phase, AppPhase::Unlocked);
    assert_eq!(reopened.state().active_wallet, DISPLAY_NAME);
    assert_eq!(reopened.store.name(), STORAGE_ID);

    let mut wallet = timed_wallet("0:me");
    set_native_balance(&mut wallet, 5_000_000_000);
    reopened.state_mut().wallet = Some(wallet);
    reopened.state_mut().send_form.destination = SEND_DEST.to_owned();
    reopened.state_mut().send_form.amount = "1.0".to_owned();
    assert!(reopened.state().send_enabled());
    reopened.handle_command(AppCommand::RequestSend);
    assert_eq!(
        reopened
            .pending_authorization
            .as_ref()
            .expect("send confirmation freezes a Journal-bound ticket")
            .ticket()
            .sender_wallet_id(),
        STORAGE_ID,
        "durable Journal identity must use the stable filename slug, not the display label"
    );

    cleanup(&dir);
}

#[test]
fn colliding_display_variants_cannot_overwrite_the_same_slug_file() {
    let dir = temp_dir("display-name-collision");
    let password = || Password::new(String::from_utf8(PW.to_vec()).unwrap());

    let mut first = controller(&dir);
    first.handle_command(AppCommand::GenerateSeed);
    first.handle_command(AppCommand::SetSeedBackupConfirmed(true));
    first.handle_command(AppCommand::CreateWallet {
        name: "My TON Wallet".to_owned(),
        network_id: 0,
        workchain: -1,
        pw: password(),
        pw2: password(),
    });
    first.pump_key();
    assert!(first.drain_save_task());
    let path = dir.join("my-ton-wallet.ccwallet");
    let original = std::fs::read(&path).unwrap();
    drop(first);

    let mut second = controller(&dir);
    second.handle_command(AppCommand::NewWalletRequest);
    second.handle_command(AppCommand::GenerateSeed);
    second.handle_command(AppCommand::SetSeedBackupConfirmed(true));
    second.handle_command(AppCommand::CreateWallet {
        name: "my__ton--wallet!!".to_owned(),
        network_id: 0,
        workchain: -1,
        pw: password(),
        pw2: password(),
    });

    assert!(!second.state().key_busy);
    assert!(second.state().lock_error.contains("my-ton-wallet.ccwallet"));
    assert_eq!(std::fs::read(path).unwrap(), original);
    assert_eq!(
        cc_wallet_storage::list_wallets(&dir).unwrap(),
        vec!["my-ton-wallet"]
    );
    cleanup(&dir);
}

#[test]
fn reserved_wallet_names_are_flagged() {
    use super::is_reserved_wallet_name;
    assert!(is_reserved_wallet_name("history"));
    assert!(is_reserved_wallet_name("HISTORY"));
    assert!(is_reserved_wallet_name("trip.history"));
    assert!(is_reserved_wallet_name("x.ccwallet"));
    assert!(is_reserved_wallet_name("x.ccwallet.foo"));
    assert!(is_reserved_wallet_name("MY.CCWALLET"));
    assert!(is_reserved_wallet_name("nul"));
    assert!(is_reserved_wallet_name("CON"));
    assert!(is_reserved_wallet_name("Nul.ccwallet"));
    assert!(is_reserved_wallet_name("com1"));
    assert!(is_reserved_wallet_name("LPT9"));
    assert!(!is_reserved_wallet_name("com0"));
    assert!(!is_reserved_wallet_name("com10"));
    assert!(!is_reserved_wallet_name("console"));
    assert!(!is_reserved_wallet_name("My Wallet"));
    assert!(
        !is_reserved_wallet_name("ccwallet"),
        "the bare word (no dot) is fine"
    );
    assert!(!is_reserved_wallet_name("Мой Кошелёк"));
}

#[test]
fn surface_error_routes_by_phase() {
    let dir = temp_dir("surface-error-locked");
    let mut c = controller(&dir);
    assert_ne!(c.state().phase, AppPhase::Unlocked);
    c.surface_error("pre-unlock message".to_owned());
    assert_eq!(c.state().lock_error, "pre-unlock message");
    cleanup(&dir);

    let dir2 = temp_dir("surface-error-unlocked");
    let mut c2 = unlocked(&dir2, WalletProfile::default());
    assert_eq!(c2.state().phase, AppPhase::Unlocked);
    c2.surface_error("unlocked message".to_owned());
    assert_eq!(c2.state().error.as_deref(), Some("unlocked message"));
    cleanup(&dir2);
}

#[test]
fn creating_a_wallet_requires_a_nonempty_name() {
    let dir = temp_dir("name-required");
    let mut c = controller(&dir);
    c.handle_command(AppCommand::CreateWallet {
        name: "   ".to_owned(),
        network_id: 0,
        workchain: -1,
        pw: Password::new("hunter2hunter2".to_owned()),
        pw2: Password::new("hunter2hunter2".to_owned()),
    });
    assert!(!c.state().lock_error.is_empty());
    assert_eq!(c.state().phase, AppPhase::Onboarding);
    assert!(!c.state().key_busy);
    cleanup(&dir);
}

#[test]
fn switch_wallet_wipes_keys_and_returns_to_the_picker() {
    let dir = temp_dir("switch");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.handle_command(AppCommand::ImportSeed(seed_input(TEST_SEED)));
    let name = c.state().active_wallet.clone();

    c.handle_command(AppCommand::SwitchWallet);
    assert_eq!(c.state().phase, AppPhase::Selecting);
    assert!(c.state().wallet_names.contains(&name));
    assert!(c.state().seed.is_empty());
    cleanup(&dir);
}

#[test]
fn deleting_the_last_wallet_from_the_picker_returns_to_onboarding() {
    let dir = temp_dir("picker-delete");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.handle_command(AppCommand::ImportSeed(seed_input(TEST_SEED)));
    let name = c.state().active_wallet.clone();
    c.handle_command(AppCommand::SwitchWallet);
    assert_eq!(c.state().phase, AppPhase::Selecting);
    assert!(c.state().wallet_names.contains(&name));

    c.handle_command(AppCommand::DeleteWalletFromPicker {
        name: name.clone(),
        pw: Password::new(String::from_utf8(PW.to_vec()).unwrap()),
    });
    c.pump_key();
    assert!(!c.state().wallet_names.contains(&name));
    assert!(c.state().wallet_names.is_empty());
    assert_eq!(c.state().phase, AppPhase::Onboarding);
    cleanup(&dir);
}

#[test]
fn picker_delete_requires_the_target_wallets_password() {
    let dir = temp_dir("picker-delete-wrong-pw");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.handle_command(AppCommand::ImportSeed(seed_input(TEST_SEED)));
    let name = c.state().active_wallet.clone();
    c.handle_command(AppCommand::SwitchWallet);
    assert_eq!(c.state().phase, AppPhase::Selecting);

    c.handle_command(AppCommand::DeleteWalletFromPicker {
        name: name.clone(),
        pw: Password::new("not-the-password".to_owned()),
    });
    c.pump_key();

    assert_eq!(c.state().lock_error, "Incorrect password");
    assert!(c.state().wallet_names.contains(&name));
    assert_eq!(c.state().phase, AppPhase::Selecting);
    assert!(
        cc_wallet_storage::VaultStore::new(dir.clone(), cc_wallet_storage::DEFAULT_WALLET_NAME)
            .exists()
            .unwrap(),
        "a wrong password must not destroy the encrypted seed file"
    );
    cleanup(&dir);
}

#[test]
fn picker_delete_with_the_correct_password_destroys_the_file() {
    let dir = temp_dir("picker-delete-right-pw");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.handle_command(AppCommand::ImportSeed(seed_input(TEST_SEED)));
    let name = c.state().active_wallet.clone();
    c.handle_command(AppCommand::SwitchWallet);
    assert_eq!(c.state().phase, AppPhase::Selecting);
    assert!(
        cc_wallet_storage::VaultStore::new(dir.clone(), cc_wallet_storage::DEFAULT_WALLET_NAME)
            .exists()
            .unwrap()
    );

    c.handle_command(AppCommand::DeleteWalletFromPicker {
        name: name.clone(),
        pw: Password::new(String::from_utf8(PW.to_vec()).unwrap()),
    });
    c.pump_key();

    assert!(!c.state().wallet_names.contains(&name));
    assert!(
        !cc_wallet_storage::VaultStore::new(dir.clone(), cc_wallet_storage::DEFAULT_WALLET_NAME)
            .exists()
            .unwrap(),
        "the correct password destroys the encrypted seed file"
    );
    cleanup(&dir);
}

#[test]
fn change_password_completion_keeps_the_session_open() {
    let dir = temp_dir("changepw");
    let profile = WalletProfile {
        seed: test_seed(),
        ..WalletProfile::default()
    };
    let mut c = unlocked(&dir, profile);
    let new_vault = Vault::create_with(b"brand-new-password", CHEAP).unwrap();
    c.apply_key_msg(KeyMsg::Ok {
        history_corrupt: false,
        journal: cc_wallet_domain::JournalEnvelope::empty(),
        selected: None,
        writer: None,
        generation: c.key_generation(),
        history: Vec::new(),
        action: KeyAction::ChangePassword,
        vault: new_vault,
        profile: WalletProfile::default(),
    });
    assert_eq!(c.state().phase, AppPhase::Unlocked);
    assert!(!c.state().auth.open);
    assert!(c.state().status.contains("changed"));
    cleanup(&dir);
}

#[test]
fn change_password_persists_the_new_keyslot_before_reporting_success() {
    let dir = temp_dir("changepw-durable");
    let profile = WalletProfile {
        seed: test_seed(),
        ..WalletProfile::default()
    };
    let mut c = unlocked(&dir, profile);
    let new_vault = Vault::create_with(b"brand-new-password", CHEAP).unwrap();
    c.apply_key_msg(KeyMsg::Ok {
        history_corrupt: false,
        journal: cc_wallet_domain::JournalEnvelope::empty(),
        selected: None,
        writer: None,
        generation: c.key_generation(),
        history: Vec::new(),
        action: KeyAction::ChangePassword,
        vault: new_vault,
        profile: WalletProfile::default(),
    });

    assert!(c.state().status.contains("changed"));
    assert!(
        c.save_task.is_none(),
        "the rekey commit is synchronous, not an async flush"
    );
    assert!(
        c.store.unlock(b"brand-new-password").is_ok(),
        "the rekeyed container is durable the moment success is reported"
    );
    match c.store.unlock(PW) {
        Err(error) => assert!(
            error.is_wrong_password(),
            "the old password no longer opens the main container"
        ),
        Ok(_) => panic!("the old password must not open the rekeyed container"),
    }
    cleanup(&dir);
}

#[test]
fn send_requires_reauth_outside_the_autosign_window() {
    let dir = temp_dir("sendreauth");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.state_mut().seed = test_seed();
    let mut wallet = timed_wallet("0:me");
    set_native_balance(&mut wallet, 2_000_000_000);
    c.state_mut().wallet = Some(wallet);
    c.state_mut().send_form.destination =
        "0:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_owned();
    c.state_mut().send_form.amount = "1.0".to_owned();
    assert!(c.state().send_enabled());

    c.handle_command(AppCommand::RequestSend);
    assert!(c.state().auth.open);
    assert_eq!(c.state().auth.mode, AuthMode::Enter);

    c.handle_command(AppCommand::AuthCancel);
    c.state_mut().extend_autosign();
    c.handle_command(AppCommand::RequestSend);
    assert_eq!(c.state().auth.mode, AuthMode::Confirm);
    cleanup(&dir);
}

#[test]
fn tick_downgrades_an_open_send_confirm_modal_when_autosign_expires() {
    let dir = temp_dir("autosign-expiry");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.state_mut().auth = AuthModal {
        open: true,
        mode: AuthMode::Confirm,
        purpose: AuthPurpose::Send,
        send_options_editable: true,
        error: String::new(),
    };
    c.state_mut().autosign_until = Some(Deadline::after(Duration::ZERO));

    c.tick();

    assert_eq!(
        c.state().auth.mode,
        AuthMode::Enter,
        "an expired window forces the password back on"
    );
    assert!(
        c.state().auth.open,
        "the modal stays open, not silently signed"
    );
    assert!(!c.state().auth.error.is_empty(), "the user is told why");
    assert!(
        c.state().autosign_until.is_none(),
        "the lapsed window is cleared"
    );
    cleanup(&dir);
}

#[test]
fn tick_hides_the_revealed_seed_when_its_deadline_expires() {
    let dir = temp_dir("seed-reveal-expiry");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.state_mut().seed = test_seed();
    c.state_mut().seed_editing = true;
    c.state_mut().show_seed = true;
    c.state_mut().seed_reveal_deadline = Some(Deadline::after(Duration::ZERO));

    c.tick();

    assert!(!c.state().show_seed, "the reveal deadline hides the seed");
    assert!(
        c.state().seed_reveal_deadline.is_none(),
        "the deadline is cleared once it fires"
    );
    cleanup(&dir);
}

#[test]
fn tick_screen_locks_on_the_wall_clock_when_the_monotonic_clock_froze_during_suspend() {
    let dir = temp_dir("idle-lock-suspend");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.state_mut().screen_lock_mins = 1;
    c.last_activity = std::time::Instant::now();
    c.last_activity_wall = SystemTime::now() - Duration::from_secs(3600);

    c.tick();

    assert_eq!(
        c.state().phase,
        AppPhase::Locked,
        "an hour of wall time past the 1-minute window locks the wallet even though the monotonic clock froze"
    );
    cleanup(&dir);
}

#[test]
fn typing_refreshes_the_idle_lock_window() {
    let dir = temp_dir("idle-typing");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.state_mut().screen_lock_mins = 1;
    c.last_activity = std::time::Instant::now() - Duration::from_secs(120);
    c.last_activity_wall = SystemTime::now() - Duration::from_secs(120);

    c.note_activity();
    c.tick();

    assert_eq!(
        c.state().phase,
        AppPhase::Unlocked,
        "active typing must keep the wallet unlocked"
    );
    cleanup(&dir);
}

fn confirm_send_modal_with_expired_autosign(dir: &Path) -> AppController {
    let mut c = unlocked(dir, WalletProfile::default());
    c.state_mut().seed = test_seed();
    let mut wallet = timed_wallet("0:me");
    set_native_balance(&mut wallet, 2_000_000_000);
    c.state_mut().wallet = Some(wallet);
    c.state_mut().send_form.destination =
        "0:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_owned();
    c.state_mut().send_form.amount = "1.0".to_owned();
    c.state_mut().extend_autosign();
    c.handle_command(AppCommand::RequestSend);
    assert_eq!(
        c.state().auth.mode,
        AuthMode::Confirm,
        "an open auto-sign window opens a confirm-only modal"
    );
    c.state_mut().autosign_until = Some(crate::state::Deadline::after(std::time::Duration::ZERO));
    assert!(!c.state().within_autosign(), "the window has lapsed");
    c
}

#[test]
fn tick_demotes_an_open_confirm_send_modal_when_autosign_expires() {
    let dir = temp_dir("autosign-tick-demote");
    let mut c = confirm_send_modal_with_expired_autosign(&dir);

    c.tick();

    assert!(c.state().autosign_until.is_none());
    assert!(c.state().auth.open, "the modal stays open");
    assert_eq!(
        c.state().auth.mode,
        AuthMode::Enter,
        "an expired auto-sign demotes the confirm modal to password entry"
    );
    assert!(!c.state().auth.error.is_empty());
    cleanup(&dir);
}

#[test]
fn confirm_after_autosign_expiry_asks_for_a_password_instead_of_signing() {
    let dir = temp_dir("autosign-confirm-demote");
    let mut c = confirm_send_modal_with_expired_autosign(&dir);

    c.handle_command(AppCommand::AuthSubmit {
        pw: Password::new(String::new()),
        pw2: Password::new(String::new()),
        remember: false,
    });

    assert!(c.state().auth.open, "the modal is not dismissed");
    assert_eq!(
        c.state().auth.mode,
        AuthMode::Enter,
        "a confirm click after expiry requires the password, it must not sign"
    );
    assert!(
        !c.state().sending,
        "nothing was sent without re-entering the password"
    );
    cleanup(&dir);
}

#[test]
fn re_auth_send_opens_the_autosign_window_only_when_remember_is_ticked() {
    let dir = temp_dir("send-remember");
    let mut c = unlocked(&dir, WalletProfile::default());

    c.pending_authorization = Some(send_authorization(1, 2));
    let vault = Vault::create_with(PW, CHEAP).unwrap();
    c.apply_key_msg(KeyMsg::Ok {
        history_corrupt: false,
        journal: cc_wallet_domain::JournalEnvelope::empty(),
        selected: None,
        writer: None,
        generation: c.key_generation(),
        history: Vec::new(),
        action: KeyAction::ConfirmSend {
            remember: false,
            auth_generation: 1,
            auth_nonce: 2,
        },
        vault,
        profile: WalletProfile::default(),
    });
    assert!(
        !c.state().within_autosign(),
        "unchecked 'stay unlocked' must not open the auto-sign window"
    );
    assert!(c.state().autosign_until.is_none());

    c.pending_authorization = Some(send_authorization(3, 4));
    c.state_mut().recipient_check = RecipientCheck::Known(DestinationAccountStatus::Active);
    let vault = Vault::create_with(PW, CHEAP).unwrap();
    c.apply_key_msg(KeyMsg::Ok {
        history_corrupt: false,
        journal: cc_wallet_domain::JournalEnvelope::empty(),
        selected: None,
        writer: None,
        generation: c.key_generation(),
        history: Vec::new(),
        action: KeyAction::ConfirmSend {
            remember: true,
            auth_generation: 3,
            auth_nonce: 4,
        },
        vault,
        profile: WalletProfile::default(),
    });
    assert!(
        c.state().within_autosign(),
        "checked 'stay unlocked' opens the auto-sign window"
    );
    cleanup(&dir);
}

fn confirm_setting_change(c: &mut AppController) {
    c.handle_command(AppCommand::AuthSubmit {
        pw: Password::new("a-test-password".to_owned()),
        pw2: Password::new(String::new()),
        remember: false,
    });
    c.pump_key();
}

#[test]
fn setting_the_timers_prompts_for_the_password_then_persists_them() {
    let dir = temp_dir("timers");
    let mut c = unlocked(&dir, WalletProfile::default());

    c.handle_command(AppCommand::SetAutosign(30));
    assert!(
        c.state().auth.open,
        "changing a timer prompts for the password"
    );
    assert_eq!(c.state().auth.purpose, AuthPurpose::ChangeSecuritySetting);
    assert_eq!(c.state().auth.mode, AuthMode::Enter);
    assert_eq!(
        c.pending_security_setting,
        Some(SecuritySetting::AutoSign(30))
    );
    assert_eq!(
        c.state().autosign_mins,
        5,
        "the value must not change before the password is verified"
    );

    confirm_setting_change(&mut c);
    assert!(!c.state().auth.open, "a verified change closes the prompt");
    assert_eq!(c.pending_security_setting, None);
    assert_eq!(c.state().autosign_mins, 30);
    assert_eq!(c.state().to_profile().autosign_mins, 30);

    c.handle_command(AppCommand::SetScreenLock(60));
    assert_eq!(
        c.pending_security_setting,
        Some(SecuritySetting::ScreenLock(60))
    );
    assert_eq!(c.state().screen_lock_mins, 5);
    confirm_setting_change(&mut c);
    assert_eq!(c.state().screen_lock_mins, 60);
    assert_eq!(c.state().to_profile().screen_lock_mins, 60);
    cleanup(&dir);
}

#[test]
fn re_selecting_the_active_timer_value_does_not_prompt() {
    let dir = temp_dir("timers-noop");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.handle_command(AppCommand::SetAutosign(5));
    assert!(
        !c.state().auth.open,
        "re-selecting the current value must not prompt"
    );
    assert_eq!(c.pending_security_setting, None);
    cleanup(&dir);
}

#[test]
fn cancelling_the_timer_prompt_discards_the_change() {
    let dir = temp_dir("timers-cancel");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.handle_command(AppCommand::SetAutosign(60));
    assert!(c.state().auth.open);

    c.handle_command(AppCommand::AuthCancel);
    assert!(!c.state().auth.open, "cancelling closes the prompt");
    assert_eq!(
        c.pending_security_setting, None,
        "the pending change is dropped"
    );
    assert_eq!(c.state().autosign_mins, 5, "nothing was changed");
    assert_eq!(c.state().to_profile().autosign_mins, 5);
    cleanup(&dir);
}

#[test]
fn a_wrong_password_keeps_the_timer_prompt_open_and_unchanged() {
    let dir = temp_dir("timers-wrong-pw");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.handle_command(AppCommand::SetAutosign(60));

    c.handle_command(AppCommand::AuthSubmit {
        pw: Password::new("not-the-password".to_owned()),
        pw2: Password::new(String::new()),
        remember: false,
    });
    c.pump_key();

    assert!(
        c.state().auth.open,
        "a wrong password leaves the prompt open to retry"
    );
    assert_eq!(c.state().auth.error, "Incorrect password");
    assert_eq!(
        c.pending_security_setting,
        Some(SecuritySetting::AutoSign(60)),
        "the pending change survives a wrong-password attempt so a retry can apply it"
    );
    assert_eq!(
        c.state().autosign_mins,
        5,
        "the value is not changed by a failed attempt"
    );

    confirm_setting_change(&mut c);
    assert!(!c.state().auth.open);
    assert_eq!(c.state().autosign_mins, 60);
    cleanup(&dir);
}

#[test]
fn merge_activity_dedups_and_sorts_without_inventing_finality() {
    let dir = temp_dir("activity");
    let mut c = unlocked(&dir, WalletProfile::default());

    let event = |lt: u64, ext: &str| ActivityEvent {
        tx_hash: optional_digest(&format!("tx{lt}")),
        counterparty: "0:other".to_owned(),
        movements: vec![movement(AssetId::Native, 1)],
        fee_native: 1,
        ext_msg_hash: optional_digest(ext),
        int_msg_hash: optional_digest("int"),
        ..ActivityEvent::test_stub(lt, lt)
    };

    c.merge_activity(vec![event(10, ""), event(30, ""), event(20, "")]);
    let lts: Vec<u64> = c.state().activity.iter().map(|e| e.lt).collect();
    assert_eq!(lts, vec![30, 20, 10]);

    c.merge_activity(vec![event(40, "sendhash")]);
    assert_eq!(c.state().activity[0].lt, 40);
    assert!(c.state().activity[0].finality_ms.is_none());

    let len = c.state().activity.len();
    c.merge_activity(vec![event(40, "sendhash")]);
    assert_eq!(c.state().activity.len(), len);
    cleanup(&dir);
}

#[test]
fn merge_activity_keeps_sibling_events_sharing_an_lt() {
    let dir = temp_dir("activity-siblings");
    let mut c = unlocked(&dir, WalletProfile::default());

    let sibling = |int: &str| ActivityEvent {
        tx_hash: optional_digest("tx-shared"),
        counterparty: "0:other".to_owned(),
        movements: vec![movement(AssetId::Native, 1)],
        fee_native: 1,
        ext_msg_hash: optional_digest("ext-shared"),
        int_msg_hash: optional_digest(int),
        ..ActivityEvent::test_stub(50, 50)
    };
    let at_lt_50 = |c: &AppController| c.state().activity.iter().filter(|e| e.lt == 50).count();

    c.merge_activity(vec![sibling("int-a"), sibling("int-b")]);
    assert_eq!(
        at_lt_50(&c),
        2,
        "both siblings are retained, not deduped by lt"
    );

    c.merge_activity(vec![sibling("int-a"), sibling("int-b")]);
    assert_eq!(at_lt_50(&c), 2, "a re-scan of the same rows dedups");

    c.merge_activity(vec![sibling("int-a"), sibling("int-c")]);
    assert_eq!(
        at_lt_50(&c),
        3,
        "only the previously-missing sibling is added"
    );
    cleanup(&dir);
}

#[test]
fn optimistic_pending_row_is_shown_then_reconciled_by_the_confirmed_tx() {
    let dir = temp_dir("pending");
    let mut c = unlocked(&dir, WalletProfile::default());

    let request = native_request(SEND_DEST, 5_000);
    let lt = c.push_pending_send(&request);
    c.session.awaiting_send_lt = Some(lt);
    assert_eq!(c.state().activity.len(), 1);
    let row = &c.state().activity[0];
    assert!(row.pending);
    assert_eq!(row.direction, ActivityDirection::Out);
    assert_eq!(row.movements[0].amount.native_units(), Some(5_000));
    assert!(row.ext_msg_hash.is_none());
    assert!(row.finality_ms.is_none());
    assert_eq!(c.session.pending_sends.len(), 1);
    assert!(
        c.session.pending_sends[0].1.is_none(),
        "showing sending immediately must not start finality during preparation"
    );

    let awaiting = c.session.awaiting_send_lt.take().expect("awaiting lt");
    c.state
        .activity
        .iter_mut()
        .find(|e| e.lt == awaiting)
        .unwrap()
        .ext_msg_hash = optional_digest("exthash");
    c.session.awaiting_send_lt = Some(awaiting);
    c.arm_awaiting_send_finality();
    assert!(c.session.pending_sends[0].1.is_some());

    c.record_account_announcement(8_000_000);

    let confirmed = ActivityEvent {
        tx_hash: optional_digest("realtx"),
        counterparty: "0:other".to_owned(),
        movements: vec![movement(AssetId::Native, 5_000)],
        fee_native: 42,
        ext_msg_hash: optional_digest("exthash"),
        int_msg_hash: optional_digest("int"),
        ..ActivityEvent::test_stub(8_000_000, 8_000_000)
    };
    c.merge_activity(vec![confirmed]);

    assert_eq!(c.state().activity.len(), 1);
    let row = &c.state().activity[0];
    assert!(!row.pending);
    assert_eq!(row.lt, 8_000_000);
    assert!(
        row.finality_ms.is_some(),
        "the subscription announced this transaction, so the row can say how long it took"
    );
    assert!(c.session.pending_sends.is_empty());
    cleanup(&dir);
}

#[test]
fn a_drifted_endpoint_observation_does_not_match_or_poison_persistence() {
    let dir = temp_dir("m8-endpoint-drift");
    let (mut c, _fake) = ready_to_send(&dir);
    let ext_hash = digest("M8-DRIFT");
    let (_record_id, endpoint) = install_blocking_history_record(&mut c, ext_hash.clone(), 0x62);
    assert!(c.state().journal_blocking, "the send starts out blocking");

    let drifted = endpoint_observation(
        ext_hash.clone(),
        "https://drifted-default.example/",
        SEND_DEST,
        "drift-request",
        "drift-tx",
        true,
    );
    c.reconcile_endpoint_observations(c.subscription_generation, vec![drifted]);
    assert_eq!(
        c.state().persistence_health,
        PersistenceHealth::Ready,
        "a drifted-endpoint observation must not poison persistence"
    );
    assert!(
        c.state().journal_blocking,
        "the record stays blocking (wallet alive), not reconciled by a foreign endpoint"
    );

    let same = endpoint_observation(
        ext_hash,
        &endpoint,
        SEND_DEST,
        "same-request",
        "same-tx",
        true,
    );
    c.reconcile_endpoint_observations(c.subscription_generation, vec![same]);
    assert!(
        !c.state().journal_blocking,
        "a same-endpoint observation reconciles the send and clears the block"
    );
    cleanup(&dir);
}

#[test]
fn rpc_confirmed_activity_is_saved_before_send_reenables() {
    let dir = temp_dir("rpc-confirmed-activity-save");
    let (mut c, _fake) = ready_to_send(&dir);
    let ext_hash = digest("RPC-CONFIRMED-ACTIVITY");
    let (record_id, endpoint) = install_blocking_history_record(&mut c, ext_hash.clone(), 0x51);
    let pending_lt = c.push_pending_send(&native_request(SEND_DEST, 1));
    c.state
        .activity
        .iter_mut()
        .find(|event| event.lt == pending_lt)
        .expect("the optimistic row exists")
        .ext_msg_hash = Some(ext_hash.clone());
    c.session.awaiting_send_lt = Some(pending_lt);
    c.arm_awaiting_send_finality();
    c.session.in_flight_record_id = Some(record_id);
    c.state.sending = true;
    c.state.busy = true;
    let observation = endpoint_observation(
        ext_hash.clone(),
        &endpoint,
        SEND_DEST,
        "rpc-confirmation-request",
        "rpc-confirmation-tx",
        true,
    );
    let tx_hash = observation.tx_hash().clone();

    c.reconcile_endpoint_observations(c.subscription_generation, vec![observation]);
    assert!(!c.state().journal_blocking);
    assert!(!c.state().sending);
    assert!(!c.state().busy);
    assert!(c.state().send_form.destination.is_empty());
    assert!(c.state().send_form.amount.is_empty());
    assert!(!c.state().send_enabled());
    assert!(
        c.state()
            .activity
            .iter()
            .find(|event| event.lt == pending_lt)
            .and_then(|event| event.finality_ms)
            .is_none(),
        "reading the transaction back over RPC is us going to look, not the chain \
         telling us — only the subscription stops the clock"
    );

    std::thread::sleep(Duration::from_millis(5));
    c.record_account_announcement(44);
    c.merge_activity(vec![ActivityEvent {
        tx_hash: Some(tx_hash),
        counterparty: SEND_DEST.to_owned(),
        movements: vec![movement(AssetId::Native, 1)],
        fee_native: 1,
        ext_msg_hash: Some(ext_hash),
        int_msg_hash: optional_digest("rpc-confirmation-int"),
        ..ActivityEvent::test_stub(44, 1_700_000_001)
    }]);

    assert_eq!(c.state().persistence_health, PersistenceHealth::Ready);
    assert!(c.save_task.is_none());
    assert!(!c.dirty);
    assert!(c.save_deadline.is_none());
    assert!(
        c.state().activity[0].finality_ms.is_some(),
        "once the subscription announced it, the row reports how long that took"
    );
    c.handle_command(AppCommand::SetSendDestination(SEND_DEST.to_owned()));
    c.handle_command(AppCommand::SetSendAmount("1.0".to_owned()));
    assert!(c.state().send_enabled());
    cleanup(&dir);
}

#[test]
fn an_orphaned_optimistic_row_is_reconciled_by_a_later_transaction() {
    let dir = temp_dir("pending-timeout");
    let mut c = unlocked(&dir, WalletProfile::default());

    let request = native_request(SEND_DEST, 7);
    let lt = c.push_pending_send(&request);
    {
        let row = c.state.activity.iter_mut().find(|e| e.lt == lt).unwrap();
        row.ext_msg_hash = optional_digest("H");
        row.pending = false;
        row.success = false;
    }
    c.session.pending_sends.clear();
    c.session.awaiting_send_lt = None;

    let confirmed = ActivityEvent {
        tx_hash: optional_digest("realtx"),
        counterparty: "0:other".to_owned(),
        movements: vec![movement(AssetId::Native, 7)],
        fee_native: 3,
        ext_msg_hash: optional_digest("H"),
        int_msg_hash: optional_digest("int"),
        ..ActivityEvent::test_stub(9_000_000, 9_000_000)
    };
    c.merge_activity(vec![confirmed]);

    assert_eq!(
        c.state().activity.len(),
        1,
        "orphan replaced, not duplicated"
    );
    assert_eq!(c.state().activity[0].tx_hash, optional_digest("realtx"));
    assert!(c.state().activity[0].success);
    cleanup(&dir);
}

#[test]
fn lock_drops_optimistic_send_tracking() {
    let dir = temp_dir("pending-lock");
    let mut c = unlocked(&dir, WalletProfile::default());
    let request = native_request(SEND_DEST, 1);
    let lt = c.push_pending_send(&request);
    c.session.awaiting_send_lt = Some(lt);
    assert!(!c.session.pending_sends.is_empty());

    c.lock();
    assert!(c.session.awaiting_send_lt.is_none());
    assert!(c.session.pending_sends.is_empty());
    cleanup(&dir);
}

#[test]
fn fee_estimate_applies_only_for_the_current_generation_and_clears_on_lock() {
    use cc_wallet_chain::FeeEstimate;

    let dir = temp_dir("fee-estimate");
    let mut c = unlocked(&dir, WalletProfile::default());
    assert_eq!(
        c.state().effective_send_fee(),
        crate::state::HARDCODED_SEND_FEE_NANOS
    );

    let stale_generation = c.subscription_generation.wrapping_add(1);
    c.apply_event(AppEvent::FeeEstimated {
        generation: stale_generation,
        seq: c.fee_request_seq,
        estimate: FeeEstimate {
            fee_nanos: 99,
            deploy: false,
        },
    });
    assert_eq!(c.state().fee_estimate, None);

    c.apply_event(AppEvent::FeeEstimated {
        generation: c.subscription_generation,
        seq: c.fee_request_seq,
        estimate: FeeEstimate {
            fee_nanos: 74_865_123,
            deploy: true,
        },
    });
    assert_eq!(c.state().effective_send_fee(), 74_865_123);
    assert!(c.state().fee_estimate.unwrap().deploy);
    assert!(!c.state().fee_estimating);

    c.state_mut().send_form.destination =
        "0:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_owned();
    c.state_mut().send_form.amount = "1.0".to_owned();
    let exact_fee = c.state().effective_send_fee();
    let mut wallet = timed_wallet("0:me");
    set_native_balance(&mut wallet, 1_000_000_000 + exact_fee - 1);
    c.state_mut().wallet = Some(wallet);
    assert!(!c.state().can_afford_send());
    set_native_balance(
        c.state_mut().wallet.as_mut().unwrap(),
        1_000_000_000 + exact_fee,
    );
    assert!(c.state().can_afford_send());

    c.lock();
    assert_eq!(c.state().fee_estimate, None);
    assert_eq!(
        c.state().effective_send_fee(),
        crate::state::HARDCODED_SEND_FEE_NANOS
    );
    cleanup(&dir);
}

#[test]
fn a_stale_request_cannot_overwrite_a_newer_estimate() {
    use cc_wallet_chain::FeeEstimate;

    let dir = temp_dir("fee-race");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.fee_request_seq = 2;
    c.apply_event(AppEvent::FeeEstimated {
        generation: c.subscription_generation,
        seq: 2,
        estimate: FeeEstimate {
            fee_nanos: 76_000_000,
            deploy: false,
        },
    });
    assert_eq!(c.state().effective_send_fee(), 76_000_000);

    c.apply_event(AppEvent::FeeEstimated {
        generation: c.subscription_generation,
        seq: 1,
        estimate: FeeEstimate {
            fee_nanos: 7_500_000,
            deploy: false,
        },
    });
    assert_eq!(c.state().effective_send_fee(), 76_000_000);

    c.apply_event(AppEvent::FeeEstimateFailed {
        generation: c.subscription_generation,
        seq: 1,
    });
    assert_eq!(c.state().effective_send_fee(), 76_000_000);
    cleanup(&dir);
}

#[test]
fn a_failed_latest_estimate_drops_the_stale_one_and_falls_back() {
    use cc_wallet_chain::FeeEstimate;

    let dir = temp_dir("fee-estimate-fail");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.apply_event(AppEvent::FeeEstimated {
        generation: c.subscription_generation,
        seq: c.fee_request_seq,
        estimate: FeeEstimate {
            fee_nanos: 10_600_000,
            deploy: true,
        },
    });
    assert_eq!(c.state().effective_send_fee(), 10_600_000);

    c.state_mut().fee_estimating = true;
    c.apply_event(AppEvent::FeeEstimateFailed {
        generation: c.subscription_generation,
        seq: c.fee_request_seq,
    });
    assert!(!c.state().fee_estimating);
    assert_eq!(c.state().fee_estimate, None);
    assert_eq!(c.state().error, None, "estimate failures must stay silent");
    assert_eq!(
        c.state().effective_send_fee(),
        crate::state::HARDCODED_SEND_FEE_NANOS
    );
    cleanup(&dir);
}

#[test]
fn max_refines_the_full_balance_fee_and_leaves_only_the_drift_headroom() {
    let dir = temp_dir("max-exact-fee");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.state_mut().seed = test_seed();
    let balance = 97_736_548_757u128;
    let mut wallet = timed_wallet("0:me");
    set_native_balance(&mut wallet, balance);
    c.state_mut().wallet = Some(wallet);
    c.state_mut().send_form.destination = SEND_DEST.to_owned();

    c.handle_command(AppCommand::SetMaxAmount);

    let approx = balance
        - crate::state::HARDCODED_SEND_FEE_NANOS
        - cc_wallet_domain::LOCAL_SEND_FEE_HEADROOM_NANOS;
    assert_eq!(
        c.state().send_form.amount,
        cc_wallet_domain::format_native_fixed9(approx).unwrap()
    );
    assert!(c.state().max_refining);
    assert!(!c.state().send_enabled());

    let max_seq = c.pending_max_seq.expect("MAX fee emulation is running");
    let exact_fee = 7_491_005;
    c.apply_event(AppEvent::MaxFeeEstimated {
        generation: c.subscription_generation,
        seq: max_seq,
        estimate: FeeEstimate {
            fee_nanos: exact_fee,
            deploy: false,
        },
    });

    let spendable = balance - exact_fee - cc_wallet_domain::LOCAL_SEND_FEE_HEADROOM_NANOS;
    assert_eq!(
        c.state().send_form.amount,
        cc_wallet_domain::format_native_fixed9(spendable).unwrap()
    );
    assert!(!c.state().max_refining);
    assert!(c.state().can_afford_send());
    assert!(c.state().send_enabled());

    set_native_balance(
        c.state_mut().wallet.as_mut().unwrap(),
        spendable + exact_fee - 1,
    );
    assert!(
        !c.state().can_afford_send(),
        "one missing base unit below amount plus the exact fee is refused"
    );
    set_native_balance(
        c.state_mut().wallet.as_mut().unwrap(),
        spendable + exact_fee,
    );
    assert!(
        c.state().can_afford_send(),
        "a later exact fee may consume every remaining unit of MAX headroom"
    );
    cleanup(&dir);
}

#[test]
fn max_fill_and_refined_max_agree_when_fee_matches() {
    let dir = temp_dir("max-agree");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.state_mut().seed = test_seed();
    let balance = 12_345_678_900u128;
    let mut wallet = timed_wallet("0:me");
    set_native_balance(&mut wallet, balance);
    c.state_mut().wallet = Some(wallet);
    c.state_mut().send_form.destination = SEND_DEST.to_owned();

    c.handle_command(AppCommand::SetMaxAmount);
    let approx_amount = c.state().send_form.amount.clone();
    let seeding_fee = crate::state::HARDCODED_SEND_FEE_NANOS;
    assert_eq!(
        approx_amount,
        cc_wallet_domain::format_native_fixed9(cc_wallet_domain::max_native_spendable(
            balance,
            seeding_fee
        ))
        .unwrap()
    );

    let max_seq = c.pending_max_seq.expect("MAX fee emulation is running");
    c.apply_event(AppEvent::MaxFeeEstimated {
        generation: c.subscription_generation,
        seq: max_seq,
        estimate: FeeEstimate {
            fee_nanos: seeding_fee,
            deploy: false,
        },
    });

    assert_eq!(
        c.state().send_form.amount,
        approx_amount,
        "a refined fee equal to the seeding fee must leave the MAX amount unchanged"
    );
    cleanup(&dir);
}

#[test]
fn a_second_max_click_waits_for_the_single_flight_worker_then_replaces_it() {
    let dir = temp_dir("max-single-flight-replace");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.state_mut().seed = test_seed();
    let mut wallet = timed_wallet("0:me");
    set_native_balance(&mut wallet, 5_000_000_000);
    c.state_mut().wallet = Some(wallet);
    c.state_mut().send_form.destination = SEND_DEST.to_owned();

    c.handle_command(AppCommand::SetMaxAmount);
    let first_seq = c.pending_max_seq.expect("first MAX worker");
    c.handle_command(AppCommand::SetMaxAmount);
    assert!(c.queued_max_request.is_some());
    assert!(c.pending_max_seq.is_none());

    c.apply_event(AppEvent::MaxFeeEstimated {
        generation: c.subscription_generation,
        seq: first_seq,
        estimate: FeeEstimate {
            fee_nanos: 7_490_000,
            deploy: false,
        },
    });

    assert!(c.queued_max_request.is_none());
    assert!(
        c.pending_max_seq.is_some_and(|seq| seq > first_seq),
        "the replacement MAX owns a new emulation request"
    );
    assert!(c.state().max_refining);
    cleanup(&dir);
}

#[test]
fn a_user_typed_amount_survives_max_refinement_completion() {
    let dir = temp_dir("max-typed-survives");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.state_mut().seed = test_seed();
    let mut wallet = timed_wallet("0:me");
    set_native_balance(&mut wallet, 5_000_000_000);
    c.state_mut().wallet = Some(wallet);
    c.state_mut().send_form.destination = SEND_DEST.to_owned();

    c.handle_command(AppCommand::SetMaxAmount);
    let seq = c.pending_max_seq.expect("MAX worker");

    c.handle_command(AppCommand::SetSendAmount("1.0".to_owned()));
    assert!(
        c.pending_max_seq.is_none(),
        "typing disarms the pending MAX"
    );
    assert!(!c.state().max_refining);

    c.apply_event(AppEvent::MaxFeeEstimated {
        generation: c.subscription_generation,
        seq,
        estimate: FeeEstimate {
            fee_nanos: 7_490_000,
            deploy: false,
        },
    });
    assert_eq!(
        c.state().send_form.amount,
        "1.0",
        "the user-typed amount survives a late MAX refinement"
    );
    cleanup(&dir);
}

#[test]
fn a_failed_max_emulation_reenables_the_form_without_a_sticky_error() {
    let dir = temp_dir("max-failure-unlocks");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.state_mut().seed = test_seed();
    let mut wallet = timed_wallet("0:me");
    set_native_balance(&mut wallet, 5_000_000_000);
    c.state_mut().wallet = Some(wallet);
    c.state_mut().send_form.destination = SEND_DEST.to_owned();

    c.handle_command(AppCommand::SetMaxAmount);
    let seq = c.pending_max_seq.expect("MAX worker");
    c.apply_event(AppEvent::FeeEstimateFailed {
        generation: c.subscription_generation,
        seq,
    });

    assert!(!c.state().max_refining);
    assert!(c.pending_max_seq.is_none());
    assert!(c.state().error.is_none());
    cleanup(&dir);
}

#[test]
fn a_balance_change_during_max_reprices_the_new_snapshot() {
    let dir = temp_dir("max-balance-change");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.state_mut().seed = test_seed();
    let mut wallet = timed_wallet("0:me");
    set_native_balance(&mut wallet, 5_000_000_000);
    c.state_mut().wallet = Some(wallet);
    c.state_mut().send_form.destination = SEND_DEST.to_owned();

    c.handle_command(AppCommand::SetMaxAmount);
    let old_seq = c.pending_max_seq.expect("old MAX worker");
    set_native_balance(c.state_mut().wallet.as_mut().unwrap(), 6_000_000_000);
    c.apply_event(AppEvent::MaxFeeEstimated {
        generation: c.subscription_generation,
        seq: old_seq,
        estimate: FeeEstimate {
            fee_nanos: 7_490_000,
            deploy: false,
        },
    });

    assert_eq!(c.pending_max_balance, Some(6_000_000_000));
    assert!(
        c.pending_max_seq.is_some_and(|seq| seq > old_seq),
        "the stale full-balance price is discarded and recomputed"
    );
    assert!(c.state().max_refining);
    cleanup(&dir);
}

#[test]
fn max_amount_is_refetched_for_the_real_destination() {
    let dir = temp_dir("max-refetch-dest");
    let (mut c, fake) = ready_to_send(&dir);
    c.state_mut().send_form.destination.clear();
    c.state_mut().send_form.amount.clear();
    let balance = 5_000_000_000u128;
    let f1 = 3_000_000u128;
    let f2 = 9_000_000u128;
    let headroom = cc_wallet_domain::LOCAL_SEND_FEE_HEADROOM_NANOS;

    fake.set_fee(Ok(FeeEstimate {
        fee_nanos: f1,
        deploy: false,
    }));
    c.handle_command(AppCommand::SetMaxAmount);
    c.pump_events();
    assert_eq!(
        c.state().send_form.amount,
        cc_wallet_domain::format_native_fixed9(balance - f1 - headroom).unwrap(),
        "MAX with no recipient prices against the own address (F1)"
    );

    fake.set_fee(Ok(FeeEstimate {
        fee_nanos: f2,
        deploy: false,
    }));
    c.handle_command(AppCommand::SetSendDestination(SEND_DEST.to_owned()));
    c.estimate_fee();
    c.pump_events();
    assert_eq!(
        c.state().send_form.amount,
        cc_wallet_domain::format_native_fixed9(balance - f2 - headroom).unwrap(),
        "MAX is re-derived against the real destination (F2)"
    );
    cleanup(&dir);
}

#[test]
fn manual_amount_edit_stops_max_tracking() {
    let dir = temp_dir("max-manual-stops");
    let (mut c, fake) = ready_to_send(&dir);
    c.state_mut().send_form.destination.clear();
    c.state_mut().send_form.amount.clear();
    fake.set_fee(Ok(FeeEstimate {
        fee_nanos: 3_000_000,
        deploy: false,
    }));
    c.handle_command(AppCommand::SetMaxAmount);
    c.pump_events();

    c.handle_command(AppCommand::SetSendAmount("5".to_owned()));
    fake.set_fee(Ok(FeeEstimate {
        fee_nanos: 9_000_000,
        deploy: false,
    }));
    c.handle_command(AppCommand::SetSendDestination(SEND_DEST.to_owned()));
    c.estimate_fee();
    c.pump_events();
    assert_eq!(
        c.state().send_form.amount,
        "5",
        "a manual edit stops MAX tracking; the destination change leaves it alone"
    );
    cleanup(&dir);
}

#[test]
fn hiding_the_selected_asset_stops_max_tracking() {
    let dir = temp_dir("max-hide-asset");
    let (mut c, _fake) = ready_to_send(&dir);
    c.state_mut().set_asset_visibility(1, true);
    c.state_mut().select_asset(AssetId::CurrencyCollection(1));
    c.handle_command(AppCommand::SetMaxAmount);
    assert!(c.max_filled, "MAX fills the CC amount");

    c.handle_command(AppCommand::SetAssetVisibility {
        cc_id: 1,
        visible: false,
    });
    assert_eq!(c.state().selected_asset, AssetId::Native);
    assert!(!c.max_filled, "the CC MAX does not carry over to native");
    cleanup(&dir);
}

#[test]
fn first_load_still_runs_placeholder_estimate() {
    let dir = temp_dir("placeholder-first-load");
    let (mut c, fake) = ready_to_send(&dir);
    c.state_mut().send_form.destination.clear();
    c.state_mut().send_form.amount.clear();
    c.state_mut().fee_estimate = None;
    assert!(!c.state().fee_estimating);

    c.estimate_fee();
    c.pump_events();
    assert_eq!(
        fake.fee_bounces().len(),
        1,
        "the placeholder self-send estimate runs once when no fee is known yet"
    );
    assert!(c.state().fee_estimate.is_some());
    cleanup(&dir);
}

#[test]
fn auto_refresh_with_empty_form_reuses_known_fee() {
    let dir = temp_dir("placeholder-reuse-fee");
    let (mut c, fake) = ready_to_send(&dir);
    c.state_mut().send_form.destination.clear();
    c.state_mut().send_form.amount.clear();
    c.state_mut().fee_estimate = None;

    c.estimate_fee();
    c.pump_events();
    assert_eq!(fake.fee_bounces().len(), 1);
    assert!(c.state().fee_estimate.is_some());

    c.estimate_fee();
    c.estimate_fee();
    c.pump_events();
    assert_eq!(
        fake.fee_bounces().len(),
        1,
        "a known fee is reused, not re-emulated on every empty-form refresh"
    );
    assert!(!c.state().fee_estimating);
    cleanup(&dir);
}

#[test]
fn max_clears_only_the_form_error_and_preserves_a_background_blocker() {
    let dir = temp_dir("max-preserves-background-error");
    let mut c = unlocked(&dir, WalletProfile::default());
    let mut wallet = timed_wallet("0:me");
    set_native_balance(&mut wallet, 5_000_000_000);
    c.state_mut().wallet = Some(wallet);
    c.state_mut().snapshot_refresh_error = Some("history refresh incomplete".to_owned());
    c.state_mut().set_error("History refresh is incomplete");
    c.state_mut()
        .set_send_form_error("Enter a valid amount for the new transfer");

    c.handle_command(AppCommand::SetMaxAmount);

    assert_eq!(
        c.state().error.as_deref(),
        Some("History refresh is incomplete")
    );
    assert_eq!(c.state().status, "Error");
    assert!(!c.state().send_form_error);
    assert_eq!(
        c.state().send_form.amount,
        cc_wallet_domain::format_native_fixed9(
            5_000_000_000
                - crate::state::HARDCODED_SEND_FEE_NANOS
                - cc_wallet_domain::LOCAL_SEND_FEE_HEADROOM_NANOS
        )
        .unwrap()
    );
    assert!(
        !c.state().send_enabled(),
        "MAX must not hide or relax the unrelated refresh blocker"
    );
    cleanup(&dir);
}

#[test]
fn max_on_a_dust_balance_does_not_create_a_sticky_technical_banner() {
    let dir = temp_dir("max-dust-no-banner");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.state_mut().wallet = Some(timed_wallet("0:me"));
    c.state_mut().snapshot_refresh_error = Some("history refresh incomplete".to_owned());
    c.state_mut().set_error("History refresh is incomplete");

    c.handle_command(AppCommand::SetMaxAmount);

    assert!(!c.state().send_form_error);
    assert_eq!(
        c.state().error.as_deref(),
        Some("History refresh is incomplete")
    );
    assert_eq!(c.state().send_form.amount, "0.000000000");
    assert!(
        !c.state().send_enabled(),
        "a zero MAX remains disabled without replacing the real background blocker"
    );
    cleanup(&dir);
}

#[test]
fn an_authorized_but_unaffordable_send_surfaces_a_banner_and_does_not_send() {
    let dir = temp_dir("fee-guard-banner");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.state_mut().seed = test_seed();
    let mut wallet = timed_wallet("0:me");
    set_native_balance(&mut wallet, 1_000);
    c.state_mut().wallet = Some(wallet);
    c.state_mut().send_form.destination =
        "0:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_owned();
    c.state_mut().send_form.amount = "1.0".to_owned();
    c.state_mut().recipient_check = RecipientCheck::Known(DestinationAccountStatus::Active);
    assert!(!c.state().can_afford_send());

    c.dispatch_test_authorization();

    assert!(!c.state().sending, "the unaffordable send must not proceed");
    assert!(
        c.state()
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("Insufficient balance"),
        "a blocked authorized send must surface a banner, not vanish silently"
    );
    cleanup(&dir);
}

#[test]
fn returning_to_the_picker_wipes_a_staged_onboarding_seed() {
    let dir = temp_dir("staged-seed-back");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.lock();
    c.state_mut().seed = test_seed();
    c.state_mut().show_seed = true;
    c.state_mut().seed_unsaved = true;
    c.state_mut().onboard_import_valid = true;

    c.handle_command(AppCommand::BackToPicker);

    assert!(c.state().seed.is_empty(), "the staged phrase must be wiped");
    assert!(!c.state().seed_editing);
    assert!(!c.state().show_seed);
    assert!(!c.state().seed_unsaved);
    assert!(!c.state().onboard_import_valid);
    cleanup(&dir);
}

#[test]
fn an_aborted_onboarding_wipes_the_confirmed_seed_too() {
    let dir = temp_dir("staged-confirmed-seed");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.lock();
    c.state_mut().seed = test_seed();
    c.state_mut().confirmed_seed = test_seed();
    c.state_mut().seed_saved = true;

    c.handle_command(AppCommand::BackToPicker);

    assert!(c.state().seed.is_empty(), "the staged phrase is wiped");
    assert!(
        c.state().confirmed_seed.is_empty(),
        "the confirmed-backup copy is wiped too"
    );
    assert!(!c.state().seed_saved);
    cleanup(&dir);
}

#[test]
fn entering_unlocked_clears_every_rust_seed_presentation_flag() {
    let dir = temp_dir("unlock-secret-lifetime");
    let mut c = controller(&dir);
    c.state_mut().seed = test_seed();
    c.state_mut().seed_editing = true;
    c.state_mut().show_seed = true;
    c.state_mut().seed_reveal_deadline = Some(Deadline::after(Duration::from_secs(60)));
    c.state_mut().seed_unsaved = true;
    c.state_mut().onboard_import_valid = true;
    c.state_mut().seed_backup_confirmed = true;

    let vault = Vault::create_with(PW, CHEAP).unwrap();
    let writer = c.store.writer_for_new().unwrap();
    c.apply_key_msg(KeyMsg::Ok {
        history_corrupt: false,
        journal: cc_wallet_domain::JournalEnvelope::empty(),
        selected: None,
        writer: Some(writer),
        generation: c.key_generation(),
        history: Vec::new(),
        action: KeyAction::Create,
        vault,
        profile: WalletProfile {
            seed: test_seed(),
            ..WalletProfile::default()
        },
    });

    assert_eq!(c.state().phase, AppPhase::Unlocked);
    assert_eq!(c.state().seed.expose_secret(), TEST_SEED);
    assert!(!c.state().seed_editing);
    assert!(!c.state().show_seed);
    assert!(c.state().seed_reveal_deadline.is_none());
    assert!(!c.state().seed_unsaved);
    assert!(!c.state().onboard_import_valid);
    assert!(!c.state().seed_backup_confirmed);
    cleanup(&dir);
}

#[test]
fn replacing_the_seed_drops_the_old_wallets_fee_estimate() {
    use cc_wallet_chain::FeeEstimate;

    let dir = temp_dir("fee-save-seed");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.apply_event(AppEvent::FeeEstimated {
        generation: c.subscription_generation,
        seq: c.fee_request_seq,
        estimate: FeeEstimate {
            fee_nanos: 74_865_123,
            deploy: false,
        },
    });
    assert!(c.state().fee_estimate.is_some());

    c.handle_command(AppCommand::SaveSeed(seed_input(TEST_SEED)));
    assert_eq!(c.state().fee_estimate, None);
    cleanup(&dir);
}

#[test]
fn a_created_wallet_is_bound_to_its_network_and_workchain() {
    let dir = temp_dir("identity");
    let mut c = controller(&dir);
    c.handle_command(AppCommand::GenerateSeed);
    assert!(!c.state().seed.is_empty());

    let create = |c: &mut AppController| {
        c.handle_command(AppCommand::CreateWallet {
            name: "Testnet".to_owned(),
            network_id: 2000,
            workchain: 0,
            pw: Password::new("hunter2hunter2".to_owned()),
            pw2: Password::new("hunter2hunter2".to_owned()),
        });
    };
    create(&mut c);
    assert!(
        c.state().active_wallet.is_empty(),
        "create is blocked before the backup is confirmed"
    );
    assert!(!c.state().lock_error.is_empty());

    c.handle_command(AppCommand::SetSeedBackupConfirmed(true));
    create(&mut c);
    assert_eq!(c.state().active_wallet, "Testnet");
    assert_eq!(c.state().network_id, 2000);
    assert_eq!(c.state().workchain, 0);
    assert_eq!(
        c.state().resolved_endpoint(),
        "https://rpc-testnet.tychoprotocol.com/"
    );
    cleanup(&dir);
}

#[test]
fn a_new_onboarding_clears_a_prior_backup_confirmation() {
    let dir = temp_dir("backup-reset");
    let mut c = controller(&dir);
    c.handle_command(AppCommand::SetSeedBackupConfirmed(true));
    c.handle_command(AppCommand::NewWalletRequest);
    assert!(
        !c.state().seed_backup_confirmed,
        "starting a new wallet must require re-confirming the backup"
    );
    cleanup(&dir);
}

#[test]
fn changing_the_onboarding_phrase_re_arms_the_backup_gate() {
    let dir = temp_dir("backup-rearm");
    let mut c = controller(&dir);
    c.handle_command(AppCommand::NewWalletRequest);

    let phrase_a = generated_seed_phrase();
    let phrase_b = generated_seed_phrase();
    assert_ne!(phrase_a, phrase_b);

    c.handle_command(AppCommand::OnboardImportSeed(seed_input(phrase_a.clone())));
    c.handle_command(AppCommand::SetSeedBackupConfirmed(true));
    c.handle_command(AppCommand::OnboardImportSeed(seed_input(phrase_a)));
    assert!(
        c.state().seed_backup_confirmed,
        "re-staging the same phrase must not un-check the box"
    );
    c.handle_command(AppCommand::OnboardImportSeed(seed_input(phrase_b)));
    assert!(
        !c.state().seed_backup_confirmed,
        "a changed phrase re-arms the backup gate"
    );
    cleanup(&dir);
}

#[test]
fn a_stale_generation_destination_check_is_dropped() {
    let dir = temp_dir("dest-check-stale");
    let mut c = unlocked(&dir, WalletProfile::default());
    let dest = "0:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_owned();
    c.state_mut().send_form.destination = dest.clone();

    c.apply_event(AppEvent::DestinationChecked {
        generation: c.subscription_generation.wrapping_sub(1),
        seq: c.dest_check_seq,
        address: dest.clone(),
        status: Some(DestinationAccountStatus::NonExist),
    });
    assert_eq!(
        c.state().recipient_check,
        RecipientCheck::Unchecked,
        "a check from a superseded endpoint session is ignored"
    );
    cleanup(&dir);
}

#[test]
fn the_destination_check_records_non_exist_and_uninit_distinctly() {
    let dir = temp_dir("dest-exists");
    let mut c = unlocked(&dir, WalletProfile::default());
    let dest = "0:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_owned();
    c.state_mut().send_form.destination = dest.clone();

    c.apply_event(AppEvent::DestinationChecked {
        generation: c.subscription_generation,
        seq: c.dest_check_seq,
        address: dest.clone(),
        status: Some(DestinationAccountStatus::Uninit),
    });
    assert!(c.state().recipient_inactive());
    assert_eq!(
        c.state().recipient_check,
        RecipientCheck::Known(DestinationAccountStatus::Uninit)
    );

    c.apply_event(AppEvent::DestinationChecked {
        generation: c.subscription_generation,
        seq: c.dest_check_seq,
        address: dest,
        status: Some(DestinationAccountStatus::NonExist),
    });
    assert!(c.state().recipient_inactive());
    assert_eq!(
        c.state().recipient_check,
        RecipientCheck::Known(DestinationAccountStatus::NonExist)
    );

    c.state_mut().reset_recipient_status();
    assert_eq!(c.state().recipient_check, RecipientCheck::Unchecked);
    cleanup(&dir);
}

#[test]
fn copying_never_arms_an_auto_hide_in_the_unsaved_phrase_flow() {
    let dir = temp_dir("copy-unsaved-reveal");
    let mut c = unlocked(&dir, WalletProfile::default());
    let _mem = mem_clipboard(&mut c);

    c.state_mut().show_seed = true;
    c.state_mut().seed_reveal_deadline = None;
    c.copy_seed_to_clipboard(seed_input(TEST_SEED));
    assert!(
        c.state().seed_reveal_deadline.is_none(),
        "copying a brand-new phrase must not hide it behind an auto-hide timer"
    );

    c.state_mut().seed_reveal_deadline = Some(Deadline::after(Duration::from_secs(1)));
    c.copy_seed_to_clipboard(seed_input(TEST_SEED));
    assert!(c.state().seed_reveal_deadline.is_some());
    cleanup(&dir);
}

#[test]
fn a_frozen_recipient_counts_as_inactive_and_is_recorded_distinctly() {
    let dir = temp_dir("dest-frozen");
    let mut c = unlocked(&dir, WalletProfile::default());
    let dest = "0:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_owned();
    c.state_mut().send_form.destination = dest.clone();

    c.apply_event(AppEvent::DestinationChecked {
        generation: c.subscription_generation,
        seq: c.dest_check_seq,
        address: dest,
        status: Some(DestinationAccountStatus::Frozen),
    });
    assert_eq!(
        c.state().recipient_check,
        RecipientCheck::Known(DestinationAccountStatus::Frozen)
    );
    assert!(
        c.state().recipient_inactive(),
        "a frozen account cannot process a normal send, so the advisory applies"
    );
    assert!(!c.state().recipient_send_permitted(false));
    cleanup(&dir);
}

#[test]
fn a_send_submit_refuses_while_the_destination_check_is_unresolved() {
    let dir = temp_dir("gate-pending");
    let (mut c, _fake) = ready_to_send(&dir);
    c.state_mut().auth = AuthModal {
        open: true,
        mode: AuthMode::Enter,
        purpose: AuthPurpose::Send,
        send_options_editable: true,
        error: String::new(),
    };
    c.state_mut().recipient_check = RecipientCheck::Pending;

    c.handle_command(AppCommand::AuthSubmit {
        pw: Password::new("pw".to_owned()),
        pw2: Password::new(String::new()),
        remember: false,
    });

    assert!(c.state().auth.open, "the modal stays open on refusal");
    assert!(
        c.state().auth.error.contains("verifying the recipient"),
        "the refusal names the pending check: {}",
        c.state().auth.error
    );
    assert!(!c.state().key_busy, "no key operation may start unverified");

    c.state_mut().recipient_check = RecipientCheck::Failed;
    c.handle_command(AppCommand::AuthSubmit {
        pw: Password::new("pw".to_owned()),
        pw2: Password::new(String::new()),
        remember: false,
    });
    assert!(
        c.state().auth.error.contains("Could not verify"),
        "the refusal names the failed check: {}",
        c.state().auth.error
    );
    assert!(!c.state().key_busy);
    cleanup(&dir);
}

#[test]
fn a_send_submit_refuses_an_unacknowledged_inactive_recipient() {
    let dir = temp_dir("gate-unacked");
    let (mut c, _fake) = ready_to_send(&dir);
    c.state_mut().auth = AuthModal {
        open: true,
        mode: AuthMode::Enter,
        purpose: AuthPurpose::Send,
        send_options_editable: true,
        error: String::new(),
    };
    c.state_mut().recipient_check = RecipientCheck::Known(DestinationAccountStatus::NonExist);

    c.handle_command(AppCommand::AuthSubmit {
        pw: Password::new("pw".to_owned()),
        pw2: Password::new(String::new()),
        remember: false,
    });

    assert!(c.state().auth.open);
    assert!(
        c.state().auth.error.contains("new-address option"),
        "the refusal points at the acknowledgment: {}",
        c.state().auth.error
    );
    assert!(!c.state().key_busy);
    cleanup(&dir);
}

#[test]
fn the_choke_point_refuses_an_unverified_or_unacknowledged_recipient() {
    let dir = temp_dir("choke-recipient");
    let (mut c, _fake) = ready_to_send(&dir);
    c.state_mut().seed = test_seed();

    c.state_mut().recipient_check = RecipientCheck::Pending;
    c.dispatch_test_authorization();
    assert!(!c.state().sending, "an unverified recipient must not sign");
    assert!(
        c.state()
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("not verified"),
        "the refusal surfaces a banner: {:?}",
        c.state().error
    );

    c.state_mut().error = None;
    c.state_mut().recipient_check = RecipientCheck::Known(DestinationAccountStatus::Uninit);
    c.dispatch_test_authorization();
    assert!(
        !c.state().sending,
        "an unacknowledged inactive recipient must not sign"
    );
    assert!(
        c.state()
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("new-address option"),
        "the refusal names the missing acknowledgment: {:?}",
        c.state().error
    );

    c.state_mut().error = None;
    c.state_mut().allow_unbounced = true;
    c.dispatch_test_authorization();
    assert!(c.state().sending, "an acknowledged inactive send proceeds");
    cleanup(&dir);
}

#[test]
fn a_reopened_send_confirmation_never_inherits_the_acknowledgment() {
    let dir = temp_dir("gate-ack-scope");
    let (mut c, fake) = ready_to_send(&dir);
    fake.set_destination(Ok(DestinationAccountStatus::NonExist));
    c.state_mut().recipient_check = RecipientCheck::Known(DestinationAccountStatus::NonExist);

    c.handle_command(AppCommand::RequestSend);
    c.pump_events();
    c.handle_command(AppCommand::SetAllowUnbounced(true));
    assert!(c.state().allow_unbounced);
    assert!(
        !c.pending_authorization
            .as_ref()
            .expect("first attempt holds an authorization")
            .bounce()
    );

    c.handle_command(AppCommand::AuthCancel);
    assert!(
        !c.state().allow_unbounced,
        "a cancelled confirmation must not leave its acknowledgment behind"
    );

    c.handle_command(AppCommand::SelectAsset(AssetId::CurrencyCollection(1)));
    c.handle_command(AppCommand::SetSendAmount("1.0".to_owned()));
    c.state_mut().allow_unbounced = true;
    c.handle_command(AppCommand::RequestSend);
    c.pump_events();
    assert!(
        !c.state().allow_unbounced,
        "a fresh confirmation ceremony always starts unacknowledged"
    );
    assert!(
        c.pending_authorization
            .as_ref()
            .expect("second attempt holds an authorization")
            .bounce(),
        "the fresh ticket is bounceable until re-acknowledged in this dialog"
    );
    cleanup(&dir);
}

#[test]
fn a_superseded_check_result_never_overwrites_a_fresher_status() {
    let dir = temp_dir("gate-ghost-result");
    let (mut c, _fake) = ready_to_send(&dir);
    c.dest_check_seq = 2;

    c.apply_event(AppEvent::DestinationChecked {
        generation: c.subscription_generation,
        seq: 1,
        address: SEND_DEST.to_owned(),
        status: None,
    });
    assert_eq!(
        c.state().recipient_check,
        RecipientCheck::Known(DestinationAccountStatus::Active),
        "a stale check result must not overwrite a fresher status"
    );

    c.apply_event(AppEvent::DestinationChecked {
        generation: c.subscription_generation,
        seq: 2,
        address: SEND_DEST.to_owned(),
        status: Some(DestinationAccountStatus::Uninit),
    });
    assert_eq!(
        c.state().recipient_check,
        RecipientCheck::Known(DestinationAccountStatus::Uninit)
    );
    cleanup(&dir);
}

#[test]
fn a_resolved_check_clears_a_stale_gate_refusal() {
    let dir = temp_dir("gate-stale-error");
    let (mut c, _fake) = ready_to_send(&dir);
    c.state_mut().auth = AuthModal {
        open: true,
        mode: AuthMode::Enter,
        purpose: AuthPurpose::Send,
        send_options_editable: true,
        error: String::new(),
    };
    c.state_mut().recipient_check = RecipientCheck::Pending;
    c.handle_command(AppCommand::AuthSubmit {
        pw: Password::new("pw".to_owned()),
        pw2: Password::new(String::new()),
        remember: false,
    });
    assert!(!c.state().auth.error.is_empty());

    c.apply_event(AppEvent::DestinationChecked {
        generation: c.subscription_generation,
        seq: c.dest_check_seq,
        address: SEND_DEST.to_owned(),
        status: Some(DestinationAccountStatus::Active),
    });
    assert!(
        c.state().auth.error.is_empty(),
        "a resolved check clears the now-stale 'verifying' refusal"
    );
    cleanup(&dir);
}

#[test]
fn form_edits_are_frozen_during_the_risk_review_window() {
    let dir = temp_dir("risk-window-freeze");
    let (mut c, _fake) = ready_to_send(&dir);
    c.pending_risk_review = Some(PendingRiskReview {
        authorization: send_authorization(1, 2),
        blocker_digest: digest("RISK-FREEZE-BLOCKER"),
        reservation_digest: digest("RISK-FREEZE-RESERVATION"),
        reservations: Vec::new(),
        broad_duplicate: false,
    });

    c.handle_command(AppCommand::SetSendDestination(OTHER_SEND_DEST.to_owned()));

    assert_eq!(
        c.state().send_form.destination,
        SEND_DEST,
        "the destination is frozen while a risk review is open"
    );
    assert_eq!(
        c.state().recipient_check,
        RecipientCheck::Known(DestinationAccountStatus::Active),
        "the verified status is not reset by a refused edit"
    );
    cleanup(&dir);
}

#[test]
fn a_public_copy_stops_the_seed_countdown() {
    let dir = temp_dir("copy-ttl-public");
    let mut c = unlocked(&dir, WalletProfile::default());
    let _mem = mem_clipboard(&mut c);

    c.copy_seed_to_clipboard(seed_input(TEST_SEED));
    assert_eq!(c.state().seed_copy_ttl_secs, 60);

    c.copy_text("0:deadbeef");
    assert_eq!(c.state().seed_copy_ttl_secs, 0);
    cleanup(&dir);
}

#[test]
fn a_check_that_cannot_spawn_demotes_to_failed_instead_of_spinning() {
    let dir = temp_dir("gate-cannot-spawn");
    let (mut c, _fake) = ready_to_send(&dir);
    c.state_mut().auth = AuthModal {
        open: true,
        mode: AuthMode::Enter,
        purpose: AuthPurpose::Send,
        send_options_editable: true,
        error: String::new(),
    };
    c.state_mut().recipient_check = RecipientCheck::Unchecked;
    c.state_mut().network_mismatch = true;

    c.tick();

    assert_eq!(
        c.state().recipient_check,
        RecipientCheck::Failed,
        "a check that cannot start surfaces the failed notice on the paced path"
    );
    assert!(c.session.dest_check_retry_at.is_some());
    cleanup(&dir);
}

#[test]
fn a_generation_bump_resets_a_stranded_pending_check() {
    let dir = temp_dir("gate-stranded-pending");
    let (mut c, _fake) = ready_to_send(&dir);
    c.state_mut().recipient_check = RecipientCheck::Pending;

    c.stop_subscription();

    assert_eq!(c.state().recipient_check, RecipientCheck::Unchecked);
    cleanup(&dir);
}

#[test]
fn the_send_tick_drives_an_unchecked_recipient_back_to_a_check() {
    let dir = temp_dir("gate-tick-recheck");
    let (mut c, _fake) = ready_to_send(&dir);
    c.state_mut().auth = AuthModal {
        open: true,
        mode: AuthMode::Enter,
        purpose: AuthPurpose::Send,
        send_options_editable: true,
        error: String::new(),
    };
    c.state_mut().recipient_check = RecipientCheck::Unchecked;

    c.tick();

    assert_eq!(
        c.state().recipient_check,
        RecipientCheck::Pending,
        "an open send confirmation re-runs a stranded/unchecked destination check"
    );
    cleanup(&dir);
}

#[test]
fn a_risk_confirmation_refuses_before_the_ceremony_while_the_check_is_unresolved() {
    let dir = temp_dir("gate-risk-preceremony");
    let (mut c, _fake) = ready_to_send(&dir);
    c.state_mut().auth = AuthModal {
        open: true,
        mode: AuthMode::Enter,
        purpose: AuthPurpose::Send,
        send_options_editable: false,
        error: String::new(),
    };
    c.state_mut().recipient_check = RecipientCheck::Failed;

    c.handle_command(AppCommand::AuthSubmit {
        pw: Password::new("pw".to_owned()),
        pw2: Password::new(String::new()),
        remember: false,
    });

    assert!(
        c.state().auth.open,
        "the refusal keeps the modal (and the durable risk grant) intact"
    );
    assert!(
        c.state().auth.error.contains("Could not verify"),
        "the refusal explains the unresolved check: {}",
        c.state().auth.error
    );
    assert!(
        !c.state().key_busy,
        "no password ceremony may start unverified"
    );

    c.state_mut().recipient_check = RecipientCheck::Known(DestinationAccountStatus::Uninit);
    assert!(c.state().recipient_send_permitted(true));
    assert!(!c.state().recipient_send_permitted(false));
    cleanup(&dir);
}

#[test]
fn a_clipboard_problem_suppresses_the_copy_countdown() {
    let dir = temp_dir("copy-ttl-degraded");
    let mut c = unlocked(&dir, WalletProfile::default());
    let _mem = mem_clipboard(&mut c);

    c.copy_seed_to_clipboard(seed_input(TEST_SEED));
    assert_eq!(c.state().seed_copy_ttl_secs, 60);

    c.state_mut().clipboard_notice = "Could not clear every clipboard selection".to_owned();
    c.tick();
    assert_eq!(c.state().seed_copy_ttl_secs, 0);
    cleanup(&dir);
}

#[test]
fn the_copy_countdown_publishes_the_real_clipboard_ttl() {
    let dir = temp_dir("copy-ttl");
    let mut c = unlocked(&dir, WalletProfile::default());
    let _mem = mem_clipboard(&mut c);

    assert_eq!(c.state().seed_copy_ttl_secs, 0);
    c.copy_seed_to_clipboard(seed_input(TEST_SEED));
    assert_eq!(
        c.state().seed_copy_ttl_secs,
        60,
        "an explicit copy starts the full clipboard TTL"
    );

    c.clipboard_deadline = Some(crate::state::Deadline::after(std::time::Duration::ZERO));
    c.tick();
    assert_eq!(
        c.state().seed_copy_ttl_secs,
        0,
        "the countdown ends exactly when the wipe clears the clipboard"
    );
    cleanup(&dir);
}

#[test]
fn a_pasted_phrase_arms_the_wipe_without_a_copy_countdown() {
    let dir = temp_dir("paste-no-ttl");
    let mut c = controller(&dir);
    let mem = mem_clipboard(&mut c);
    c.state_mut().phase = AppPhase::Onboarding;

    let phrase = generated_seed_phrase();
    mem.board.borrow_mut().clipboard = phrase.clone();
    c.handle_command(AppCommand::OnboardImportSeed(seed_input(phrase)));

    assert!(
        c.clipboard_deadline.is_some(),
        "the pasted phrase is still wiped on the deadline"
    );
    assert_eq!(
        c.state().seed_copy_ttl_secs,
        0,
        "a paste the wallet did not perform must not claim a copy countdown"
    );
    cleanup(&dir);
}

#[test]
fn an_inactive_destination_stays_bounceable_unless_explicitly_opted_in() {
    let dir = temp_dir("dest-bounce");
    let mut c = unlocked(&dir, WalletProfile::default());
    let dest = "0:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_owned();
    c.state_mut().send_form.destination = dest.clone();

    c.apply_event(AppEvent::DestinationChecked {
        generation: c.subscription_generation,
        seq: c.dest_check_seq,
        address: dest,
        status: Some(DestinationAccountStatus::NonExist),
    });
    assert_eq!(
        c.state().recipient_check,
        RecipientCheck::Known(DestinationAccountStatus::NonExist)
    );
    assert!(c.state().recipient_inactive());
    assert!(
        c.state().send_bounce(),
        "an inactive destination is bounceable by default so a typo returns the funds"
    );

    c.handle_command(AppCommand::SetAllowUnbounced(true));
    assert!(
        !c.state().send_bounce(),
        "an explicit opt-in funds a new address non-bounceably"
    );

    c.state_mut().recipient_check = RecipientCheck::Known(DestinationAccountStatus::Active);
    assert!(
        c.state().send_bounce(),
        "an active destination is always sent bounceable regardless of the opt-in"
    );
    cleanup(&dir);
}

#[test]
fn a_second_topup_to_the_same_address_re_runs_the_destination_check() {
    let dir = temp_dir("dest-recheck");
    let mut c = unlocked(&dir, WalletProfile::default());
    let dest = "0:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_owned();
    c.state_mut().send_form.destination = dest.clone();

    c.apply_event(AppEvent::DestinationChecked {
        generation: c.subscription_generation,
        seq: c.dest_check_seq,
        address: dest.clone(),
        status: Some(DestinationAccountStatus::NonExist),
    });
    assert!(
        !c.needs_destination_check(),
        "a same address with a known status is debounced"
    );

    c.state_mut().reset_recipient_status();
    assert!(
        c.needs_destination_check(),
        "with no current status the same address is re-checked, not skipped"
    );

    c.apply_event(AppEvent::DestinationChecked {
        generation: c.subscription_generation,
        seq: c.dest_check_seq,
        address: dest.clone(),
        status: Some(DestinationAccountStatus::NonExist),
    });
    assert!(
        c.state().recipient_inactive(),
        "a follow-up top-up to a now-Uninit address still offers the non-bounce opt-in"
    );
    cleanup(&dir);
}

#[test]
fn changing_the_destination_resets_the_unbounced_opt_in() {
    let dir = temp_dir("dest-reset");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.state_mut().allow_unbounced = true;
    c.state_mut().recipient_check = RecipientCheck::Known(DestinationAccountStatus::Uninit);

    c.handle_command(AppCommand::SetSendDestination(
        "0:abcdef1234567890".to_owned(),
    ));
    assert!(
        !c.state().allow_unbounced,
        "a new recipient clears the opt-in"
    );
    assert_eq!(
        c.state().recipient_check,
        RecipientCheck::Unchecked,
        "the new recipient has not been checked yet"
    );
    cleanup(&dir);
}

#[test]
fn generating_a_new_phrase_never_lets_autosave_overwrite_the_funded_seed() {
    let dir = temp_dir("seed-stage");
    let mut c = unlocked(
        &dir,
        WalletProfile {
            seed: test_seed(),
            ..WalletProfile::default()
        },
    );
    assert_eq!(c.state().confirmed_seed.expose_secret(), TEST_SEED);

    c.handle_command(AppCommand::GenerateSeed);
    assert!(c.state().seed_unsaved);
    assert_ne!(
        c.state().seed.expose_secret(),
        TEST_SEED,
        "a fresh candidate is staged for display"
    );
    assert_eq!(
        c.state().to_profile().seed.expose_secret(),
        TEST_SEED,
        "the autosave payload keeps the confirmed funded seed, not the candidate"
    );

    c.handle_command(AppCommand::DiscardSeed);
    assert!(!c.state().seed_unsaved);
    assert_eq!(
        c.state().seed.expose_secret(),
        TEST_SEED,
        "discard reverts to the funded seed from memory, never an empty string"
    );
    assert!(c.state().seed_saved);
    cleanup(&dir);
}

#[test]
fn committing_a_staged_phrase_updates_the_confirmed_seed() {
    let dir = temp_dir("seed-commit");
    let mut c = unlocked(
        &dir,
        WalletProfile {
            seed: test_seed(),
            ..WalletProfile::default()
        },
    );
    c.handle_command(AppCommand::GenerateSeed);
    let candidate = Arc::clone(&c.state().seed);

    c.handle_command(AppCommand::UseSeed);

    assert!(!c.state().seed_unsaved);
    assert_eq!(c.state().seed, candidate);
    assert_eq!(
        c.state().confirmed_seed,
        candidate,
        "committing promotes the candidate to the confirmed seed"
    );
    assert_eq!(c.state().to_profile().seed, candidate);
    cleanup(&dir);
}

#[test]
fn verify_network_id_blocks_sends_on_a_network_mismatch() {
    let dir = temp_dir("net-mismatch");
    let mut c = unlocked(&dir, WalletProfile::default());
    let mut wallet = timed_wallet("0:me");
    set_native_balance(&mut wallet, 5_000_000_000);
    c.state_mut().wallet = Some(wallet);
    c.state_mut().send_form.destination =
        "0:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_owned();
    c.state_mut().send_form.amount = "1.0".to_owned();
    assert!(c.state().send_enabled());

    let mut mismatched = wallet_with_native("0:me", 5_000_000_000);
    mismatched.global_id = 2000;
    let load_gen = c.subscription_generation;
    apply_owned_load(&mut c, load_gen, mismatched);
    assert!(c.state().network_mismatch);
    assert!(
        !c.state().send_enabled(),
        "a network mismatch must block sending"
    );
    c.state_mut().network_mismatch = false;
    assert!(c.state().send_enabled());
    cleanup(&dir);
}

#[test]
fn lock_reconstructs_state_and_cannot_leak_a_stale_selected_asset() {
    let dir = temp_dir("lock-reconstruct");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.state_mut().active_wallet = "keep".to_owned();
    c.state_mut().wallet_names = vec!["keep".to_owned(), "other".to_owned()];
    c.state_mut().set_asset_visibility(1, true);
    c.state_mut().select_asset(AssetId::CurrencyCollection(1));
    assert_eq!(c.state().selected_asset, AssetId::CurrencyCollection(1));

    c.lock();

    assert_eq!(c.state().selected_asset, AssetId::Native);
    assert_eq!(
        c.state().send_form.token,
        cc_wallet_domain::SendToken::Native
    );
    assert_eq!(c.state().phase, AppPhase::Locked);
    assert_eq!(c.state().active_wallet, "keep");
    assert_eq!(
        c.state().wallet_names,
        vec!["keep".to_owned(), "other".to_owned()]
    );
    assert!(c.state().seed.is_empty());
    assert!(c.state().wallet.is_none());
    assert!(c.state().activity.is_empty());
    cleanup(&dir);
}

#[test]
fn a_send_in_flight_blocks_a_repeat_confirm() {
    let dir = temp_dir("double-send");
    let mut c = unlocked(&dir, WalletProfile::default());
    let mut wallet = timed_wallet("0:me");
    set_native_balance(&mut wallet, 5_000_000_000);
    c.state_mut().wallet = Some(wallet);
    c.state_mut().send_form.destination =
        "0:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_owned();
    c.state_mut().send_form.amount = "1.0".to_owned();

    c.state_mut().sending = true;
    assert!(
        !c.state().send_enabled(),
        "the Send button must be disabled while a send is in flight"
    );
    let before = c.state().activity.len();

    c.dispatch_test_authorization();
    assert_eq!(c.state().activity.len(), before, "no second optimistic row");
    cleanup(&dir);
}

#[test]
fn a_stale_auto_load_does_not_clear_a_newer_refresh_guard() {
    let dir = temp_dir("stale-autoload");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.wallet_load_seq = 2;
    c.load.wallet_auto_refresh_id = Some(2);
    c.state_mut().auto_refreshing = true;

    c.apply_event(AppEvent::WalletAutoLoaded {
        generation: c.subscription_generation.wrapping_sub(1),
        request_id: 1,
        snapshot: timed_wallet("0:me"),
    });

    assert!(
        c.state().auto_refreshing,
        "a stale result must not release the guard owned by a newer request"
    );
    assert_eq!(c.load.wallet_auto_refresh_id, Some(2));
    cleanup(&dir);
}

#[test]
fn a_post_confirmation_refresh_is_redriven_after_an_older_snapshot() {
    let dir = temp_dir("queued-autoload");
    let (mut c, fake) = ready_to_send(&dir);
    c.ensure_subscription(SEND_DEST.to_owned());
    let generation = c.subscription_generation;

    c.wallet_load_seq = 7;
    c.load.wallet_auto_refresh_id = Some(7);
    c.state_mut().auto_refreshing = true;

    let mut fresh = timed_wallet(SEND_DEST);
    set_native_balance(&mut fresh, 9_000_000_000);
    fake.set_load_wallet(Ok(fresh));

    c.auto_refresh_wallet(generation);
    assert!(c.load.wallet_auto_refresh_again);
    assert_eq!(fake.load_wallet_calls(), 0);

    let mut older = timed_wallet(SEND_DEST);
    set_native_balance(&mut older, 1_000_000_000);
    c.apply_event(AppEvent::WalletAutoLoaded {
        generation,
        request_id: 7,
        snapshot: older,
    });
    c.pump_events();

    assert_eq!(fake.load_wallet_calls(), 1);
    assert_eq!(
        c.state().wallet.as_ref().unwrap().native_balance(),
        9_000_000_000
    );
    assert!(c.load.wallet_auto_refresh_id.is_none());
    assert!(!c.load.wallet_auto_refresh_again);
    assert!(!c.state().auto_refreshing);
    cleanup(&dir);
}

#[test]
fn a_queued_auto_refresh_moves_to_the_reconnected_generation() {
    let dir = temp_dir("queued-autoload-reconnect");
    let (mut c, fake) = ready_to_send(&dir);
    let old_generation = c.subscription_generation;
    c.wallet_load_seq = 11;
    c.load.wallet_auto_refresh_id = Some(11);
    c.state_mut().auto_refreshing = true;

    let mut fresh = timed_wallet(SEND_DEST);
    set_native_balance(&mut fresh, 8_000_000_000);
    fake.set_load_wallet(Ok(fresh));
    c.auto_refresh_wallet(old_generation);
    assert!(c.load.wallet_auto_refresh_again);

    c.subscription_generation = c.subscription_generation.wrapping_add(1);
    c.apply_event(AppEvent::WalletAutoLoaded {
        generation: old_generation,
        request_id: 11,
        snapshot: wallet_with_native(SEND_DEST, 1_000_000_000),
    });
    c.pump_events();

    assert_eq!(fake.load_wallet_calls(), 1);
    assert_eq!(
        c.state().wallet.as_ref().unwrap().native_balance(),
        8_000_000_000
    );
    assert!(c.load.wallet_auto_refresh_id.is_none());
    assert!(!c.load.wallet_auto_refresh_again);
    assert!(!c.state().auto_refreshing);
    cleanup(&dir);
}

#[test]
fn an_auto_load_flags_a_network_mismatch() {
    let dir = temp_dir("autoload-netcheck");
    let mut c = unlocked(&dir, WalletProfile::default());
    assert_eq!(c.state().network_id, 0);

    let mut snapshot = timed_wallet("0:me");
    snapshot.global_id = 2000;
    let generation = c.subscription_generation;
    apply_owned_auto_load(&mut c, generation, snapshot);

    assert!(
        c.state().network_mismatch,
        "an auto-refresh that lands on the wrong network is flagged, not silently trusted"
    );
    assert!(
        c.state().wallet.is_none(),
        "a wrong-network auto-load snapshot is never adopted"
    );
    assert!(
        c.load.wallet_auto_refresh_id.is_none(),
        "auto-refresh bookkeeping is drained"
    );
    assert!(!c.state().auto_refreshing);
    cleanup(&dir);
}

#[test]
fn a_mismatched_wallet_load_is_never_adopted() {
    let dir = temp_dir("mismatch-not-adopted");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.state_mut().wallet = None;
    c.state_mut().activity.clear();

    let mut mismatched = wallet_with_native("0:me", 5_000_000_000);
    mismatched.global_id = c.state().network_id + 1;
    let load_gen = c.subscription_generation;
    apply_owned_load(&mut c, load_gen, mismatched);

    assert!(c.state().network_mismatch);
    assert!(
        c.state().wallet.is_none(),
        "a wrong-network snapshot is never stored"
    );
    assert!(
        c.state().activity.is_empty(),
        "no foreign-network history is fetched or merged"
    );
    assert!(
        !c.load.fetch_in_flight,
        "no history fetch is started while mismatched"
    );
    assert!(
        c.subscription_task.is_none(),
        "no subscription is opened while mismatched"
    );
    assert!(
        c.state().subscription_status.contains("different network"),
        "subscription status reflects the mismatch, got {:?}",
        c.state().subscription_status
    );
    assert!(
        c.state()
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("network"),
        "the error explains the mismatch"
    );
    cleanup(&dir);
}

#[test]
fn fetch_and_subscribe_are_inert_while_mismatched() {
    let dir = temp_dir("mismatch-inert");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.state_mut().network_mismatch = true;

    c.fetch_transactions(c.subscription_generation);
    c.ensure_subscription("0:me".to_owned());

    assert!(!c.load.fetch_in_flight, "no fetch starts while mismatched");
    assert!(
        c.subscription_task.is_none(),
        "no subscription opens while mismatched"
    );
    cleanup(&dir);
}

#[test]
fn a_key_result_is_single_use() {
    let dir = temp_dir("single-use-key");
    let mut c = unlocked(&dir, WalletProfile::default());
    let generation = c.key_generation();

    c.apply_key_msg(KeyMsg::Ok {
        history_corrupt: false,
        journal: cc_wallet_domain::JournalEnvelope::empty(),
        selected: None,
        writer: None,
        generation,
        action: KeyAction::ChangePassword,
        vault: Vault::create_with(PW, CHEAP).unwrap(),
        profile: WalletProfile::default(),
        history: Vec::new(),
    });
    assert_ne!(
        c.key_generation(),
        generation,
        "consuming a key result invalidates its generation"
    );

    c.state_mut().status = "sentinel".to_owned();
    c.apply_key_msg(KeyMsg::Ok {
        history_corrupt: false,
        journal: cc_wallet_domain::JournalEnvelope::empty(),
        selected: None,
        writer: None,
        generation,
        action: KeyAction::ChangePassword,
        vault: Vault::create_with(PW, CHEAP).unwrap(),
        profile: WalletProfile::default(),
        history: Vec::new(),
    });
    assert_eq!(
        c.state().status,
        "sentinel",
        "a duplicate key message for an already-consumed generation is dropped"
    );
    cleanup(&dir);
}

#[test]
fn the_history_incomplete_banner_clears_on_a_later_clean_fetch() {
    let dir = temp_dir("history-incomplete");
    let mut c = unlocked(&dir, WalletProfile::default());
    let generation = c.subscription_generation;

    c.apply_event(AppEvent::TransactionsLoaded {
        generation,
        fetch_id: 0,
        head_refresh_only: false,
        events: vec![],
        integrity_error: None,
        incomplete: true,
        gap: true,
        deepest_lt: None,
    });
    assert!(
        c.state().history_incomplete,
        "an incomplete fetch raises the banner"
    );

    c.apply_event(AppEvent::TransactionsLoaded {
        generation,
        fetch_id: 0,
        head_refresh_only: false,
        events: vec![],
        integrity_error: None,
        incomplete: false,
        gap: false,
        deepest_lt: Some(100),
    });
    assert!(
        !c.state().history_incomplete,
        "a later clean fetch clears the banner even with no new events"
    );
    cleanup(&dir);
}

#[test]
fn malformed_full_width_history_blocks_signing_until_a_complete_valid_refresh() {
    let dir = temp_dir("history-amount-integrity");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.state_mut().wallet = Some(wallet_with_native("0:me", 2_000_000_000));
    c.state_mut().send_form.destination =
        "0:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_owned();
    c.state_mut().send_form.amount = "1.0".to_owned();
    assert!(c.state().send_enabled());
    let generation = c.subscription_generation;

    c.apply_event(AppEvent::TransactionsLoaded {
        generation,
        fetch_id: 0,
        head_refresh_only: false,
        events: Vec::new(),
        integrity_error: Some(
            "transaction extra-currency 77 has invalid amount \"2^248\"".to_owned(),
        ),
        incomplete: true,
        gap: true,
        deepest_lt: None,
    });
    assert!(!c.state().send_enabled());
    assert!(
        c.state()
            .history_integrity_error
            .as_deref()
            .is_some_and(|error| error.contains("extra-currency 77"))
    );

    c.apply_event(AppEvent::TransactionsLoaded {
        generation,
        fetch_id: 0,
        head_refresh_only: false,
        events: Vec::new(),
        integrity_error: None,
        incomplete: true,
        gap: false,
        deepest_lt: Some(100),
    });
    assert!(!c.state().send_enabled());

    c.apply_event(AppEvent::TransactionsLoaded {
        generation,
        fetch_id: 0,
        head_refresh_only: false,
        events: Vec::new(),
        integrity_error: None,
        incomplete: false,
        gap: false,
        deepest_lt: Some(100),
    });
    assert!(c.state().history_integrity_error.is_none());
    assert!(c.state().send_enabled());
    cleanup(&dir);
}

#[test]
fn a_failed_fresh_snapshot_blocks_the_old_balance_until_a_valid_replacement() {
    let dir = temp_dir("snapshot-amount-integrity");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.state_mut().wallet = Some(wallet_with_native("0:me", 2_000_000_000));
    c.state_mut().send_form.destination =
        "0:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_owned();
    c.state_mut().send_form.amount = "1.0".to_owned();
    assert!(c.state().send_enabled());
    let generation = c.subscription_generation;

    apply_owned_load_failed(
        &mut c,
        generation,
        "extra-currency 9 balance is outside VarUint248".to_owned(),
    );
    assert!(!c.state().send_enabled());
    assert!(c.state().snapshot_refresh_error.is_some());

    apply_owned_auto_load(
        &mut c,
        generation,
        wallet_with_native("0:me", 2_000_000_000),
    );
    assert!(c.state().snapshot_refresh_error.is_none());
    assert!(c.state().send_enabled());
    cleanup(&dir);
}

#[test]
fn a_fetch_while_one_is_in_flight_is_coalesced_not_duplicated() {
    let dir = temp_dir("fetch-coalesce");
    let mut c = unlocked(&dir, WalletProfile::default());
    let generation = c.subscription_generation;

    c.load.fetch_in_flight = true;
    c.fetch_transactions(generation);
    c.fetch_transactions(generation);

    assert!(
        c.load.fetch_in_flight,
        "the in-flight walk is left running, not restarted"
    );
    assert!(
        c.load.fetch_again,
        "overlapping requests are remembered for one re-run, not spawned concurrently"
    );
    cleanup(&dir);
}

#[test]
fn a_stale_transactions_result_still_clears_the_fetch_guard() {
    let dir = temp_dir("fetch-guard-clear");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.load.fetch_in_flight = true;
    c.load.fetch_in_flight_id = Some(77);

    c.apply_event(AppEvent::TransactionsLoaded {
        generation: c.subscription_generation.wrapping_add(9),
        fetch_id: 77,
        head_refresh_only: false,
        events: vec![],
        integrity_error: None,
        incomplete: false,
        gap: false,
        deepest_lt: None,
    });
    assert!(
        !c.load.fetch_in_flight,
        "a stale-generation result clears the in-flight guard"
    );
    cleanup(&dir);
}

#[test]
fn an_old_fetch_completion_cannot_release_a_new_session_fetch_guard() {
    let dir = temp_dir("fetch-owner-isolation");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.load.fetch_in_flight = true;
    c.load.fetch_in_flight_id = Some(102);

    c.apply_event(AppEvent::TransactionsLoaded {
        generation: c.subscription_generation.wrapping_sub(1),
        fetch_id: 101,
        head_refresh_only: false,
        events: vec![],
        integrity_error: None,
        incomplete: true,
        gap: true,
        deepest_lt: None,
    });

    assert!(c.load.fetch_in_flight);
    assert_eq!(c.load.fetch_in_flight_id, Some(102));
    cleanup(&dir);
}

#[test]
fn an_old_scan_result_cannot_consume_the_new_fetchs_continuation() {
    let dir = temp_dir("fetch-scan-owner-isolation");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.load.fetch_in_flight = true;
    c.load.fetch_in_flight_id = Some(202);
    c.load.history_reconciliation_scan = Some(HistoryReconciliationScan {
        next_before_lt: 500,
        stop_at: Some(900),
        age_cutoff: None,
        deepest_lt: Some(500),
        observations: Vec::new(),
        automatic_continuations_remaining: 0,
    });

    c.apply_event(AppEvent::EndpointHistoryScanned {
        generation: c.subscription_generation,
        fetch_id: 201,
        head_refresh_only: false,
        observations: Vec::new(),
        scan_start_before_lt: Some(500),
        scan_stop_at: Some(900),
        scan_age_cutoff: None,
        continuation_before_lt: None,
        deepest_lt: Some(400),
        gap: false,
    });

    let scan = c
        .load
        .history_reconciliation_scan
        .as_ref()
        .expect("the new owner's continuation remains installed");
    assert_eq!(scan.next_before_lt, 500);
    assert_eq!(c.load.fetch_in_flight_id, Some(202));
    cleanup(&dir);
}

#[test]
fn a_scan_that_ran_out_of_continuations_still_refreshes_the_head() {
    let dir = temp_dir("fetch-stranded-scan");
    let (mut c, fake) = ready_to_send(&dir);
    c.load.history_reconciliation_scan = Some(HistoryReconciliationScan {
        next_before_lt: 500,
        stop_at: None,
        age_cutoff: None,
        deepest_lt: Some(500),
        observations: Vec::new(),
        automatic_continuations_remaining: 0,
    });
    c.load.fetch_in_flight = true;
    c.load.fetch_in_flight_id = Some(401);
    c.load.fetch_again = false;
    c.load.fetch_head_after_history_scan = false;

    c.apply_event(AppEvent::TransactionsLoaded {
        generation: c.subscription_generation,
        fetch_id: 401,
        head_refresh_only: false,
        events: Vec::new(),
        integrity_error: None,
        incomplete: true,
        gap: false,
        deepest_lt: Some(500),
    });
    c.pump_events();

    assert!(
        !fake.transaction_before_lts().is_empty(),
        "nothing was scheduled: the scan is stranded, so the head is never re-read and new \
         transactions — a swap's own legs among them — never reach merge_activity"
    );
    assert!(
        fake.transaction_before_lts().contains(&None),
        "the follow-up must read the HEAD (before_lt = None), not walk further back; \
         windows requested were {:?}",
        fake.transaction_before_lts()
    );
    cleanup(&dir);
}

#[test]
fn a_stale_owned_completion_redrives_the_current_generations_scan() {
    let dir = temp_dir("fetch-stale-owner-redrive");
    let (mut c, fake) = ready_to_send(&dir);
    c.load.history_reconciliation_scan = Some(HistoryReconciliationScan {
        next_before_lt: 500,
        stop_at: None,
        age_cutoff: None,
        deepest_lt: Some(500),
        observations: Vec::new(),
        automatic_continuations_remaining: 0,
    });
    c.load.fetch_in_flight = true;
    c.load.fetch_in_flight_id = Some(301);
    c.load.fetch_again = true;

    c.apply_event(AppEvent::TransactionsLoaded {
        generation: c.subscription_generation.wrapping_sub(1),
        fetch_id: 301,
        head_refresh_only: false,
        events: Vec::new(),
        integrity_error: None,
        incomplete: true,
        gap: false,
        deepest_lt: Some(500),
    });

    assert!(c.load.fetch_in_flight);
    assert_ne!(c.load.fetch_in_flight_id, Some(301));
    assert!(c.load.fetch_head_after_history_scan);
    c.pump_events();
    assert_eq!(fake.transaction_before_lts(), vec![Some(500), None]);
    cleanup(&dir);
}

#[test]
fn an_interrupted_fetch_forces_the_next_fetch_to_close_the_gap() {
    let dir = temp_dir("history-gap");
    let mut c = unlocked(&dir, WalletProfile::default());
    let generation = c.subscription_generation;

    c.apply_event(AppEvent::TransactionsLoaded {
        generation,
        fetch_id: 0,
        head_refresh_only: false,
        events: vec![],
        integrity_error: None,
        incomplete: false,
        gap: false,
        deepest_lt: Some(500),
    });
    assert_eq!(c.session.history_synced_floor, Some(500));
    assert!(!c.session.history_has_gap);

    c.apply_event(AppEvent::TransactionsLoaded {
        generation,
        fetch_id: 0,
        head_refresh_only: false,
        events: vec![],
        integrity_error: None,
        incomplete: true,
        gap: true,
        deepest_lt: Some(450),
    });
    assert_eq!(
        c.session.history_synced_floor,
        Some(500),
        "a gapped fetch never advances the no-gap floor"
    );
    assert!(
        c.session.history_has_gap,
        "an RPC error flags a gap so the next fetch re-walks to close it"
    );

    c.apply_event(AppEvent::TransactionsLoaded {
        generation,
        fetch_id: 0,
        head_refresh_only: false,
        events: vec![],
        integrity_error: None,
        incomplete: false,
        gap: false,
        deepest_lt: Some(300),
    });
    assert_eq!(
        c.session.history_synced_floor,
        Some(300),
        "the floor only extends downward"
    );
    assert!(
        !c.session.history_has_gap,
        "the gap is closed by a clean fetch"
    );

    c.apply_event(AppEvent::TransactionsLoaded {
        generation,
        fetch_id: 0,
        head_refresh_only: false,
        events: vec![],
        integrity_error: None,
        incomplete: false,
        gap: false,
        deepest_lt: Some(900),
    });
    assert_eq!(
        c.session.history_synced_floor,
        Some(300),
        "a clean fetch that stops at the newest known tx keeps the deeper floor"
    );
    cleanup(&dir);
}

#[test]
fn an_empty_account_fetch_does_not_poison_the_no_gap_floor() {
    let dir = temp_dir("history-empty");
    let mut c = unlocked(&dir, WalletProfile::default());
    let generation = c.subscription_generation;

    c.apply_event(AppEvent::TransactionsLoaded {
        generation,
        fetch_id: 0,
        head_refresh_only: false,
        events: vec![],
        integrity_error: None,
        incomplete: false,
        gap: false,
        deepest_lt: None,
    });
    assert_eq!(
        c.session.history_synced_floor, None,
        "an empty account leaves the floor unset, never poisoned to a high sentinel"
    );
    assert!(!c.session.history_has_gap);
    cleanup(&dir);
}

#[test]
fn an_incomplete_batch_without_scan_progress_never_advances_the_trusted_floor() {
    let dir = temp_dir("history-budget");
    let mut c = unlocked(&dir, WalletProfile::default());
    let generation = c.subscription_generation;

    c.apply_event(AppEvent::TransactionsLoaded {
        generation,
        fetch_id: 0,
        head_refresh_only: false,
        events: vec![],
        integrity_error: None,
        incomplete: true,
        gap: false,
        deepest_lt: Some(700),
    });
    assert_eq!(c.session.history_synced_floor, None);
    assert!(
        c.session.history_has_gap,
        "an incomplete event without scan progress cannot clear the prior refetch obligation"
    );
    assert!(
        c.state().history_incomplete,
        "but the view is still flagged incomplete"
    );
    cleanup(&dir);
}

const HISTORY_NOW: u64 = 1_800_000_000;

fn history_event(lt: u64, time_unix: u64, asset: AssetId) -> ActivityEvent {
    ActivityEvent {
        direction: ActivityDirection::In,
        tx_hash: optional_digest(&format!("tx{lt}")),
        counterparty: "0:src".to_owned(),
        movements: vec![movement(asset, 1)],
        ..ActivityEvent::test_stub(lt, time_unix)
    }
}

#[test]
fn history_is_capped_but_keeps_every_pending_row() {
    let dir = temp_dir("history-cap");
    let mut c = unlocked(&dir, WalletProfile::default());
    for lt in 0..(super::MAX_HISTORY as u64 + 200) {
        c.state_mut()
            .activity
            .push(history_event(lt, HISTORY_NOW, AssetId::Native));
    }
    let request = native_request(SEND_DEST, 1);
    c.push_pending_send(&request);
    c.sort_activity();
    c.cap_history_at(HISTORY_NOW);

    assert_eq!(
        c.state().activity.iter().filter(|e| e.pending).count(),
        1,
        "the pending row survives the cap"
    );
    assert_eq!(
        c.state().activity.iter().filter(|e| !e.pending).count(),
        super::MAX_HISTORY,
        "confirmed rows are capped to MAX_HISTORY even when all are recent"
    );
    let newest = c
        .state()
        .activity
        .iter()
        .filter(|e| !e.pending)
        .map(|e| e.lt)
        .max()
        .unwrap();
    assert_eq!(
        newest,
        super::MAX_HISTORY as u64 + 199,
        "the newest rows are kept"
    );
    cleanup(&dir);
}

#[test]
fn history_count_cap_preserves_the_complete_boundary_lt_tie() {
    let dir = temp_dir("history-cap-lt-tie");
    let mut c = unlocked(&dir, WalletProfile::default());
    for index in 0..(super::MAX_HISTORY - 1) {
        c.state_mut().activity.push(history_event(
            10_000 + index as u64,
            HISTORY_NOW,
            AssetId::Native,
        ));
    }
    for index in 0..3 {
        let mut event = history_event(100, HISTORY_NOW, AssetId::Native);
        event.tx_hash = optional_digest(&format!("boundary-{index}"));
        c.state_mut().activity.push(event);
    }
    c.state_mut()
        .activity
        .push(history_event(99, HISTORY_NOW, AssetId::Native));
    c.sort_activity();
    c.cap_history_at(HISTORY_NOW);

    assert_eq!(
        c.state()
            .activity
            .iter()
            .filter(|event| event.lt == 100)
            .count(),
        3,
        "every row in the authenticated-LT boundary tie is retained"
    );
    assert!(c.state().activity.iter().all(|event| event.lt != 99));
    assert_eq!(c.state().activity.len(), super::MAX_HISTORY + 2);
    cleanup(&dir);
}

#[test]
fn history_keeps_the_last_ten_of_an_idle_asset_past_the_age_window() {
    let dir = temp_dir("history-idle-asset");
    let mut c = unlocked(&dir, WalletProfile::default());
    let old = HISTORY_NOW - super::HISTORY_MAX_AGE_SECS - 10_000;
    for lt in 200..220u64 {
        c.state_mut()
            .activity
            .push(history_event(lt, HISTORY_NOW, AssetId::Native));
    }
    for lt in 100..115u64 {
        c.state_mut()
            .activity
            .push(history_event(lt, old, AssetId::CurrencyCollection(1)));
    }
    c.sort_activity();
    c.cap_history_at(HISTORY_NOW);

    let idle = c
        .state()
        .activity
        .iter()
        .filter(|e| e.moves_asset(AssetId::CurrencyCollection(1)))
        .count();
    assert_eq!(
        idle,
        super::HISTORY_MIN_KEEP,
        "the newest 10 of an idle token survive past the age window"
    );
    let recent_native = c
        .state()
        .activity
        .iter()
        .filter(|e| e.moves_asset(AssetId::Native))
        .count();
    assert_eq!(
        recent_native, 20,
        "recent rows are all kept by the age rule"
    );
    cleanup(&dir);
}

#[test]
fn history_with_only_an_old_chain_head_preserves_more() {
    let dir = temp_dir("history-old-drop");
    let mut c = unlocked(&dir, WalletProfile::default());
    let old = HISTORY_NOW - super::HISTORY_MAX_AGE_SECS - 10_000;
    for lt in 0..50u64 {
        c.state_mut()
            .activity
            .push(history_event(lt, old, AssetId::Native));
    }
    c.sort_activity();
    c.cap_history_at(HISTORY_NOW);

    let kept: Vec<u64> = c.state().activity.iter().map(|e| e.lt).collect();
    assert_eq!(
        kept.len(),
        50,
        "an old-only chain head moves the age anchor backwards and preserves more"
    );
    assert_eq!(
        *kept.iter().max().unwrap(),
        49,
        "and it is the newest rows that are kept"
    );
    cleanup(&dir);
}

#[test]
fn loading_old_only_history_uses_the_conservative_chain_anchor() {
    let dir = temp_dir("history-load-cap");
    let mut c = controller(&dir);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let old = now - super::HISTORY_MAX_AGE_SECS - 10_000;
    let history: Vec<ActivityEvent> = (0..40u64)
        .map(|lt| history_event(lt, old, AssetId::Native))
        .collect();
    let vault = Vault::create_with(PW, CHEAP).unwrap();
    let writer = c.store.writer_for_new().unwrap();
    c.apply_key_msg(KeyMsg::Ok {
        history_corrupt: false,
        journal: cc_wallet_domain::JournalEnvelope::empty(),
        selected: None,
        writer: Some(writer),
        generation: c.key_generation(),
        history,
        action: KeyAction::Unlock,
        vault,
        profile: WalletProfile::default(),
    });

    let kept: Vec<u64> = c
        .state()
        .activity
        .iter()
        .filter(|e| !e.pending)
        .map(|e| e.lt)
        .collect();
    assert_eq!(
        kept.len(),
        40,
        "old-only loaded history is preserved relative to its own newest chain time"
    );
    assert_eq!(
        *kept.iter().max().unwrap(),
        39,
        "and the newest loaded rows are the ones kept"
    );
    cleanup(&dir);
}

#[test]
fn changing_the_password_revokes_the_autosign_window() {
    let dir = temp_dir("rekey-autosign");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.state_mut().extend_autosign();
    assert!(c.state().within_autosign(), "the auto-sign window is open");

    let vault = Vault::create_with(b"a-new-password!!", CHEAP).unwrap();
    c.apply_key_msg(KeyMsg::Ok {
        history_corrupt: false,
        journal: cc_wallet_domain::JournalEnvelope::empty(),
        selected: None,
        writer: None,
        generation: c.key_generation(),
        action: KeyAction::ChangePassword,
        vault,
        profile: WalletProfile::default(),
        history: Vec::new(),
    });

    assert!(
        !c.state().within_autosign(),
        "changing the password revokes the cached authorization"
    );
    assert!(c.state().autosign_until.is_none());
    cleanup(&dir);
}

#[test]
fn a_cancelled_change_password_never_touches_the_container() {
    let dir = temp_dir("cancel-rekey");
    let mut c = unlocked(
        &dir,
        WalletProfile {
            seed: test_seed(),
            ..WalletProfile::default()
        },
    );
    c.flush_save_blocking();
    assert!(
        c.store.unlock(PW).is_ok(),
        "the created container opens with its password"
    );

    let stale = c.key_generation();
    c.cancel_auth();
    let rekeyed = Vault::create_with(b"a-brand-new-pass", CHEAP).unwrap();
    c.apply_key_msg(KeyMsg::Ok {
        history_corrupt: false,
        journal: cc_wallet_domain::JournalEnvelope::empty(),
        selected: None,
        writer: None,
        generation: stale,
        action: KeyAction::ChangePassword,
        vault: rekeyed,
        profile: WalletProfile::default(),
        history: Vec::new(),
    });
    c.flush_save_blocking();

    assert!(
        c.store.unlock(PW).is_ok(),
        "the original password still opens the wallet"
    );
    assert!(
        c.store.unlock(b"a-brand-new-pass").is_err(),
        "a cancelled re-key is never written to disk, so it cannot revert or lock out the wallet"
    );
    cleanup(&dir);
}

#[test]
fn a_stale_key_result_is_discarded_after_a_context_switch() {
    let dir = temp_dir("stale-key");
    let mut c = unlocked(&dir, WalletProfile::default());
    let stale = c.key_generation();
    c.cancel_auth();
    assert_ne!(stale, c.key_generation());

    let vault = Vault::create_with(PW, CHEAP).unwrap();
    c.apply_key_msg(KeyMsg::Ok {
        history_corrupt: false,
        journal: cc_wallet_domain::JournalEnvelope::empty(),
        selected: None,
        writer: None,
        generation: stale,
        history: Vec::new(),
        action: KeyAction::DeleteWallet,
        vault,
        profile: WalletProfile::default(),
    });

    assert_eq!(c.state().phase, AppPhase::Unlocked);
    cleanup(&dir);
}

#[test]
fn replacing_the_seed_clears_the_old_identitys_activity() {
    let dir = temp_dir("seed-replace-activity");
    let profile = WalletProfile {
        seed: test_seed(),
        ..WalletProfile::default()
    };
    let mut c = unlocked(&dir, profile);
    c.state_mut().derived_wallet_address = "0:old-address".to_owned();
    c.state_mut().activity.push(ActivityEvent {
        direction: ActivityDirection::In,
        tx_hash: optional_digest("old"),
        counterparty: "0:old".to_owned(),
        movements: vec![movement(AssetId::Native, 1)],
        int_msg_hash: optional_digest("i"),
        ..ActivityEvent::test_stub(999_999_999, 1)
    });

    c.handle_command(AppCommand::ImportSeed(seed_input(
        "twelve eleven ten nine eight seven six five four three two one",
    )));

    assert!(
        c.state().activity.is_empty(),
        "the old identity's activity must be cleared with the seed"
    );
    assert_ne!(
        c.state().wallet_address(),
        Some("0:old-address"),
        "the old identity's locally derived address must be retired with the seed"
    );
    cleanup(&dir);
}

#[derive(Default)]
struct FakeInner {
    prepare_error: Option<ChainError>,
    prepared_hash: Option<Digest32>,
    return_wrong_prepared_ticket: bool,
    candidate_count: usize,
    broadcasts: VecDeque<ChainResult<CandidateBroadcastOutcome>>,
    fee: Option<ChainResult<FeeEstimate>>,
    fee_bounces: Vec<bool>,
    load_wallet: Option<ChainResult<WalletSnapshot>>,
    load_wallet_calls: u32,
    destination: Option<ChainResult<DestinationAccountStatus>>,
    pages: VecDeque<ChainResult<TransactionPage>>,
    prepare_calls: u32,
    broadcast_calls: Vec<usize>,
    barrier_probe_dir: Option<PathBuf>,
    barrier_probe_results: Vec<bool>,
    last_prepare: Option<(WalletInputs, SendTicket, Vec<Reservation>, Vec<Reservation>)>,
    transaction_calls: u32,
    transaction_before_lts: Vec<Option<u64>>,
    sub_events: VecDeque<SubscriptionEvent>,
    sub_result: Option<ChainResult<()>>,
    last_sub_address: Option<String>,
    clear_config_cache_calls: u32,
    seal_calls: u32,
    unseal_calls: u32,
    drain_emulation_blocks: bool,
    drain_calls: u32,
    storage: Option<StorageSnapshot>,
    storage_ops: Vec<StorageOp>,
}

#[derive(Clone, Default)]
struct FakeChain(Arc<Mutex<FakeInner>>);

impl FakeChain {
    fn set_storage(&self, snapshot: StorageSnapshot) {
        self.0.lock().unwrap().storage = Some(snapshot);
    }

    fn storage_ops(&self) -> Vec<StorageOp> {
        self.0.lock().unwrap().storage_ops.clone()
    }

    fn set_prepare_error(&self, error: ChainError) {
        self.0.lock().unwrap().prepare_error = Some(error);
    }

    fn set_prepared_hash(&self, hash: Digest32) {
        self.0.lock().unwrap().prepared_hash = Some(hash);
    }

    fn return_wrong_prepared_ticket(&self) {
        self.0.lock().unwrap().return_wrong_prepared_ticket = true;
    }

    fn push_broadcast(&self, result: ChainResult<CandidateBroadcastOutcome>) {
        self.0.lock().unwrap().broadcasts.push_back(result);
    }

    fn set_candidate_count(&self, count: usize) {
        self.0.lock().unwrap().candidate_count = count;
    }

    fn probe_attempt_barriers_in(&self, dir: &Path) {
        self.0.lock().unwrap().barrier_probe_dir = Some(dir.to_path_buf());
    }

    fn set_fee(&self, result: ChainResult<FeeEstimate>) {
        self.0.lock().unwrap().fee = Some(result);
    }

    fn fee_bounces(&self) -> Vec<bool> {
        self.0.lock().unwrap().fee_bounces.clone()
    }

    fn set_load_wallet(&self, result: ChainResult<WalletSnapshot>) {
        self.0.lock().unwrap().load_wallet = Some(result);
    }

    fn load_wallet_calls(&self) -> u32 {
        self.0.lock().unwrap().load_wallet_calls
    }

    fn set_destination(&self, result: ChainResult<DestinationAccountStatus>) {
        self.0.lock().unwrap().destination = Some(result);
    }

    fn push_page(&self, page: ChainResult<TransactionPage>) {
        self.0.lock().unwrap().pages.push_back(page);
    }

    fn prepare_calls(&self) -> u32 {
        self.0.lock().unwrap().prepare_calls
    }

    fn broadcast_calls(&self) -> Vec<usize> {
        self.0.lock().unwrap().broadcast_calls.clone()
    }

    fn clear_config_cache_calls(&self) -> u32 {
        self.0.lock().unwrap().clear_config_cache_calls
    }

    fn seal_calls(&self) -> u32 {
        self.0.lock().unwrap().seal_calls
    }

    fn unseal_calls(&self) -> u32 {
        self.0.lock().unwrap().unseal_calls
    }

    fn block_emulation_drain(&self) {
        self.0.lock().unwrap().drain_emulation_blocks = true;
    }

    fn unblock_emulation_drain(&self) {
        self.0.lock().unwrap().drain_emulation_blocks = false;
    }

    fn drain_calls(&self) -> u32 {
        self.0.lock().unwrap().drain_calls
    }

    fn barrier_probe_results(&self) -> Vec<bool> {
        self.0.lock().unwrap().barrier_probe_results.clone()
    }

    fn last_prepare(
        &self,
    ) -> Option<(WalletInputs, SendTicket, Vec<Reservation>, Vec<Reservation>)> {
        self.0.lock().unwrap().last_prepare.take()
    }

    fn transaction_calls(&self) -> u32 {
        self.0.lock().unwrap().transaction_calls
    }

    fn transaction_before_lts(&self) -> Vec<Option<u64>> {
        self.0.lock().unwrap().transaction_before_lts.clone()
    }

    fn push_sub_event(&self, event: SubscriptionEvent) {
        self.0.lock().unwrap().sub_events.push_back(event);
    }

    fn set_sub_result(&self, result: ChainResult<()>) {
        self.0.lock().unwrap().sub_result = Some(result);
    }

    fn last_sub_address(&self) -> Option<String> {
        self.0.lock().unwrap().last_sub_address.clone()
    }
}

fn fake_prepared_record(
    ticket: SendTicket,
    external_hash: Digest32,
    authorized_overlap: Vec<Reservation>,
) -> PreparedRecord {
    let expire_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .saturating_add(u64::from(cc_wallet_chain::DEFAULT_TTL_SECS));
    fake_prepared_record_with_expiry(
        ticket,
        external_hash,
        authorized_overlap,
        u32::try_from(expire_at).unwrap(),
    )
}

fn fake_prepared_record_with_expiry(
    ticket: SendTicket,
    external_hash: Digest32,
    authorized_overlap: Vec<Reservation>,
    expire_at: u32,
) -> PreparedRecord {
    let fee = AssetAmount::native(LOCAL_SEND_FEE_CEILING_NANOS).unwrap();
    let record_id = ticket.record_id().clone();
    let (balances, reservations) = match ticket.request().asset_id() {
        AssetId::Native => {
            let total = ticket
                .request()
                .value()
                .checked_add_same_asset(&fee)
                .unwrap();
            (
                vec![total.clone()],
                vec![Reservation::new(record_id, total, ReservationKind::Transfer).unwrap()],
            )
        }
        AssetId::CurrencyCollection(_) => (
            vec![fee.clone(), ticket.request().value().clone()],
            vec![
                Reservation::new(
                    record_id.clone(),
                    ticket.request().value().clone(),
                    ReservationKind::Transfer,
                )
                .unwrap(),
                Reservation::new(record_id, fee, ReservationKind::NativeFee).unwrap(),
            ],
        ),
    };
    let provenance = PrepareProvenance::new(
        ticket.endpoint_identity().to_owned(),
        "fake-route".to_owned(),
        vec![
            "fake-config-request".to_owned(),
            "fake-account-request".to_owned(),
            "fake-route-request".to_owned(),
        ],
        1,
        digest("FAKE-ACCOUNT"),
        false,
        balances,
        digest("FAKE-SIGNATURE-CONTEXT"),
        ticket.network_global_id(),
        false,
        None,
        digest("FAKE-FEE-INPUT"),
        1,
        LOCAL_SEND_FEE_CEILING_NANOS,
        authorized_overlap,
    )
    .unwrap();
    PreparedRecord::new(ticket, provenance, external_hash, expire_at, reservations).unwrap()
}

fn install_blocking_history_record(
    controller: &mut AppController,
    external_hash: Digest32,
    record_byte: u8,
) -> (RecordId, String) {
    let expire_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .saturating_add(u64::from(cc_wallet_chain::DEFAULT_TTL_SECS));
    install_blocking_history_record_with_expiry(
        controller,
        external_hash,
        record_byte,
        u32::try_from(expire_at).unwrap(),
    )
}

fn install_blocking_history_record_with_expiry(
    controller: &mut AppController,
    external_hash: Digest32,
    record_byte: u8,
    expire_at: u32,
) -> (RecordId, String) {
    controller.capture_live_journal_reconcile_floor();
    let sender_address = controller
        .state()
        .wallet
        .as_ref()
        .expect("the history fixture has a loaded wallet")
        .address
        .clone();
    let authorization = SendAuthorization::new(
        RecordId::from_bytes([record_byte; 32]),
        controller.store.name().to_owned(),
        sender_address,
        controller.wallet_inputs().unwrap(),
        native_request(SEND_DEST, 1),
        true,
        u64::from(record_byte),
        u64::from(record_byte) + 1,
    )
    .unwrap();
    let (_, ticket) = authorization.into_parts();
    let prepared = fake_prepared_record_with_expiry(ticket, external_hash, Vec::new(), expire_at);
    let record_id = prepared.ticket().record_id().clone();
    let route_id = prepared.prepare_provenance().route_id().to_owned();
    let endpoint = prepared.ticket().endpoint_identity().to_owned();
    controller.journal.append_prepared(prepared).unwrap();
    controller
        .journal
        .append_delivery(
            &record_id,
            DeliveryEvidence::AttemptStarted {
                attempt_no: 1,
                route_id: route_id.clone(),
            },
        )
        .unwrap();
    controller
        .journal
        .append_delivery(
            &record_id,
            DeliveryEvidence::MayHaveBroadcast {
                attempt_no: 1,
                route_id,
            },
        )
        .unwrap();
    assert!(controller.persist_journal_barrier());
    controller.refresh_journal_policy();
    (record_id, endpoint)
}

fn synthetic_prepared(
    generation: u64,
    nonce: u64,
    hash_label: &str,
    candidates: usize,
) -> PreparedChainSend {
    let (_, ticket) = send_authorization(generation, nonce).into_parts();
    PreparedChainSend::for_test(
        fake_prepared_record(ticket, digest(hash_label), Vec::new()),
        candidates,
    )
    .unwrap()
}

fn persisted_journal(dir: &Path) -> cc_wallet_domain::JournalEnvelope {
    let store = cc_wallet_storage::VaultStore::new(
        dir.to_path_buf(),
        cc_wallet_storage::DEFAULT_WALLET_NAME,
    );
    let opened = store.unlock(PW).unwrap();
    cc_wallet_domain::JournalEnvelope::decode(&opened.journal).unwrap()
}

fn endpoint_observation(
    ext_hash: Digest32,
    endpoint: &str,
    sender: &str,
    request_id: &str,
    tx_label: &str,
    success: bool,
) -> EndpointTransactionEvidence {
    EndpointTransactionEvidence::new(
        endpoint.to_owned(),
        request_id.to_owned(),
        sender.to_owned(),
        digest(tx_label),
        ext_hash,
        44,
        success,
        if success { 0 } else { 37 },
        vec![movement(AssetId::Native, 123)],
    )
    .unwrap()
}

impl ChainService for FakeChain {
    fn generate_seed(&self) -> ChainResult<SeedPhrase> {
        Ok(SeedPhrase::new(TEST_SEED.to_owned()))
    }

    fn clear_config_cache(&self) {
        self.0.lock().unwrap().clear_config_cache_calls += 1;
    }

    fn seal_key_ops(&self) {
        self.0.lock().unwrap().seal_calls += 1;
    }

    fn unseal_key_ops(&self) {
        self.0.lock().unwrap().unseal_calls += 1;
    }

    fn drain_emulation_jobs(&self, _timeout: std::time::Duration) -> bool {
        let mut inner = self.0.lock().unwrap();
        inner.drain_calls += 1;
        !inner.drain_emulation_blocks
    }

    fn derive_wallet_address(&self, _inputs: &WalletInputs) -> ChainResult<String> {
        Ok(SEND_DEST.to_owned())
    }

    fn storage_address_for(&self, _inputs: &WalletInputs) -> ChainResult<String> {
        Ok(STORAGE_ADDR.to_owned())
    }

    fn load_storage(&self, _inputs: WalletInputs) -> ChainFuture<'_, StorageSnapshot> {
        let snapshot = self.0.lock().unwrap().storage.clone().unwrap_or_default();
        Box::pin(async move { Ok(snapshot) })
    }

    fn prepare_storage_op(
        &self,
        _inputs: WalletInputs,
        op: StorageOp,
    ) -> ChainFuture<'_, cc_wallet_chain::PreparedStorageOp> {
        self.0.lock().unwrap().storage_ops.push(op);
        Box::pin(async {
            Err(ChainError::Wallet(
                "the test double records the op and stops before signing".to_owned(),
            ))
        })
    }

    fn load_wallet<'a>(
        &'a self,
        _inputs: &'a EndpointAddressInputs,
    ) -> ChainFuture<'a, WalletSnapshot> {
        let result = {
            let mut inner = self.0.lock().unwrap();
            inner.load_wallet_calls += 1;
            inner
                .load_wallet
                .clone()
                .unwrap_or_else(|| Ok(timed_wallet("0:me")))
        };
        Box::pin(async move { result })
    }

    fn prepare_transaction(
        &self,
        inputs: WalletInputs,
        ticket: SendTicket,
        active_reservations: Vec<Reservation>,
        authorized_overlap: Vec<Reservation>,
    ) -> ChainFuture<'_, PreparedChainSend> {
        let (error, external_hash, candidate_count, return_wrong_prepared_ticket) = {
            let mut inner = self.0.lock().unwrap();
            inner.prepare_calls += 1;
            inner.last_prepare = Some((
                inputs,
                ticket.clone(),
                active_reservations,
                authorized_overlap.clone(),
            ));
            (
                inner.prepare_error.take(),
                inner
                    .prepared_hash
                    .clone()
                    .unwrap_or_else(|| digest("FAKE-PREPARED")),
                inner.candidate_count.max(1),
                inner.return_wrong_prepared_ticket,
            )
        };
        Box::pin(async move {
            if let Some(error) = error {
                return Err(error);
            }
            let ticket = if return_wrong_prepared_ticket {
                SendTicket::new(
                    RecordId::from_bytes([0x99; 32]),
                    ticket.sender_wallet_id().to_owned(),
                    ticket.sender_address().to_owned(),
                    ticket.network_global_id(),
                    ticket.endpoint_identity().to_owned(),
                    ticket.request().clone(),
                    ticket.bounce(),
                    ticket.auth_generation(),
                    ticket.auth_nonce(),
                )
                .unwrap()
            } else {
                ticket
            };
            PreparedChainSend::for_test(
                fake_prepared_record(ticket, external_hash, authorized_overlap),
                candidate_count,
            )
        })
    }

    fn broadcast_prepared_candidate<'a>(
        &'a self,
        prepared: &'a PreparedChainSend,
        candidate_index: usize,
    ) -> ChainFuture<'a, CandidateBroadcastOutcome> {
        let probe_dir = self.0.lock().unwrap().barrier_probe_dir.clone();
        let barrier_is_durable = probe_dir.map(|dir| {
            let store =
                cc_wallet_storage::VaultStore::new(dir, cc_wallet_storage::DEFAULT_WALLET_NAME);
            store
                .unlock(PW)
                .ok()
                .and_then(|opened| cc_wallet_domain::JournalEnvelope::decode(&opened.journal).ok())
                .and_then(|journal| journal.record(prepared.record_id()).cloned())
                .is_some_and(|record| {
                    matches!(
                        record.latest_evidence(),
                        cc_wallet_domain::DeliveryEvidence::AttemptStarted {
                            attempt_no,
                            route_id,
                        } if *attempt_no == u32::try_from(candidate_index + 1).unwrap()
                            && route_id == prepared.route_id()
                    )
                })
        });
        let result = {
            let mut inner = self.0.lock().unwrap();
            inner.broadcast_calls.push(candidate_index);
            if let Some(result) = barrier_is_durable {
                inner.barrier_probe_results.push(result);
            }
            inner.broadcasts.pop_front().unwrap_or_else(|| {
                Ok(CandidateBroadcastOutcome::NodeResponseObserved {
                    request_id: format!("fake-broadcast-{candidate_index}"),
                    response: cc_wallet_domain::NodeResponseKind::Acknowledged,
                    detail: "fake node acknowledgement".to_owned(),
                })
            })
        };
        Box::pin(async move { result })
    }

    fn estimate_fee(
        &self,
        _inputs: WalletInputs,
        _request: SendRequest,
        bounce: bool,
    ) -> ChainFuture<'_, FeeEstimate> {
        let result = {
            let mut inner = self.0.lock().unwrap();
            inner.fee_bounces.push(bounce);
            inner.fee.clone().unwrap_or(Ok(FeeEstimate {
                fee_nanos: 7_400_000,
                deploy: false,
            }))
        };
        Box::pin(async move { result })
    }

    fn check_destination<'a>(
        &'a self,
        _inputs: &'a EndpointAddressInputs,
        _address: String,
    ) -> ChainFuture<'a, DestinationAccountStatus> {
        let result = self
            .0
            .lock()
            .unwrap()
            .destination
            .clone()
            .unwrap_or(Ok(DestinationAccountStatus::Active));
        Box::pin(async move { result })
    }

    fn load_transactions<'a>(
        &'a self,
        _inputs: &'a EndpointAddressInputs,
        _limit: u32,
        before_lt: Option<u64>,
    ) -> ChainFuture<'a, TransactionPage> {
        let mut inner = self.0.lock().unwrap();
        inner.transaction_calls += 1;
        inner.transaction_before_lts.push(before_lt);
        let page = inner
            .pages
            .pop_front()
            .unwrap_or_else(|| Ok(TransactionPage::default()));
        Box::pin(async move { page })
    }

    fn probe_endpoint(&self, _endpoint: String) -> ChainFuture<'_, i32> {
        Box::pin(async move { Ok(0) })
    }

    fn subscribe(
        &self,
        inputs: EndpointAddressInputs,
        mut emit: Box<dyn FnMut(SubscriptionEvent) + Send>,
    ) -> ChainFuture<'_, ()> {
        let (events, result) = {
            let mut inner = self.0.lock().unwrap();
            inner.last_sub_address = Some(inputs.address().to_owned());
            let events: Vec<_> = inner.sub_events.drain(..).collect();
            (events, inner.sub_result.clone())
        };
        Box::pin(async move {
            for event in events {
                emit(event);
            }
            match result {
                Some(result) => result,
                None => std::future::pending::<ChainResult<()>>().await,
            }
        })
    }
}

const SEND_DEST: &str = "0:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
const OTHER_SEND_DEST: &str = "0:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";

fn unlocked_with_fake(dir: &Path, fake: &FakeChain) -> AppController {
    let mut c = unlocked(dir, WalletProfile::default());
    c.state_mut().seed = test_seed();
    c.chain = Arc::new(fake.clone());
    c.flush_save_blocking();
    while c.rx.try_recv().is_ok() {}
    c
}

fn ready_to_send(dir: &Path) -> (AppController, FakeChain) {
    let fake = FakeChain::default();
    let mut c = unlocked_with_fake(dir, &fake);
    let mut wallet = timed_wallet("0:me");
    set_native_balance(&mut wallet, 5_000_000_000);
    c.state_mut().wallet = Some(wallet);
    c.state_mut().send_form.destination = SEND_DEST.to_owned();
    c.state_mut().send_form.amount = "1.0".to_owned();
    c.state_mut().recipient_check = RecipientCheck::Known(DestinationAccountStatus::Active);
    (c, fake)
}

#[test]
fn a_successful_lock_seals_key_operations() {
    let dir = temp_dir("lock-seal");
    let fake = FakeChain::default();
    let mut c = unlocked_with_fake(&dir, &fake);

    assert!(c.lock());
    assert_eq!(c.state().phase, AppPhase::Locked);
    assert_eq!(fake.seal_calls(), 1, "lock seals key derivation");
    assert_eq!(
        fake.unseal_calls(),
        0,
        "a locked wallet stays sealed until the next unlock"
    );
    cleanup(&dir);
}

#[test]
fn lock_defers_while_emulation_jobs_active() {
    let dir = temp_dir("lock-defers");
    let fake = FakeChain::default();
    let mut c = unlocked_with_fake(&dir, &fake);
    fake.block_emulation_drain();

    assert!(!c.lock(), "a blocked drain defers rather than completing");
    assert!(c.has_pending_teardown(), "the lock is queued");
    assert_eq!(c.state().phase, AppPhase::Unlocked, "wallet stays open");
    assert!(c.state().busy, "the UI shows the pending teardown as busy");
    assert_eq!(
        fake.seal_calls(),
        1,
        "request_lock seals before the drain check"
    );
    assert_eq!(
        fake.unseal_calls(),
        0,
        "the deferred lock stays sealed until it completes or times out"
    );

    c.handle_command(AppCommand::SetSendAmount("9.0".to_owned()));
    assert_ne!(c.state().send_form.amount, "9.0", "commands are gated");

    fake.unblock_emulation_drain();
    c.tick();
    assert!(!c.has_pending_teardown());
    assert_eq!(
        c.state().phase,
        AppPhase::Locked,
        "the deferred lock completes"
    );
    cleanup(&dir);
}

#[test]
fn deferred_lock_gives_up_after_deadline() {
    let dir = temp_dir("lock-deadline");
    let fake = FakeChain::default();
    let mut c = unlocked_with_fake(&dir, &fake);
    fake.block_emulation_drain();

    assert!(!c.lock());
    assert!(c.has_pending_teardown());
    assert_eq!(fake.unseal_calls(), 0);

    c.expire_pending_teardown();
    c.tick();
    assert!(!c.has_pending_teardown(), "the deferred lock gave up");
    assert_eq!(c.state().phase, AppPhase::Unlocked, "the wallet stays open");
    assert!(!c.state().busy, "the busy spinner is cleared");
    assert_eq!(
        fake.unseal_calls(),
        1,
        "giving up unseals so the still-open wallet can derive again"
    );
    assert!(c.state().error.is_some(), "the failure is surfaced");
    cleanup(&dir);
}

#[test]
fn switch_wallet_completes_after_a_deferred_lock() {
    let dir = temp_dir("switch-deferred");
    let fake = FakeChain::default();
    let mut c = unlocked_with_fake(&dir, &fake);
    fake.block_emulation_drain();

    c.handle_command(AppCommand::SwitchWallet);
    assert!(
        c.has_pending_teardown(),
        "the switch-to-picker lock is deferred"
    );
    assert_eq!(c.state().phase, AppPhase::Unlocked);

    fake.unblock_emulation_drain();
    c.tick();
    assert!(!c.has_pending_teardown());
    assert_ne!(
        c.state().phase,
        AppPhase::Unlocked,
        "the follow-up runs: the session is torn down to the picker/lock screen"
    );
    cleanup(&dir);
}

#[test]
fn drop_final_drain_is_bounded_to_three_attempts() {
    let fake = FakeChain::default();
    fake.block_emulation_drain();
    assert!(
        !super::final_emulation_drain(&fake),
        "a wedged worker makes the bounded drain report failure, not hang"
    );
    assert_eq!(
        fake.drain_calls(),
        3,
        "the final drain makes exactly three bounded attempts"
    );
}

#[test]
fn delete_wallet_with_a_deferred_drain_destroys_only_after_the_lock_completes() {
    let dir = temp_dir("delete-deferred");
    let fake = FakeChain::default();
    let mut c = unlocked_with_fake(&dir, &fake);
    let vault_path = dir.join(format!("{}.ccwallet", c.store.name()));
    assert!(
        vault_path.is_file(),
        "the wallet file exists before deletion"
    );

    fake.block_emulation_drain();
    c.do_delete_wallet();
    assert!(c.has_pending_teardown(), "the delete lock is deferred");
    assert!(
        vault_path.is_file(),
        "the file is not destroyed while the lock is still deferred"
    );
    assert_eq!(
        c.state().phase,
        AppPhase::Unlocked,
        "the session is still up"
    );

    fake.unblock_emulation_drain();
    c.tick();
    assert!(!c.has_pending_teardown());
    assert!(
        !vault_path.exists(),
        "the file is destroyed once the deferred lock completes"
    );
    assert_ne!(
        c.state().phase,
        AppPhase::Unlocked,
        "the wallet is torn down after deletion"
    );
    cleanup(&dir);
}

#[test]
fn activating_a_new_seed_clears_the_chain_key_cache() {
    let dir = temp_dir("seed-clears-cache");
    let fake = FakeChain::default();
    let mut c = unlocked_with_fake(&dir, &fake);
    let before = fake.clear_config_cache_calls();

    c.handle_command(AppCommand::SaveSeed(seed_input(TEST_SEED)));

    assert!(
        fake.clear_config_cache_calls() > before,
        "activating a seed evicts the previous seed's cached key"
    );
    cleanup(&dir);
}

#[test]
fn send_form_locked_tracks_the_busy_gate() {
    let dir = temp_dir("send-form-locked");
    let (mut c, _fake) = ready_to_send(&dir);
    assert!(!c.send_form_locked(), "an idle form is editable");

    c.state_mut().sending = true;
    assert!(c.send_form_locked(), "an in-flight send locks the form");
    c.state_mut().sending = false;
    assert!(!c.send_form_locked());

    c.handle_command(AppCommand::RequestSend);
    assert!(
        c.pending_authorization.is_some(),
        "RequestSend captures an authorization"
    );
    assert!(
        c.send_form_locked(),
        "a pending authorization locks the form"
    );
    cleanup(&dir);
}

#[test]
fn pending_authorization_busy_gates_every_value_and_network_control() {
    const OTHER_DEST: &str = "0:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
    let dir = temp_dir("auth-controls-locked");
    let (mut c, _fake) = ready_to_send(&dir);
    c.handle_command(AppCommand::AddEndpoint("https://alt.example".to_owned()));
    let removable_endpoint = c.state().custom_endpoints[0].clone();

    c.handle_command(AppCommand::RequestSend);
    let authorization = c
        .pending_authorization
        .as_ref()
        .expect("request captured an immutable authorization");
    let authorization_generation = authorization.generation();
    let authorization_nonce = authorization.nonce();
    let authorization_digest = authorization.ticket().digest().unwrap();
    let form = c.state().send_form.clone();
    let selected_asset = c.state().selected_asset;
    let visible_assets = c.state().visible_cc_assets.clone();
    let allow_unbounced = c.state().allow_unbounced;
    let custom_endpoints = c.state().custom_endpoints.clone();
    let selected_endpoint = c.state().selected_endpoint;
    let seed = Arc::clone(&c.state().seed);
    let auth_shape = (
        c.state().auth.open,
        c.state().auth.mode,
        c.state().auth.purpose,
    );

    for command in [
        AppCommand::QuickSend(OTHER_DEST.to_owned()),
        AppCommand::GenerateSeed,
        AppCommand::SaveSeed(seed_input(TEST_SEED)),
        AppCommand::ImportSeed(seed_input(TEST_SEED)),
        AppCommand::UseSeed,
        AppCommand::DiscardSeed,
        AppCommand::ChangePasswordRequest,
        AppCommand::RevealSeed,
        AppCommand::DeleteWallet,
        AppCommand::SetAssetVisibility {
            cc_id: 1,
            visible: true,
        },
        AppCommand::SelectAsset(AssetId::CurrencyCollection(1)),
        AppCommand::SetSendDestination(OTHER_DEST.to_owned()),
        AppCommand::SetSendAmount("2.0".to_owned()),
        AppCommand::SetMaxAmount,
        AppCommand::SetAllowUnbounced(true),
        AppCommand::AddEndpoint("https://new.example".to_owned()),
        AppCommand::SelectEndpoint(1),
        AppCommand::RemoveEndpoint(removable_endpoint.clone()),
    ] {
        c.handle_command(command);
        let current = c
            .pending_authorization
            .as_ref()
            .expect("busy-gating retains the authorization");
        assert_eq!(current.generation(), authorization_generation);
        assert_eq!(current.nonce(), authorization_nonce);
        assert_eq!(current.ticket().digest().unwrap(), authorization_digest);
        assert_eq!(c.state().send_form, form);
        assert_eq!(c.state().selected_asset, selected_asset);
        assert_eq!(c.state().visible_cc_assets, visible_assets);
        assert_eq!(c.state().allow_unbounced, allow_unbounced);
        assert_eq!(c.state().custom_endpoints, custom_endpoints);
        assert_eq!(c.state().selected_endpoint, selected_endpoint);
        assert_eq!(c.state().seed, seed);
        assert_eq!(
            (
                c.state().auth.open,
                c.state().auth.mode,
                c.state().auth.purpose,
            ),
            auth_shape
        );
        assert!(c.state().auth.error.contains("locked"));
    }

    let auth_generation = c.auth_generation;
    c.handle_command(AppCommand::RequestSend);
    let current = c
        .pending_authorization
        .as_ref()
        .expect("a duplicate request retains the authorization");
    assert_eq!(current.generation(), authorization_generation);
    assert_eq!(current.nonce(), authorization_nonce);
    assert_eq!(current.ticket().digest().unwrap(), authorization_digest);
    assert_eq!(c.auth_generation, auth_generation);
    cleanup(&dir);
}

#[test]
fn inactive_recipient_option_updates_the_pending_authorization_without_a_technical_error() {
    let dir = temp_dir("auth-inactive-recipient-option");
    let (mut c, fake) = ready_to_send(&dir);
    fake.set_destination(Ok(DestinationAccountStatus::Uninit));
    c.state_mut().recipient_check = RecipientCheck::Known(DestinationAccountStatus::Uninit);
    c.handle_command(AppCommand::RequestSend);
    c.pump_events();
    let original = c
        .pending_authorization
        .as_ref()
        .expect("request captured an authorization");
    let generation = original.generation();
    let nonce = original.nonce();
    assert!(original.bounce());
    assert!(c.state().auth.send_options_editable);
    assert!(
        c.session.fee_reestimate_at.is_none(),
        "confirmation cancels a redundant queued fee preview"
    );

    c.handle_command(AppCommand::SetAllowUnbounced(true));

    let updated = c
        .pending_authorization
        .as_ref()
        .expect("the confirmation option keeps the authorization");
    assert_eq!(updated.generation(), generation);
    assert_eq!(updated.nonce(), nonce);
    assert!(!updated.bounce());
    assert!(c.state().allow_unbounced);
    assert!(c.state().auth.error.is_empty());
    assert!(c.state().error.is_none());

    c.pump_events();
    c.tick();
    c.pump_events();
    assert!(fake.fee_bounces().is_empty());
    cleanup(&dir);
}

#[test]
fn opening_send_confirmation_keeps_the_last_fee_estimate_visible() {
    let dir = temp_dir("auth-keeps-fee-preview");
    let (mut c, _fake) = ready_to_send(&dir);
    c.state_mut().fee_estimate = Some(FeeEstimate {
        fee_nanos: 7_483_004,
        deploy: false,
    });

    c.handle_command(AppCommand::SetSendAmount("1.0".to_owned()));
    assert_eq!(
        c.state().fee_estimate.map(|estimate| estimate.fee_nanos),
        Some(7_483_004),
        "editing the form keeps the last successful estimate during debounce"
    );
    assert!(c.session.fee_reestimate_at.is_some());

    c.handle_command(AppCommand::RequestSend);

    assert!(c.pending_authorization.is_some());
    assert!(c.session.fee_reestimate_at.is_none());
    assert_eq!(
        c.state().fee_estimate.map(|estimate| estimate.fee_nanos),
        Some(7_483_004),
        "cancelling the debounce must not turn the confirmation fee unavailable"
    );
    cleanup(&dir);
}

#[test]
fn auto_refresh_does_not_start_a_fee_preview_while_send_confirmation_is_open() {
    let dir = temp_dir("auth-autoload-no-fee-preview");
    let (mut c, fake) = ready_to_send(&dir);
    c.handle_command(AppCommand::RequestSend);
    assert!(c.pending_authorization.is_some());

    let snapshot = c.state().wallet.clone().expect("wallet is loaded");
    let generation = c.subscription_generation;
    apply_owned_auto_load(&mut c, generation, snapshot);
    c.pump_events();
    c.tick();
    c.pump_events();

    assert!(
        fake.fee_bounces().is_empty(),
        "an auto-refresh must not contend with exact send preparation"
    );
    assert!(!c.state().fee_estimating);
    cleanup(&dir);
}

#[test]
fn frozen_send_options_ignore_stale_checkbox_commands_without_a_technical_error() {
    let dir = temp_dir("auth-frozen-inactive-recipient-option");
    let (mut c, _fake) = ready_to_send(&dir);
    c.state_mut().recipient_check = RecipientCheck::Known(DestinationAccountStatus::Uninit);
    c.handle_command(AppCommand::RequestSend);
    let authorization = c
        .pending_authorization
        .as_ref()
        .expect("request captured an authorization");
    let record_id = authorization.ticket().record_id().clone();
    let ticket_digest = authorization.ticket().digest().unwrap();

    c.pending_risk_consumption = Some(PendingRiskConsumption {
        consumption: RiskGrantConsumption::new(
            RiskNonce::from_bytes([0x88; 32]),
            record_id,
            ticket_digest,
        ),
        overlap: Vec::new(),
    });
    c.state_mut().auth.send_options_editable = false;
    c.handle_command(AppCommand::SetAllowUnbounced(true));
    assert!(c.pending_authorization.as_ref().unwrap().bounce());
    assert!(!c.state().allow_unbounced);
    assert!(c.state().auth.error.is_empty());
    assert!(c.state().error.is_none());

    c.pending_risk_consumption = None;
    c.state_mut().auth.send_options_editable = true;
    c.state_mut().key_busy = true;
    c.handle_command(AppCommand::SetAllowUnbounced(true));
    assert!(c.pending_authorization.as_ref().unwrap().bounce());
    assert!(!c.state().allow_unbounced);
    assert!(c.state().auth.error.is_empty());
    assert!(c.state().error.is_none());
    cleanup(&dir);
}

#[test]
fn socket_free_prepare_keeps_value_and_network_controls_busy_gated() {
    const OTHER_DEST: &str = "0:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
    let dir = temp_dir("prepare-controls-locked");
    let (mut c, _fake) = ready_to_send(&dir);
    c.handle_command(AppCommand::AddEndpoint("https://alt.example".to_owned()));
    let original_form = c.state().send_form.clone();
    let original_endpoint = c.state().selected_endpoint;
    let original_bounce = c.state().allow_unbounced;

    c.dispatch_test_authorization();
    assert!(c.state().sending);
    for command in [
        AppCommand::SetSendDestination(OTHER_DEST.to_owned()),
        AppCommand::SetSendAmount("2.0".to_owned()),
        AppCommand::SetAllowUnbounced(true),
        AppCommand::SelectEndpoint(1),
    ] {
        c.handle_command(command);
        assert_eq!(c.state().send_form, original_form);
        assert_eq!(c.state().selected_endpoint, original_endpoint);
        assert_eq!(c.state().allow_unbounced, original_bounce);
    }
    assert!(
        c.state()
            .error
            .as_deref()
            .is_some_and(|error| error.contains("authorization snapshot"))
    );
    cleanup(&dir);
}

#[test]
fn stale_authorization_generation_or_nonce_is_consumed_without_sending() {
    let dir = temp_dir("auth-stale-ticket");
    let (mut c, fake) = ready_to_send(&dir);
    c.handle_command(AppCommand::RequestSend);
    let authorization = c.pending_authorization.as_ref().unwrap();
    let authorization_generation = authorization.generation();
    let stale_nonce = authorization.nonce().wrapping_add(1);
    let vault = Vault::create_with(PW, CHEAP).unwrap();
    c.apply_key_msg(KeyMsg::Ok {
        history_corrupt: false,
        journal: cc_wallet_domain::JournalEnvelope::empty(),
        selected: None,
        writer: None,
        generation: c.key_generation(),
        history: Vec::new(),
        action: KeyAction::ConfirmSend {
            remember: false,
            auth_generation: authorization_generation,
            auth_nonce: stale_nonce,
        },
        vault,
        profile: WalletProfile::default(),
    });

    assert!(
        c.pending_authorization.is_none(),
        "the stale ticket is burned"
    );
    assert!(c.state().auth.error.contains("Stale"));
    assert_eq!(fake.prepare_calls(), 0);
    assert!(!c.state().sending);
    cleanup(&dir);
}

#[test]
fn post_auth_send_consumes_only_the_exact_snapshot_not_the_live_form() {
    const OTHER_DEST: &str = "0:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
    let dir = temp_dir("auth-exact-snapshot");
    let (mut c, fake) = ready_to_send(&dir);
    fake.set_prepared_hash(digest("AUTH-SNAPSHOT"));
    c.handle_command(AppCommand::RequestSend);
    let authorization = c.pending_authorization.as_ref().unwrap();
    let authorization_generation = authorization.generation();
    let authorization_nonce = authorization.nonce();

    c.state_mut().send_form.destination = OTHER_DEST.to_owned();
    c.state_mut().send_form.amount = "2.0".to_owned();
    c.state_mut().recipient_check = RecipientCheck::Known(DestinationAccountStatus::Uninit);
    c.state_mut().allow_unbounced = true;
    assert!(c.state().can_afford_send());

    let vault = Vault::create_with(PW, CHEAP).unwrap();
    c.apply_key_msg(KeyMsg::Ok {
        history_corrupt: false,
        journal: cc_wallet_domain::JournalEnvelope::empty(),
        selected: None,
        writer: None,
        generation: c.key_generation(),
        history: Vec::new(),
        action: KeyAction::ConfirmSend {
            remember: false,
            auth_generation: authorization_generation,
            auth_nonce: authorization_nonce,
        },
        vault,
        profile: WalletProfile::default(),
    });
    c.pump_events();

    let (_, ticket, _, _) = fake
        .last_prepare()
        .expect("authorized send reached socket-free preparation");
    assert_eq!(ticket.request().destination(), SEND_DEST);
    assert_eq!(ticket.request().value().native_units(), Some(1_000_000_000));
    assert!(
        ticket.bounce(),
        "the ticket's original bounce value is immutable"
    );
    cleanup(&dir);
}

#[test]
fn exhausted_auth_generation_refuses_to_create_a_ticket() {
    let dir = temp_dir("auth-generation-overflow");
    let (mut c, fake) = ready_to_send(&dir);
    c.auth_generation = u64::MAX;
    c.handle_command(AppCommand::RequestSend);
    assert!(c.pending_authorization.is_none());
    assert_eq!(fake.prepare_calls(), 0);
    assert!(
        c.state()
            .error
            .as_deref()
            .is_some_and(|error| error.contains("generation is exhausted"))
    );
    cleanup(&dir);
}

#[test]
fn a_dispatched_send_reaches_the_chain_with_the_form_values() {
    let dir = temp_dir("dispatch-send-inputs");
    let (mut c, fake) = ready_to_send(&dir);

    c.dispatch_test_authorization();
    assert!(c.state().sending, "Send locks immediately on dispatch");
    assert_eq!(
        c.state().activity.iter().filter(|e| e.pending).count(),
        1,
        "the optimistic row appears in the dispatch reducer turn"
    );
    assert!(c.state().activity[0].ext_msg_hash.is_none());
    assert!(
        c.session
            .pending_sends
            .iter()
            .all(|(_, started_at)| started_at.is_none()),
        "read-only preparation is excluded from finality"
    );

    c.pump_events();

    assert_eq!(
        fake.prepare_calls(),
        1,
        "the chain was asked to prepare exactly once"
    );
    assert_eq!(fake.broadcast_calls(), vec![0]);
    let (inputs, ticket, active, overlap) =
        fake.last_prepare().expect("the prepare call was recorded");
    assert_eq!(
        inputs.seed.expose_secret(),
        TEST_SEED,
        "the dispatch built inputs from state"
    );
    assert_eq!(
        ticket.request().destination(),
        SEND_DEST,
        "the recipient came from the form"
    );
    assert_eq!(
        ticket.request().value().native_units(),
        Some(1_000_000_000),
        "1.0 was parsed to nanos for the chain call"
    );
    assert!(active.is_empty());
    assert!(overlap.is_empty());
    assert_eq!(
        c.state()
            .activity
            .iter()
            .filter(|event| event.pending)
            .count(),
        1,
        "Prepared enriches the existing optimistic row instead of duplicating it"
    );
    assert!(c.state().activity[0].ext_msg_hash.is_some());
    assert!(
        c.session
            .pending_sends
            .iter()
            .all(|(_, started_at)| started_at.is_some()),
        "the first durable AttemptStarted arms finality before broadcast"
    );
    assert!(
        c.state().journal_blocking,
        "an acknowledgement still blocks replacement signing"
    );
    assert!(
        c.state().send_form.destination.is_empty(),
        "an observed node response clears the submitted recipient"
    );
    assert!(
        c.state().send_form.amount.is_empty(),
        "an observed node response clears the submitted amount"
    );
    assert_eq!(c.state().recipient_check, RecipientCheck::Unchecked);
    assert!(!c.state().allow_unbounced);
    cleanup(&dir);
}

#[test]
fn every_candidate_socket_observes_its_durable_attempt_barrier() {
    let dir = temp_dir("durable-attempt-before-socket");
    let (mut c, fake) = ready_to_send(&dir);
    fake.set_candidate_count(2);
    fake.probe_attempt_barriers_in(&dir);
    fake.push_broadcast(Ok(CandidateBroadcastOutcome::NotTransmitted {
        detail: "candidate zero failed before connect".to_owned(),
        retry_next_candidate: true,
    }));
    fake.push_broadcast(Ok(CandidateBroadcastOutcome::NodeResponseObserved {
        request_id: "candidate-one-ack".to_owned(),
        response: cc_wallet_domain::NodeResponseKind::Acknowledged,
        detail: "node accepted the request".to_owned(),
    }));

    c.dispatch_test_authorization();
    c.pump_events();

    assert_eq!(fake.broadcast_calls(), vec![0, 1]);
    assert_eq!(
        fake.barrier_probe_results(),
        vec![true, true],
        "each fake socket opened only after reading its exact AttemptStarted from the vault"
    );
    let record = persisted_journal(&dir).records()[0].clone();
    assert!(matches!(
        record.latest_evidence(),
        DeliveryEvidence::NodeResponseObserved {
            attempt_no: 2,
            response: cc_wallet_domain::NodeResponseKind::Acknowledged,
            ..
        }
    ));
    assert!(
        c.state().journal_blocking,
        "ACK never unlocks ordinary signing"
    );
    assert!(!c.state().send_enabled());
    cleanup(&dir);
}

#[test]
fn a_prepared_barrier_failure_opens_no_candidate_socket_and_stays_sticky() {
    let dir = temp_dir("prepared-save-failure");
    let (mut c, fake) = ready_to_send(&dir);
    c.writer
        .as_mut()
        .expect("unlocked wallet owns its authenticated writer")
        .poison()
        .unwrap();

    c.dispatch_test_authorization();
    c.pump_events();

    assert_eq!(fake.prepare_calls(), 1, "read-only prepare was allowed");
    assert!(
        fake.broadcast_calls().is_empty(),
        "no signed-body socket opened"
    );
    assert_eq!(
        c.state().persistence_health,
        PersistenceHealth::Failed,
        "the durability failure remains a signing blocker"
    );
    assert!(persisted_journal(&dir).records().is_empty());
    assert!(!c.state().send_enabled());
    cleanup(&dir);
}

#[test]
fn a_failed_read_only_prepare_creates_no_journal_attempt_or_socket() {
    let dir = temp_dir("prepare-read-failure");
    let (mut c, fake) = ready_to_send(&dir);
    fake.set_prepare_error(ChainError::Wallet("fresh account read failed".to_owned()));

    c.dispatch_test_authorization();
    c.pump_events();

    assert_eq!(fake.prepare_calls(), 1);
    assert!(fake.broadcast_calls().is_empty());
    assert!(persisted_journal(&dir).records().is_empty());
    assert!(!c.state().sending);
    assert!(
        c.state().activity.iter().all(|event| !event.pending),
        "a socket-free preparation error removes the optimistic row"
    );
    assert_eq!(c.state().persistence_health, PersistenceHealth::Ready);
    assert!(!c.state().send_form_error);
    assert_eq!(
        c.state().error.as_deref(),
        Some("fresh account read failed")
    );
    assert_eq!(
        c.state().send_form.destination,
        SEND_DEST,
        "a socket-free prepare failure keeps the recipient for retry"
    );
    assert_eq!(
        c.state().send_form.amount,
        "1.0",
        "a socket-free prepare failure keeps the amount for retry"
    );
    cleanup(&dir);
}

#[test]
fn fresh_insufficient_funds_is_a_retryable_form_error_cleared_by_form_edits() {
    let dir = temp_dir("prepare-insufficient-form-error");
    let (mut c, fake) = ready_to_send(&dir);
    let message = "Insufficient fresh balance for this amount plus the network fee";
    fake.set_prepare_error(ChainError::InsufficientFunds(message.to_owned()));

    c.dispatch_test_authorization();
    c.pump_events();

    assert!(!c.state().sending);
    assert!(!c.state().busy);
    assert!(c.state().send_form_error);
    assert_eq!(c.state().error.as_deref(), Some(message));
    assert_eq!(c.state().send_form.destination, SEND_DEST);
    assert_eq!(c.state().send_form.amount, "1.0");

    c.handle_command(AppCommand::SetSendAmount("0.5".to_owned()));
    assert!(!c.state().send_form_error);
    assert!(c.state().error.is_none());

    fake.set_prepare_error(ChainError::InsufficientFunds(message.to_owned()));
    c.dispatch_test_authorization();
    c.pump_events();
    assert!(c.state().send_form_error);

    c.handle_command(AppCommand::SetMaxAmount);
    assert!(!c.state().send_form_error);
    assert!(c.state().error.is_none());
    cleanup(&dir);
}

#[test]
fn local_authorization_may_consume_part_of_max_headroom() {
    let dir = temp_dir("local-auth-consumes-headroom");
    let (mut c, fake) = ready_to_send(&dir);
    let fee = c.state().effective_send_fee();
    let remaining_headroom = cc_wallet_domain::LOCAL_SEND_FEE_HEADROOM_NANOS / 2;
    set_native_balance(
        c.state_mut().wallet.as_mut().unwrap(),
        1_000_000_000 + fee + remaining_headroom,
    );

    assert!(
        c.state().send_enabled(),
        "the exact fee fits even though less than the original MAX headroom remains"
    );
    c.dispatch_test_authorization();
    c.pump_events();
    assert_eq!(
        fake.prepare_calls(),
        1,
        "local authorization must reach the fresh chain affordability check"
    );
    cleanup(&dir);
}

#[test]
fn a_prepared_value_for_another_ticket_is_dropped_before_journal_or_socket() {
    let dir = temp_dir("wrong-prepared-ticket");
    let (mut c, fake) = ready_to_send(&dir);
    fake.return_wrong_prepared_ticket();

    c.dispatch_test_authorization();
    c.pump_events();

    assert_eq!(fake.prepare_calls(), 1);
    assert!(fake.broadcast_calls().is_empty());
    assert!(persisted_journal(&dir).records().is_empty());
    assert!(!c.state().sending);
    assert!(
        c.state()
            .error
            .as_deref()
            .is_some_and(|error| error.contains("different immutable ticket"))
    );
    cleanup(&dir);
}

#[test]
fn a_risk_prepared_value_without_its_matching_consumption_is_dropped() {
    let dir = temp_dir("risk-prepared-without-consumption");
    let (mut c, fake) = ready_to_send(&dir);
    let prepared = synthetic_prepared(71, 73, "RISK-NO-CONSUMPTION", 1);
    let expected_ticket_digest = prepared.prepared_record().ticket().digest().unwrap();

    c.apply_event(AppEvent::SendPrepared {
        generation: c.session_generation,
        expected_ticket_digest,
        risk_grant_required: true,
        prepared,
    });

    assert!(fake.broadcast_calls().is_empty());
    assert!(persisted_journal(&dir).records().is_empty());
    assert!(
        c.state()
            .error
            .as_deref()
            .is_some_and(|error| error.contains("one-use grant"))
    );
    cleanup(&dir);
}

#[test]
fn locally_proven_not_transmitted_relaxes_only_after_its_durable_transition() {
    let dir = temp_dir("durable-not-transmitted");
    let (mut c, fake) = ready_to_send(&dir);
    fake.push_broadcast(Ok(CandidateBroadcastOutcome::NotTransmitted {
        detail: "connect failed before any bytes".to_owned(),
        retry_next_candidate: false,
    }));
    c.state_mut().recipient_check = RecipientCheck::Known(DestinationAccountStatus::Uninit);
    c.state_mut().allow_unbounced = true;

    c.dispatch_test_authorization();
    c.pump_events();

    let journal = persisted_journal(&dir);
    assert!(matches!(
        journal.records()[0].latest_evidence(),
        DeliveryEvidence::NotBroadcast { .. }
    ));
    assert!(!c.state().journal_blocking);
    assert!(!c.state().sending);
    assert_eq!(c.state().status, "NotTransmitted — locally proven");
    assert!(c.state().activity.iter().all(|event| !event.pending));
    assert_eq!(
        c.state().send_form.amount,
        "1.0",
        "a transfer proven not transmitted remains ready for retry"
    );
    assert_eq!(
        c.state().send_form.destination,
        SEND_DEST,
        "a transfer proven not transmitted keeps its recipient for retry"
    );
    assert_eq!(
        c.state().recipient_check,
        RecipientCheck::Known(DestinationAccountStatus::Uninit)
    );
    assert!(c.state().allow_unbounced);
    cleanup(&dir);
}

#[test]
fn a_failed_not_broadcast_save_keeps_the_durable_attempt_and_blocks_signing() {
    let dir = temp_dir("not-transmitted-save-failure");
    let mut c = unlocked(&dir, WalletProfile::default());
    let prepared = synthetic_prepared(31, 7, "NOT-BROADCAST-FAIL", 1);
    let record_id = prepared.record_id().clone();
    c.journal
        .append_prepared(prepared.prepared_record().clone())
        .unwrap();
    c.journal
        .append_delivery(
            &record_id,
            DeliveryEvidence::AttemptStarted {
                attempt_no: 1,
                route_id: prepared.route_id().to_owned(),
            },
        )
        .unwrap();
    assert!(c.persist_journal_barrier());
    c.writer.as_mut().unwrap().poison().unwrap();

    c.apply_candidate_outcome(
        c.session_generation,
        prepared,
        0,
        CandidateBroadcastOutcome::NotTransmitted {
            detail: "pre-connect proof".to_owned(),
            retry_next_candidate: false,
        },
    );

    let journal = persisted_journal(&dir);
    assert!(matches!(
        journal.records()[0].latest_evidence(),
        DeliveryEvidence::AttemptStarted { .. }
    ));
    assert_eq!(c.state().persistence_health, PersistenceHealth::Failed);
    assert!(!c.state().send_enabled());
    cleanup(&dir);
}

#[test]
fn may_have_broadcast_is_durable_and_keeps_every_reservation() {
    let dir = temp_dir("durable-may-have");
    let (mut c, fake) = ready_to_send(&dir);
    fake.push_broadcast(Ok(CandidateBroadcastOutcome::MayHaveBroadcast {
        detail: "connection dropped after write".to_owned(),
    }));
    c.state_mut().recipient_check = RecipientCheck::Known(DestinationAccountStatus::Uninit);
    c.state_mut().allow_unbounced = true;

    c.dispatch_test_authorization();
    c.pump_events();

    let journal = persisted_journal(&dir);
    let record = &journal.records()[0];
    assert!(matches!(
        record.latest_evidence(),
        DeliveryEvidence::MayHaveBroadcast { .. }
    ));
    assert_eq!(record.reservations().len(), 1);
    assert_eq!(c.state().active_reservations, record.reservations());
    assert!(c.state().journal_blocking);
    assert!(!c.state().sending);
    assert!(
        c.state().send_form.amount.is_empty(),
        "a possibly broadcast transfer clears the stale amount immediately"
    );
    assert!(
        c.state().send_form.destination.is_empty(),
        "a possibly broadcast transfer clears the stale recipient immediately"
    );
    assert_eq!(c.state().recipient_check, RecipientCheck::Unchecked);
    assert!(!c.state().allow_unbounced);
    assert!(!c.state().amount_exceeds_balance());
    cleanup(&dir);
}

#[test]
fn unresolved_vault_records_block_identity_replacement_and_address_filter_bypass() {
    const OTHER_ADDRESS: &str =
        "0:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
    let dir = temp_dir("unresolved-identity-immutable");
    let (mut c, fake) = ready_to_send(&dir);
    fake.push_broadcast(Ok(CandidateBroadcastOutcome::MayHaveBroadcast {
        detail: "old transfer outcome unknown".to_owned(),
    }));
    c.dispatch_test_authorization();
    c.pump_events();
    assert!(c.state().journal_blocking);

    let original_seed = Arc::clone(&c.state().seed);
    c.handle_command(AppCommand::ImportSeed(seed_input(
        "twelve eleven ten nine eight seven six five four three two one",
    )));
    assert_eq!(c.state().seed, original_seed);
    assert!(
        c.state()
            .error
            .as_deref()
            .is_some_and(|error| error.contains("identity cannot change"))
    );

    c.handle_command(AppCommand::AddEndpoint(
        "https://alternate.example".to_owned(),
    ));
    let selected_endpoint = c.state().selected_endpoint;
    c.state_mut().clear_error();
    c.handle_command(AppCommand::SelectEndpoint(1));
    assert_eq!(c.state().selected_endpoint, selected_endpoint);
    assert!(
        c.state()
            .error
            .as_deref()
            .is_some_and(|error| error.contains("prepared endpoint cannot be replaced"))
    );

    let mut other = WalletSnapshot::new_with_network_time(
        OTHER_ADDRESS,
        0,
        "Active",
        5_000_000_000,
        Default::default(),
        0,
        Some(
            ObservedNetworkTime::new(
                1_700_000_000,
                "https://rpc.example/",
                "other-address-request",
                Instant::now(),
            )
            .unwrap(),
        ),
    )
    .unwrap();
    set_native_balance(&mut other, 5_000_000_000);
    c.state_mut().wallet = Some(other);
    c.refresh_journal_policy();
    assert!(c.state().journal_blocking);
    assert!(!c.state().send_enabled());
    cleanup(&dir);
}

#[test]
fn restart_recovers_prepared_to_durable_not_broadcast_before_returning_unlocked() {
    let dir = temp_dir("restart-prepared-recovery");
    let mut original = unlocked(&dir, WalletProfile::default());
    let prepared = synthetic_prepared(41, 1, "RESTORED-PREPARED", 1);
    original
        .journal
        .append_prepared(prepared.prepared_record().clone())
        .unwrap();
    assert!(original.persist_journal_barrier());
    drop(original);

    let mut reopened = controller(&dir);
    reopened.handle_command(AppCommand::Unlock(Password::new(
        String::from_utf8(PW.to_vec()).unwrap(),
    )));
    reopened.pump_key();

    assert_eq!(reopened.state().phase, AppPhase::Unlocked);
    let journal = persisted_journal(&dir);
    assert!(matches!(
        journal.records()[0].latest_evidence(),
        DeliveryEvidence::NotBroadcast { .. }
    ));
    assert!(!reopened.state().journal_blocking);
    assert_eq!(
        reopened.state().journal_status,
        "",
        "the locally proven restart recovery no longer appears unresolved"
    );
    cleanup(&dir);
}

#[test]
fn restart_promotes_attempt_started_to_may_have_and_restarts_full_cooling() {
    let dir = temp_dir("restart-attempt-recovery");
    let mut original = unlocked(&dir, WalletProfile::default());
    let prepared = synthetic_prepared(42, 2, "RESTORED-ATTEMPT", 1);
    let record_id = prepared.record_id().clone();
    let external_hash = prepared.external_hash().clone();
    let prepared_endpoint = prepared
        .prepared_record()
        .ticket()
        .endpoint_identity()
        .to_owned();
    original
        .journal
        .append_prepared(prepared.prepared_record().clone())
        .unwrap();
    original
        .journal
        .append_delivery(
            &record_id,
            DeliveryEvidence::AttemptStarted {
                attempt_no: 1,
                route_id: prepared.route_id().to_owned(),
            },
        )
        .unwrap();
    original
        .state_mut()
        .activity
        .push(history_event(100, 1_700_000_100, AssetId::Native));
    assert!(original.persist_journal_barrier());
    drop(original);

    let mut reopened = controller(&dir);
    reopened.handle_command(AppCommand::Unlock(Password::new(
        String::from_utf8(PW.to_vec()).unwrap(),
    )));
    reopened.pump_key();

    let journal = persisted_journal(&dir);
    assert!(matches!(
        journal.records()[0].latest_evidence(),
        DeliveryEvidence::MayHaveBroadcast { .. }
    ));
    assert!(reopened.state().journal_blocking);
    assert!(!reopened.state().risk_override_eligible);
    assert_eq!(
        reopened.state().journal_status,
        "Unknown — transmission or outcome unknown"
    );
    assert_eq!(
        reopened.session.journal_reconcile_floor, None,
        "restart cannot reconstruct the original pre-send LT from newer Activity"
    );

    let fake = FakeChain::default();
    let mut wallet = timed_wallet(SEND_DEST);
    set_native_balance(&mut wallet, 5_000_000_000);
    fake.set_load_wallet(Ok(wallet.clone()));
    reopened.state_mut().wallet = Some(wallet);
    reopened.chain = Arc::new(fake.clone());

    let mut matching = fresh_sample_transaction();
    matching.lt = 44;
    matching
        .in_msg
        .as_mut()
        .expect("the outgoing sample has an external inbound message")
        .hash = external_hash.to_hex();
    let mut newer = matching.clone();
    newer.lt = 100;
    newer.hash = digest("RESTORED-NEWER-TX").to_hex();
    newer
        .in_msg
        .as_mut()
        .expect("the newer sample has an external inbound message")
        .hash = digest("RESTORED-NEWER-EXT").to_hex();
    fake.push_page(Ok(TransactionPage {
        transactions: vec![newer],
        skipped: 0,
        source_endpoint: prepared_endpoint.clone(),
        request_id: "restart-before-late-index".to_owned(),
    }));
    fake.push_page(Ok(TransactionPage {
        transactions: vec![matching],
        skipped: 0,
        source_endpoint: prepared_endpoint,
        request_id: "restart-after-late-index".to_owned(),
    }));

    reopened.fetch_transactions(reopened.subscription_generation);
    reopened.pump_events();
    assert!(reopened.state().journal_blocking);
    assert_eq!(reopened.session.history_synced_floor, Some(100));
    assert_eq!(reopened.session.journal_reconcile_floor, None);

    reopened.fetch_transactions(reopened.subscription_generation);
    reopened.pump_events();
    assert!(!reopened.state().journal_blocking);
    assert!(matches!(
        reopened
            .journal
            .record(&record_id)
            .unwrap()
            .latest_evidence(),
        DeliveryEvidence::VerifiedTerminal {
            outcome: TerminalOutcome::Success,
            ..
        }
    ));
    cleanup(&dir);
}

#[test]
fn wall_time_and_suspend_never_accelerate_cooling_or_change_delivery_evidence() {
    let dir = temp_dir("risk-cooling-suspend");
    let mut c = unlocked(&dir, WalletProfile::default());
    let prepared = synthetic_prepared(43, 3, "COOLING", 1);
    let record_id = prepared.record_id().clone();
    c.journal
        .append_prepared(prepared.prepared_record().clone())
        .unwrap();
    c.journal
        .append_delivery(
            &record_id,
            DeliveryEvidence::AttemptStarted {
                attempt_no: 1,
                route_id: prepared.route_id().to_owned(),
            },
        )
        .unwrap();
    c.journal
        .append_delivery(
            &record_id,
            DeliveryEvidence::MayHaveBroadcast {
                attempt_no: 1,
                route_id: prepared.route_id().to_owned(),
            },
        )
        .unwrap();
    assert!(c.persist_journal_barrier());
    c.refresh_journal_policy();
    c.session.risk_cooling_started_at = Some(
        Instant::now()
            .checked_sub(Duration::from_secs(
                cc_wallet_chain::RISK_OVERRIDE_COOLING_SECS,
            ))
            .unwrap(),
    );
    c.refresh_journal_policy();
    assert!(c.state().risk_override_eligible);

    c.last_tick = Some((Instant::now(), SystemTime::now() - Duration::from_secs(300)));
    c.tick();

    assert!(!c.state().risk_override_eligible);
    assert!(matches!(
        c.journal.record(&record_id).unwrap().latest_evidence(),
        DeliveryEvidence::MayHaveBroadcast { .. }
    ));
    assert!(c.state().journal_blocking);
    cleanup(&dir);
}

#[test]
fn endpoint_reconciliation_requires_exact_hash_account_and_is_idempotent() {
    const OTHER_SENDER: &str = "0:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
    let dir = temp_dir("endpoint-evidence-exact");
    let (mut c, fake) = ready_to_send(&dir);
    fake.set_prepared_hash(digest("ENDPOINT-MATCH"));
    fake.push_broadcast(Ok(CandidateBroadcastOutcome::MayHaveBroadcast {
        detail: "ambiguous write".to_owned(),
    }));
    c.dispatch_test_authorization();
    c.pump_events();
    let record_id = c.journal.records()[0].ticket().record_id().clone();
    let endpoint = c.journal.records()[0]
        .ticket()
        .endpoint_identity()
        .to_owned();
    let before = c
        .journal
        .record(&record_id)
        .unwrap()
        .delivery_events()
        .len();

    c.reconcile_endpoint_observations(
        c.subscription_generation,
        vec![
            endpoint_observation(
                digest("WRONG-HASH"),
                &endpoint,
                SEND_DEST,
                "wrong-hash-request",
                "wrong-hash-tx",
                true,
            ),
            endpoint_observation(
                digest("ENDPOINT-MATCH"),
                &endpoint,
                OTHER_SENDER,
                "wrong-account-request",
                "wrong-account-tx",
                true,
            ),
        ],
    );
    assert_eq!(
        c.journal
            .record(&record_id)
            .unwrap()
            .delivery_events()
            .len(),
        before,
        "wrong hash and wrong sender observations change no evidence"
    );

    c.apply_event(AppEvent::TransactionsLoaded {
        generation: c.subscription_generation,
        fetch_id: 0,
        head_refresh_only: false,
        events: Vec::new(),
        integrity_error: None,
        incomplete: true,
        gap: true,
        deepest_lt: None,
    });
    assert_eq!(
        c.journal
            .record(&record_id)
            .unwrap()
            .delivery_events()
            .len(),
        before,
        "a gap/null batch creates no delivery evidence"
    );
    assert!(c.state().journal_blocking);

    c.reconcile_endpoint_observations(
        c.subscription_generation,
        vec![
            endpoint_observation(
                digest("ENDPOINT-MATCH"),
                &endpoint,
                SEND_DEST,
                "matching-request",
                "matching-success-tx",
                true,
            ),
            endpoint_observation(
                digest("ENDPOINT-MATCH"),
                &endpoint,
                SEND_DEST,
                "same-transaction-new-rpc-request",
                "matching-success-tx",
                true,
            ),
        ],
    );
    let after_success = c
        .journal
        .record(&record_id)
        .unwrap()
        .delivery_events()
        .len();
    assert!(matches!(
        c.journal.record(&record_id).unwrap().latest_evidence(),
        DeliveryEvidence::VerifiedTerminal {
            outcome: TerminalOutcome::Success,
            proof_ref,
        } if proof_ref == &format!(
            "rpc-history:{}",
            digest("matching-success-tx").to_hex()
        )
    ));
    assert_eq!(after_success, before + 2);
    assert_eq!(c.state().journal_status, "");
    assert!(!c.state().journal_blocking);
    assert!(c.state().active_reservations.is_empty());
    assert!(!c.state().send_enabled());
    assert!(c.state().send_form.destination.is_empty());
    assert!(c.state().send_form.amount.is_empty());
    assert_eq!(
        c.state().status,
        "Success — confirmed in RPC transaction history"
    );

    c.reconcile_endpoint_observations(
        c.subscription_generation,
        vec![endpoint_observation(
            digest("ENDPOINT-MATCH"),
            &endpoint,
            SEND_DEST,
            "duplicate-request-with-new-id",
            "matching-success-tx",
            true,
        )],
    );
    assert_eq!(
        c.journal
            .record(&record_id)
            .unwrap()
            .delivery_events()
            .len(),
        after_success,
        "the same exact endpoint transaction is idempotent across RPC request ids"
    );
    cleanup(&dir);
}

#[test]
fn a_blocking_ack_retries_delayed_history_without_sse_or_relogin() {
    let dir = temp_dir("journal-delayed-history-poll");
    let (mut c, fake) = ready_to_send(&dir);
    let mut matching = fresh_sample_transaction();
    matching.lt = 44;
    let ext_msg_hash = Digest32::try_from_hex(
        &matching
            .in_msg
            .as_ref()
            .expect("the outgoing sample has an external inbound message")
            .hash,
    )
    .unwrap();
    fake.set_prepared_hash(ext_msg_hash);
    let mut newer = matching.clone();
    newer.lt = 100;
    newer.hash = digest("NEWER-HISTORY-TX").to_hex();
    newer
        .in_msg
        .as_mut()
        .expect("the newer transaction also has an inbound message")
        .hash = digest("NEWER-HISTORY-EXT").to_hex();

    let mut refreshed_wallet = timed_wallet(SEND_DEST);
    set_native_balance(&mut refreshed_wallet, 4_000_000_000);
    fake.set_load_wallet(Ok(refreshed_wallet));

    fake.push_page(Ok(TransactionPage {
        transactions: vec![newer],
        skipped: 0,
        source_endpoint: c.current_endpoint(),
        request_id: "history-before-indexing".to_owned(),
    }));
    fake.push_page(Ok(TransactionPage {
        transactions: vec![matching],
        skipped: 0,
        source_endpoint: c.current_endpoint(),
        request_id: "history-after-indexing".to_owned(),
    }));

    c.dispatch_test_authorization();
    c.pump_events();

    assert_eq!(fake.transaction_calls(), 1);
    assert!(c.state().journal_blocking);
    assert!(c.state().activity.iter().any(|event| event.pending));
    assert!(c.journal_reconcile_at.is_some());
    assert_eq!(c.session.history_synced_floor, Some(100));
    assert_eq!(
        c.session.journal_reconcile_floor, None,
        "the first clean post-send fetch must not move the captured pre-send floor"
    );

    c.journal_reconcile_at = Some(Instant::now());
    c.tick();
    c.pump_events();

    assert_eq!(fake.transaction_calls(), 2);
    assert!(!c.state().journal_blocking);
    assert!(c.state().active_reservations.is_empty());
    assert!(!c.state().activity.iter().any(|event| event.pending));
    assert!(c.journal_reconcile_at.is_none());
    assert_eq!(fake.load_wallet_calls(), 1);
    assert_eq!(
        c.state().wallet.as_ref().unwrap().native_balance(),
        4_000_000_000,
        "polling-only confirmation must refresh the wallet balance too"
    );
    assert!(matches!(
        c.journal.records()[0].latest_evidence(),
        DeliveryEvidence::VerifiedTerminal {
            outcome: TerminalOutcome::Success,
            proof_ref,
        } if proof_ref.starts_with("rpc-history:")
    ));
    cleanup(&dir);
}

#[test]
fn a_pruned_rpc_does_not_erase_local_history_or_poll_an_old_record_forever() {
    let dir = temp_dir("journal-pruned-rpc");
    let (mut c, _fake) = ready_to_send(&dir);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let old_time = now.saturating_sub(365 * 24 * 60 * 60);
    c.state_mut()
        .activity
        .push(history_event(700, old_time, AssetId::Native));
    c.sort_activity();

    let old_expiry =
        u32::try_from(now.saturating_sub(super::JOURNAL_RECONCILE_POST_EXPIRY_SECS + 1)).unwrap();
    install_blocking_history_record_with_expiry(
        &mut c,
        digest("OLD-UNRESOLVED-EXTERNAL"),
        0xc1,
        old_expiry,
    );

    assert!(c.state().journal_blocking);
    assert_eq!(c.session.journal_reconcile_floor, Some(700));
    assert!(
        c.journal_reconcile_at.is_none(),
        "an expired unresolved record remains blocked without perpetual background archive walks"
    );

    c.apply_event(AppEvent::TransactionsLoaded {
        generation: c.subscription_generation,
        fetch_id: 0,
        head_refresh_only: false,
        events: Vec::new(),
        integrity_error: None,
        incomplete: false,
        gap: false,
        deepest_lt: None,
    });
    c.tick();

    assert!(c.state().activity.iter().any(|event| event.lt == 700));
    assert!(c.state().journal_blocking);
    assert!(c.journal_reconcile_at.is_none());
    cleanup(&dir);
}

#[test]
fn risk_review_reconciles_fresh_history_before_opening_the_override() {
    let dir = temp_dir("risk-fresh-history-first");
    let (mut c, fake) = ready_to_send(&dir);
    let mut matching = fresh_sample_transaction();
    matching.lt = 55;
    let ext_msg_hash = Digest32::try_from_hex(
        &matching
            .in_msg
            .as_ref()
            .expect("the outgoing sample has an external inbound message")
            .hash,
    )
    .unwrap();
    let (record_id, endpoint) = install_blocking_history_record(&mut c, ext_msg_hash, 0xa1);
    c.session.risk_cooling_started_at = Some(
        Instant::now()
            .checked_sub(Duration::from_secs(
                cc_wallet_chain::RISK_OVERRIDE_COOLING_SECS,
            ))
            .unwrap(),
    );
    c.refresh_journal_policy();
    fake.push_page(Ok(TransactionPage {
        transactions: vec![matching],
        skipped: 0,
        source_endpoint: endpoint,
        request_id: "risk-preflight-history".to_owned(),
    }));

    c.handle_command(AppCommand::RequestRiskOverride);
    assert!(c.pending_risk_reconciliation);
    assert!(c.pending_authorization.is_some());
    c.pump_events();

    assert!(matches!(
        c.journal.record(&record_id).unwrap().latest_evidence(),
        DeliveryEvidence::VerifiedTerminal {
            outcome: TerminalOutcome::Success,
            proof_ref,
        } if proof_ref.starts_with("rpc-history:")
    ));
    assert!(!c.state().journal_blocking);
    assert!(!c.state().risk_review_open);
    assert!(c.pending_authorization.is_none());
    assert!(c.pending_risk_context.is_none());
    assert!(!c.state().busy);
    assert_ne!(
        c.state().status,
        "Checking the previous transfer before risk review…"
    );
    cleanup(&dir);
}

#[test]
fn cancelling_the_preflight_history_check_ignores_its_late_completion() {
    let dir = temp_dir("risk-cancel-preflight");
    let (mut c, fake) = ready_to_send(&dir);
    install_blocking_history_record(&mut c, digest("RISK-CANCEL-BLOCKER"), 0xa2);
    c.session.risk_cooling_started_at = Some(
        Instant::now()
            .checked_sub(Duration::from_secs(
                cc_wallet_chain::RISK_OVERRIDE_COOLING_SECS,
            ))
            .unwrap(),
    );
    c.refresh_journal_policy();
    fake.push_page(Ok(TransactionPage {
        transactions: Vec::new(),
        skipped: 0,
        source_endpoint: c.current_endpoint(),
        request_id: "cancelled-risk-preflight".to_owned(),
    }));

    c.handle_command(AppCommand::RequestRiskOverride);
    assert!(c.pending_risk_reconciliation);
    assert!(c.load.fetch_in_flight);
    c.handle_command(AppCommand::CancelRiskOverride);
    assert!(!c.pending_risk_reconciliation);
    assert!(c.pending_authorization.is_none());
    assert!(!c.state().busy);

    c.pump_events();

    assert!(c.state().journal_blocking);
    assert!(!c.state().risk_review_open);
    assert!(c.pending_authorization.is_none());
    assert!(c.pending_risk_context.is_none());
    cleanup(&dir);
}

#[test]
fn a_reconnect_during_the_risk_preflight_aborts_the_stranded_reconciliation() {
    let dir = temp_dir("risk-preflight-reconnect");
    let (mut c, fake) = ready_to_send(&dir);
    install_blocking_history_record(&mut c, digest("RISK-RECONNECT-BLOCKER"), 0xa4);
    c.session.risk_cooling_started_at = Some(
        Instant::now()
            .checked_sub(Duration::from_secs(
                cc_wallet_chain::RISK_OVERRIDE_COOLING_SECS,
            ))
            .unwrap(),
    );
    c.refresh_journal_policy();
    fake.push_page(Ok(TransactionPage {
        transactions: Vec::new(),
        skipped: 0,
        source_endpoint: c.current_endpoint(),
        request_id: "stranded-risk-preflight".to_owned(),
    }));

    c.handle_command(AppCommand::RequestRiskOverride);
    assert!(c.pending_risk_reconciliation);
    assert!(c.state().busy);
    assert!(c.load.fetch_in_flight);
    assert!(!c.load.fetch_again);

    c.subscription_generation = c.subscription_generation.wrapping_add(1);
    c.pump_events();

    assert!(!c.pending_risk_reconciliation);
    assert!(!c.state().busy);
    assert!(c.pending_authorization.is_none());
    assert!(c.pending_risk_context.is_none());
    assert!(!c.state().risk_review_open);
    assert!(
        c.state()
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("restarted"),
        "the user is told the pre-check was interrupted and to retry"
    );
    assert!(c.state().journal_blocking);
    cleanup(&dir);
}

#[test]
fn a_stale_completion_with_a_queued_refire_does_not_abort_the_preflight() {
    let dir = temp_dir("risk-preflight-refire-gate");
    let (mut c, fake) = ready_to_send(&dir);
    install_blocking_history_record(&mut c, digest("RISK-REFIRE-BLOCKER"), 0xa5);
    c.session.risk_cooling_started_at = Some(
        Instant::now()
            .checked_sub(Duration::from_secs(
                cc_wallet_chain::RISK_OVERRIDE_COOLING_SECS,
            ))
            .unwrap(),
    );
    c.refresh_journal_policy();
    fake.push_page(Ok(TransactionPage {
        transactions: Vec::new(),
        skipped: 0,
        source_endpoint: c.current_endpoint(),
        request_id: "refire-risk-preflight".to_owned(),
    }));

    c.handle_command(AppCommand::RequestRiskOverride);
    assert!(c.pending_risk_reconciliation);
    let stale_gen = c.subscription_generation;

    c.subscription_generation = c.subscription_generation.wrapping_add(1);
    c.load.fetch_again = true;
    c.apply_event(AppEvent::TransactionsLoaded {
        generation: stale_gen,
        fetch_id: 0,
        head_refresh_only: false,
        events: Vec::new(),
        integrity_error: None,
        incomplete: false,
        gap: false,
        deepest_lt: None,
    });

    assert!(c.pending_risk_reconciliation);
    assert!(c.pending_authorization.is_some());
    assert!(c.state().busy);
    assert!(!c.load.fetch_again, "the refire consumed the queued flag");
    assert!(c.state().error.is_none());
    cleanup(&dir);
}

#[test]
fn endpoint_reported_failure_preserves_effects_and_becomes_terminal() {
    let dir = temp_dir("endpoint-failed-evidence");
    let (mut c, fake) = ready_to_send(&dir);
    fake.set_prepared_hash(digest("ENDPOINT-FAILED"));
    fake.push_broadcast(Ok(CandidateBroadcastOutcome::NodeResponseObserved {
        request_id: "remote-rejection".to_owned(),
        response: cc_wallet_domain::NodeResponseKind::Rejected,
        detail: "remote response is not delivery proof".to_owned(),
    }));
    c.dispatch_test_authorization();
    c.pump_events();
    let record_id = c.journal.records()[0].ticket().record_id().clone();
    let endpoint = c.journal.records()[0]
        .ticket()
        .endpoint_identity()
        .to_owned();

    c.reconcile_endpoint_observations(
        c.subscription_generation,
        vec![endpoint_observation(
            digest("ENDPOINT-FAILED"),
            &endpoint,
            SEND_DEST,
            "failed-tx-request",
            "failed-tx",
            false,
        )],
    );

    let record = c.journal.record(&record_id).unwrap();
    let events = record.delivery_events();
    assert!(matches!(
        events[events.len() - 2].evidence(),
        DeliveryEvidence::EndpointReportedFailedOnChain { tx }
            if !tx.success() && tx.exit_code() == 37 && tx.effects().len() == 1
    ));
    assert!(matches!(
        record.latest_evidence(),
        DeliveryEvidence::VerifiedTerminal {
            outcome: TerminalOutcome::FailedOnChain,
            proof_ref,
        } if proof_ref.starts_with("rpc-history:")
    ));
    assert_eq!(c.state().journal_status, "");
    assert!(!c.state().journal_blocking);
    assert!(c.state().active_reservations.is_empty());
    assert_eq!(
        c.state().status,
        "Failed on-chain — confirmed in RPC transaction history"
    );
    cleanup(&dir);
}

#[test]
fn conflicting_transactions_for_one_external_message_change_no_evidence() {
    let dir = temp_dir("endpoint-conflicting-evidence");
    let (mut c, fake) = ready_to_send(&dir);
    fake.set_prepared_hash(digest("ENDPOINT-CONFLICT"));
    fake.push_broadcast(Ok(CandidateBroadcastOutcome::MayHaveBroadcast {
        detail: "ambiguous write".to_owned(),
    }));
    c.dispatch_test_authorization();
    c.pump_events();
    let record_id = c.journal.records()[0].ticket().record_id().clone();
    let endpoint = c.journal.records()[0]
        .ticket()
        .endpoint_identity()
        .to_owned();
    let before = c
        .journal
        .record(&record_id)
        .unwrap()
        .delivery_events()
        .len();

    c.reconcile_endpoint_observations(
        c.subscription_generation,
        vec![
            endpoint_observation(
                digest("ENDPOINT-CONFLICT"),
                &endpoint,
                SEND_DEST,
                "conflict-request-a",
                "conflict-tx-a",
                true,
            ),
            endpoint_observation(
                digest("ENDPOINT-CONFLICT"),
                &endpoint,
                SEND_DEST,
                "conflict-request-b",
                "conflict-tx-b",
                true,
            ),
        ],
    );

    assert_eq!(
        c.journal
            .record(&record_id)
            .unwrap()
            .delivery_events()
            .len(),
        before
    );
    assert!(c.state().journal_blocking);
    assert!(
        c.state()
            .error
            .as_deref()
            .is_some_and(|error| error.contains("conflicting details"))
    );
    assert_eq!(
        persisted_journal(&dir)
            .record(&record_id)
            .unwrap()
            .delivery_events()
            .len(),
        before
    );
    assert!(!c.state().active_reservations.is_empty());

    c.reconcile_endpoint_observations(
        c.subscription_generation,
        vec![endpoint_observation(
            digest("ENDPOINT-CONFLICT"),
            &endpoint,
            SEND_DEST,
            "clean-retry-request",
            "conflict-tx-a",
            true,
        )],
    );
    assert!(c.state().error.is_none());
    assert!(matches!(
        c.journal.record(&record_id).unwrap().latest_evidence(),
        DeliveryEvidence::VerifiedTerminal {
            outcome: TerminalOutcome::Success,
            proof_ref,
        } if proof_ref.starts_with("rpc-history:")
    ));
    assert!(!c.state().journal_blocking);
    assert!(c.state().active_reservations.is_empty());
    cleanup(&dir);
}

#[test]
fn observing_an_older_record_does_not_clear_a_different_in_flight_send() {
    let dir = temp_dir("endpoint-old-record-during-new-send");
    let (mut c, fake) = ready_to_send(&dir);
    fake.set_prepared_hash(digest("OLDER-ENDPOINT-MATCH"));
    fake.push_broadcast(Ok(CandidateBroadcastOutcome::MayHaveBroadcast {
        detail: "older transfer outcome unknown".to_owned(),
    }));
    c.dispatch_test_authorization();
    c.pump_events();
    let old_record_id = c.journal.records()[0].ticket().record_id().clone();
    let endpoint = c.journal.records()[0]
        .ticket()
        .endpoint_identity()
        .to_owned();

    let newer_record_id = RecordId::from_bytes([0xabu8; 32]);
    c.session.in_flight_record_id = Some(newer_record_id.clone());
    c.session.awaiting_send_lt = Some(777);
    c.state_mut().sending = true;
    c.state_mut().busy = true;
    c.state_mut().status = "Preparing a newer transfer".to_owned();

    c.reconcile_endpoint_observations(
        c.subscription_generation,
        vec![endpoint_observation(
            digest("OLDER-ENDPOINT-MATCH"),
            &endpoint,
            SEND_DEST,
            "older-match-request",
            "older-match-tx",
            true,
        )],
    );

    assert!(matches!(
        c.journal.record(&old_record_id).unwrap().latest_evidence(),
        DeliveryEvidence::VerifiedTerminal {
            outcome: TerminalOutcome::Success,
            proof_ref,
        } if proof_ref.starts_with("rpc-history:")
    ));
    assert_eq!(
        c.session.in_flight_record_id.as_ref(),
        Some(&newer_record_id)
    );
    assert_eq!(c.session.awaiting_send_lt, Some(777));
    assert!(c.state().sending);
    assert!(c.state().busy);
    assert_eq!(c.state().status, "Preparing a newer transfer");
    cleanup(&dir);
}

#[test]
fn a_late_socket_outcome_cannot_downgrade_endpoint_transaction_evidence() {
    let dir = temp_dir("endpoint-before-socket-result");
    let mut c = unlocked(&dir, WalletProfile::default());
    let prepared = synthetic_prepared(63, 9, "ENDPOINT-BEFORE-ACK", 1);
    let record_id = prepared.record_id().clone();
    let endpoint = prepared
        .prepared_record()
        .ticket()
        .endpoint_identity()
        .to_owned();
    let sender = prepared
        .prepared_record()
        .ticket()
        .sender_address()
        .to_owned();
    c.journal
        .append_prepared(prepared.prepared_record().clone())
        .unwrap();
    c.journal
        .append_delivery(
            &record_id,
            DeliveryEvidence::AttemptStarted {
                attempt_no: 1,
                route_id: prepared.route_id().to_owned(),
            },
        )
        .unwrap();
    assert!(c.persist_journal_barrier());
    c.state_mut().sending = true;
    c.state_mut().busy = true;
    c.state_mut().send_form.amount = "9.0".to_owned();
    c.state_mut().recipient_check = RecipientCheck::Known(DestinationAccountStatus::Uninit);
    c.state_mut().allow_unbounced = true;
    c.session.in_flight_record_id = Some(record_id.clone());

    c.reconcile_endpoint_observations(
        c.subscription_generation,
        vec![endpoint_observation(
            digest("ENDPOINT-BEFORE-ACK"),
            &endpoint,
            &sender,
            "endpoint-first",
            "endpoint-first-tx",
            true,
        )],
    );
    assert!(
        c.state().send_form.amount.is_empty(),
        "terminal endpoint evidence clears the completed transfer amount"
    );
    assert!(
        c.state().send_form.destination.is_empty(),
        "terminal endpoint evidence clears the completed transfer recipient"
    );
    assert_eq!(c.state().recipient_check, RecipientCheck::Unchecked);
    assert!(!c.state().allow_unbounced);
    c.handle_command(AppCommand::SetSendDestination(OTHER_SEND_DEST.to_owned()));
    c.handle_command(AppCommand::SetSendAmount("0.5".to_owned()));
    c.apply_candidate_outcome(
        c.session_generation,
        prepared,
        0,
        CandidateBroadcastOutcome::NodeResponseObserved {
            request_id: "late-ack".to_owned(),
            response: cc_wallet_domain::NodeResponseKind::Acknowledged,
            detail: "late socket completion".to_owned(),
        },
    );

    assert!(matches!(
        persisted_journal(&dir)
            .record(&record_id)
            .unwrap()
            .latest_evidence(),
        DeliveryEvidence::VerifiedTerminal { proof_ref, .. }
            if proof_ref.starts_with("rpc-history:")
    ));
    assert!(!c.state().sending);
    assert!(!c.state().busy);
    assert_eq!(
        c.state().send_form.amount,
        "0.5",
        "a late socket result for the completed transfer must not erase newer input"
    );
    assert_eq!(
        c.state().send_form.destination,
        OTHER_SEND_DEST,
        "a late socket result for the completed transfer must not erase a newer recipient"
    );
    assert!(!c.state().journal_blocking);
    assert!(c.state().journal_status.is_empty());
    assert_eq!(
        c.state().status,
        "Success — confirmed in RPC transaction history"
    );
    cleanup(&dir);
}

#[test]
fn restart_normalizes_endpoint_report_to_terminal_and_releases_reservation() {
    let dir = temp_dir("restart-endpoint-report-remains-blocking");
    let mut original = unlocked(&dir, WalletProfile::default());
    let prepared = synthetic_prepared(64, 10, "LEGACY-ENDPOINT-MATCH", 1);
    let record_id = prepared.record_id().clone();
    let endpoint = prepared
        .prepared_record()
        .ticket()
        .endpoint_identity()
        .to_owned();
    let sender = prepared
        .prepared_record()
        .ticket()
        .sender_address()
        .to_owned();
    original
        .journal
        .append_prepared(prepared.prepared_record().clone())
        .unwrap();
    original
        .journal
        .append_delivery(
            &record_id,
            DeliveryEvidence::AttemptStarted {
                attempt_no: 1,
                route_id: prepared.route_id().to_owned(),
            },
        )
        .unwrap();
    original
        .journal
        .append_delivery(
            &record_id,
            DeliveryEvidence::EndpointReportedSuccess {
                tx: endpoint_observation(
                    digest("LEGACY-ENDPOINT-MATCH"),
                    &endpoint,
                    &sender,
                    "legacy-request",
                    "legacy-tx",
                    true,
                ),
            },
        )
        .unwrap();
    let future_authorization = send_authorization(65, 11);
    let future_ticket = future_authorization.ticket();
    let legacy_blocker_digest = blocker_set_digest(&[BlockerRow::new(
        record_id.clone(),
        EvidenceTag::EndpointReportedSuccess,
        digest("LEGACY-ENDPOINT-MATCH"),
    )
    .unwrap()])
    .unwrap();
    let legacy_reservation_digest =
        reservation_set_digest(original.journal.record(&record_id).unwrap().reservations())
            .unwrap();
    let legacy_grant = RiskGrant::new(
        legacy_blocker_digest,
        legacy_reservation_digest,
        future_ticket.digest().unwrap(),
        future_ticket.record_id().clone(),
        RiskNonce::from_bytes([0x65; 32]),
        RISK_WARNING_VERSION,
        overlap_set_digest(&[]).unwrap(),
    );
    original.journal.append_risk_grant(legacy_grant).unwrap();
    assert!(original.persist_journal_barrier());
    drop(original);

    let mut reopened = controller(&dir);
    reopened.handle_command(AppCommand::Unlock(Password::new(
        String::from_utf8(PW.to_vec()).unwrap(),
    )));
    reopened.pump_key();

    assert_eq!(reopened.state().phase, AppPhase::Unlocked);
    assert!(!reopened.state().journal_blocking);
    assert!(reopened.state().active_reservations.is_empty());
    assert_eq!(persisted_journal(&dir).risk_events().len(), 1);
    assert!(matches!(
        persisted_journal(&dir)
            .record(&record_id)
            .unwrap()
            .latest_evidence(),
        DeliveryEvidence::VerifiedTerminal {
            outcome: TerminalOutcome::Success,
            proof_ref,
        } if proof_ref.starts_with("rpc-history:")
    ));
    assert!(reopened.state().journal_status.is_empty());
    cleanup(&dir);
}

#[test]
fn duplicate_risk_request_with_an_empty_new_form_is_friendly_and_edit_scoped() {
    let dir = temp_dir("risk-empty-new-form");
    let (mut c, fake) = ready_to_send(&dir);
    fake.push_broadcast(Ok(CandidateBroadcastOutcome::MayHaveBroadcast {
        detail: "old transfer outcome unknown".to_owned(),
    }));
    c.dispatch_test_authorization();
    c.pump_events();
    c.session.risk_cooling_started_at = Some(
        Instant::now()
            .checked_sub(Duration::from_secs(
                cc_wallet_chain::RISK_OVERRIDE_COOLING_SECS,
            ))
            .unwrap(),
    );
    c.refresh_journal_policy();
    assert!(c.state().risk_override_eligible);

    c.state_mut().send_form.destination = SEND_DEST.to_owned();
    c.state_mut().send_form.amount.clear();
    assert!(!c.state().risk_override_form_ready());
    let prior_status = c.state().status.clone();
    c.handle_command(AppCommand::RequestRiskOverride);

    assert_eq!(
        c.state().error.as_deref(),
        Some(
            "Enter a valid recipient and positive amount for the new transfer before reviewing duplicate risk"
        )
    );
    assert!(c.state().send_form_error);
    assert!(c.pending_authorization.is_none());
    assert!(!c.state().risk_review_open);

    c.handle_command(AppCommand::SetSendAmount("2.0".to_owned()));
    assert!(c.state().risk_override_form_ready());
    assert!(!c.state().send_form_error);
    assert!(c.state().error.is_none());
    assert_eq!(c.state().status, prior_status);

    c.state_mut().snapshot_refresh_error = Some("snapshot failed".to_owned());
    c.state_mut().send_form.amount.clear();
    c.handle_command(AppCommand::RequestRiskOverride);
    assert!(!c.state().send_form_error);
    assert!(
        c.state()
            .error
            .as_deref()
            .is_some_and(|error| error.contains("valid refresh"))
    );
    c.handle_command(AppCommand::SetSendAmount("2.0".to_owned()));
    assert!(
        c.state()
            .error
            .as_deref()
            .is_some_and(|error| error.contains("valid refresh")),
        "editing a form-scoped field must not hide a snapshot/integrity blocker"
    );
    cleanup(&dir);
}

#[test]
fn ambiguous_transfer_can_use_one_durable_exact_duplicate_risk_grant() {
    let dir = temp_dir("risk-grant-consumption");
    let (mut c, fake) = ready_to_send(&dir);
    fake.set_prepared_hash(digest("OLD-RISK-RECORD"));
    fake.push_broadcast(Ok(CandidateBroadcastOutcome::MayHaveBroadcast {
        detail: "old transfer outcome unknown".to_owned(),
    }));
    c.dispatch_test_authorization();
    c.pump_events();
    assert_eq!(c.journal.records().len(), 1);
    let old_record_id = c.journal.records()[0].ticket().record_id().clone();
    assert!(matches!(
        c.journal.record(&old_record_id).unwrap().latest_evidence(),
        DeliveryEvidence::MayHaveBroadcast { .. }
    ));
    assert!(c.state().journal_blocking);
    assert!(!c.state().active_reservations.is_empty());

    c.state_mut().send_form.destination = SEND_DEST.to_owned();
    c.state_mut().send_form.amount = "2.0".to_owned();
    c.state_mut().recipient_check = RecipientCheck::Known(DestinationAccountStatus::Uninit);
    c.state_mut().allow_unbounced = true;
    let mut fresh = timed_wallet("0:me");
    set_native_balance(&mut fresh, 5_000_000_000);
    fake.set_load_wallet(Ok(fresh));
    c.session.risk_cooling_started_at = Some(
        Instant::now()
            .checked_sub(Duration::from_secs(
                cc_wallet_chain::RISK_OVERRIDE_COOLING_SECS,
            ))
            .unwrap(),
    );
    c.refresh_journal_policy();
    assert!(c.state().risk_override_eligible);

    c.handle_command(AppCommand::RequestRiskOverride);
    c.pump_events();

    assert!(c.state().risk_review_open);
    assert!(c.state().risk_requires_duplicate_confirmation);
    assert!(
        c.state()
            .risk_review_details
            .contains("Both transfers may debit; native fees may burn")
    );
    assert!(
        c.state()
            .risk_review_details
            .contains(&digest("OLD-RISK-RECORD").to_hex())
    );
    assert!(c.state().risk_review_details.contains("asset Native"));
    assert!(c.state().risk_review_details.contains("amount 1.000000000"));
    assert!(c.state().risk_review_details.contains("amount 2.000000000"));
    assert_eq!(c.state().risk_overlap_labels.len(), 1);

    c.handle_command(AppCommand::ConfirmRiskOverride {
        typed_confirmation: String::new(),
        acknowledge_both_may_debit: false,
        acknowledge_duplicate: true,
    });
    assert!(c.state().risk_review_open);
    assert!(persisted_journal(&dir).risk_events().is_empty());

    c.handle_command(AppCommand::SetRiskOverlap {
        index: 0,
        selected: true,
    });
    c.handle_command(AppCommand::ConfirmRiskOverride {
        typed_confirmation: String::new(),
        acknowledge_both_may_debit: true,
        acknowledge_duplicate: true,
    });

    let granted = persisted_journal(&dir);
    assert_eq!(granted.risk_events().len(), 1, "grant is durable first");
    assert_eq!(granted.records().len(), 1, "no new Prepared exists yet");
    let authorization = c
        .pending_authorization
        .as_ref()
        .expect("the exact granted ticket proceeds to authentication");
    let authorization_generation = authorization.generation();
    let authorization_nonce = authorization.nonce();
    let authorized_ticket = authorization.ticket().clone();
    assert!(c.pending_risk_consumption.is_some());
    assert!(c.state().auth.open);
    assert!(!c.state().auth.send_options_editable);

    let vault = Vault::create_with(PW, CHEAP).unwrap();
    c.apply_key_msg(KeyMsg::Ok {
        history_corrupt: false,
        journal: cc_wallet_domain::JournalEnvelope::empty(),
        selected: None,
        writer: None,
        generation: c.key_generation(),
        history: Vec::new(),
        action: KeyAction::ConfirmSend {
            remember: false,
            auth_generation: authorization_generation,
            auth_nonce: authorization_nonce,
        },
        vault,
        profile: WalletProfile::default(),
    });
    c.pump_events();

    let final_journal = persisted_journal(&dir);
    assert_eq!(final_journal.risk_events().len(), 2);
    assert_eq!(final_journal.records().len(), 2);
    assert!(matches!(
        final_journal
            .record(&old_record_id)
            .unwrap()
            .latest_evidence(),
        DeliveryEvidence::MayHaveBroadcast { .. }
    ));
    assert!(
        final_journal.record(&old_record_id).unwrap().is_blocking(),
        "the one-shot authority never rewrites or releases the ambiguous evidence"
    );
    let consumption_seq = final_journal.risk_events()[1].journal_seq();
    let new_record = final_journal
        .record(authorized_ticket.record_id())
        .expect("the consumed ticket owns the new Prepared");
    assert_eq!(
        new_record.delivery_events()[0].journal_seq(),
        consumption_seq + 1,
        "Consumption and its exact Prepared are atomically adjacent"
    );
    let (_, sent_ticket, active, overlap) = fake.last_prepare().unwrap();
    assert_eq!(sent_ticket, authorized_ticket);
    assert_eq!(active.len(), 1, "the old reservation remains active");
    assert_eq!(overlap, active, "only the explicitly selected row overlaps");
    assert!(c.pending_risk_consumption.is_none());
    cleanup(&dir);
}

#[test]
fn endpoint_observation_cancels_a_stale_risk_grant_and_releases_the_blocker() {
    let dir = temp_dir("risk-grant-endpoint-race");
    let (mut c, fake) = ready_to_send(&dir);
    fake.set_prepared_hash(digest("RISK-RACE-OLD"));
    fake.push_broadcast(Ok(CandidateBroadcastOutcome::MayHaveBroadcast {
        detail: "old transfer outcome unknown".to_owned(),
    }));
    c.dispatch_test_authorization();
    c.pump_events();
    let old_record_id = c.journal.records()[0].ticket().record_id().clone();
    let endpoint = c.journal.records()[0]
        .ticket()
        .endpoint_identity()
        .to_owned();

    c.state_mut().send_form.destination = SEND_DEST.to_owned();
    c.state_mut().send_form.amount = "2.0".to_owned();
    c.state_mut().recipient_check = RecipientCheck::Known(DestinationAccountStatus::Active);
    let mut fresh = timed_wallet("0:me");
    set_native_balance(&mut fresh, 5_000_000_000);
    fake.set_load_wallet(Ok(fresh));
    c.session.risk_cooling_started_at = Some(
        Instant::now()
            .checked_sub(Duration::from_secs(
                cc_wallet_chain::RISK_OVERRIDE_COOLING_SECS,
            ))
            .unwrap(),
    );
    c.refresh_journal_policy();
    c.handle_command(AppCommand::RequestRiskOverride);
    c.pump_events();
    c.handle_command(AppCommand::SetRiskOverlap {
        index: 0,
        selected: true,
    });
    c.handle_command(AppCommand::ConfirmRiskOverride {
        typed_confirmation: String::new(),
        acknowledge_both_may_debit: true,
        acknowledge_duplicate: true,
    });

    let authorization = c
        .pending_authorization
        .as_ref()
        .expect("the durable grant owns a runtime authorization");
    let authorization_generation = authorization.generation();
    let authorization_nonce = authorization.nonce();
    assert!(c.pending_risk_consumption.is_some());
    assert_eq!(persisted_journal(&dir).risk_events().len(), 1);

    let vault = Vault::create_with(PW, CHEAP).unwrap();
    c.apply_key_msg(KeyMsg::Ok {
        history_corrupt: false,
        journal: cc_wallet_domain::JournalEnvelope::empty(),
        selected: None,
        writer: None,
        generation: c.key_generation(),
        history: Vec::new(),
        action: KeyAction::ConfirmSend {
            remember: false,
            auth_generation: authorization_generation,
            auth_nonce: authorization_nonce,
        },
        vault,
        profile: WalletProfile::default(),
    });
    assert!(c.state().sending);
    assert!(c.state().busy);
    assert!(c.pending_risk_consumption.is_some());
    assert!(c.session.in_flight_record_id.is_none());

    c.reconcile_endpoint_observations(
        c.subscription_generation,
        vec![endpoint_observation(
            digest("RISK-RACE-OLD"),
            &endpoint,
            SEND_DEST,
            "risk-race-request",
            "risk-race-tx",
            true,
        )],
    );

    assert!(c.pending_risk_consumption.is_none());
    assert!(c.state().sending);
    assert!(c.state().busy);
    assert_eq!(c.state().persistence_health, PersistenceHealth::Ready);
    assert!(matches!(
        c.journal.record(&old_record_id).unwrap().latest_evidence(),
        DeliveryEvidence::VerifiedTerminal {
            outcome: TerminalOutcome::Success,
            proof_ref,
        } if proof_ref.starts_with("rpc-history:")
    ));
    assert!(!c.state().journal_blocking);
    assert!(c.state().active_reservations.is_empty());

    c.pump_events();

    let persisted = persisted_journal(&dir);
    assert_eq!(persisted.records().len(), 1);
    assert_eq!(persisted.risk_events().len(), 1);
    assert_eq!(c.state().persistence_health, PersistenceHealth::Ready);
    assert!(!c.state().sending);
    assert!(!c.state().busy);
    assert!(
        c.state()
            .error
            .as_deref()
            .is_some_and(|error| error.contains("one-use grant"))
    );
    cleanup(&dir);
}

#[test]
fn endpoint_observation_silently_cancels_a_queued_stale_risk_context_failure() {
    let dir = temp_dir("risk-context-endpoint-race");
    let (mut c, fake) = ready_to_send(&dir);
    fake.set_prepared_hash(digest("RISK-CONTEXT-OLD"));
    fake.push_broadcast(Ok(CandidateBroadcastOutcome::MayHaveBroadcast {
        detail: "old transfer outcome unknown".to_owned(),
    }));
    c.dispatch_test_authorization();
    c.pump_events();
    let old_record_id = c.journal.records()[0].ticket().record_id().clone();
    let endpoint = c.journal.records()[0]
        .ticket()
        .endpoint_identity()
        .to_owned();

    c.state_mut().send_form.destination = SEND_DEST.to_owned();
    c.state_mut().send_form.amount = "2.0".to_owned();
    fake.set_load_wallet(Err(ChainError::Wallet(
        "late risk-context failure".to_owned(),
    )));
    c.session.risk_cooling_started_at = Some(
        Instant::now()
            .checked_sub(Duration::from_secs(
                cc_wallet_chain::RISK_OVERRIDE_COOLING_SECS,
            ))
            .unwrap(),
    );
    c.refresh_journal_policy();
    c.handle_command(AppCommand::RequestRiskOverride);
    assert!(c.pending_risk_context.is_some());
    assert!(c.state().busy);

    c.reconcile_endpoint_observations(
        c.subscription_generation,
        vec![endpoint_observation(
            digest("RISK-CONTEXT-OLD"),
            &endpoint,
            SEND_DEST,
            "risk-context-terminal-request",
            "risk-context-terminal-tx",
            true,
        )],
    );

    assert!(c.pending_risk_context.is_none());
    assert!(c.pending_authorization.is_none());
    assert!(!c.state().busy);
    assert!(matches!(
        c.journal.record(&old_record_id).unwrap().latest_evidence(),
        DeliveryEvidence::VerifiedTerminal {
            outcome: TerminalOutcome::Success,
            proof_ref,
        } if proof_ref.starts_with("rpc-history:")
    ));
    assert!(!c.state().journal_blocking);
    assert!(c.state().active_reservations.is_empty());
    assert_eq!(
        c.state().status,
        "Success — confirmed in RPC transaction history"
    );
    assert!(c.state().error.is_none());

    c.pump_events();

    assert_eq!(
        c.state().status,
        "Success — confirmed in RPC transaction history"
    );
    assert!(c.state().error.is_none());
    assert!(!c.state().risk_review_open);
    cleanup(&dir);
}

#[test]
fn risk_context_rpc_keeps_the_exact_authorization_busy_gate_installed() {
    let dir = temp_dir("risk-context-busy-gate");
    let (mut c, fake) = ready_to_send(&dir);
    fake.push_broadcast(Ok(CandidateBroadcastOutcome::MayHaveBroadcast {
        detail: "old transfer outcome unknown".to_owned(),
    }));
    c.dispatch_test_authorization();
    c.pump_events();
    c.state_mut().send_form.destination = SEND_DEST.to_owned();
    c.state_mut().send_form.amount = "2.0".to_owned();

    let mut fresh = timed_wallet("0:me");
    set_native_balance(&mut fresh, 5_000_000_000);
    fake.set_load_wallet(Ok(fresh));
    c.session.risk_cooling_started_at = Some(
        Instant::now()
            .checked_sub(Duration::from_secs(
                cc_wallet_chain::RISK_OVERRIDE_COOLING_SECS,
            ))
            .unwrap(),
    );
    c.refresh_journal_policy();
    let original_form = c.state().send_form.clone();

    c.handle_command(AppCommand::RequestRiskOverride);
    assert!(
        c.pending_authorization.is_some(),
        "the non-Clone capability stays in the controller during the RPC"
    );
    c.handle_command(AppCommand::SetSendAmount("2.0".to_owned()));
    assert_eq!(c.state().send_form, original_form);
    assert!(
        c.state()
            .error
            .as_deref()
            .is_some_and(|error| error.contains("authorization snapshot"))
    );

    c.pump_events();
    assert!(c.pending_authorization.is_none());
    assert!(c.pending_risk_review.is_some());
    assert!(c.state().risk_review_open);
    cleanup(&dir);
}

#[test]
fn risk_review_rejects_balances_with_network_time_from_another_endpoint() {
    let dir = temp_dir("risk-context-wrong-endpoint");
    let (mut c, fake) = ready_to_send(&dir);
    fake.push_broadcast(Ok(CandidateBroadcastOutcome::MayHaveBroadcast {
        detail: "old outcome unknown".to_owned(),
    }));
    c.dispatch_test_authorization();
    c.pump_events();
    c.state_mut().send_form.destination = SEND_DEST.to_owned();
    c.state_mut().send_form.amount = "2.0".to_owned();

    let mut wrong_source = WalletSnapshot::new_with_network_time(
        SEND_DEST,
        0,
        "Active",
        5_000_000_000,
        Default::default(),
        0,
        Some(
            ObservedNetworkTime::new(
                1_700_000_000,
                "https://different.example/",
                "wrong-endpoint-request",
                Instant::now(),
            )
            .unwrap(),
        ),
    )
    .unwrap();
    set_native_balance(&mut wrong_source, 5_000_000_000);
    fake.set_load_wallet(Ok(wrong_source));
    c.session.risk_cooling_started_at = Some(
        Instant::now()
            .checked_sub(Duration::from_secs(
                cc_wallet_chain::RISK_OVERRIDE_COOLING_SECS,
            ))
            .unwrap(),
    );
    c.refresh_journal_policy();

    c.handle_command(AppCommand::RequestRiskOverride);
    c.pump_events();

    assert!(!c.state().risk_review_open);
    assert!(c.pending_authorization.is_none());
    assert!(c.pending_risk_review.is_none());
    assert!(
        c.state()
            .error
            .as_deref()
            .is_some_and(|error| error.contains("exact authorized endpoint"))
    );
    assert!(persisted_journal(&dir).risk_events().is_empty());
    cleanup(&dir);
}

#[test]
fn cancelling_risk_review_revokes_every_runtime_authorization_capability() {
    let dir = temp_dir("risk-cancel-capability");
    let mut c = unlocked(&dir, WalletProfile::default());
    let authorization = send_authorization(7, 8);
    let authorization_generation = authorization.generation();
    let authorization_nonce = authorization.nonce();
    let ticket_digest = authorization.ticket().digest().unwrap();
    let record_id = authorization.ticket().record_id().clone();
    c.pending_authorization = Some(authorization);
    c.pending_risk_consumption = Some(PendingRiskConsumption {
        consumption: RiskGrantConsumption::new(
            RiskNonce::from_bytes([9; 32]),
            record_id,
            ticket_digest.clone(),
        ),
        overlap: Vec::new(),
    });
    c.state_mut().auth = AuthModal {
        open: true,
        mode: AuthMode::Enter,
        purpose: AuthPurpose::Send,
        send_options_editable: false,
        error: String::new(),
    };

    c.handle_command(AppCommand::RequestRiskOverride);
    let retained = c
        .pending_authorization
        .as_ref()
        .expect("the active authorization remains busy-gated");
    assert_eq!(retained.generation(), authorization_generation);
    assert_eq!(retained.nonce(), authorization_nonce);
    assert_eq!(retained.ticket().digest().unwrap(), ticket_digest);
    assert!(
        c.state()
            .error
            .as_deref()
            .is_some_and(|error| error.contains("authorization snapshot")),
        "a second review request is busy-gated while the exact ticket is active"
    );

    c.handle_command(AppCommand::CancelRiskOverride);
    assert!(c.pending_authorization.is_none());
    assert!(c.pending_risk_review.is_none());
    assert!(c.pending_risk_consumption.is_none());
    assert!(!c.state().auth.open);
    cleanup(&dir);
}

#[test]
fn risk_grant_save_failure_never_reaches_authentication_or_signing() {
    let dir = temp_dir("risk-grant-save-failure");
    let (mut c, fake) = ready_to_send(&dir);
    fake.push_broadcast(Ok(CandidateBroadcastOutcome::MayHaveBroadcast {
        detail: "old outcome unknown".to_owned(),
    }));
    c.dispatch_test_authorization();
    c.pump_events();
    c.state_mut().send_form.destination = SEND_DEST.to_owned();
    c.state_mut().send_form.amount = "2.0".to_owned();
    c.state_mut().recipient_check = RecipientCheck::Known(DestinationAccountStatus::Active);
    let mut fresh = timed_wallet("0:me");
    set_native_balance(&mut fresh, 5_000_000_000);
    fake.set_load_wallet(Ok(fresh));
    c.session.risk_cooling_started_at = Some(
        Instant::now()
            .checked_sub(Duration::from_secs(
                cc_wallet_chain::RISK_OVERRIDE_COOLING_SECS,
            ))
            .unwrap(),
    );
    c.refresh_journal_policy();
    c.handle_command(AppCommand::RequestRiskOverride);
    c.pump_events();
    assert!(c.state().risk_review_open);
    c.writer.as_mut().unwrap().poison().unwrap();

    c.handle_command(AppCommand::ConfirmRiskOverride {
        typed_confirmation: String::new(),
        acknowledge_both_may_debit: true,
        acknowledge_duplicate: true,
    });

    assert_eq!(persisted_journal(&dir).risk_events().len(), 0);
    assert!(c.pending_authorization.is_none());
    assert!(c.pending_risk_consumption.is_none());
    assert!(!c.state().auth.open);
    assert_eq!(c.state().persistence_health, PersistenceHealth::Failed);
    assert_eq!(
        fake.prepare_calls(),
        1,
        "only the original transfer prepared"
    );
    cleanup(&dir);
}

#[test]
fn a_dispatched_fee_estimate_populates_the_estimate() {
    let dir = temp_dir("dispatch-fee-ok");
    let (mut c, fake) = ready_to_send(&dir);
    fake.set_fee(Ok(FeeEstimate {
        fee_nanos: 12_345_678,
        deploy: false,
    }));

    c.estimate_fee();
    c.pump_events();

    assert!(!c.state().fee_estimating);
    assert_eq!(
        c.state().fee_estimate.map(|f| f.fee_nanos),
        Some(12_345_678),
        "the estimate from the chain is shown"
    );
    cleanup(&dir);
}

#[test]
fn a_failed_fee_estimate_clears_to_unknown() {
    let dir = temp_dir("dispatch-fee-fail");
    let (mut c, fake) = ready_to_send(&dir);
    fake.set_fee(Err(ChainError::Wallet("bad blockchain config".to_owned())));

    c.estimate_fee();
    c.pump_events();

    assert!(!c.state().fee_estimating);
    assert_eq!(
        c.state().fee_estimate,
        None,
        "a rejected estimate degrades to 'fee unknown', never a bogus number"
    );
    cleanup(&dir);
}

#[test]
fn a_dispatched_refresh_applies_the_loaded_snapshot() {
    let dir = temp_dir("dispatch-load-ok");
    let (mut c, fake) = ready_to_send(&dir);
    c.state_mut().derived_wallet_address = OTHER_SEND_DEST.to_owned();
    let gid = c.state().network_id;
    let mut snapshot = timed_wallet("0:me");
    set_native_balance(&mut snapshot, 9_000_000_000);
    snapshot.global_id = gid;
    fake.set_load_wallet(Ok(snapshot));

    c.refresh_wallet();
    c.pump_events();

    assert_eq!(
        c.state()
            .wallet
            .as_ref()
            .map(WalletSnapshot::native_balance),
        Some(9_000_000_000),
        "the refreshed balance is applied from the chain snapshot"
    );
    assert_eq!(
        c.state().wallet_address(),
        Some(SEND_DEST),
        "a successful snapshot replaces the provisional locally derived address"
    );
    assert!(!c.state().busy);
    cleanup(&dir);
}

#[test]
fn a_failed_refresh_keeps_the_local_address_and_cached_activity_offline() {
    let dir = temp_dir("dispatch-load-fail");
    let fake = FakeChain::default();
    fake.set_load_wallet(Err(ChainError::Wallet("node is down".to_owned())));
    let mut c = unlocked_with_fake(&dir, &fake);
    c.state_mut().send_form.destination = OTHER_SEND_DEST.to_owned();
    c.state_mut().send_form.amount = "1.0".to_owned();
    let cached_activity = history_event(77, HISTORY_NOW, AssetId::Native);
    c.state_mut().activity.push(cached_activity.clone());

    c.refresh_wallet();
    c.pump_events();

    assert!(!c.state().busy, "the refresh guard is cleared on failure");
    assert!(
        c.state().wallet.is_none(),
        "offline address availability must not fabricate a trusted RPC snapshot"
    );
    assert_eq!(c.state().wallet_address(), Some(SEND_DEST));
    assert_eq!(c.state().activity, vec![cached_activity]);
    assert_eq!(c.subscription_addr.as_deref(), Some(SEND_DEST));
    assert_eq!(c.state().live_status, LiveStatus::Connecting);
    assert!(
        c.state()
            .error
            .as_deref()
            .is_some_and(|e| e.contains("node is down"))
    );
    assert!(
        c.state()
            .snapshot_refresh_error
            .as_deref()
            .is_some_and(|e| e.contains("node is down"))
    );
    assert!(!c.state().send_enabled());

    c.handle_command(AppCommand::ClearError);
    assert!(
        c.state().error.is_none(),
        "the visible RPC error is dismissible"
    );
    assert!(
        c.state().snapshot_refresh_error.is_some(),
        "dismissing the banner must retain the signing safety blocker"
    );
    assert!(!c.state().send_enabled());

    fake.set_load_wallet(Err(ChainError::Wallet("node is still down".to_owned())));
    c.refresh_wallet();
    c.pump_events();
    assert!(
        c.state()
            .error
            .as_deref()
            .is_some_and(|e| e.contains("node is still down")),
        "a later failed refresh should surface a fresh dismissible error"
    );
    cleanup(&dir);
}

#[test]
fn a_ready_offline_subscription_automatically_reloads_the_wallet_snapshot() {
    let dir = temp_dir("dispatch-offline-recovery");
    let fake = FakeChain::default();
    fake.set_load_wallet(Err(ChainError::Wallet("node is down".to_owned())));
    let mut c = unlocked_with_fake(&dir, &fake);

    c.refresh_wallet();
    c.pump_events();
    assert!(c.state().wallet.is_none());
    assert!(c.state().snapshot_refresh_error.is_some());

    let mut snapshot = timed_wallet(SEND_DEST);
    set_native_balance(&mut snapshot, 4_000_000_000);
    snapshot.global_id = c.state().network_id;
    fake.set_load_wallet(Ok(snapshot));
    c.apply_event(AppEvent::SubscriptionReady {
        generation: c.subscription_generation,
        uuid: "reconnected".to_owned(),
    });
    c.pump_events();

    assert_eq!(
        c.state()
            .wallet
            .as_ref()
            .map(WalletSnapshot::native_balance),
        Some(4_000_000_000)
    );
    assert!(c.state().snapshot_refresh_error.is_none());
    assert!(c.state().error.is_none());
    assert_eq!(c.state().live_status, LiveStatus::Live);
    cleanup(&dir);
}

#[test]
fn a_dispatched_destination_check_records_activeness() {
    let dir = temp_dir("dispatch-dest");
    let (mut c, fake) = ready_to_send(&dir);
    fake.set_destination(Ok(DestinationAccountStatus::NonExist));

    c.state_mut().reset_recipient_status();
    c.check_destination();
    c.pump_events();

    assert_eq!(
        c.state().recipient_check,
        RecipientCheck::Known(DestinationAccountStatus::NonExist),
        "an inactive destination is recorded so a non-bounceable send can warn"
    );
    cleanup(&dir);
}

#[test]
fn a_dispatched_fetch_clears_the_guard_on_an_empty_page() {
    let dir = temp_dir("dispatch-fetch-empty");
    let (mut c, _fake) = ready_to_send(&dir);
    let g = c.subscription_generation;

    c.fetch_transactions(g);
    assert!(
        c.load.fetch_in_flight,
        "the coalescing guard is taken on dispatch"
    );
    c.pump_events();

    assert!(
        !c.load.fetch_in_flight,
        "a completed walk releases the guard"
    );
    assert!(!c.state().history_incomplete);
    assert!(!c.session.history_has_gap);
    cleanup(&dir);
}

#[test]
fn a_page_rpc_error_flags_a_gap_and_still_releases_the_guard() {
    let dir = temp_dir("dispatch-fetch-gap");
    let (mut c, fake) = ready_to_send(&dir);
    let g = c.subscription_generation;
    fake.push_page(Err(ChainError::Wallet("rpc 500".to_owned())));

    c.fetch_transactions(g);
    c.pump_events();

    assert!(
        !c.load.fetch_in_flight,
        "even a failed walk must release the guard"
    );
    assert!(
        c.session.history_has_gap,
        "a mid-walk RPC error leaves a gap the next fetch must re-walk"
    );
    assert!(c.state().history_incomplete);
    cleanup(&dir);
}

#[test]
fn an_oversized_endpoint_page_is_rejected_as_a_history_gap() {
    let dir = temp_dir("dispatch-fetch-oversized-page");
    let (mut c, fake) = ready_to_send(&dir);
    let sample = fresh_sample_transaction();
    let transactions = (0..101u64)
        .map(|offset| {
            let mut transaction = sample.clone();
            transaction.lt = 1_000 - offset;
            transaction
        })
        .collect();
    fake.push_page(Ok(TransactionPage {
        transactions,
        skipped: 0,
        source_endpoint: c.current_endpoint(),
        request_id: "oversized-history-page".to_owned(),
    }));

    c.fetch_transactions(c.subscription_generation);
    c.pump_events();

    assert!(c.session.history_has_gap);
    assert!(c.state().history_incomplete);
    assert!(
        c.state()
            .history_integrity_error
            .as_deref()
            .is_some_and(|error| error.contains("exceeds the requested 100-transaction limit"))
    );
    assert!(
        c.state().activity.is_empty(),
        "no prefix of an endpoint page that violates the request bound is merged"
    );
    cleanup(&dir);
}

#[test]
fn a_matching_transaction_on_an_incomplete_walk_never_terminalizes_the_journal() {
    let dir = temp_dir("dispatch-fetch-match-then-gap");
    let (mut c, fake) = ready_to_send(&dir);
    let mut wallet = timed_wallet(SEND_DEST);
    set_native_balance(&mut wallet, 5_000_000_000);
    c.state_mut().wallet = Some(wallet);
    let sample = fresh_sample_transaction();
    let ext_msg_hash = Digest32::try_from_hex(
        &sample
            .in_msg
            .as_ref()
            .expect("the real outgoing sample has an external inbound message")
            .hash,
    )
    .unwrap();
    let (record_id, endpoint) = install_blocking_history_record(&mut c, ext_msg_hash, 0x91);
    let before = c
        .journal
        .record(&record_id)
        .unwrap()
        .delivery_events()
        .len();

    let transactions = (0..100)
        .map(|offset| {
            let mut transaction = sample.clone();
            transaction.lt = 10_000 - offset;
            transaction
        })
        .collect();
    fake.push_page(Ok(TransactionPage {
        transactions,
        skipped: 0,
        source_endpoint: endpoint,
        request_id: "matching-full-page".to_owned(),
    }));
    fake.push_page(Err(ChainError::Wallet(
        "next history page failed".to_owned(),
    )));

    c.fetch_transactions(c.subscription_generation);
    c.pump_events();

    assert_eq!(fake.transaction_calls(), 2);
    assert!(c.state().history_incomplete);
    assert!(c.session.history_has_gap);
    assert!(c.state().journal_blocking);
    assert_eq!(
        c.journal
            .record(&record_id)
            .unwrap()
            .delivery_events()
            .len(),
        before,
        "the matching prefix is not terminal evidence until the whole walk completes"
    );
    assert!(matches!(
        c.journal.record(&record_id).unwrap().latest_evidence(),
        DeliveryEvidence::MayHaveBroadcast { .. }
    ));
    cleanup(&dir);
}

#[test]
fn a_skipped_matching_page_retries_before_recording_endpoint_evidence() {
    let dir = temp_dir("dispatch-fetch-skipped-match-retry");
    let (mut c, fake) = ready_to_send(&dir);
    let mut wallet = timed_wallet(SEND_DEST);
    set_native_balance(&mut wallet, 5_000_000_000);
    fake.set_load_wallet(Ok(wallet.clone()));
    c.state_mut().wallet = Some(wallet);

    let mut matching = fresh_sample_transaction();
    matching.lt = 44;
    let ext_msg_hash = Digest32::try_from_hex(
        &matching
            .in_msg
            .as_ref()
            .expect("the real outgoing sample has an external inbound message")
            .hash,
    )
    .unwrap();
    let (record_id, endpoint) = install_blocking_history_record(&mut c, ext_msg_hash, 0x92);
    let before = c
        .journal
        .record(&record_id)
        .unwrap()
        .delivery_events()
        .len();

    fake.push_page(Ok(TransactionPage {
        transactions: vec![matching.clone()],
        skipped: 1,
        source_endpoint: endpoint.clone(),
        request_id: "skipped-matching-page".to_owned(),
    }));
    c.fetch_transactions(c.subscription_generation);
    c.pump_events();

    assert!(
        c.state().activity.iter().any(|event| event.lt == 44),
        "decoded Activity remains visible even though reconciliation waits for a clean walk"
    );
    assert!(c.state().history_incomplete);
    assert!(
        c.session.history_has_gap,
        "an undecodable row keeps a trusted-floor refetch obligation"
    );
    assert_eq!(
        c.session.history_synced_floor, None,
        "an incomplete page never promotes its decoded neighbour into the trusted floor"
    );
    assert!(c.state().journal_blocking);
    assert_eq!(
        c.journal
            .record(&record_id)
            .unwrap()
            .delivery_events()
            .len(),
        before,
        "the skipped page supplies no terminal delivery evidence"
    );

    fake.push_page(Ok(TransactionPage {
        transactions: vec![matching],
        skipped: 0,
        source_endpoint: endpoint,
        request_id: "clean-matching-retry".to_owned(),
    }));
    c.fetch_transactions(c.subscription_generation);
    c.pump_events();

    assert_eq!(fake.transaction_calls(), 2);
    assert!(!c.state().history_incomplete);
    assert!(!c.session.history_has_gap);
    assert!(!c.state().journal_blocking);
    assert!(c.state().active_reservations.is_empty());
    assert_eq!(
        c.journal
            .record(&record_id)
            .unwrap()
            .delivery_events()
            .len(),
        before + 2,
    );
    assert!(matches!(
        c.journal.record(&record_id).unwrap().latest_evidence(),
        DeliveryEvidence::VerifiedTerminal {
            outcome: TerminalOutcome::Success,
            proof_ref,
        } if proof_ref.starts_with("rpc-history:")
    ));
    assert!(c.state().send_enabled());
    cleanup(&dir);
}

#[test]
fn an_inclusive_trusted_boundary_is_reobserved_before_recording_endpoint_evidence() {
    let dir = temp_dir("dispatch-fetch-budget-boundary-retry");
    let (mut c, fake) = ready_to_send(&dir);
    let mut wallet = timed_wallet(SEND_DEST);
    set_native_balance(&mut wallet, 5_000_000_000);
    fake.set_load_wallet(Ok(wallet.clone()));
    c.state_mut().wallet = Some(wallet);

    let mut matching = fresh_sample_transaction();
    matching.lt = 44;
    let ext_msg_hash = Digest32::try_from_hex(
        &matching
            .in_msg
            .as_ref()
            .expect("the real outgoing sample has an external inbound message")
            .hash,
    )
    .unwrap();
    let (record_id, endpoint) = install_blocking_history_record(&mut c, ext_msg_hash, 0x93);

    c.state_mut()
        .activity
        .push(history_event(45, HISTORY_NOW, AssetId::Native));
    c.session.history_synced_floor = Some(44);
    c.session.history_has_gap = false;
    c.state_mut().history_incomplete = true;
    assert_eq!(c.session.history_synced_floor, Some(44));
    assert!(!c.session.history_has_gap);
    assert!(c.state().history_incomplete);

    fake.push_page(Ok(TransactionPage {
        transactions: vec![matching],
        skipped: 0,
        source_endpoint: endpoint,
        request_id: "clean-budget-boundary-retry".to_owned(),
    }));
    c.fetch_transactions(c.subscription_generation);
    c.pump_events();

    assert!(!c.state().history_incomplete);
    assert!(!c.state().journal_blocking);
    assert!(c.state().active_reservations.is_empty());
    assert!(matches!(
        c.journal.record(&record_id).unwrap().latest_evidence(),
        DeliveryEvidence::VerifiedTerminal {
            outcome: TerminalOutcome::Success,
            proof_ref,
        } if proof_ref.starts_with("rpc-history:")
    ));
    assert!(c.state().send_enabled());
    cleanup(&dir);
}

#[test]
fn a_budgeted_scan_resumes_below_a_shifted_head_and_records_qualified_evidence() {
    const BOUNDARY_LT: u64 = 10_000;
    const FIRST_HEAD_LT: u64 = BOUNDARY_LT + 1_999;

    let dir = temp_dir("dispatch-fetch-budget-continuation");
    let (mut c, fake) = ready_to_send(&dir);
    let mut wallet = timed_wallet(SEND_DEST);
    set_native_balance(&mut wallet, 5_000_000_000);
    fake.set_load_wallet(Ok(wallet.clone()));
    c.state_mut().wallet = Some(wallet);

    let sample = fresh_sample_transaction();
    let ext_msg_hash = Digest32::try_from_hex(
        &sample
            .in_msg
            .as_ref()
            .expect("the real outgoing sample has an external inbound message")
            .hash,
    )
    .unwrap();
    let (record_id, endpoint) = install_blocking_history_record(&mut c, ext_msg_hash, 0x94);

    for page_index in 0..20u64 {
        let transactions = (0..100u64)
            .map(|row| {
                let lt = FIRST_HEAD_LT - (page_index * 100 + row);
                let mut transaction = sample.clone();
                transaction.lt = lt;
                if lt != BOUNDARY_LT {
                    transaction.in_msg = None;
                }
                transaction
            })
            .collect();
        fake.push_page(Ok(TransactionPage {
            transactions,
            skipped: 0,
            source_endpoint: endpoint.clone(),
            request_id: format!("budget-page-{page_index}"),
        }));
    }
    fake.push_page(Ok(TransactionPage {
        transactions: Vec::new(),
        skipped: 0,
        source_endpoint: endpoint.clone(),
        request_id: "budget-continuation-end".to_owned(),
    }));
    let mut new_head = sample;
    new_head.lt = FIRST_HEAD_LT + 1;
    new_head.in_msg = None;
    fake.push_page(Ok(TransactionPage {
        transactions: vec![new_head],
        skipped: 0,
        source_endpoint: endpoint,
        request_id: "shifted-head-refresh".to_owned(),
    }));

    c.fetch_transactions(c.subscription_generation);
    c.fetch_transactions(c.subscription_generation);
    c.pump_events();

    let cursors = fake.transaction_before_lts();
    assert_eq!(fake.transaction_calls(), 22);
    assert_eq!(cursors[0], None);
    assert_eq!(
        cursors[20],
        Some(BOUNDARY_LT),
        "the page-budget retry resumes below the retained boundary"
    );
    assert_eq!(
        cursors[21], None,
        "the coalesced new-head refresh runs only after continuation completion"
    );
    assert!(!c.state().history_incomplete);
    assert!(!c.session.history_has_gap);
    assert_eq!(c.session.history_synced_floor, Some(BOUNDARY_LT));
    assert!(!c.state().journal_blocking);
    assert!(c.state().active_reservations.is_empty());
    assert!(matches!(
        c.journal.record(&record_id).unwrap().latest_evidence(),
        DeliveryEvidence::VerifiedTerminal {
            outcome: TerminalOutcome::Success,
            proof_ref,
        } if proof_ref.starts_with("rpc-history:")
    ));
    assert!(c.state().send_enabled());
    cleanup(&dir);
}

#[test]
fn an_update_queued_during_continuation_advances_then_refreshes_the_head() {
    let dir = temp_dir("dispatch-fetch-continuation-queued-update");
    let (mut c, fake) = ready_to_send(&dir);
    c.load.history_reconciliation_scan = Some(HistoryReconciliationScan {
        next_before_lt: 500,
        stop_at: None,
        age_cutoff: None,
        deepest_lt: Some(500),
        observations: Vec::new(),
        automatic_continuations_remaining: 0,
    });
    c.load.fetch_in_flight = true;
    c.load.fetch_in_flight_id = Some(41);
    c.load.fetch_again = true;

    c.apply_event(AppEvent::TransactionsLoaded {
        generation: c.subscription_generation,
        fetch_id: 41,
        head_refresh_only: false,
        events: Vec::new(),
        integrity_error: None,
        incomplete: true,
        gap: false,
        deepest_lt: Some(500),
    });
    assert!(
        c.load.fetch_in_flight,
        "the queued update advances the scan"
    );
    assert!(c.load.fetch_head_after_history_scan);
    assert!(!c.load.fetch_again);

    c.pump_events();

    assert_eq!(
        fake.transaction_before_lts(),
        vec![Some(500), None],
        "the queued update first resumes the cursor, then re-reads the head"
    );
    assert!(!c.load.fetch_in_flight);
    assert!(c.load.history_reconciliation_scan.is_none());
    assert!(!c.load.fetch_head_after_history_scan);
    cleanup(&dir);
}

#[test]
fn a_queued_head_refresh_runs_even_when_the_driven_continuation_hits_its_budget() {
    const CONTINUATION_START_LT: u64 = 3_000;
    const CONTINUATION_BOUNDARY_LT: u64 = 1_000;

    let dir = temp_dir("dispatch-fetch-continuation-budget-then-head");
    let (mut c, fake) = ready_to_send(&dir);
    c.load.history_reconciliation_scan = Some(HistoryReconciliationScan {
        next_before_lt: CONTINUATION_START_LT,
        stop_at: None,
        age_cutoff: None,
        deepest_lt: Some(CONTINUATION_START_LT),
        observations: Vec::new(),
        automatic_continuations_remaining: 0,
    });
    c.state_mut().history_incomplete = true;
    c.load.fetch_in_flight = true;
    c.load.fetch_in_flight_id = Some(41);
    c.load.fetch_again = true;

    let sample = fresh_sample_transaction();
    for page_index in 0..20u64 {
        let transactions = (0..100u64)
            .map(|row| {
                let mut transaction = sample.clone();
                transaction.lt = CONTINUATION_START_LT - 1 - (page_index * 100 + row);
                transaction.in_msg = None;
                transaction
            })
            .collect();
        fake.push_page(Ok(TransactionPage {
            transactions,
            skipped: 0,
            source_endpoint: c.current_endpoint(),
            request_id: format!("continuation-budget-page-{page_index}"),
        }));
    }
    let mut new_head = sample;
    new_head.lt = CONTINUATION_START_LT + 1_000;
    fake.push_page(Ok(TransactionPage {
        transactions: vec![new_head],
        skipped: 0,
        source_endpoint: c.current_endpoint(),
        request_id: "promised-head-refresh".to_owned(),
    }));

    c.apply_event(AppEvent::TransactionsLoaded {
        generation: c.subscription_generation,
        fetch_id: 41,
        head_refresh_only: false,
        events: Vec::new(),
        integrity_error: None,
        incomplete: true,
        gap: false,
        deepest_lt: Some(CONTINUATION_START_LT),
    });
    c.pump_events();

    let cursors = fake.transaction_before_lts();
    assert_eq!(cursors.len(), 21);
    assert_eq!(cursors[0], Some(CONTINUATION_START_LT));
    assert_eq!(cursors[19], Some(CONTINUATION_BOUNDARY_LT + 100));
    assert_eq!(
        cursors[20], None,
        "the promised account-head read must not be starved by another page-budget hit"
    );
    let retained = c
        .load
        .history_reconciliation_scan
        .as_ref()
        .expect("the still-incomplete deep scan remains resumable");
    assert_eq!(retained.next_before_lt, CONTINUATION_BOUNDARY_LT);
    assert!(c.state().history_incomplete);
    assert!(!c.load.fetch_in_flight);
    assert!(!c.load.fetch_again);
    assert!(!c.load.fetch_head_after_history_scan);
    assert!(
        c.state()
            .activity
            .iter()
            .any(|event| event.lt == CONTINUATION_START_LT + 1_000),
        "the distinct head fetch merged the newly arrived transaction"
    );
    cleanup(&dir);
}

#[test]
fn a_budgeted_head_refresh_rebases_one_scan_without_losing_the_deep_obligation() {
    let dir = temp_dir("dispatch-fetch-budgeted-head-rebase");
    let (mut c, _fake) = ready_to_send(&dir);
    let staged = endpoint_observation(
        digest("STAGED-DEEP-OBSERVATION"),
        &c.current_endpoint(),
        SEND_DEST,
        "staged-deep-request",
        "staged-deep-transaction",
        true,
    );
    c.load.history_reconciliation_scan = Some(HistoryReconciliationScan {
        next_before_lt: 1_000,
        stop_at: Some(100),
        age_cutoff: Some(123),
        deepest_lt: Some(1_000),
        observations: vec![staged.clone()],
        automatic_continuations_remaining: 0,
    });
    c.load.fetch_in_flight = true;
    c.load.fetch_in_flight_id = Some(77);

    c.apply_event(AppEvent::EndpointHistoryScanned {
        generation: c.subscription_generation,
        fetch_id: 77,
        head_refresh_only: true,
        observations: Vec::new(),
        scan_start_before_lt: None,
        scan_stop_at: Some(3_500),
        scan_age_cutoff: Some(9_999),
        continuation_before_lt: Some(3_000),
        deepest_lt: Some(3_000),
        gap: false,
    });

    let rebased = c
        .load
        .history_reconciliation_scan
        .as_ref()
        .expect("the new head cursor and old deep obligation form one retained scan");
    assert_eq!(rebased.next_before_lt, 3_000);
    assert_eq!(
        rebased.stop_at,
        Some(100),
        "the original trusted terminal boundary must survive"
    );
    assert_eq!(
        rebased.age_cutoff,
        Some(123),
        "the original conservative age cutoff must not slide forward"
    );
    assert_eq!(rebased.deepest_lt, Some(1_000));
    assert_eq!(rebased.observations, vec![staged]);
    cleanup(&dir);
}

#[test]
fn a_resumed_scan_keeps_the_original_head_age_cutoff() {
    let dir = temp_dir("dispatch-fetch-continuation-age-cutoff");
    let (mut c, fake) = ready_to_send(&dir);
    let mut transaction = fresh_sample_transaction();
    transaction.lt = 499;
    let original_cutoff = u64::from(transaction.now).saturating_sub(1);
    transaction.now = u32::try_from(original_cutoff.saturating_sub(1)).unwrap();

    c.load.history_reconciliation_scan = Some(HistoryReconciliationScan {
        next_before_lt: 500,
        stop_at: None,
        age_cutoff: Some(original_cutoff),
        deepest_lt: Some(500),
        observations: Vec::new(),
        automatic_continuations_remaining: 0,
    });
    fake.push_page(Ok(TransactionPage {
        transactions: vec![transaction],
        skipped: 0,
        source_endpoint: c.current_endpoint(),
        request_id: "fixed-original-age-cutoff".to_owned(),
    }));

    c.continue_history_scan(c.subscription_generation);
    c.pump_events();

    assert!(
        c.state().activity.iter().all(|event| event.lt != 499),
        "the continuation stops at the original head's age boundary instead of sliding it backward"
    );
    assert!(c.load.history_reconciliation_scan.is_none());
    assert!(!c.state().history_incomplete);
    cleanup(&dir);
}

#[test]
fn a_burst_of_fetches_coalesces_into_one_extra_walk() {
    let dir = temp_dir("dispatch-fetch-coalesce");
    let (mut c, fake) = ready_to_send(&dir);
    let g = c.subscription_generation;

    c.fetch_transactions(g);
    c.fetch_transactions(g);
    c.fetch_transactions(g);
    c.fetch_transactions(g);
    assert!(c.load.fetch_in_flight);
    assert!(
        c.load.fetch_again,
        "the burst folded into a single pending re-fetch"
    );

    c.pump_events();

    assert!(!c.load.fetch_in_flight);
    assert!(
        !c.load.fetch_again,
        "the single pending re-fetch was serviced"
    );
    assert_eq!(
        fake.transaction_calls(),
        2,
        "four fetch requests produced exactly two walks"
    );
    cleanup(&dir);
}

#[test]
fn a_ready_event_from_the_stream_goes_live() {
    let dir = temp_dir("sub-ready");
    let (mut c, fake) = ready_to_send(&dir);
    fake.push_sub_event(SubscriptionEvent::Ready {
        uuid: "sub-xyz".to_owned(),
    });

    c.ensure_subscription(SEND_DEST.to_owned());
    c.pump_events();

    assert_eq!(c.state().live_status, LiveStatus::Live);
    assert!(
        c.state().subscription_status.contains("sub-xyz"),
        "the stream's uuid is surfaced"
    );
    cleanup(&dir);
}

#[test]
fn a_reconnected_subscription_redrives_an_idle_history_continuation() {
    let dir = temp_dir("sub-ready-history-redrive");
    let (mut c, fake) = ready_to_send(&dir);
    c.load.history_reconciliation_scan = Some(HistoryReconciliationScan {
        next_before_lt: 500,
        stop_at: None,
        age_cutoff: None,
        deepest_lt: Some(500),
        observations: Vec::new(),
        automatic_continuations_remaining: 0,
    });
    c.state_mut().history_incomplete = true;

    c.apply_event(AppEvent::SubscriptionReady {
        generation: c.subscription_generation,
        uuid: "reconnected".to_owned(),
    });
    c.pump_events();

    assert_eq!(
        fake.transaction_before_lts(),
        vec![Some(500), None],
        "reconnect resumes the retained cursor and then refreshes the head"
    );
    assert!(c.load.history_reconciliation_scan.is_none());
    assert!(!c.state().history_incomplete);
    cleanup(&dir);
}

#[test]
fn a_reconnected_subscription_rechecks_a_blocking_journal() {
    let dir = temp_dir("sub-ready-journal-redrive");
    let (mut c, fake) = ready_to_send(&dir);
    install_blocking_history_record(&mut c, digest("RECONNECT-BLOCKER"), 0xa2);
    c.load.history_reconciliation_scan = None;
    c.state_mut().history_incomplete = false;
    c.session.history_has_gap = false;
    let before = fake.transaction_calls();

    c.apply_event(AppEvent::SubscriptionReady {
        generation: c.subscription_generation,
        uuid: "reconnected-with-blocker".to_owned(),
    });
    c.pump_events();

    assert_eq!(
        fake.transaction_calls(),
        before + 1,
        "reconnect must refresh history even when the only obligation is the Journal blocker"
    );
    assert!(c.state().journal_blocking);
    assert!(c.journal_reconcile_at.is_some());
    cleanup(&dir);
}

#[test]
fn an_account_update_from_the_stream_triggers_a_history_fetch() {
    let dir = temp_dir("sub-update");
    let (mut c, fake) = ready_to_send(&dir);
    fake.push_sub_event(SubscriptionEvent::Update(AccountUpdate {
        max_lt: 42,
        gen_utime: Some(7),
    }));
    let before = fake.transaction_calls();

    c.ensure_subscription(SEND_DEST.to_owned());
    c.pump_events();

    assert_eq!(c.state().subscription_status, "account update received");
    assert!(
        fake.transaction_calls() > before,
        "an account update pulls fresh history"
    );
    assert_eq!(
        fake.last_sub_address().as_deref(),
        Some(SEND_DEST),
        "the subscription bound the wallet address"
    );
    cleanup(&dir);
}

#[test]
fn a_stream_that_ends_with_an_error_schedules_a_reconnect() {
    let dir = temp_dir("sub-error");
    let (mut c, fake) = ready_to_send(&dir);
    fake.set_sub_result(Err(ChainError::Wallet("stream closed".to_owned())));

    c.ensure_subscription(SEND_DEST.to_owned());
    c.pump_events();

    assert_eq!(c.state().live_status, LiveStatus::Connecting);
    assert!(c.state().subscription_status.contains("stream closed"));
    assert!(
        c.subscription_retry_at.is_some(),
        "a failed stream schedules a backoff retry"
    );
    cleanup(&dir);
}

#[test]
fn resubscribing_to_the_same_endpoint_and_address_is_a_no_op() {
    let dir = temp_dir("sub-keying");
    let (mut c, _fake) = ready_to_send(&dir);
    let gen0 = c.subscription_generation;

    c.ensure_subscription(SEND_DEST.to_owned());
    let gen1 = c.subscription_generation;
    assert_ne!(gen1, gen0, "the first subscription bumps the generation");
    assert!(c.subscription_key.as_deref().unwrap().contains(SEND_DEST));

    c.ensure_subscription(SEND_DEST.to_owned());
    assert_eq!(
        c.subscription_generation, gen1,
        "an identical re-subscribe must not bump the generation or restart the stream"
    );

    c.ensure_subscription(OTHER_SEND_DEST.to_owned());
    assert_ne!(
        c.subscription_generation, gen1,
        "a new address re-subscribes"
    );
    assert!(
        c.subscription_key
            .as_deref()
            .unwrap()
            .contains(OTHER_SEND_DEST)
    );
    cleanup(&dir);
}

#[test]
fn stopping_the_subscription_bumps_the_generation_and_resets_state() {
    let dir = temp_dir("sub-stop");
    let (mut c, _fake) = ready_to_send(&dir);
    c.ensure_subscription(SEND_DEST.to_owned());
    let g = c.subscription_generation;

    c.stop_subscription();

    assert_ne!(
        c.subscription_generation, g,
        "stopping bumps the generation so any late in-flight event is dropped"
    );
    assert_eq!(c.state().live_status, LiveStatus::Offline);
    assert!(c.subscription_key.is_none());
    assert_eq!(
        c.subscription_backoff_secs,
        super::SUBSCRIPTION_BACKOFF_MIN_SECS,
        "the backoff is reset for the next connection"
    );
    cleanup(&dir);
}

#[test]
fn an_event_from_a_superseded_subscription_is_ignored() {
    let dir = temp_dir("sub-stale");
    let (mut c, _fake) = ready_to_send(&dir);
    c.ensure_subscription(SEND_DEST.to_owned());
    let before = c.state().live_status;
    let stale = c.subscription_generation.wrapping_sub(1);

    c.apply_event(AppEvent::SubscriptionReady {
        generation: stale,
        uuid: "ghost".to_owned(),
    });

    assert_eq!(
        c.state().live_status,
        before,
        "a Ready from a superseded generation must not flip the live status"
    );
    assert!(!c.state().subscription_status.contains("ghost"));
    cleanup(&dir);
}

#[test]
fn the_reconnect_backoff_grows_then_caps() {
    let dir = temp_dir("sub-backoff-grow");
    let (mut c, _fake) = ready_to_send(&dir);
    c.ensure_subscription(SEND_DEST.to_owned());
    let g = c.subscription_generation;

    c.apply_event(AppEvent::SubscriptionFailed {
        generation: g,
        error: "x".to_owned(),
    });
    let b1 = c.subscription_backoff_secs;
    c.apply_event(AppEvent::SubscriptionFailed {
        generation: g,
        error: "x".to_owned(),
    });
    let b2 = c.subscription_backoff_secs;
    assert!(b2 > b1, "backoff grows on each successive failure");

    for _ in 0..10 {
        c.apply_event(AppEvent::SubscriptionFailed {
            generation: g,
            error: "x".to_owned(),
        });
    }
    assert_eq!(
        c.subscription_backoff_secs,
        super::SUBSCRIPTION_BACKOFF_MAX_SECS,
        "backoff never exceeds the cap, so reconnects don't blow out to hours"
    );
    cleanup(&dir);
}

#[test]
fn a_live_subscription_resets_the_backoff_and_clears_the_retry() {
    let dir = temp_dir("sub-backoff-reset");
    let (mut c, _fake) = ready_to_send(&dir);
    c.ensure_subscription(SEND_DEST.to_owned());
    let g = c.subscription_generation;

    for _ in 0..5 {
        c.apply_event(AppEvent::SubscriptionFailed {
            generation: g,
            error: "x".to_owned(),
        });
    }
    assert!(c.subscription_backoff_secs > super::SUBSCRIPTION_BACKOFF_MIN_SECS);
    assert!(c.subscription_retry_at.is_some());

    c.apply_event(AppEvent::SubscriptionReady {
        generation: g,
        uuid: "ok".to_owned(),
    });

    assert_eq!(
        c.subscription_backoff_secs,
        super::SUBSCRIPTION_BACKOFF_MIN_SECS,
        "a successful connection resets the backoff"
    );
    assert!(
        c.subscription_retry_at.is_none(),
        "and cancels the pending retry"
    );
    assert_eq!(c.state().live_status, LiveStatus::Live);
    cleanup(&dir);
}

#[test]
fn tick_re_subscribes_once_the_backoff_has_elapsed() {
    let dir = temp_dir("sub-tick-retry");
    let (mut c, _fake) = ready_to_send(&dir);
    c.ensure_subscription(SEND_DEST.to_owned());
    let g = c.subscription_generation;

    c.apply_event(AppEvent::SubscriptionFailed {
        generation: g,
        error: "dropped".to_owned(),
    });
    c.subscription_retry_at = Some(std::time::Instant::now());

    c.tick();

    assert_ne!(
        c.subscription_generation, g,
        "tick reconnects once the retry deadline passes"
    );
    assert!(
        c.subscription_retry_at.is_none(),
        "the due retry is consumed, not re-fired every tick"
    );
    cleanup(&dir);
}

#[test]
fn manual_refresh_retries_the_load_without_stacking_or_racing_the_reconnect() {
    let dir = temp_dir("manual-refresh-retry");
    let (mut c, fake) = ready_to_send(&dir);
    c.pump_events();
    assert!(!c.state().busy, "precondition: no load in flight");

    c.ensure_subscription(SEND_DEST.to_owned());
    let g = c.subscription_generation;
    c.apply_event(AppEvent::SubscriptionFailed {
        generation: g,
        error: "dropped".to_owned(),
    });
    let scheduled_retry = c
        .subscription_retry_at
        .expect("a backoff reconnect is scheduled");
    let scheduled_backoff = c.subscription_backoff_secs;

    let before = fake.load_wallet_calls();

    c.handle_command(AppCommand::RefreshWallet);
    assert!(c.state().busy, "a manual retry starts a foreground load");
    assert_eq!(
        c.subscription_retry_at,
        Some(scheduled_retry),
        "the pending reconnect is left in the future, not pulled forward into a race"
    );
    assert_eq!(
        c.subscription_backoff_secs, scheduled_backoff,
        "the backoff is left untouched"
    );

    c.handle_command(AppCommand::RefreshWallet);
    c.pump_events();
    assert_eq!(
        fake.load_wallet_calls(),
        before + 1,
        "the busy guard prevents a stacked concurrent load"
    );
    cleanup(&dir);
}

#[test]
fn a_clean_resync_does_not_clear_the_durable_quarantine_obligation() {
    let dir = temp_dir("hist-corrupt-gate");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.flush_save_blocking();
    assert!(!c.dirty);

    let opened = c.store.unlock(PW).unwrap();
    let counter = opened.selected.save_counter();
    c.session.activity_quarantine_pending = Some(opened.selected);
    c.writer = Some(opened.writer);
    c.state_mut().history_corrupt = true;
    c.state_mut().persistence_health = crate::state::PersistenceHealth::QuarantineRequired;

    c.save_profile();
    assert!(c.dirty, "the change is pending");

    c.apply_event(AppEvent::TransactionsLoaded {
        generation: c.subscription_generation,
        fetch_id: 0,
        head_refresh_only: false,
        events: Vec::new(),
        integrity_error: None,
        incomplete: false,
        gap: false,
        deepest_lt: None,
    });
    assert!(
        !c.state().history_corrupt,
        "a clean re-sync clears the corruption flag"
    );
    assert!(
        c.session.activity_quarantine_pending.is_some(),
        "a clean fetch cannot discharge the exact selected-byte obligation"
    );
    c.flush_save_blocking();
    assert!(!c.dirty, "the write completes after durable quarantine");
    assert!(c.session.activity_quarantine_pending.is_none());
    assert!(
        dir.join(format!("wallet.ccwallet.v1.{counter}.orphan"))
            .exists(),
        "the exact candidate is preserved before the commit"
    );
    cleanup(&dir);
}

#[test]
fn a_gapped_resync_does_not_clear_the_corruption_flag() {
    let dir = temp_dir("hist-corrupt-gap");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.state_mut().history_corrupt = true;

    c.apply_event(AppEvent::TransactionsLoaded {
        generation: c.subscription_generation,
        fetch_id: 0,
        head_refresh_only: false,
        events: Vec::new(),
        integrity_error: None,
        incomplete: true,
        gap: true,
        deepest_lt: None,
    });

    assert!(
        c.state().history_corrupt,
        "a gapped read leaves the corruption hold-off in place"
    );
    cleanup(&dir);
}

#[test]
fn an_explicit_rekey_quarantines_but_does_not_forge_a_clean_history_verdict() {
    let dir = temp_dir("hist-corrupt-rekey");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.flush_save_blocking();
    let opened = c.store.unlock(PW).unwrap();
    let counter = opened.selected.save_counter();
    c.session.activity_quarantine_pending = Some(opened.selected);
    c.writer = Some(opened.writer);
    c.state_mut().history_corrupt = true;
    c.state_mut().persistence_health = crate::state::PersistenceHealth::QuarantineRequired;

    c.persist_new_container();
    assert!(c.drain_save_task());

    assert!(
        c.state().history_corrupt,
        "re-keying cannot relabel unreadable history as clean"
    );
    assert!(c.session.activity_quarantine_pending.is_none());
    assert!(
        dir.join(format!("wallet.ccwallet.v1.{counter}.orphan"))
            .exists(),
        "re-key first preserves the selected container"
    );
    cleanup(&dir);
}

#[test]
fn clearing_the_explorer_address_drops_the_looked_up_account() {
    let dir = temp_dir("explorer-clear");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.state_mut().account_detail = Some(AccountInspection {
        exists: true,
        status: "Active",
        balance: 1_980_000_000,
        due_payment: 0,
        extra_balance: std::collections::BTreeMap::new(),
        last_trans_lt: 7,
        last_paid: 1_700_000_000,
        storage_bits: 1_629,
        storage_cells: 9,
        code_hash: Some("ab".repeat(32)),
        data_hash: Some("cd".repeat(32)),
        code_boc: Some("te6ccg".to_owned()),
        code_bytes: 89,
        data_boc: Some("te6ccg".to_owned()),
        data_bytes: 49,
        decoded: None,
    });
    c.state_mut().account_error = Some("stale error".to_owned());
    c.state_mut().account_loading = true;
    c.state_mut().inspected_address = "-1:00".to_owned();

    c.handle_command(AppCommand::InspectAccount(String::new()));

    assert!(c.state().account_detail.is_none());
    assert!(c.state().account_error.is_none());
    assert!(!c.state().account_loading);
    assert!(c.state().inspected_address.is_empty());
    cleanup(&dir);
}

#[test]
fn a_lookup_that_outlives_its_session_is_reissued_not_left_spinning() {
    let dir = temp_dir("explorer-stale-generation");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.state_mut().inspected_address = "-1:00".to_owned();
    c.state_mut().account_loading = true;
    let seq = c.account_fetch_seq;
    let stale_generation = c.subscription_generation.wrapping_sub(1);

    c.apply_event(AppEvent::AccountInspected {
        generation: stale_generation,
        seq,
        address: "-1:00".to_owned(),
        result: Ok(AccountInspection {
            exists: true,
            status: "Active",
            balance: 1,
            due_payment: 0,
            extra_balance: std::collections::BTreeMap::new(),
            last_trans_lt: 1,
            last_paid: 1,
            storage_bits: 1,
            storage_cells: 1,
            code_hash: None,
            data_hash: None,
            code_boc: None,
            code_bytes: 0,
            data_boc: None,
            data_bytes: 0,
            decoded: None,
        }),
    });

    assert!(
        c.state().account_detail.is_none(),
        "an account read on a superseded session is never shown"
    );
    assert_ne!(
        c.account_fetch_seq, seq,
        "the lookup is reissued for the session we are actually on"
    );
    assert!(
        !c.state().account_loading || c.state().account_error.is_none(),
        "the panel is either reading again or reporting why it cannot"
    );
    cleanup(&dir);
}

#[test]
fn a_scan_clears_the_previous_account_history_before_the_new_one_lands() {
    let dir = temp_dir("explorer-history-reset");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.state_mut().account_txs = vec![account_tx(7)];
    c.state_mut().account_txs_skipped = 2;
    c.state_mut().account_txs_error = Some("stale".to_owned());

    c.handle_command(AppCommand::InspectAccount("-1:00".to_owned()));

    assert!(
        c.state().account_txs.is_empty(),
        "the previous account's transactions never linger under a new address"
    );
    assert_eq!(c.state().account_txs_skipped, 0);
    assert!(c.state().account_txs_error.is_none());
    assert!(
        c.state().account_txs_loading,
        "the list says it is reading rather than showing an empty history"
    );
    cleanup(&dir);
}

#[test]
fn following_a_transaction_from_activity_lands_on_it_in_the_explorer() {
    let dir = temp_dir("explorer-follow-from-activity");
    let fake = FakeChain::default();
    let mut c = unlocked_with_fake(&dir, &fake);
    c.state_mut().selected_tab = AppTab::Wallet;
    let party = "-1:00".to_owned();
    let tx = digest("followed-tx").to_string();

    c.handle_command(AppCommand::OpenInExplorer {
        address: party.clone(),
        transaction_hash: tx.clone(),
    });

    assert_eq!(
        c.state().selected_tab,
        AppTab::Explorer,
        "the reader is taken to the page that can answer the question"
    );
    assert_eq!(
        c.state().inspected_address,
        party,
        "the account on the other side of the transfer is the one inspected"
    );
    assert!(c.state().account_loading && c.state().account_txs_loading);
    assert!(
        c.state().trace_hash.is_empty(),
        "the tree waits: the arriving account would replace it"
    );

    let seq = c.account_fetch_seq;
    let generation = c.subscription_generation;
    c.apply_event(AppEvent::AccountTransactionsLoaded {
        generation,
        seq,
        address: party,
        result: Ok(AccountTxPage {
            rows: Vec::new(),
            skipped: 0,
        }),
    });

    assert_eq!(
        c.state().trace_hash,
        tx,
        "once the account has settled, the transaction's own tree is opened"
    );
    assert!(c.pending_explorer_trace.is_none(), "and only once");
    cleanup(&dir);
}

#[test]
fn a_transaction_still_on_its_way_has_no_tree_to_follow() {
    let dir = temp_dir("explorer-follow-pending");
    let fake = FakeChain::default();
    let mut c = unlocked_with_fake(&dir, &fake);

    c.handle_command(AppCommand::OpenInExplorer {
        address: "-1:00".to_owned(),
        transaction_hash: String::new(),
    });

    assert_eq!(c.state().selected_tab, AppTab::Explorer);
    assert!(
        c.pending_explorer_trace.is_none(),
        "a row with no transaction hash queues nothing"
    );
    let seq = c.account_fetch_seq;
    let generation = c.subscription_generation;
    c.apply_event(AppEvent::AccountTransactionsLoaded {
        generation,
        seq,
        address: "-1:00".to_owned(),
        result: Ok(AccountTxPage {
            rows: Vec::new(),
            skipped: 0,
        }),
    });
    assert!(c.state().trace_hash.is_empty());
    cleanup(&dir);
}

#[test]
fn a_history_that_fails_leaves_the_account_panel_alone() {
    let dir = temp_dir("explorer-history-failure");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.state_mut().inspected_address = "-1:00".to_owned();
    c.state_mut().account_txs_loading = true;
    let seq = c.account_fetch_seq;
    let generation = c.subscription_generation;

    c.apply_event(AppEvent::AccountTransactionsLoaded {
        generation,
        seq,
        address: "-1:00".to_owned(),
        result: Err("history unavailable".to_owned()),
    });

    assert!(!c.state().account_txs_loading);
    assert_eq!(
        c.state().account_txs_error.as_deref(),
        Some("history unavailable")
    );
    assert!(
        c.state().account_error.is_none(),
        "the account state is a separate read and is not blamed for the history"
    );
    cleanup(&dir);
}

#[test]
fn a_history_for_an_address_no_longer_on_screen_is_dropped() {
    let dir = temp_dir("explorer-history-stale-address");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.state_mut().inspected_address = "-1:11".to_owned();
    c.state_mut().account_txs_loading = true;
    let seq = c.account_fetch_seq;
    let generation = c.subscription_generation;

    c.apply_event(AppEvent::AccountTransactionsLoaded {
        generation,
        seq,
        address: "-1:00".to_owned(),
        result: Ok(AccountTxPage {
            rows: vec![account_tx(1)],
            skipped: 0,
        }),
    });

    assert!(
        c.state().account_txs.is_empty(),
        "a history belonging to another address never lands in the panel"
    );
    assert!(
        c.state().account_txs_loading,
        "and the list keeps waiting for the one it asked for"
    );
    cleanup(&dir);
}

fn account_tx(lt: u64) -> AccountTx {
    AccountTx {
        received: Vec::new(),
        hash: Digest32::try_from_hex(&"ab".repeat(32)).expect("canonical hash"),
        lt,
        time_unix: 1_700_000_000,
        kind: AccountTxKind::In,
        counterparty: "-1:22".to_owned(),
        extra_parties: 0,
        movements: Vec::new(),
        fee_native: 5_000,
        int_out_msgs: 0,
        ext_out_msgs: 0,
        success: true,
        bounced: false,
        exit_code: 0,
    }
}

#[test]
fn opening_a_trace_marks_it_reading_and_scanning_again_puts_it_away() {
    let dir = temp_dir("explorer-trace-open");
    let mut c = unlocked(&dir, WalletProfile::default());

    c.handle_command(AppCommand::TraceTransaction("ab".repeat(32)));
    assert!(c.state().trace_loading);
    assert_eq!(c.state().trace_hash, "ab".repeat(32));

    c.handle_command(AppCommand::InspectAccount("-1:00".to_owned()));
    assert!(!c.state().trace_loading);
    assert!(c.state().trace.is_none());
    assert!(c.state().trace_hash.is_empty());
    cleanup(&dir);
}

#[test]
fn a_trace_that_lands_after_the_panel_closed_is_dropped() {
    let dir = temp_dir("explorer-trace-closed");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.handle_command(AppCommand::TraceTransaction("ab".repeat(32)));
    let seq = c.trace_fetch_seq;
    let generation = c.subscription_generation;

    c.handle_command(AppCommand::CloseTrace);
    c.apply_event(AppEvent::TraceLoaded {
        generation,
        seq,
        transaction_hash: "ab".repeat(32),
        result: Ok(empty_trace()),
    });

    assert!(
        c.state().trace.is_none(),
        "a diagram the user closed never appears after the fact"
    );
    assert!(!c.state().trace_loading);
    cleanup(&dir);
}

#[test]
fn a_failed_trace_reports_itself_without_touching_the_transaction_list() {
    let dir = temp_dir("explorer-trace-failure");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.state_mut().account_txs = vec![account_tx(9)];
    c.handle_command(AppCommand::TraceTransaction("cd".repeat(32)));
    let seq = c.trace_fetch_seq;
    let generation = c.subscription_generation;

    c.apply_event(AppEvent::TraceLoaded {
        generation,
        seq,
        transaction_hash: "cd".repeat(32),
        result: Err("this endpoint no longer keeps that transaction".to_owned()),
    });

    assert_eq!(
        c.state().trace_error.as_deref(),
        Some("this endpoint no longer keeps that transaction")
    );
    assert!(!c.state().trace_loading);
    assert_eq!(
        c.state().account_txs.len(),
        1,
        "the list the row came from is left standing"
    );
    cleanup(&dir);
}

fn empty_trace() -> cc_wallet_chain::AccountTrace {
    cc_wallet_chain::AccountTrace {
        root: Digest32::try_from_hex(&"ab".repeat(32)).expect("canonical hash"),
        focus: Digest32::try_from_hex(&"ab".repeat(32)).expect("canonical hash"),
        parties: Vec::new(),
        edges: Vec::new(),
        total_fees_native: 0,
        failed: 0,
        unexecuted: 0,
        truncated: false,
    }
}

#[test]
fn a_trace_walked_once_is_shown_again_without_asking_the_network() {
    let dir = temp_dir("explorer-trace-remembered");
    let mut c = unlocked(&dir, WalletProfile::default());
    let hash = "ab".repeat(32);

    c.handle_command(AppCommand::TraceTransaction(hash.clone()));
    let (seq, generation) = (c.trace_fetch_seq, c.subscription_generation);
    c.apply_event(AppEvent::TraceLoaded {
        generation,
        seq,
        transaction_hash: hash.clone(),
        result: Ok(empty_trace()),
    });
    assert!(c.state().trace.is_some());

    c.handle_command(AppCommand::CloseTrace);
    c.handle_command(AppCommand::TraceTransaction(hash.clone()));

    assert!(
        !c.state().trace_loading,
        "a trace already walked is not walked again"
    );
    assert_eq!(c.state().trace.as_ref(), Some(&empty_trace()));
    assert_eq!(c.state().trace_hash, hash);

    c.apply_event(AppEvent::TraceLoaded {
        generation,
        seq,
        transaction_hash: hash,
        result: Err("too late".to_owned()),
    });
    assert!(c.state().trace_error.is_none());
    cleanup(&dir);
}

#[test]
fn a_trace_still_waiting_on_the_chain_is_not_kept() {
    let dir = temp_dir("explorer-trace-unsettled");
    let mut c = unlocked(&dir, WalletProfile::default());
    let hash = "cd".repeat(32);
    let mut waiting = empty_trace();
    waiting.unexecuted = 1;

    c.handle_command(AppCommand::TraceTransaction(hash.clone()));
    let (seq, generation) = (c.trace_fetch_seq, c.subscription_generation);
    c.apply_event(AppEvent::TraceLoaded {
        generation,
        seq,
        transaction_hash: hash.clone(),
        result: Ok(waiting),
    });

    c.handle_command(AppCommand::CloseTrace);
    c.handle_command(AppCommand::TraceTransaction(hash));
    assert!(
        c.state().trace_loading,
        "an unfinished story is asked for again, not repeated from memory"
    );
    cleanup(&dir);
}

#[test]
fn traces_are_forgotten_when_the_endpoint_changes_under_them() {
    let dir = temp_dir("explorer-trace-endpoint");
    let mut c = unlocked(&dir, WalletProfile::default());
    let hash = "ef".repeat(32);

    c.handle_command(AppCommand::TraceTransaction(hash.clone()));
    let (seq, generation) = (c.trace_fetch_seq, c.subscription_generation);
    c.apply_event(AppEvent::TraceLoaded {
        generation,
        seq,
        transaction_hash: hash.clone(),
        result: Ok(empty_trace()),
    });

    c.handle_command(AppCommand::AddEndpoint(
        "https://elsewhere.example:8001".to_owned(),
    ));
    let elsewhere = c.state().endpoint_display_list().len() - 1;
    c.handle_command(AppCommand::SelectEndpoint(elsewhere));
    assert_eq!(
        c.state().resolved_endpoint(),
        "https://elsewhere.example:8001/",
        "the test drove the endpoint somewhere new"
    );

    c.handle_command(AppCommand::TraceTransaction(hash));
    assert!(
        c.state().trace_loading,
        "another chain is asked its own question"
    );
    cleanup(&dir);
}

#[test]
fn a_history_that_outlives_its_session_is_asked_again_not_left_spinning() {
    let dir = temp_dir("explorer-history-stale-generation");
    let mut c = unlocked(&dir, WalletProfile::default());
    c.state_mut().inspected_address = "-1:00".to_owned();
    c.state_mut().account_txs_loading = true;
    let seq = c.account_fetch_seq;
    let stale_generation = c.subscription_generation.wrapping_sub(1);

    c.apply_event(AppEvent::AccountTransactionsLoaded {
        generation: stale_generation,
        seq,
        address: "-1:00".to_owned(),
        result: Ok(AccountTxPage {
            rows: vec![account_tx(3)],
            skipped: 0,
        }),
    });

    assert!(
        c.state().account_txs.is_empty(),
        "history read on a superseded session is never shown"
    );
    assert_ne!(
        c.account_fetch_seq, seq,
        "the lookup is reissued for the session we are actually on"
    );
    assert!(
        c.state().account_txs_loading || c.state().account_txs_error.is_some(),
        "the list is either reading again or saying why it cannot"
    );
    cleanup(&dir);
}

const SWAP_POOL: &str = "0:4273920c193f325e2db7d77b5668c8ac60f4d2ac37bc239b9aeea5a27924ccf4";
const NANO: u128 = 1_000_000_000;

fn pool_snapshot(native: u128, extras: &[(u32, u128)]) -> PoolSnapshot {
    PoolSnapshot {
        address: SWAP_POOL.to_owned(),
        owner: "0:owner".to_owned(),
        fee_bps: 30,
        paused: false,
        native_reserve: native,
        cc_reserves: extras.iter().copied().collect(),
    }
}

fn ready_to_swap(dir: &Path) -> (AppController, FakeChain) {
    let fake = FakeChain::default();
    let mut c = unlocked_with_fake(dir, &fake);
    let mut wallet = timed_wallet("0:me");
    wallet
        .replace_balances(
            50 * NANO,
            [
                (1u32, CcAmount::from_u128(200 * NANO)),
                (3u32, CcAmount::from_u128(9 * NANO)),
            ]
            .into_iter()
            .collect(),
        )
        .unwrap();
    c.state_mut().wallet = Some(wallet);
    c.state_mut().swap.pool = Some(pool_snapshot(
        100 * NANO,
        &[(1, 100 * NANO), (2, 100 * NANO)],
    ));
    c.handle_command(AppCommand::SetSwapFromToken(AssetId::CurrencyCollection(1)));
    c.handle_command(AppCommand::SetSwapToToken(AssetId::CurrencyCollection(2)));
    c.handle_command(AppCommand::SetSwapAmount("10".to_owned()));
    (c, fake)
}

fn swap_out_event(lt: u64, ext: &str, asset: AssetId, units: u128, fee: u128) -> ActivityEvent {
    ActivityEvent {
        direction: ActivityDirection::Out,
        tx_hash: optional_digest(&format!("swap-tx{lt}")),
        counterparty: SWAP_POOL.to_owned(),
        movements: vec![
            movement(asset, units),
            movement(AssetId::Native, 200_000_000),
        ],
        fee_native: fee,
        ext_msg_hash: optional_digest(ext),
        int_msg_hash: optional_digest(&format!("swap-int{lt}")),
        ..ActivityEvent::test_stub(lt, 1_700_000_000)
    }
}

fn pool_answer_event(
    lt: u64,
    asset: AssetId,
    units: u128,
    fee: u128,
    bounced: bool,
) -> ActivityEvent {
    ActivityEvent {
        direction: ActivityDirection::In,
        tx_hash: optional_digest(&format!("pool-tx{lt}")),
        counterparty: SWAP_POOL.to_owned(),
        movements: vec![movement(asset, units)],
        fee_native: fee,
        bounced,
        ext_msg_hash: None,
        int_msg_hash: optional_digest(&format!("pool-int{lt}")),
        ..ActivityEvent::test_stub(lt, 1_700_000_100)
    }
}

fn dispatch_swap(c: &mut AppController, ext: &str, out_units: u128) {
    let sent = c
        .state()
        .swap
        .form
        .input()
        .expect("the fixture form parses");
    c.swap_in_flight = Some(super::swap::SwapIntent {
        sent,
        out_asset: c.state().swap.form.to_asset(),
        expected_out_units: out_units,
        min_out_units: out_units * 995 / 1000,
        slippage_bps: 50,
        pool: SWAP_POOL.to_owned(),
    });
    let generation = c.session_generation;
    c.apply_event(AppEvent::SwapFinished {
        generation,
        result: Ok(crate::event::BroadcastDispatch {
            outcome: CandidateBroadcastOutcome::NodeResponseObserved {
                request_id: "req".to_owned(),
                response: cc_wallet_domain::NodeResponseKind::Acknowledged,
                detail: "acknowledged".to_owned(),
            },
            ext_msg_hash: digest(ext),
            broadcast_started_at: Instant::now(),
        }),
    });
}

#[test]
fn only_the_tokens_the_pool_holds_can_be_swapped() {
    let dir = temp_dir("swap-pooled-assets");
    let (mut c, _fake) = ready_to_swap(&dir);

    assert_eq!(
        c.state().swap_pool_assets(),
        vec![
            AssetId::Native,
            AssetId::CurrencyCollection(1),
            AssetId::CurrencyCollection(2)
        ],
        "the offered assets are the pool's holdings, in the wallet's own order"
    );

    c.state_mut().swap.form.to = cc_wallet_domain::SendToken::Cc(3);
    let generation = c.subscription_generation;
    let seq = c.swap_pool_seq;
    c.apply_swap_pool_loaded(
        generation,
        seq,
        pool_snapshot(100 * NANO, &[(1, 100 * NANO), (2, 100 * NANO)]),
    );
    assert_eq!(
        c.state().swap.form.to_asset(),
        AssetId::Native,
        "an unheld output falls back to the first asset the pool holds"
    );
    assert_ne!(
        c.state().swap.form.from_asset(),
        c.state().swap.form.to_asset(),
        "the two sides stay distinct"
    );
    cleanup(&dir);
}

#[test]
fn max_spends_the_whole_token_but_keeps_a_coin_back_for_gas() {
    let dir = temp_dir("swap-max");
    let (mut c, _fake) = ready_to_swap(&dir);

    c.handle_command(AppCommand::SetSwapFromToken(AssetId::CurrencyCollection(1)));
    c.handle_command(AppCommand::SetMaxSwapAmount);
    assert_eq!(c.state().swap.form.amount, "200.000000000");
    assert!(
        c.state().swap_button_enabled(),
        "the whole token is swappable"
    );

    c.handle_command(AppCommand::SetSwapFromToken(AssetId::Native));
    c.handle_command(AppCommand::SetMaxSwapAmount);
    assert_eq!(
        c.state().swap.form.amount,
        "49.000000000",
        "50 less one COIN"
    );
    assert!(
        c.state().swap_button_enabled(),
        "what MAX offers must be affordable, cushion included"
    );

    let mut wallet = timed_wallet("0:me");
    set_native_balance(&mut wallet, 250_000_000);
    c.state_mut().wallet = Some(wallet);
    c.handle_command(AppCommand::SetMaxSwapAmount);
    assert_eq!(c.state().swap.form.amount, "0.000000000");
    assert!(!c.state().swap_button_enabled(), "zero is not a swap");
    cleanup(&dir);
}

#[test]
fn the_tolerance_steps_by_a_tenth_of_a_percent_and_stops_at_the_ends() {
    let dir = temp_dir("swap-slippage-steps");
    let (mut c, _fake) = ready_to_swap(&dir);

    assert_eq!(c.state().swap.form.slippage_bps, DEFAULT_SLIPPAGE_BPS);
    assert_eq!(c.state().swap.slippage_input, "0.5");

    c.handle_command(AppCommand::StepSwapSlippage(true));
    assert_eq!(c.state().swap.form.slippage_bps, 60);
    assert_eq!(
        c.state().swap.slippage_input,
        "0.6",
        "the field shows the figure the arrows landed on"
    );

    c.handle_command(AppCommand::StepSwapSlippage(false));
    c.handle_command(AppCommand::StepSwapSlippage(false));
    assert_eq!(c.state().swap.form.slippage_bps, 40);
    assert_eq!(c.state().swap.slippage_input, "0.4");

    for _ in 0..8 {
        c.handle_command(AppCommand::StepSwapSlippage(false));
    }
    assert_eq!(c.state().swap.form.slippage_bps, 0);
    assert_eq!(c.state().swap.slippage_input, "0");
    assert!(c.state().swap_button_enabled(), "no slippage is signable");

    for _ in 0..200 {
        c.handle_command(AppCommand::StepSwapSlippage(true));
    }
    assert_eq!(
        c.state().swap.form.slippage_bps,
        1_000,
        "10% is the ceiling"
    );
    assert_eq!(c.state().swap.slippage_input, "10");

    c.handle_command(AppCommand::EditSwapSlippage("0.57".to_owned()));
    assert_eq!(c.state().swap.form.slippage_bps, 57, "0.57% is 57 bps");
    assert_eq!(c.state().swap.slippage_input, "0.57");
    assert!(c.state().swap_button_enabled());
    c.handle_command(AppCommand::StepSwapSlippage(true));
    assert_eq!(c.state().swap.form.slippage_bps, 60);
    cleanup(&dir);
}

#[test]
fn a_refused_tolerance_keeps_the_last_good_one_and_blocks_swapping() {
    let dir = temp_dir("swap-slippage-refused");
    let (mut c, _fake) = ready_to_swap(&dir);

    c.handle_command(AppCommand::SetSwapSlippage(50));
    let before = c.state().swap.quote.expect("the fixture prices a quote");

    for refused in ["", "12", "0.001", "abc", "-1"] {
        c.handle_command(AppCommand::EditSwapSlippage(refused.to_owned()));
        assert_eq!(
            c.state().swap.form.slippage_bps,
            50,
            "{refused:?} must not move the tolerance in force"
        );
        assert!(
            !c.state().swap_slippage_typed_ok(),
            "{refused:?} is not a tolerance this wallet honours"
        );
        assert!(
            !c.state().swap_button_enabled(),
            "{refused:?} must not be signable"
        );
        assert_eq!(
            c.state().swap.quote,
            Some(before),
            "{refused:?} must not reprice the quote"
        );
        c.handle_command(AppCommand::StepSwapSlippage(true));
        assert!(c.state().swap_slippage_typed_ok());
        assert!(c.state().swap_button_enabled());
        c.handle_command(AppCommand::SetSwapSlippage(50));
    }

    c.handle_command(AppCommand::EditSwapSlippage("10".to_owned()));
    assert_eq!(
        c.state().swap.form.slippage_bps,
        1_000,
        "10% is the ceiling"
    );
    assert!(c.state().swap_slippage_typed_ok());
    assert!(c.state().swap_button_enabled());
    cleanup(&dir);
}

#[test]
fn a_filled_swap_reads_its_settled_figures_back_out_of_history() {
    let dir = temp_dir("swap-receipt-filled");
    let (mut c, _fake) = ready_to_swap(&dir);
    c.state_mut().selected_tab = AppTab::Swap;
    let out_units = 9_066_108_938;

    dispatch_swap(&mut c, "swap-ext", out_units);

    let receipt = c.state().swap.receipt.clone().expect("a receipt is opened");
    assert_eq!(
        receipt.sent,
        amount(AssetId::CurrencyCollection(1), 10 * NANO)
    );
    assert_eq!(receipt.out_asset, AssetId::CurrencyCollection(2));
    assert_eq!(receipt.expected_out_units, out_units);
    assert!(
        !receipt.settled(),
        "nothing is settled before the chain says so"
    );
    assert_eq!(
        c.state().selected_tab,
        AppTab::Swap,
        "a swap that reached the node leaves the reader on the page that reports it"
    );
    assert!(
        c.state().swap.form.amount.is_empty(),
        "the form is cleared for the next swap"
    );

    c.merge_activity(vec![swap_out_event(
        40,
        "other-ext",
        AssetId::CurrencyCollection(1),
        10 * NANO,
        7_000_000,
    )]);
    assert!(
        !c.state()
            .swap
            .receipt
            .as_ref()
            .expect("still open")
            .settled(),
        "the receipt is matched by its own external message, not by amount"
    );

    c.merge_activity(vec![
        swap_out_event(
            50,
            "swap-ext",
            AssetId::CurrencyCollection(1),
            10 * NANO,
            7_400_000,
        ),
        pool_answer_event(
            60,
            AssetId::CurrencyCollection(2),
            out_units,
            1_600_000,
            false,
        ),
    ]);

    let receipt = c
        .state()
        .swap
        .receipt
        .clone()
        .expect("the receipt survives");
    assert_eq!(receipt.received_units, Some(out_units));
    assert_eq!(receipt.returned_units, None);
    assert!(!receipt.returned());
    assert!(receipt.settled());
    assert_eq!(
        receipt.fee_native,
        7_400_000 + 1_600_000,
        "the fees are both of this swap's own transactions, as Activity counts them"
    );
    cleanup(&dir);
}

#[test]
fn a_swaps_own_row_reports_its_finality_like_any_other_send() {
    let dir = temp_dir("swap-finality");
    let (mut c, _fake) = ready_to_swap(&dir);
    dispatch_swap(&mut c, "swap-ext", 9_066_108_938);
    assert_eq!(
        c.session.pending_externals.len(),
        1,
        "a broadcast swap is timed from the moment it went out"
    );

    c.merge_activity(vec![ActivityEvent {
        counterparty: "0:other".to_owned(),
        tx_hash: optional_digest("unrelated"),
        ext_msg_hash: optional_digest("other-ext"),
        int_msg_hash: optional_digest("other-int"),
        ..ActivityEvent::test_stub(30, 1_700_000_000)
    }]);
    assert_eq!(c.session.pending_externals.len(), 1);

    c.record_account_announcement(50);
    c.merge_activity(vec![swap_out_event(
        50,
        "swap-ext",
        AssetId::CurrencyCollection(1),
        10 * NANO,
        7_400_000,
    )]);

    let row = c
        .state()
        .activity
        .iter()
        .find(|event| event.ext_msg_hash == optional_digest("swap-ext"))
        .expect("the swap's own row is in history");
    assert!(
        row.finality_ms.is_some(),
        "a swap is our own send, so its row says how long it took to appear"
    );
    assert!(
        c.session.pending_externals.is_empty(),
        "a swap that has been seen is no longer waiting to be timed"
    );

    let stamped = row.finality_ms;
    c.merge_activity(vec![swap_out_event(
        51,
        "swap-ext",
        AssetId::CurrencyCollection(1),
        10 * NANO,
        7_400_000,
    )]);
    assert_eq!(
        c.state()
            .activity
            .iter()
            .filter(|event| event.ext_msg_hash == optional_digest("swap-ext"))
            .filter_map(|event| event.finality_ms)
            .min(),
        stamped,
        "the first sighting is the one that counts"
    );
    cleanup(&dir);
}

#[test]
fn a_bounced_swap_reads_as_returned_with_only_the_fees_spent() {
    let dir = temp_dir("swap-receipt-returned");
    let (mut c, _fake) = ready_to_swap(&dir);
    c.handle_command(AppCommand::SetSwapFromToken(AssetId::CurrencyCollection(3)));
    c.handle_command(AppCommand::SetSwapToToken(AssetId::CurrencyCollection(1)));
    c.handle_command(AppCommand::SetSwapAmount("2".to_owned()));
    assert!(
        c.state().swap.quote.is_some_and(|quote| quote.is_empty()),
        "a token the pool does not hold has no route, not a windfall"
    );

    dispatch_swap(&mut c, "bounce-ext", 0);
    c.merge_activity(vec![
        swap_out_event(
            70,
            "bounce-ext",
            AssetId::CurrencyCollection(3),
            2 * NANO,
            7_100_000,
        ),
        pool_answer_event(
            80,
            AssetId::CurrencyCollection(3),
            2 * NANO,
            1_800_000,
            true,
        ),
    ]);

    let receipt = c
        .state()
        .swap
        .receipt
        .clone()
        .expect("the receipt survives");
    assert_eq!(receipt.returned_units, Some(2 * NANO));
    assert_eq!(receipt.received_units, None);
    assert!(receipt.returned() && receipt.settled());
    assert_eq!(receipt.fee_native, 7_100_000 + 1_800_000);
    cleanup(&dir);
}

#[test]
fn a_swap_that_never_reached_the_node_reports_the_failure_and_opens_no_receipt() {
    let dir = temp_dir("swap-not-transmitted");
    let (mut c, _fake) = ready_to_swap(&dir);
    c.state_mut().selected_tab = AppTab::Swap;
    let sent = c.state().swap.form.input().unwrap();
    c.swap_in_flight = Some(super::swap::SwapIntent {
        sent,
        out_asset: AssetId::CurrencyCollection(2),
        expected_out_units: 1,
        min_out_units: 0,
        slippage_bps: 50,
        pool: SWAP_POOL.to_owned(),
    });
    let generation = c.session_generation;
    c.apply_event(AppEvent::SwapFinished {
        generation,
        result: Ok(crate::event::BroadcastDispatch {
            outcome: CandidateBroadcastOutcome::NotTransmitted {
                detail: "no route to the node".to_owned(),
                retry_next_candidate: false,
            },
            ext_msg_hash: digest("dead-ext"),
            broadcast_started_at: Instant::now(),
        }),
    });

    assert!(
        c.state().swap.receipt.is_none(),
        "a swap that never left the wallet has nothing to report"
    );
    assert!(
        c.state()
            .error
            .as_deref()
            .is_some_and(|error| error.contains("did not reach the network")),
        "the failure is said plainly"
    );
    assert_eq!(c.state().selected_tab, AppTab::Swap);
    assert!(
        !c.state().swap.form.amount.is_empty(),
        "the amount is kept so the swap can be tried again"
    );
    cleanup(&dir);
}

#[test]
fn switching_wallets_drops_the_swap_receipt_of_the_one_left_behind() {
    let dir = temp_dir("swap-receipt-identity");
    let (mut c, _fake) = ready_to_swap(&dir);
    dispatch_swap(&mut c, "swap-ext", 9_066_108_938);
    assert!(c.state().swap.receipt.is_some());

    c.handle_command(AppCommand::ImportSeed(seed_input(SECOND_TEST_SEED)));

    assert!(
        c.state().swap.receipt.is_none(),
        "a receipt belongs to the wallet that made the swap"
    );
    assert!(c.swap_in_flight.is_none());
    cleanup(&dir);
}

#[test]
fn the_send_button_settles_once_instead_of_blinking_while_the_fee_lands() {
    let dir = temp_dir("send-button-settles");
    let (mut c, _fake) = ready_to_send(&dir);
    c.state_mut().send_form.destination.clear();
    c.state_mut().send_form.amount.clear();

    let mut seen = Vec::new();
    let record = |c: &AppController, seen: &mut Vec<bool>| {
        let now = c.state().send_ready();
        if seen.last() != Some(&now) {
            seen.push(now);
        }
    };
    record(&c, &mut seen);

    c.handle_command(AppCommand::SetSendAmount("1.0".to_owned()));
    record(&c, &mut seen);
    c.handle_command(AppCommand::SetSendDestination(SEND_DEST.to_owned()));
    record(&c, &mut seen);

    assert!(
        c.state().fee_estimate_stale,
        "an edited form has no fee of its own yet"
    );
    assert!(
        c.state().fee_estimate_stale,
        "the form was edited, so no estimate of its own has landed yet"
    );
    assert!(
        c.state().send_ready(),
        "the button lights as soon as the form is complete — it does not wait 600ms for \
         a debounced estimate, it judges the amount against a fee bound the real one is \
         not expected to beat, so the verdict does not change when it lands"
    );
    assert_eq!(
        c.state().pending_send_fee_bound(),
        crate::state::HARDCODED_SEND_FEE_NANOS + LOCAL_SEND_FEE_HEADROOM_NANOS,
        "with no estimate yet the bound is the app's own default fee plus its headroom"
    );

    c.estimate_fee();
    record(&c, &mut seen);
    c.apply_event(AppEvent::FeeEstimated {
        generation: c.subscription_generation,
        seq: c.fee_request_seq,
        estimate: FeeEstimate {
            fee_nanos: 2_804_671,
            deploy: false,
        },
    });
    record(&c, &mut seen);

    assert!(
        c.state().send_ready(),
        "once the estimate lands the button turns on"
    );
    assert_eq!(
        seen,
        vec![false, true],
        "the button may only go off-then-on; it blinked instead: {seen:?}"
    );
    cleanup(&dir);
}

const STORAGE_ADDR: &str = "0:5f5c08a95c2f1332dd6305d824d31b76f7cdb3040e3955c08d23b269ed13969b";

fn stored(id: u32, title: &str, data: &str) -> StorageRecord {
    StorageRecord {
        id,
        title: title.to_owned(),
        data: data.to_owned(),
    }
}

fn settle(c: &mut AppController) {
    c.pump_events();
}

fn dispatch_record(c: &mut AppController, ext: &str) {
    let generation = c.session_generation;
    c.apply_event(AppEvent::StorageFinished {
        generation,
        op: StorageOp::Put {
            id: 2,
            title: "watched".to_owned(),
            data: "x".to_owned(),
        },
        result: Ok(crate::event::BroadcastDispatch {
            outcome: CandidateBroadcastOutcome::NodeResponseObserved {
                request_id: "req".to_owned(),
                response: cc_wallet_domain::NodeResponseKind::Acknowledged,
                detail: "acknowledged".to_owned(),
            },
            ext_msg_hash: digest(ext),
            broadcast_started_at: Instant::now(),
        }),
    });
    settle(c);
}

fn add_record(c: &mut AppController, title: &str, data: &str) {
    c.handle_command(AppCommand::SetStorageTitle(title.to_owned()));
    c.handle_command(AppCommand::SetStorageData(data.to_owned()));
    c.handle_command(AppCommand::AddStorageRecord);
    settle(c);
}

fn authorize(c: &mut AppController) {
    c.handle_command(AppCommand::AuthSubmit {
        pw: Password::new(String::from_utf8(PW.to_vec()).unwrap()),
        pw2: Password::new(String::new()),
        remember: false,
    });
    c.pump_key();
    c.pump_events();
}

fn storage_controller(
    dir: &Path,
    chain: FakeChain,
    records: Vec<StorageRecord>,
) -> (AppController, MemoryClipboard) {
    chain.set_storage(StorageSnapshot {
        address: STORAGE_ADDR.to_owned(),
        exists: true,
        balance: 1_000_000_000,
        records,
        unreadable: 0,
    });
    let profile = WalletProfile {
        seed: test_seed(),
        ..WalletProfile::default()
    };
    let mut c = unlocked(dir, profile);
    c.state_mut().seed = test_seed();
    c.chain = Arc::new(chain);
    c.flush_save_blocking();
    while c.rx.try_recv().is_ok() {}
    let mem = mem_clipboard(&mut c);
    c.handle_command(AppCommand::SelectTab(AppTab::Storage));
    settle(&mut c);
    (c, mem)
}

#[test]
fn opening_the_storage_tab_reads_what_is_on_chain() {
    let dir = temp_dir("storage-open");
    let chain = FakeChain::default();
    let (c, _mem) = storage_controller(
        &dir,
        chain,
        vec![
            stored(1, "Inna's phone", "86594423664"),
            stored(2, "My email", "abc@gmail.com"),
        ],
    );

    assert!(c.state().storage.exists);
    assert!(c.state().storage.loaded);
    assert_eq!(c.state().storage.address, STORAGE_ADDR);
    assert_eq!(c.state().storage.records.len(), 2);
    assert_eq!(c.state().storage.records[0].title, "Inna's phone");
    assert_eq!(c.state().storage.records[1].data, "abc@gmail.com");
    cleanup(&dir);
}

#[test]
fn adding_a_record_asks_for_authorization_before_it_reaches_the_chain() {
    let dir = temp_dir("storage-auth-gate");
    let chain = FakeChain::default();
    let (mut c, _mem) = storage_controller(&dir, chain.clone(), Vec::new());

    c.handle_command(AppCommand::SetStorageTitle("Inna's phone".to_owned()));
    c.handle_command(AppCommand::SetStorageData("86594423664".to_owned()));
    c.handle_command(AppCommand::AddStorageRecord);
    settle(&mut c);

    assert!(c.state().auth.open, "the record waits for authorization");
    assert_eq!(c.state().auth.purpose, AuthPurpose::Storage);
    assert!(
        chain.storage_ops().is_empty(),
        "nothing reached the chain before the user authorized it"
    );

    c.handle_command(AppCommand::AuthCancel);
    settle(&mut c);
    assert!(
        chain.storage_ops().is_empty(),
        "cancelling drops the request instead of sending it"
    );
    assert!(!c.state().auth.open);
    cleanup(&dir);
}

#[test]
fn an_authorized_record_reaches_the_chain_with_the_lowest_free_number() {
    let dir = temp_dir("storage-lowest-gap");
    let chain = FakeChain::default();
    let (mut c, _mem) = storage_controller(
        &dir,
        chain.clone(),
        vec![stored(1, "one", "a"), stored(3, "three", "c")],
    );

    c.handle_command(AppCommand::SetStorageTitle("  My email  ".to_owned()));
    c.handle_command(AppCommand::SetStorageData("abc@gmail.com".to_owned()));
    c.handle_command(AppCommand::AddStorageRecord);
    settle(&mut c);
    authorize(&mut c);

    assert_eq!(
        chain.storage_ops(),
        vec![StorageOp::Put {
            id: 2,
            title: "My email".to_owned(),
            data: "abc@gmail.com".to_owned(),
        }],
        "the freed number 2 is reused and the name is trimmed"
    );
    cleanup(&dir);
}

#[test]
fn a_record_the_form_would_reject_never_opens_the_authorization() {
    let dir = temp_dir("storage-form-gate");
    let chain = FakeChain::default();
    let (mut c, _mem) = storage_controller(&dir, chain.clone(), Vec::new());

    c.handle_command(AppCommand::SetStorageTitle("   ".to_owned()));
    c.handle_command(AppCommand::SetStorageData("86594423664".to_owned()));
    c.handle_command(AppCommand::AddStorageRecord);
    settle(&mut c);
    assert!(!c.state().auth.open, "a blank name never asks to sign");
    assert!(!c.state().storage.form_error.is_empty());

    c.handle_command(AppCommand::SetStorageTitle("fine".to_owned()));
    c.handle_command(AppCommand::SetStorageData("x".repeat(2000)));
    c.handle_command(AppCommand::AddStorageRecord);
    settle(&mut c);
    assert!(
        !c.state().auth.open,
        "an oversized record never asks to sign"
    );

    assert!(chain.storage_ops().is_empty());
    cleanup(&dir);
}

#[test]
fn deleting_names_the_record_and_refuses_one_that_is_not_there() {
    let dir = temp_dir("storage-delete");
    let chain = FakeChain::default();
    let (mut c, _mem) = storage_controller(&dir, chain.clone(), vec![stored(4, "note", "secret")]);

    c.handle_command(AppCommand::DeleteStorageRecord(9));
    settle(&mut c);
    assert!(
        !c.state().auth.open,
        "deleting an absent record asks nothing"
    );
    assert!(!c.state().storage.error.is_empty());

    c.handle_command(AppCommand::DeleteStorageRecord(4));
    settle(&mut c);
    assert_eq!(c.state().auth.purpose, AuthPurpose::Storage);
    authorize(&mut c);

    assert_eq!(chain.storage_ops(), vec![StorageOp::Delete { id: 4 }]);
    cleanup(&dir);
}

#[test]
fn a_record_in_flight_looks_for_its_own_transaction_the_way_a_transfer_does() {
    let dir = temp_dir("storage-settle-fetch");
    let chain = FakeChain::default();
    let (mut c, _mem) = storage_controller(&dir, chain.clone(), vec![stored(1, "one", "a")]);
    let before = chain.transaction_calls();

    dispatch_record(&mut c, "settle-ext");
    assert!(
        c.storage_watch.is_some(),
        "a dispatched record is being watched for settlement"
    );

    let fetched_on_dispatch = chain.transaction_calls();
    assert!(
        fetched_on_dispatch > before,
        "dispatching a record reads history once, the way a transfer does"
    );

    c.poll_storage_settlement(Instant::now() + Duration::from_secs(5));
    settle(&mut c);
    assert!(
        chain.transaction_calls() > fetched_on_dispatch,
        "and it keeps looking on every settlement tick, so the moment its row \
         appears is found on the same cadence a transfer's is"
    );
    cleanup(&dir);
}

#[test]
fn an_announcement_makes_a_settling_record_look_again_at_once() {
    let dir = temp_dir("storage-expedite");
    let chain = FakeChain::default();
    let (mut c, _mem) = storage_controller(&dir, chain, vec![stored(1, "one", "a")]);

    dispatch_record(&mut c, "expedite-ext");
    assert!(c.storage_watch.is_some(), "the record is being watched");
    let read = c.storage_seq;

    c.apply_event(AppEvent::SubscriptionUpdate {
        generation: c.subscription_generation,
        update: cc_wallet_chain::AccountUpdate {
            max_lt: 99,
            gen_utime: None,
        },
    });
    assert!(
        c.storage_seq > read,
        "the account moved, so the storage is read again there and then rather \
         than at the end of a poll interval"
    );
    cleanup(&dir);
}

#[test]
fn a_row_the_subscription_never_announced_reports_no_finality() {
    let dir = temp_dir("finality-needs-a-subscription");
    let chain = FakeChain::default();
    let (mut c, _mem) = storage_controller(&dir, chain, vec![stored(1, "one", "a")]);

    // An announcement from before the message went out belongs to someone
    // else's transaction and cannot time ours.
    c.record_account_announcement(70);
    dispatch_record(&mut c, "quiet-ext");

    // The row turns up in a read we went and made ourselves, with the
    // subscription silent throughout.
    c.merge_activity(vec![ActivityEvent {
        direction: ActivityDirection::Out,
        tx_hash: optional_digest("quiet-tx"),
        counterparty: STORAGE_ADDR.to_owned(),
        ext_msg_hash: optional_digest("quiet-ext"),
        int_msg_hash: optional_digest("quiet-int"),
        ..ActivityEvent::test_stub(70, 1_700_000_000)
    }]);

    let row = c
        .state()
        .activity
        .iter()
        .find(|event| event.ext_msg_hash == optional_digest("quiet-ext"))
        .expect("the transaction is in history");
    assert!(
        row.finality_ms.is_none(),
        "how long our own poll took to notice is not how long the chain took, \
         so the row says nothing rather than something untrue"
    );
    cleanup(&dir);
}

#[test]
fn a_records_own_row_reports_its_finality_like_any_other_send() {
    let dir = temp_dir("storage-finality");
    let chain = FakeChain::default();
    let (mut c, _mem) = storage_controller(&dir, chain, vec![stored(1, "one", "a")]);
    let generation = c.session_generation;

    c.apply_event(AppEvent::StorageFinished {
        generation,
        op: StorageOp::Delete { id: 1 },
        result: Ok(crate::event::BroadcastDispatch {
            outcome: CandidateBroadcastOutcome::NodeResponseObserved {
                request_id: "req".to_owned(),
                response: cc_wallet_domain::NodeResponseKind::Acknowledged,
                detail: "acknowledged".to_owned(),
            },
            ext_msg_hash: digest("storage-ext"),
            broadcast_started_at: Instant::now(),
        }),
    });
    assert_eq!(
        c.session.pending_externals.len(),
        1,
        "a record on the wire is timed from the moment it went out"
    );

    c.record_account_announcement(60);
    c.merge_activity(vec![ActivityEvent {
        direction: ActivityDirection::Out,
        tx_hash: optional_digest("storage-tx"),
        counterparty: STORAGE_ADDR.to_owned(),
        ext_msg_hash: optional_digest("storage-ext"),
        int_msg_hash: optional_digest("storage-int"),
        ..ActivityEvent::test_stub(60, 1_700_000_000)
    }]);

    let row = c
        .state()
        .activity
        .iter()
        .find(|event| event.ext_msg_hash == optional_digest("storage-ext"))
        .expect("the record's own transaction is in history");
    assert!(
        row.finality_ms.is_some(),
        "writing a record is our own send, so its row says how long it took to appear"
    );
    assert!(
        c.session.pending_externals.is_empty(),
        "a record that has been seen is no longer waiting to be timed"
    );
    cleanup(&dir);
}

#[test]
fn signing_a_record_can_stay_unlocked_the_way_signing_a_transfer_can() {
    let dir = temp_dir("storage-remember");
    let chain = FakeChain::default();
    let (mut c, _mem) = storage_controller(&dir, chain.clone(), Vec::new());

    add_record(&mut c, "first", "a");
    authorize(&mut c);
    assert!(
        !c.state().within_autosign(),
        "an unticked 'stay unlocked' leaves the next record asking again"
    );

    add_record(&mut c, "second", "b");
    assert_eq!(c.state().auth.mode, AuthMode::Enter, "it asks again");
    c.handle_command(AppCommand::AuthSubmit {
        pw: Password::new(String::from_utf8(PW.to_vec()).unwrap()),
        pw2: Password::new(String::new()),
        remember: true,
    });
    c.pump_key();
    c.pump_events();
    assert!(
        c.state().within_autosign(),
        "ticking it opens the same auto-sign window a transfer opens"
    );

    add_record(&mut c, "third", "c");
    assert_eq!(
        c.state().auth.mode,
        AuthMode::Confirm,
        "and the next record only asks to be confirmed"
    );
    cleanup(&dir);
}

#[test]
fn copying_a_record_puts_its_contents_on_the_clipboard_and_not_its_name() {
    let dir = temp_dir("storage-copy");
    let chain = FakeChain::default();
    let (mut c, mem) =
        storage_controller(&dir, chain, vec![stored(1, "My email", "abc@gmail.com")]);

    c.handle_command(AppCommand::CopyStorageRecord(1));
    settle(&mut c);

    assert_eq!(clipboard_of(&mem), "abc@gmail.com");
    cleanup(&dir);
}

#[test]
fn locking_forgets_every_decrypted_record() {
    let dir = temp_dir("storage-lock");
    let chain = FakeChain::default();
    let (mut c, _mem) =
        storage_controller(&dir, chain, vec![stored(1, "My email", "abc@gmail.com")]);
    assert_eq!(c.state().storage.records.len(), 1);

    c.handle_command(AppCommand::LockNow);
    settle(&mut c);

    assert!(
        c.state().storage.records.is_empty(),
        "plaintext records do not survive a lock"
    );
    assert!(c.state().storage.title_input.is_empty());
    assert!(c.state().storage.data_input.is_empty());
    cleanup(&dir);
}

#[test]
fn record_contents_stay_hidden_until_the_password_reveals_them() {
    let dir = temp_dir("storage-reveal");
    let chain = FakeChain::default();
    let (mut c, _mem) =
        storage_controller(&dir, chain, vec![stored(1, "My email", "abc@gmail.com")]);

    assert!(
        !c.state().storage.revealed,
        "a freshly opened storage never shows what the records hold"
    );

    c.handle_command(AppCommand::RevealStorageRecords);
    settle(&mut c);
    assert!(c.state().auth.open, "revealing asks for the password");
    assert_eq!(c.state().auth.purpose, AuthPurpose::RevealRecords);
    assert!(
        !c.state().storage.revealed,
        "asking is not the same as revealing"
    );

    authorize(&mut c);
    assert!(c.state().storage.revealed);
    assert!(
        c.state().storage.reveal_ttl_secs > 0 && c.state().storage.reveal_ttl_secs <= 60,
        "the reveal is on a countdown: {}",
        c.state().storage.reveal_ttl_secs
    );
    cleanup(&dir);
}

#[test]
fn a_revealed_record_hides_itself_again_when_its_minute_is_up() {
    let dir = temp_dir("storage-reveal-expiry");
    let chain = FakeChain::default();
    let (mut c, _mem) = storage_controller(&dir, chain, vec![stored(1, "My email", "secret")]);

    c.handle_command(AppCommand::RevealStorageRecords);
    settle(&mut c);
    authorize(&mut c);
    assert!(c.state().storage.revealed);

    c.state_mut().records_reveal_deadline = Some(Deadline::after(Duration::ZERO));
    c.tick();

    assert!(
        !c.state().storage.revealed,
        "an expired reveal hides the records again"
    );
    assert_eq!(c.state().storage.reveal_ttl_secs, 0);
    cleanup(&dir);
}

#[test]
fn hiding_records_also_wipes_what_was_copied_from_them() {
    let dir = temp_dir("storage-copy-wipe");
    let chain = FakeChain::default();
    let (mut c, mem) =
        storage_controller(&dir, chain, vec![stored(1, "My email", "abc@gmail.com")]);

    c.handle_command(AppCommand::CopyStorageRecord(1));
    settle(&mut c);
    assert_eq!(clipboard_of(&mem), "abc@gmail.com");

    c.handle_command(AppCommand::HideStorageRecords);
    settle(&mut c);
    assert_eq!(
        clipboard_of(&mem),
        "",
        "a copied record is wiped from the clipboard, like the seed phrase"
    );
    cleanup(&dir);
}

#[test]
fn a_copied_record_is_wiped_when_the_wallet_locks() {
    let dir = temp_dir("storage-copy-lock");
    let chain = FakeChain::default();
    let (mut c, mem) =
        storage_controller(&dir, chain, vec![stored(1, "My email", "abc@gmail.com")]);

    c.handle_command(AppCommand::CopyStorageRecord(1));
    settle(&mut c);
    assert_eq!(clipboard_of(&mem), "abc@gmail.com");

    c.handle_command(AppCommand::LockNow);
    settle(&mut c);
    assert_eq!(
        clipboard_of(&mem),
        "",
        "locking takes the record off the clipboard with it"
    );
    cleanup(&dir);
}

#[test]
fn only_deleting_a_record_is_dressed_as_dangerous() {
    let dir = temp_dir("storage-danger");
    let chain = FakeChain::default();
    let (mut c, _mem) = storage_controller(&dir, chain.clone(), vec![stored(1, "note", "secret")]);

    c.handle_command(AppCommand::SetStorageTitle("another".to_owned()));
    c.handle_command(AppCommand::SetStorageData("value".to_owned()));
    c.handle_command(AppCommand::AddStorageRecord);
    settle(&mut c);
    assert!(
        !c.state().storage.pending_danger,
        "saving a record is an ordinary action"
    );
    c.handle_command(AppCommand::AuthCancel);
    settle(&mut c);
    assert!(
        !c.state().storage.pending_danger,
        "cancelling clears the danger flag with the request"
    );

    c.handle_command(AppCommand::DeleteStorageRecord(1));
    settle(&mut c);
    assert!(
        c.state().storage.pending_danger,
        "deleting is the one that must not look routine"
    );
    cleanup(&dir);
}

#[test]
fn leaving_the_storage_page_hides_the_records_again() {
    let dir = temp_dir("storage-leave");
    let chain = FakeChain::default();
    let (mut c, mem) =
        storage_controller(&dir, chain, vec![stored(1, "My email", "abc@gmail.com")]);

    c.handle_command(AppCommand::RevealStorageRecords);
    settle(&mut c);
    authorize(&mut c);
    assert!(c.state().storage.revealed);
    c.handle_command(AppCommand::CopyStorageRecord(1));
    settle(&mut c);
    assert_eq!(clipboard_of(&mem), "abc@gmail.com");

    c.handle_command(AppCommand::SelectTab(AppTab::Wallet));
    settle(&mut c);

    assert!(
        !c.state().storage.revealed,
        "walking away from the page puts the records back behind the password"
    );
    assert_eq!(
        clipboard_of(&mem),
        "",
        "and takes what was copied off the clipboard with it"
    );
    cleanup(&dir);
}

#[test]
fn a_save_in_flight_does_not_add_or_remove_anything_on_the_page() {
    let dir = temp_dir("storage-no-jitter");
    let chain = FakeChain::default();
    let (mut c, _mem) = storage_controller(&dir, chain, vec![stored(1, "one", "a")]);

    // The row that reports progress is always present, so a notice appearing or
    // clearing can never change the page's layout under the user's cursor.
    let rows_before = c.state().storage.records.len();
    c.handle_command(AppCommand::SetStorageTitle("two".to_owned()));
    c.handle_command(AppCommand::SetStorageData("b".to_owned()));
    c.handle_command(AppCommand::AddStorageRecord);
    settle(&mut c);
    assert_eq!(
        c.state().storage.records.len(),
        rows_before,
        "an unconfirmed save must not insert a row that later disappears"
    );
    cleanup(&dir);
}

#[test]
fn a_result_this_session_cannot_use_still_unlocks_the_form() {
    let dir = temp_dir("storage-busy-release");
    let chain = FakeChain::default();
    let (mut c, _mem) = storage_controller(&dir, chain, vec![stored(1, "one", "a")]);

    c.state_mut().storage.busy = true;
    // A generation this session will never match: the result is discarded, but
    // the page must not stay locked because of it.
    c.apply_event(AppEvent::StorageFinished {
        generation: u64::MAX,
        op: StorageOp::Delete { id: 1 },
        result: Err(ChainError::Wallet("gone".to_owned())),
    });

    assert!(
        !c.state().storage.busy,
        "a stale result must not leave the page busy forever"
    );
    cleanup(&dir);
}

#[test]
fn a_copied_record_is_wiped_on_the_same_timer_as_the_recovery_phrase() {
    let dir = temp_dir("storage-copy-ttl");
    let chain = FakeChain::default();
    let (mut c, mem) =
        storage_controller(&dir, chain, vec![stored(1, "My email", "abc@gmail.com")]);

    c.handle_command(AppCommand::CopyStorageRecord(1));
    settle(&mut c);
    assert_eq!(clipboard_of(&mem), "abc@gmail.com");

    let armed = c
        .clipboard_deadline
        .expect("copying a record arms the wipe, exactly as copying the phrase does");
    assert!(
        armed.remaining_secs() > 55 && armed.remaining_secs() <= 60,
        "the record gets the recovery phrase's own minute, not a different one: {}s",
        armed.remaining_secs()
    );

    c.clipboard_deadline = Some(Deadline::after(Duration::ZERO));
    c.tick();

    assert_eq!(
        clipboard_of(&mem),
        "",
        "the timer takes the record off the clipboard without anyone asking"
    );
    cleanup(&dir);
}
