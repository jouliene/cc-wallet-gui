use std::time::{Duration, Instant};

use cc_wallet_chain::{CandidateBroadcastOutcome, ChainError, MAX_STORAGE_RECORDS};
use cc_wallet_domain::{StorageOp, StorageSnapshot, WalletInputs, next_free_id, validate_record};
use zeroize::Zeroizing;

use super::AppController;
use crate::event::{AppEvent, BroadcastDispatch};
use crate::state::{AuthModal, AuthMode, AuthPurpose, Deadline, StorageUi};

pub(super) struct PendingStorage {
    pub op: StorageOp,
    pub inputs: WalletInputs,
    pub generation: u64,
}

const STORAGE_POLL_EVERY: Duration = Duration::from_millis(1500);

const STORAGE_POLL_FOR: Duration = Duration::from_secs(90);

const RECORD_REVEAL_FOR: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StorageExpectation {
    Exists,
    Holds(u32),
    Lacks(u32),
}

impl StorageExpectation {
    fn of(op: &StorageOp) -> Self {
        match op {
            StorageOp::Create => Self::Exists,
            StorageOp::Put { id, .. } => Self::Holds(*id),
            StorageOp::Delete { id } => Self::Lacks(*id),
        }
    }

    fn met_by(self, snapshot: &StorageUi) -> bool {
        match self {
            Self::Exists => snapshot.exists,
            Self::Holds(id) => snapshot.records.iter().any(|record| record.id == id),
            Self::Lacks(id) => !snapshot.records.iter().any(|record| record.id == id),
        }
    }
}

pub(super) struct StorageWatch {
    expectation: StorageExpectation,
    next_poll: Instant,
    give_up_at: Instant,
}

impl AppController {
    pub(super) fn on_storage_tab_opened(&mut self) {
        if self.state.storage.loaded || self.state.storage.loading {
            return;
        }
        self.refresh_storage();
    }

    pub(super) fn refresh_storage(&mut self) {
        let inputs = match self.wallet_inputs() {
            Ok(inputs) => inputs,
            Err(error) => {
                self.state.storage.error = error;
                return;
            }
        };
        if self.state.storage.address.is_empty()
            && let Ok(address) = self.chain.storage_address_for(&inputs)
        {
            self.state.storage.address = address;
        }
        self.state.storage.loading = true;
        self.state.storage.error.clear();
        let generation = self.subscription_generation;
        self.storage_seq = self.storage_seq.wrapping_add(1);
        let seq = self.storage_seq;
        let tx = self.tx.clone();
        let chain = self.chain.clone();
        self.runtime.spawn(async move {
            let event = match chain.load_storage(inputs).await {
                Ok(snapshot) => AppEvent::StorageLoaded {
                    generation,
                    seq,
                    snapshot,
                },
                Err(error) => AppEvent::StorageLoadFailed {
                    generation,
                    seq,
                    error: error.to_string(),
                },
            };
            let _ = tx.send(event);
        });
    }

    pub(super) fn apply_storage_loaded(
        &mut self,
        generation: u64,
        seq: u64,
        snapshot: StorageSnapshot,
    ) {
        if generation != self.subscription_generation || seq != self.storage_seq {
            self.abandon_stale_storage_read(seq);
            return;
        }
        self.state.storage.loading = false;
        self.state.storage.loaded = true;
        self.state.storage.error.clear();
        self.state.storage.address = snapshot.address;
        self.state.storage.exists = snapshot.exists;
        self.state.storage.balance = snapshot.balance;
        self.state.storage.records = snapshot.records;
        self.state.storage.unreadable = snapshot.unreadable;

        if let Some(watch) = self.storage_watch.as_ref()
            && watch.expectation.met_by(&self.state.storage)
        {
            self.storage_watch = None;
            self.state.storage.notice.clear();
        }
    }

    pub(super) fn poll_storage_settlement(&mut self) {
        let Some(watch) = self.storage_watch.as_ref() else {
            return;
        };
        let now = Instant::now();
        if now >= watch.give_up_at {
            self.storage_watch = None;
            self.state.storage.notice.clear();
            self.state.storage.error =
                "The request reached the network but the storage has not changed yet. Refresh to check again.".to_owned();
            return;
        }
        if now < watch.next_poll || self.state.storage.loading {
            return;
        }
        if let Some(watch) = self.storage_watch.as_mut() {
            watch.next_poll = now + STORAGE_POLL_EVERY;
        }
        self.refresh_storage();
    }

    pub(super) fn apply_storage_load_failed(&mut self, generation: u64, seq: u64, error: String) {
        if generation != self.subscription_generation || seq != self.storage_seq {
            self.abandon_stale_storage_read(seq);
            return;
        }
        self.state.storage.loading = false;
        self.state.storage.error = error;
    }

    /// A read whose wallet identity changed under it is discarded, but it is
    /// still the answer to the only request in flight. Leaving `loading` set
    /// would strand the page on "Looking for your storage…" with nothing left to
    /// resolve it, so the read is re-armed instead.
    fn abandon_stale_storage_read(&mut self, seq: u64) {
        if seq != self.storage_seq || !self.state.storage.loading {
            return;
        }
        self.state.storage.loading = false;
        if self.state.selected_tab == crate::state::AppTab::Storage {
            self.refresh_storage();
        }
    }

    pub(super) fn set_storage_title(&mut self, title: String) {
        self.state.storage.title_input = title;
        self.state.storage.form_error.clear();
    }

    pub(super) fn set_storage_data(&mut self, data: String) {
        self.state.storage.data_input = data;
        self.state.storage.form_error.clear();
    }

    pub(super) fn clear_storage_form(&mut self) {
        self.state.storage.title_input.clear();
        self.state.storage.data_input.clear();
        self.state.storage.form_error.clear();
    }

    pub(super) fn create_storage(&mut self) {
        if self.state.storage.exists {
            self.state.storage.error = "This wallet already has a storage".to_owned();
            return;
        }
        self.request_storage_op(StorageOp::Create);
    }

    pub(super) fn add_storage_record(&mut self) {
        if !self.state.storage.exists {
            self.state.storage.form_error = "Create the storage first".to_owned();
            return;
        }
        let title = self.state.storage.title_input.trim().to_owned();
        let data = self.state.storage.data_input.clone();
        if let Err(error) = validate_record(&title, &data) {
            self.state.storage.form_error = error.to_string();
            return;
        }
        let id = match next_free_id(&self.state.storage.taken_ids(), MAX_STORAGE_RECORDS) {
            Ok(id) => id,
            Err(error) => {
                self.state.storage.form_error = error.to_string();
                return;
            }
        };
        self.request_storage_op(StorageOp::Put { id, title, data });
    }

    pub(super) fn delete_storage_record(&mut self, id: u32) {
        if !self.state.storage.records.iter().any(|r| r.id == id) {
            self.state.storage.error = "That record is no longer in the storage".to_owned();
            return;
        }
        self.request_storage_op(StorageOp::Delete { id });
    }

    pub(super) fn copy_storage_record(&mut self, id: u32) {
        let Some(record) = self
            .state
            .storage
            .records
            .iter()
            .find(|record| record.id == id)
        else {
            return;
        };
        let data = Zeroizing::new(record.data.clone());
        self.copy_secret_to_clipboard(data);
    }

    pub(super) fn reveal_storage_records(&mut self) {
        if self.state.storage.records.is_empty() {
            return;
        }
        self.state.auth = AuthModal {
            open: true,
            mode: AuthMode::Enter,
            purpose: AuthPurpose::RevealRecords,
            send_options_editable: false,
            error: String::new(),
        };
    }

    pub(super) fn show_records_for_one_minute(&mut self) {
        self.state.storage.revealed = true;
        self.state.records_reveal_deadline = Some(Deadline::after(RECORD_REVEAL_FOR));
        self.refresh_record_reveal_ttl();
    }

    pub(super) fn hide_storage_records(&mut self) {
        self.state.storage.revealed = false;
        self.state.records_reveal_deadline = None;
        self.state.storage.reveal_ttl_secs = 0;
        self.clear_seed_from_clipboard();
    }

    pub(super) fn expire_record_reveal(&mut self) {
        if self
            .state
            .records_reveal_deadline
            .is_some_and(|deadline| deadline.expired())
        {
            self.hide_storage_records();
            return;
        }
        self.refresh_record_reveal_ttl();
    }

    fn refresh_record_reveal_ttl(&mut self) {
        self.state.storage.reveal_ttl_secs = self
            .state
            .records_reveal_deadline
            .map_or(0, |deadline| deadline.remaining_secs());
    }

    fn request_storage_op(&mut self, op: StorageOp) {
        if self.pending_storage.is_some() || self.state.storage.busy {
            self.state.storage.error =
                "A storage request is already waiting for confirmation".to_owned();
            return;
        }
        let inputs = match self.wallet_inputs() {
            Ok(inputs) => inputs,
            Err(error) => {
                self.state.set_error(error);
                return;
            }
        };
        let Some(generation) = self.auth_generation.checked_add(1) else {
            self.state.set_error(
                "Storage authorization generation is exhausted; lock and reopen the wallet",
            );
            return;
        };
        self.auth_generation = generation;
        self.state.storage.pending_label = op.label().to_owned();
        self.state.storage.pending_danger = matches!(op, StorageOp::Delete { .. });
        self.pending_storage = Some(PendingStorage {
            op,
            inputs,
            generation,
        });
        let mode = if self.state.within_autosign() {
            AuthMode::Confirm
        } else {
            AuthMode::Enter
        };
        self.state.auth = AuthModal {
            open: true,
            mode,
            purpose: AuthPurpose::Storage,
            send_options_editable: false,
            error: String::new(),
        };
    }

    pub(super) fn clear_pending_storage(&mut self) {
        self.pending_storage = None;
        self.state.storage.pending_label.clear();
        self.state.storage.pending_danger = false;
    }

    pub(super) fn reset_storage_for_new_identity(&mut self) {
        self.clear_pending_storage();
        self.storage_watch = None;
        self.state.records_reveal_deadline = None;
        self.state.storage = StorageUi::default();
        if self.state.selected_tab == crate::state::AppTab::Storage {
            self.refresh_storage();
        }
    }

    pub(super) fn dispatch_authorized_storage(&mut self) {
        let Some(pending) = self.pending_storage.take() else {
            return;
        };
        let PendingStorage { op, inputs, .. } = pending;
        self.state.storage.busy = true;
        self.state.storage.error.clear();
        self.state.storage.notice.clear();
        self.state.busy = true;
        let generation = self.session_generation;
        let tx = self.tx.clone();
        let chain = self.chain.clone();
        let dispatched = op.clone();
        self.runtime.spawn(async move {
            let result = match chain.prepare_storage_op(inputs, dispatched.clone()).await {
                Ok(prepared) => {
                    let ext_msg_hash = prepared.external_hash().clone();
                    let broadcast_started_at = Instant::now();
                    broadcast_all_candidates(chain.as_ref(), &prepared)
                        .await
                        .map(|outcome| BroadcastDispatch {
                            outcome,
                            ext_msg_hash,
                            broadcast_started_at,
                        })
                }
                Err(error) => Err(error),
            };
            let _ = tx.send(AppEvent::StorageFinished {
                generation,
                op: dispatched,
                result,
            });
        });
    }

    pub(super) fn apply_storage_finished(
        &mut self,
        generation: u64,
        op: StorageOp,
        result: Result<BroadcastDispatch, ChainError>,
    ) {
        // Even a result this session can no longer act on has to release the
        // page: `busy` gates the form, and leaving it set would lock the user
        // out of typing with nothing left to clear it.
        self.state.storage.busy = false;
        self.state.storage.pending_label.clear();
        self.state.busy = false;
        if generation != self.session_generation {
            return;
        }
        self.state.storage.pending_label.clear();
        self.state.busy = false;
        match result {
            Ok(dispatch) if broadcast_reached_node(&dispatch.outcome) => {
                // The row this message becomes in Activity is owed a finality
                // reading like any other transfer, and the only thing that can
                // tie the two together is the hash we just put on the wire.
                self.session
                    .pending_externals
                    .push((dispatch.ext_msg_hash, dispatch.broadcast_started_at));
                self.state.storage.notice = match &op {
                    StorageOp::Create => "Creating the storage on chain…".to_owned(),
                    StorageOp::Put { id, .. } => format!("Saving record #{id}…"),
                    StorageOp::Delete { id } => format!("Deleting record #{id}…"),
                };
                if matches!(op, StorageOp::Put { .. }) {
                    self.state.storage.title_input.clear();
                    self.state.storage.data_input.clear();
                    self.state.storage.form_error.clear();
                }
                let now = Instant::now();
                self.storage_watch = Some(StorageWatch {
                    expectation: StorageExpectation::of(&op),
                    next_poll: now + STORAGE_POLL_EVERY,
                    give_up_at: now + STORAGE_POLL_FOR,
                });
                self.auto_refresh_wallet(self.subscription_generation);
                self.fetch_transactions(self.subscription_generation);
                self.refresh_storage();
            }
            Ok(dispatch) => {
                self.state.storage.error = format!(
                    "The storage request did not reach the network: {}",
                    outcome_detail(&dispatch.outcome)
                );
            }
            Err(error) => {
                self.state.storage.error = error.to_string();
            }
        }
    }
}

async fn broadcast_all_candidates(
    chain: &dyn cc_wallet_chain::ChainService,
    prepared: &cc_wallet_chain::PreparedStorageOp,
) -> Result<CandidateBroadcastOutcome, ChainError> {
    let candidates = prepared.candidate_count().max(1);
    let mut last: Option<CandidateBroadcastOutcome> = None;
    for index in 0..candidates {
        let outcome = chain.broadcast_storage_op(prepared, index).await?;
        let retry = matches!(
            &outcome,
            CandidateBroadcastOutcome::NotTransmitted {
                retry_next_candidate: true,
                ..
            }
        );
        last = Some(outcome);
        if !retry {
            break;
        }
    }
    Ok(last.expect("at least one candidate was attempted"))
}

fn broadcast_reached_node(outcome: &CandidateBroadcastOutcome) -> bool {
    matches!(
        outcome,
        CandidateBroadcastOutcome::NodeResponseObserved { .. }
            | CandidateBroadcastOutcome::MayHaveBroadcast { .. }
    )
}

fn outcome_detail(outcome: &CandidateBroadcastOutcome) -> String {
    match outcome {
        CandidateBroadcastOutcome::NotTransmitted { detail, .. }
        | CandidateBroadcastOutcome::MayHaveBroadcast { detail }
        | CandidateBroadcastOutcome::NodeResponseObserved { detail, .. } => detail.clone(),
    }
}
