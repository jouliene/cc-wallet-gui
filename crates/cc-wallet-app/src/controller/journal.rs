use std::time::{Duration, Instant};

use cc_wallet_chain::{
    CandidateBroadcastOutcome, DEFAULT_TTL_SECS, PreparedChainSend, RISK_OVERRIDE_COOLING_SECS,
};
use cc_wallet_domain::{
    DeliveryEvidence, Digest32, EndpointTransactionEvidence, NodeResponseKind, RecordId,
    SendRecord, TerminalOutcome,
};

use super::AppController;
use crate::event::AppEvent;

const ENDPOINT_BATCH_CONFLICT_ERROR: &str = "The endpoint returned conflicting details for the same external message; ordinary sending remains blocked";
const ENDPOINT_STORED_CONFLICT_ERROR: &str = "The endpoint returned conflicting details for a previously matched transaction; ordinary sending remains blocked";

impl AppController {
    pub(super) fn refresh_journal_policy(&mut self) {
        let wallet_id = self.store.name();
        let blocking: Vec<&SendRecord> = self
            .journal
            .records()
            .iter()
            .filter(|record| {
                record.is_blocking() && record.ticket().sender_wallet_id() == wallet_id
            })
            .collect();
        let blocking_count = blocking.len();
        let active_reservations = blocking
            .iter()
            .flat_map(|record| record.reservations().iter().cloned())
            .collect();
        let first_label = blocking
            .first()
            .map(|record| delivery_label(record.latest_evidence()));
        let now = super::now_unix();
        let reconcile_time_floor = blocking
            .iter()
            .filter_map(|record| recent_reconciliation_floor(record.expire_at(), now))
            .min();

        self.state.journal_blocking = !blocking.is_empty();
        self.state.active_reservations = active_reservations;

        if blocking.is_empty() {
            self.session.risk_cooling_started_at = None;
            self.state.risk_override_eligible = false;
            self.state.journal_status.clear();
            self.reset_journal_reconciliation();
            self.session.journal_reconcile_floor = None;
            self.session.journal_reconcile_time_floor = None;
            return;
        }

        self.session.journal_reconcile_time_floor = reconcile_time_floor;
        let has_recent = self.session.journal_reconcile_time_floor.is_some();
        if has_recent && self.journal_reconcile_at.is_none() {
            self.journal_reconcile_at = Some(Instant::now() + self.journal_reconcile_delay);
        } else if !has_recent {
            self.reset_journal_reconciliation();
        }

        let started = self
            .session
            .risk_cooling_started_at
            .get_or_insert_with(Instant::now);
        self.state.risk_override_eligible =
            started.elapsed() >= Duration::from_secs(RISK_OVERRIDE_COOLING_SECS);
        let label = first_label.expect("a blocking record has a delivery label");
        self.state.journal_status = if blocking_count == 1 {
            label.to_owned()
        } else {
            format!("{label} ({blocking_count} unresolved records)")
        };
    }

    pub(super) fn reset_journal_reconciliation(&mut self) {
        self.journal_reconcile_at = None;
        self.journal_reconcile_delay = super::JOURNAL_RECONCILE_MIN_DELAY;
    }

    pub(super) fn capture_live_journal_reconcile_floor(&mut self) {
        if self.journal.records().iter().any(|record| {
            record.is_blocking() && record.ticket().sender_wallet_id() == self.store.name()
        }) {
            return;
        }
        let activity_head = self
            .state
            .activity
            .iter()
            .filter(|event| event.tx_hash.is_some())
            .map(|event| event.lt)
            .max();
        let snapshot_head = self
            .state
            .wallet
            .as_ref()
            .map(|wallet| wallet.last_trans_lt)
            .filter(|lt| *lt != 0);
        self.session.journal_reconcile_floor = activity_head.into_iter().chain(snapshot_head).max();
    }

    pub(super) fn expedite_journal_reconciliation(&mut self) {
        if !self.state.journal_blocking || !self.has_recent_blocking_record() {
            return;
        }
        self.journal_reconcile_delay = super::JOURNAL_RECONCILE_MIN_DELAY;
        self.journal_reconcile_at = Some(Instant::now() + self.journal_reconcile_delay);
    }

    pub(super) fn poll_journal_reconciliation(&mut self, now: Instant) {
        if !self.state.journal_blocking || !self.has_recent_blocking_record() {
            self.reset_journal_reconciliation();
            return;
        }
        if self.load.fetch_in_flight
            || self
                .journal_reconcile_at
                .is_none_or(|retry_at| now < retry_at)
        {
            return;
        }

        self.fetch_transactions(self.subscription_generation);
        self.journal_reconcile_delay = self
            .journal_reconcile_delay
            .saturating_mul(2)
            .min(super::JOURNAL_RECONCILE_MAX_DELAY);
        self.journal_reconcile_at = Some(now + self.journal_reconcile_delay);
    }

    fn has_recent_blocking_record(&self) -> bool {
        let wallet_id = self.store.name();
        let now = super::now_unix();
        self.journal.records().iter().any(|record| {
            record.is_blocking()
                && record.ticket().sender_wallet_id() == wallet_id
                && recent_reconciliation_floor(record.expire_at(), now).is_some()
        })
    }

    pub(super) fn recover_restored_delivery_state(&mut self) -> bool {
        let recoveries: Vec<(RecordId, DeliveryEvidence)> = self
            .journal
            .records()
            .iter()
            .filter_map(|record| match record.latest_evidence() {
                DeliveryEvidence::Prepared => Some((
                    record.ticket().record_id().clone(),
                    DeliveryEvidence::NotBroadcast {
                        route_id: record.prepare_provenance().route_id().to_owned(),
                        detail: "application restarted before any signed-body attempt; runtime-only BOC was discarded"
                            .to_owned(),
                    },
                )),
                DeliveryEvidence::AttemptStarted {
                    attempt_no,
                    route_id,
                } => Some((
                    record.ticket().record_id().clone(),
                    DeliveryEvidence::MayHaveBroadcast {
                        attempt_no: *attempt_no,
                        route_id: route_id.clone(),
                    },
                )),
                DeliveryEvidence::EndpointReportedSuccess { tx }
                | DeliveryEvidence::EndpointReportedFailedOnChain { tx } => Some((
                    record.ticket().record_id().clone(),
                    rpc_history_terminal(tx),
                )),
                _ => None,
            })
            .collect();
        if recoveries.is_empty() {
            self.refresh_journal_policy();
            return true;
        }

        let mut candidate = self.journal.clone();
        for (record_id, evidence) in recoveries {
            if let Err(error) = candidate.append_delivery(&record_id, evidence) {
                self.persistence_failed(format!(
                    "could not normalize restored send state: {error}"
                ));
                self.refresh_journal_policy();
                return false;
            }
        }
        self.journal = candidate;
        let saved = self.persist_journal_barrier();
        self.refresh_journal_policy();
        saved
    }

    pub(super) fn apply_prepared_send(
        &mut self,
        generation: u64,
        expected_ticket_digest: Digest32,
        risk_grant_required: bool,
        prepared: PreparedChainSend,
    ) {
        if generation != self.session_generation {
            return;
        }
        let ticket_digest = match prepared.prepared_record().ticket().digest() {
            Ok(digest) if digest == expected_ticket_digest => digest,
            Ok(_) => {
                self.reject_unbound_prepared(
                    "The chain service returned a Prepared value for a different immutable ticket",
                );
                return;
            }
            Err(error) => {
                self.reject_unbound_prepared(format!(
                    "The chain service returned an unbindable Prepared ticket: {error}"
                ));
                return;
            }
        };
        let risk_consumption = self.pending_risk_consumption.clone().filter(|pending| {
            pending.consumption.new_record_id() == prepared.record_id()
                && pending.consumption.new_ticket_digest() == &ticket_digest
        });
        if risk_grant_required && risk_consumption.is_none() {
            self.reject_unbound_prepared(
                "The duplicate-risk Prepared value no longer matches its durable one-use grant",
            );
            return;
        }
        self.capture_live_journal_reconcile_floor();
        let appended = match risk_consumption.as_ref() {
            Some(pending) => self.journal.append_consumption_and_prepared(
                pending.consumption.clone(),
                prepared.prepared_record().clone(),
            ),
            None => self
                .journal
                .append_prepared(prepared.prepared_record().clone()),
        };
        if let Err(error) = appended {
            self.discard_awaiting_send();
            self.state.sending = false;
            self.state.busy = false;
            self.persistence_failed(format!("could not append Prepared evidence: {error}"));
            return;
        }
        if risk_consumption.is_some() {
            self.pending_risk_consumption = None;
        }
        if !self.persist_journal_barrier() {
            self.discard_awaiting_send();
            self.state.sending = false;
            self.state.busy = false;
            self.refresh_journal_policy();
            return;
        }

        self.session.in_flight_record_id = Some(prepared.record_id().clone());
        self.session.risk_cooling_started_at = Some(Instant::now());
        self.refresh_journal_policy();
        let lt = self.begin_pending_send(prepared.request());
        if let Some(row) = self.state.activity.iter_mut().find(|event| event.lt == lt) {
            row.ext_msg_hash = Some(prepared.external_hash().clone());
        }
        self.state.status =
            "Transfer prepared durably; recording the first delivery attempt…".to_owned();
        self.start_prepared_candidate(generation, prepared, 0);
    }

    fn reject_unbound_prepared(&mut self, error: impl Into<String>) {
        self.pending_risk_consumption = None;
        self.discard_awaiting_send();
        self.state.sending = false;
        self.state.busy = false;
        self.state.set_error(error.into());
        self.refresh_journal_policy();
    }

    pub(super) fn start_prepared_candidate(
        &mut self,
        generation: u64,
        prepared: PreparedChainSend,
        candidate_index: usize,
    ) {
        if generation != self.session_generation {
            return;
        }
        if candidate_index >= prepared.candidate_count() {
            self.finish_locally_not_broadcast(
                prepared.record_id().clone(),
                prepared.route_id().to_owned(),
                "no pre-resolved send route candidate accepted a socket attempt".to_owned(),
            );
            return;
        }
        if message_expired(prepared.expire_at()) {
            self.finish_locally_not_broadcast(
                prepared.record_id().clone(),
                prepared.route_id().to_owned(),
                "signed transfer expired before the next socket call; nothing further was broadcast"
                    .to_owned(),
            );
            return;
        }
        let attempt_no = match u32::try_from(candidate_index + 1) {
            Ok(value) => value,
            Err(_) => {
                self.persistence_failed(
                    "send route has more candidates than the Journal attempt counter can represent",
                );
                return;
            }
        };
        if let Err(error) = self.journal.append_delivery(
            prepared.record_id(),
            DeliveryEvidence::AttemptStarted {
                attempt_no,
                route_id: prepared.route_id().to_owned(),
            },
        ) {
            self.persistence_failed(format!("could not append AttemptStarted evidence: {error}"));
            return;
        }
        if !self.persist_journal_barrier() {
            self.refresh_journal_policy();
            return;
        }
        self.refresh_journal_policy();
        self.arm_awaiting_send_finality();
        self.session.awaiting_replay =
            Some((prepared.record_id().clone(), prepared.created_at_ms()));

        let tx = self.tx.clone();
        let chain = self.chain.clone();
        self.runtime.spawn(async move {
            let outcome = chain
                .broadcast_prepared_candidate(&prepared, candidate_index)
                .await
                .unwrap_or_else(|error| CandidateBroadcastOutcome::MayHaveBroadcast {
                    detail: format!(
                        "delivery call failed after its durable attempt barrier: {error}"
                    ),
                });
            let _ = tx.send(AppEvent::CandidateBroadcastFinished {
                generation,
                prepared,
                candidate_index,
                outcome,
            });
        });
    }

    pub(super) fn apply_candidate_outcome(
        &mut self,
        generation: u64,
        prepared: PreparedChainSend,
        candidate_index: usize,
        outcome: CandidateBroadcastOutcome,
    ) {
        if generation != self.session_generation {
            return;
        }
        let attempt_no = match u32::try_from(candidate_index + 1) {
            Ok(value) => value,
            Err(_) => {
                self.persistence_failed(
                    "candidate result does not fit the Journal attempt counter",
                );
                return;
            }
        };
        let current_attempt = self
            .journal
            .record(prepared.record_id())
            .is_some_and(|record| {
                matches!(
                    record.latest_evidence(),
                    DeliveryEvidence::AttemptStarted {
                        attempt_no: current,
                        route_id,
                    } if *current == attempt_no && route_id == prepared.route_id()
                )
            });
        if !current_attempt {
            self.clear_in_flight_send(prepared.record_id());
            self.refresh_journal_policy();
            return;
        }
        match outcome {
            CandidateBroadcastOutcome::NotTransmitted {
                detail: _,
                retry_next_candidate,
            } if retry_next_candidate && candidate_index + 1 < prepared.candidate_count() => {
                self.state.status =
                    "A route failed before connection; recording the next attempt…".to_owned();
                self.start_prepared_candidate(generation, prepared, candidate_index + 1);
            }
            CandidateBroadcastOutcome::NotTransmitted { detail, .. } => {
                self.finish_locally_not_broadcast(
                    prepared.record_id().clone(),
                    prepared.route_id().to_owned(),
                    detail,
                );
            }
            CandidateBroadcastOutcome::MayHaveBroadcast { detail } => {
                self.finish_blocking_delivery(
                    prepared.record_id(),
                    DeliveryEvidence::MayHaveBroadcast {
                        attempt_no,
                        route_id: prepared.route_id().to_owned(),
                    },
                    format!("Unknown — transmission or outcome unknown. {detail}"),
                );
            }
            CandidateBroadcastOutcome::NodeResponseObserved {
                request_id,
                response,
                detail,
            } => {
                let status = if response == NodeResponseKind::Acknowledged {
                    format!("Unconfirmed — node response observed. {detail}")
                } else {
                    format!("Unknown — response observed, delivery unresolved. {detail}")
                };
                self.finish_blocking_delivery(
                    prepared.record_id(),
                    DeliveryEvidence::NodeResponseObserved {
                        attempt_no,
                        route_id: prepared.route_id().to_owned(),
                        request_id,
                        response,
                    },
                    status,
                );
            }
        }
    }

    fn finish_blocking_delivery(
        &mut self,
        record_id: &RecordId,
        evidence: DeliveryEvidence,
        status: String,
    ) {
        if let Err(error) = self.journal.append_delivery(record_id, evidence) {
            self.persistence_failed(format!("could not append delivery evidence: {error}"));
            return;
        }
        if !self.persist_journal_barrier() {
            self.refresh_journal_policy();
            return;
        }
        if self.clear_in_flight_send(record_id) {
            self.clear_broadcast_send_form();
        }
        self.state.status = status;
        self.state.error = None;
        self.refresh_journal_policy();
        self.expedite_journal_reconciliation();
        self.fetch_transactions(self.subscription_generation);
    }

    fn finish_locally_not_broadcast(
        &mut self,
        record_id: RecordId,
        route_id: String,
        detail: String,
    ) {
        if let Err(error) = self.journal.append_delivery(
            &record_id,
            DeliveryEvidence::NotBroadcast { route_id, detail },
        ) {
            self.persistence_failed(format!("could not append NotBroadcast evidence: {error}"));
            return;
        }
        if !self.persist_journal_barrier() {
            self.refresh_journal_policy();
            return;
        }
        if let Some(record) = self.journal.record(&record_id) {
            let hash = record.ext_msg_hash().clone();
            let removed: Vec<u64> = self
                .state
                .activity
                .iter()
                .filter(|event| {
                    event.tx_hash.is_none() && event.ext_msg_hash.as_ref() == Some(&hash)
                })
                .map(|event| event.lt)
                .collect();
            self.state.activity.retain(|event| {
                !(event.tx_hash.is_none() && event.ext_msg_hash.as_ref() == Some(&hash))
            });
            self.session
                .pending_sends
                .retain(|(lt, _)| !removed.contains(lt));
        }
        self.clear_in_flight_send(&record_id);
        self.state.status = "NotTransmitted — locally proven".to_owned();
        self.state.error = Some(
            "The signed transfer was locally proven not to have reached any socket; it is safe to prepare a new ticket."
                .to_owned(),
        );
        self.refresh_journal_policy();
    }

    pub(super) fn reconcile_endpoint_observations(
        &mut self,
        generation: u64,
        observations: Vec<EndpointTransactionEvidence>,
    ) -> bool {
        if generation != self.subscription_generation {
            return false;
        }
        if observations.iter().enumerate().any(|(index, left)| {
            observations[index + 1..].iter().any(|right| {
                same_endpoint_message(left, right) && !same_endpoint_transaction(left, right)
            })
        }) {
            self.state.set_error(ENDPOINT_BATCH_CONFLICT_ERROR);
            self.refresh_journal_policy();
            return false;
        }
        let mut candidate_journal = self.journal.clone();
        let mut changed = false;
        let mut accepted_match = false;
        let mut last_observation_status = None;
        let mut matched_records = Vec::new();
        for observation in observations {
            let record_id = candidate_journal
                .records()
                .iter()
                .find(|record| observation_matches_record(record, &observation))
                .map(|record| record.ticket().record_id().clone());
            let Some(record_id) = record_id else {
                continue;
            };

            let status = if observation.success() {
                "Success — confirmed in RPC transaction history"
            } else {
                "Failed on-chain — confirmed in RPC transaction history"
            };
            let terminal_evidence = rpc_history_terminal(&observation);
            let latest = candidate_journal
                .record(&record_id)
                .expect("a matched Journal record remains present")
                .latest_evidence()
                .clone();

            match latest {
                DeliveryEvidence::EndpointReportedSuccess { tx }
                | DeliveryEvidence::EndpointReportedFailedOnChain { tx } => {
                    if !same_endpoint_transaction(&tx, &observation) {
                        self.state.set_error(ENDPOINT_STORED_CONFLICT_ERROR);
                        self.refresh_journal_policy();
                        return false;
                    }
                    if let Err(error) =
                        candidate_journal.append_delivery(&record_id, terminal_evidence)
                    {
                        self.persistence_failed(format!(
                            "could not finalize the RPC-confirmed transaction: {error}"
                        ));
                        self.refresh_journal_policy();
                        return false;
                    }
                    changed = true;
                    accepted_match = true;
                }
                _ => {
                    let endpoint_evidence = if observation.success() {
                        DeliveryEvidence::EndpointReportedSuccess { tx: observation }
                    } else {
                        DeliveryEvidence::EndpointReportedFailedOnChain { tx: observation }
                    };
                    if let Err(error) =
                        candidate_journal.append_delivery(&record_id, endpoint_evidence)
                    {
                        self.persistence_failed(format!(
                            "could not append endpoint-qualified transaction evidence: {error}"
                        ));
                        self.refresh_journal_policy();
                        return false;
                    }
                    if let Err(error) =
                        candidate_journal.append_delivery(&record_id, terminal_evidence)
                    {
                        self.persistence_failed(format!(
                            "could not finalize the RPC-confirmed transaction: {error}"
                        ));
                        self.refresh_journal_policy();
                        return false;
                    }
                    changed = true;
                    accepted_match = true;
                }
            }
            last_observation_status = Some(status);
            matched_records.push(record_id);
        }
        if changed {
            self.journal = candidate_journal;
        }
        if changed && !self.persist_journal_barrier() {
            self.invalidate_pending_risk_after_journal_change();
            self.refresh_journal_policy();
            return false;
        }
        if changed {
            self.invalidate_pending_risk_after_journal_change();
        }
        if accepted_match {
            if matches!(
                self.state.error.as_deref(),
                Some(ENDPOINT_BATCH_CONFLICT_ERROR | ENDPOINT_STORED_CONFLICT_ERROR)
            ) {
                self.state.clear_error();
            }
            let resolved_in_flight = matched_records
                .iter()
                .any(|record_id| self.clear_in_flight_send(record_id));
            if resolved_in_flight {
                self.clear_broadcast_send_form();
            }
            if let Some(status) = last_observation_status
                && (resolved_in_flight || (!self.state.sending && !self.state.busy))
            {
                self.state.status = status.to_owned();
            }
        }
        self.refresh_journal_policy();
        accepted_match
    }

    /// Stops the spinner the moment the stream says the account moved.
    ///
    /// One transfer of ours is on the wire and the chain has just said this
    /// account changed. That is the news the person is waiting for, and it is
    /// the earliest there is — anything else the wallet could ask costs another
    /// round trip, which is a delay they would sit and watch for no gain they
    /// can see. So the row settles here, on the frame itself.
    ///
    /// It is not *proof* the movement is ours; only the replay guard is, and
    /// that follows a beat later and is what the Journal waits for before it
    /// lets another transfer go out. The display leads, the ledger confirms.
    pub(super) fn confirm_in_flight_from_announcement(&mut self) {
        let Some((record_id, _)) = self.session.awaiting_replay.as_ref() else {
            return;
        };
        let Some(record) = self.journal.record(record_id) else {
            return;
        };
        if !record.is_blocking() {
            return;
        }
        let ext_msg_hash = record.ext_msg_hash().clone();
        self.settle_optimistic_row(&ext_msg_hash);
    }

    /// The same news, for everything else of ours on the wire.
    pub(super) fn end_waits_on_announcement(&mut self) {
        self.confirm_in_flight_from_announcement();
        self.end_external_waits();
    }

    /// Confirms an in-flight transfer from the wallet's own replay guard.
    ///
    /// The account state carries the timestamp the wallet contract stored the
    /// last time it executed one of our messages, and the node serves that as
    /// soon as it applies the block — measurably sooner than the same
    /// transaction reaches its transaction index, and on a slow index by
    /// several seconds. If the guard has reached the timestamp our signed
    /// message carries, that message ran and committed: an aborted transaction
    /// rolls the storage back, so the guard could not have moved.
    ///
    /// That answers the same question the transaction listing is asked, only
    /// earlier, so it is terminal evidence and the record stops blocking. The
    /// listing is still wanted — for the hash, the fee and the effects — but no
    /// longer for telling the person in front of the wallet that their transfer
    /// went through.
    pub(super) fn reconcile_from_replay_guard(&mut self) {
        let Some((record_id, sent_ms)) = self.session.awaiting_replay.clone() else {
            return;
        };
        let Some(record) = self.journal.record(&record_id) else {
            self.session.awaiting_replay = None;
            return;
        };
        if !record.is_blocking() {
            self.session.awaiting_replay = None;
            return;
        }
        let Some(snapshot) = self.state.wallet.as_ref() else {
            return;
        };
        // A test-only prepared send carries no timestamp, and a snapshot that
        // is not our wallet code carries no guard. Neither can confirm.
        if sent_ms == 0 || snapshot.last_message_ms() < sent_ms {
            return;
        }
        let account_lt = snapshot.last_trans_lt;
        let ext_msg_hash = record.ext_msg_hash().clone();
        let proof_ref = format!(
            "ever-wallet-replay:{sent_ms}@{}#{account_lt}",
            record.ticket().endpoint_identity()
        );
        if let Err(error) = self.journal.append_delivery(
            &record_id,
            DeliveryEvidence::VerifiedTerminal {
                outcome: TerminalOutcome::Success,
                proof_ref,
            },
        ) {
            self.persistence_failed(format!(
                "could not record the wallet's own confirmation: {error}"
            ));
            return;
        }
        self.session.awaiting_replay = None;
        let persisted = self.persist_journal_barrier();
        self.invalidate_pending_risk_after_journal_change();
        if !persisted {
            self.refresh_journal_policy();
            return;
        }
        if self.clear_in_flight_send(&record_id) {
            self.clear_broadcast_send_form();
        }
        self.settle_optimistic_row(&ext_msg_hash);
        self.state.status = "Success — the wallet's own replay guard advanced".to_owned();
        self.state.error = None;
        self.refresh_journal_policy();
    }

    fn clear_in_flight_send(&mut self, record_id: &RecordId) -> bool {
        if self.session.in_flight_record_id.as_ref() != Some(record_id) {
            return false;
        }
        self.session.in_flight_record_id = None;
        self.state.sending = false;
        self.state.busy = false;
        self.session.awaiting_send_lt = None;
        true
    }

    fn clear_broadcast_send_form(&mut self) {
        self.clear_pending_max();
        self.max_filled = false;
        self.session.fee_reestimate_at = None;
        self.state.send_form.destination.clear();
        self.state.send_form.amount.clear();
        // A note belongs to the transfer that carried it. Leaving it behind
        // attaches it to whatever is sent next.
        self.state.send_form.comment.clear();
        self.clear_chat_draft_after_send();
        self.state.reset_recipient_status();
        self.state.clear_send_form_error();
    }

    fn invalidate_pending_risk_after_journal_change(&mut self) {
        let pending_risk = self.pending_risk_reconciliation
            || self.pending_risk_context.is_some()
            || self.pending_risk_review.is_some()
            || self.pending_risk_consumption.is_some();
        if !pending_risk {
            return;
        }
        let context_load_was_busy =
            self.pending_risk_reconciliation || self.pending_risk_context.is_some();
        if self.state.key_busy && self.state.auth.purpose == crate::state::AuthPurpose::Send {
            self.key_generation = self.key_generation.wrapping_add(1);
            self.state.key_busy = false;
        }
        self.cancel_risk_override();
        if context_load_was_busy && !self.state.sending {
            self.state.busy = false;
        }
    }
}

pub(super) fn same_endpoint_transaction(
    left: &EndpointTransactionEvidence,
    right: &EndpointTransactionEvidence,
) -> bool {
    same_endpoint_message(left, right)
        && left.tx_hash() == right.tx_hash()
        && left.lt() == right.lt()
        && left.success() == right.success()
        && left.exit_code() == right.exit_code()
        && left.effects() == right.effects()
}

pub(super) fn observation_matches_record(
    record: &SendRecord,
    observation: &EndpointTransactionEvidence,
) -> bool {
    record.is_blocking()
        && record.ext_msg_hash() == observation.ext_msg_hash()
        && record.ticket().sender_address() == observation.sender_address()
        && record.ticket().endpoint_identity() == observation.source_endpoint()
}

pub(super) fn same_endpoint_message(
    left: &EndpointTransactionEvidence,
    right: &EndpointTransactionEvidence,
) -> bool {
    left.sender_address() == right.sender_address() && left.ext_msg_hash() == right.ext_msg_hash()
}

fn message_expired(expire_at: u32) -> bool {
    super::now_unix() >= u64::from(expire_at)
}

fn recent_reconciliation_floor(expire_at: u32, now: u64) -> Option<u64> {
    let sent_at = u64::from(expire_at.saturating_sub(DEFAULT_TTL_SECS));
    let expire_at = u64::from(expire_at);
    let grace = super::JOURNAL_RECONCILE_POST_EXPIRY_SECS;
    if sent_at > now.saturating_add(grace) || now > expire_at.saturating_add(grace) {
        return None;
    }
    Some(sent_at.saturating_sub(grace))
}

fn delivery_label(evidence: &DeliveryEvidence) -> &'static str {
    match evidence {
        DeliveryEvidence::Prepared => "Unconfirmed — prepared/recovery pending",
        DeliveryEvidence::AttemptStarted { .. } | DeliveryEvidence::MayHaveBroadcast { .. } => {
            "Unknown — transmission or outcome unknown"
        }
        DeliveryEvidence::NodeResponseObserved {
            response: NodeResponseKind::Acknowledged,
            ..
        } => "Unconfirmed — node response observed",
        DeliveryEvidence::NodeResponseObserved { .. } => {
            "Unknown — response observed, delivery unresolved"
        }
        DeliveryEvidence::EndpointReportedSuccess { .. } => {
            "Success — confirmed in RPC transaction history"
        }
        DeliveryEvidence::EndpointReportedFailedOnChain { .. } => {
            "FailedOnChain — confirmed in RPC transaction history"
        }
        DeliveryEvidence::VerifiedTerminal {
            outcome: TerminalOutcome::Success,
            proof_ref,
        } if proof_ref.starts_with("rpc-history:") => {
            "Success — confirmed in RPC transaction history"
        }
        DeliveryEvidence::VerifiedTerminal {
            outcome: TerminalOutcome::FailedOnChain,
            proof_ref,
        } if proof_ref.starts_with("rpc-history:") => {
            "FailedOnChain — confirmed in RPC transaction history"
        }
        DeliveryEvidence::VerifiedTerminal {
            outcome: TerminalOutcome::Success,
            proof_ref,
        } if proof_ref.starts_with("ever-wallet-replay:") => {
            "Success — the wallet's own replay guard advanced"
        }
        DeliveryEvidence::VerifiedTerminal {
            outcome: TerminalOutcome::Success,
            ..
        } => "Success — independently verified terminal evidence",
        DeliveryEvidence::VerifiedTerminal {
            outcome: TerminalOutcome::FailedOnChain,
            ..
        } => "FailedOnChain — independently verified terminal evidence",
        DeliveryEvidence::NotBroadcast { .. } => "NotTransmitted — locally proven",
    }
}

fn rpc_history_terminal(tx: &EndpointTransactionEvidence) -> DeliveryEvidence {
    DeliveryEvidence::VerifiedTerminal {
        outcome: if tx.success() {
            TerminalOutcome::Success
        } else {
            TerminalOutcome::FailedOnChain
        },
        proof_ref: format!("rpc-history:{}", tx.tx_hash().to_hex()),
    }
}

#[cfg(test)]
mod label_tests {
    use super::*;

    const ADDRESS: &str = "0:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn endpoint_tx(success: bool) -> EndpointTransactionEvidence {
        EndpointTransactionEvidence::new(
            "https://rpc.example/".to_owned(),
            "request-1".to_owned(),
            ADDRESS.to_owned(),
            Digest32::from_bytes([0x11; 32]),
            Digest32::from_bytes([0x22; 32]),
            7,
            success,
            if success { 0 } else { 37 },
            Vec::new(),
        )
        .unwrap()
    }

    #[test]
    fn every_delivery_evidence_variant_has_the_exact_qualified_ui_label() {
        let cases = [
            (
                DeliveryEvidence::Prepared,
                "Unconfirmed — prepared/recovery pending",
            ),
            (
                DeliveryEvidence::AttemptStarted {
                    attempt_no: 1,
                    route_id: "route".to_owned(),
                },
                "Unknown — transmission or outcome unknown",
            ),
            (
                DeliveryEvidence::MayHaveBroadcast {
                    attempt_no: 1,
                    route_id: "route".to_owned(),
                },
                "Unknown — transmission or outcome unknown",
            ),
            (
                DeliveryEvidence::NodeResponseObserved {
                    attempt_no: 1,
                    route_id: "route".to_owned(),
                    request_id: "request".to_owned(),
                    response: NodeResponseKind::Acknowledged,
                },
                "Unconfirmed — node response observed",
            ),
            (
                DeliveryEvidence::NodeResponseObserved {
                    attempt_no: 1,
                    route_id: "route".to_owned(),
                    request_id: "request".to_owned(),
                    response: NodeResponseKind::Rejected,
                },
                "Unknown — response observed, delivery unresolved",
            ),
            (
                DeliveryEvidence::NodeResponseObserved {
                    attempt_no: 1,
                    route_id: "route".to_owned(),
                    request_id: "request".to_owned(),
                    response: NodeResponseKind::TransportError,
                },
                "Unknown — response observed, delivery unresolved",
            ),
            (
                DeliveryEvidence::NodeResponseObserved {
                    attempt_no: 1,
                    route_id: "route".to_owned(),
                    request_id: "request".to_owned(),
                    response: NodeResponseKind::Malformed,
                },
                "Unknown — response observed, delivery unresolved",
            ),
            (
                DeliveryEvidence::EndpointReportedSuccess {
                    tx: endpoint_tx(true),
                },
                "Success — confirmed in RPC transaction history",
            ),
            (
                DeliveryEvidence::EndpointReportedFailedOnChain {
                    tx: endpoint_tx(false),
                },
                "FailedOnChain — confirmed in RPC transaction history",
            ),
            (
                DeliveryEvidence::VerifiedTerminal {
                    outcome: TerminalOutcome::Success,
                    proof_ref: "proof".to_owned(),
                },
                "Success — independently verified terminal evidence",
            ),
            (
                DeliveryEvidence::VerifiedTerminal {
                    outcome: TerminalOutcome::Success,
                    proof_ref: "rpc-history:endpoint#7".to_owned(),
                },
                "Success — confirmed in RPC transaction history",
            ),
            (
                DeliveryEvidence::VerifiedTerminal {
                    outcome: TerminalOutcome::Success,
                    proof_ref: "ever-wallet-replay:1700000000000@endpoint#7".to_owned(),
                },
                "Success — the wallet's own replay guard advanced",
            ),
            (
                DeliveryEvidence::VerifiedTerminal {
                    outcome: TerminalOutcome::FailedOnChain,
                    proof_ref: "proof".to_owned(),
                },
                "FailedOnChain — independently verified terminal evidence",
            ),
            (
                DeliveryEvidence::NotBroadcast {
                    route_id: "route".to_owned(),
                    detail: "local proof".to_owned(),
                },
                "NotTransmitted — locally proven",
            ),
        ];

        for (evidence, expected) in cases {
            assert_eq!(delivery_label(&evidence), expected);
        }
    }

    #[test]
    fn automatic_reconciliation_is_bounded_around_a_plausible_message_lifetime() {
        let now = 1_700_000_000u64;
        let grace = super::super::JOURNAL_RECONCILE_POST_EXPIRY_SECS;
        let fresh_expiry =
            u32::try_from(now + u64::from(DEFAULT_TTL_SECS)).expect("test time fits u32");
        assert_eq!(
            recent_reconciliation_floor(fresh_expiry, now),
            Some(now.saturating_sub(grace))
        );

        let just_too_old = u32::try_from(now - grace - 1).expect("test time fits u32");
        assert_eq!(recent_reconciliation_floor(just_too_old, now), None);
        assert_eq!(recent_reconciliation_floor(u32::MAX, now), None);
    }
}
