use std::time::{Duration, Instant};

use cc_wallet_domain::{EndpointTransactionEvidence, WalletSnapshot};

use super::journal::{same_endpoint_message, same_endpoint_transaction};
use super::{
    AppController, HistoryReconciliationScan, MAX_AUTOMATIC_HISTORY_CONTINUATIONS,
    SUBSCRIPTION_BACKOFF_MAX_SECS, SUBSCRIPTION_BACKOFF_MIN_SECS,
};
use crate::event::AppEvent;
use crate::state::{AppTab, LiveStatus};

impl AppController {
    fn apply_wallet_snapshot(&mut self, snapshot: WalletSnapshot, manual: bool) {
        self.state.snapshot_refresh_error = None;
        self.state.error = None;
        self.state.status = if snapshot.observed_network_time().is_some() {
            "Wallet updated".to_owned()
        } else {
            "Network time unavailable — signing is disabled".to_owned()
        };
        let address = snapshot.address.clone();
        self.state
            .derived_wallet_address
            .clone_from(&snapshot.address);
        self.state.wallet = Some(snapshot);
        self.refresh_journal_policy();
        if manual {
            self.state.selected_tab = AppTab::Wallet;
        }
        self.ensure_subscription(address);
        if manual {
            self.fetch_transactions(self.subscription_generation);
        }
        if !self.state.sending && self.pending_authorization.is_none() {
            self.estimate_fee();
        }
    }

    fn apply_wallet_load_failed(&mut self, error: String) {
        self.state.snapshot_refresh_error = Some(error.clone());
        self.state.set_error(error);
        if self.state.wallet.is_none()
            && let Some(address) = self.state.wallet_address().map(str::to_owned)
        {
            self.ensure_subscription(address);
        }
    }

    pub(super) fn apply_event(&mut self, event: AppEvent) {
        match event {
            AppEvent::WalletLoaded {
                generation,
                request_id,
                snapshot,
            } => {
                if self.load.wallet_load_id != Some(request_id) {
                    return;
                }
                self.load.wallet_load_id = None;
                self.state.busy = false;
                if generation == self.subscription_generation {
                    if !self.verify_network_id(snapshot.global_id) {
                        self.state.live_status = LiveStatus::Offline;
                        self.state.subscription_status =
                            "endpoint serves a different network".to_owned();
                        return;
                    }
                    self.apply_wallet_snapshot(snapshot, true);
                }
            }
            AppEvent::WalletAutoLoaded {
                generation,
                request_id,
                snapshot,
            } => {
                if self.load.wallet_auto_refresh_id != Some(request_id) {
                    return;
                }
                self.load.wallet_auto_refresh_id = None;
                self.state.auto_refreshing = false;
                let refresh_again = std::mem::take(&mut self.load.wallet_auto_refresh_again);
                if generation == self.subscription_generation {
                    if !self.verify_network_id(snapshot.global_id) {
                        self.state.live_status = LiveStatus::Offline;
                        self.state.subscription_status =
                            "endpoint serves a different network".to_owned();
                        return;
                    }
                    self.apply_wallet_snapshot(snapshot, false);
                }
                if refresh_again && self.state.phase == crate::state::AppPhase::Unlocked {
                    self.auto_refresh_wallet(self.subscription_generation);
                }
            }
            AppEvent::WalletAutoLoadFailed {
                generation,
                request_id,
                error,
            } => {
                if self.load.wallet_auto_refresh_id != Some(request_id) {
                    return;
                }
                self.load.wallet_auto_refresh_id = None;
                self.state.auto_refreshing = false;
                let refresh_again = std::mem::take(&mut self.load.wallet_auto_refresh_again);
                if generation == self.subscription_generation {
                    self.apply_wallet_load_failed(error);
                }
                if refresh_again && self.state.phase == crate::state::AppPhase::Unlocked {
                    self.auto_refresh_wallet(self.subscription_generation);
                }
            }
            AppEvent::WalletLoadFailed {
                generation,
                request_id,
                error,
            } => {
                if self.load.wallet_load_id != Some(request_id) {
                    return;
                }
                self.load.wallet_load_id = None;
                self.state.busy = false;
                if generation == self.subscription_generation {
                    self.apply_wallet_load_failed(error);
                }
            }
            AppEvent::SubscriptionReady { generation, uuid } => {
                if generation == self.subscription_generation {
                    self.state.live_status = LiveStatus::Live;
                    self.state.subscription_status = format!("subscribed {uuid}");
                    self.state.error = None;
                    self.subscription_backoff_secs = SUBSCRIPTION_BACKOFF_MIN_SECS;
                    self.subscription_retry_at = None;
                    if self.state.journal_blocking
                        || self.load.history_reconciliation_scan.is_some()
                        || self.state.history_incomplete
                        || self.session.history_has_gap
                    {
                        self.expedite_journal_reconciliation();
                        self.fetch_transactions(generation);
                    }
                    if self.state.wallet.is_none() || self.state.snapshot_refresh_error.is_some() {
                        self.auto_refresh_wallet(generation);
                    }
                }
            }
            AppEvent::SubscriptionUpdate { generation, update } => {
                if generation == self.subscription_generation {
                    self.state.subscription_status = "account update received".to_owned();
                    self.record_account_announcement(update.max_lt);
                    self.expedite_journal_reconciliation();
                    self.expedite_storage_settlement();
                    self.fetch_transactions(generation);
                    self.auto_refresh_wallet(generation);
                }
            }
            AppEvent::SubscriptionFailed { generation, error } => {
                if generation == self.subscription_generation {
                    self.subscription_task = None;
                    self.subscription_key = None;
                    self.state.live_status = LiveStatus::Connecting;
                    self.state.subscription_status = format!("reconnecting ({error})");
                    let backoff = self.subscription_backoff_secs;
                    self.subscription_retry_at =
                        Some(Instant::now() + Duration::from_secs(backoff));
                    self.subscription_backoff_secs =
                        (backoff.saturating_mul(2)).min(SUBSCRIPTION_BACKOFF_MAX_SECS);
                }
            }
            AppEvent::SendPrepared {
                generation,
                expected_ticket_digest,
                risk_grant_required,
                prepared,
            } => self.apply_prepared_send(
                generation,
                expected_ticket_digest,
                risk_grant_required,
                prepared,
            ),
            AppEvent::CandidateBroadcastFinished {
                generation,
                prepared,
                candidate_index,
                outcome,
            } => self.apply_candidate_outcome(generation, prepared, candidate_index, outcome),
            AppEvent::FeeEstimated {
                generation,
                seq,
                estimate,
            } => {
                if seq == self.fee_request_seq {
                    self.state.fee_estimating = false;
                    self.state.fee_estimate_stale = false;
                    if generation == self.subscription_generation {
                        self.state.fee_estimate = Some(estimate);
                    }
                    self.start_queued_max_fee_estimate();
                }
            }
            AppEvent::MaxFeeEstimated {
                generation,
                seq,
                estimate,
            } => {
                if seq == self.fee_request_seq {
                    self.state.fee_estimating = false;
                    self.state.fee_estimate_stale = false;
                    let owns_refinement = self.pending_max_seq == Some(seq);
                    if generation == self.subscription_generation && owns_refinement {
                        let form_frozen = self.pending_authorization.is_some()
                            || self.pending_risk_review.is_some()
                            || self.pending_risk_reconciliation
                            || self.state.sending;
                        if !form_frozen {
                            let current_balance = self.state.wallet.as_ref().and_then(|wallet| {
                                wallet
                                    .balance_for(cc_wallet_domain::AssetId::Native)
                                    .native_units()
                            });
                            if current_balance != self.pending_max_balance {
                                self.clear_pending_max();
                                self.set_max_amount();
                                return;
                            }
                            self.state.fee_estimate = Some(estimate);
                            if let Some(balance) = current_balance {
                                let spendable = cc_wallet_domain::max_native_spendable(
                                    balance,
                                    estimate.fee_nanos,
                                );
                                self.state.send_form.amount =
                                    cc_wallet_domain::format_native_fixed9(spendable)
                                        .expect("a native snapshot amount has fixed-9 formatting");
                            }
                        }
                    }
                    if owns_refinement {
                        self.clear_pending_max();
                    } else {
                        self.start_queued_max_fee_estimate();
                    }
                }
            }
            AppEvent::FeeEstimateFailed { generation, seq } => {
                if seq == self.fee_request_seq {
                    self.state.fee_estimating = false;
                    self.state.fee_estimate_stale = false;
                    if generation == self.subscription_generation {
                        self.state.fee_estimate = None;
                    }
                    if self.pending_max_seq == Some(seq) {
                        self.clear_pending_max();
                    } else {
                        self.start_queued_max_fee_estimate();
                    }
                }
            }
            AppEvent::SendFailed { generation, error } => {
                if generation != self.session_generation {
                    return;
                }
                self.state.busy = false;
                self.state.sending = false;
                self.pending_risk_consumption = None;
                match error {
                    cc_wallet_chain::ChainError::InsufficientFunds(message) => {
                        self.state.set_send_form_error(message);
                    }
                    error => self.state.set_error(error.to_string()),
                }
                self.discard_awaiting_send();
            }
            AppEvent::DestinationChecked {
                generation,
                seq,
                address,
                status,
            } => {
                if generation == self.subscription_generation
                    && seq == self.dest_check_seq
                    && self.state.send_form.destination.trim() == address
                {
                    self.state.recipient_check = match status {
                        Some(status) => {
                            if self.state.auth.error == super::seed_auth::GATE_MSG_PENDING
                                || self.state.auth.error == super::seed_auth::GATE_MSG_FAILED
                            {
                                self.state.auth.error.clear();
                            }
                            crate::state::RecipientCheck::Known(status)
                        }
                        None => {
                            self.session.dest_check_retry_at =
                                Some(crate::state::Deadline::after(super::DEST_CHECK_RETRY_DELAY));
                            crate::state::RecipientCheck::Failed
                        }
                    };
                }
            }
            AppEvent::ValidatorClockLoaded {
                generation,
                seq,
                cycle,
            } => {
                if generation == self.subscription_generation
                    && seq == self.clock_fetch_seq
                    && let Some(cycle) = cycle
                {
                    self.state.validator_cycle = Some(cycle);
                }
            }
            AppEvent::NetworkStatsLoaded {
                generation,
                seq,
                stats,
            } => {
                if generation == self.subscription_generation
                    && seq == self.stats_fetch_seq
                    && let Some(stats) = stats
                {
                    self.state.network_stats = Some(stats);
                }
            }
            AppEvent::AccountInspected {
                generation,
                seq,
                address,
                result,
            } => {
                if seq != self.account_fetch_seq || address != self.state.inspected_address {
                    return;
                }
                if generation != self.subscription_generation {
                    self.inspect_account(address);
                    return;
                }
                self.state.account_loading = false;
                match result {
                    Ok(detail) => {
                        self.state.account_detail = Some(detail);
                        self.state.account_error = None;
                    }
                    Err(error) => {
                        self.state.account_detail = None;
                        self.state.account_error = Some(error);
                    }
                }
            }
            AppEvent::AccountTransactionsLoaded {
                generation,
                seq,
                address,
                result,
            } => {
                if seq != self.account_fetch_seq || address != self.state.inspected_address {
                    return;
                }
                if generation != self.subscription_generation {
                    self.inspect_account(address);
                    return;
                }
                self.state.account_txs_loading = false;
                match result {
                    Ok(page) => {
                        self.state.account_txs = page.rows;
                        self.state.account_txs_skipped = page.skipped;
                        self.state.account_txs_error = None;
                    }
                    Err(error) => {
                        self.state.account_txs.clear();
                        self.state.account_txs_skipped = 0;
                        self.state.account_txs_error = Some(error);
                    }
                }
                if let Some(hash) = self.pending_explorer_trace.take() {
                    self.trace_transaction(hash);
                }
            }
            AppEvent::TraceLoaded {
                generation,
                seq,
                transaction_hash,
                result,
            } => {
                if seq != self.trace_fetch_seq || transaction_hash != self.state.trace_hash {
                    return;
                }
                if generation != self.subscription_generation {
                    self.trace_transaction(transaction_hash);
                    return;
                }
                self.state.trace_loading = false;
                match result {
                    Ok(trace) => {
                        self.remember_trace(&transaction_hash, &trace);
                        self.state.trace = Some(trace);
                        self.state.trace_error = None;
                    }
                    Err(error) => {
                        self.state.trace = None;
                        self.state.trace_error = Some(error);
                    }
                }
            }
            AppEvent::EndpointHistoryScanned {
                generation,
                fetch_id,
                head_refresh_only,
                observations,
                scan_start_before_lt,
                scan_stop_at,
                scan_age_cutoff,
                continuation_before_lt,
                deepest_lt,
                gap,
            } => {
                if (fetch_id != 0 && self.load.fetch_in_flight_id != Some(fetch_id))
                    || generation != self.subscription_generation
                {
                    return;
                }
                if gap {
                    self.load.history_reconciliation_scan = None;
                    return;
                }
                let relevant = observations
                    .into_iter()
                    .filter(|observation| {
                        self.journal.records().iter().any(|record| {
                            super::journal::observation_matches_record(record, observation)
                        })
                    })
                    .collect::<Vec<_>>();
                if head_refresh_only {
                    if let Some(next_before_lt) = continuation_before_lt {
                        let original = self.load.history_reconciliation_scan.take();
                        let (stop_at, age_cutoff, combined_deepest_lt, mut observations) =
                            match original {
                                Some(scan) => (
                                    scan.stop_at,
                                    scan.age_cutoff,
                                    match (scan.deepest_lt, deepest_lt) {
                                        (Some(left), Some(right)) => Some(left.min(right)),
                                        (left, right) => left.or(right),
                                    },
                                    scan.observations,
                                ),
                                None => (scan_stop_at, scan_age_cutoff, deepest_lt, Vec::new()),
                            };
                        extend_scan_observations(&mut observations, relevant);
                        self.load.history_reconciliation_scan = Some(HistoryReconciliationScan {
                            next_before_lt,
                            stop_at,
                            age_cutoff,
                            deepest_lt: combined_deepest_lt,
                            observations,
                            automatic_continuations_remaining: MAX_AUTOMATIC_HISTORY_CONTINUATIONS,
                        });
                    } else if let Some(scan) = self.load.history_reconciliation_scan.as_mut() {
                        extend_scan_observations(&mut scan.observations, relevant);
                    }
                    return;
                }
                if let Some(next_before_lt) = continuation_before_lt {
                    match self.load.history_reconciliation_scan.as_mut() {
                        Some(scan)
                            if scan.stop_at == scan_stop_at
                                && scan.age_cutoff == scan_age_cutoff
                                && scan_start_before_lt == Some(scan.next_before_lt) =>
                        {
                            scan.next_before_lt = next_before_lt;
                            if let Some(deepest_lt) = deepest_lt {
                                scan.deepest_lt = Some(
                                    scan.deepest_lt
                                        .map_or(deepest_lt, |old| old.min(deepest_lt)),
                                );
                            }
                            extend_scan_observations(&mut scan.observations, relevant);
                        }
                        None if scan_start_before_lt.is_none() => {
                            let mut observations = Vec::new();
                            extend_scan_observations(&mut observations, relevant);
                            self.load.history_reconciliation_scan =
                                Some(HistoryReconciliationScan {
                                    next_before_lt,
                                    stop_at: scan_stop_at,
                                    age_cutoff: scan_age_cutoff,
                                    deepest_lt,
                                    observations,
                                    automatic_continuations_remaining:
                                        MAX_AUTOMATIC_HISTORY_CONTINUATIONS,
                                });
                        }
                        _ => {
                            self.load.history_reconciliation_scan = None;
                        }
                    }
                } else {
                    let completed_scan = match self.load.history_reconciliation_scan.as_ref() {
                        Some(scan)
                            if scan.stop_at == scan_stop_at
                                && scan.age_cutoff == scan_age_cutoff
                                && scan_start_before_lt == Some(scan.next_before_lt) =>
                        {
                            self.load.history_reconciliation_scan.take()
                        }
                        None if scan_start_before_lt.is_none() => None,
                        _ => return,
                    };
                    let completed_floor = completed_scan
                        .as_ref()
                        .and_then(|scan| scan.deepest_lt)
                        .into_iter()
                        .chain(deepest_lt)
                        .min();
                    if let Some(floor) = completed_floor {
                        self.session.history_synced_floor = Some(
                            self.session
                                .history_synced_floor
                                .map_or(floor, |old| old.min(floor)),
                        );
                    }
                    let mut complete_observations =
                        completed_scan.map_or_else(Vec::new, |scan| scan.observations);
                    extend_scan_observations(&mut complete_observations, relevant);
                    if !complete_observations.is_empty() {
                        let accepted =
                            self.reconcile_endpoint_observations(generation, complete_observations);
                        if accepted && fetch_id != 0 {
                            self.auto_refresh_wallet(generation);
                        }
                    }
                }
            }
            AppEvent::TransactionsLoaded {
                generation,
                fetch_id,
                head_refresh_only,
                events,
                integrity_error,
                incomplete,
                gap,
                deepest_lt,
            } => {
                if fetch_id != 0 && self.load.fetch_in_flight_id != Some(fetch_id) {
                    return;
                }
                self.load.fetch_in_flight = false;
                self.load.fetch_in_flight_id = None;
                if generation != self.subscription_generation {
                    if self.pending_risk_reconciliation && !self.load.fetch_again {
                        self.abort_risk_review(
                            "The live connection restarted during the duplicate-risk pre-check; start the review again",
                        );
                    }
                    if std::mem::take(&mut self.load.fetch_again) {
                        if self.load.history_reconciliation_scan.is_some() {
                            self.load.fetch_head_after_history_scan = true;
                            self.continue_history_scan(self.subscription_generation);
                        } else {
                            self.fetch_transactions(self.subscription_generation);
                        }
                    }
                    return;
                }
                self.merge_activity(events);
                let retained_scan_pending = !gap && self.load.history_reconciliation_scan.is_some();
                self.state.history_incomplete = incomplete || retained_scan_pending;
                if let Some(error) = integrity_error {
                    let message = format!(
                        "Transaction history failed validation; signing is blocked until a complete valid refresh: {error}"
                    );
                    self.state.history_integrity_error = Some(message.clone());
                    self.state.set_error(message);
                } else if !self.state.history_incomplete && !gap {
                    self.state.history_integrity_error = None;
                }
                if gap {
                    self.load.history_reconciliation_scan = None;
                    self.session.history_has_gap = true;
                } else if !self.state.history_incomplete {
                    self.state.history_corrupt = false;
                    self.session.history_has_gap = false;
                    if let Some(floor) = deepest_lt {
                        self.session.history_synced_floor = Some(
                            self.session
                                .history_synced_floor
                                .map_or(floor, |old| old.min(floor)),
                        );
                    }
                }
                let scan_pending = self.load.history_reconciliation_scan.is_some();
                let queued_during_scan = scan_pending && std::mem::take(&mut self.load.fetch_again);
                if queued_during_scan {
                    self.load.fetch_head_after_history_scan = true;
                }
                let auto_continue = scan_pending
                    && self
                        .load
                        .history_reconciliation_scan
                        .as_mut()
                        .is_some_and(|scan| {
                            if scan.automatic_continuations_remaining == 0 {
                                false
                            } else {
                                scan.automatic_continuations_remaining -= 1;
                                true
                            }
                        });
                if auto_continue || queued_during_scan {
                    self.continue_history_scan(self.subscription_generation);
                } else if scan_pending && self.load.fetch_head_after_history_scan {
                    self.load.fetch_head_after_history_scan = false;
                    self.fetch_history_head(self.subscription_generation);
                } else if self.load.history_reconciliation_scan.is_none()
                    && (self.load.fetch_again || self.load.fetch_head_after_history_scan)
                {
                    self.load.fetch_again = false;
                    self.load.fetch_head_after_history_scan = false;
                    self.fetch_transactions(self.subscription_generation);
                } else if scan_pending && !head_refresh_only {
                    self.fetch_history_head(self.subscription_generation);
                }
                self.finish_pending_risk_reconciliation();
            }
            AppEvent::RiskContextLoaded {
                generation,
                authorization_digest,
                snapshot,
            } => self.apply_risk_context_loaded(generation, authorization_digest, snapshot),
            AppEvent::RiskContextFailed {
                generation,
                authorization_digest,
                error,
            } => {
                if generation == self.session_generation
                    && self.pending_risk_context.as_ref() == Some(&authorization_digest)
                {
                    self.abort_risk_review(format!(
                        "Could not refresh the duplicate-risk context: {error}"
                    ));
                }
            }
            AppEvent::EndpointTested {
                for_network,
                url,
                reachable,
                reported_network_id,
                matches_wallet,
                error,
            } => self.apply_endpoint_tested(
                for_network,
                &url,
                reachable,
                reported_network_id,
                matches_wallet,
                error,
            ),
            AppEvent::SwapPoolLoaded {
                generation,
                seq,
                snapshot,
            } => self.apply_swap_pool_loaded(generation, seq, snapshot),
            AppEvent::SwapPoolFailed {
                generation,
                seq,
                error,
            } => self.apply_swap_pool_failed(generation, seq, error),
            AppEvent::SwapFinished { generation, result } => {
                self.apply_swap_finished(generation, result)
            }
            AppEvent::StorageLoaded {
                generation,
                seq,
                snapshot,
            } => self.apply_storage_loaded(generation, seq, snapshot),
            AppEvent::StorageLoadFailed {
                generation,
                seq,
                error,
            } => self.apply_storage_load_failed(generation, seq, error),
            AppEvent::StorageFinished {
                generation,
                op,
                result,
            } => self.apply_storage_finished(generation, op, result),
            AppEvent::Error(error) => self.state.set_error(error),
        }
    }
}

fn extend_scan_observations(
    retained: &mut Vec<EndpointTransactionEvidence>,
    incoming: Vec<EndpointTransactionEvidence>,
) {
    for observation in incoming {
        let mut same_message_count = 0usize;
        let mut already_retained = false;
        for existing in retained.iter() {
            if same_endpoint_message(existing, &observation) {
                same_message_count += 1;
                already_retained |= same_endpoint_transaction(existing, &observation);
            }
        }
        if already_retained {
            continue;
        }
        if same_message_count < 2 {
            retained.push(observation);
        }
    }
}
