use std::sync::mpsc::Sender;
use std::time::Instant;

use cc_wallet_chain::SubscriptionEvent;
use cc_wallet_chain::activity_from_chain_tx;
use cc_wallet_domain::{
    ActivityDirection, ActivityEvent, ActivityMessage, AssetMovement, EndpointTransactionEvidence,
    SendRequest,
};

use super::AppController;
use crate::event::AppEvent;
use crate::state::LiveStatus;

struct FetchCompletionGuard {
    tx: Sender<AppEvent>,
    generation: u64,
    fetch_id: u64,
    head_refresh_only: bool,
    armed: bool,
}

impl Drop for FetchCompletionGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.tx.send(AppEvent::TransactionsLoaded {
                generation: self.generation,
                fetch_id: self.fetch_id,
                head_refresh_only: self.head_refresh_only,
                events: Vec::new(),
                integrity_error: None,
                incomplete: true,
                gap: true,
                deepest_lt: None,
            });
        }
    }
}

impl AppController {
    fn reset_stranded_destination_check(&mut self) {
        if matches!(
            self.state.recipient_check,
            crate::state::RecipientCheck::Pending
        ) {
            self.state.recipient_check = crate::state::RecipientCheck::Unchecked;
        }
    }

    pub(super) fn stop_subscription(&mut self) {
        if let Some(task) = self.subscription_task.take() {
            task.abort();
        }
        self.subscription_generation = self.subscription_generation.wrapping_add(1);
        self.reset_stranded_destination_check();
        self.subscription_key = None;
        self.subscription_addr = None;
        self.subscription_retry_at = None;
        self.subscription_backoff_secs = super::SUBSCRIPTION_BACKOFF_MIN_SECS;
        self.load = super::LoadRuntime {
            wallet_load_id: self.load.wallet_load_id,
            ..Default::default()
        };
        self.state.live_status = LiveStatus::Offline;
        self.state.subscription_status = "not subscribed".to_owned();
        self.state.auto_refreshing = false;
        self.reset_journal_reconciliation();
    }

    pub(super) fn ensure_subscription(&mut self, address: String) {
        if self.state.network_mismatch {
            return;
        }
        let endpoint = self.state.resolved_endpoint().trim().to_owned();
        let inputs = match cc_wallet_domain::EndpointAddressInputs::new(endpoint, address) {
            Ok(inputs) => inputs,
            Err(error) => {
                self.state.subscription_status = error.to_string();
                self.state.live_status = LiveStatus::Error;
                return;
            }
        };
        self.subscription_addr = Some(inputs.address().to_owned());
        let endpoint = inputs.endpoint();
        let address = inputs.address();
        let key = format!("{endpoint}|{address}");
        if self.subscription_key.as_deref() == Some(key.as_str())
            && self
                .subscription_task
                .as_ref()
                .is_some_and(|task| !task.is_finished())
        {
            return;
        }

        if let Some(task) = self.subscription_task.take() {
            task.abort();
        }
        self.subscription_generation = self.subscription_generation.wrapping_add(1);
        self.reset_stranded_destination_check();
        let generation = self.subscription_generation;
        self.subscription_key = Some(key);
        self.state.live_status = LiveStatus::Connecting;
        self.state.subscription_status = "connecting subscription".to_owned();

        let tx = self.tx.clone();
        let chain = self.chain.clone();
        self.subscription_task = Some(self.runtime.spawn(async move {
            let event_tx = tx.clone();
            let emit: Box<dyn FnMut(SubscriptionEvent) + Send> = Box::new(move |event| {
                let app_event = match event {
                    SubscriptionEvent::Ready { uuid } => {
                        AppEvent::SubscriptionReady { generation, uuid }
                    }
                    SubscriptionEvent::Update(update) => {
                        AppEvent::SubscriptionUpdate { generation, update }
                    }
                };
                let _ = event_tx.send(app_event);
            });
            let result = chain.subscribe(inputs, emit).await;
            if let Err(error) = result {
                let _ = tx.send(AppEvent::SubscriptionFailed {
                    generation,
                    error: error.to_string(),
                });
            }
        }));
    }

    pub(super) fn fetch_transactions(&mut self, generation: u64) {
        if !self.load.fetch_in_flight && self.load.history_reconciliation_scan.is_some() {
            self.load.fetch_head_after_history_scan = true;
        }
        self.fetch_transactions_inner(generation, false);
    }

    pub(super) fn continue_history_scan(&mut self, generation: u64) {
        self.fetch_transactions_inner(generation, false);
    }

    pub(super) fn fetch_history_head(&mut self, generation: u64) {
        self.fetch_transactions_inner(generation, true);
    }

    fn fetch_transactions_inner(&mut self, generation: u64, head_refresh_only: bool) {
        if self.state.network_mismatch {
            return;
        }
        if self.load.fetch_in_flight {
            self.load.fetch_again = true;
            return;
        }
        let Ok(inputs) = self.endpoint_address_inputs() else {
            return;
        };
        let sender_address = inputs.address().to_owned();
        let (initial_before_lt, stop_at, initial_age_cutoff) = if head_refresh_only {
            (
                None,
                self.state.activity.iter().map(|event| event.lt).max(),
                None,
            )
        } else if let Some(scan) = self.load.history_reconciliation_scan.as_ref() {
            (Some(scan.next_before_lt), scan.stop_at, scan.age_cutoff)
        } else {
            let (stop_at, age_cutoff) =
                if self.session.history_has_gap || self.state.history_incomplete {
                    (
                        self.session.history_synced_floor,
                        self.state
                            .journal_blocking
                            .then_some(self.session.journal_reconcile_time_floor)
                            .flatten(),
                    )
                } else if self.state.journal_blocking {
                    (
                        if self.pending_risk_reconciliation {
                            None
                        } else {
                            self.session.journal_reconcile_floor
                        },
                        self.session.journal_reconcile_time_floor,
                    )
                } else {
                    (self.state.activity.iter().map(|event| event.lt).max(), None)
                };
            (None, stop_at, age_cutoff)
        };
        let hard_age_cutoff = self
            .state
            .journal_blocking
            .then_some(self.session.journal_reconcile_time_floor)
            .flatten();
        let local_now = super::now_unix();
        let tx = self.tx.clone();
        let chain = self.chain.clone();
        self.fetch_seq = self.fetch_seq.wrapping_add(1);
        if self.fetch_seq == 0 {
            self.fetch_seq = 1;
        }
        let fetch_id = self.fetch_seq;
        self.load.fetch_in_flight = true;
        self.load.fetch_in_flight_id = Some(fetch_id);
        self.runtime.spawn(async move {
            let mut completion = FetchCompletionGuard {
                tx: tx.clone(),
                generation,
                fetch_id,
                head_refresh_only,
                armed: true,
            };
            const PAGE: u32 = 100;
            const MAX_PAGES: usize = 20;
            let mut events = Vec::new();
            let mut observations = Vec::new();
            let mut before_lt = initial_before_lt;
            let mut incomplete = false;
            let mut integrity_error = None;
            let mut natural_end = false;
            let mut rpc_error = false;
            let mut walk_gap = false;
            let mut deepest_lt: Option<u64> = None;
            let mut age_cutoff = initial_age_cutoff;
            let mut saw_newest_chain_time = initial_before_lt.is_some();
            'pages: for _ in 0..MAX_PAGES {
                let mut page = match chain.load_transactions(&inputs, PAGE, before_lt).await {
                    Ok(page) => page,
                    Err(_) => {
                        rpc_error = true;
                        walk_gap = true;
                        break;
                    }
                };
                let page_endpoint = page.source_endpoint.clone();
                let page_request_id = page.request_id.clone();
                let raw_page_len = match page.transactions.len().checked_add(page.skipped) {
                    Some(len) if len <= PAGE as usize => len,
                    _ => {
                        events.clear();
                        observations.clear();
                        integrity_error = Some(format!(
                            "endpoint history page exceeds the requested {PAGE}-transaction limit"
                        ));
                        rpc_error = true;
                        walk_gap = true;
                        break;
                    }
                };
                if page.skipped > 0 {
                    incomplete = true;
                    walk_gap = true;
                    age_cutoff = hard_age_cutoff;
                    saw_newest_chain_time = true;
                }
                if page.transactions.is_empty() {
                    natural_end = true;
                    break;
                }
                page.transactions
                    .sort_by_key(|transaction| std::cmp::Reverse(transaction.lt));
                let full = raw_page_len == PAGE as usize;
                if !saw_newest_chain_time {
                    let newest_lt = page.transactions[0].lt;
                    let newest_rows = page
                        .transactions
                        .iter()
                        .take_while(|transaction| transaction.lt == newest_lt)
                        .collect::<Vec<_>>();
                    let tie_may_continue =
                        full && newest_rows.len() == page.transactions.len() && page.skipped == 0;
                    let newest_time = newest_rows.first().map(|transaction| transaction.now);
                    let unambiguous = !tie_may_continue
                        && newest_time.is_some_and(|time| {
                            newest_rows
                                .iter()
                                .all(|transaction| transaction.now == time)
                        });
                    let retention_cutoff = unambiguous
                        .then_some(newest_time)
                        .flatten()
                        .and_then(|time| {
                            conservative_history_age_anchor(local_now, Some(time.into()))
                        })
                        .map(|anchor| anchor.saturating_sub(super::HISTORY_MAX_AGE_SECS));
                    age_cutoff = match (age_cutoff, retention_cutoff) {
                        (Some(reconciliation), Some(retention)) => {
                            Some(reconciliation.max(retention))
                        }
                        (left, right) => left.or(right),
                    };
                    saw_newest_chain_time = true;
                }
                let mut oldest_lt = before_lt.unwrap_or(u64::MAX);
                let mut reached_stop_at = false;
                for raw in &page.transactions {
                    if stop_at.is_some_and(|known| raw.lt < known) {
                        natural_end = true;
                        break 'pages;
                    }
                    if raw.now == 0 && hard_age_cutoff.is_some() {
                        natural_end = true;
                        break 'pages;
                    }
                    if raw.now != 0 && age_cutoff.is_some_and(|cutoff| u64::from(raw.now) < cutoff)
                    {
                        natural_end = true;
                        break 'pages;
                    }
                    oldest_lt = raw.lt;
                    deepest_lt = Some(raw.lt);
                    match activity_from_chain_tx(raw) {
                        Ok(events_for_tx) => {
                            let combined_effects: Vec<_> = events_for_tx
                                .iter()
                                .flat_map(|event| event.movements.iter().cloned())
                                .collect();
                            for (index, event) in events_for_tx.into_iter().enumerate() {
                                if index == 0
                                    && let (Some(tx_hash), Some(ext_msg_hash)) =
                                        (event.tx_hash.clone(), event.ext_msg_hash.clone())
                                {
                                    match EndpointTransactionEvidence::new(
                                        page_endpoint.clone(),
                                        page_request_id.clone(),
                                        sender_address.clone(),
                                        tx_hash,
                                        ext_msg_hash,
                                        event.lt,
                                        event.success,
                                        event.exit_code,
                                        combined_effects.clone(),
                                    ) {
                                        Ok(observation) => observations.push(observation),
                                        Err(error) => {
                                            events.clear();
                                            observations.clear();
                                            integrity_error = Some(error.to_string());
                                            rpc_error = true;
                                            walk_gap = true;
                                            break 'pages;
                                        }
                                    }
                                }
                                events.push(event);
                            }
                        }
                        Err(error) => {
                            events.clear();
                            integrity_error = Some(error.to_string());
                            rpc_error = true;
                            walk_gap = true;
                            break 'pages;
                        }
                    }
                    if stop_at == Some(raw.lt) {
                        reached_stop_at = true;
                    }
                }
                if reached_stop_at {
                    natural_end = true;
                    break;
                }
                if !full {
                    natural_end = true;
                    break;
                }
                before_lt = Some(oldest_lt);
            }
            let budget_hit = !rpc_error && !natural_end;
            if rpc_error || budget_hit {
                incomplete = true;
            }
            let continuation_before_lt = if budget_hit && !walk_gap && integrity_error.is_none() {
                match (initial_before_lt, before_lt) {
                    (None, Some(next)) => Some(next),
                    (Some(start), Some(next)) if next < start => Some(next),
                    _ => {
                        walk_gap = true;
                        integrity_error = Some(
                            "endpoint history pagination did not advance to an older logical time"
                                .to_owned(),
                        );
                        None
                    }
                }
            } else {
                None
            };
            completion.armed = false;
            let _ = tx.send(AppEvent::EndpointHistoryScanned {
                generation,
                fetch_id,
                head_refresh_only,
                observations,
                scan_start_before_lt: initial_before_lt,
                scan_stop_at: stop_at,
                scan_age_cutoff: age_cutoff,
                continuation_before_lt,
                deepest_lt,
                gap: walk_gap,
            });
            let _ = tx.send(AppEvent::TransactionsLoaded {
                generation,
                fetch_id,
                head_refresh_only,
                gap: walk_gap,
                deepest_lt,
                events,
                integrity_error,
                incomplete,
            });
        });
    }

    pub(super) fn push_pending_send(&mut self, request: &SendRequest) -> u64 {
        self.pending_seq += 1;
        let lt = self.pending_seq;
        self.state.activity.push(ActivityEvent {
            direction: ActivityDirection::Out,
            lt,
            time_unix: super::now_unix(),
            tx_hash: None,
            counterparty: request.destination().to_owned(),
            movements: vec![AssetMovement {
                amount: request.value().clone(),
            }],
            fee_native: 0,
            success: true,
            bounced: false,
            exit_code: 0,
            ext_msg_hash: None,
            int_msg_hash: None,
            finality_ms: None,
            pending: true,
            message: (!request.comment().is_empty()).then(|| ActivityMessage::Plain {
                text: request.comment().to_owned(),
            }),
        });
        self.session.pending_sends.push((lt, None));
        self.sort_activity();
        lt
    }

    pub(super) fn begin_pending_send(&mut self, request: &SendRequest) -> u64 {
        if let Some(lt) = self.session.awaiting_send_lt
            && self
                .state
                .activity
                .iter()
                .any(|event| event.tx_hash.is_none() && event.lt == lt)
        {
            return lt;
        }
        let lt = self.push_pending_send(request);
        self.session.awaiting_send_lt = Some(lt);
        lt
    }

    pub(super) fn arm_awaiting_send_finality(&mut self) {
        let Some(lt) = self.session.awaiting_send_lt else {
            return;
        };
        if let Some((_, started_at)) = self
            .session
            .pending_sends
            .iter_mut()
            .find(|(pending_lt, _)| *pending_lt == lt)
            && started_at.is_none()
        {
            *started_at = Some(Instant::now());
        }
    }

    fn settled_wait_for(&self, hash: &cc_wallet_domain::Digest32) -> Option<u64> {
        self.session
            .pending_externals
            .iter()
            .find(|pending| &pending.hash == hash)
            .and_then(|pending| pending.settled_ms)
    }

    pub(super) fn end_external_waits(&mut self) {
        for pending in &mut self.session.pending_externals {
            if pending.settled_ms.is_none() {
                pending.settled_ms = u64::try_from(pending.started_at.elapsed().as_millis()).ok();
            }
        }
    }

    fn broadcast_started_at(
        &self,
        hash: &cc_wallet_domain::Digest32,
        replaced: &[(u64, u64, Option<u64>)],
    ) -> Option<Instant> {
        if let Some(pending) = self
            .session
            .pending_externals
            .iter()
            .find(|pending| &pending.hash == hash)
        {
            return Some(pending.started_at);
        }
        self.session
            .pending_sends
            .iter()
            .filter(|(lt, _)| replaced.iter().any(|(replaced_lt, _, _)| replaced_lt == lt))
            .filter_map(|(_, started_at)| *started_at)
            .min()
    }

    fn spun_for(&self, started_at: Instant) -> Option<u64> {
        u64::try_from(started_at.elapsed().as_millis()).ok()
    }

    pub(super) fn settle_optimistic_row(&mut self, ext_msg_hash: &cc_wallet_domain::Digest32) {
        let ours: Vec<u64> = self
            .state
            .activity
            .iter()
            .filter(|event| event.tx_hash.is_none())
            .filter(|event| event.ext_msg_hash.as_ref() == Some(ext_msg_hash))
            .map(|event| event.lt)
            .collect();
        let finality = self
            .session
            .pending_sends
            .iter()
            .filter(|(lt, _)| ours.contains(lt))
            .filter_map(|(_, started_at)| *started_at)
            .min()
            .and_then(|started_at| self.spun_for(started_at));
        for event in self
            .state
            .activity
            .iter_mut()
            .filter(|event| event.tx_hash.is_none())
            .filter(|event| event.ext_msg_hash.as_ref() == Some(ext_msg_hash))
        {
            event.pending = false;
            if event.finality_ms.is_none() {
                event.finality_ms = finality;
            }
        }
        self.sort_activity();
    }

    pub(super) fn discard_awaiting_send(&mut self) {
        let Some(lt) = self.session.awaiting_send_lt.take() else {
            return;
        };
        self.state
            .activity
            .retain(|event| !(event.tx_hash.is_none() && event.lt == lt));
        self.session.pending_sends.retain(|(held, _)| *held != lt);
    }

    pub(super) fn sort_activity(&mut self) {
        self.state.activity.sort_by(|a, b| {
            a.tx_hash
                .is_some()
                .cmp(&b.tx_hash.is_some())
                .then(b.lt.cmp(&a.lt))
        });
        self.rebuild_chat();
    }

    pub(super) fn merge_activity(&mut self, incoming: Vec<ActivityEvent>) {
        let mut changed = false;
        let mut optimistic_confirmation_merged = false;
        for mut event in incoming {
            if self.state.activity.iter().any(|held| {
                held.tx_hash.is_some()
                    && held.lt == event.lt
                    && held.int_msg_hash == event.int_msg_hash
            }) {
                continue;
            }
            if let Some(hash) = event.ext_msg_hash.clone() {
                let removed: Vec<(u64, u64, Option<u64>)> = self
                    .state
                    .activity
                    .iter()
                    .filter(|held| {
                        held.tx_hash.is_none() && held.ext_msg_hash.as_ref() == Some(&hash)
                    })
                    .map(|held| (held.lt, held.time_unix, held.finality_ms))
                    .collect();
                optimistic_confirmation_merged |= !removed.is_empty();
                if event.finality_ms.is_none() {
                    event.finality_ms = removed
                        .iter()
                        .filter_map(|(_, _, finality)| *finality)
                        .min()
                        .or_else(|| self.settled_wait_for(&hash))
                        .or_else(|| {
                            self.broadcast_started_at(&hash, &removed)
                                .and_then(|started_at| self.spun_for(started_at))
                        });
                }
                self.state.activity.retain(|held| {
                    !(held.tx_hash.is_none() && held.ext_msg_hash.as_ref() == Some(&hash))
                });
                self.session
                    .pending_sends
                    .retain(|(lt, _)| !removed.iter().any(|(removed_lt, _, _)| removed_lt == lt));
                self.session
                    .pending_externals
                    .retain(|pending| pending.hash != hash);
            }
            self.state.activity.push(event);
            changed = true;
        }
        if changed {
            self.reconcile_swap_receipt();
        }
        if changed {
            self.sort_activity();
            self.cap_history();
            if optimistic_confirmation_merged {
                let _ = self.persist_journal_barrier();
            } else {
                self.save_history();
            }
        }
    }

    pub(super) fn cap_history(&mut self) {
        self.cap_history_at(super::now_unix());
    }

    pub(super) fn cap_history_at(&mut self, local_now_unix: u64) {
        use std::collections::HashMap;

        use cc_wallet_domain::AssetId;

        let newest_chain_time = newest_unambiguous_chain_time(&self.state.activity);
        let age_anchor = conservative_history_age_anchor(local_now_unix, newest_chain_time);
        let min_time = age_anchor.map(|anchor| anchor.saturating_sub(super::HISTORY_MAX_AGE_SECS));
        let mut per_asset: HashMap<AssetId, usize> = HashMap::new();
        let mut kept_confirmed: usize = 0;
        let mut cap_boundary_lt: Option<u64> = None;
        self.state.activity.retain(|event| {
            if event.tx_hash.is_none() {
                return true;
            }
            if kept_confirmed >= super::MAX_HISTORY && cap_boundary_lt != Some(event.lt) {
                return false;
            }
            let young = min_time.is_none_or(|cutoff| event.time_unix >= cutoff);
            let within_global_floor = kept_confirmed < super::HISTORY_MIN_KEEP;
            let within_per_asset = event.movements.iter().any(|movement| {
                per_asset
                    .get(&movement.amount.asset_id())
                    .copied()
                    .unwrap_or(0)
                    < super::HISTORY_MIN_KEEP
            });
            let keep = young || within_global_floor || within_per_asset;
            if keep {
                kept_confirmed += 1;
                if kept_confirmed == super::MAX_HISTORY {
                    cap_boundary_lt = Some(event.lt);
                }
                for movement in &event.movements {
                    *per_asset.entry(movement.amount.asset_id()).or_insert(0) += 1;
                }
            }
            keep
        });
    }
}

fn conservative_history_age_anchor(local_now: u64, newest_chain: Option<u64>) -> Option<u64> {
    const MAX_FUTURE_SKEW_SECS: u64 = 10 * 60;
    let newest_chain = newest_chain.filter(|value| *value > 0)?;
    if newest_chain > local_now.saturating_add(MAX_FUTURE_SKEW_SECS) {
        return None;
    }
    Some(local_now.min(newest_chain))
}

fn newest_unambiguous_chain_time(events: &[ActivityEvent]) -> Option<u64> {
    let newest_lt = events
        .iter()
        .filter(|event| event.tx_hash.is_some())
        .map(|event| event.lt)
        .max()?;
    let mut times = events
        .iter()
        .filter(|event| event.tx_hash.is_some() && event.lt == newest_lt)
        .map(|event| event.time_unix);
    let first = times.next()?;
    times.all(|time| time == first).then_some(first)
}

#[cfg(test)]
mod fetch_guard_tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn an_armed_guard_emits_a_gap_result_on_drop() {
        let (tx, rx) = mpsc::channel();
        drop(FetchCompletionGuard {
            tx,
            generation: 7,
            fetch_id: 11,
            head_refresh_only: false,
            armed: true,
        });
        match rx.try_recv() {
            Ok(AppEvent::TransactionsLoaded {
                generation,
                fetch_id,
                head_refresh_only,
                gap,
                incomplete,
                events,
                integrity_error,
                deepest_lt,
            }) => {
                assert_eq!(generation, 7);
                assert_eq!(fetch_id, 11);
                assert!(!head_refresh_only);
                assert!(gap, "an abnormal exit reports a gap");
                assert!(incomplete);
                assert!(events.is_empty());
                assert!(integrity_error.is_none());
                assert!(deepest_lt.is_none());
            }
            other => panic!("expected a terminal TransactionsLoaded, got {other:?}"),
        }
    }

    #[test]
    fn a_disarmed_guard_stays_silent_on_drop() {
        let (tx, rx) = mpsc::channel();
        let mut guard = FetchCompletionGuard {
            tx,
            generation: 1,
            fetch_id: 2,
            head_refresh_only: false,
            armed: true,
        };
        guard.armed = false;
        drop(guard);
        assert!(
            rx.try_recv().is_err(),
            "a disarmed guard must not emit anything"
        );
    }

    #[test]
    fn history_age_anchor_only_uses_plausible_chain_time_to_preserve_more() {
        let local = 1_800_000_000;
        assert_eq!(conservative_history_age_anchor(local, None), None);
        assert_eq!(conservative_history_age_anchor(local, Some(0)), None);
        assert_eq!(
            conservative_history_age_anchor(local, Some(local + 601)),
            None,
            "a future-skewed endpoint disables age deletion"
        );
        assert_eq!(
            conservative_history_age_anchor(local, Some(local - 10_000)),
            Some(local - 10_000),
            "an old chain head moves the cutoff backwards"
        );
        assert_eq!(
            conservative_history_age_anchor(local, Some(local + 600)),
            Some(local),
            "a plausible near-future stamp can never move the cutoff forward"
        );
    }

    #[test]
    fn only_the_newest_unambiguous_lt_can_supply_history_time() {
        fn event(lt: u64, time_unix: u64) -> ActivityEvent {
            ActivityEvent {
                direction: cc_wallet_domain::ActivityDirection::In,
                tx_hash: Some(cc_wallet_domain::Digest32::from_bytes([lt as u8; 32])),
                counterparty: String::new(),
                movements: Vec::new(),
                ..ActivityEvent::test_stub(lt, time_unix)
            }
        }
        let older_with_larger_time = vec![event(10, 100), event(9, 9_999)];
        assert_eq!(
            newest_unambiguous_chain_time(&older_with_larger_time),
            Some(100)
        );

        let conflicting_tie = vec![event(10, 100), event(10, 101)];
        assert_eq!(newest_unambiguous_chain_time(&conflicting_tie), None);
    }
}
