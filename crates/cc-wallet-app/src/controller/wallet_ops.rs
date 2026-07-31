use std::sync::mpsc::Sender;

use cc_wallet_chain::ChainError;
use cc_wallet_domain::{
    AssetId, SendAuthorization, SendRequest, format_fixed9_amount, format_native_fixed9,
};

use super::AppController;
use crate::event::AppEvent;
use crate::state::AppTab;

struct SendCompletionGuard {
    tx: Sender<AppEvent>,
    generation: u64,
    armed: bool,
}

impl Drop for SendCompletionGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.tx.send(AppEvent::SendFailed {
                generation: self.generation,
                error: ChainError::Wallet(
                    "the transfer preparation task ended abnormally before reporting a result"
                        .to_owned(),
                ),
            });
        }
    }
}

impl AppController {
    fn next_load_id(&mut self) -> u64 {
        self.wallet_load_seq = self.wallet_load_seq.wrapping_add(1);
        if self.wallet_load_seq == 0 {
            self.wallet_load_seq = 1;
        }
        self.wallet_load_seq
    }

    pub(super) fn refresh_wallet(&mut self) {
        self.spawn_wallet_load(true);
    }

    pub(super) fn manual_refresh_wallet(&mut self) {
        if self.state.busy {
            return;
        }
        self.refresh_wallet();
    }

    pub(super) fn auto_refresh_wallet(&mut self, generation: u64) {
        if generation != self.subscription_generation {
            return;
        }
        if self.load.wallet_auto_refresh_id.is_some() {
            self.load.wallet_auto_refresh_again = true;
            return;
        }
        self.spawn_wallet_load(false);
    }

    fn spawn_wallet_load(&mut self, manual: bool) {
        let generation = self.subscription_generation;
        let request_id = self.next_load_id();
        let inputs = match self.wallet_load_inputs() {
            Ok(inputs) => inputs,
            Err(error) => {
                if manual {
                    self.load.wallet_load_id = Some(request_id);
                    self.apply_event(AppEvent::WalletLoadFailed {
                        generation,
                        request_id,
                        error,
                    });
                } else {
                    self.load.wallet_auto_refresh_id = Some(request_id);
                    self.apply_event(AppEvent::WalletAutoLoadFailed {
                        generation,
                        request_id,
                        error,
                    });
                }
                return;
            }
        };
        if manual {
            self.load.wallet_load_id = Some(request_id);
            self.state.busy = true;
            self.state.status = "Updating wallet...".to_owned();
        } else {
            self.load.wallet_auto_refresh_id = Some(request_id);
            self.state.auto_refreshing = true;
        }
        let tx = self.tx.clone();
        let chain = self.chain.clone();
        self.runtime.spawn(async move {
            let event = match chain.load_wallet(&inputs).await {
                Ok(snapshot) if manual => AppEvent::WalletLoaded {
                    generation,
                    request_id,
                    snapshot,
                },
                Ok(snapshot) => AppEvent::WalletAutoLoaded {
                    generation,
                    request_id,
                    snapshot,
                },
                Err(error) if manual => AppEvent::WalletLoadFailed {
                    generation,
                    request_id,
                    error: error.to_string(),
                },
                Err(error) => AppEvent::WalletAutoLoadFailed {
                    generation,
                    request_id,
                    error: error.to_string(),
                },
            };
            let _ = tx.send(event);
        });
    }

    pub(super) fn spawn_fee_estimate(&mut self, request: SendRequest, is_max: bool) -> Option<u64> {
        if self.state.sending || self.pending_authorization.is_some() {
            self.session.fee_reestimate_at = None;
            return None;
        }
        if self.state.fee_estimating {
            if is_max {
                self.session.fee_reestimate_at = None;
                self.queued_max_request = Some(request);
                self.state.max_refining = true;
            } else {
                self.session.fee_reestimate_at = Some(std::time::Instant::now());
            }
            return None;
        }
        let Ok(inputs) = self.wallet_inputs() else {
            return None;
        };
        self.session.fee_reestimate_at = None;
        let generation = self.subscription_generation;
        self.fee_request_seq += 1;
        let seq = self.fee_request_seq;
        self.state.fee_estimating = true;
        let bounce = self.state.send_bounce();
        let tx = self.tx.clone();
        let chain = self.chain.clone();
        self.runtime.spawn(async move {
            let event = match chain.estimate_fee(inputs, request, bounce).await {
                Ok(estimate) if is_max => AppEvent::MaxFeeEstimated {
                    generation,
                    seq,
                    estimate,
                },
                Ok(estimate) => AppEvent::FeeEstimated {
                    generation,
                    seq,
                    estimate,
                },
                Err(_) => AppEvent::FeeEstimateFailed { generation, seq },
            };
            let _ = tx.send(event);
        });
        Some(seq)
    }

    pub(super) fn start_queued_max_fee_estimate(&mut self) {
        let Some(request) = self.queued_max_request.take() else {
            return;
        };
        match self.spawn_fee_estimate(request, true) {
            Some(seq) => self.pending_max_seq = Some(seq),
            None if self.queued_max_request.is_some() => {}
            None => self.clear_pending_max(),
        }
    }

    pub(super) fn estimate_fee(&mut self) {
        self.check_destination();
        if self.max_filled
            && self.state.recipient_valid()
            && self.state.selected_asset == AssetId::Native
        {
            self.set_max_amount();
            return;
        }
        let request = match self.state.send_form.request() {
            Ok(request) => request,
            Err(_) => {
                if self.state.fee_estimate.is_some() || self.state.fee_estimating {
                    return;
                }
                let Some(address) = self.state.wallet.as_ref().map(|w| w.address.clone()) else {
                    return;
                };
                SendRequest::native(address, 1).expect("the loaded wallet address is valid")
            }
        };
        let _ = self.spawn_fee_estimate(request, false);
    }

    pub(super) fn set_max_amount(&mut self) {
        self.state.clear_send_form_error();
        let asset = self.state.selected_asset;
        let Some(balance) = self.state.wallet.as_ref().map(|w| w.balance_for(asset)) else {
            self.state.status = "Wallet not loaded".to_owned();
            return;
        };
        self.max_filled = true;
        match asset {
            AssetId::Native => {
                let balance_units = balance
                    .native_units()
                    .expect("the selected native balance is native");
                self.clear_pending_max();
                let approx = cc_wallet_domain::max_native_spendable(
                    balance_units,
                    self.state.effective_send_fee(),
                );
                self.state.send_form.amount = format_native_fixed9(approx)
                    .expect("a checked snapshot balance has a fixed-9 representation");
                if balance_units == 0 {
                    return;
                }
                let destination = if self.state.recipient_valid() {
                    self.state.send_form.destination.trim().to_owned()
                } else {
                    self.state
                        .wallet
                        .as_ref()
                        .expect("the wallet was loaded above")
                        .address
                        .clone()
                };
                let Ok(request) = SendRequest::native(destination, balance_units) else {
                    return;
                };
                self.session.fee_reestimate_at = None;
                self.pending_max_balance = Some(balance_units);
                self.state.max_refining = true;
                match self.spawn_fee_estimate(request, true) {
                    Some(seq) => self.pending_max_seq = Some(seq),
                    None if self.queued_max_request.is_some() => {}
                    None => self.clear_pending_max(),
                }
            }
            AssetId::CurrencyCollection(_) => {
                self.state.send_form.amount = format_fixed9_amount(&balance)
                    .expect("a supported selected CC has a fixed-9 representation");
                self.schedule_fee_reestimate();
            }
        }
    }

    pub(super) fn send_authorized_transaction(&mut self, authorization: SendAuthorization) {
        if self.state.sending {
            return;
        }
        let risk_override = self.pending_risk_consumption.as_ref().and_then(|pending| {
            let digest = authorization.ticket().digest().ok()?;
            (pending.consumption.new_record_id() == authorization.ticket().record_id()
                && pending.consumption.new_ticket_digest() == &digest)
                .then(|| pending.overlap.clone())
        });
        if let Some(reason) = self.state.send_safety_block_reason()
            && !(matches!(reason, crate::state::SendBlockReason::JournalBlocking)
                && risk_override.is_some())
        {
            self.state.set_error(reason.message());
            return;
        }
        if !self.state.recipient_send_permitted(risk_override.is_some()) {
            if matches!(
                self.state.recipient_check,
                crate::state::RecipientCheck::Known(_)
            ) {
                self.state.set_error(
                    "This recipient has no active account — confirm the new-address option to send",
                );
            } else {
                self.state.set_error(
                    "The recipient account state is not verified yet — try the send again in a moment",
                );
                self.check_destination();
            }
            return;
        }
        if !self.state.can_afford_request_with_overlap(
            authorization.request(),
            risk_override.as_deref().unwrap_or(&[]),
        ) {
            self.state
                .set_send_form_error("Insufficient balance for this amount plus the fee");
            return;
        }
        let generation = self.session_generation;
        let (inputs, ticket) = authorization.into_parts();
        let expected_ticket_digest = match ticket.digest() {
            Ok(digest) => digest,
            Err(error) => {
                self.pending_risk_consumption = None;
                self.state.set_error(format!(
                    "The immutable send ticket could not be bound: {error}"
                ));
                return;
            }
        };
        let risk_grant_required = risk_override.is_some();
        let active_reservations = self.state.active_reservations.clone();
        let authorized_overlap = risk_override.unwrap_or_default();

        self.begin_pending_send(ticket.request());
        self.state.sending = true;
        self.state.busy = true;
        self.state.status = "Preparing the transfer from fresh read-only chain state…".to_owned();
        let tx = self.tx.clone();
        let chain = self.chain.clone();
        self.runtime.spawn(async move {
            let mut guard = SendCompletionGuard {
                tx: tx.clone(),
                generation,
                armed: true,
            };
            let event = match chain
                .prepare_transaction(inputs, ticket, active_reservations, authorized_overlap)
                .await
            {
                Ok(prepared) => AppEvent::SendPrepared {
                    generation,
                    expected_ticket_digest,
                    risk_grant_required,
                    prepared,
                },
                Err(error) => AppEvent::SendFailed { generation, error },
            };
            guard.armed = false;
            let _ = tx.send(event);
        });
    }

    #[cfg(test)]
    pub(super) fn dispatch_test_authorization(&mut self) {
        let Ok(inputs) = self.wallet_inputs() else {
            return;
        };
        let Ok(request) = self.state.send_form.request() else {
            return;
        };
        let Some(sender_address) = self
            .state
            .wallet
            .as_ref()
            .map(|wallet| wallet.address.clone())
        else {
            return;
        };
        let Ok(record_id) = crate::random_ids::new_record_id() else {
            return;
        };
        let Ok(authorization) = SendAuthorization::new(
            record_id,
            self.store.name().to_owned(),
            sender_address,
            inputs,
            request,
            self.state.send_bounce(),
            self.auth_generation,
            0,
        ) else {
            return;
        };
        self.send_authorized_transaction(authorization);
    }

    pub(super) fn needs_destination_check(&self) -> bool {
        matches!(
            self.state.recipient_check,
            crate::state::RecipientCheck::Unchecked | crate::state::RecipientCheck::Failed
        )
    }

    pub(super) fn check_destination(&mut self) {
        if self.state.network_mismatch {
            return;
        }
        if !self.state.recipient_valid() {
            return;
        }
        let address = self.state.send_form.destination.trim().to_owned();
        if !self.needs_destination_check() {
            return;
        }
        let Ok(inputs) = self.endpoint_address_inputs() else {
            return;
        };
        self.state.recipient_check = crate::state::RecipientCheck::Pending;
        let generation = self.subscription_generation;
        self.dest_check_seq = self.dest_check_seq.wrapping_add(1);
        let seq = self.dest_check_seq;
        if let Some(task) = self.session.dest_check_task.take() {
            task.abort();
        }
        let tx = self.tx.clone();
        let chain = self.chain.clone();
        self.session.dest_check_task = Some(self.runtime.spawn(async move {
            let status = tokio::time::timeout(
                std::time::Duration::from_secs(12),
                chain.check_destination(&inputs, address.clone()),
            )
            .await
            .ok()
            .and_then(Result::ok);
            let _ = tx.send(AppEvent::DestinationChecked {
                generation,
                seq,
                address,
                status,
            });
        }));
    }

    pub(super) fn quick_send(&mut self, address: String) {
        self.state.send_form.destination = address;
        self.state.selected_tab = AppTab::Wallet;
        self.state.status = "Recipient filled from contacts".to_owned();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dropped_prepare_guard_reports_send_failed() {
        let (tx, rx) = std::sync::mpsc::channel();
        drop(SendCompletionGuard {
            tx,
            generation: 7,
            armed: true,
        });
        match rx.recv().unwrap() {
            AppEvent::SendFailed { generation, error } => {
                assert_eq!(generation, 7);
                assert!(error.to_string().contains("abnormally"));
            }
            other => panic!("expected SendFailed, got {other:?}"),
        }
    }

    #[test]
    fn a_disarmed_prepare_guard_stays_silent() {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut guard = SendCompletionGuard {
            tx,
            generation: 7,
            armed: true,
        };
        guard.armed = false;
        drop(guard);
        assert!(rx.try_recv().is_err());
    }
}
