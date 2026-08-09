use std::time::Instant;

use cc_wallet_chain::{CandidateBroadcastOutcome, ChainError, PoolSnapshot};
use cc_wallet_domain::{
    ActivityDirection, ActivityEvent, AssetAmount, AssetId, MAX_SLIPPAGE_BPS, SwapRequest,
    WalletInputs, base_units_u128, canonicalize_recipient, format_fixed9_amount,
    format_slippage_percent, parse_slippage_percent, quote_swap, step_slippage_bps,
};

use super::AppController;
use crate::event::{AppEvent, BroadcastDispatch};
use crate::state::{
    AuthModal, AuthMode, AuthPurpose, SWAP_MAX_NATIVE_RESERVE, SwapFigures, SwapReceipt,
};

pub(super) struct PendingSwap {
    pub request: SwapRequest,
    pub inputs: WalletInputs,
    pub pool: String,
    pub generation: u64,
}

pub(super) struct SwapIntent {
    pub sent: AssetAmount,
    pub out_asset: AssetId,
    pub expected_out_units: u128,
    pub min_out_units: u128,
    pub slippage_bps: u16,
    pub pool: String,
}

impl AppController {
    fn current_pool_address(&self) -> Option<String> {
        self.networks
            .dex_pool_for(self.state.network_id)
            .map(str::to_owned)
    }

    pub(super) fn on_swap_tab_opened(&mut self) {
        self.refresh_swap_pool();
    }

    pub(super) fn refresh_swap_pool(&mut self) {
        let Some(pool) = self.current_pool_address() else {
            self.state.swap.pool = None;
            self.state.swap.quote = None;
            self.state.swap.pool_loading = false;
            self.state.swap.pool_error = "No swap pool is configured for this network".to_owned();
            return;
        };
        let endpoint = self.current_endpoint();
        if endpoint.is_empty() {
            self.state.swap.pool_error = "No endpoint configured for this network".to_owned();
            return;
        }
        let endpoint = match crate::canonical_endpoint(&endpoint) {
            Ok(endpoint) => endpoint,
            Err(error) => {
                self.state.swap.pool_error = error;
                return;
            }
        };
        self.state.swap.pool_loading = true;
        self.state.swap.pool_error.clear();
        let generation = self.subscription_generation;
        self.swap_pool_seq = self.swap_pool_seq.wrapping_add(1);
        let seq = self.swap_pool_seq;
        let tx = self.tx.clone();
        let chain = self.chain.clone();
        self.runtime.spawn(async move {
            let event = match chain.load_pool_state(&endpoint, &pool).await {
                Ok(snapshot) => AppEvent::SwapPoolLoaded {
                    generation,
                    seq,
                    snapshot,
                },
                Err(error) => AppEvent::SwapPoolFailed {
                    generation,
                    seq,
                    error: error.to_string(),
                },
            };
            let _ = tx.send(event);
        });
    }

    pub(super) fn apply_swap_pool_loaded(&mut self, generation: u64, seq: u64, pool: PoolSnapshot) {
        if generation != self.subscription_generation || seq != self.swap_pool_seq {
            return;
        }
        self.state.swap.pool_loading = false;
        self.state.swap.pool_error.clear();
        self.state.swap.pool = Some(pool);
        self.align_swap_form_with_pool();
        self.recompute_swap_quote();
    }

    fn align_swap_form_with_pool(&mut self) {
        let assets = self.state.swap_pool_assets();
        if assets.is_empty() {
            return;
        }
        let form = &mut self.state.swap.form;
        if !assets.contains(&form.from_asset()) {
            form.from = send_token(assets[0]);
        }
        let from = form.from_asset();
        if (!assets.contains(&form.to_asset()) || form.to_asset() == from)
            && let Some(other) = assets.iter().find(|asset| **asset != from)
        {
            form.to = send_token(*other);
        }
    }

    pub(super) fn apply_swap_pool_failed(&mut self, generation: u64, seq: u64, error: String) {
        if generation != self.subscription_generation || seq != self.swap_pool_seq {
            return;
        }
        self.state.swap.pool_loading = false;
        self.state.swap.pool = None;
        self.state.swap.quote = None;
        self.state.swap.pool_error = error;
    }

    pub(super) fn set_swap_from_token(&mut self, asset: AssetId) {
        if !asset.is_sendable() {
            return;
        }
        self.state.swap.form.from = send_token(asset);
        if self.state.swap.form.to == self.state.swap.form.from {
            self.state.swap.form.flip();
        }
        self.recompute_swap_quote();
    }

    pub(super) fn set_swap_to_token(&mut self, asset: AssetId) {
        if !asset.is_sendable() {
            return;
        }
        self.state.swap.form.to = send_token(asset);
        if self.state.swap.form.to == self.state.swap.form.from {
            self.state.swap.form.flip();
        }
        self.recompute_swap_quote();
    }

    pub(super) fn set_swap_amount(&mut self, amount: String) {
        self.state.swap.form.amount = amount;
        self.recompute_swap_quote();
    }

    pub(super) fn set_max_swap_amount(&mut self) {
        let asset = self.state.swap.form.from_asset();
        let balance = self.state.balance_or_zero(asset);
        let spendable = match asset {
            AssetId::Native => AssetAmount::native(
                balance
                    .native_units()
                    .unwrap_or(0)
                    .saturating_sub(SWAP_MAX_NATIVE_RESERVE),
            )
            .ok(),
            AssetId::CurrencyCollection(_) => Some(balance),
        };
        let Some(text) = spendable
            .as_ref()
            .and_then(|amount| format_fixed9_amount(amount).ok())
        else {
            return;
        };
        self.state.swap.form.amount = text;
        self.recompute_swap_quote();
    }

    pub(super) fn set_swap_slippage(&mut self, slippage_bps: u16) {
        let bps = slippage_bps.min(MAX_SLIPPAGE_BPS);
        self.state.swap.form.slippage_bps = bps;
        self.state.swap.slippage_input = format_slippage_percent(bps);
        self.recompute_swap_quote();
    }

    pub(super) fn step_swap_slippage(&mut self, up: bool) {
        let current = self.state.swap.form.clamped_slippage_bps();
        self.set_swap_slippage(step_slippage_bps(current, up));
    }

    pub(super) fn edit_swap_slippage(&mut self, text: String) {
        self.state.swap.slippage_input = text;
        if let Some(bps) = parse_slippage_percent(&self.state.swap.slippage_input) {
            self.state.swap.form.slippage_bps = bps;
            self.recompute_swap_quote();
        }
    }

    pub(super) fn flip_swap(&mut self) {
        self.state.swap.form.flip();
        self.recompute_swap_quote();
    }

    pub(super) fn recompute_swap_quote(&mut self) {
        let Some(pool) = self.state.swap.pool.as_ref() else {
            self.state.swap.quote = None;
            return;
        };
        let form = &self.state.swap.form;
        let (from, to) = (form.from_asset(), form.to_asset());
        let in_units = match form.input().ok().as_ref().and_then(base_units_u128) {
            Some(units) if units > 0 => units,
            _ => {
                self.state.swap.quote = None;
                return;
            }
        };
        self.state.swap.quote = quote_swap(
            in_units,
            pool.reserve_units(from),
            pool.reserve_units(to),
            pool.fee_bps,
            form.clamped_slippage_bps(),
        );
    }

    pub(super) fn swap_ready(&self) -> bool {
        self.pending_swap.is_none() && self.state.swap_button_enabled()
    }

    pub(super) fn request_swap(&mut self) {
        if self.pending_swap.is_some() {
            self.state.auth.error =
                "A swap authorization is already waiting for confirmation".to_owned();
            return;
        }
        if !self.swap_ready() {
            return;
        }
        let Some(request) = self.state.swap_request() else {
            return;
        };
        let Some(pool) = self.current_pool_address() else {
            self.state
                .set_error("No swap pool is configured for this network");
            return;
        };
        let inputs = match self.wallet_inputs() {
            Ok(inputs) => inputs,
            Err(error) => {
                self.state.set_error(error);
                return;
            }
        };
        let Some(generation) = self.auth_generation.checked_add(1) else {
            self.state.set_error(
                "Swap authorization generation is exhausted; lock and reopen the wallet",
            );
            return;
        };
        self.auth_generation = generation;
        self.state.swap.confirm = Some(SwapFigures {
            sent: request.input().clone(),
            out_asset: request.output(),
            out_units: self
                .state
                .swap
                .quote
                .filter(|quote| !quote.is_empty())
                .map(|quote| quote.out_units)
                .unwrap_or(0),
        });
        self.pending_swap = Some(PendingSwap {
            request,
            inputs,
            pool,
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
            purpose: AuthPurpose::Swap,
            send_options_editable: false,
            error: String::new(),
        };
    }

    pub(super) fn clear_pending_swap(&mut self) {
        self.pending_swap = None;
        self.state.swap.confirm = None;
    }

    pub(super) fn reset_swap_for_new_identity(&mut self) {
        self.clear_pending_swap();
        self.swap_in_flight = None;
        self.state.swap.form.amount.clear();
        self.state.swap.quote = None;
        self.state.swap.receipt = None;
    }

    pub(super) fn dispatch_authorized_swap(&mut self) {
        let Some(pending) = self.pending_swap.take() else {
            return;
        };
        self.state.swap.confirm = None;
        let PendingSwap {
            request,
            inputs,
            pool,
            ..
        } = pending;
        let quote = self.state.swap.quote;
        self.swap_in_flight = Some(SwapIntent {
            sent: request.input().clone(),
            out_asset: request.output(),
            expected_out_units: quote.map(|quote| quote.out_units).unwrap_or(0),
            min_out_units: request.min_out_units(),
            slippage_bps: request.slippage_bps(),
            pool: canonicalize_recipient(&pool).unwrap_or_else(|_| pool.clone()),
        });
        self.state.swap.swapping = true;
        self.state.busy = true;
        let generation = self.session_generation;
        let tx = self.tx.clone();
        let chain = self.chain.clone();
        self.runtime.spawn(async move {
            let result = match chain.prepare_swap(inputs, pool, request).await {
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
            let _ = tx.send(AppEvent::SwapFinished { generation, result });
        });
    }

    pub(super) fn apply_swap_finished(
        &mut self,
        generation: u64,
        result: Result<BroadcastDispatch, ChainError>,
    ) {
        if generation != self.session_generation {
            return;
        }
        self.state.swap.swapping = false;
        self.state.busy = false;
        let intent = self.swap_in_flight.take();
        match result {
            Ok(dispatch) if broadcast_reached_node(&dispatch.outcome) => {
                self.session
                    .pending_externals
                    .push((dispatch.ext_msg_hash.clone(), dispatch.broadcast_started_at));
                self.state.swap.receipt = intent.map(|intent| SwapReceipt {
                    sent: intent.sent,
                    out_asset: intent.out_asset,
                    expected_out_units: intent.expected_out_units,
                    min_out_units: intent.min_out_units,
                    slippage_bps: intent.slippage_bps,
                    pool: intent.pool,
                    ext_msg_hash: Some(dispatch.ext_msg_hash),
                    submitted_unix: super::now_unix(),
                    received_units: None,
                    returned_units: None,
                    fee_native: 0,
                });
                self.state.swap.form.amount.clear();
                self.state.swap.quote = None;
                self.auto_refresh_wallet(self.subscription_generation);
                self.fetch_transactions(self.subscription_generation);
                self.refresh_swap_pool();
                self.reconcile_swap_receipt();
            }
            Ok(dispatch) => {
                self.state.set_error(format!(
                    "The swap did not reach the network: {}",
                    outcome_detail(&dispatch.outcome)
                ));
            }
            Err(error) => {
                self.state.set_error(error.to_string());
            }
        }
    }

    pub(super) fn reconcile_swap_receipt(&mut self) {
        let Some(receipt) = self.state.swap.receipt.as_ref() else {
            return;
        };
        if receipt.settled() {
            return;
        }
        let Some(hash) = receipt.ext_msg_hash.clone() else {
            return;
        };
        let pool = receipt.pool.clone();
        let in_asset = receipt.sent.asset_id();
        let out_asset = receipt.out_asset;

        let Some((sent_lt, sent_fee)) = self
            .state
            .activity
            .iter()
            .filter(|event| settled_direction(event, ActivityDirection::Out))
            .find(|event| event.ext_msg_hash.as_ref() == Some(&hash))
            .map(|event| (event.lt, event.fee_native))
        else {
            return;
        };

        let mut received_units = None;
        let mut returned_units = None;
        let mut fee_native = sent_fee;
        for event in self
            .state
            .activity
            .iter()
            .filter(|event| settled_direction(event, ActivityDirection::In))
            .filter(|event| event.lt > sent_lt && event.counterparty == pool)
        {
            let wanted = if event.bounced { in_asset } else { out_asset };
            let Some(units) = event
                .movements
                .iter()
                .filter(|movement| movement.amount.asset_id() == wanted)
                .filter_map(|movement| base_units_u128(&movement.amount))
                .find(|units| *units > 0)
            else {
                continue;
            };
            if event.bounced {
                returned_units = Some(units);
            } else {
                received_units = Some(units);
            }
            fee_native = fee_native.saturating_add(event.fee_native);
        }

        let Some(receipt) = self.state.swap.receipt.as_mut() else {
            return;
        };
        receipt.received_units = received_units;
        receipt.returned_units = returned_units;
        receipt.fee_native = fee_native;
        if receipt.settled() {
            self.refresh_swap_pool();
        }
    }
}

async fn broadcast_all_candidates(
    chain: &dyn cc_wallet_chain::ChainService,
    prepared: &cc_wallet_chain::PreparedSwap,
) -> Result<CandidateBroadcastOutcome, ChainError> {
    let candidates = prepared.candidate_count().max(1);
    let mut last: Option<CandidateBroadcastOutcome> = None;
    for index in 0..candidates {
        let outcome = chain.broadcast_swap(prepared, index).await?;
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

fn settled_direction(event: &ActivityEvent, direction: ActivityDirection) -> bool {
    !event.pending && event.tx_hash.is_some() && event.direction == direction
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

fn send_token(asset: AssetId) -> cc_wallet_domain::SendToken {
    match asset {
        AssetId::Native => cc_wallet_domain::SendToken::Native,
        AssetId::CurrencyCollection(id) => cc_wallet_domain::SendToken::Cc(id),
    }
}
