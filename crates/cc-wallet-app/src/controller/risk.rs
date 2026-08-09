use cc_wallet_chain::LOCAL_SEND_FEE_CEILING_NANOS;
use cc_wallet_domain::{
    AssetAmount, AssetId, BlockerRow, Digest32, EndpointAddressInputs, RISK_WARNING_VERSION,
    Reservation, RiskGrant, RiskGrantConsumption, SendAuthorization, SendTicket,
    blocker_set_digest, evaluate_affordability, format_base_units, format_fixed9_amount,
    overlap_set_digest, reservation_set_digest,
};

use super::{AppController, PendingRiskConsumption, PendingRiskReview};
use crate::event::AppEvent;
use crate::state::{AuthModal, AuthMode, AuthPurpose, PersistenceHealth};

impl AppController {
    pub(super) fn request_risk_override(&mut self) {
        if self.pending_authorization.is_some() {
            self.state
                .set_error("A transfer authorization or duplicate-risk review is already active");
            return;
        }
        self.refresh_journal_policy();
        if !self.state.journal_blocking || !self.state.risk_override_eligible {
            self.state.set_error(
                "The duplicate-risk review is unavailable until the fresh monotonic cooling period completes",
            );
            return;
        }
        if self.state.persistence_health != PersistenceHealth::Ready
            || self.state.sending
            || self.state.busy
        {
            self.state
                .set_error("The wallet must be idle and durably writable for risk review");
            return;
        }
        if self.state.snapshot_refresh_error.is_some()
            || self.state.history_integrity_error.is_some()
        {
            self.state.set_error(
                "Duplicate-risk review is blocked until balances and transaction history complete a valid refresh",
            );
            return;
        }
        let request = match self.state.send_request() {
            Ok(request) => request,
            Err(_) => {
                self.state.set_send_form_error(
                    "Enter a valid recipient and positive amount for the new transfer before reviewing duplicate risk",
                );
                return;
            }
        };
        let inputs = match self.wallet_inputs() {
            Ok(inputs) => inputs,
            Err(error) => {
                self.state.set_error(error);
                return;
            }
        };
        let Some(sender_address) = self
            .state
            .wallet
            .as_ref()
            .map(|wallet| wallet.address.clone())
        else {
            self.state.set_error("Wallet is not loaded");
            return;
        };
        let record_id = match crate::random_ids::new_record_id() {
            Ok(value) => value,
            Err(error) => {
                self.state
                    .set_error(format!("Could not create a risk-review ticket: {error}"));
                return;
            }
        };
        let auth_nonce = match crate::random_ids::new_auth_nonce() {
            Ok(value) => value,
            Err(error) => {
                self.state
                    .set_error(format!("Could not create a risk-review nonce: {error}"));
                return;
            }
        };
        let Some(auth_generation) = self.auth_generation.checked_add(1) else {
            self.state.set_error(
                "Transfer authorization generation is exhausted; lock and reopen the wallet",
            );
            return;
        };
        self.auth_generation = auth_generation;
        let authorization = match SendAuthorization::new(
            record_id,
            self.store.name().to_owned(),
            sender_address,
            inputs,
            request,
            self.state.send_bounce(),
            auth_generation,
            auth_nonce,
        ) {
            Ok(value) => value,
            Err(error) => {
                self.state.set_error(error.to_string());
                return;
            }
        };
        let authorization_digest = match authorization.ticket().digest() {
            Ok(digest) => digest,
            Err(error) => {
                self.state.set_error(error.to_string());
                return;
            }
        };

        self.pending_authorization = Some(authorization);
        self.pending_risk_context = Some(authorization_digest);
        self.pending_risk_reconciliation = true;
        self.state.busy = true;
        self.state.status = "Checking the previous transfer before risk review…".to_owned();
        self.fetch_transactions(self.subscription_generation);
    }

    pub(super) fn finish_pending_risk_reconciliation(&mut self) {
        if !self.pending_risk_reconciliation || self.load.fetch_in_flight {
            return;
        }
        self.pending_risk_reconciliation = false;
        self.state.busy = false;
        self.refresh_journal_policy();

        if !self.state.journal_blocking {
            self.cancel_risk_override();
            return;
        }
        if self.state.history_incomplete
            || self.session.history_has_gap
            || self.state.history_integrity_error.is_some()
        {
            self.abort_risk_review(
                "Could not complete a fresh transaction-history check; risk review remains closed",
            );
            return;
        }
        if !self.state.risk_override_eligible {
            self.abort_risk_review(
                "The duplicate-risk review is unavailable until the fresh monotonic cooling period completes",
            );
            return;
        }

        let Some(authorization) = self.pending_authorization.as_ref() else {
            self.abort_risk_review("The risk-review authorization capability was lost");
            return;
        };
        let expected_digest = match authorization.ticket().digest() {
            Ok(digest) => digest,
            Err(error) => {
                self.abort_risk_review(error.to_string());
                return;
            }
        };
        let risk_inputs = match EndpointAddressInputs::new(
            authorization.ticket().endpoint_identity().to_owned(),
            authorization.ticket().sender_address().to_owned(),
        ) {
            Ok(inputs) => inputs,
            Err(error) => {
                self.abort_risk_review(error.to_string());
                return;
            }
        };
        let generation = self.session_generation;
        let chain = self.chain.clone();
        let tx = self.tx.clone();
        if self.pending_risk_context.as_ref() != Some(&expected_digest) {
            self.abort_risk_review(
                "The risk-review authorization digest changed during reconciliation",
            );
            return;
        }
        self.state.busy = true;
        self.state.status = "Refreshing balances for duplicate-risk review…".to_owned();
        self.runtime.spawn(async move {
            let event = match chain.load_wallet(&risk_inputs).await {
                Ok(snapshot) => AppEvent::RiskContextLoaded {
                    generation,
                    authorization_digest: expected_digest,
                    snapshot,
                },
                Err(error) => AppEvent::RiskContextFailed {
                    generation,
                    authorization_digest: expected_digest,
                    error: error.to_string(),
                },
            };
            let _ = tx.send(event);
        });
    }

    pub(super) fn apply_risk_context_loaded(
        &mut self,
        generation: u64,
        authorization_digest: Digest32,
        snapshot: cc_wallet_domain::WalletSnapshot,
    ) {
        if generation != self.session_generation {
            return;
        }
        if self.pending_risk_context.as_ref() != Some(&authorization_digest) {
            return;
        }
        self.state.busy = false;
        self.refresh_journal_policy();
        self.pending_risk_context = None;
        let Some(authorization) = self.pending_authorization.take() else {
            self.abort_risk_review("The risk-review authorization capability was lost");
            return;
        };
        let digest_matches = authorization
            .ticket()
            .digest()
            .is_ok_and(|digest| digest == authorization_digest);
        if !digest_matches {
            self.abort_risk_review("The risk-review authorization digest is invalid");
            return;
        }
        let network_time_matches_endpoint =
            snapshot.observed_network_time().is_some_and(|observation| {
                observation.source_endpoint() == authorization.ticket().endpoint_identity()
            });
        if !self.state.risk_override_eligible
            || snapshot.address != authorization.ticket().sender_address()
            || snapshot.global_id != authorization.ticket().network_global_id()
            || !network_time_matches_endpoint
        {
            self.abort_risk_review(
                "Risk review context changed or lacks network-time provenance from the exact authorized endpoint",
            );
            return;
        }
        self.state
            .derived_wallet_address
            .clone_from(&snapshot.address);
        self.state.wallet = Some(snapshot);
        let (blockers, reservations, broad_duplicate) =
            match self.risk_scope(authorization.ticket()) {
                Ok(value) => value,
                Err(error) => {
                    self.abort_risk_review(error);
                    return;
                }
            };
        let blocker_digest = match blocker_set_digest(&blockers) {
            Ok(value) => value,
            Err(error) => {
                self.abort_risk_review(error.to_string());
                return;
            }
        };
        let reservation_digest = match reservation_set_digest(&reservations) {
            Ok(value) => value,
            Err(error) => {
                self.abort_risk_review(error.to_string());
                return;
            }
        };
        self.pending_risk_review = Some(PendingRiskReview {
            authorization,
            blocker_digest,
            reservation_digest,
            reservations: reservations.clone(),
            broad_duplicate,
        });
        self.state.risk_overlap_labels = reservations.iter().map(reservation_label).collect();
        self.state.risk_overlap_selected = vec![false; reservations.len()];
        self.state.risk_requires_duplicate_confirmation = broad_duplicate;
        self.state.risk_review_open = true;
        self.refresh_risk_details();
    }

    pub(super) fn set_risk_overlap(&mut self, index: usize, selected: bool) {
        if !self.state.risk_review_open {
            return;
        }
        if let Some(slot) = self.state.risk_overlap_selected.get_mut(index) {
            *slot = selected;
            self.refresh_risk_details();
        }
    }

    pub(super) fn confirm_risk_override(
        &mut self,
        typed_confirmation: String,
        acknowledge_both_may_debit: bool,
        acknowledge_duplicate: bool,
    ) {
        let _ = typed_confirmation;
        if !acknowledge_both_may_debit {
            self.state
                .set_error("Acknowledge that both transfers may debit before sending this one");
            return;
        }
        let Some(review) = self.pending_risk_review.as_ref() else {
            self.state.set_error("The risk review is no longer current");
            return;
        };
        if review.broad_duplicate && !acknowledge_duplicate {
            self.state.set_error(
                "This is the same payee and asset as an unresolved transfer; the second explicit confirmation is required",
            );
            return;
        }
        self.refresh_journal_policy();
        if !self.state.risk_override_eligible {
            self.cancel_risk_override();
            self.state
                .set_error("The risk cooling context changed; start a fresh review");
            return;
        }
        let prepared_grant = (|| -> Result<_, String> {
            let review = self
                .pending_risk_review
                .as_ref()
                .ok_or_else(|| "The risk review is no longer current".to_owned())?;
            let (blockers, reservations, broad_duplicate) =
                self.risk_scope(review.authorization.ticket())?;
            let current_blockers = blocker_set_digest(&blockers).map_err(|e| e.to_string())?;
            let current_reservations =
                reservation_set_digest(&reservations).map_err(|e| e.to_string())?;
            if current_blockers != review.blocker_digest
                || current_reservations != review.reservation_digest
                || reservations != review.reservations
                || broad_duplicate != review.broad_duplicate
            {
                return Err(
                    "The blocker or reservation set changed; start a fresh duplicate-risk review"
                        .to_owned(),
                );
            }
            let overlap: Vec<Reservation> = review
                .reservations
                .iter()
                .zip(&self.state.risk_overlap_selected)
                .filter(|(_, selected)| **selected)
                .map(|(row, _)| row.clone())
                .collect();
            let ticket_digest = review
                .authorization
                .ticket()
                .digest()
                .map_err(|error| error.to_string())?;
            Ok((
                overlap,
                ticket_digest,
                review.authorization.ticket().record_id().clone(),
                review.blocker_digest.clone(),
                review.reservation_digest.clone(),
            ))
        })();
        let (overlap, ticket_digest, record_id, blocker_digest, reservation_digest) =
            match prepared_grant {
                Ok(value) => value,
                Err(error) => {
                    self.cancel_risk_override();
                    self.state.set_error(error);
                    return;
                }
            };
        let one_use_nonce = match crate::random_ids::new_risk_nonce() {
            Ok(value) => value,
            Err(error) => {
                self.state
                    .set_error(format!("Could not create a one-use risk nonce: {error}"));
                return;
            }
        };
        let overlap_digest = match overlap_set_digest(&overlap) {
            Ok(value) => value,
            Err(error) => {
                self.state.set_error(error.to_string());
                return;
            }
        };
        let grant = RiskGrant::new(
            blocker_digest,
            reservation_digest,
            ticket_digest.clone(),
            record_id.clone(),
            one_use_nonce.clone(),
            RISK_WARNING_VERSION,
            overlap_digest,
        );
        let consumption = RiskGrantConsumption::new(one_use_nonce, record_id, ticket_digest);
        if let Err(error) = self.journal.append_risk_grant(grant) {
            self.cancel_risk_override();
            self.persistence_failed(format!("could not append the one-use risk grant: {error}"));
            return;
        }
        if !self.persist_journal_barrier() {
            self.cancel_risk_override();
            return;
        }

        let Some(review) = self.pending_risk_review.take() else {
            self.persistence_failed(
                "the durable risk grant lost its exact runtime authorization capability",
            );
            return;
        };
        self.pending_risk_consumption = Some(PendingRiskConsumption {
            consumption,
            overlap,
        });
        self.pending_authorization = Some(review.authorization);
        self.state.risk_review_open = false;
        self.state.risk_review_details.clear();
        self.state.risk_overlap_labels.clear();
        self.state.risk_overlap_selected.clear();
        let mode = if self.state.within_autosign() {
            AuthMode::Confirm
        } else {
            AuthMode::Enter
        };
        self.state.auth = AuthModal {
            open: true,
            mode,
            purpose: AuthPurpose::Send,
            send_options_editable: false,
            error: String::new(),
        };
        self.state.status =
            "One-use duplicate-risk grant is durable; authenticate this exact ticket".to_owned();
    }

    pub(super) fn cancel_risk_override(&mut self) {
        let background_load =
            self.pending_risk_reconciliation || self.pending_risk_context.is_some();
        self.pending_authorization = None;
        self.pending_risk_reconciliation = false;
        self.pending_risk_context = None;
        self.pending_risk_review = None;
        self.pending_risk_consumption = None;
        if self.state.auth.purpose == AuthPurpose::Send {
            self.state.auth.open = false;
            self.state.auth.error.clear();
        }
        self.state.risk_review_open = false;
        self.state.risk_review_details.clear();
        self.state.risk_overlap_labels.clear();
        self.state.risk_overlap_selected.clear();
        self.state.risk_requires_duplicate_confirmation = false;
        if background_load && !self.state.sending {
            self.state.busy = false;
        }
    }

    pub(super) fn abort_risk_review(&mut self, message: impl Into<String>) {
        self.cancel_risk_override();
        self.state.set_error(message);
    }

    fn risk_scope(
        &self,
        ticket: &SendTicket,
    ) -> Result<(Vec<BlockerRow>, Vec<Reservation>, bool), String> {
        let relevant: Vec<_> = self.journal.blocking_records_for_scope(
            ticket.sender_wallet_id(),
            ticket.sender_address(),
            ticket.network_global_id(),
        );
        if relevant.is_empty() {
            return Err("No unresolved Journal record remains for this sender/network".to_owned());
        }
        let mut blockers = Vec::with_capacity(relevant.len());
        let mut reservations = Vec::new();
        let mut broad_duplicate = false;
        for record in relevant {
            blockers.push(
                BlockerRow::new(
                    record.ticket().record_id().clone(),
                    record.latest_evidence_tag(),
                    record.ext_msg_hash().clone(),
                )
                .map_err(|error| error.to_string())?,
            );
            reservations.extend(record.reservations().iter().cloned());
            broad_duplicate |= record.has_duplicate_fingerprint(ticket);
        }
        Ok((blockers, reservations, broad_duplicate))
    }

    fn refresh_risk_details(&mut self) {
        let Some(review) = self.pending_risk_review.as_ref() else {
            return;
        };
        let overlap: Vec<Reservation> = review
            .reservations
            .iter()
            .zip(&self.state.risk_overlap_selected)
            .filter(|(_, selected)| **selected)
            .map(|(row, _)| row.clone())
            .collect();
        let ticket = review.authorization.ticket();
        let mut text = String::new();
        text.push_str("DUPLICATE-RISK REVIEW — elapsed time is not delivery proof. Both transfers may debit; native fees may burn.\n\n");
        for record in self.journal.blocking_records_for_scope(
            ticket.sender_wallet_id(),
            ticket.sender_address(),
            ticket.network_global_id(),
        ) {
            let (symbol, amount) = exact_amount(record.ticket().request().value());
            text.push_str(&format!(
                "Blocking record {}\n  external hash {}\n  destination {}\n  asset {} amount {}\n  expiry {}\n  evidence {:?}\n",
                record.ticket().record_id(),
                record.ext_msg_hash(),
                record.ticket().request().destination(),
                symbol,
                amount,
                record.expire_at(),
                record.latest_evidence_tag(),
            ));
        }
        text.push_str("\nReservations (selection is explicit; every row remains durable):\n");
        for (index, row) in review.reservations.iter().enumerate() {
            let selected = self
                .state
                .risk_overlap_selected
                .get(index)
                .copied()
                .unwrap_or(false);
            text.push_str(&format!(
                "  [{}] {}\n",
                if selected { "OVERLAP" } else { "RESERVED" },
                reservation_label(row)
            ));
        }
        let (new_symbol, new_amount) = exact_amount(ticket.request().value());
        text.push_str(&format!(
            "\nExact new ticket\n  record {}\n  sender {}\n  network {}\n  endpoint {}\n  destination {}\n  asset {} amount {}\n  bounce {}\n  auth generation {} nonce {}\n",
            ticket.record_id(),
            ticket.sender_address(),
            ticket.network_global_id(),
            ticket.endpoint_identity(),
            ticket.request().destination(),
            new_symbol,
            new_amount,
            ticket.bounce(),
            ticket.auth_generation(),
            ticket.auth_nonce(),
        ));

        if let Some(wallet) = self.state.wallet.as_ref() {
            let mut balances = Vec::with_capacity(wallet.extra_balance().len() + 1);
            balances.push(wallet.balance_for(AssetId::Native));
            balances.extend(
                wallet
                    .extra_balance()
                    .keys()
                    .map(|&id| wallet.balance_for(AssetId::CurrencyCollection(id))),
            );
            text.push_str("\nFresh displayed balances:\n");
            for balance in &balances {
                let (symbol, amount) = exact_amount(balance);
                text.push_str(&format!("  {symbol}: {amount}\n"));
            }
            if let Ok(requested) = requested_with_fee_ceiling(ticket.request().value()) {
                match evaluate_affordability(&balances, &review.reservations, &overlap, &requested)
                {
                    Ok(report) => {
                        text.push_str("\nWorst-case aggregate debit/fees:\n");
                        for outcome in report.outcomes() {
                            let symbol = asset_label(outcome.asset());
                            match outcome.worst_case() {
                                Some(total) => {
                                    let (_, amount) = exact_amount(total);
                                    text.push_str(&format!(
                                        "  {symbol}: {amount}{}\n",
                                        if outcome.worst_case_warns() {
                                            " — exceeds fresh balance; one transfer may fail and native fees may still burn"
                                        } else {
                                            ""
                                        }
                                    ));
                                }
                                None => {
                                    text.push_str(&format!(
                                        "  {symbol}: aggregate exceeds the asset protocol maximum; exact components remain listed above\n"
                                    ));
                                }
                            }
                        }
                        if !report.is_affordable() {
                            text.push_str("Selected non-overlapped reservations make this new ticket unaffordable; final pre-sign will refuse it.\n");
                        }
                    }
                    Err(error) => text.push_str(&format!(
                        "Affordability evaluation refused the selected rows: {error}\n"
                    )),
                }
            }
        }
        text.push_str("\nSeparate encrypted vaults containing the same seed are independent; this wallet cannot coordinate a duplicate-seed copy in another file.\n");
        self.state.risk_review_details = text;
    }
}

fn requested_with_fee_ceiling(value: &AssetAmount) -> Result<Vec<AssetAmount>, String> {
    let fee =
        AssetAmount::native(LOCAL_SEND_FEE_CEILING_NANOS).map_err(|error| error.to_string())?;
    match value.asset_id() {
        AssetId::Native => value
            .checked_add_same_asset(&fee)
            .map(|total| vec![total])
            .map_err(|error| error.to_string()),
        AssetId::CurrencyCollection(_) => Ok(vec![value.clone(), fee]),
    }
}

fn exact_amount(amount: &AssetAmount) -> (String, String) {
    let symbol = asset_label(amount.asset_id());
    let rendered = format_fixed9_amount(amount).unwrap_or_else(|_| format_base_units(amount));
    (symbol, rendered)
}

fn asset_label(asset: AssetId) -> String {
    match asset {
        AssetId::Native => "Native".to_owned(),
        AssetId::CurrencyCollection(id) => format!("CurrencyCollection({id})"),
    }
}

fn reservation_label(row: &Reservation) -> String {
    let (asset, amount) = exact_amount(row.amount());
    format!(
        "record={} kind={:?} asset={} amount={}",
        row.record_id(),
        row.kind(),
        asset,
        amount
    )
}
