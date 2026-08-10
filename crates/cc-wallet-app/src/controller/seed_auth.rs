use std::sync::Arc;

use cc_wallet_domain::{
    ActivityEnvelope, AssetId, EnvelopeError, JournalEnvelope, SeedPhrase, SendAuthorization,
    SendRequest, WalletProfile, normalize_seed, validate_seed,
};
use cc_wallet_storage::VaultStore;
use cc_wallet_vault::{ActivitySection, Vault};
use zeroize::Zeroizing;

use super::{
    AppController, CLIPBOARD_EXHAUSTED_RETRY_DELAY, CLIPBOARD_MAX_RETRIES, CLIPBOARD_RETRY_DELAY,
    KeyAction, KeyMsg, SEED_CLIPBOARD_TTL, SecuritySetting,
};
use crate::clipboard::{Selection, clipboard_contains_seed, ct_str_eq};
use crate::command::{Password, SeedInput};
use crate::state::{AuthModal, AuthMode, AuthPurpose};

pub(super) const GATE_MSG_ACK: &str =
    "Confirm the new-address option above to send to this account";
pub(super) const GATE_MSG_FAILED: &str =
    "Could not verify the recipient account — retrying, try again in a moment";
pub(super) const GATE_MSG_PENDING: &str =
    "Still verifying the recipient account — try again in a moment";

impl AppController {
    pub(super) fn create_password(&mut self, pw: Password, pw2: Password) {
        if pw.char_count() < 8 {
            self.state.lock_error = "Use at least 8 characters".to_owned();
            return;
        }
        if pw.expose_secret() != pw2.expose_secret() {
            self.state.lock_error = "Passwords don't match".to_owned();
            return;
        }
        let profile = self.state.to_profile();
        self.spawn_create(pw, profile);
    }

    pub(super) fn unlock(&mut self, pw: Password) {
        if pw.is_empty() {
            return;
        }
        self.spawn_unlock(pw, KeyAction::Unlock);
    }

    fn spawn_unlock(&mut self, password: Password, action: KeyAction) {
        if self.state.key_busy {
            return;
        }
        if !self.drain_save_task() {
            let error =
                "Wallet data could not be saved; resolve the storage error before this action"
                    .to_owned();
            if self.state.auth.open {
                self.state.auth.error = error;
            } else {
                self.state.lock_error = error;
            }
            return;
        }
        self.state.key_busy = true;
        self.state.lock_error.clear();
        self.state.auth.error = String::new();
        match self.vault.clone() {
            Some(vault) if action.is_reauth() => {
                self.spawn_verify_password(vault, password, action)
            }
            _ => self.spawn_unlock_store(self.store.clone(), password, action),
        }
    }

    fn spawn_verify_password(
        &self,
        vault: std::sync::Arc<cc_wallet_vault::Vault>,
        password: Password,
        action: KeyAction,
    ) {
        let tx = self.key_tx.clone();
        let generation = self.key_generation;
        self.runtime.spawn_blocking(move || {
            let msg = if vault.verify_password(password.as_bytes()) {
                KeyMsg::Verified { generation, action }
            } else {
                KeyMsg::WrongPassword { generation, action }
            };
            let _ = tx.send(msg);
        });
    }

    pub(super) fn spawn_unlock_store(
        &self,
        store: VaultStore,
        password: Password,
        action: KeyAction,
    ) {
        let tx = self.key_tx.clone();
        let generation = self.key_generation;
        self.runtime.spawn_blocking(move || {
            let msg = match store.unlock(password.as_bytes()) {
                Ok(opened) => {
                    match (
                        serde_json::from_slice::<WalletProfile>(&opened.wallet),
                        JournalEnvelope::decode(&opened.journal),
                    ) {
                        (Ok(profile), Ok(journal)) => {
                            let activity: Result<(Vec<_>, bool), EnvelopeError> = match opened
                                .activity
                            {
                                ActivitySection::Absent => Ok((Vec::new(), false)),
                                ActivitySection::Corrupt => Ok((Vec::new(), true)),
                                ActivitySection::Present(bytes) => ActivityEnvelope::decode(&bytes)
                                    .map(|envelope| (envelope.into_events(), false)),
                            };
                            match activity {
                                Ok((history, history_corrupt)) => KeyMsg::Ok {
                                    generation,
                                    action,
                                    vault: opened.vault,
                                    profile,
                                    history,
                                    history_corrupt,
                                    journal,
                                    selected: Some(opened.selected),
                                    writer: Some(opened.writer),
                                },
                                Err(error) => KeyMsg::Failed {
                                    generation,
                                    action,
                                    error: format!(
                                        "This wallet's transaction history is in an unsupported \
                                         format ({error}). Update the app, or create a new wallet \
                                         and re-import your recovery phrase."
                                    ),
                                },
                            }
                        }
                        (Err(error), _) => KeyMsg::Failed {
                            generation,
                            action,
                            error: format!(
                                "This wallet can't be opened: {error} Create a new wallet and \
                                 re-import your recovery phrase."
                            ),
                        },
                        (_, Err(error)) => KeyMsg::Failed {
                            generation,
                            action,
                            error: format!(
                                "This wallet's send journal can't be opened ({error}). It may \
                                 have been written by a newer version of CC Wallet."
                            ),
                        },
                    }
                }
                Err(error) if error.is_wrong_password() => {
                    KeyMsg::WrongPassword { generation, action }
                }
                Err(error) if error.is_unsupported_format() => KeyMsg::Failed {
                    generation,
                    action,
                    error: "This wallet uses an unsupported older format and can't be \
                            opened. Go back, create a new wallet, and re-import your \
                            recovery phrase."
                        .to_string(),
                },
                Err(error) => KeyMsg::Failed {
                    generation,
                    action,
                    error: error.to_string(),
                },
            };
            let _ = tx.send(msg);
        });
    }

    fn spawn_create(&mut self, password: Password, profile: WalletProfile) {
        if self.state.key_busy {
            return;
        }
        self.state.key_busy = true;
        self.state.lock_error.clear();
        let tx = self.key_tx.clone();
        let store = self.store.clone();
        let params = self.kdf_params;
        let display_name = self.state.active_wallet.clone();
        let generation = self.key_generation;
        self.runtime.spawn_blocking(move || {
            let msg = match Vault::create_named_with(password.as_bytes(), params, &display_name) {
                Ok(vault) => match store.writer_for_new() {
                    Ok(writer) => KeyMsg::Ok {
                        generation,
                        action: KeyAction::Create,
                        vault,
                        profile,
                        history: Vec::new(),
                        history_corrupt: false,
                        journal: JournalEnvelope::empty(),
                        selected: None,
                        writer: Some(writer),
                    },
                    Err(error) => KeyMsg::Failed {
                        generation,
                        action: KeyAction::Create,
                        error: error.to_string(),
                    },
                },
                Err(error) => KeyMsg::Failed {
                    generation,
                    action: KeyAction::Create,
                    error: error.to_string(),
                },
            };
            let _ = tx.send(msg);
        });
    }

    fn spawn_change_password(&mut self, new_password: Password) {
        if self.vault.is_none() || self.state.key_busy {
            return;
        }
        if !self.drain_save_task() || !self.ensure_activity_quarantined() {
            return;
        }
        self.state.key_busy = true;
        let tx = self.key_tx.clone();
        let params = self.kdf_params;
        let profile = self.state.to_profile();
        let display_name = self.state.active_wallet.clone();
        let generation = self.key_generation;
        self.runtime.spawn_blocking(move || {
            let msg = match Vault::create_named_with(new_password.as_bytes(), params, &display_name)
            {
                Ok(vault) => KeyMsg::Ok {
                    generation,
                    action: KeyAction::ChangePassword,
                    vault,
                    profile,
                    history: Vec::new(),
                    history_corrupt: false,
                    journal: JournalEnvelope::empty(),
                    selected: None,
                    writer: None,
                },
                Err(error) => KeyMsg::Failed {
                    generation,
                    action: KeyAction::ChangePassword,
                    error: error.to_string(),
                },
            };
            let _ = tx.send(msg);
        });
    }

    pub(super) fn request_send(&mut self) {
        if self.pending_authorization.is_some() {
            self.state.auth.error =
                "A transfer authorization is already waiting for confirmation".to_owned();
            return;
        }
        if !self.state.send_enabled() {
            return;
        }
        self.state.allow_unbounced = false;
        let request = match self.state.send_request() {
            Ok(request) => request,
            Err(error) => {
                self.state.set_error(error.to_string());
                return;
            }
        };
        self.authorize_transfer(request);
    }

    /// Everything a transfer goes through once there is a transfer to make.
    ///
    /// Kept apart from the form that usually fills it in, because a reply
    /// written in a conversation is the same operation from a different screen
    /// — and routing it through the form meant the message appeared for an
    /// instant in the note field of a card the writer was not looking at.
    pub(super) fn authorize_transfer(&mut self, request: SendRequest) {
        let inputs = match self.wallet_inputs() {
            Ok(inputs) => inputs,
            Err(error) => {
                self.state.set_error(error);
                return;
            }
        };
        let record_id = match crate::random_ids::new_record_id() {
            Ok(record_id) => record_id,
            Err(error) => {
                self.state
                    .set_error(format!("Could not create a transfer record: {error}"));
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
        let sender_wallet_id = self.store.name().to_owned();
        let nonce = match crate::random_ids::new_auth_nonce() {
            Ok(nonce) => nonce,
            Err(error) => {
                self.state.set_error(format!(
                    "Could not create a transfer authorization: {error}"
                ));
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
            sender_wallet_id,
            sender_address,
            inputs,
            request,
            self.state.send_bounce(),
            self.auth_generation,
            nonce,
        ) {
            Ok(authorization) => authorization,
            Err(error) => {
                self.state.set_error(error.to_string());
                return;
            }
        };
        self.pending_authorization = Some(authorization);
        let mode = if self.state.within_autosign() {
            AuthMode::Confirm
        } else {
            AuthMode::Enter
        };
        self.state.auth = AuthModal {
            open: true,
            mode,
            purpose: AuthPurpose::Send,
            send_options_editable: true,
            error: String::new(),
        };
        self.session.fee_reestimate_at = None;
        self.check_destination();
    }

    pub(super) fn update_pending_send_unbounced(&mut self, allow: bool) -> bool {
        if !self.state.auth.open
            || self.state.auth.purpose != AuthPurpose::Send
            || self.state.sending
            || self.state.key_busy
            || !self.state.recipient_inactive()
            || self.pending_risk_consumption.is_some()
        {
            return false;
        }
        let Some(authorization) = self.pending_authorization.take() else {
            return false;
        };
        let (inputs, ticket) = authorization.into_parts();
        let replacement = SendAuthorization::new(
            ticket.record_id().clone(),
            ticket.sender_wallet_id().to_owned(),
            ticket.sender_address().to_owned(),
            inputs,
            ticket.request().clone(),
            !allow,
            ticket.auth_generation(),
            ticket.auth_nonce(),
        );
        match replacement {
            Ok(authorization) => {
                self.pending_authorization = Some(authorization);
                self.state.allow_unbounced = allow;
                self.state.auth.error.clear();
            }
            Err(error) => {
                self.state.auth.open = false;
                self.state.set_error(format!(
                    "Could not update the new-address transfer option: {error}"
                ));
            }
        }
        true
    }

    pub(super) fn change_password_request(&mut self) {
        self.state.auth = AuthModal {
            open: true,
            mode: AuthMode::Enter,
            purpose: AuthPurpose::ChangePassword,
            send_options_editable: false,
            error: String::new(),
        };
    }

    pub(super) fn request_security_setting(&mut self, setting: SecuritySetting) {
        let unchanged = match setting {
            SecuritySetting::AutoSign(mins) => mins == self.state.autosign_mins,
            SecuritySetting::ScreenLock(mins) => mins == self.state.screen_lock_mins,
        };
        if unchanged {
            return;
        }
        self.pending_security_setting = Some(setting);
        self.state.auth = AuthModal {
            open: true,
            mode: AuthMode::Enter,
            purpose: AuthPurpose::ChangeSecuritySetting,
            send_options_editable: false,
            error: String::new(),
        };
    }

    pub(super) fn apply_security_setting(&mut self, setting: SecuritySetting) {
        match setting {
            SecuritySetting::AutoSign(mins) => self.state.autosign_mins = mins,
            SecuritySetting::ScreenLock(mins) => self.state.screen_lock_mins = mins,
        }
        self.save_profile();
    }

    pub(super) fn cancel_auth(&mut self) {
        self.invalidate_key_ops();
        self.state.auth.open = false;
        self.state.auth.error = String::new();
        self.state.allow_unbounced = false;
        self.pending_security_setting = None;
        self.clear_pending_swap();
        self.clear_pending_storage();
    }

    pub(super) fn refuse_unpermitted_send(&mut self) -> bool {
        let risk_flow = !self.state.auth.send_options_editable;
        if self.state.signing_recipient_permitted(risk_flow) {
            return false;
        }
        self.state.auth.error = match self.state.recipient_check {
            crate::state::RecipientCheck::Known(_) => GATE_MSG_ACK.to_owned(),
            crate::state::RecipientCheck::Failed => {
                self.check_destination();
                GATE_MSG_FAILED.to_owned()
            }
            _ => GATE_MSG_PENDING.to_owned(),
        };
        true
    }

    pub(super) fn auth_submit(&mut self, pw: Password, pw2: Password, remember: bool) {
        if !self.state.auth.open || self.state.key_busy {
            return;
        }
        match (self.state.auth.mode, self.state.auth.purpose) {
            (AuthMode::Confirm, AuthPurpose::Send) => {
                if !self.state.within_autosign() {
                    self.state.auth.mode = AuthMode::Enter;
                    self.state.auth.error =
                        "Auto-sign expired — enter your password to confirm".to_owned();
                    return;
                }
                if self.refuse_unpermitted_send() {
                    return;
                }
                let Some(authorization) = self.pending_authorization.take() else {
                    self.state.auth.error =
                        "The transfer authorization no longer exists".to_owned();
                    return;
                };
                self.state.auth.open = false;
                if remember {
                    self.state.extend_autosign();
                }
                self.send_authorized_transaction(authorization);
            }
            (AuthMode::Enter, AuthPurpose::Send) => {
                if self.refuse_unpermitted_send() {
                    return;
                }
                let Some(authorization) = self.pending_authorization.as_ref() else {
                    self.state.auth.error =
                        "The transfer authorization no longer exists".to_owned();
                    return;
                };
                self.spawn_unlock(
                    pw,
                    KeyAction::ConfirmSend {
                        remember,
                        auth_generation: authorization.generation(),
                        auth_nonce: authorization.nonce(),
                    },
                );
            }
            (AuthMode::Confirm, AuthPurpose::Swap) => {
                if !self.state.within_autosign() {
                    self.state.auth.mode = AuthMode::Enter;
                    self.state.auth.error =
                        "Auto-sign expired — enter your password to confirm".to_owned();
                    return;
                }
                if self.pending_swap.is_none() {
                    self.state.auth.error = "The swap authorization no longer exists".to_owned();
                    return;
                }
                self.state.auth.open = false;
                if remember {
                    self.state.extend_autosign();
                }
                self.dispatch_authorized_swap();
            }
            (AuthMode::Enter, AuthPurpose::Swap) => {
                let Some(pending) = self.pending_swap.as_ref() else {
                    self.state.auth.error = "The swap authorization no longer exists".to_owned();
                    return;
                };
                self.spawn_unlock(
                    pw,
                    KeyAction::ConfirmSwap {
                        remember,
                        generation: pending.generation,
                    },
                );
            }
            (AuthMode::Confirm, AuthPurpose::Storage) => {
                if !self.state.within_autosign() {
                    self.state.auth.mode = AuthMode::Enter;
                    self.state.auth.error =
                        "Auto-sign expired — enter your password to confirm".to_owned();
                    return;
                }
                if self.pending_storage.is_none() {
                    self.state.auth.error = "The storage authorization no longer exists".to_owned();
                    return;
                }
                self.state.auth.open = false;
                if remember {
                    self.state.extend_autosign();
                }
                self.dispatch_authorized_storage();
            }
            (AuthMode::Enter, AuthPurpose::Storage) => {
                let Some(pending) = self.pending_storage.as_ref() else {
                    self.state.auth.error = "The storage authorization no longer exists".to_owned();
                    return;
                };
                self.spawn_unlock(
                    pw,
                    KeyAction::ConfirmStorage {
                        remember,
                        generation: pending.generation,
                    },
                );
            }
            (AuthMode::Enter, AuthPurpose::ChangePassword) => {
                self.spawn_unlock(pw, KeyAction::VerifyForChangePassword);
            }
            (AuthMode::Create, AuthPurpose::ChangePassword) => {
                if pw.char_count() < 8 {
                    self.state.auth.error = "Use at least 8 characters".to_owned();
                    return;
                }
                if pw.expose_secret() != pw2.expose_secret() {
                    self.state.auth.error = "Passwords don't match".to_owned();
                    return;
                }
                self.spawn_change_password(pw);
            }
            (AuthMode::Enter, AuthPurpose::RevealRecords) => {
                self.spawn_unlock(pw, KeyAction::RevealRecords);
            }
            (AuthMode::Enter, AuthPurpose::RevealSeed) => {
                self.spawn_unlock(pw, KeyAction::RevealSeed);
            }
            (AuthMode::Enter, AuthPurpose::DeleteWallet) => {
                self.spawn_unlock(pw, KeyAction::DeleteWallet);
            }
            (AuthMode::Enter, AuthPurpose::ChangeSecuritySetting) => {
                let Some(setting) = self.pending_security_setting else {
                    self.state.auth.error = "The setting change is no longer pending".to_owned();
                    return;
                };
                self.spawn_unlock(pw, KeyAction::ApplySecuritySetting(setting));
            }
            _ => {}
        }
    }

    pub(super) fn reveal_seed(&mut self) {
        self.state.auth = AuthModal {
            open: true,
            mode: AuthMode::Enter,
            purpose: AuthPurpose::RevealSeed,
            send_options_editable: false,
            error: String::new(),
        };
    }

    pub(super) fn show_seed_for_one_minute(&mut self) {
        self.state.show_seed = true;
        self.state.seed_reveal_deadline = Some(crate::state::Deadline::after(
            std::time::Duration::from_secs(60),
        ));
    }

    pub(super) fn hide_seed(&mut self) {
        self.clear_seed_from_clipboard();
        self.state.show_seed = false;
        self.state.seed_reveal_deadline = None;
    }

    pub(super) fn copy_seed_to_clipboard(&mut self, phrase: SeedInput) {
        let phrase = phrase.into_zeroizing();
        let phrase = Zeroizing::new(normalize_seed(&phrase));
        if phrase.is_empty() {
            return;
        }
        self.clear_seed_from_clipboard();
        let prior_wipe_unresolved = self.clipboard_secret.is_some();
        match self.clipboard.set(Selection::Clipboard, &phrase) {
            Ok(()) => {
                self.extend_tracked_clipboard_secret(phrase, prior_wipe_unresolved);
                self.clipboard_copy_explicit = true;
                if self.state.seed_reveal_deadline.is_some() {
                    self.state.seed_reveal_deadline =
                        Some(crate::state::Deadline::after(SEED_CLIPBOARD_TTL));
                }
                if prior_wipe_unresolved {
                    self.state.clipboard_notice = "A prior recovery phrase could not be cleared; retrying every tracked phrase automatically."
                        .to_owned();
                } else {
                    self.state.clipboard_notice.clear();
                }
            }
            Err(error) => {
                eprintln!("cc-wallet: could not copy to the clipboard: {error}");
                if prior_wipe_unresolved {
                    self.state.clipboard_notice = "Could not copy the new phrase; the wallet is still retrying cleanup of a prior recovery phrase."
                        .to_owned();
                } else {
                    self.clipboard_secret = None;
                    self.clipboard_deadline = None;
                    self.state.clipboard_notice =
                        "Could not copy to the clipboard. Write the phrase down instead."
                            .to_owned();
                }
            }
        }
        self.refresh_seed_copy_ttl();
    }

    pub(super) fn copy_secret_to_clipboard(&mut self, secret: Zeroizing<String>) {
        if secret.is_empty() {
            return;
        }
        self.clear_seed_from_clipboard();
        let prior_wipe_unresolved = self.clipboard_secret.is_some();
        match self.clipboard.set(Selection::Clipboard, &secret) {
            Ok(()) => {
                self.extend_tracked_clipboard_secret(secret, prior_wipe_unresolved);
                self.clipboard_copy_explicit = true;
                self.state.clipboard_notice.clear();
            }
            Err(error) => {
                eprintln!("cc-wallet: could not copy to the clipboard: {error}");
                self.clipboard_secret = None;
                self.clipboard_deadline = None;
                self.state.clipboard_notice = "Could not copy to the clipboard.".to_owned();
            }
        }
        self.refresh_seed_copy_ttl();
    }

    pub(super) fn refresh_seed_copy_ttl(&mut self) {
        self.state.seed_copy_ttl_secs = if self.clipboard_copy_explicit
            && self.clipboard_secret.is_some()
            && self.state.clipboard_notice.is_empty()
        {
            self.clipboard_deadline
                .map(|deadline| deadline.remaining_secs())
                .unwrap_or(0)
        } else {
            0
        };
    }

    fn extend_tracked_clipboard_secret(&mut self, phrase: Zeroizing<String>, retry_soon: bool) {
        let had_existing = self.clipboard_secret.is_some();
        let tracked = match self.clipboard_secret.take() {
            Some(existing)
                if existing
                    .lines()
                    .any(|entry| ct_str_eq(entry, phrase.as_str())) =>
            {
                existing
            }
            Some(existing) => {
                let capacity = existing.len() + 1 + phrase.len();
                let mut combined = Zeroizing::new(String::with_capacity(capacity));
                combined.push_str(&existing);
                combined.push('\n');
                combined.push_str(&phrase);
                combined
            }
            None => phrase,
        };
        self.clipboard_secret = Some(tracked);
        self.clipboard_deadline = Some(crate::state::Deadline::after(if retry_soon {
            CLIPBOARD_RETRY_DELAY
        } else {
            SEED_CLIPBOARD_TTL
        }));
        if !had_existing {
            self.clipboard_retries = 0;
        }
    }

    pub(super) fn copy_text(&mut self, text: &str) {
        if let Err(error) = self.clipboard.set(Selection::Clipboard, text) {
            eprintln!("cc-wallet: could not copy to the clipboard: {error}");
        } else {
            self.clipboard_copy_explicit = false;
            self.refresh_seed_copy_ttl();
        }
    }

    pub(super) fn clear_seed_from_clipboard(&mut self) {
        self.clipboard_deadline = None;
        let Some(secret) = self.clipboard_secret.take() else {
            self.clipboard_copy_explicit = false;
            self.refresh_seed_copy_ttl();
            return;
        };
        let mut unresolved = false;

        for selection in [Selection::Clipboard, Selection::Primary] {
            match self.clipboard.get(selection) {
                Ok(current) => {
                    let current = Zeroizing::new(current);
                    if tracked_clipboard_contains_seed(&current, &secret, selection)
                        && let Err(error) = self.clipboard.set(selection, "")
                    {
                        eprintln!(
                            "cc-wallet: could not clear {}: {error}",
                            selection_name(selection)
                        );
                        unresolved = true;
                    }
                }
                Err(error) => {
                    eprintln!(
                        "cc-wallet: could not read {} to clear it: {error}",
                        selection_name(selection)
                    );
                    unresolved = true;
                }
            }
        }

        if unresolved {
            if self.clipboard_retries < CLIPBOARD_MAX_RETRIES {
                self.clipboard_retries += 1;
                self.clipboard_secret = Some(secret);
                self.clipboard_deadline =
                    Some(crate::state::Deadline::after(CLIPBOARD_RETRY_DELAY));
                self.state.clipboard_notice =
                    "Could not clear every clipboard selection; retrying automatically.".to_owned();
            } else {
                self.clipboard_secret = Some(secret);
                self.clipboard_deadline = Some(crate::state::Deadline::after(
                    CLIPBOARD_EXHAUSTED_RETRY_DELAY,
                ));
                self.note_clipboard_wipe_failed();
            }
        } else {
            self.clipboard_retries = 0;
            self.state.clipboard_notice.clear();
            self.clipboard_copy_explicit = false;
        }
        self.refresh_seed_copy_ttl();
    }

    fn note_clipboard_wipe_failed(&mut self) {
        self.state.clipboard_notice =
            "Could not clear the clipboard automatically. Clear it yourself.".to_owned();
    }

    pub(super) fn generate_seed(&mut self) {
        self.clear_seed_from_clipboard();
        match self.chain.generate_seed() {
            Ok(seed) => {
                self.stop_subscription();
                self.state.seed = Arc::new(seed);
                self.state.seed_backup_confirmed = false;
                self.state.seed_saved = false;
                self.state.seed_editing = true;
                self.state.show_seed = true;
                self.state.seed_unsaved = true;
                self.state.wallet = None;
                self.state.status =
                    "New phrase generated. Use it to replace your wallet.".to_owned();
                self.state.error = None;
            }
            Err(error) => self
                .state
                .set_error(format!("failed to generate seed: {error}")),
        }
    }

    pub(super) fn onboard_import_seed(&mut self, seed: SeedInput) {
        let seed = seed.into_zeroizing();
        let seed = Zeroizing::new(normalize_seed(&seed));
        if !ct_str_eq(seed.as_str(), self.state.seed.expose_secret()) {
            self.state.seed_backup_confirmed = false;
        }
        if self
            .clipboard_secret
            .as_ref()
            .is_some_and(|copied| !ct_str_eq(copied.as_str(), seed.as_str()))
        {
            self.clear_seed_from_clipboard();
        }
        if crate::seed_phrase_is_valid(&seed) {
            self.state.seed = SeedPhrase::shared_zeroizing(seed);
            self.state.onboard_import_valid = true;
            let seed = Arc::clone(&self.state.seed);
            self.register_pasted_seed_for_wipe(seed.expose_secret());
        } else {
            self.state.seed = SeedPhrase::empty_shared();
            self.state.onboard_import_valid = false;
        }
    }

    fn register_pasted_seed_for_wipe(&mut self, seed: &str) {
        if self
            .clipboard_secret
            .as_ref()
            .is_some_and(|held| held.lines().any(|tracked| ct_str_eq(tracked, seed)))
        {
            return;
        }
        let mut clipboard_holds_seed = false;
        let mut read_failed = false;
        for selection in [Selection::Clipboard, Selection::Primary] {
            match self.clipboard.get(selection) {
                Ok(current) => {
                    let current = Zeroizing::new(current);
                    clipboard_holds_seed |= clipboard_contains_seed(&current, seed, selection);
                }
                Err(error) => {
                    eprintln!(
                        "cc-wallet: could not inspect {} for a pasted seed: {error}",
                        selection_name(selection)
                    );
                    read_failed = true;
                }
            }
        }
        if clipboard_holds_seed || read_failed {
            let prior_wipe_unresolved = self.clipboard_secret.is_some();
            self.extend_tracked_clipboard_secret(
                Zeroizing::new(seed.to_owned()),
                read_failed || prior_wipe_unresolved,
            );
            if read_failed {
                self.state.clipboard_notice =
                    "Could not inspect every clipboard selection; retrying automatically."
                        .to_owned();
            } else if prior_wipe_unresolved {
                self.state.clipboard_notice = "A prior recovery phrase could not be cleared; retrying every tracked phrase automatically."
                    .to_owned();
            }
            self.refresh_seed_copy_ttl();
        }
    }

    pub(super) fn save_seed(&mut self, seed: SeedInput) {
        let seed = seed.into_zeroizing();
        let seed = Zeroizing::new(normalize_seed(&seed));
        if let Err(error) = validate_seed(&seed) {
            self.state.set_error(error.to_string());
            return;
        }
        self.register_pasted_seed_for_wipe(&seed);
        self.activate_seed(SeedPhrase::shared_zeroizing(seed));
    }

    fn activate_seed(&mut self, seed: Arc<SeedPhrase>) {
        self.stop_subscription();
        self.chain.clear_config_cache();
        self.forget_traces();
        self.state.seed = seed;
        self.state.confirmed_seed = Arc::clone(&self.state.seed);
        self.state.seed_saved = true;
        self.state.seed_editing = false;
        self.hide_seed();
        self.state.seed_unsaved = false;
        self.state.visible_cc_assets.clear();
        self.state.select_asset(AssetId::Native);
        self.state.derived_wallet_address.clear();
        self.state.wallet = None;
        self.state.activity.clear();
        // A conversation belongs to the wallet that could read it.
        self.close_chat();
        self.session.pending_sends.clear();
        self.session.awaiting_send_lt = None;
        self.session.in_flight_record_id = None;
        self.session.history_synced_floor = None;
        self.session.history_has_gap = true;
        self.load.history_reconciliation_scan = None;
        self.state.reset_recipient_status();
        self.state.fee_estimate = None;
        self.state.fee_estimating = false;
        self.reset_swap_for_new_identity();
        self.reset_storage_for_new_identity();
        self.save_profile();
        self.save_history();
        self.refresh_wallet();
    }

    pub(super) fn use_seed(&mut self) {
        let seed = Arc::clone(&self.state.seed);
        self.activate_seed(seed);
    }

    pub(super) fn discard_seed(&mut self) {
        self.state.seed = Arc::clone(&self.state.confirmed_seed);
        self.state.seed_saved = !self.state.seed.is_empty();
        self.state.seed_unsaved = false;
        self.hide_seed();
        self.state.status = "Discarded unsaved phrase".to_owned();
    }
}

fn selection_name(selection: Selection) -> &'static str {
    match selection {
        Selection::Clipboard => "the clipboard",
        Selection::Primary => "the PRIMARY selection",
    }
}

fn tracked_clipboard_contains_seed(current: &str, tracked: &str, selection: Selection) -> bool {
    tracked
        .lines()
        .any(|secret| clipboard_contains_seed(current, secret, selection))
}
