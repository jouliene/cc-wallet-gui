use cc_wallet_chain::SealedComment;
use cc_wallet_domain::{
    ActivityDirection, ActivityMessage, canonicalize_recipient, truncate_comment_to,
};

use super::AppController;
use crate::state::{ChatLine, ChatUi};

impl AppController {
    /// Opens the conversation with one address over the activity list.
    ///
    /// The messages are already in hand — this only narrows them to one
    /// counterparty and puts them in the order they were said. What is not in
    /// hand is the key that opens the sealed ones, so that is asked for
    /// separately and the lines are rebuilt when it arrives.
    pub(super) fn open_chat(&mut self, peer: String) {
        let Ok(peer) = canonicalize_recipient(&peer) else {
            return;
        };
        self.state.chat = ChatUi {
            open: true,
            peer,
            ..ChatUi::default()
        };
        self.rebuild_chat();
        self.fetch_chat_peer_key();
    }

    pub(super) fn close_chat(&mut self) {
        self.state.chat = ChatUi::default();
        self.chat_key_seq = self.chat_key_seq.wrapping_add(1);
    }

    /// Rebuilds the open conversation from the activity as it now stands.
    ///
    /// Called again whenever the history moves, because a conversation that
    /// froze at the moment it was opened would quietly stop being one.
    pub(super) fn rebuild_chat(&mut self) {
        if !self.state.chat.open {
            return;
        }
        let peer = self.state.chat.peer.clone();

        let mut carried: Vec<(u64, u64, bool, bool, ActivityMessage)> = Vec::new();
        for event in &self.state.activity {
            let Some(message) = event.message.as_ref() else {
                continue;
            };
            if event.counterparty != peer {
                continue;
            }
            carried.push((
                event.lt,
                event.time_unix,
                event.direction == ActivityDirection::Out,
                event.pending,
                message.clone(),
            ));
        }
        carried.sort_by_key(|(lt, ..)| *lt);

        let sealed: Vec<SealedComment<'_>> = carried
            .iter()
            .filter_map(|(_, _, outgoing, _, message)| match message {
                ActivityMessage::Sealed { sender_key, blob } => Some(SealedComment {
                    outgoing: *outgoing,
                    sender_key: sender_key.as_bytes(),
                    blob,
                }),
                ActivityMessage::Plain { .. } => None,
            })
            .collect();

        let opened = self.open_sealed(&peer, &sealed);
        let mut opened = opened.into_iter();

        self.state.chat.lines = carried
            .iter()
            .map(
                |(lt, time_unix, outgoing, pending, message)| match message {
                    ActivityMessage::Plain { text } => ChatLine {
                        outgoing: *outgoing,
                        time_unix: *time_unix,
                        lt: *lt,
                        text: text.clone(),
                        sealed: false,
                        locked: false,
                        pending: *pending,
                    },
                    ActivityMessage::Sealed { .. } => {
                        let text = opened.next().flatten();
                        ChatLine {
                            outgoing: *outgoing,
                            time_unix: *time_unix,
                            lt: *lt,
                            locked: text.is_none(),
                            text: text.unwrap_or_default(),
                            sealed: true,
                            pending: *pending,
                        }
                    }
                },
            )
            .collect();
    }

    /// The plaintext of each sealed message, in the order given.
    ///
    /// Everything comes back locked rather than erroring when the wallet has no
    /// keys to hand: a conversation is readable exactly when the wallet is
    /// open, and saying so with a padlock beats saying so with a failure.
    fn open_sealed(&mut self, peer: &str, sealed: &[SealedComment<'_>]) -> Vec<Option<String>> {
        if sealed.is_empty() {
            return Vec::new();
        }
        let Ok(inputs) = self.wallet_inputs() else {
            return vec![None; sealed.len()];
        };
        let peer_key = self.session.chat_peer_key;
        match self
            .chain
            .open_conversation(&inputs, peer, peer_key.as_ref(), sealed)
        {
            Ok(opened) => opened,
            Err(error) => {
                self.state.chat.error = error.to_string();
                vec![None; sealed.len()]
            }
        }
    }

    /// Asks the peer's account for the key that opens what we sent them.
    ///
    /// Their own messages carry the key they used, but ours name us, so without
    /// this one read every message this wallet wrote stays shut to its author.
    fn fetch_chat_peer_key(&mut self) {
        self.session.chat_peer_key = None;
        self.chat_key_seq = self.chat_key_seq.wrapping_add(1);
        let seq = self.chat_key_seq;
        let peer = self.state.chat.peer.clone();
        let Ok(inputs) = self.endpoint_address_inputs() else {
            return;
        };
        self.state.chat.loading = true;
        let chain = self.chain.clone();
        let tx = self.tx.clone();
        self.runtime.spawn(async move {
            let report = tokio::time::timeout(
                std::time::Duration::from_secs(12),
                chain.check_destination(&inputs, peer.clone()),
            )
            .await
            .ok()
            .and_then(Result::ok);
            let _ = tx.send(crate::event::AppEvent::ChatPeerKeyLoaded {
                seq,
                peer,
                key: report.and_then(|report| report.encrypt_key),
            });
        });
    }

    /// Takes the answer, or the absence of one.
    ///
    /// Deliberately not gated on the subscription generation: which peer was
    /// asked about is settled by the sequence and the address, and the wallet
    /// resubscribing in the meantime says nothing about whether this answer is
    /// still the right one. Gating on it left the conversation reading
    /// "opening…" forever whenever the two raced.
    pub(super) fn apply_chat_peer_key(&mut self, seq: u64, peer: String, key: Option<[u8; 32]>) {
        if seq != self.chat_key_seq || self.state.chat.peer != peer {
            return;
        }
        self.state.chat.loading = false;
        self.state.chat.peer_key_known = key.is_some();
        self.session.chat_peer_key = key;
        self.rebuild_chat();
    }
}

impl AppController {
    pub(super) fn set_chat_draft(&mut self, text: String) {
        self.state.chat.error.clear();
        let limit = self.state.chat.draft_limit();
        self.state.chat.draft = truncate_comment_to(&text, limit).to_owned();
    }

    pub(super) fn set_chat_encrypt(&mut self, on: bool) {
        // Sealing is only on offer when the other end publishes a key, and
        // turning it on costs seventy-three bytes of the budget — so the draft
        // is cut to the new limit at the moment the limit changes, not at the
        // moment it is sent.
        self.state.chat.encrypt = on && self.state.chat.peer_key_known;
        let limit = self.state.chat.draft_limit();
        self.state.chat.draft = truncate_comment_to(&self.state.chat.draft, limit).to_owned();
    }

    /// Sends the draft as a transfer carrying it.
    ///
    /// There is one sender in this wallet and this is not a second one: the
    /// send form is filled in with what the conversation means, and the same
    /// authorization, the same gates and the same signing dialog do the rest.
    /// The form is on screen above the conversation, so what it shows is what
    /// is about to happen.
    pub(super) fn send_chat_message(&mut self) {
        if !self.state.chat.can_send() {
            return;
        }
        self.state.clear_send_form_error();
        self.state.select_asset(cc_wallet_domain::AssetId::Native);
        self.state.send_form.token = cc_wallet_domain::SendToken::Native;
        self.state.send_form.amount =
            cc_wallet_domain::format_native_fixed9(crate::state::CHAT_ATTACH_NANOS)
                .expect("one nano is in the native domain");
        self.state.send_form.comment = self.state.chat.draft.clone();
        self.state.send_form.destination = self.state.chat.peer.clone();
        // Editing the destination invalidates what was known about the last
        // one, including the key a comment would be sealed to, so the intention
        // to seal is held here until the account answers again.
        self.state.reset_recipient_status();
        self.state.chat.sending = true;
        self.check_destination();
        self.advance_chat_send();
    }

    /// Carries an asked-for reply forward once the recipient's account answers.
    ///
    /// Authorizing before the answer arrives is refused downstream with "the
    /// recipient account state is not verified yet", so the wait is held here
    /// rather than shown to whoever pressed send.
    pub(super) fn advance_chat_send(&mut self) {
        if !self.state.chat.sending {
            return;
        }
        match self.state.recipient_check {
            crate::state::RecipientCheck::Known(status) if status.is_active() => {
                self.state.chat.sending = false;
                self.state.send_form.encrypt =
                    self.state.chat.encrypt && self.state.recipient_encrypt_key.is_some();
                self.request_send();
            }
            crate::state::RecipientCheck::Known(_) => {
                self.state.chat.sending = false;
                self.state.chat.error =
                    "This account is not active, so it cannot be written to".to_owned();
            }
            crate::state::RecipientCheck::Failed => {
                self.state.chat.sending = false;
                self.state.chat.error = "Could not read this recipient's account".to_owned();
            }
            _ => {}
        }
    }

    /// The draft belongs to the message that carried it, exactly as the send
    /// form's own note does.
    pub(super) fn clear_chat_draft_after_send(&mut self) {
        self.state.chat.draft.clear();
        self.state.chat.sending = false;
    }
}
