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
            let _ = tx.send(crate::event::AppEvent::ChatPeerKeyLoaded { seq, peer, report });
        });
    }

    /// Takes the answer, or the absence of one.
    ///
    /// Deliberately not gated on the subscription generation: which peer was
    /// asked about is settled by the sequence and the address, and the wallet
    /// resubscribing in the meantime says nothing about whether this answer is
    /// still the right one. Gating on it left the conversation reading
    /// "opening…" forever whenever the two raced.
    pub(super) fn apply_chat_peer_key(
        &mut self,
        seq: u64,
        peer: String,
        report: Option<cc_wallet_chain::DestinationReport>,
    ) {
        if seq != self.chat_key_seq || self.state.chat.peer != peer {
            return;
        }
        self.state.chat.loading = false;
        self.state.chat.peer_active = report.is_some_and(|report| report.status.is_active());
        self.state.chat.peer_key_known = report.is_some_and(|report| report.encrypt_key.is_some());
        self.session.chat_peer_key = report.and_then(|report| report.encrypt_key);
        self.rebuild_chat();
    }
}

impl AppController {
    pub(super) fn set_chat_draft(&mut self, text: String) {
        self.state.chat.error.clear();
        let limit = self.state.chat.draft_limit();
        self.state.chat.draft = truncate_comment_to(&text, limit).to_owned();
    }

    /// Sends the draft as a transfer carrying it.
    ///
    /// It builds its own transfer and hands it to the same authorization every
    /// other one goes through. What it does not do is borrow the send form to
    /// carry the words there: that made the message flash through the note
    /// field of a card nobody was looking at, and a form is not a scratchpad.
    pub(super) fn send_chat_message(&mut self) {
        if !self.state.chat.can_send() {
            return;
        }
        let Some(key) = self.session.chat_peer_key else {
            self.state.chat.error = "This account publishes no key to encrypt to".to_owned();
            return;
        };
        let request = match cc_wallet_domain::SendRequest::native(
            self.state.chat.peer.clone(),
            crate::state::CHAT_ATTACH_NANOS,
        ) {
            Ok(request) => request
                .with_comment(&self.state.chat.draft)
                .sealed_to(Some(key)),
            Err(error) => {
                self.state.chat.error = error.to_string();
                return;
            }
        };
        self.state.chat.error.clear();
        self.state.chat.sending = true;
        self.authorize_transfer(request);
        // The dialog is up or it never opened; either way the waiting is over.
        self.state.chat.sending = self.pending_authorization.is_some();
    }

    /// The draft belongs to the message that carried it, exactly as the send
    /// form's own note does.
    pub(super) fn clear_chat_draft_after_send(&mut self) {
        self.state.chat.draft.clear();
        self.state.chat.sending = false;
    }
}
