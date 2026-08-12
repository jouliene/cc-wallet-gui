use cc_wallet_chain::SealedComment;
use cc_wallet_domain::{
    ActivityDirection, ActivityMessage, canonicalize_recipient, truncate_comment_to,
};

struct Said {
    awaiting_chain: bool,
    lt: u64,
    time_unix: u64,
    outgoing: bool,
    pending: bool,
    message: ActivityMessage,
}

use super::AppController;
use crate::state::{ChatLine, ChatUi};

impl AppController {
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

    pub(super) fn rebuild_chat(&mut self) {
        if !self.state.chat.open {
            return;
        }
        let peer = self.state.chat.peer.clone();

        let mut carried: Vec<Said> = Vec::new();
        for event in &self.state.activity {
            let Some(message) = event.message.as_ref() else {
                continue;
            };
            if event.counterparty != peer {
                continue;
            }
            carried.push(Said {
                awaiting_chain: event.tx_hash.is_none(),
                lt: event.lt,
                time_unix: event.time_unix,
                outgoing: event.direction == ActivityDirection::Out,
                pending: event.pending,
                message: message.clone(),
            });
        }
        carried.sort_by_key(|said| (said.awaiting_chain, said.lt));

        let sealed: Vec<SealedComment<'_>> = carried
            .iter()
            .filter_map(|said| match &said.message {
                ActivityMessage::Sealed { sender_key, blob } => Some(SealedComment {
                    outgoing: said.outgoing,
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
            .map(|said| match &said.message {
                ActivityMessage::Plain { text } => ChatLine {
                    outgoing: said.outgoing,
                    time_unix: said.time_unix,
                    lt: said.lt,
                    text: text.clone(),
                    sealed: false,
                    locked: false,
                    pending: said.pending,
                },
                ActivityMessage::Sealed { .. } => {
                    let text = opened.next().flatten();
                    ChatLine {
                        outgoing: said.outgoing,
                        time_unix: said.time_unix,
                        lt: said.lt,
                        locked: text.is_none(),
                        text: text.unwrap_or_default(),
                        sealed: true,
                        pending: said.pending,
                    }
                }
            })
            .collect();
    }

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
            let report =
                super::broadcast::probe_destination(chain.as_ref(), &inputs, peer.clone()).await;
            let _ = tx.send(crate::event::AppEvent::ChatPeerKeyLoaded { seq, peer, report });
        });
    }

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
        self.spawn_fee_estimate(request.clone(), false);
        self.authorize_transfer(request);
        self.state.chat.sending = self.pending_authorization.is_some();
    }

    pub(super) fn clear_chat_draft_after_send(&mut self) {
        self.state.chat.draft.clear();
        self.state.chat.sending = false;
    }
}
