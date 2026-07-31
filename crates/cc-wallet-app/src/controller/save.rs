use std::sync::Arc;
use std::time::{Duration, Instant};

use cc_wallet_domain::{ActivityEnvelope, ActivityEvent};
use zeroize::Zeroizing;

use super::AppController;
use crate::state::{AppPhase, PersistenceHealth};

struct CurrentPayloads {
    profile: Zeroizing<Vec<u8>>,
    journal: Vec<u8>,
    activity: Option<Vec<u8>>,
}

impl AppController {
    pub(super) fn save_profile(&mut self) {
        self.mark_dirty();
    }

    pub(super) fn save_history(&mut self) {
        self.mark_dirty();
    }

    fn mark_dirty(&mut self) {
        if self.vault.is_none() || self.state.persistence_health == PersistenceHealth::Failed {
            return;
        }
        self.dirty = true;
        if self.save_deadline.is_none() {
            self.save_deadline = Some(Instant::now() + Duration::from_millis(600));
        }
    }

    pub(super) fn persist_journal_barrier(&mut self) -> bool {
        if self.vault.is_none() || self.state.persistence_health == PersistenceHealth::Failed {
            return false;
        }
        self.dirty = true;
        self.save_deadline = None;
        self.flush_save_blocking()
    }

    pub(super) fn persist_new_container(&mut self) {
        self.dirty = true;
        self.save_deadline = None;
        self.flush_save();
    }

    fn current_payloads(&mut self) -> Result<CurrentPayloads, String> {
        let profile = self.state.to_profile().encode();
        let activity = self.encoded_activity()?;
        Ok(CurrentPayloads {
            profile,
            journal: self.journal.encode(),
            activity,
        })
    }

    fn encoded_activity(&mut self) -> Result<Option<Vec<u8>>, String> {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        for event in self
            .state
            .activity
            .iter()
            .filter(|event| event.tx_hash.is_some())
        {
            event.hash(&mut hasher);
        }
        let hash = hasher.finish();
        if self
            .activity_payload_cache
            .as_ref()
            .map(|(cached, _)| *cached)
            != Some(hash)
        {
            let persisted: Vec<ActivityEvent> = self
                .state
                .activity
                .iter()
                .filter(|event| event.tx_hash.is_some())
                .cloned()
                .collect();
            let encoded = if persisted.is_empty() {
                None
            } else {
                Some(
                    ActivityEnvelope::new(persisted)
                        .encode()
                        .map_err(|error| format!("could not encode Activity: {error}"))?,
                )
            };
            #[cfg(test)]
            self.activity_encode_count
                .set(self.activity_encode_count.get() + 1);
            self.activity_payload_cache = Some((hash, encoded));
        }
        Ok(self
            .activity_payload_cache
            .as_ref()
            .expect("just populated")
            .1
            .clone())
    }

    pub(super) fn persistence_failed(&mut self, detail: impl Into<String>) {
        if let Some(writer) = self.writer.as_mut()
            && !writer.has_pending_write()
        {
            let _ = writer.poison();
        }
        self.state.persistence_health = PersistenceHealth::Failed;
        self.dirty = true;
        self.save_deadline = None;
        let message = format!(
            "Wallet persistence failed; signing and lifecycle transitions are blocked: {}",
            detail.into()
        );
        self.state.persistence_error = Some(message.clone());
        self.state.set_error(message);
    }

    pub(super) fn ensure_activity_quarantined(&mut self) -> bool {
        let Some(selected) = self.session.activity_quarantine_pending.clone() else {
            return self.state.persistence_health != PersistenceHealth::Failed;
        };
        if self.save_task.is_some()
            || self
                .writer
                .as_ref()
                .is_some_and(|writer| writer.has_pending_write())
        {
            return false;
        }
        match self.store.quarantine_selected(&selected) {
            Ok(_) => {
                self.session.activity_quarantine_pending = None;
                self.state.persistence_health = PersistenceHealth::Ready;
                true
            }
            Err(error) => {
                self.persistence_failed(format!(
                    "could not preserve the damaged history before saving: {error}"
                ));
                false
            }
        }
    }

    pub(super) fn flush_save(&mut self) {
        if self
            .save_task
            .as_ref()
            .is_some_and(tokio::task::JoinHandle::is_finished)
            && !self.drain_save_task()
        {
            return;
        }
        if !self.dirty
            || self.state.phase != AppPhase::Unlocked
            || self.state.key_busy
            || self.state.persistence_health == PersistenceHealth::Failed
        {
            return;
        }
        if self.save_task.is_some() {
            return;
        }
        if !self.ensure_activity_quarantined() {
            return;
        }
        let payloads = match self.current_payloads() {
            Ok(payloads) => payloads,
            Err(error) => {
                self.persistence_failed(error);
                return;
            }
        };
        let Some(vault) = self.vault.as_ref().map(Arc::clone) else {
            self.persistence_failed("the authenticated vault writer is unavailable");
            return;
        };
        let Some(mut writer) = self.writer.take() else {
            self.persistence_failed("the authenticated vault writer is unavailable");
            return;
        };
        self.dirty = false;
        self.save_deadline = None;
        self.state.persistence_health = PersistenceHealth::WritePending;
        self.save_task = Some(self.runtime.spawn_blocking(move || {
            let result = match writer.prepare(
                &vault,
                &payloads.profile,
                &payloads.journal,
                payloads.activity.as_deref(),
            ) {
                Ok(prepared) => writer.consume(prepared.execute()),
                Err(error) => Err(error),
            };
            (writer, result)
        }));
    }

    pub(super) fn drain_save_task(&mut self) -> bool {
        let Some(handle) = self.save_task.take() else {
            return self.state.persistence_health != PersistenceHealth::Failed;
        };
        match self.runtime.block_on(handle) {
            Ok((writer, result)) => {
                self.writer = Some(writer);
                match result {
                    Ok(_) if self.state.persistence_health == PersistenceHealth::Failed => {
                        if let Some(writer) = self.writer.as_mut() {
                            let _ = writer.poison();
                        }
                        false
                    }
                    Ok(_) => {
                        self.state.persistence_health = PersistenceHealth::Ready;
                        if self.state.error.is_none() {
                            self.state.status = "Saved".to_owned();
                        }
                        if self.dirty && self.save_deadline.is_none() {
                            self.save_deadline = Some(Instant::now());
                        }
                        true
                    }
                    Err(error) => {
                        self.persistence_failed(error.to_string());
                        false
                    }
                }
            }
            Err(_join_error) => {
                self.persistence_failed("a started write lost its authenticated writer");
                false
            }
        }
    }

    pub(super) fn flush_save_blocking(&mut self) -> bool {
        if !self.drain_save_task() {
            return false;
        }
        if !self.dirty || self.vault.is_none() {
            return self.state.persistence_health != PersistenceHealth::Failed;
        }
        if !self.ensure_activity_quarantined() {
            return false;
        }
        let payloads = match self.current_payloads() {
            Ok(payloads) => payloads,
            Err(error) => {
                self.persistence_failed(error);
                return false;
            }
        };
        let result = match (self.vault.as_ref(), self.writer.as_mut()) {
            (Some(vault), Some(writer)) => writer.save_sync(
                vault,
                &payloads.profile,
                &payloads.journal,
                payloads.activity.as_deref(),
            ),
            _ => {
                self.persistence_failed("the authenticated vault writer is unavailable");
                return false;
            }
        };
        match result {
            Ok(_) => {
                self.dirty = false;
                self.save_deadline = None;
                self.state.persistence_health = PersistenceHealth::Ready;
                true
            }
            Err(error) => {
                self.persistence_failed(error.to_string());
                false
            }
        }
    }
}
