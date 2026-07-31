use super::AppController;
use crate::event::AppEvent;

impl AppController {
    pub(super) fn save_contact(
        &mut self,
        index: Option<usize>,
        name: String,
        address: String,
        tag: String,
    ) {
        match self.state.save_contact_entry(index, name, address, tag) {
            Ok(()) => {
                self.save_profile();
                self.state.status = "Contact saved".to_owned();
                self.state.error = None;
            }
            Err(error) => self.apply_event(AppEvent::Error(error)),
        }
    }

    pub(super) fn delete_contact(&mut self, index: usize) {
        self.state.delete_contact(index);
        self.save_profile();
        self.state.status = "Contact deleted".to_owned();
        self.state.error = None;
    }

    pub(super) fn reorder_contacts(&mut self, from: usize, to: usize) {
        self.state.reorder_contact(from, to);
        self.save_profile();
    }
}
