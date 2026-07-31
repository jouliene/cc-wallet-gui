use crate::event::AppEvent;

use super::AppController;

impl AppController {
    fn full_endpoints(&self) -> Vec<String> {
        self.state.endpoint_display_list()
    }

    pub(super) fn current_endpoint(&self) -> String {
        self.state.resolved_endpoint()
    }

    pub(super) fn refresh_network_view(&mut self) {
        let id = self.state.network_id;
        self.state.network_name = self
            .networks
            .name_for(id)
            .map(str::to_owned)
            .unwrap_or_else(|| format!("network {id}"));
        self.state.default_endpoint = self.networks.endpoint_for(id).map(str::to_owned);
        self.state.selected_endpoint = self.state.selected_endpoint_index();
    }

    pub(super) fn add_endpoint(&mut self, url: String) {
        if url.trim().is_empty() {
            return;
        }
        let url = match crate::canonical_endpoint(&url) {
            Ok(url) => url,
            Err(error) => {
                self.state.endpoint_test_result = format!("Not a valid endpoint URL: {error}");
                return;
            }
        };
        let is_default = self.networks.endpoint_for(self.state.network_id) == Some(url.as_str());
        if is_default || self.state.custom_endpoints.contains(&url) {
            self.state.endpoint_test_result = "That endpoint is already in the list".to_owned();
            return;
        }
        self.state.custom_endpoints.push(url);
        self.save_profile();
        self.state.endpoint_test_result.clear();
        self.refresh_network_view();
    }

    pub(super) fn select_endpoint(&mut self, index: usize) {
        let len = self.full_endpoints().len();
        if index >= len {
            return;
        }
        self.state.selected_endpoint = index;
        self.save_profile();
        self.refresh_network_view();
        self.chain.clear_config_cache();
        self.forget_traces();
        self.state.network_mismatch = false;
        self.state.reset_recipient_status();
        self.stop_subscription();
        self.refresh_wallet();
    }

    pub(super) fn remove_endpoint(&mut self, url: String) {
        let Ok(url) = crate::canonical_endpoint(&url) else {
            return;
        };
        let Some(pos) = self.state.custom_endpoints.iter().position(|e| *e == url) else {
            return;
        };
        let was_active = self.state.resolved_endpoint();
        let default_offset = usize::from(self.state.default_endpoint.is_some());
        let removed_full_index = pos + default_offset;
        self.state.custom_endpoints.remove(pos);
        if self.state.selected_endpoint == removed_full_index {
            self.state.selected_endpoint = 0;
        } else if self.state.selected_endpoint > removed_full_index {
            self.state.selected_endpoint -= 1;
        }
        self.save_profile();
        self.refresh_network_view();
        if self.state.resolved_endpoint() != was_active {
            self.chain.clear_config_cache();
            self.forget_traces();
            self.state.network_mismatch = false;
            self.state.reset_recipient_status();
            self.stop_subscription();
            self.refresh_wallet();
        }
    }

    pub(super) fn test_endpoint(&mut self, url: String) {
        if url.trim().is_empty() {
            return;
        }
        let url = match crate::canonical_endpoint(&url) {
            Ok(url) => url,
            Err(error) => {
                self.state.endpoint_test_result = format!("Not a valid endpoint URL: {error}");
                return;
            }
        };
        self.state.endpoint_test_result = "Testing endpoint…".to_owned();
        self.endpoint_test_url = Some(url.clone());
        let tx = self.tx.clone();
        let chain = self.chain.clone();
        let want = self.state.network_id;
        self.runtime.spawn(async move {
            let event = match chain.probe_endpoint(url.clone()).await {
                Ok(gid) => AppEvent::EndpointTested {
                    for_network: want,
                    url,
                    reachable: true,
                    reported_network_id: Some(gid),
                    matches_wallet: gid == want,
                    error: None,
                },
                Err(error) => AppEvent::EndpointTested {
                    for_network: want,
                    url,
                    reachable: false,
                    reported_network_id: None,
                    matches_wallet: false,
                    error: Some(error.to_string()),
                },
            };
            let _ = tx.send(event);
        });
    }

    pub(super) fn apply_endpoint_tested(
        &mut self,
        for_network: i32,
        url: &str,
        reachable: bool,
        reported: Option<i32>,
        matches: bool,
        error: Option<String>,
    ) {
        if self.endpoint_test_url.as_deref() != Some(url) {
            return;
        }
        self.endpoint_test_url = None;
        if for_network != self.state.network_id {
            return;
        }
        self.state.endpoint_test_result = if !reachable {
            format!(
                "Unreachable: {}",
                error.unwrap_or_else(|| "no response".to_owned())
            )
        } else if matches {
            format!("OK: serves network {}", reported.unwrap_or_default())
        } else {
            format!(
                "Wrong network: endpoint serves {}, wallet is on {}",
                reported.unwrap_or_default(),
                self.state.network_id
            )
        };
    }
}
