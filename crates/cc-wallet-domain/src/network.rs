use serde::{Deserialize, Serialize};

use crate::{DEFAULT_ENDPOINT, TYCHO_TESTNET_ENDPOINT};

pub const LOCAL_DEX_POOL: &str =
    "0:4273920c193f325e2db7d77b5668c8ac60f4d2ac37bc239b9aeea5a27924ccf4";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Network {
    pub id: i32,
    pub name: String,
    pub endpoints: Vec<String>,
    #[serde(default)]
    pub selected: usize,
    #[serde(default)]
    pub require_signature_id: bool,
    #[serde(default)]
    pub dex_pool: String,
}

impl Network {
    pub fn active_endpoint(&self) -> Option<&str> {
        if self.endpoints.is_empty() {
            return None;
        }
        let idx = self.selected.min(self.endpoints.len() - 1);
        self.endpoints.get(idx).map(String::as_str)
    }

    pub fn dex_pool(&self) -> Option<&str> {
        let trimmed = self.dex_pool.trim();
        (!trimmed.is_empty()).then_some(trimmed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkRegistry {
    pub networks: Vec<Network>,
}

impl Default for NetworkRegistry {
    fn default() -> Self {
        Self::defaults()
    }
}

impl NetworkRegistry {
    pub fn defaults() -> Self {
        Self {
            networks: vec![
                Network {
                    id: 2000,
                    name: "Tycho testnet".to_owned(),
                    endpoints: vec![TYCHO_TESTNET_ENDPOINT.to_owned()],
                    selected: 0,
                    require_signature_id: true,
                    dex_pool: String::new(),
                },
                Network {
                    id: 0,
                    name: "Local".to_owned(),
                    endpoints: vec![DEFAULT_ENDPOINT.to_owned()],
                    selected: 0,
                    require_signature_id: false,
                    dex_pool: LOCAL_DEX_POOL.to_owned(),
                },
            ],
        }
    }

    pub fn get(&self, id: i32) -> Option<&Network> {
        self.networks.iter().find(|n| n.id == id)
    }

    pub fn endpoint_for(&self, id: i32) -> Option<&str> {
        self.get(id).and_then(Network::active_endpoint)
    }

    pub fn dex_pool_for(&self, id: i32) -> Option<&str> {
        self.get(id).and_then(Network::dex_pool)
    }

    pub fn name_for(&self, id: i32) -> Option<&str> {
        self.get(id).map(|n| n.name.as_str())
    }

    pub fn require_signature_id(&self, id: i32) -> bool {
        self.get(id).is_some_and(|n| n.require_signature_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_seed_the_two_built_in_networks() {
        let reg = NetworkRegistry::defaults();
        assert_eq!(reg.get(2000).unwrap().name, "Tycho testnet");
        assert_eq!(reg.get(0).unwrap().name, "Local");
        assert_eq!(reg.endpoint_for(0), Some(DEFAULT_ENDPOINT));
        assert_eq!(reg.endpoint_for(2000), Some(TYCHO_TESTNET_ENDPOINT));
        assert_eq!(reg.endpoint_for(999), None);
    }

    #[test]
    fn signature_id_is_pinned_for_testnet_and_permissive_elsewhere() {
        let reg = NetworkRegistry::defaults();
        assert!(
            reg.require_signature_id(2000),
            "testnet pins signature-with-id (verified live)"
        );
        assert!(
            !reg.require_signature_id(0),
            "the local dev network stays permissive"
        );
        assert!(
            !reg.require_signature_id(999),
            "an unknown network never blocks a send"
        );
    }

    #[test]
    fn the_registry_is_hardcoded_and_carries_default_endpoints() {
        let reg = NetworkRegistry::default();
        assert_eq!(reg.endpoint_for(0), Some(DEFAULT_ENDPOINT));
        assert_eq!(reg.endpoint_for(2000), Some(TYCHO_TESTNET_ENDPOINT));
        assert!(reg.require_signature_id(2000));
        assert!(!reg.require_signature_id(0));
    }
}
