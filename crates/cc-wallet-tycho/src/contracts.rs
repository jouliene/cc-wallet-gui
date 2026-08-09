use std::collections::BTreeMap;
use std::sync::OnceLock;

use tycho_types::prelude::Cell;

use crate::ccdex::ccdex_pool_spec;
use crate::elector::elector_spec;
use crate::everwallet::ever_wallet_spec;
use crate::storage::storage_spec;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DecodedValue {
    Text(String),
    Data(String),
    Moment(u64),
    Amount(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DecodedField {
    pub label: String,
    pub value: DecodedValue,
}

impl DecodedField {
    pub fn text(label: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            value: DecodedValue::Text(value.into()),
        }
    }

    pub fn data(label: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            value: DecodedValue::Data(value.into()),
        }
    }

    pub fn moment(label: impl Into<String>, unix_seconds: u64) -> Self {
        Self {
            label: label.into(),
            value: DecodedValue::Moment(unix_seconds),
        }
    }

    pub fn amount(label: impl Into<String>, units: u128) -> Self {
        Self {
            label: label.into(),
            value: DecodedValue::Amount(fixed9(units)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DecodedContract {
    pub kind: &'static str,
    pub fields: Vec<DecodedField>,
}

pub(crate) fn fixed9(units: u128) -> String {
    format!("{}.{:09}", units / 1_000_000_000, units % 1_000_000_000)
}

pub struct ContractSpec {
    pub name: &'static str,
    pub code_hash: Option<fn() -> String>,
    pub well_known_address: Option<&'static str>,
    pub decode_data: fn(&Cell) -> Option<DecodedContract>,
    pub external_method: fn(&Cell) -> Option<(&'static str, u32)>,
    pub internal_method: fn(u32) -> Option<&'static str>,
    /// How this contract's own outgoing message reads when it carries an op it
    /// also ACCEPTS. A contract that answers with a distinct op needs nothing
    /// here — the name already says which direction it is. One that echoes the
    /// op it is answering about does, or the same name appears on arrows going
    /// both ways and reads as two identical calls.
    pub internal_reply: fn(u32) -> Option<&'static str>,
}

#[derive(Clone, Copy, Default)]
pub struct ContractAt<'a> {
    pub address: Option<&'a str>,
    pub code_hash: Option<&'a str>,
}

impl<'a> ContractAt<'a> {
    pub fn by_address(address: &'a str) -> Self {
        Self {
            address: Some(address),
            code_hash: None,
        }
    }

    pub fn by_code(code_hash: &'a str) -> Self {
        Self {
            address: None,
            code_hash: Some(code_hash),
        }
    }

    fn resolve(self) -> Option<&'static ContractSpec> {
        if let Some(address) = self.address.filter(|address| !address.is_empty())
            && let Some(&position) = address_index().get(address)
        {
            return specs().get(position);
        }
        self.code_hash.and_then(contract_for_code_hash)
    }
}

fn specs() -> &'static [ContractSpec] {
    static SPECS: OnceLock<Vec<ContractSpec>> = OnceLock::new();
    SPECS.get_or_init(|| {
        vec![
            ever_wallet_spec(),
            elector_spec(),
            ccdex_pool_spec(),
            storage_spec(),
        ]
    })
}

fn index() -> &'static BTreeMap<String, usize> {
    static INDEX: OnceLock<BTreeMap<String, usize>> = OnceLock::new();
    INDEX.get_or_init(|| {
        specs()
            .iter()
            .enumerate()
            .filter_map(|(position, spec)| spec.code_hash.map(|code_hash| (code_hash(), position)))
            .collect()
    })
}

fn address_index() -> &'static BTreeMap<&'static str, usize> {
    static INDEX: OnceLock<BTreeMap<&'static str, usize>> = OnceLock::new();
    INDEX.get_or_init(|| {
        specs()
            .iter()
            .enumerate()
            .filter_map(|(position, spec)| {
                spec.well_known_address.map(|address| (address, position))
            })
            .collect()
    })
}

pub fn contract_for_code_hash(code_hash: &str) -> Option<&'static ContractSpec> {
    index()
        .get(code_hash)
        .and_then(|&position| specs().get(position))
}

pub fn contract_name(at: ContractAt) -> Option<&'static str> {
    at.resolve().map(|spec| spec.name)
}

pub fn decode_contract_data(at: ContractAt, data: Option<&Cell>) -> Option<DecodedContract> {
    (at.resolve()?.decode_data)(data?)
}

pub fn external_method(at: ContractAt, body: &Cell) -> Option<(&'static str, u32)> {
    (at.resolve()?.external_method)(body)
}

pub fn internal_method(at: ContractAt, function_id: u32) -> Option<&'static str> {
    (at.resolve()?.internal_method)(function_id)
}

pub fn internal_reply(at: ContractAt, function_id: u32) -> Option<&'static str> {
    (at.resolve()?.internal_reply)(function_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elector::{ELECTOR_ADDRESS, ELECTOR_CONTRACT};
    use crate::everwallet::{EVER_WALLET_CONTRACT, ever_wallet_code_hash};

    #[test]
    fn a_contract_is_found_by_the_code_hash_an_account_reports() {
        let spec = contract_for_code_hash(&ever_wallet_code_hash()).expect("ever wallet is known");

        assert_eq!(spec.name, EVER_WALLET_CONTRACT);
        assert_eq!(
            contract_name(ContractAt::by_code(&ever_wallet_code_hash())),
            Some("Ever Wallet")
        );
    }

    #[test]
    fn a_singleton_is_found_by_the_address_the_network_fixes_it_at() {
        assert_eq!(
            contract_name(ContractAt::by_address(ELECTOR_ADDRESS)),
            Some(ELECTOR_CONTRACT)
        );
        assert_eq!(
            internal_method(ContractAt::by_address(ELECTOR_ADDRESS), 0x4e73_744b),
            Some("new_stake"),
            "and its methods are named the same way"
        );
    }

    #[test]
    fn code_we_do_not_know_is_not_guessed_at() {
        let stranger = "ab".repeat(32);

        assert!(contract_for_code_hash(&stranger).is_none());
        assert_eq!(contract_name(ContractAt::by_code(&stranger)), None);
        assert_eq!(
            decode_contract_data(ContractAt::by_code(&stranger), Some(&Cell::default())),
            None
        );
        assert_eq!(
            external_method(ContractAt::by_code(&stranger), &Cell::default()),
            None
        );
        assert_eq!(
            internal_method(ContractAt::by_code(&stranger), 0x1234_5678),
            None
        );
        assert_eq!(
            external_method(ContractAt::default(), &Cell::default()),
            None,
            "an end we could not read at all is a stranger too"
        );
    }

    #[test]
    fn every_registered_contract_is_reachable_by_what_identifies_it() {
        for spec in specs() {
            assert!(
                spec.code_hash.is_some() || spec.well_known_address.is_some(),
                "{} can be recognised by neither its code nor its address",
                spec.name
            );
            if let Some(code_hash) = spec.code_hash {
                assert_eq!(
                    contract_name(ContractAt::by_code(&code_hash())),
                    Some(spec.name),
                    "{} is registered but cannot be found by its code hash",
                    spec.name
                );
            }
            if let Some(address) = spec.well_known_address {
                assert_eq!(
                    contract_name(ContractAt::by_address(address)),
                    Some(spec.name),
                    "{} is registered but cannot be found by its address",
                    spec.name
                );
            }
        }
    }
}
