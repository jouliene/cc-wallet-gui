use serde::{Deserialize, Deserializer, Serialize};

use crate::address::canonicalize_recipient;
use crate::amount::{AssetAmount, CcAmount, parse_send_amount};
use crate::asset::AssetId;
use crate::error::{WalletError, WalletResult};
use crate::ids::RecordId;
use crate::journal::SendTicket;
use crate::profile::WalletInputs;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum SendToken {
    #[default]
    Native,
    Cc(u32),
}

impl SendToken {
    pub fn asset_id(self) -> AssetId {
        match self {
            Self::Native => AssetId::Native,
            Self::Cc(id) => AssetId::CurrencyCollection(id),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendForm {
    pub token: SendToken,
    pub destination: String,
    pub amount: String,
}

impl Default for SendForm {
    fn default() -> Self {
        Self {
            token: SendToken::Native,
            destination: String::new(),
            amount: String::new(),
        }
    }
}

impl SendForm {
    pub fn request(&self) -> WalletResult<SendRequest> {
        let value = parse_send_amount(self.token.asset_id(), &self.amount)?;
        SendRequest::new(self.destination.clone(), value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SendRequest {
    destination: String,
    value: AssetAmount,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SendRequestWire {
    destination: String,
    value: AssetAmount,
}

impl<'de> Deserialize<'de> for SendRequest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = SendRequestWire::deserialize(deserializer)?;
        Self::new(wire.destination, wire.value).map_err(serde::de::Error::custom)
    }
}

impl SendRequest {
    pub fn new(destination: impl Into<String>, value: AssetAmount) -> WalletResult<Self> {
        let destination = destination.into();
        let destination = canonicalize_recipient(&destination)?;
        if value.is_zero() {
            return Err(WalletError::amount("amount must be greater than zero"));
        }
        if let AssetId::CurrencyCollection(id) = value.asset_id()
            && !AssetId::CurrencyCollection(id).is_known_cc()
        {
            return Err(WalletError::amount(
                "only currency-collection ids 1, 2, and 3 can be sent",
            ));
        }
        Ok(Self { destination, value })
    }

    pub fn native(destination: impl Into<String>, units: u128) -> WalletResult<Self> {
        let value =
            AssetAmount::native(units).map_err(|error| WalletError::amount(error.to_string()))?;
        Self::new(destination, value)
    }

    pub fn currency_collection(
        destination: impl Into<String>,
        id: u32,
        units: CcAmount,
    ) -> WalletResult<Self> {
        Self::new(destination, AssetAmount::currency_collection(id, units))
    }

    pub fn destination(&self) -> &str {
        &self.destination
    }

    pub fn value(&self) -> &AssetAmount {
        &self.value
    }

    pub fn asset_id(&self) -> AssetId {
        self.value.asset_id()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct SendAuthorization {
    inputs: WalletInputs,
    ticket: SendTicket,
}

impl SendAuthorization {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        record_id: RecordId,
        sender_wallet_id: String,
        sender_address: String,
        inputs: WalletInputs,
        request: SendRequest,
        bounce: bool,
        generation: u64,
        nonce: u64,
    ) -> WalletResult<Self> {
        if inputs.endpoint.is_empty() || inputs.endpoint.trim() != inputs.endpoint {
            return Err(WalletError::validation(
                "authorization endpoint identity is empty or noncanonical",
            ));
        }
        crate::validate_workchain(inputs.workchain)?;
        let ticket = SendTicket::new(
            record_id,
            sender_wallet_id,
            canonicalize_recipient(&sender_address)?,
            inputs.network_id,
            inputs.endpoint.clone(),
            SendRequest::new(request.destination().to_owned(), request.value().clone())?,
            bounce,
            generation,
            nonce,
        )
        .map_err(|error| WalletError::validation(error.to_string()))?;
        Ok(Self { inputs, ticket })
    }

    pub fn generation(&self) -> u64 {
        self.ticket.auth_generation()
    }

    pub fn nonce(&self) -> u64 {
        self.ticket.auth_nonce()
    }

    pub fn matches(&self, generation: u64, nonce: u64) -> bool {
        self.ticket.auth_generation() == generation && self.ticket.auth_nonce() == nonce
    }

    pub fn inputs(&self) -> &WalletInputs {
        &self.inputs
    }

    pub fn request(&self) -> &SendRequest {
        self.ticket.request()
    }

    pub fn bounce(&self) -> bool {
        self.ticket.bounce()
    }

    pub fn ticket(&self) -> &SendTicket {
        &self.ticket
    }

    pub fn into_parts(self) -> (WalletInputs, SendTicket) {
        (self.inputs, self.ticket)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEST: &str = "0:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn builds_native_send_request() {
        let form = SendForm {
            token: SendToken::Native,
            destination: DEST.to_owned(),
            amount: "1.2".to_owned(),
        };
        let request = form.request().unwrap();
        assert_eq!(request.asset_id(), AssetId::Native);
        assert_eq!(request.value().native_units(), Some(1_200_000_000));
    }

    #[test]
    fn builds_full_width_cc_send_request() {
        let form = SendForm {
            token: SendToken::Cc(2),
            destination: DEST.to_owned(),
            amount: "340282366920938463463374607431.768211456".to_owned(),
        };
        let request = form.request().unwrap();
        assert_eq!(request.asset_id(), AssetId::CurrencyCollection(2));
        assert_eq!(
            request.value().cc_units().unwrap().to_canonical_decimal(),
            "340282366920938463463374607431768211456"
        );
    }

    #[test]
    fn request_wire_has_only_destination_and_one_typed_value() {
        let request = SendRequest::currency_collection(
            DEST,
            1,
            CcAmount::try_from_canonical_decimal("340282366920938463463374607431768211456")
                .unwrap(),
        )
        .unwrap();
        let json = serde_json::to_string(&request).unwrap();
        assert_eq!(
            json,
            r#"{"destination":"0:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","value":{"asset":"currency_collection","currency_id":1,"base_units":"340282366920938463463374607431768211456"}}"#
        );
        assert_eq!(serde_json::from_str::<SendRequest>(&json).unwrap(), request);
        for invalid in [
            r#"{"destination":"0:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","value":{"asset":"native","base_units":"0"}}"#,
            r#"{"destination":"0:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","value":{"asset":"currency_collection","currency_id":4,"base_units":"1"}}"#,
            r#"{"destination":"0:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","value":{"asset":"native","base_units":"1"},"mode":"Native"}"#,
        ] {
            assert!(serde_json::from_str::<SendRequest>(invalid).is_err());
        }
    }

    #[test]
    fn request_canonicalizes_friendly_address_and_rejects_other_workchains() {
        let raw = "0:dddde93b1d3398f0b4305c08de9a032e0bc1b257c4ce2c72090aea1ff3e9ecfd";
        let request =
            SendRequest::native("UQDd3ek7HTOY8LQwXAjemgMuC8GyV8TOLHIJCuof8-ns_Tyv", 1).unwrap();
        assert_eq!(request.destination(), raw);
        for workchain in [10, 127, -5] {
            assert!(
                SendRequest::native(
                    format!("{workchain}:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
                    1,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn authorization_snapshot_is_immutable_and_generation_nonce_bound() {
        let request = SendRequest::native(DEST, 7).unwrap();
        let inputs = WalletInputs {
            endpoint: "https://rpc.example/".to_owned(),
            network_id: 2000,
            workchain: 0,
            seed: crate::SeedPhrase::shared("redacted test seed".to_owned()),
            require_signature_id: true,
        };
        let ticket = SendAuthorization::new(
            RecordId::from_bytes([3; 32]),
            "wallet.ccwallet".to_owned(),
            DEST.to_owned(),
            inputs,
            request.clone(),
            true,
            9,
            11,
        )
        .unwrap();
        assert!(ticket.matches(9, 11));
        assert!(!ticket.matches(8, 11));
        assert!(!ticket.matches(9, 12));
        assert_eq!(ticket.inputs().endpoint, "https://rpc.example/");
        assert_eq!(ticket.inputs().seed.expose_secret(), "redacted test seed");
        assert_eq!(ticket.request(), &request);
        assert!(ticket.bounce());
    }
}
