use serde::{Deserialize, Serialize};

use crate::amount::AssetAmount;
use crate::asset::AssetId;
use crate::ids::{Digest32, PublicKey32};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActivityDirection {
    In,
    Out,
}

impl ActivityDirection {
    pub fn label(self) -> &'static str {
        match self {
            Self::In => "IN",
            Self::Out => "OUT",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetMovement {
    pub amount: AssetAmount,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ActivityMessage {
    Plain {
        text: String,
    },
    Sealed {
        sender_key: PublicKey32,
        #[serde(with = "hex_bytes")]
        blob: Vec<u8>,
    },
}

impl ActivityMessage {
    pub fn is_sealed(&self) -> bool {
        matches!(self, Self::Sealed { .. })
    }
}

mod hex_bytes {
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        let mut hex = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            hex.push_str(&format!("{byte:02x}"));
        }
        serializer.serialize_str(&hex)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        if !text.len().is_multiple_of(2) {
            return Err(D::Error::custom("a hex blob has an even number of digits"));
        }
        (0..text.len() / 2)
            .map(|i| {
                let pair = &text[2 * i..2 * i + 2];
                if pair
                    .bytes()
                    .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b))
                {
                    return Err(D::Error::custom("a hex blob is lowercase ASCII hex"));
                }
                u8::from_str_radix(pair, 16).map_err(D::Error::custom)
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivityEvent {
    pub direction: ActivityDirection,
    pub lt: u64,
    pub time_unix: u64,
    #[serde(deserialize_with = "crate::strict::required_nullable")]
    pub tx_hash: Option<Digest32>,
    pub counterparty: String,
    pub movements: Vec<AssetMovement>,
    #[serde(with = "crate::amount::native_scalar")]
    pub fee_native: u128,
    pub success: bool,
    pub bounced: bool,
    pub exit_code: i32,
    #[serde(deserialize_with = "crate::strict::required_nullable")]
    pub ext_msg_hash: Option<Digest32>,
    #[serde(deserialize_with = "crate::strict::required_nullable")]
    pub int_msg_hash: Option<Digest32>,
    #[serde(deserialize_with = "crate::strict::required_nullable")]
    pub finality_ms: Option<u64>,
    pub pending: bool,
    #[serde(deserialize_with = "crate::strict::required_nullable")]
    pub message: Option<ActivityMessage>,
}

impl ActivityEvent {
    pub fn moves_asset(&self, asset: AssetId) -> bool {
        self.movements
            .iter()
            .any(|movement| movement.amount.asset_id() == asset)
    }
}

#[cfg(any(test, feature = "test-fixtures"))]
impl ActivityEvent {
    pub fn test_stub(lt: u64, time_unix: u64) -> Self {
        Self {
            direction: ActivityDirection::Out,
            lt,
            time_unix,
            tx_hash: Some(Digest32::from_bytes([0xaa; 32])),
            counterparty: "0:x".to_owned(),
            movements: vec![AssetMovement {
                amount: AssetAmount::native(1_000_000_000).expect("1 native token is in range"),
            }],
            fee_native: 0,
            success: true,
            bounced: false,
            exit_code: 0,
            ext_msg_hash: None,
            int_msg_hash: None,
            finality_ms: None,
            pending: false,
            message: None,
        }
    }
}

#[cfg(test)]
mod fixture_tests {
    use super::*;

    #[test]
    fn test_stub_defaults_are_a_confirmed_successful_out_transfer() {
        let e = ActivityEvent::test_stub(7, 1_700_000_000);
        assert_eq!(e.direction, ActivityDirection::Out);
        assert!(e.success);
        assert!(!e.pending);
        assert!(!e.bounced);
        assert_eq!(e.exit_code, 0);
        assert_eq!(e.fee_native, 0);
        assert_eq!(e.ext_msg_hash, None);
        assert_eq!(e.int_msg_hash, None);
        assert_eq!(e.finality_ms, None);
        assert_eq!(e.lt, 7);
        assert_eq!(e.time_unix, 1_700_000_000);
        assert_eq!(e.tx_hash, Some(Digest32::from_bytes([0xaa; 32])));
        assert_eq!(e.counterparty, "0:x");
        assert_eq!(e.movements.len(), 1);
        assert!(e.movements[0].amount.asset_id().is_native());
        assert_eq!(e.movements[0].amount.native_units(), Some(1_000_000_000));
    }
}
