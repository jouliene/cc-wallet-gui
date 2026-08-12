use std::fmt;

use serde::de::{self, Visitor};
use serde::{Deserializer, Serializer};

const ID_BYTES: usize = 32;
const ID_HEX_LEN: usize = ID_BYTES * 2;

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdError {
    WrongLength,
    NonCanonicalHex,
}

impl fmt::Display for IdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::WrongLength => "identifier must be exactly 64 hex digits",
            Self::NonCanonicalHex => {
                "identifier must be lowercase ASCII hex with no prefix, sign, whitespace, \
                 or separators"
            }
        })
    }
}

impl std::error::Error for IdError {}

pub(crate) fn hex_lower_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX_DIGITS[(b >> 4) as usize] as char);
        out.push(HEX_DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

pub(crate) fn hex_lower_decode(text: &str) -> Option<Vec<u8>> {
    let src = text.as_bytes();
    if !src.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(src.len() / 2);
    for pair in src.chunks_exact(2) {
        let hi = lower_hex_value(pair[0]).ok()?;
        let lo = lower_hex_value(pair[1]).ok()?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn to_hex(bytes: &[u8; ID_BYTES]) -> String {
    hex_lower_encode(bytes)
}

fn from_hex(text: &str) -> Result<[u8; ID_BYTES], IdError> {
    if text.len() != ID_HEX_LEN {
        return Err(IdError::WrongLength);
    }
    let bytes = hex_lower_decode(text).ok_or(IdError::NonCanonicalHex)?;
    bytes.try_into().map_err(|_| IdError::WrongLength)
}

fn lower_hex_value(b: u8) -> Result<u8, IdError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => Err(IdError::NonCanonicalHex),
    }
}

macro_rules! hex32_newtype {
    ($(#[$meta:meta])* $name:ident, $expecting:literal) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; ID_BYTES]);

        impl $name {
            pub fn from_bytes(bytes: [u8; ID_BYTES]) -> Self {
                Self(bytes)
            }

            pub fn as_bytes(&self) -> &[u8; ID_BYTES] {
                &self.0
            }

            pub fn to_hex(&self) -> String {
                to_hex(&self.0)
            }

            pub fn try_from_hex(text: &str) -> Result<Self, IdError> {
                Ok(Self(from_hex(text)?))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self.to_hex())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.to_hex())
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.to_hex())
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                struct HexVisitor;

                impl Visitor<'_> for HexVisitor {
                    type Value = $name;

                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        f.write_str($expecting)
                    }

                    fn visit_str<E: de::Error>(self, value: &str) -> Result<$name, E> {
                        $name::try_from_hex(value).map_err(E::custom)
                    }
                }

                deserializer.deserialize_str(HexVisitor)
            }
        }
    };
}

hex32_newtype!(RecordId, "a 64-lowercase-hex record id");

hex32_newtype!(RiskNonce, "a 64-lowercase-hex risk nonce");

hex32_newtype!(Digest32, "a 64-lowercase-hex 32-byte digest");

hex32_newtype!(PublicKey32, "a 64-lowercase-hex public key");

#[cfg(test)]
mod tests {

    #[test]
    fn the_shared_codec_round_trips_every_byte_and_refuses_everything_else() {
        let all: Vec<u8> = (0..=255u8).collect();
        let hex = hex_lower_encode(&all);
        assert_eq!(hex.len(), 512);
        assert!(
            hex.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        assert_eq!(hex_lower_decode(&hex).as_deref(), Some(all.as_slice()));

        assert_eq!(hex_lower_encode(&[]), "");
        assert_eq!(hex_lower_decode(""), Some(Vec::new()));

        for refused in [
            "0",
            "abc",
            "AB",
            "0G",
            "ff ",
            " ff",
            "0x",
            "\u{e9}\u{e9}",
            "a\u{e9}a",
        ] {
            assert_eq!(
                hex_lower_decode(refused),
                None,
                "{refused:?} is not lowercase hex"
            );
        }
    }
    use super::*;

    fn ramp() -> [u8; ID_BYTES] {
        let mut bytes = [0u8; ID_BYTES];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = i as u8;
        }
        bytes
    }

    #[test]
    fn record_id_hex_is_lowercase_padded_and_byte_exact() {
        let id = RecordId::from_bytes(ramp());
        let hex = id.to_hex();
        assert_eq!(hex.len(), ID_HEX_LEN);
        assert_eq!(&hex[..6], "000102");
        assert_eq!(&hex[hex.len() - 4..], "1e1f");
        assert_eq!(id.as_bytes(), &ramp());
        assert_eq!(RecordId::try_from_hex(&hex).unwrap(), id);

        assert_eq!(
            RecordId::from_bytes([0x00; ID_BYTES]).to_hex(),
            "0".repeat(64)
        );
        assert_eq!(
            RecordId::from_bytes([0xff; ID_BYTES]).to_hex(),
            "f".repeat(64)
        );
    }

    #[test]
    fn ids_serialize_as_a_64_lowercase_hex_string_and_round_trip() {
        let nonce = RiskNonce::from_bytes([0xab; ID_BYTES]);
        let json = serde_json::to_string(&nonce).unwrap();
        assert_eq!(json, format!("\"{}\"", "ab".repeat(32)));
        assert_eq!(serde_json::from_str::<RiskNonce>(&json).unwrap(), nonce);

        let id = RecordId::from_bytes(ramp());
        let round = serde_json::from_str::<RecordId>(&serde_json::to_string(&id).unwrap()).unwrap();
        assert_eq!(round, id);
    }

    #[test]
    fn id_deserialize_is_strict() {
        assert!(serde_json::from_str::<RecordId>(&format!("\"{}\"", "0".repeat(64))).is_ok());
        for bad in [
            format!("\"{}\"", "0".repeat(63)),
            format!("\"{}\"", "0".repeat(65)),
            "\"\"".to_owned(),
            format!("\"{}\"", "A".repeat(64)),
            format!("\"0x{}\"", "0".repeat(62)),
            format!("\"{}\"", "g".repeat(64)),
            format!("\" {}\"", "0".repeat(63)),
            "123".to_owned(),
        ] {
            assert!(
                serde_json::from_str::<RecordId>(&bad).is_err(),
                "must reject {bad}"
            );
        }
    }

    #[test]
    fn ids_order_lexicographically_by_raw_bytes() {
        let mut a = [0u8; ID_BYTES];
        a[0] = 1;
        let mut b = [0u8; ID_BYTES];
        b[31] = 1;
        assert!(RecordId::from_bytes(b) < RecordId::from_bytes(a));
    }

    #[test]
    fn digest32_round_trips_and_is_strict() {
        let d = Digest32::from_bytes([0x5a; ID_BYTES]);
        assert_eq!(d.as_bytes(), &[0x5a; ID_BYTES]);
        let json = serde_json::to_string(&d).unwrap();
        assert_eq!(json, format!("\"{}\"", "5a".repeat(32)));
        assert_eq!(serde_json::from_str::<Digest32>(&json).unwrap(), d);
        for bad in [
            format!("\"{}\"", "5A".repeat(32)),
            format!("\"{}\"", "5a".repeat(31)),
            "123".to_owned(),
        ] {
            assert!(
                serde_json::from_str::<Digest32>(&bad).is_err(),
                "must reject {bad}"
            );
        }
    }
}
