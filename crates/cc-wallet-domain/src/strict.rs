use serde::Deserialize;

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt;
use std::marker::PhantomData;

use serde::Deserializer;
use serde::de::{DeserializeOwned, DeserializeSeed, Error as _, MapAccess, Visitor};
use serde_json::value::RawValue;
use zeroize::Zeroizing;

use crate::activity::ActivityEvent;
use crate::ids::{Digest32, RecordId, RiskNonce};
use crate::journal::{RiskEvent, SendRecord};
use crate::profile::AddressBookEntry;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StrictError {
    Malformed,
    DuplicateKey(String),
    UnsupportedSchema(u32),
    NewerSchema(u32),
    MissingWriterStamp,
    WrongWriterVersion { expected: u32, found: u32 },
    MissingField(&'static str),
    WrongType(&'static str),
    UnknownFields(Vec<String>),
}

impl fmt::Display for StrictError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => f.write_str("bytes are not a single well-formed JSON object"),
            Self::DuplicateKey(k) => write!(f, "duplicate top-level key `{k}`"),
            Self::UnsupportedSchema(v) => {
                write!(f, "schema {v} is not a supported format")
            }
            Self::NewerSchema(v) => write!(f, "schema {v} is newer than this build"),
            Self::MissingWriterStamp => {
                f.write_str("current schema requires a writer_version stamp")
            }
            Self::WrongWriterVersion { expected, found } => {
                write!(f, "writer_version {found} is not the expected {expected}")
            }
            Self::MissingField(k) => write!(f, "required field `{k}` is missing"),
            Self::WrongType(k) => {
                write!(f, "field `{k}` has the wrong type or a noncanonical value")
            }
            Self::UnknownFields(keys) => write!(f, "unexpected field(s): {}", keys.join(", ")),
        }
    }
}

impl std::error::Error for StrictError {}

mod sealed {
    pub trait Sealed {}
}

pub trait SchemaPolicy: sealed::Sealed {
    const SCHEMA: u32;
    const WRITER: u32;
}

pub struct EnvelopeSchemaV1;
impl sealed::Sealed for EnvelopeSchemaV1 {}
impl SchemaPolicy for EnvelopeSchemaV1 {
    const SCHEMA: u32 = 1;
    const WRITER: u32 = 1;
}

pub(crate) struct ProfileSchemaV1;
impl sealed::Sealed for ProfileSchemaV1 {}
impl SchemaPolicy for ProfileSchemaV1 {
    const SCHEMA: u32 = 1;
    const WRITER: u32 = 0;
}

pub trait StrictSlot: DeserializeOwned + sealed::Sealed {}

macro_rules! strict_slot {
    ($($t:ty),* $(,)?) => {$(
        impl sealed::Sealed for $t {}
        impl StrictSlot for $t {}
    )*};
}

strict_slot!(
    bool,
    u8,
    u16,
    u32,
    u64,
    usize,
    i8,
    i32,
    i64,
    String,
    RecordId,
    RiskNonce,
    Digest32,
    AddressBookEntry
);

impl<T: StrictSlot> sealed::Sealed for Vec<T> {}
impl<T: StrictSlot> StrictSlot for Vec<T> {}

impl<T: StrictSlot + Ord> sealed::Sealed for BTreeSet<T> {}
impl<T: StrictSlot + Ord> StrictSlot for BTreeSet<T> {}

strict_slot!(ActivityEvent, SendRecord, RiskEvent);

struct OwnedRaw(Zeroizing<Box<str>>);

impl OwnedRaw {
    fn new(value: Box<RawValue>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    fn get(&self) -> &str {
        &self.0
    }
}

struct RawMembersSeed<'a> {
    duplicate: &'a mut Option<String>,
}

impl<'a, 'de> DeserializeSeed<'de> for RawMembersSeed<'a> {
    type Value = Vec<(String, OwnedRaw)>;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        struct RawMembersVisitor<'a> {
            duplicate: &'a mut Option<String>,
        }

        impl<'a, 'de> Visitor<'de> for RawMembersVisitor<'a> {
            type Value = Vec<(String, OwnedRaw)>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut members: Vec<(String, OwnedRaw)> = Vec::new();
                let mut seen = BTreeSet::new();
                while let Some((key, value)) = map.next_entry::<String, Box<RawValue>>()? {
                    let value = OwnedRaw::new(value);
                    if !seen.insert(key.clone()) {
                        *self.duplicate = Some(key);
                        return Err(A::Error::custom("duplicate top-level key"));
                    }
                    members.push((key, value));
                }
                Ok(members)
            }
        }

        deserializer.deserialize_map(RawMembersVisitor {
            duplicate: self.duplicate,
        })
    }
}

fn take(members: &mut Vec<(String, OwnedRaw)>, key: &str) -> Option<OwnedRaw> {
    let pos = members.iter().position(|(k, _)| k == key)?;
    Some(members.remove(pos).1)
}

fn take_u32_stamp(
    members: &mut Vec<(String, OwnedRaw)>,
    key: &str,
) -> Result<Option<u32>, StrictError> {
    match take(members, key) {
        None => Ok(None),
        Some(raw) => serde_json::from_str::<u32>(raw.get())
            .map(Some)
            .map_err(|_| StrictError::Malformed),
    }
}

pub struct StrictObject {
    members: Vec<(String, OwnedRaw)>,
}

impl StrictObject {
    pub fn parse(bytes: &[u8]) -> Result<Self, StrictError> {
        let mut duplicate = None;
        let mut de = serde_json::Deserializer::from_slice(bytes);
        let result = RawMembersSeed {
            duplicate: &mut duplicate,
        }
        .deserialize(&mut de);
        let members = result.map_err(|_| match duplicate.take() {
            Some(key) => StrictError::DuplicateKey(key),
            None => StrictError::Malformed,
        })?;
        de.end().map_err(|_| StrictError::Malformed)?;
        Ok(Self { members })
    }

    pub fn require_schema<P: SchemaPolicy>(mut self) -> Result<SchemaChecked<P>, StrictError> {
        let schema = match take_u32_stamp(&mut self.members, "schema_version")? {
            None => return Err(StrictError::UnsupportedSchema(0)),
            Some(v) => v,
        };
        match schema.cmp(&P::SCHEMA) {
            Ordering::Equal => Ok(SchemaChecked {
                members: self.members,
                _policy: PhantomData,
            }),
            Ordering::Greater => Err(StrictError::NewerSchema(schema)),
            Ordering::Less => Err(StrictError::UnsupportedSchema(schema)),
        }
    }
}

pub struct SchemaChecked<P: SchemaPolicy> {
    members: Vec<(String, OwnedRaw)>,
    _policy: PhantomData<P>,
}

impl<P: SchemaPolicy> SchemaChecked<P> {
    pub fn require_writer(mut self) -> Result<Classified, StrictError> {
        match take_u32_stamp(&mut self.members, "writer_version")? {
            None => Err(StrictError::MissingWriterStamp),
            Some(found) if found == P::WRITER => Ok(Classified {
                members: self.members,
            }),
            Some(found) => Err(StrictError::WrongWriterVersion {
                expected: P::WRITER,
                found,
            }),
        }
    }
}

impl SchemaChecked<ProfileSchemaV1> {
    pub(crate) fn into_profile_content(self) -> Classified {
        Classified {
            members: self.members,
        }
    }
}

pub struct Classified {
    members: Vec<(String, OwnedRaw)>,
}

impl Classified {
    pub fn take_required<T: StrictSlot>(&mut self, key: &'static str) -> Result<T, StrictError> {
        let raw = take(&mut self.members, key).ok_or(StrictError::MissingField(key))?;
        serde_json::from_str::<T>(raw.get()).map_err(|_| StrictError::WrongType(key))
    }

    pub(crate) fn take_required_zeroizing_string(
        &mut self,
        key: &'static str,
    ) -> Result<Zeroizing<String>, StrictError> {
        let raw = take(&mut self.members, key).ok_or(StrictError::MissingField(key))?;
        serde_json::from_str::<String>(raw.get())
            .map(Zeroizing::new)
            .map_err(|_| StrictError::WrongType(key))
    }

    pub fn take_required_nullable<T: StrictSlot>(
        &mut self,
        key: &'static str,
    ) -> Result<Option<T>, StrictError> {
        let raw = take(&mut self.members, key).ok_or(StrictError::MissingField(key))?;
        serde_json::from_str::<Option<T>>(raw.get()).map_err(|_| StrictError::WrongType(key))
    }

    pub fn finish(self) -> Result<(), StrictError> {
        if self.members.is_empty() {
            Ok(())
        } else {
            Err(StrictError::UnknownFields(
                self.members.into_iter().map(|(k, _)| k).collect(),
            ))
        }
    }
}

pub(crate) fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    struct Header {
        name: String,
        count: u32,
        note: Option<String>,
    }

    fn decode_header(bytes: &[u8]) -> Result<Header, StrictError> {
        let mut classified = StrictObject::parse(bytes)?
            .require_schema::<EnvelopeSchemaV1>()?
            .require_writer()?;
        let name = classified.take_required::<String>("name")?;
        let count = classified.take_required::<u32>("count")?;
        let note = classified.take_required_nullable::<String>("note")?;
        classified.finish()?;
        Ok(Header { name, count, note })
    }

    #[test]
    fn arbitrary_key_order_decodes_and_null_required_nullable_is_none() {
        let reordered =
            br#"{"note":null,"count":3,"writer_version":1,"name":"x","schema_version":1}"#;
        assert_eq!(
            decode_header(reordered).unwrap(),
            Header {
                name: "x".to_owned(),
                count: 3,
                note: None
            }
        );
        let with_note =
            br#"{"schema_version":1,"writer_version":1,"name":"x","count":3,"note":"hi"}"#;
        assert_eq!(
            decode_header(with_note).unwrap(),
            Header {
                name: "x".to_owned(),
                count: 3,
                note: Some("hi".to_owned())
            }
        );
    }

    #[test]
    fn a_duplicate_top_level_key_is_rejected_including_the_schema_stamp() {
        let dup_schema = br#"{"schema_version":1,"schema_version":1,"writer_version":1,"name":"x","count":3,"note":null}"#;
        assert_eq!(
            decode_header(dup_schema),
            Err(StrictError::DuplicateKey("schema_version".to_owned()))
        );
        let dup_name = br#"{"schema_version":1,"writer_version":1,"name":"x","name":"y","count":3,"note":null}"#;
        assert_eq!(
            decode_header(dup_name),
            Err(StrictError::DuplicateKey("name".to_owned()))
        );
    }

    #[test]
    fn a_duplicate_key_refuses_during_collection_before_a_malformed_tail() {
        let dup_then_bad = br#"{"name":"x","name":"y","oops":@}"#;
        assert_eq!(
            StrictObject::parse(dup_then_bad).err(),
            Some(StrictError::DuplicateKey("name".to_owned()))
        );
        let dup_then_garbage = br#"{"a":1,"a":2,"b":999999999999999999999999999999999999}"#;
        assert_eq!(
            StrictObject::parse(dup_then_garbage).err(),
            Some(StrictError::DuplicateKey("a".to_owned()))
        );
    }

    #[test]
    fn the_schema_stamp_is_classified_before_content() {
        let absent = br#"{"writer_version":1,"name":"x","count":3,"note":null}"#;
        assert_eq!(
            decode_header(absent),
            Err(StrictError::UnsupportedSchema(0))
        );
        let older = br#"{"schema_version":0,"writer_version":1,"name":"x","count":3,"note":null}"#;
        assert_eq!(decode_header(older), Err(StrictError::UnsupportedSchema(0)));
        let newer = br#"{"schema_version":2,"writer_version":1,"name":"x","count":3,"note":null}"#;
        assert_eq!(decode_header(newer), Err(StrictError::NewerSchema(2)));
    }

    #[test]
    fn a_hostile_future_schema_is_never_accepted_by_the_fixed_policy() {
        let bytes =
            br#"{"schema_version":999,"writer_version":999,"name":"x","count":3,"note":null}"#;
        assert_eq!(
            StrictObject::parse(bytes)
                .unwrap()
                .require_schema::<EnvelopeSchemaV1>()
                .err(),
            Some(StrictError::NewerSchema(999))
        );
    }

    #[test]
    fn the_current_schema_requires_exactly_the_expected_writer_stamp() {
        let missing = br#"{"schema_version":1,"name":"x","count":3,"note":null}"#;
        assert_eq!(decode_header(missing), Err(StrictError::MissingWriterStamp));
        let wrong = br#"{"schema_version":1,"writer_version":9,"name":"x","count":3,"note":null}"#;
        assert_eq!(
            decode_header(wrong),
            Err(StrictError::WrongWriterVersion {
                expected: 1,
                found: 9
            })
        );
    }

    #[test]
    fn a_classified_object_cannot_read_a_consumed_stamp_as_content() {
        let mut classified =
            StrictObject::parse(br#"{"schema_version":1,"writer_version":1,"name":"x"}"#)
                .unwrap()
                .require_schema::<EnvelopeSchemaV1>()
                .unwrap()
                .require_writer()
                .unwrap();
        assert_eq!(
            classified.take_required::<u32>("schema_version"),
            Err(StrictError::MissingField("schema_version"))
        );
        assert_eq!(
            classified.take_required::<u32>("writer_version"),
            Err(StrictError::MissingField("writer_version"))
        );
    }

    #[test]
    fn an_unknown_field_is_rejected_when_the_object_must_reach_end() {
        let extra = br#"{"schema_version":1,"writer_version":1,"name":"x","count":3,"note":null,"extra":1}"#;
        assert_eq!(
            decode_header(extra),
            Err(StrictError::UnknownFields(vec!["extra".to_owned()]))
        );
    }

    #[test]
    fn a_missing_required_slot_is_an_error_and_a_nullable_slot_still_requires_its_key() {
        let missing_required = br#"{"schema_version":1,"writer_version":1,"count":3,"note":null}"#;
        assert_eq!(
            decode_header(missing_required),
            Err(StrictError::MissingField("name"))
        );
        let missing_nullable = br#"{"schema_version":1,"writer_version":1,"name":"x","count":3}"#;
        assert_eq!(
            decode_header(missing_nullable),
            Err(StrictError::MissingField("note"))
        );
    }

    #[test]
    fn a_wrong_token_or_float_slot_is_rejected_never_coerced() {
        let string_for_int =
            br#"{"schema_version":1,"writer_version":1,"name":"x","count":"3","note":null}"#;
        assert_eq!(
            decode_header(string_for_int),
            Err(StrictError::WrongType("count"))
        );
        let float_for_int =
            br#"{"schema_version":1,"writer_version":1,"name":"x","count":3.0,"note":null}"#;
        assert_eq!(
            decode_header(float_for_int),
            Err(StrictError::WrongType("count"))
        );
        let int_for_string =
            br#"{"schema_version":1,"writer_version":1,"name":5,"count":3,"note":null}"#;
        assert_eq!(
            decode_header(int_for_string),
            Err(StrictError::WrongType("name"))
        );
    }

    #[test]
    fn a_non_object_or_trailing_bytes_top_level_is_malformed() {
        for bad in [
            b"[]".as_slice(),
            b"5".as_slice(),
            b"\"x\"".as_slice(),
            b"null".as_slice(),
            b"not json".as_slice(),
            br#"{"schema_version":1} trailing"#.as_slice(),
            br#"{"schema_version":1}{"schema_version":1}"#.as_slice(),
        ] {
            assert_eq!(
                StrictObject::parse(bad).err(),
                Some(StrictError::Malformed),
                "must be malformed: {}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn a_noncanonical_stamp_token_is_malformed() {
        let string_schema =
            br#"{"schema_version":"1","writer_version":1,"name":"x","count":3,"note":null}"#;
        assert_eq!(
            StrictObject::parse(string_schema)
                .unwrap()
                .require_schema::<EnvelopeSchemaV1>()
                .err(),
            Some(StrictError::Malformed)
        );
        let float_writer =
            br#"{"schema_version":1,"writer_version":1.0,"name":"x","count":3,"note":null}"#;
        assert_eq!(
            StrictObject::parse(float_writer)
                .unwrap()
                .require_schema::<EnvelopeSchemaV1>()
                .unwrap()
                .require_writer()
                .err(),
            Some(StrictError::Malformed)
        );
    }

    #[test]
    fn project_owned_identifier_slots_decode_strictly() {
        let bytes = format!(
            r#"{{"schema_version":1,"writer_version":1,"id":"{}"}}"#,
            "ab".repeat(32)
        );
        let mut classified = StrictObject::parse(bytes.as_bytes())
            .unwrap()
            .require_schema::<EnvelopeSchemaV1>()
            .unwrap()
            .require_writer()
            .unwrap();
        let id = classified.take_required::<RecordId>("id").unwrap();
        assert_eq!(id, RecordId::from_bytes([0xab; 32]));
        classified.finish().unwrap();

        let bad = br#"{"schema_version":1,"writer_version":1,"id":123}"#;
        let mut classified = StrictObject::parse(bad)
            .unwrap()
            .require_schema::<EnvelopeSchemaV1>()
            .unwrap()
            .require_writer()
            .unwrap();
        assert_eq!(
            classified.take_required::<RecordId>("id"),
            Err(StrictError::WrongType("id"))
        );
    }
}
