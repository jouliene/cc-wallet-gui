use serde::Serialize;

use crate::activity::ActivityEvent;
use crate::ids::RecordId;
use crate::journal::{
    DeliveryEvidence, JournalError, PreparedRecord, RiskEvent, SendRecord, append_delivery_event,
    prepared_record, risk_consumption_event, risk_grant_event, validate_replay,
};
use crate::risk::{RiskGrant, RiskGrantConsumption};
use crate::strict::{EnvelopeSchemaV1, StrictError, StrictObject};

pub const ENVELOPE_SCHEMA_VERSION: u32 = 1;
pub const ENVELOPE_WRITER_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeError {
    Malformed,
    UnsupportedSchema(u32),
    NewerSchema(u32),
    MissingWriterVersion,
    IncompatibleWriter(u32),
    Replay(JournalError),
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed => formatter.write_str("stored record envelope is malformed"),
            Self::UnsupportedSchema(version) => write!(
                formatter,
                "stored record envelope schema {version} is not a supported format"
            ),
            Self::NewerSchema(version) => write!(
                formatter,
                "stored record envelope schema {version} is newer than this build"
            ),
            Self::MissingWriterVersion => {
                formatter.write_str("stored record envelope has no writer_version stamp")
            }
            Self::IncompatibleWriter(version) => write!(
                formatter,
                "stored record envelope writer {version} is incompatible with this build"
            ),
            Self::Replay(inner) => {
                write!(
                    formatter,
                    "stored journal failed replay validation: {inner}"
                )
            }
        }
    }
}

impl std::error::Error for EnvelopeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Replay(inner) => Some(inner),
            _ => None,
        }
    }
}

impl From<StrictError> for EnvelopeError {
    fn from(error: StrictError) -> Self {
        match error {
            StrictError::UnsupportedSchema(version) => Self::UnsupportedSchema(version),
            StrictError::NewerSchema(version) => Self::NewerSchema(version),
            StrictError::MissingWriterStamp => Self::MissingWriterVersion,
            StrictError::WrongWriterVersion { found, .. } => Self::IncompatibleWriter(found),
            StrictError::Malformed
            | StrictError::DuplicateKey(_)
            | StrictError::MissingField(_)
            | StrictError::WrongType(_)
            | StrictError::UnknownFields(_) => Self::Malformed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalEnvelope {
    records: Vec<SendRecord>,
    risk_events: Vec<RiskEvent>,
}

#[derive(Serialize)]
struct JournalEnvelopeWire<'a> {
    schema_version: u32,
    writer_version: u32,
    records: &'a [SendRecord],
    risk_events: &'a [RiskEvent],
}

impl JournalEnvelope {
    pub fn empty() -> Self {
        Self {
            records: Vec::new(),
            risk_events: Vec::new(),
        }
    }

    pub fn record(&self, record_id: &RecordId) -> Option<&SendRecord> {
        self.records
            .iter()
            .find(|record| record.ticket().record_id() == record_id)
    }

    pub fn blocking_records_for_scope(
        &self,
        sender_wallet_id: &str,
        sender_address: &str,
        network_global_id: i32,
    ) -> Vec<&SendRecord> {
        self.records
            .iter()
            .filter(|record| {
                record.is_blocking()
                    && record.ticket().scope()
                        == (sender_wallet_id, sender_address, network_global_id)
            })
            .collect()
    }

    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(&JournalEnvelopeWire {
            schema_version: ENVELOPE_SCHEMA_VERSION,
            writer_version: ENVELOPE_WRITER_VERSION,
            records: &self.records,
            risk_events: &self.risk_events,
        })
        .expect("validated Journal records always serialize")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        let mut content = StrictObject::parse(bytes)?
            .require_schema::<EnvelopeSchemaV1>()?
            .require_writer()?;
        let records = content.take_required::<Vec<SendRecord>>("records")?;
        let risk_events = content.take_required::<Vec<RiskEvent>>("risk_events")?;
        content.finish()?;
        validate_replay(&records, &risk_events).map_err(EnvelopeError::Replay)?;
        Ok(Self {
            records,
            risk_events,
        })
    }

    pub fn append_prepared(&mut self, prepared: PreparedRecord) -> Result<(), JournalError> {
        let mut candidate = self.clone();
        let sequence = candidate.next_sequence()?;
        candidate.records.push(prepared_record(prepared, sequence)?);
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    pub fn append_delivery(
        &mut self,
        record_id: &RecordId,
        evidence: DeliveryEvidence,
    ) -> Result<(), JournalError> {
        let mut candidate = self.clone();
        let sequence = candidate.next_sequence()?;
        let record = candidate
            .records
            .iter_mut()
            .find(|record| record.ticket().record_id() == record_id)
            .ok_or(JournalError::InvalidDelivery("record id is not present"))?;
        append_delivery_event(record, sequence, evidence)?;
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    pub fn append_risk_grant(&mut self, grant: RiskGrant) -> Result<(), JournalError> {
        let mut candidate = self.clone();
        let sequence = candidate.next_sequence()?;
        candidate
            .risk_events
            .push(risk_grant_event(sequence, grant)?);
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    pub fn append_consumption_and_prepared(
        &mut self,
        consumption: RiskGrantConsumption,
        prepared: PreparedRecord,
    ) -> Result<(), JournalError> {
        let mut candidate = self.clone();
        let consumption_sequence = candidate.next_sequence()?;
        let prepared_sequence = consumption_sequence
            .checked_add(1)
            .ok_or(JournalError::SequenceOverflow)?;
        candidate
            .risk_events
            .push(risk_consumption_event(consumption_sequence, consumption)?);
        candidate
            .records
            .push(prepared_record(prepared, prepared_sequence)?);
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    fn next_sequence(&self) -> Result<u64, JournalError> {
        self.validate()?;
        let last_delivery = self
            .records
            .iter()
            .flat_map(SendRecord::delivery_events)
            .map(|event| event.journal_seq())
            .max()
            .unwrap_or(0);
        let last_risk = self
            .risk_events
            .iter()
            .map(RiskEvent::journal_seq)
            .max()
            .unwrap_or(0);
        next_sequence_after(last_delivery.max(last_risk))
    }

    fn validate(&self) -> Result<(), JournalError> {
        validate_replay(&self.records, &self.risk_events)
    }
}

accessors!(JournalEnvelope {
    records: ref [SendRecord],
    risk_events: ref [RiskEvent]
});

fn next_sequence_after(last: u64) -> Result<u64, JournalError> {
    last.checked_add(1).ok_or(JournalError::SequenceOverflow)
}

impl Default for JournalEnvelope {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivityEnvelope {
    events: Vec<ActivityEvent>,
}

#[derive(Serialize)]
struct ActivityEnvelopeWire<'a> {
    schema_version: u32,
    writer_version: u32,
    events: &'a [ActivityEvent],
}

impl ActivityEnvelope {
    pub fn new(events: Vec<ActivityEvent>) -> Self {
        Self { events }
    }

    pub fn into_events(self) -> Vec<ActivityEvent> {
        self.events
    }

    pub fn encode(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&ActivityEnvelopeWire {
            schema_version: ENVELOPE_SCHEMA_VERSION,
            writer_version: ENVELOPE_WRITER_VERSION,
            events: &self.events,
        })
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        let mut content = StrictObject::parse(bytes)?
            .require_schema::<EnvelopeSchemaV1>()?
            .require_writer()?;
        let events = content.take_required::<Vec<ActivityEvent>>("events")?;
        content.finish()?;
        Ok(Self { events })
    }
}

accessors!(ActivityEnvelope {
    events: ref [ActivityEvent]
});

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AssetAmount, BlockerRow, CcAmount, Digest32, PrepareProvenance, Reservation,
        ReservationKind, RiskNonce, SendRequest, SendTicket, blocker_set_digest,
        overlap_set_digest, reservation_set_digest,
    };

    fn digest(byte: u8) -> Digest32 {
        Digest32::from_bytes([byte; 32])
    }

    fn record_id(byte: u8) -> RecordId {
        RecordId::from_bytes([byte; 32])
    }

    fn address(byte: u8) -> String {
        format!("0:{}", format!("{byte:02x}").repeat(32))
    }

    fn native_prepared(
        id: u8,
        ext_hash: u8,
        authorized_overlap: Vec<Reservation>,
    ) -> PreparedRecord {
        native_prepared_for_identity(id, ext_hash, authorized_overlap, "wallet-1", 0x11, 42)
    }

    fn native_prepared_for_identity(
        id: u8,
        ext_hash: u8,
        authorized_overlap: Vec<Reservation>,
        wallet_id: &str,
        sender_address: u8,
        network: i32,
    ) -> PreparedRecord {
        let ticket = SendTicket::new(
            record_id(id),
            wallet_id.to_owned(),
            address(sender_address),
            network,
            "endpoint-1".to_owned(),
            SendRequest::native(address(0x22), 100).unwrap(),
            true,
            7,
            u64::from(id),
        )
        .unwrap();
        let provenance = PrepareProvenance::new(
            "endpoint-1".to_owned(),
            "route-1".to_owned(),
            vec![format!("request-{id}")],
            100,
            digest(0x31),
            false,
            vec![AssetAmount::native(10_000_000_000).unwrap()],
            digest(0x32),
            network,
            true,
            None,
            digest(0x33),
            4,
            crate::LOCAL_SEND_FEE_CEILING_NANOS,
            authorized_overlap,
        )
        .unwrap();
        let reservation = Reservation::new(
            record_id(id),
            AssetAmount::native(100 + crate::LOCAL_SEND_FEE_CEILING_NANOS).unwrap(),
            ReservationKind::Transfer,
        )
        .unwrap();
        PreparedRecord::new(
            ticket,
            provenance,
            digest(ext_hash),
            1_000,
            vec![reservation],
        )
        .unwrap()
    }

    fn grant_for(envelope: &JournalEnvelope, prepared: &PreparedRecord, nonce: u8) -> RiskGrant {
        let relevant: Vec<_> = envelope
            .records()
            .iter()
            .filter(|record| {
                matches!(
                    record.delivery_events().last().unwrap().evidence(),
                    DeliveryEvidence::Prepared
                        | DeliveryEvidence::AttemptStarted { .. }
                        | DeliveryEvidence::MayHaveBroadcast { .. }
                        | DeliveryEvidence::NodeResponseObserved { .. }
                        | DeliveryEvidence::EndpointReportedSuccess { .. }
                        | DeliveryEvidence::EndpointReportedFailedOnChain { .. }
                )
            })
            .collect();
        let blockers: Vec<_> = relevant
            .iter()
            .map(|record| {
                BlockerRow::new(
                    record.ticket().record_id().clone(),
                    record.delivery_events().last().unwrap().evidence().tag(),
                    record.ext_msg_hash().clone(),
                )
                .unwrap()
            })
            .collect();
        let reservations: Vec<_> = relevant
            .iter()
            .flat_map(|record| record.reservations().iter().cloned())
            .collect();
        RiskGrant::new(
            blocker_set_digest(&blockers).unwrap(),
            reservation_set_digest(&reservations).unwrap(),
            prepared.ticket().digest().unwrap(),
            prepared.ticket().record_id().clone(),
            RiskNonce::from_bytes([nonce; 32]),
            1,
            overlap_set_digest(prepared.prepare_provenance().authorized_overlap()).unwrap(),
        )
    }

    fn consume(grant: &RiskGrant) -> RiskGrantConsumption {
        RiskGrantConsumption::new(
            grant.one_use_nonce().clone(),
            grant.new_record_id().clone(),
            grant.new_ticket_digest().clone(),
        )
    }

    fn activity_event() -> ActivityEvent {
        ActivityEvent {
            direction: crate::ActivityDirection::In,
            counterparty: address(0x44),
            movements: vec![crate::AssetMovement {
                amount: AssetAmount::currency_collection(1, CcAmount::from_u128(9)),
            }],
            fee_native: 5,
            int_msg_hash: Some(digest(0xbb)),
            ..ActivityEvent::test_stub(7, 100)
        }
    }

    #[test]
    fn constants_and_empty_typed_journal_are_exactly_v1() {
        assert_eq!((ENVELOPE_SCHEMA_VERSION, ENVELOPE_WRITER_VERSION), (1, 1));
        let envelope = JournalEnvelope::empty();
        assert_eq!(JournalEnvelope::decode(&envelope.encode()), Ok(envelope));
        assert_eq!(
            std::str::from_utf8(&JournalEnvelope::empty().encode()).unwrap(),
            r#"{"schema_version":1,"writer_version":1,"records":[],"risk_events":[]}"#
        );
    }

    #[test]
    fn schema_is_classified_before_hostile_content() {
        for (bytes, expected) in [
            (
                br#"{"writer_version":1,"records":"bad","risk_events":"bad"}"#.as_slice(),
                EnvelopeError::UnsupportedSchema(0),
            ),
            (
                br#"{"schema_version":0,"writer_version":1,"records":"bad","risk_events":"bad"}"#,
                EnvelopeError::UnsupportedSchema(0),
            ),
            (
                br#"{"schema_version":2,"writer_version":1,"records":"bad","risk_events":"bad"}"#,
                EnvelopeError::NewerSchema(2),
            ),
        ] {
            assert_eq!(JournalEnvelope::decode(bytes), Err(expected));
        }
    }

    #[test]
    fn writer_and_current_content_are_strict() {
        assert_eq!(
            JournalEnvelope::decode(br#"{"schema_version":1,"records":[],"risk_events":[]}"#),
            Err(EnvelopeError::MissingWriterVersion)
        );
        assert_eq!(
            JournalEnvelope::decode(
                br#"{"schema_version":1,"writer_version":2,"records":[],"risk_events":[]}"#,
            ),
            Err(EnvelopeError::IncompatibleWriter(2))
        );
        for malformed in [
            br#"{"schema_version":1,"writer_version":1,"records":[]}"#.as_slice(),
            br#"{"schema_version":1,"writer_version":1,"records":[],"risk_events":[],"x":1}"#,
            br#"{"schema_version":1,"schema_version":1,"writer_version":1,"records":[],"risk_events":[]}"#,
            br#"[]"#,
        ] {
            assert_eq!(JournalEnvelope::decode(malformed), Err(EnvelopeError::Malformed));
        }
    }

    #[test]
    fn arbitrary_top_level_order_is_accepted() {
        let bytes = br#"{"risk_events":[],"writer_version":1,"records":[],"schema_version":1}"#;
        assert_eq!(JournalEnvelope::decode(bytes), Ok(JournalEnvelope::empty()));
    }

    #[test]
    fn activity_is_typed_and_rejects_legacy_bare_vectors() {
        let envelope = ActivityEnvelope::new(vec![activity_event()]);
        assert_eq!(
            ActivityEnvelope::decode(&envelope.encode().unwrap()),
            Ok(envelope)
        );
        assert_eq!(
            ActivityEnvelope::decode(b"[]"),
            Err(EnvelopeError::Malformed)
        );
    }

    #[test]
    fn activity_encoding_fails_instead_of_panicking_on_an_invalid_native_scalar() {
        let mut event = activity_event();
        event.fee_native = crate::NATIVE_MAX_UNITS + 1;
        assert!(ActivityEnvelope::new(vec![event]).encode().is_err());
    }

    #[test]
    fn activity_requires_nullable_keys_and_rejects_nested_duplicate_amount_members() {
        let json = String::from_utf8(
            ActivityEnvelope::new(vec![activity_event()])
                .encode()
                .unwrap(),
        )
        .unwrap();
        let missing = json.replace(",\"finality_ms\":null", "");
        assert_eq!(
            ActivityEnvelope::decode(missing.as_bytes()),
            Err(EnvelopeError::Malformed)
        );
        for key in ["tx_hash", "ext_msg_hash", "int_msg_hash"] {
            let marker = format!(",\"{key}\":");
            let start = json.find(&marker).expect("fixture contains nullable key");
            let value_start = start + marker.len();
            let value_len = if json.as_bytes()[value_start] == b'"' {
                json[value_start + 1..]
                    .find('"')
                    .expect("hash string closes")
                    + 2
            } else {
                4
            };
            let mut missing = json.clone();
            missing.replace_range(start..value_start + value_len, "");
            assert_eq!(
                ActivityEnvelope::decode(missing.as_bytes()),
                Err(EnvelopeError::Malformed),
                "a required-nullable {key} key cannot be omitted"
            );
        }
        let duplicate = json.replacen(
            "\"base_units\":\"9\"",
            "\"base_units\":\"9\",\"base_units\":\"9\"",
            1,
        );
        assert_eq!(
            ActivityEnvelope::decode(duplicate.as_bytes()),
            Err(EnvelopeError::Malformed)
        );
        let number = json.replacen("\"base_units\":\"9\"", "\"base_units\":9", 1);
        assert_eq!(
            ActivityEnvelope::decode(number.as_bytes()),
            Err(EnvelopeError::Malformed)
        );
    }

    #[test]
    fn journal_assigns_one_global_contiguous_sequence_and_blocks_ordinary_overlap() {
        let mut envelope = JournalEnvelope::empty();
        envelope
            .append_prepared(native_prepared(1, 0x41, Vec::new()))
            .unwrap();
        assert_eq!(envelope.records()[0].delivery_events()[0].journal_seq(), 1);

        let before = envelope.clone();
        assert_eq!(
            envelope.append_prepared(native_prepared(2, 0x42, Vec::new())),
            Err(JournalError::OrdinarySigningBlocked)
        );
        assert_eq!(envelope, before, "a refused append is transactional");

        envelope
            .append_delivery(
                &record_id(1),
                DeliveryEvidence::AttemptStarted {
                    attempt_no: 1,
                    route_id: "route-1".to_owned(),
                },
            )
            .unwrap();
        assert_eq!(envelope.records()[0].delivery_events()[1].journal_seq(), 2);
        assert_eq!(JournalEnvelope::decode(&envelope.encode()), Ok(envelope));
    }

    #[test]
    fn delivery_machine_rejects_skipped_attempts_and_unsafe_relaxation() {
        let mut prepared = JournalEnvelope::empty();
        prepared
            .append_prepared(native_prepared(1, 0x41, Vec::new()))
            .unwrap();

        for invalid in [
            DeliveryEvidence::MayHaveBroadcast {
                attempt_no: 1,
                route_id: "route-1".to_owned(),
            },
            DeliveryEvidence::NodeResponseObserved {
                attempt_no: 1,
                route_id: "route-1".to_owned(),
                request_id: "request".to_owned(),
                response: crate::NodeResponseKind::Acknowledged,
            },
            DeliveryEvidence::AttemptStarted {
                attempt_no: 2,
                route_id: "route-1".to_owned(),
            },
        ] {
            let before = prepared.clone();
            assert!(prepared.append_delivery(&record_id(1), invalid).is_err());
            assert_eq!(prepared, before);
        }

        prepared
            .append_delivery(
                &record_id(1),
                DeliveryEvidence::AttemptStarted {
                    attempt_no: 1,
                    route_id: "route-1".to_owned(),
                },
            )
            .unwrap();
        for invalid_attempt in [1, 3] {
            let before = prepared.clone();
            assert!(
                prepared
                    .append_delivery(
                        &record_id(1),
                        DeliveryEvidence::AttemptStarted {
                            attempt_no: invalid_attempt,
                            route_id: "route-1".to_owned(),
                        },
                    )
                    .is_err()
            );
            assert_eq!(prepared, before);
        }

        let mut unknown = prepared.clone();
        unknown
            .append_delivery(
                &record_id(1),
                DeliveryEvidence::MayHaveBroadcast {
                    attempt_no: 1,
                    route_id: "route-1".to_owned(),
                },
            )
            .unwrap();
        let before = unknown.clone();
        assert!(
            unknown
                .append_delivery(
                    &record_id(1),
                    DeliveryEvidence::NotBroadcast {
                        route_id: "route-1".to_owned(),
                        detail: "unsafe downgrade".to_owned(),
                    },
                )
                .is_err()
        );
        assert_eq!(unknown, before);

        let mut acknowledged = prepared;
        acknowledged
            .append_delivery(
                &record_id(1),
                DeliveryEvidence::NodeResponseObserved {
                    attempt_no: 1,
                    route_id: "route-1".to_owned(),
                    request_id: "request".to_owned(),
                    response: crate::NodeResponseKind::Acknowledged,
                },
            )
            .unwrap();
        assert!(
            acknowledged
                .append_delivery(
                    &record_id(1),
                    DeliveryEvidence::NotBroadcast {
                        route_id: "route-1".to_owned(),
                        detail: "ACK is not a local non-transmission proof".to_owned(),
                    },
                )
                .is_err()
        );
    }

    #[test]
    fn replay_validation_reads_all_three_fields_of_the_signing_scope() {
        let base = prepared_record(native_prepared(1, 0x41, Vec::new()), 1).unwrap();
        for different in [
            native_prepared_for_identity(2, 0x42, Vec::new(), "wallet-2", 0x11, 42),
            native_prepared_for_identity(2, 0x42, Vec::new(), "wallet-1", 0x12, 42),
            native_prepared_for_identity(2, 0x42, Vec::new(), "wallet-1", 0x11, 43),
        ] {
            let other = prepared_record(different, 2).unwrap();
            let outcome = validate_replay(&[base.clone(), other], &[]);
            assert!(
                matches!(
                    outcome,
                    Err(JournalError::InvalidDelivery(
                        "one encrypted Journal cannot mix wallet, sender, or network identities"
                    ))
                ),
                "a record from another signing scope is refused, got {outcome:?}"
            );
        }
    }

    #[test]
    fn one_journal_cannot_mix_vault_sender_or_network_identity() {
        let mut envelope = JournalEnvelope::empty();
        envelope
            .append_prepared(native_prepared(1, 0x41, Vec::new()))
            .unwrap();

        for different in [
            native_prepared_for_identity(2, 0x42, Vec::new(), "wallet-2", 0x11, 42),
            native_prepared_for_identity(2, 0x42, Vec::new(), "wallet-1", 0x12, 42),
            native_prepared_for_identity(2, 0x42, Vec::new(), "wallet-1", 0x11, 43),
        ] {
            let mut candidate = envelope.clone();
            assert!(candidate.append_prepared(different).is_err());
            assert_eq!(candidate, envelope);
        }
    }

    #[test]
    fn journal_rejects_an_unrecognized_risk_warning_version_transactionally() {
        let mut envelope = JournalEnvelope::empty();
        envelope
            .append_prepared(native_prepared(1, 0x41, Vec::new()))
            .unwrap();
        let overlap = envelope.records()[0].reservations().to_vec();
        let prepared = native_prepared(2, 0x42, overlap);
        let valid = grant_for(&envelope, &prepared, 0x51);
        let invalid = RiskGrant::new(
            valid.old_blocker_set_digest().clone(),
            valid.old_reservation_set_digest().clone(),
            valid.new_ticket_digest().clone(),
            valid.new_record_id().clone(),
            valid.one_use_nonce().clone(),
            crate::RISK_WARNING_VERSION + 1,
            valid.overlap_reservation_set_digest().clone(),
        );

        let before = envelope.clone();
        assert_eq!(
            envelope.append_risk_grant(invalid),
            Err(JournalError::UnsupportedWarningVersion)
        );
        assert_eq!(envelope, before);
    }

    #[test]
    fn journal_validates_grant_blocker_digests_at_the_grant_sequence() {
        let mut envelope = JournalEnvelope::empty();
        envelope
            .append_prepared(native_prepared(1, 0x41, Vec::new()))
            .unwrap();
        let overlap = envelope.records()[0].reservations().to_vec();
        let prepared = native_prepared(2, 0x42, overlap);
        let valid = grant_for(&envelope, &prepared, 0x51);
        let invalid = RiskGrant::new(
            digest(0xfe),
            valid.old_reservation_set_digest().clone(),
            valid.new_ticket_digest().clone(),
            valid.new_record_id().clone(),
            valid.one_use_nonce().clone(),
            crate::RISK_WARNING_VERSION,
            valid.overlap_reservation_set_digest().clone(),
        );

        let before = envelope.clone();
        assert_eq!(
            envelope.append_risk_grant(invalid),
            Err(JournalError::GrantDigestMismatch)
        );
        assert_eq!(envelope, before);
    }

    #[test]
    fn consumption_and_prepared_are_atomic_adjacent_and_replay_after_restart() {
        let mut envelope = JournalEnvelope::empty();
        envelope
            .append_prepared(native_prepared(1, 0x41, Vec::new()))
            .unwrap();
        let overlap = envelope.records()[0].reservations().to_vec();
        let prepared = native_prepared(2, 0x42, overlap);
        let grant = grant_for(&envelope, &prepared, 0x51);
        envelope.append_risk_grant(grant.clone()).unwrap();

        let before = envelope.clone();
        let wrong = RiskGrantConsumption::new(
            grant.one_use_nonce().clone(),
            record_id(0xee),
            grant.new_ticket_digest().clone(),
        );
        assert_eq!(
            envelope.append_consumption_and_prepared(wrong, prepared.clone()),
            Err(JournalError::ConsumptionMismatch)
        );
        assert_eq!(envelope, before);

        envelope
            .append_consumption_and_prepared(consume(&grant), prepared)
            .unwrap();
        assert_eq!(envelope.risk_events()[0].journal_seq(), 2);
        assert_eq!(envelope.risk_events()[1].journal_seq(), 3);
        assert_eq!(envelope.records()[1].delivery_events()[0].journal_seq(), 4);
        assert_eq!(JournalEnvelope::decode(&envelope.encode()), Ok(envelope));
    }

    #[test]
    fn two_sequential_overrides_recompute_the_state_through_s_minus_one() {
        let mut envelope = JournalEnvelope::empty();
        envelope
            .append_prepared(native_prepared(1, 0x41, Vec::new()))
            .unwrap();

        let second = native_prepared(2, 0x42, envelope.records()[0].reservations().to_vec());
        let first_grant = grant_for(&envelope, &second, 0x51);
        envelope.append_risk_grant(first_grant.clone()).unwrap();
        envelope
            .append_consumption_and_prepared(consume(&first_grant), second)
            .unwrap();

        let third = native_prepared(3, 0x43, envelope.records()[1].reservations().to_vec());
        let second_grant = grant_for(&envelope, &third, 0x52);
        envelope.append_risk_grant(second_grant.clone()).unwrap();
        envelope
            .append_consumption_and_prepared(consume(&second_grant), third)
            .unwrap();

        let decoded = JournalEnvelope::decode(&envelope.encode()).unwrap();
        assert_eq!(decoded, envelope);
        let mut sequences: Vec<_> = decoded
            .records()
            .iter()
            .flat_map(SendRecord::delivery_events)
            .map(|event| event.journal_seq())
            .chain(decoded.risk_events().iter().map(RiskEvent::journal_seq))
            .collect();
        sequences.sort_unstable();
        assert_eq!(sequences, (1..=7).collect::<Vec<_>>());
    }

    #[test]
    fn required_null_boc_nested_duplicates_and_sequence_damage_are_blocking() {
        let mut envelope = JournalEnvelope::empty();
        envelope
            .append_prepared(native_prepared(1, 0x41, Vec::new()))
            .unwrap();
        let json = String::from_utf8(envelope.encode()).unwrap();

        let non_null = json.replace("\"message_boc_b64\":null", "\"message_boc_b64\":\"AA==\"");
        assert_eq!(
            JournalEnvelope::decode(non_null.as_bytes()),
            Err(EnvelopeError::Malformed)
        );
        let missing = json.replace(",\"message_boc_b64\":null", "");
        assert_ne!(
            missing, json,
            "fixture did not contain the BOC slot: {json}"
        );
        assert_eq!(
            JournalEnvelope::decode(missing.as_bytes()),
            Err(EnvelopeError::Malformed)
        );
        let duplicate = json.replacen(
            "\"message_boc_b64\":null",
            "\"message_boc_b64\":null,\"message_boc_b64\":null",
            1,
        );
        assert_eq!(
            JournalEnvelope::decode(duplicate.as_bytes()),
            Err(EnvelopeError::Malformed)
        );
        let missing_network_time = json.replace(",\"network_time\":null", "");
        assert_ne!(missing_network_time, json);
        assert_eq!(
            JournalEnvelope::decode(missing_network_time.as_bytes()),
            Err(EnvelopeError::Malformed),
            "network_time is required-present even when it is null"
        );
        let duplicate_network_time = json.replacen(
            "\"network_time\":null",
            "\"network_time\":null,\"network_time\":null",
            1,
        );
        assert_eq!(
            JournalEnvelope::decode(duplicate_network_time.as_bytes()),
            Err(EnvelopeError::Malformed)
        );
        let weakened_fee_cap = json.replace(
            &format!(
                "\"local_fee_ceiling_native\":\"{}\"",
                crate::LOCAL_SEND_FEE_CEILING_NANOS
            ),
            "\"local_fee_ceiling_native\":\"0\"",
        );
        assert_ne!(weakened_fee_cap, json);
        assert_eq!(
            JournalEnvelope::decode(weakened_fee_cap.as_bytes()),
            Err(EnvelopeError::Malformed),
            "a persisted record cannot select a cap below its exact fee headroom"
        );
        let unaffordable =
            json.replacen("\"base_units\":\"10000000000\"", "\"base_units\":\"1\"", 1);
        assert_ne!(unaffordable, json);
        assert!(
            matches!(
                JournalEnvelope::decode(unaffordable.as_bytes()),
                Err(EnvelopeError::Replay(_))
            ),
            "replay re-evaluates the fresh balance instead of trusting provenance"
        );
        let zero = json.replacen("\"journal_seq\":1", "\"journal_seq\":0", 1);
        assert_eq!(
            JournalEnvelope::decode(zero.as_bytes()),
            Err(EnvelopeError::Malformed)
        );
        let gap = json.replacen("\"journal_seq\":1", "\"journal_seq\":2", 1);
        assert!(matches!(
            JournalEnvelope::decode(gap.as_bytes()),
            Err(EnvelopeError::Replay(_))
        ));
    }

    #[test]
    fn replay_defects_decode_with_their_cause() {
        let mut envelope = JournalEnvelope::empty();
        envelope
            .append_prepared(native_prepared(1, 0x41, Vec::new()))
            .unwrap();
        let json = String::from_utf8(envelope.encode()).unwrap();

        let gap = json.replacen("\"journal_seq\":1", "\"journal_seq\":2", 1);
        let err = JournalEnvelope::decode(gap.as_bytes()).unwrap_err();
        assert_eq!(err, EnvelopeError::Replay(JournalError::SequenceGap));
        assert!(
            err.to_string().contains("strictly contiguous"),
            "the specific replay cause reaches the user: {err}"
        );
        assert!(
            err.to_string().contains("replay validation"),
            "the envelope layer frames it as a replay failure: {err}"
        );

        let truncated = &json.as_bytes()[..json.len() / 2];
        assert_eq!(
            JournalEnvelope::decode(truncated),
            Err(EnvelopeError::Malformed)
        );
    }

    #[test]
    fn full_width_cc_record_round_trips_without_a_numeric_amount_token() {
        const MAX: &str =
            "452312848583266388373324160190187140051835877600158453279131187530910662655";
        let cc = CcAmount::try_from_canonical_decimal(MAX).unwrap();
        let ticket = SendTicket::new(
            record_id(9),
            "wallet-cc".to_owned(),
            address(0x11),
            42,
            "endpoint-1".to_owned(),
            SendRequest::currency_collection(address(0x22), 1, cc.clone()).unwrap(),
            true,
            1,
            1,
        )
        .unwrap();
        let provenance = PrepareProvenance::new(
            "endpoint-1".to_owned(),
            "route-1".to_owned(),
            vec!["request-cc".to_owned()],
            100,
            digest(1),
            false,
            vec![
                AssetAmount::native(2_000_000_000).unwrap(),
                AssetAmount::currency_collection(1, cc.clone()),
            ],
            digest(2),
            42,
            true,
            None,
            digest(3),
            4,
            crate::LOCAL_SEND_FEE_CEILING_NANOS,
            Vec::new(),
        )
        .unwrap();
        let prepared = PreparedRecord::new(
            ticket,
            provenance,
            digest(4),
            1_000,
            vec![
                Reservation::new(
                    record_id(9),
                    AssetAmount::currency_collection(1, cc),
                    ReservationKind::Transfer,
                )
                .unwrap(),
                Reservation::new(
                    record_id(9),
                    AssetAmount::native(crate::LOCAL_SEND_FEE_CEILING_NANOS).unwrap(),
                    ReservationKind::NativeFee,
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let mut envelope = JournalEnvelope::empty();
        envelope.append_prepared(prepared).unwrap();
        let bytes = envelope.encode();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(text.contains(&format!("\"base_units\":\"{MAX}\"")));
        assert!(!text.contains(&format!("\"base_units\":{MAX}")));
        assert_eq!(JournalEnvelope::decode(&bytes), Ok(envelope));
    }

    #[test]
    fn bounded_consumed_headroom_records_round_trip_and_out_of_range_caps_refuse() {
        let ticket = SendTicket::new(
            record_id(0x41),
            "wallet-dynamic-fee".to_owned(),
            address(0x11),
            42,
            "endpoint-1".to_owned(),
            SendRequest::native(address(0x22), 100).unwrap(),
            true,
            1,
            1,
        )
        .unwrap();
        let estimated_fee = 7_491_005;
        let exact_cap = estimated_fee + crate::LOCAL_SEND_FEE_HEADROOM_NANOS;
        let provenance_for = |estimated_fee, fee_cap| {
            PrepareProvenance::new(
                "endpoint-1".to_owned(),
                "route-1".to_owned(),
                vec!["request-dynamic-fee".to_owned()],
                100,
                digest(1),
                false,
                vec![AssetAmount::native(10_000_000_000).unwrap()],
                digest(2),
                42,
                true,
                None,
                digest(3),
                estimated_fee,
                fee_cap,
                Vec::new(),
            )
        };
        let provenance = provenance_for(estimated_fee, exact_cap).unwrap();
        let prepared = PreparedRecord::new(
            ticket.clone(),
            provenance,
            digest(4),
            1_000,
            vec![
                Reservation::new(
                    record_id(0x41),
                    AssetAmount::native(100 + exact_cap).unwrap(),
                    ReservationKind::Transfer,
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let mut envelope = JournalEnvelope::empty();
        envelope.append_prepared(prepared).unwrap();
        let bytes = envelope.encode();
        assert_eq!(JournalEnvelope::decode(&bytes), Ok(envelope));

        let consumed_cap = exact_cap - 1;
        let consumed_provenance = provenance_for(estimated_fee, consumed_cap).unwrap();
        let consumed_prepared = PreparedRecord::new(
            ticket,
            consumed_provenance,
            digest(5),
            1_001,
            vec![
                Reservation::new(
                    record_id(0x41),
                    AssetAmount::native(100 + consumed_cap).unwrap(),
                    ReservationKind::Transfer,
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let mut consumed_envelope = JournalEnvelope::empty();
        consumed_envelope
            .append_prepared(consumed_prepared)
            .unwrap();
        let consumed_bytes = consumed_envelope.encode();
        assert_eq!(
            JournalEnvelope::decode(&consumed_bytes),
            Ok(consumed_envelope)
        );

        assert!(
            provenance_for(estimated_fee, exact_cap + 1).is_err(),
            "a persisted record cannot exceed the shared headroom"
        );
        assert!(
            provenance_for(estimated_fee, estimated_fee - 1).is_err(),
            "a persisted record cannot reserve less than the exact emulated fee"
        );
        assert!(
            provenance_for(estimated_fee, crate::LOCAL_SEND_FEE_CEILING_NANOS).is_ok(),
            "legacy one-coin records remain readable"
        );
        assert!(
            provenance_for(
                crate::LOCAL_SEND_FEE_CEILING_NANOS + 1,
                crate::LOCAL_SEND_FEE_CEILING_NANOS
            )
            .is_err()
        );
        assert!(provenance_for(estimated_fee, crate::LOCAL_SEND_FEE_CEILING_NANOS + 1).is_err());
    }

    #[test]
    fn sequence_increment_refuses_overflow() {
        assert_eq!(next_sequence_after(0), Ok(1));
        assert_eq!(
            next_sequence_after(u64::MAX),
            Err(JournalError::SequenceOverflow)
        );
    }
}
