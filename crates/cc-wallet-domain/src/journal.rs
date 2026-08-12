use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::de::{self};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::value::RawValue;

use crate::activity::AssetMovement;
use crate::amount::AssetAmount;
use crate::asset::AssetId;
use crate::digest::{
    BlockerRow, CanonicalAddress, DigestError, EvidenceTag, Reservation, ReservationKind,
    TicketDigestInput, blocker_set_digest, overlap_set_digest, reservation_set_digest,
    ticket_digest,
};
use crate::ids::{Digest32, RecordId};
use crate::risk::{RiskAction, RiskGrant, RiskGrantConsumption};
use crate::send::SendRequest;

pub const LOCAL_SEND_FEE_CEILING_NANOS: u128 = 1_000_000_000;

pub const LOCAL_SEND_FEE_HEADROOM_NANOS: u128 = 400_000;

pub fn max_native_spendable(balance_units: u128, fee_nanos: u128) -> u128 {
    balance_units.saturating_sub(fee_nanos.saturating_add(LOCAL_SEND_FEE_HEADROOM_NANOS))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalError {
    InvalidTicket(&'static str),
    InvalidProvenance(&'static str),
    InvalidReservation(&'static str),
    InvalidDelivery(&'static str),
    DuplicateRecord,
    SequenceZero,
    SequenceGap,
    SequenceOverflow,
    OrphanConsumption,
    UnsupportedWarningVersion,
    ConsumptionMismatch,
    ConsumptionNotAdjacent,
    DuplicateConsumption,
    OrdinarySigningBlocked,
    GrantDigestMismatch,
    Digest(DigestError),
}

impl fmt::Display for JournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTicket(detail) => write!(formatter, "invalid send ticket: {detail}"),
            Self::InvalidProvenance(detail) => {
                write!(formatter, "invalid prepare provenance: {detail}")
            }
            Self::InvalidReservation(detail) => write!(formatter, "invalid reservation: {detail}"),
            Self::InvalidDelivery(detail) => write!(formatter, "invalid delivery event: {detail}"),
            Self::DuplicateRecord => formatter.write_str("a Journal record id is duplicated"),
            Self::SequenceZero => formatter.write_str("journal_seq must start at 1, never zero"),
            Self::SequenceGap => {
                formatter.write_str("journal_seq values must be unique and strictly contiguous")
            }
            Self::SequenceOverflow => formatter.write_str("journal_seq overflow"),
            Self::OrphanConsumption => {
                formatter.write_str("risk consumption has no prior matching grant")
            }
            Self::UnsupportedWarningVersion => {
                formatter.write_str("risk grant uses an unsupported warning version")
            }
            Self::ConsumptionMismatch => {
                formatter.write_str("risk consumption does not match its one-use grant")
            }
            Self::ConsumptionNotAdjacent => formatter.write_str(
                "risk consumption must be immediately followed by its matching Prepared event",
            ),
            Self::DuplicateConsumption => {
                formatter.write_str("a one-use risk grant was consumed more than once")
            }
            Self::OrdinarySigningBlocked => formatter.write_str(
                "ordinary signing is blocked by prior unresolved delivery evidence",
            ),
            Self::GrantDigestMismatch => formatter.write_str(
                "risk grant digests do not match the replayed blocker/reservation/ticket/overlap state",
            ),
            Self::Digest(error) => write!(formatter, "journal digest failed: {error}"),
        }
    }
}

impl std::error::Error for JournalError {}

impl From<DigestError> for JournalError {
    fn from(error: DigestError) -> Self {
        Self::Digest(error)
    }
}

fn validate_identity(value: &str) -> bool {
    !value.is_empty()
        && value.trim() == value
        && !value
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
}

fn parse_canonical_address(value: &str) -> Result<CanonicalAddress, JournalError> {
    let (workchain, account) = value
        .split_once(':')
        .ok_or(JournalError::InvalidTicket("address is not workchain:hash"))?;
    let workchain: i8 = workchain
        .parse()
        .map_err(|_| JournalError::InvalidTicket("address workchain is not an i8"))?;
    if !matches!(workchain, -1 | 0)
        || workchain.to_string() != value[..value.len() - account.len() - 1]
    {
        return Err(JournalError::InvalidTicket(
            "address workchain is not canonical 0 or -1",
        ));
    }
    let bytes: [u8; 32] = crate::ids::hex_lower_decode(account)
        .filter(|decoded| decoded.len() == 32)
        .and_then(|decoded| decoded.try_into().ok())
        .ok_or(JournalError::InvalidTicket(
            "address hash is not 64 lowercase hex digits",
        ))?;
    Ok(CanonicalAddress::new(workchain, bytes))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SendTicket {
    record_id: RecordId,
    sender_wallet_id: String,
    sender_address: String,
    network_global_id: i32,
    endpoint_identity: String,
    request: SendRequest,
    bounce: bool,
    auth_generation: u64,
    auth_nonce: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SendTicketWire {
    record_id: RecordId,
    sender_wallet_id: String,
    sender_address: String,
    network_global_id: i32,
    endpoint_identity: String,
    request: SendRequest,
    bounce: bool,
    auth_generation: u64,
    auth_nonce: u64,
}

impl SendTicket {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        record_id: RecordId,
        sender_wallet_id: String,
        sender_address: String,
        network_global_id: i32,
        endpoint_identity: String,
        request: SendRequest,
        bounce: bool,
        auth_generation: u64,
        auth_nonce: u64,
    ) -> Result<Self, JournalError> {
        if !validate_identity(&sender_wallet_id) {
            return Err(JournalError::InvalidTicket(
                "sender wallet identity is empty or noncanonical",
            ));
        }
        if !validate_identity(&endpoint_identity) {
            return Err(JournalError::InvalidTicket(
                "endpoint identity is empty or noncanonical",
            ));
        }
        parse_canonical_address(&sender_address)?;
        parse_canonical_address(request.destination())?;
        Ok(Self {
            record_id,
            sender_wallet_id,
            sender_address,
            network_global_id,
            endpoint_identity,
            request,
            bounce,
            auth_generation,
            auth_nonce,
        })
    }

    pub fn digest(&self) -> Result<Digest32, DigestError> {
        let sender_address = parse_canonical_address(&self.sender_address)
            .expect("SendTicket construction keeps its sender address canonical");
        let destination = parse_canonical_address(self.request.destination())
            .expect("SendTicket construction keeps its destination canonical");
        ticket_digest(&TicketDigestInput {
            record_id: &self.record_id,
            sender_wallet_id: self.sender_wallet_id.as_bytes(),
            sender_address,
            network_global_id: self.network_global_id,
            endpoint_identity: self.endpoint_identity.as_bytes(),
            destination,
            value: self.request.value(),
            bounce: self.bounce,
            auth_generation: self.auth_generation,
            auth_nonce: self.auth_nonce,
        })
    }
}

impl SendTicket {
    pub fn scope(&self) -> (&str, &str, i32) {
        (
            &self.sender_wallet_id,
            &self.sender_address,
            self.network_global_id,
        )
    }
}

accessors!(SendTicket {
    record_id: ref RecordId,
    sender_wallet_id: ref str,
    sender_address: ref str,
    network_global_id: copy i32,
    endpoint_identity: ref str,
    request: ref SendRequest,
    bounce: copy bool,
    auth_generation: copy u64,
    auth_nonce: copy u64
});

wire_deserialize!(SendTicket via SendTicketWire {
    record_id,
    sender_wallet_id,
    sender_address,
    network_global_id,
    endpoint_identity,
    request,
    bounce,
    auth_generation,
    auth_nonce
});

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NetworkTimeProvenance {
    value: u32,
    source_endpoint: String,
    request_id: String,
    observed_at_mono_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkTimeProvenanceWire {
    value: u32,
    source_endpoint: String,
    request_id: String,
    observed_at_mono_ms: u64,
}

impl NetworkTimeProvenance {
    pub fn new(
        value: u32,
        source_endpoint: String,
        request_id: String,
        observed_at_mono_ms: u64,
    ) -> Result<Self, JournalError> {
        if !validate_identity(&source_endpoint) || !validate_identity(&request_id) {
            return Err(JournalError::InvalidProvenance(
                "network-time endpoint/request identity is noncanonical",
            ));
        }
        Ok(Self {
            value,
            source_endpoint,
            request_id,
            observed_at_mono_ms,
        })
    }
}

accessors!(NetworkTimeProvenance {
    value: copy u32,
    source_endpoint: ref str,
    request_id: ref str
});

wire_deserialize!(NetworkTimeProvenance via NetworkTimeProvenanceWire {
    value,
    source_endpoint,
    request_id,
    observed_at_mono_ms
});

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrepareProvenance {
    source_endpoint: String,
    route_id: String,
    request_ids: Vec<String>,
    observed_at_mono_ms: u64,
    account_state_hash: Digest32,
    state_init_required: bool,
    balances: Vec<AssetAmount>,
    signature_context_hash: Digest32,
    signature_global_id: i32,
    signature_with_id: bool,
    network_time: Option<NetworkTimeProvenance>,
    fee_input_hash: Digest32,
    #[serde(with = "crate::amount::native_scalar")]
    estimated_fee_native: u128,
    #[serde(with = "crate::amount::native_scalar")]
    local_fee_ceiling_native: u128,
    authorized_overlap: Vec<Reservation>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareProvenanceWire {
    source_endpoint: String,
    route_id: String,
    request_ids: Vec<String>,
    observed_at_mono_ms: u64,
    account_state_hash: Digest32,
    state_init_required: bool,
    balances: Vec<AssetAmount>,
    signature_context_hash: Digest32,
    signature_global_id: i32,
    signature_with_id: bool,
    #[serde(deserialize_with = "crate::strict::required_nullable")]
    network_time: Option<NetworkTimeProvenance>,
    fee_input_hash: Digest32,
    #[serde(with = "crate::amount::native_scalar")]
    estimated_fee_native: u128,
    #[serde(with = "crate::amount::native_scalar")]
    local_fee_ceiling_native: u128,
    authorized_overlap: Vec<Reservation>,
}

impl PrepareProvenance {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source_endpoint: String,
        route_id: String,
        request_ids: Vec<String>,
        observed_at_mono_ms: u64,
        account_state_hash: Digest32,
        state_init_required: bool,
        balances: Vec<AssetAmount>,
        signature_context_hash: Digest32,
        signature_global_id: i32,
        signature_with_id: bool,
        network_time: Option<NetworkTimeProvenance>,
        fee_input_hash: Digest32,
        estimated_fee_native: u128,
        local_fee_ceiling_native: u128,
        authorized_overlap: Vec<Reservation>,
    ) -> Result<Self, JournalError> {
        if !validate_identity(&source_endpoint)
            || !validate_identity(&route_id)
            || request_ids.is_empty()
            || request_ids.iter().any(|id| !validate_identity(id))
            || request_ids.iter().collect::<BTreeSet<_>>().len() != request_ids.len()
        {
            return Err(JournalError::InvalidProvenance(
                "source/route/request identities are missing or noncanonical",
            ));
        }
        let derived_fee_ceiling = estimated_fee_native.checked_add(LOCAL_SEND_FEE_HEADROOM_NANOS);
        let bounded_dynamic_ceiling = derived_fee_ceiling.is_some_and(|maximum| {
            local_fee_ceiling_native >= estimated_fee_native && local_fee_ceiling_native <= maximum
        });
        if estimated_fee_native > LOCAL_SEND_FEE_CEILING_NANOS
            || local_fee_ceiling_native > LOCAL_SEND_FEE_CEILING_NANOS
            || (local_fee_ceiling_native != LOCAL_SEND_FEE_CEILING_NANOS
                && !bounded_dynamic_ceiling)
        {
            return Err(JournalError::InvalidProvenance(
                "native fee reserve is neither the legacy cap nor a bounded local headroom",
            ));
        }
        let mut assets = BTreeSet::new();
        if balances
            .iter()
            .any(|balance| !assets.insert(balance.asset_id()))
        {
            return Err(JournalError::InvalidProvenance(
                "fresh balances contain a duplicate asset",
            ));
        }
        if let Some(observation) = &network_time
            && (observation.source_endpoint != source_endpoint
                || observation.observed_at_mono_ms > observed_at_mono_ms)
        {
            return Err(JournalError::InvalidProvenance(
                "network-time provenance is not bound to the prepare endpoint",
            ));
        }
        overlap_set_digest(&authorized_overlap)?;
        Ok(Self {
            source_endpoint,
            route_id,
            request_ids,
            observed_at_mono_ms,
            account_state_hash,
            state_init_required,
            balances,
            signature_context_hash,
            signature_global_id,
            signature_with_id,
            network_time,
            fee_input_hash,
            estimated_fee_native,
            local_fee_ceiling_native,
            authorized_overlap,
        })
    }
}

accessors!(PrepareProvenance {
    source_endpoint: ref str,
    route_id: ref str,
    request_ids: ref [String],
    balances: ref [AssetAmount],
    network_time: opt NetworkTimeProvenance,
    authorized_overlap: ref [Reservation]
});

wire_deserialize!(PrepareProvenance via PrepareProvenanceWire {
    source_endpoint,
    route_id,
    request_ids,
    observed_at_mono_ms,
    account_state_hash,
    state_init_required,
    balances,
    signature_context_hash,
    signature_global_id,
    signature_with_id,
    network_time,
    fee_input_hash,
    estimated_fee_native,
    local_fee_ceiling_native,
    authorized_overlap
});

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeResponseKind {
    Acknowledged,
    Rejected,
    TransportError,
    Malformed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalOutcome {
    Success,
    FailedOnChain,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EndpointTransactionEvidence {
    source_endpoint: String,
    request_id: String,
    sender_address: String,
    tx_hash: Digest32,
    ext_msg_hash: Digest32,
    lt: u64,
    success: bool,
    exit_code: i32,
    effects: Vec<AssetMovement>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EndpointTransactionEvidenceWire {
    source_endpoint: String,
    request_id: String,
    sender_address: String,
    tx_hash: Digest32,
    ext_msg_hash: Digest32,
    lt: u64,
    success: bool,
    exit_code: i32,
    effects: Vec<AssetMovement>,
}

impl EndpointTransactionEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source_endpoint: String,
        request_id: String,
        sender_address: String,
        tx_hash: Digest32,
        ext_msg_hash: Digest32,
        lt: u64,
        success: bool,
        exit_code: i32,
        effects: Vec<AssetMovement>,
    ) -> Result<Self, JournalError> {
        let evidence = Self {
            source_endpoint,
            request_id,
            sender_address,
            tx_hash,
            ext_msg_hash,
            lt,
            success,
            exit_code,
            effects,
        };
        validate_endpoint_tx(&evidence)?;
        Ok(evidence)
    }
}

accessors!(EndpointTransactionEvidence {
    source_endpoint: ref str,
    request_id: ref str,
    sender_address: ref str,
    tx_hash: ref Digest32,
    ext_msg_hash: ref Digest32,
    lt: copy u64,
    success: copy bool,
    exit_code: copy i32,
    effects: ref [AssetMovement]
});

wire_deserialize!(EndpointTransactionEvidence via EndpointTransactionEvidenceWire {
    source_endpoint,
    request_id,
    sender_address,
    tx_hash,
    ext_msg_hash,
    lt,
    success,
    exit_code,
    effects
});

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "payload",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum DeliveryEvidence {
    Prepared,
    AttemptStarted {
        attempt_no: u32,
        route_id: String,
    },
    MayHaveBroadcast {
        attempt_no: u32,
        route_id: String,
    },
    NodeResponseObserved {
        attempt_no: u32,
        route_id: String,
        request_id: String,
        response: NodeResponseKind,
    },
    EndpointReportedSuccess {
        tx: EndpointTransactionEvidence,
    },
    EndpointReportedFailedOnChain {
        tx: EndpointTransactionEvidence,
    },
    VerifiedTerminal {
        outcome: TerminalOutcome,
        proof_ref: String,
    },
    NotBroadcast {
        route_id: String,
        detail: String,
    },
}

impl DeliveryEvidence {
    pub fn tag(&self) -> EvidenceTag {
        match self {
            Self::Prepared => EvidenceTag::Prepared,
            Self::AttemptStarted { .. } => EvidenceTag::AttemptStarted,
            Self::MayHaveBroadcast { .. } => EvidenceTag::MayHaveBroadcast,
            Self::NodeResponseObserved { .. } => EvidenceTag::NodeResponseObserved,
            Self::EndpointReportedSuccess { .. } => EvidenceTag::EndpointReportedSuccess,
            Self::EndpointReportedFailedOnChain { .. } => {
                EvidenceTag::EndpointReportedFailedOnChain
            }
            Self::VerifiedTerminal {
                outcome: TerminalOutcome::Success,
                ..
            } => EvidenceTag::VerifiedTerminalSuccess,
            Self::VerifiedTerminal {
                outcome: TerminalOutcome::FailedOnChain,
                ..
            } => EvidenceTag::VerifiedTerminalFailedOnChain,
            Self::NotBroadcast { .. } => EvidenceTag::NotBroadcast,
        }
    }

    fn validate(&self) -> Result<(), JournalError> {
        match self {
            Self::Prepared => Ok(()),
            Self::AttemptStarted {
                attempt_no,
                route_id,
            }
            | Self::MayHaveBroadcast {
                attempt_no,
                route_id,
            } if *attempt_no > 0 && validate_identity(route_id) => Ok(()),
            Self::NodeResponseObserved {
                attempt_no,
                route_id,
                request_id,
                ..
            } if *attempt_no > 0
                && validate_identity(route_id)
                && validate_identity(request_id) =>
            {
                Ok(())
            }
            Self::EndpointReportedSuccess { tx } if tx.success => validate_endpoint_tx(tx),
            Self::EndpointReportedFailedOnChain { tx } if !tx.success => validate_endpoint_tx(tx),
            Self::VerifiedTerminal { proof_ref, .. } if validate_identity(proof_ref) => Ok(()),
            Self::NotBroadcast { route_id, detail }
                if validate_identity(route_id) && validate_identity(detail) =>
            {
                Ok(())
            }
            _ => Err(JournalError::InvalidDelivery(
                "payload is empty, inconsistent, or out of range",
            )),
        }
    }
}

fn validate_endpoint_tx(tx: &EndpointTransactionEvidence) -> Result<(), JournalError> {
    if !validate_identity(&tx.source_endpoint)
        || !validate_identity(&tx.request_id)
        || parse_canonical_address(&tx.sender_address).is_err()
    {
        return Err(JournalError::InvalidDelivery(
            "endpoint transaction provenance is noncanonical",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryEvent {
    journal_seq: u64,
    evidence: DeliveryEvidence,
}

impl DeliveryEvent {
    fn new(journal_seq: u64, evidence: DeliveryEvidence) -> Result<Self, JournalError> {
        if journal_seq == 0 {
            return Err(JournalError::SequenceZero);
        }
        evidence.validate()?;
        Ok(Self {
            journal_seq,
            evidence,
        })
    }
}

accessors!(DeliveryEvent {
    journal_seq: copy u64,
    evidence: ref DeliveryEvidence
});

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiskEvent {
    journal_seq: u64,
    action: RiskAction,
}

impl RiskEvent {
    fn new(journal_seq: u64, action: RiskAction) -> Result<Self, JournalError> {
        if journal_seq == 0 {
            return Err(JournalError::SequenceZero);
        }
        Ok(Self {
            journal_seq,
            action,
        })
    }

    pub fn grant(&self) -> Option<&RiskGrant> {
        match &self.action {
            RiskAction::Granted(grant) => Some(grant),
            RiskAction::Consumed(_) => None,
        }
    }

    pub fn consumption(&self) -> Option<&RiskGrantConsumption> {
        match &self.action {
            RiskAction::Consumed(consumption) => Some(consumption),
            RiskAction::Granted(_) => None,
        }
    }
}

accessors!(RiskEvent {
    journal_seq: copy u64
});

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedRecord {
    ticket: SendTicket,
    prepare_provenance: PrepareProvenance,
    ext_msg_hash: Digest32,
    expire_at: u32,
    reservations: Vec<Reservation>,
}

fn check_prepared_shape(
    ticket: &SendTicket,
    prepare_provenance: &PrepareProvenance,
    reservations: &[Reservation],
) -> Result<(), JournalError> {
    if prepare_provenance.source_endpoint != ticket.endpoint_identity
        || prepare_provenance.signature_global_id != ticket.network_global_id
    {
        return Err(JournalError::InvalidProvenance(
            "prepare source/global id does not match the immutable ticket",
        ));
    }
    validate_reservations(
        ticket,
        prepare_provenance.local_fee_ceiling_native,
        reservations,
    )
}

impl PreparedRecord {
    pub fn new(
        ticket: SendTicket,
        prepare_provenance: PrepareProvenance,
        ext_msg_hash: Digest32,
        expire_at: u32,
        reservations: Vec<Reservation>,
    ) -> Result<Self, JournalError> {
        check_prepared_shape(&ticket, &prepare_provenance, &reservations)?;
        Ok(Self {
            ticket,
            prepare_provenance,
            ext_msg_hash,
            expire_at,
            reservations,
        })
    }
}

accessors!(PreparedRecord {
    ticket: ref SendTicket,
    prepare_provenance: ref PrepareProvenance,
    ext_msg_hash: ref Digest32,
    expire_at: copy u32,
    reservations: ref [Reservation]
});

fn validate_reservations(
    ticket: &SendTicket,
    fee_units: u128,
    reservations: &[Reservation],
) -> Result<(), JournalError> {
    if reservations.iter().any(|reservation| {
        reservation.record_id() != ticket.record_id() || reservation.amount().is_zero()
    }) {
        return Err(JournalError::InvalidReservation(
            "row id differs from the ticket or amount is zero",
        ));
    }
    match ticket.request.value().asset_id() {
        AssetId::Native => {
            let fee = AssetAmount::native(fee_units)
                .map_err(|_| JournalError::InvalidReservation("native fee is out of domain"))?;
            let total = ticket
                .request
                .value()
                .checked_add_same_asset(&fee)
                .map_err(|_| {
                    JournalError::InvalidReservation("native transfer plus fee overflows")
                })?;
            if reservations.len() != 1
                || reservations[0].kind() != ReservationKind::Transfer
                || reservations[0].amount() != &total
            {
                return Err(JournalError::InvalidReservation(
                    "native send requires one exact transfer-plus-fee reservation",
                ));
            }
        }
        AssetId::CurrencyCollection(_) => {
            let fee = AssetAmount::native(fee_units)
                .map_err(|_| JournalError::InvalidReservation("native fee is out of domain"))?;
            let transfer = reservations.iter().filter(|row| {
                row.kind() == ReservationKind::Transfer && row.amount() == ticket.request.value()
            });
            let native_fee = reservations
                .iter()
                .filter(|row| row.kind() == ReservationKind::NativeFee && row.amount() == &fee);
            if reservations.len() != 2 || transfer.count() != 1 || native_fee.count() != 1 {
                return Err(JournalError::InvalidReservation(
                    "CC send requires exact CC transfer and separate native-fee reservations",
                ));
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendRecord {
    ticket: SendTicket,
    prepare_provenance: PrepareProvenance,
    ext_msg_hash: Digest32,
    expire_at: u32,
    reservations: Vec<Reservation>,
    delivery_events: Vec<DeliveryEvent>,
}

impl SendRecord {
    pub fn latest_evidence(&self) -> &DeliveryEvidence {
        &self
            .delivery_events
            .last()
            .expect("validated record always has Prepared")
            .evidence
    }

    pub fn latest_evidence_tag(&self) -> EvidenceTag {
        self.latest_evidence().tag()
    }

    pub fn is_blocking(&self) -> bool {
        self.latest_evidence_tag().is_blocking()
    }

    pub fn has_duplicate_fingerprint(&self, ticket: &SendTicket) -> bool {
        self.ticket.scope() == ticket.scope()
            && self.ticket.request.destination() == ticket.request.destination()
            && self.ticket.request.asset_id() == ticket.request.asset_id()
    }

    fn validate_static(&self) -> Result<(), JournalError> {
        if self.delivery_events.is_empty()
            || !matches!(self.delivery_events[0].evidence, DeliveryEvidence::Prepared)
            || self
                .delivery_events
                .iter()
                .skip(1)
                .any(|event| matches!(event.evidence, DeliveryEvidence::Prepared))
        {
            return Err(JournalError::InvalidDelivery(
                "each record requires exactly one first Prepared event",
            ));
        }
        check_prepared_shape(&self.ticket, &self.prepare_provenance, &self.reservations)?;
        let mut prior = 0u64;
        let mut terminal = false;
        let mut previous_evidence: Option<&DeliveryEvidence> = None;
        for event in &self.delivery_events {
            event.evidence.validate()?;
            if let Some(previous) = previous_evidence
                && !valid_delivery_transition(previous, &event.evidence)
            {
                return Err(JournalError::InvalidDelivery(
                    "delivery evidence transition is not monotone or attempt-bound",
                ));
            }
            match &event.evidence {
                DeliveryEvidence::AttemptStarted { route_id, .. }
                | DeliveryEvidence::MayHaveBroadcast { route_id, .. }
                | DeliveryEvidence::NodeResponseObserved { route_id, .. }
                | DeliveryEvidence::NotBroadcast { route_id, .. }
                    if route_id != self.prepare_provenance.route_id() =>
                {
                    return Err(JournalError::InvalidDelivery(
                        "delivery route differs from the frozen prepare route",
                    ));
                }
                DeliveryEvidence::EndpointReportedSuccess { tx }
                | DeliveryEvidence::EndpointReportedFailedOnChain { tx }
                    if tx.source_endpoint() != self.ticket.endpoint_identity()
                        || tx.sender_address() != self.ticket.sender_address()
                        || tx.ext_msg_hash() != &self.ext_msg_hash =>
                {
                    return Err(JournalError::InvalidDelivery(
                        "endpoint transaction does not match the immutable ticket/message",
                    ));
                }
                _ => {}
            }
            if event.journal_seq <= prior {
                return Err(JournalError::SequenceGap);
            }
            if terminal {
                return Err(JournalError::InvalidDelivery(
                    "no event may follow durable terminal evidence",
                ));
            }
            terminal = matches!(
                event.evidence,
                DeliveryEvidence::VerifiedTerminal { .. } | DeliveryEvidence::NotBroadcast { .. }
            );
            prior = event.journal_seq;
            previous_evidence = Some(&event.evidence);
        }
        Ok(())
    }
}

accessors!(SendRecord {
    ticket: ref SendTicket,
    prepare_provenance: ref PrepareProvenance,
    ext_msg_hash: ref Digest32,
    expire_at: copy u32,
    reservations: ref [Reservation],
    delivery_events: ref [DeliveryEvent]
});

fn valid_delivery_transition(previous: &DeliveryEvidence, next: &DeliveryEvidence) -> bool {
    match (previous, next) {
        (
            DeliveryEvidence::Prepared,
            DeliveryEvidence::AttemptStarted { attempt_no: 1, .. }
            | DeliveryEvidence::NotBroadcast { .. },
        ) => true,
        (
            DeliveryEvidence::AttemptStarted {
                attempt_no: previous,
                ..
            },
            DeliveryEvidence::AttemptStarted {
                attempt_no: next, ..
            },
        ) => previous.checked_add(1) == Some(*next),
        (
            DeliveryEvidence::AttemptStarted {
                attempt_no: previous,
                ..
            },
            DeliveryEvidence::MayHaveBroadcast {
                attempt_no: next, ..
            }
            | DeliveryEvidence::NodeResponseObserved {
                attempt_no: next, ..
            },
        ) => previous == next,
        (DeliveryEvidence::AttemptStarted { .. }, DeliveryEvidence::NotBroadcast { .. }) => true,
        (
            DeliveryEvidence::AttemptStarted { .. }
            | DeliveryEvidence::MayHaveBroadcast { .. }
            | DeliveryEvidence::NodeResponseObserved { .. },
            DeliveryEvidence::EndpointReportedSuccess { .. }
            | DeliveryEvidence::EndpointReportedFailedOnChain { .. },
        ) => true,
        (
            DeliveryEvidence::AttemptStarted { .. }
            | DeliveryEvidence::MayHaveBroadcast { .. }
            | DeliveryEvidence::NodeResponseObserved { .. }
            | DeliveryEvidence::EndpointReportedSuccess { .. }
            | DeliveryEvidence::EndpointReportedFailedOnChain { .. },
            DeliveryEvidence::VerifiedTerminal { .. },
        ) => true,
        _ => false,
    }
}

impl Serialize for SendRecord {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(7))?;
        map.serialize_entry("ticket", &self.ticket)?;
        map.serialize_entry("prepare_provenance", &self.prepare_provenance)?;
        map.serialize_entry("ext_msg_hash", &self.ext_msg_hash)?;
        map.serialize_entry("expire_at", &self.expire_at)?;
        map.serialize_entry("message_boc_b64", &Option::<String>::None)?;
        map.serialize_entry("reservations", &self.reservations)?;
        map.serialize_entry("delivery_events", &self.delivery_events)?;
        map.end()
    }
}

struct RequiredNull;

impl<'de> Deserialize<'de> for RequiredNull {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = Box::<RawValue>::deserialize(deserializer)?;
        if raw.get() == "null" {
            Ok(RequiredNull)
        } else {
            Err(de::Error::custom(
                "message_boc_b64 must be the required literal null",
            ))
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SendRecordWire {
    ticket: SendTicket,
    prepare_provenance: PrepareProvenance,
    ext_msg_hash: Digest32,
    expire_at: u32,
    message_boc_b64: RequiredNull,
    reservations: Vec<Reservation>,
    delivery_events: Vec<DeliveryEvent>,
}

impl<'de> Deserialize<'de> for SendRecord {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = SendRecordWire::deserialize(deserializer)?;
        let _ = wire.message_boc_b64;
        let record = Self {
            ticket: wire.ticket,
            prepare_provenance: wire.prepare_provenance,
            ext_msg_hash: wire.ext_msg_hash,
            expire_at: wire.expire_at,
            reservations: wire.reservations,
            delivery_events: wire.delivery_events,
        };
        record.validate_static().map_err(de::Error::custom)?;
        Ok(record)
    }
}

enum ReplayItem<'a> {
    Delivery(&'a SendRecord, &'a DeliveryEvent),
    Risk(&'a RiskEvent),
}

impl ReplayItem<'_> {
    fn seq(&self) -> u64 {
        match self {
            Self::Delivery(_, event) => event.journal_seq,
            Self::Risk(event) => event.journal_seq,
        }
    }
}

pub(crate) fn validate_replay(
    records: &[SendRecord],
    risk_events: &[RiskEvent],
) -> Result<(), JournalError> {
    let mut record_ids = BTreeSet::new();
    let identity = records.first().map(|record| record.ticket.scope());
    for record in records {
        record.validate_static()?;
        if identity.is_some_and(|scope| record.ticket.scope() != scope) {
            return Err(JournalError::InvalidDelivery(
                "one encrypted Journal cannot mix wallet, sender, or network identities",
            ));
        }
        if !record_ids.insert(record.ticket.record_id.clone()) {
            return Err(JournalError::DuplicateRecord);
        }
    }

    let mut stream = Vec::new();
    for record in records {
        stream.extend(
            record
                .delivery_events
                .iter()
                .map(|event| ReplayItem::Delivery(record, event)),
        );
    }
    stream.extend(risk_events.iter().map(ReplayItem::Risk));
    stream.sort_by_key(ReplayItem::seq);
    for (index, item) in stream.iter().enumerate() {
        let expected = u64::try_from(index)
            .map_err(|_| JournalError::SequenceOverflow)?
            .checked_add(1)
            .ok_or(JournalError::SequenceOverflow)?;
        if item.seq() == 0 {
            return Err(JournalError::SequenceZero);
        }
        if item.seq() != expected {
            return Err(JournalError::SequenceGap);
        }
    }

    let mut active: BTreeMap<RecordId, (&SendRecord, EvidenceTag)> = BTreeMap::new();
    let mut blocking: BTreeMap<RecordId, (&SendRecord, EvidenceTag)> = BTreeMap::new();
    let mut grants: BTreeMap<crate::RiskNonce, &RiskGrant> = BTreeMap::new();
    let mut consumed = BTreeSet::new();
    let mut pending_consumption: Option<(&RiskGrant, &RiskGrantConsumption)> = None;

    for item in stream {
        if pending_consumption.is_some()
            && !matches!(
                item,
                ReplayItem::Delivery(
                    _,
                    DeliveryEvent {
                        evidence: DeliveryEvidence::Prepared,
                        ..
                    }
                )
            )
        {
            return Err(JournalError::ConsumptionNotAdjacent);
        }
        match item {
            ReplayItem::Risk(event) => match &event.action {
                RiskAction::Granted(grant) => {
                    if grant.warning_version() != crate::RISK_WARNING_VERSION {
                        return Err(JournalError::UnsupportedWarningVersion);
                    }
                    validate_grant_old_state(grant, &blocking)?;
                    if grants
                        .insert(grant.one_use_nonce().clone(), grant)
                        .is_some()
                    {
                        return Err(JournalError::DuplicateConsumption);
                    }
                }
                RiskAction::Consumed(consumption) => {
                    let grant = grants
                        .get(consumption.one_use_nonce())
                        .copied()
                        .ok_or(JournalError::OrphanConsumption)?;
                    if !grant.authorizes(consumption) {
                        return Err(JournalError::ConsumptionMismatch);
                    }
                    if !consumed.insert(consumption.one_use_nonce().clone()) {
                        return Err(JournalError::DuplicateConsumption);
                    }
                    pending_consumption = Some((grant, consumption));
                }
            },
            ReplayItem::Delivery(record, event) => {
                if matches!(event.evidence, DeliveryEvidence::Prepared) {
                    if active.contains_key(record.ticket.record_id()) {
                        return Err(JournalError::InvalidDelivery("second Prepared"));
                    }
                    match pending_consumption.take() {
                        Some((grant, consumption)) => {
                            if record.ticket.record_id() != consumption.new_record_id()
                                || record.ticket.digest()? != *consumption.new_ticket_digest()
                            {
                                return Err(JournalError::ConsumptionMismatch);
                            }
                            validate_grant_state(grant, record, &blocking)?;
                        }
                        None => {
                            if !record.prepare_provenance.authorized_overlap.is_empty() {
                                return Err(JournalError::OrphanConsumption);
                            }
                            if blocking.values().any(|(prior_record, evidence)| {
                                same_signing_scope(prior_record, record) && evidence.is_blocking()
                            }) {
                                return Err(JournalError::OrdinarySigningBlocked);
                            }
                        }
                    }
                    let active_reservations: Vec<_> = blocking
                        .values()
                        .filter(|(prior_record, evidence)| {
                            same_signing_scope(prior_record, record) && evidence.is_blocking()
                        })
                        .flat_map(|(prior_record, _)| prior_record.reservations.iter().cloned())
                        .collect();
                    let requested: Vec<_> = record
                        .reservations
                        .iter()
                        .map(|reservation| reservation.amount().clone())
                        .collect();
                    let affordability = crate::evaluate_affordability(
                        &record.prepare_provenance.balances,
                        &active_reservations,
                        &record.prepare_provenance.authorized_overlap,
                        &requested,
                    )
                    .map_err(|_| {
                        JournalError::InvalidReservation(
                            "Prepared affordability inputs are inconsistent",
                        )
                    })?;
                    if !affordability.is_affordable() {
                        return Err(JournalError::InvalidReservation(
                            "Prepared is not affordable against its fresh balances and reservations",
                        ));
                    }
                    active.insert(
                        record.ticket.record_id.clone(),
                        (record, EvidenceTag::Prepared),
                    );
                    blocking.insert(
                        record.ticket.record_id.clone(),
                        (record, EvidenceTag::Prepared),
                    );
                } else {
                    let state = active
                        .get_mut(record.ticket.record_id())
                        .ok_or(JournalError::InvalidDelivery("event precedes Prepared"))?;
                    let tag = event.evidence.tag();
                    state.1 = tag;
                    if tag.is_blocking() {
                        blocking.insert(record.ticket.record_id.clone(), (record, tag));
                    } else {
                        blocking.remove(record.ticket.record_id());
                    }
                }
            }
        }
    }
    if pending_consumption.is_some() {
        return Err(JournalError::ConsumptionNotAdjacent);
    }
    Ok(())
}

fn validate_grant_old_state(
    grant: &RiskGrant,
    active: &BTreeMap<RecordId, (&SendRecord, EvidenceTag)>,
) -> Result<(), JournalError> {
    let mut blockers = Vec::new();
    let mut reservations = Vec::new();
    for (record_id, (record, evidence)) in active {
        if evidence.is_blocking() {
            blockers.push(BlockerRow::new(
                record_id.clone(),
                *evidence,
                record.ext_msg_hash.clone(),
            )?);
            reservations.extend(record.reservations.iter().cloned());
        }
    }
    if blockers.is_empty()
        || blocker_set_digest(&blockers)? != *grant.old_blocker_set_digest()
        || reservation_set_digest(&reservations)? != *grant.old_reservation_set_digest()
    {
        return Err(JournalError::GrantDigestMismatch);
    }
    Ok(())
}

fn validate_grant_state(
    grant: &RiskGrant,
    new_record: &SendRecord,
    active: &BTreeMap<RecordId, (&SendRecord, EvidenceTag)>,
) -> Result<(), JournalError> {
    let mut blockers = Vec::new();
    let mut reservations = Vec::new();
    for (record_id, (record, evidence)) in active {
        if same_signing_scope(record, new_record) && evidence.is_blocking() {
            blockers.push(BlockerRow::new(
                record_id.clone(),
                *evidence,
                record.ext_msg_hash.clone(),
            )?);
            reservations.extend(record.reservations.iter().cloned());
        }
    }
    if blockers.is_empty() {
        return Err(JournalError::GrantDigestMismatch);
    }
    let overlap = &new_record.prepare_provenance.authorized_overlap;
    if overlap.iter().any(|row| !reservations.contains(row)) {
        return Err(JournalError::InvalidReservation(
            "authorized overlap is not a subset of active reservations",
        ));
    }
    let ticket = new_record.ticket.digest()?;
    if blocker_set_digest(&blockers)? != *grant.old_blocker_set_digest()
        || reservation_set_digest(&reservations)? != *grant.old_reservation_set_digest()
        || overlap_set_digest(overlap)? != *grant.overlap_reservation_set_digest()
        || ticket != *grant.new_ticket_digest()
        || new_record.ticket.record_id() != grant.new_record_id()
    {
        return Err(JournalError::GrantDigestMismatch);
    }
    Ok(())
}

fn same_signing_scope(left: &SendRecord, right: &SendRecord) -> bool {
    left.ticket.scope() == right.ticket.scope()
}

pub(crate) fn prepared_record(
    prepared: PreparedRecord,
    journal_seq: u64,
) -> Result<SendRecord, JournalError> {
    Ok(SendRecord {
        ticket: prepared.ticket,
        prepare_provenance: prepared.prepare_provenance,
        ext_msg_hash: prepared.ext_msg_hash,
        expire_at: prepared.expire_at,
        reservations: prepared.reservations,
        delivery_events: vec![DeliveryEvent::new(journal_seq, DeliveryEvidence::Prepared)?],
    })
}

pub(crate) fn append_delivery_event(
    record: &mut SendRecord,
    journal_seq: u64,
    evidence: DeliveryEvidence,
) -> Result<(), JournalError> {
    let event = DeliveryEvent::new(journal_seq, evidence)?;
    record.delivery_events.push(event);
    if let Err(error) = record.validate_static() {
        record.delivery_events.pop();
        return Err(error);
    }
    Ok(())
}

pub(crate) fn risk_grant_event(
    journal_seq: u64,
    grant: RiskGrant,
) -> Result<RiskEvent, JournalError> {
    RiskEvent::new(journal_seq, RiskAction::Granted(grant))
}

pub(crate) fn risk_consumption_event(
    journal_seq: u64,
    consumption: RiskGrantConsumption,
) -> Result<RiskEvent, JournalError> {
    RiskEvent::new(journal_seq, RiskAction::Consumed(consumption))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_response_observed_transport_error_blocks() {
        let evidence = DeliveryEvidence::NodeResponseObserved {
            attempt_no: 1,
            route_id: "route".to_owned(),
            request_id: "req".to_owned(),
            response: NodeResponseKind::TransportError,
        };
        assert_eq!(evidence.tag(), EvidenceTag::NodeResponseObserved);
        assert!(
            evidence.tag().is_blocking(),
            "an unresolved transport error must keep the record blocking"
        );
    }

    #[test]
    fn max_native_spendable_subtracts_fee_plus_headroom() {
        let balance = 5_000_000u128;
        let fee = 1_000_000u128;
        assert_eq!(
            max_native_spendable(balance, fee),
            balance - fee - LOCAL_SEND_FEE_HEADROOM_NANOS
        );
    }

    #[test]
    fn max_native_spendable_saturates_to_zero_when_fee_exceeds_balance() {
        assert_eq!(max_native_spendable(100, 1_000_000), 0);
        assert_eq!(max_native_spendable(0, 0), 0);
        assert_eq!(max_native_spendable(LOCAL_SEND_FEE_HEADROOM_NANOS, 0), 0);
    }
}
