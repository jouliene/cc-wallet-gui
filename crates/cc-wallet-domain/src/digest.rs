use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::amount::AssetAmount;
use crate::asset::AssetId;
use crate::ids::{Digest32, RecordId};

const AMOUNT_DOMAIN: &[u8] = b"cc-wallet/asset-amount/v1\0";
const DIGEST_DOMAIN: &[u8] = b"cc-wallet/journal-v1/";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DigestError {
    FieldTooLong,
    TooManyFields,
    TooManyRows,
    DuplicateRow,
    NonBlockingEvidence,
    NativeFeeRequiresNativeAmount,
}

impl fmt::Display for DigestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::FieldTooLong => "a digest field length exceeds the u32 length prefix",
            Self::TooManyFields => "a digest has more fields than the u16 tag space allows",
            Self::TooManyRows => "a set has more rows than the u32 count prefix allows",
            Self::DuplicateRow => "a set has two rows with the same canonical key",
            Self::NonBlockingEvidence => "a blocker row requires a blocking evidence state",
            Self::NativeFeeRequiresNativeAmount => {
                "a native-fee reservation must hold a native amount"
            }
        })
    }
}

impl std::error::Error for DigestError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DigestKind {
    Ticket,
    BlockerSet,
    ReservationSet,
    OverlapSet,
}

impl DigestKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ticket => "ticket",
            Self::BlockerSet => "blocker-set",
            Self::ReservationSet => "reservation-set",
            Self::OverlapSet => "overlap-set",
        }
    }
}

fn frame(tag: u16, bytes: &[u8]) -> Result<Vec<u8>, DigestError> {
    let len = checked_field_len(bytes.len())?;
    let mut out = Vec::with_capacity(2 + 4 + bytes.len());
    out.extend_from_slice(&tag.to_be_bytes());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(out)
}

fn checked_field_len(len: usize) -> Result<u32, DigestError> {
    u32::try_from(len).map_err(|_| DigestError::FieldTooLong)
}

fn asset_amount_bytes(amount: &AssetAmount) -> Vec<u8> {
    let mut out = Vec::from(AMOUNT_DOMAIN);
    match amount.asset_id() {
        AssetId::Native => {
            let decimal = amount
                .native_units()
                .expect("a native AssetId implies native units")
                .to_string();
            out.push(0x00);
            push_len_prefixed_decimal(&mut out, &decimal);
        }
        AssetId::CurrencyCollection(id) => {
            let decimal = amount
                .cc_units()
                .expect("a currency-collection AssetId implies cc units")
                .to_canonical_decimal();
            out.push(0x01);
            out.extend_from_slice(&id.to_be_bytes());
            push_len_prefixed_decimal(&mut out, &decimal);
        }
    }
    out
}

fn push_len_prefixed_decimal(out: &mut Vec<u8>, decimal: &str) {
    debug_assert!(
        decimal.len() <= u8::MAX as usize,
        "a bounded amount decimal fits the one-byte length prefix"
    );
    out.push(decimal.len() as u8);
    out.extend_from_slice(decimal.as_bytes());
}

fn digest(kind: DigestKind, fields: &[&[u8]]) -> Result<Digest32, DigestError> {
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_DOMAIN);
    hasher.update(kind.as_str().as_bytes());
    hasher.update([0x00u8]);
    for (index, field) in fields.iter().enumerate() {
        let tag = u16::try_from(index + 1).map_err(|_| DigestError::TooManyFields)?;
        hasher.update(frame(tag, field)?);
    }
    let out: [u8; 32] = hasher.finalize().into();
    Ok(Digest32::from_bytes(out))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceTag {
    Prepared,
    AttemptStarted,
    MayHaveBroadcast,
    NodeResponseObserved,
    EndpointReportedSuccess,
    EndpointReportedFailedOnChain,
    VerifiedTerminalSuccess,
    VerifiedTerminalFailedOnChain,
    NotBroadcast,
}

impl EvidenceTag {
    fn code(self) -> u8 {
        match self {
            Self::Prepared => 0x00,
            Self::AttemptStarted => 0x01,
            Self::MayHaveBroadcast => 0x02,
            Self::NodeResponseObserved => 0x03,
            Self::EndpointReportedSuccess => 0x04,
            Self::EndpointReportedFailedOnChain => 0x05,
            Self::VerifiedTerminalSuccess => 0x06,
            Self::VerifiedTerminalFailedOnChain => 0x07,
            Self::NotBroadcast => 0x08,
        }
    }

    pub fn is_blocking(self) -> bool {
        match self {
            Self::Prepared
            | Self::AttemptStarted
            | Self::MayHaveBroadcast
            | Self::NodeResponseObserved
            | Self::EndpointReportedSuccess
            | Self::EndpointReportedFailedOnChain => true,
            Self::VerifiedTerminalSuccess
            | Self::VerifiedTerminalFailedOnChain
            | Self::NotBroadcast => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationKind {
    Transfer,
    NativeFee,
}

impl ReservationKind {
    fn code(self) -> u8 {
        match self {
            Self::Transfer => 0x00,
            Self::NativeFee => 0x01,
        }
    }
}

fn blocker_row_bytes(
    record_id: &RecordId,
    evidence: EvidenceTag,
    external_hash: &Digest32,
) -> Result<Vec<u8>, DigestError> {
    if !evidence.is_blocking() {
        return Err(DigestError::NonBlockingEvidence);
    }
    let mut body = frame(1, record_id.as_bytes())?;
    body.extend(frame(2, &[evidence.code()])?);
    body.extend(frame(3, external_hash.as_bytes())?);
    prefix_row_length(body)
}

fn reservation_row_bytes(
    record_id: &RecordId,
    amount: &AssetAmount,
    kind: ReservationKind,
) -> Result<Vec<u8>, DigestError> {
    if kind == ReservationKind::NativeFee && amount.native_units().is_none() {
        return Err(DigestError::NativeFeeRequiresNativeAmount);
    }
    let mut body = frame(1, record_id.as_bytes())?;
    body.extend(frame(2, &asset_amount_bytes(amount))?);
    body.extend(frame(3, &[kind.code()])?);
    prefix_row_length(body)
}

fn prefix_row_length(body: Vec<u8>) -> Result<Vec<u8>, DigestError> {
    let len = checked_field_len(body.len())?;
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

#[derive(Clone)]
pub struct BlockerRow {
    record_id: RecordId,
    evidence: EvidenceTag,
    external_hash: Digest32,
}

impl BlockerRow {
    pub fn new(
        record_id: RecordId,
        evidence: EvidenceTag,
        external_hash: Digest32,
    ) -> Result<Self, DigestError> {
        if !evidence.is_blocking() {
            return Err(DigestError::NonBlockingEvidence);
        }
        Ok(Self {
            record_id,
            evidence,
            external_hash,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Reservation {
    record_id: RecordId,
    amount: AssetAmount,
    kind: ReservationKind,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReservationWire {
    record_id: RecordId,
    amount: AssetAmount,
    kind: ReservationKind,
}

wire_deserialize!(Reservation via ReservationWire {
    record_id,
    amount,
    kind
});

impl Reservation {
    pub fn new(
        record_id: RecordId,
        amount: AssetAmount,
        kind: ReservationKind,
    ) -> Result<Self, DigestError> {
        if kind == ReservationKind::NativeFee && amount.native_units().is_none() {
            return Err(DigestError::NativeFeeRequiresNativeAmount);
        }
        Ok(Self {
            record_id,
            amount,
            kind,
        })
    }
}

accessors!(Reservation {
    record_id: ref RecordId,
    amount: ref AssetAmount,
    kind: copy ReservationKind
});

fn assemble_set_blob(rows: &[Vec<u8>]) -> Result<Vec<u8>, DigestError> {
    let count = checked_row_count(rows.len())?;
    let total = checked_set_blob_len(rows.iter().map(Vec::len))?;
    let mut blob = Vec::with_capacity(total);
    blob.extend_from_slice(&count.to_be_bytes());
    for row in rows {
        blob.extend_from_slice(row);
    }
    Ok(blob)
}

fn checked_row_count(len: usize) -> Result<u32, DigestError> {
    u32::try_from(len).map_err(|_| DigestError::TooManyRows)
}

fn checked_set_blob_len(lengths: impl IntoIterator<Item = usize>) -> Result<usize, DigestError> {
    let total = lengths.into_iter().try_fold(4usize, |total, length| {
        total.checked_add(length).ok_or(DigestError::FieldTooLong)
    })?;
    checked_field_len(total)?;
    Ok(total)
}

pub fn blocker_set_digest(rows: &[BlockerRow]) -> Result<Digest32, DigestError> {
    let mut items: Vec<([u8; 32], Vec<u8>)> = Vec::with_capacity(rows.len());
    for row in rows {
        let bytes = blocker_row_bytes(&row.record_id, row.evidence, &row.external_hash)?;
        items.push((*row.record_id.as_bytes(), bytes));
    }
    items.sort_by_key(|(key, _)| *key);
    if items.windows(2).any(|w| w[0].0 == w[1].0) {
        return Err(DigestError::DuplicateRow);
    }
    let ordered: Vec<Vec<u8>> = items.into_iter().map(|(_, bytes)| bytes).collect();
    let blob = assemble_set_blob(&ordered)?;
    digest(DigestKind::BlockerSet, &[&blob])
}

pub fn reservation_set_digest(rows: &[Reservation]) -> Result<Digest32, DigestError> {
    reservation_like_set_digest(DigestKind::ReservationSet, rows)
}

pub fn overlap_set_digest(rows: &[Reservation]) -> Result<Digest32, DigestError> {
    reservation_like_set_digest(DigestKind::OverlapSet, rows)
}

type ReservationSortKey = ([u8; 32], Vec<u8>, u8);

fn reservation_like_set_digest(
    kind: DigestKind,
    rows: &[Reservation],
) -> Result<Digest32, DigestError> {
    let mut items: Vec<(ReservationSortKey, Vec<u8>)> = Vec::with_capacity(rows.len());
    for row in rows {
        let key = (
            *row.record_id.as_bytes(),
            asset_amount_bytes(&row.amount),
            row.kind.code(),
        );
        let bytes = reservation_row_bytes(&row.record_id, &row.amount, row.kind)?;
        items.push((key, bytes));
    }
    items.sort_by(|a, b| a.0.cmp(&b.0));
    if items.windows(2).any(|w| w[0].0 == w[1].0) {
        return Err(DigestError::DuplicateRow);
    }
    let ordered: Vec<Vec<u8>> = items.into_iter().map(|(_, bytes)| bytes).collect();
    let blob = assemble_set_blob(&ordered)?;
    digest(kind, &[&blob])
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct CanonicalAddress {
    workchain: i8,
    account: [u8; 32],
}

impl CanonicalAddress {
    pub(crate) fn new(workchain: i8, account: [u8; 32]) -> Self {
        Self { workchain, account }
    }

    pub(crate) fn digest_bytes(&self) -> [u8; 33] {
        let mut out = [0u8; 33];
        out[0] = self.workchain as u8;
        out[1..].copy_from_slice(&self.account);
        out
    }
}

#[derive(Clone, Copy)]
pub(crate) struct TicketDigestInput<'a> {
    pub(crate) record_id: &'a RecordId,
    pub(crate) sender_wallet_id: &'a [u8],
    pub(crate) sender_address: CanonicalAddress,
    pub(crate) network_global_id: i32,
    pub(crate) endpoint_identity: &'a [u8],
    pub(crate) destination: CanonicalAddress,
    pub(crate) value: &'a AssetAmount,
    pub(crate) bounce: bool,
    pub(crate) auth_generation: u64,
    pub(crate) auth_nonce: u64,
}

pub(crate) fn ticket_digest(ticket: &TicketDigestInput) -> Result<Digest32, DigestError> {
    let sender_address = ticket.sender_address.digest_bytes();
    let destination = ticket.destination.digest_bytes();
    let network_global_id = ticket.network_global_id.to_be_bytes();
    let value = asset_amount_bytes(ticket.value);
    let bounce = [u8::from(ticket.bounce)];
    let auth_generation = ticket.auth_generation.to_be_bytes();
    let auth_nonce = ticket.auth_nonce.to_be_bytes();
    let fields: [&[u8]; 10] = [
        ticket.record_id.as_bytes(),
        ticket.sender_wallet_id,
        &sender_address,
        &network_global_id,
        ticket.endpoint_identity,
        &destination,
        &value,
        &bounce,
        &auth_generation,
        &auth_nonce,
    ];
    digest(DigestKind::Ticket, &fields)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amount::CcAmount;

    fn native(n: u128) -> AssetAmount {
        AssetAmount::native(n).unwrap()
    }

    fn cc(id: u32, n: u128) -> AssetAmount {
        AssetAmount::currency_collection(id, CcAmount::from_u128(n))
    }

    fn rid(byte: u8) -> RecordId {
        RecordId::from_bytes([byte; 32])
    }

    #[test]
    fn frame_is_tag_then_u32_length_then_bytes() {
        assert_eq!(frame(1, b"").unwrap(), b"\x00\x01\x00\x00\x00\x00");
        assert_eq!(frame(1, b"ab").unwrap(), b"\x00\x01\x00\x00\x00\x02ab");
        assert_eq!(frame(0x0102, b"x").unwrap(), b"\x01\x02\x00\x00\x00\x01x");
    }

    #[test]
    fn frame_field_length_is_refused_above_u32_max() {
        assert_eq!(checked_field_len(0), Ok(0));
        assert_eq!(checked_field_len(u32::MAX as usize), Ok(u32::MAX));
        #[cfg(target_pointer_width = "64")]
        assert_eq!(
            checked_field_len(u32::MAX as usize + 1),
            Err(DigestError::FieldTooLong)
        );
    }

    #[test]
    fn set_row_count_is_refused_above_u32_max() {
        assert_eq!(checked_row_count(0), Ok(0));
        assert_eq!(checked_row_count(u32::MAX as usize), Ok(u32::MAX));
        #[cfg(target_pointer_width = "64")]
        assert_eq!(
            checked_row_count(u32::MAX as usize + 1),
            Err(DigestError::TooManyRows)
        );
    }

    #[test]
    fn set_blob_length_is_checked_before_allocation() {
        assert_eq!(checked_set_blob_len([]), Ok(4));
        assert_eq!(
            checked_set_blob_len([u32::MAX as usize - 4]),
            Ok(u32::MAX as usize)
        );
        #[cfg(target_pointer_width = "64")]
        assert_eq!(
            checked_set_blob_len([u32::MAX as usize - 3]),
            Err(DigestError::FieldTooLong)
        );
        assert_eq!(
            checked_set_blob_len([usize::MAX]),
            Err(DigestError::FieldTooLong)
        );
    }

    #[test]
    fn asset_amount_bytes_match_the_golden_encoding() {
        assert_eq!(
            asset_amount_bytes(&native(1)),
            b"cc-wallet/asset-amount/v1\0\x00\x011".as_slice()
        );
        assert_eq!(
            asset_amount_bytes(&cc(1, 1)),
            b"cc-wallet/asset-amount/v1\0\x01\x00\x00\x00\x01\x011".as_slice()
        );
        assert_eq!(
            asset_amount_bytes(&cc(2, 1)),
            b"cc-wallet/asset-amount/v1\0\x01\x00\x00\x00\x02\x011".as_slice()
        );
        assert_ne!(
            asset_amount_bytes(&native(1)),
            asset_amount_bytes(&cc(1, 1))
        );
        assert_ne!(asset_amount_bytes(&cc(1, 1)), asset_amount_bytes(&cc(2, 1)));
        let big = CcAmount::try_from_canonical_decimal("340282366920938463463374607431768211456")
            .unwrap();
        let enc = asset_amount_bytes(&AssetAmount::currency_collection(3, big));
        assert!(
            enc.ends_with(b"340282366920938463463374607431768211456"),
            "full decimal is preserved"
        );
        assert_eq!(enc[enc.len() - 40], 39);
    }

    #[test]
    fn digest_matches_an_independent_sha256_oracle() {
        let d = digest(DigestKind::ReservationSet, &[b"x"]).unwrap();
        assert_eq!(
            d.to_hex(),
            "9a4d06c30d3e24fd044c2397071c4bde5568c91fb750718e5ab54c098a93c07c"
        );
    }

    #[test]
    fn digest_separates_kind_field_count_and_order() {
        let a = digest(DigestKind::BlockerSet, &[b"x"]).unwrap();
        assert_ne!(a, digest(DigestKind::ReservationSet, &[b"x"]).unwrap());
        assert_ne!(a, digest(DigestKind::BlockerSet, &[b"x", b""]).unwrap());
        assert_ne!(
            digest(DigestKind::BlockerSet, &[b"a", b"bc"]).unwrap(),
            digest(DigestKind::BlockerSet, &[b"ab", b"c"]).unwrap()
        );
        assert_eq!(a, digest(DigestKind::BlockerSet, &[b"x"]).unwrap());
    }

    #[test]
    fn digest_kind_wire_spellings_are_fixed() {
        assert_eq!(DigestKind::BlockerSet.as_str(), "blocker-set");
        assert_eq!(DigestKind::ReservationSet.as_str(), "reservation-set");
        assert_eq!(DigestKind::OverlapSet.as_str(), "overlap-set");
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn evidence_and_reservation_codes_are_fixed() {
        for (i, tag) in [
            EvidenceTag::Prepared,
            EvidenceTag::AttemptStarted,
            EvidenceTag::MayHaveBroadcast,
            EvidenceTag::NodeResponseObserved,
            EvidenceTag::EndpointReportedSuccess,
            EvidenceTag::EndpointReportedFailedOnChain,
            EvidenceTag::VerifiedTerminalSuccess,
            EvidenceTag::VerifiedTerminalFailedOnChain,
            EvidenceTag::NotBroadcast,
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(tag.code(), i as u8);
        }
        assert_eq!(ReservationKind::Transfer.code(), 0x00);
        assert_eq!(ReservationKind::NativeFee.code(), 0x01);
    }

    #[test]
    fn row_bytes_match_the_golden_framing() {
        let rid0 = rid(0);
        let hff = Digest32::from_bytes([0xff; 32]);
        let blk = blocker_row_bytes(&rid0, EvidenceTag::MayHaveBroadcast, &hff).unwrap();
        assert_eq!(&blk[..4], &83u32.to_be_bytes());
        assert_eq!(blk.len(), 87);
        assert_eq!(
            hex(&blk),
            "00000053000100000020000000000000000000000000000000000000000000000000000000000000000000020000000102000300000020ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
        let rn = reservation_row_bytes(
            &rid0,
            &AssetAmount::native(1).unwrap(),
            ReservationKind::Transfer,
        )
        .unwrap();
        assert_eq!(
            hex(&rn),
            "00000050000100000020000000000000000000000000000000000000000000000000000000000000000000020000001d63632d77616c6c65742f61737365742d616d6f756e742f76310000013100030000000100"
        );
        let rc = reservation_row_bytes(&rid0, &cc(1, 1), ReservationKind::Transfer).unwrap();
        assert_eq!(
            hex(&rc),
            "00000054000100000020000000000000000000000000000000000000000000000000000000000000000000020000002163632d77616c6c65742f61737365742d616d6f756e742f7631000100000001013100030000000100"
        );
        let rn_fee = reservation_row_bytes(
            &rid0,
            &AssetAmount::native(1).unwrap(),
            ReservationKind::NativeFee,
        )
        .unwrap();
        assert_eq!(
            hex(&rn_fee),
            "00000050000100000020000000000000000000000000000000000000000000000000000000000000000000020000001d63632d77616c6c65742f61737365742d616d6f756e742f76310000013100030000000101"
        );
        assert_ne!(rn, rn_fee);
        assert_eq!(&rn[..rn.len() - 1], &rn_fee[..rn_fee.len() - 1]);
    }

    #[test]
    fn row_encoders_refuse_states_the_typed_model_forbids() {
        let r = rid(0);
        let hff = Digest32::from_bytes([0xff; 32]);

        for (tag, blocking) in [
            (EvidenceTag::Prepared, true),
            (EvidenceTag::AttemptStarted, true),
            (EvidenceTag::MayHaveBroadcast, true),
            (EvidenceTag::NodeResponseObserved, true),
            (EvidenceTag::EndpointReportedSuccess, true),
            (EvidenceTag::EndpointReportedFailedOnChain, true),
            (EvidenceTag::VerifiedTerminalSuccess, false),
            (EvidenceTag::VerifiedTerminalFailedOnChain, false),
            (EvidenceTag::NotBroadcast, false),
        ] {
            assert_eq!(tag.is_blocking(), blocking);
            assert_eq!(
                blocker_row_bytes(&r, tag, &hff).is_ok(),
                blocking,
                "blocker admissibility for {tag:?}"
            );
            assert_eq!(
                BlockerRow::new(rid(0), tag, Digest32::from_bytes([0xff; 32])).is_ok(),
                blocking,
                "projection admissibility for {tag:?}"
            );
        }
        assert_eq!(
            blocker_row_bytes(&r, EvidenceTag::NotBroadcast, &hff),
            Err(DigestError::NonBlockingEvidence)
        );

        assert_eq!(
            reservation_row_bytes(&r, &cc(1, 1), ReservationKind::NativeFee),
            Err(DigestError::NativeFeeRequiresNativeAmount)
        );
        assert!(reservation_row_bytes(&r, &cc(1, 1), ReservationKind::Transfer).is_ok());
        let native1 = AssetAmount::native(1).unwrap();
        assert!(reservation_row_bytes(&r, &native1, ReservationKind::NativeFee).is_ok());
        assert!(reservation_row_bytes(&r, &native1, ReservationKind::Transfer).is_ok());

        assert_eq!(
            Reservation::new(rid(0), cc(1, 1), ReservationKind::NativeFee).err(),
            Some(DigestError::NativeFeeRequiresNativeAmount)
        );
        assert!(Reservation::new(rid(0), cc(1, 1), ReservationKind::Transfer).is_ok());
        assert!(Reservation::new(rid(0), native(1), ReservationKind::NativeFee).is_ok());
    }

    #[test]
    fn digest_refuses_more_fields_than_the_u16_tag_space() {
        let max_fields: Vec<&[u8]> = vec![b"".as_slice(); 65_535];
        assert!(digest(DigestKind::BlockerSet, &max_fields).is_ok());

        let over_fields: Vec<&[u8]> = vec![b"".as_slice(); 65_536];
        assert_eq!(
            digest(DigestKind::BlockerSet, &over_fields),
            Err(DigestError::TooManyFields)
        );
    }

    fn blk_row(id: u8, tag: EvidenceTag) -> BlockerRow {
        BlockerRow::new(rid(id), tag, Digest32::from_bytes([0xff; 32])).unwrap()
    }

    fn res_row(id: u8, amount: AssetAmount, kind: ReservationKind) -> Reservation {
        Reservation::new(rid(id), amount, kind).unwrap()
    }

    #[test]
    fn set_digests_match_the_independent_oracle() {
        assert_eq!(
            blocker_set_digest(&[]).unwrap().to_hex(),
            "1770ca12172f1182e8a50124caf76f0dc757ae500e90420d6a6f360a115fedd7"
        );
        assert_eq!(
            blocker_set_digest(&[blk_row(0, EvidenceTag::MayHaveBroadcast)])
                .unwrap()
                .to_hex(),
            "244875fb21138fd211498c46f5712bdf8d601afc1c7cac645334917ceb85931f"
        );
        assert_eq!(
            reservation_set_digest(&[res_row(0, native(1), ReservationKind::Transfer)])
                .unwrap()
                .to_hex(),
            "2a1d39924aff6a5f6130b468ce39706ed8cff04507fbd937ec367f8773cd155b"
        );
        assert_eq!(
            overlap_set_digest(&[res_row(0, native(1), ReservationKind::NativeFee)])
                .unwrap()
                .to_hex(),
            "3bdb0451fc9e752483cba1f308e4ee6c62b316b913cc11ae02ae190424ab5faf"
        );
        assert_eq!(
            reservation_set_digest(&[
                res_row(0, native(1), ReservationKind::Transfer),
                res_row(1, native(1), ReservationKind::Transfer),
            ])
            .unwrap()
            .to_hex(),
            "de58447b29e7475dc38fdd2c41d570e609593497099aa22fd14e23c5c2d85826"
        );
    }

    #[test]
    fn set_digest_is_canonical_regardless_of_input_order() {
        let sorted = [
            res_row(0, native(1), ReservationKind::Transfer),
            res_row(1, native(1), ReservationKind::Transfer),
        ];
        let reversed = [
            res_row(1, native(1), ReservationKind::Transfer),
            res_row(0, native(1), ReservationKind::Transfer),
        ];
        assert_eq!(
            reservation_set_digest(&sorted).unwrap(),
            reservation_set_digest(&reversed).unwrap()
        );

        assert_eq!(
            blocker_set_digest(&[
                blk_row(2, EvidenceTag::Prepared),
                blk_row(1, EvidenceTag::Prepared),
            ])
            .unwrap(),
            blocker_set_digest(&[
                blk_row(1, EvidenceTag::Prepared),
                blk_row(2, EvidenceTag::Prepared),
            ])
            .unwrap()
        );
    }

    #[test]
    fn set_builders_reject_duplicate_rows() {
        assert_eq!(
            blocker_set_digest(&[
                blk_row(0, EvidenceTag::Prepared),
                blk_row(0, EvidenceTag::AttemptStarted),
            ]),
            Err(DigestError::DuplicateRow)
        );
        assert_eq!(
            reservation_set_digest(&[
                res_row(0, native(1), ReservationKind::Transfer),
                res_row(0, native(1), ReservationKind::Transfer),
            ]),
            Err(DigestError::DuplicateRow)
        );
        assert!(
            reservation_set_digest(&[
                res_row(0, native(1), ReservationKind::Transfer),
                res_row(0, native(2), ReservationKind::Transfer),
            ])
            .is_ok()
        );
    }

    #[test]
    fn set_digests_separate_kind_membership_and_asset() {
        let one = [res_row(0, native(1), ReservationKind::Transfer)];
        assert_ne!(
            reservation_set_digest(&one).unwrap(),
            overlap_set_digest(&one).unwrap()
        );
        assert_ne!(
            reservation_set_digest(&[]).unwrap(),
            reservation_set_digest(&one).unwrap()
        );
        assert_ne!(
            reservation_set_digest(&[res_row(0, cc(1, 1), ReservationKind::Transfer)]).unwrap(),
            reservation_set_digest(&[res_row(0, cc(2, 1), ReservationKind::Transfer)]).unwrap()
        );
        assert_ne!(
            blocker_set_digest(&[]).unwrap(),
            reservation_set_digest(&[]).unwrap()
        );
    }

    fn addr(workchain: i8, byte: u8) -> CanonicalAddress {
        CanonicalAddress::new(workchain, [byte; 32])
    }

    #[test]
    fn canonical_address_encodes_workchain_as_one_twos_complement_byte() {
        assert_eq!(addr(0, 0x11).digest_bytes()[0], 0x00);
        assert_eq!(addr(-1, 0x11).digest_bytes()[0], 0xff);
        assert_eq!(addr(127, 0x11).digest_bytes()[0], 0x7f);
        assert_eq!(addr(-128, 0x11).digest_bytes()[0], 0x80);
        assert_eq!(&addr(5, 0xab).digest_bytes()[1..], &[0xab; 32]);
    }

    #[test]
    fn ticket_digest_matches_the_independent_oracle() {
        let rid0 = rid(0);
        let value = native(5);
        let t = TicketDigestInput {
            record_id: &rid0,
            sender_wallet_id: b"w1",
            sender_address: addr(0, 0x11),
            network_global_id: 2000,
            endpoint_identity: b"ep",
            destination: addr(-1, 0x22),
            value: &value,
            bounce: true,
            auth_generation: 7,
            auth_nonce: 9,
        };
        assert_eq!(
            ticket_digest(&t).unwrap().to_hex(),
            "bd4a425c30636d69c00e2e9941a23cb0dcf7d373c9baa19c111f0e9bb6711391"
        );
    }

    #[allow(clippy::too_many_arguments)]
    #[test]
    fn ticket_digest_separates_every_field() {
        let rid0 = rid(0);
        let rid1 = rid(1);
        let v5 = native(5);
        let v6 = native(6);
        let base_input = TicketDigestInput {
            record_id: &rid0,
            sender_wallet_id: b"w1",
            sender_address: addr(0, 0x11),
            network_global_id: 2000,
            endpoint_identity: b"ep",
            destination: addr(-1, 0x22),
            value: &v5,
            bounce: true,
            auth_generation: 7,
            auth_nonce: 9,
        };
        let hex = |input: &TicketDigestInput| ticket_digest(input).unwrap().to_hex();
        let base = hex(&base_input);

        type Mutate<'a> = &'a dyn Fn(&mut TicketDigestInput<'a>);
        let mutations: [(&str, Mutate); 12] = [
            ("record_id", &|t| t.record_id = &rid1),
            ("sender_wallet_id", &|t| t.sender_wallet_id = b"w2"),
            ("sender_address", &|t| t.sender_address = addr(0, 0x12)),
            ("sender_workchain", &|t| t.sender_address = addr(-1, 0x11)),
            ("network_global_id", &|t| t.network_global_id = 2001),
            ("endpoint_identity", &|t| t.endpoint_identity = b"eq"),
            ("destination", &|t| t.destination = addr(-1, 0x23)),
            ("destination_workchain", &|t| t.destination = addr(0, 0x22)),
            ("value", &|t| t.value = &v6),
            ("bounce", &|t| t.bounce = false),
            ("auth_generation", &|t| t.auth_generation = 8),
            ("auth_nonce", &|t| t.auth_nonce = 10),
        ];

        let mut all = vec![base.clone()];
        for (field, mutate) in mutations {
            let mut input = base_input;
            mutate(&mut input);
            let mutated = hex(&input);
            assert_ne!(base, mutated, "changing {field} must change the digest");
            all.push(mutated);
        }
        all.sort();
        all.dedup();
        assert_eq!(all.len(), 13, "base plus 12 mutations are all distinct");
    }
}
