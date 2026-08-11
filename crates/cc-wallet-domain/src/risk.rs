use serde::{Deserialize, Deserializer, Serialize};

use crate::ids::{Digest32, RecordId, RiskNonce};

pub const RISK_WARNING_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RiskGrant {
    old_blocker_set_digest: Digest32,
    old_reservation_set_digest: Digest32,
    new_ticket_digest: Digest32,
    new_record_id: RecordId,
    one_use_nonce: RiskNonce,
    warning_version: u16,
    overlap_reservation_set_digest: Digest32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RiskGrantWire {
    old_blocker_set_digest: Digest32,
    old_reservation_set_digest: Digest32,
    new_ticket_digest: Digest32,
    new_record_id: RecordId,
    one_use_nonce: RiskNonce,
    warning_version: u16,
    overlap_reservation_set_digest: Digest32,
}

impl<'de> Deserialize<'de> for RiskGrant {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = RiskGrantWire::deserialize(deserializer)?;
        Ok(Self::new(
            wire.old_blocker_set_digest,
            wire.old_reservation_set_digest,
            wire.new_ticket_digest,
            wire.new_record_id,
            wire.one_use_nonce,
            wire.warning_version,
            wire.overlap_reservation_set_digest,
        ))
    }
}

impl RiskGrant {
    pub fn new(
        old_blocker_set_digest: Digest32,
        old_reservation_set_digest: Digest32,
        new_ticket_digest: Digest32,
        new_record_id: RecordId,
        one_use_nonce: RiskNonce,
        warning_version: u16,
        overlap_reservation_set_digest: Digest32,
    ) -> Self {
        Self {
            old_blocker_set_digest,
            old_reservation_set_digest,
            new_ticket_digest,
            new_record_id,
            one_use_nonce,
            warning_version,
            overlap_reservation_set_digest,
        }
    }

    pub fn authorizes(&self, consumption: &RiskGrantConsumption) -> bool {
        self.one_use_nonce == consumption.one_use_nonce
            && self.new_record_id == consumption.new_record_id
            && self.new_ticket_digest == consumption.new_ticket_digest
    }
}

accessors!(RiskGrant {
    old_blocker_set_digest: ref Digest32,
    old_reservation_set_digest: ref Digest32,
    new_ticket_digest: ref Digest32,
    new_record_id: ref RecordId,
    one_use_nonce: ref RiskNonce,
    warning_version: copy u16,
    overlap_reservation_set_digest: ref Digest32
});

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RiskGrantConsumption {
    one_use_nonce: RiskNonce,
    new_record_id: RecordId,
    new_ticket_digest: Digest32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RiskGrantConsumptionWire {
    one_use_nonce: RiskNonce,
    new_record_id: RecordId,
    new_ticket_digest: Digest32,
}

impl<'de> Deserialize<'de> for RiskGrantConsumption {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = RiskGrantConsumptionWire::deserialize(deserializer)?;
        Ok(Self::new(
            wire.one_use_nonce,
            wire.new_record_id,
            wire.new_ticket_digest,
        ))
    }
}

impl RiskGrantConsumption {
    pub fn new(
        one_use_nonce: RiskNonce,
        new_record_id: RecordId,
        new_ticket_digest: Digest32,
    ) -> Self {
        Self {
            one_use_nonce,
            new_record_id,
            new_ticket_digest,
        }
    }
}

accessors!(RiskGrantConsumption {
    one_use_nonce: ref RiskNonce,
    new_record_id: ref RecordId,
    new_ticket_digest: ref Digest32
});

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "payload",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(crate) enum RiskAction {
    Granted(RiskGrant),
    Consumed(RiskGrantConsumption),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amount::{AssetAmount, CcAmount};
    use crate::digest::{
        BlockerRow, CanonicalAddress, EvidenceTag, Reservation, ReservationKind, TicketDigestInput,
        blocker_set_digest, overlap_set_digest, reservation_set_digest, ticket_digest,
    };

    fn d(byte: u8) -> Digest32 {
        Digest32::from_bytes([byte; 32])
    }

    fn rid(byte: u8) -> RecordId {
        RecordId::from_bytes([byte; 32])
    }

    fn nonce(byte: u8) -> RiskNonce {
        RiskNonce::from_bytes([byte; 32])
    }

    fn native(n: u128) -> AssetAmount {
        AssetAmount::native(n).unwrap()
    }

    fn cc(id: u32, n: u128) -> AssetAmount {
        AssetAmount::currency_collection(id, CcAmount::from_u128(n))
    }

    fn sample_ticket_digest() -> Digest32 {
        let record_id = rid(0x30);
        let value = native(1_000);
        let sender = CanonicalAddress::new(0, [0x22; 32]);
        let destination = CanonicalAddress::new(0, [0x33; 32]);
        let input = TicketDigestInput {
            record_id: &record_id,
            sender_wallet_id: b"wallet-1",
            sender_address: sender,
            network_global_id: 42,
            endpoint_identity: b"endpoint-1",
            destination,
            value: &value,
            bounce: true,
            auth_generation: 1,
            auth_nonce: 2,
        };
        ticket_digest(&input).unwrap()
    }

    #[test]
    fn risk_grant_exposes_exactly_its_seven_fields() {
        let grant = RiskGrant::new(d(1), d(2), d(3), rid(4), nonce(5), 7, d(6));
        assert_eq!(grant.old_blocker_set_digest(), &d(1));
        assert_eq!(grant.old_reservation_set_digest(), &d(2));
        assert_eq!(grant.new_ticket_digest(), &d(3));
        assert_eq!(grant.new_record_id(), &rid(4));
        assert_eq!(grant.one_use_nonce(), &nonce(5));
        assert_eq!(grant.warning_version(), 7);
        assert_eq!(grant.overlap_reservation_set_digest(), &d(6));
    }

    #[test]
    fn consumption_exposes_exactly_its_three_fields() {
        let consumption = RiskGrantConsumption::new(nonce(5), rid(4), d(3));
        assert_eq!(consumption.one_use_nonce(), &nonce(5));
        assert_eq!(consumption.new_record_id(), &rid(4));
        assert_eq!(consumption.new_ticket_digest(), &d(3));
    }

    #[test]
    fn grant_authorizes_only_its_exact_one_use_consumption() {
        let grant = RiskGrant::new(d(1), d(2), d(3), rid(4), nonce(5), 7, d(6));
        assert!(grant.authorizes(&RiskGrantConsumption::new(nonce(5), rid(4), d(3))));
        assert!(!grant.authorizes(&RiskGrantConsumption::new(nonce(0xaa), rid(4), d(3))));
        assert!(!grant.authorizes(&RiskGrantConsumption::new(nonce(5), rid(0xaa), d(3))));
        assert!(!grant.authorizes(&RiskGrantConsumption::new(nonce(5), rid(4), d(0xaa))));
    }

    #[test]
    fn risk_event_carries_a_grant_or_a_consumption() {
        let grant = RiskGrant::new(d(1), d(2), d(3), rid(4), nonce(5), 7, d(6));
        let consumption = RiskGrantConsumption::new(nonce(5), rid(4), d(3));
        match RiskAction::Granted(grant.clone()) {
            RiskAction::Granted(inner) => assert_eq!(inner, grant),
            RiskAction::Consumed(_) => panic!("expected a grant"),
        }
        match RiskAction::Consumed(consumption.clone()) {
            RiskAction::Consumed(inner) => assert_eq!(inner, consumption),
            RiskAction::Granted(_) => panic!("expected a consumption"),
        }
    }

    #[test]
    fn grant_digests_recompute_byte_identically_from_the_same_state() {
        let blockers = [BlockerRow::new(rid(0x10), EvidenceTag::Prepared, d(0x11)).unwrap()];
        let reservations = [
            Reservation::new(rid(0x20), native(1_000), ReservationKind::Transfer).unwrap(),
            Reservation::new(rid(0x20), native(7), ReservationKind::NativeFee).unwrap(),
            Reservation::new(rid(0x21), cc(1, 42), ReservationKind::Transfer).unwrap(),
        ];
        let overlap = [reservations[0].clone()];

        let grant = RiskGrant::new(
            blocker_set_digest(&blockers).unwrap(),
            reservation_set_digest(&reservations).unwrap(),
            sample_ticket_digest(),
            rid(0x30),
            nonce(0x31),
            1,
            overlap_set_digest(&overlap).unwrap(),
        );

        assert_eq!(
            grant.old_blocker_set_digest(),
            &blocker_set_digest(&blockers).unwrap()
        );
        assert_eq!(
            grant.old_reservation_set_digest(),
            &reservation_set_digest(&reservations).unwrap()
        );
        assert_eq!(
            grant.overlap_reservation_set_digest(),
            &overlap_set_digest(&overlap).unwrap()
        );
        assert_eq!(grant.new_ticket_digest(), &sample_ticket_digest());
    }

    #[test]
    fn mutating_a_non_overlapped_reservation_invalidates_the_stored_reservation_digest() {
        let reservations = vec![
            Reservation::new(rid(0x20), native(1_000), ReservationKind::Transfer).unwrap(),
            Reservation::new(rid(0x21), native(500), ReservationKind::Transfer).unwrap(),
        ];
        let overlap = [reservations[0].clone()];
        let grant = RiskGrant::new(
            d(0),
            reservation_set_digest(&reservations).unwrap(),
            d(0),
            rid(0x30),
            nonce(0x31),
            1,
            overlap_set_digest(&overlap).unwrap(),
        );
        let stored = grant.old_reservation_set_digest();

        let mutated = vec![
            reservations[0].clone(),
            Reservation::new(rid(0x21), native(501), ReservationKind::Transfer).unwrap(),
        ];
        assert_ne!(stored, &reservation_set_digest(&mutated).unwrap());

        let mut added = reservations.clone();
        added.push(Reservation::new(rid(0x22), native(9), ReservationKind::Transfer).unwrap());
        assert_ne!(stored, &reservation_set_digest(&added).unwrap());

        let removed = vec![reservations[0].clone()];
        assert_ne!(stored, &reservation_set_digest(&removed).unwrap());

        assert_eq!(stored, &reservation_set_digest(&reservations).unwrap());
    }
}
