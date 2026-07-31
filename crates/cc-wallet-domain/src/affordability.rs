use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use num_bigint::BigUint;

use crate::Reservation;
use crate::amount::{AssetAmount, CcAmount};
use crate::asset::AssetId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AffordabilityError {
    DuplicateAsset { asset: AssetId },
    DuplicateReservation,
    DuplicateOverlap,
    OverlapRowNotReserved,
}

impl std::fmt::Display for AffordabilityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateAsset { asset } => {
                write!(f, "more than one amount was supplied for asset {asset:?}")
            }
            Self::DuplicateReservation => f.write_str("a reservation row is duplicated"),
            Self::DuplicateOverlap => f.write_str("an overlap row is duplicated"),
            Self::OverlapRowNotReserved => {
                f.write_str("an overlap row is not one of the outstanding reservations")
            }
        }
    }
}

impl std::error::Error for AffordabilityError {}

#[derive(Debug, Clone)]
pub struct AssetAffordability {
    asset: AssetId,
    balance: AssetAmount,
    reserved: Option<AssetAmount>,
    available: Option<AssetAmount>,
    requested: AssetAmount,
    reservation_components: Vec<AssetAmount>,
    worst_case: Option<AssetAmount>,
    sufficient: bool,
    worst_case_warns: bool,
}

impl AssetAffordability {
    pub fn asset(&self) -> AssetId {
        self.asset
    }

    pub fn balance(&self) -> &AssetAmount {
        &self.balance
    }

    pub fn reserved(&self) -> Option<&AssetAmount> {
        self.reserved.as_ref()
    }

    pub fn available(&self) -> Option<&AssetAmount> {
        self.available.as_ref()
    }

    pub fn requested(&self) -> &AssetAmount {
        &self.requested
    }

    pub fn reservation_components(&self) -> &[AssetAmount] {
        &self.reservation_components
    }

    pub fn is_sufficient(&self) -> bool {
        self.sufficient
    }

    pub fn worst_case(&self) -> Option<&AssetAmount> {
        self.worst_case.as_ref()
    }

    pub fn worst_case_warns(&self) -> bool {
        self.worst_case_warns
    }
}

#[derive(Debug, Clone)]
pub struct AffordabilityReport {
    outcomes: Vec<AssetAffordability>,
}

impl AffordabilityReport {
    pub fn is_affordable(&self) -> bool {
        self.outcomes.iter().all(AssetAffordability::is_sufficient)
    }

    pub fn outcomes(&self) -> &[AssetAffordability] {
        &self.outcomes
    }

    pub fn outcome(&self, asset: AssetId) -> Option<&AssetAffordability> {
        self.outcomes.iter().find(|outcome| outcome.asset == asset)
    }
}

fn zero_amount(asset: &AssetId) -> AssetAmount {
    match asset {
        AssetId::Native => AssetAmount::native(0).expect("zero is within the native domain"),
        AssetId::CurrencyCollection(id) => AssetAmount::currency_collection(*id, CcAmount::zero()),
    }
}

fn amount_to_biguint(amount: &AssetAmount) -> BigUint {
    match amount.native_units() {
        Some(units) => BigUint::from(units),
        None => BigUint::from_bytes_be(
            &amount
                .cc_units()
                .expect("a non-native amount carries cc units")
                .to_be_bytes_31(),
        ),
    }
}

fn biguint_to_amount(value: &BigUint, asset: &AssetId) -> Option<AssetAmount> {
    let decimal = value.to_str_radix(10);
    match asset {
        AssetId::Native => decimal
            .parse::<u128>()
            .ok()
            .and_then(|units| AssetAmount::native(units).ok()),
        AssetId::CurrencyCollection(id) => CcAmount::try_from_canonical_decimal(&decimal)
            .ok()
            .map(|units| AssetAmount::currency_collection(*id, units)),
    }
}

fn index_by_asset(
    amounts: &[AssetAmount],
) -> Result<BTreeMap<AssetId, AssetAmount>, AffordabilityError> {
    let mut map = BTreeMap::new();
    for amount in amounts {
        if map.insert(amount.asset_id(), amount.clone()).is_some() {
            return Err(AffordabilityError::DuplicateAsset {
                asset: amount.asset_id(),
            });
        }
    }
    Ok(map)
}

fn has_duplicate_rows(rows: &[Reservation]) -> bool {
    rows.iter()
        .enumerate()
        .any(|(index, row)| rows[index + 1..].contains(row))
}

pub fn evaluate_affordability(
    balances: &[AssetAmount],
    reservations: &[Reservation],
    overlap: &[Reservation],
    requested: &[AssetAmount],
) -> Result<AffordabilityReport, AffordabilityError> {
    let balances = index_by_asset(balances)?;
    let requested = index_by_asset(requested)?;

    if has_duplicate_rows(reservations) {
        return Err(AffordabilityError::DuplicateReservation);
    }
    if has_duplicate_rows(overlap) {
        return Err(AffordabilityError::DuplicateOverlap);
    }
    for row in overlap {
        if !reservations.contains(row) {
            return Err(AffordabilityError::OverlapRowNotReserved);
        }
    }

    let mut relevant: BTreeSet<AssetId> = BTreeSet::new();
    for row in reservations {
        relevant.insert(row.amount().asset_id());
    }
    for asset in requested.keys() {
        relevant.insert(*asset);
    }

    let mut outcomes = Vec::with_capacity(relevant.len());
    for asset in relevant {
        let b = balances
            .get(&asset)
            .cloned()
            .unwrap_or_else(|| zero_amount(&asset));
        let n = requested
            .get(&asset)
            .cloned()
            .unwrap_or_else(|| zero_amount(&asset));

        let mut reserved_big = BigUint::from(0u8);
        let mut all_big = BigUint::from(0u8);
        let mut components = Vec::new();
        for row in reservations {
            if row.amount().asset_id() != asset {
                continue;
            }
            let value = amount_to_biguint(row.amount());
            all_big += &value;
            if !overlap.contains(row) {
                reserved_big += &value;
                components.push(row.amount().clone());
            }
        }

        let reserved = biguint_to_amount(&reserved_big, &asset);
        let available = match &reserved {
            Some(s)
                if s.cmp_same_asset(&b)
                    .expect("reserved shares the asset")
                    .is_le() =>
            {
                Some(
                    b.checked_sub_same_asset(s)
                        .expect("S <= B was just checked, so B - S cannot underflow"),
                )
            }
            _ => None,
        };

        let worst_case = biguint_to_amount(&(&all_big + amount_to_biguint(&n)), &asset);
        let worst_case_warns = match &worst_case {
            None => true,
            Some(w) => {
                w.cmp_same_asset(&b).expect("worst case shares the asset") == Ordering::Greater
            }
        };

        let sufficient = match &available {
            Some(a) => {
                n.cmp_same_asset(&b)
                    .expect("requested shares the asset")
                    .is_le()
                    && n.cmp_same_asset(a)
                        .expect("requested and available share the asset")
                        .is_le()
            }
            None => false,
        };

        outcomes.push(AssetAffordability {
            asset,
            balance: b,
            reserved,
            available,
            requested: n,
            reservation_components: components,
            worst_case,
            sufficient,
            worst_case_warns,
        });
    }

    Ok(AffordabilityReport { outcomes })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amount::NATIVE_MAX_UNITS;
    use crate::digest::ReservationKind;
    use crate::ids::RecordId;

    const CC_MAX: &str =
        "452312848583266388373324160190187140051835877600158453279131187530910662655";

    fn native(n: u128) -> AssetAmount {
        AssetAmount::native(n).unwrap()
    }

    fn cc(id: u32, n: &str) -> AssetAmount {
        AssetAmount::currency_collection(id, CcAmount::try_from_canonical_decimal(n).unwrap())
    }

    fn rid(byte: u8) -> RecordId {
        RecordId::from_bytes([byte; 32])
    }

    fn res(id: u8, amount: AssetAmount, kind: ReservationKind) -> Reservation {
        Reservation::new(rid(id), amount, kind).unwrap()
    }

    fn dec(amount: Option<&AssetAmount>) -> Option<String> {
        amount.map(|a| match a.native_units() {
            Some(u) => u.to_string(),
            None => a.cc_units().unwrap().to_canonical_decimal(),
        })
    }

    #[test]
    fn a_send_within_balance_with_no_reservations_is_affordable() {
        let report = evaluate_affordability(&[native(10)], &[], &[], &[native(5)]).unwrap();
        assert!(report.is_affordable());
        let out = report.outcome(AssetId::Native).unwrap();
        assert_eq!(dec(out.reserved()), Some("0".to_owned()));
        assert_eq!(dec(out.available()), Some("10".to_owned()));
        assert_eq!(dec(out.worst_case()), Some("5".to_owned()));
        assert!(!out.worst_case_warns());
    }

    #[test]
    fn a_send_above_balance_is_not_affordable() {
        let report = evaluate_affordability(&[native(3)], &[], &[], &[native(5)]).unwrap();
        assert!(!report.is_affordable());
    }

    #[test]
    fn reservations_reduce_available_and_can_block_a_send_that_fits_the_raw_balance() {
        let reservations = [res(1, native(8), ReservationKind::Transfer)];
        let report =
            evaluate_affordability(&[native(10)], &reservations, &[], &[native(5)]).unwrap();
        let out = report.outcome(AssetId::Native).unwrap();
        assert_eq!(dec(out.available()), Some("2".to_owned()));
        assert!(!report.is_affordable(), "N<=B but N>available must block");
    }

    #[test]
    fn overlap_is_per_row_and_never_frees_a_different_row_of_the_same_record() {
        let cc_transfer = res(1, cc(1, "100"), ReservationKind::Transfer);
        let native_fee = res(1, native(10), ReservationKind::NativeFee);
        let reservations = [cc_transfer.clone(), native_fee.clone()];
        let balances = [native(10), cc(1, "100")];
        let request = [native(1)];

        let cc_only = evaluate_affordability(
            &balances,
            &reservations,
            std::slice::from_ref(&cc_transfer),
            &request,
        )
        .unwrap();
        let nat = cc_only.outcome(AssetId::Native).unwrap();
        assert_eq!(dec(nat.reserved()), Some("10".to_owned()));
        assert_eq!(dec(nat.available()), Some("0".to_owned()));
        assert!(
            !cc_only.is_affordable(),
            "CC-only grant must not free the native fee"
        );

        let both = evaluate_affordability(
            &balances,
            &reservations,
            &[cc_transfer, native_fee],
            &request,
        )
        .unwrap();
        assert!(
            both.is_affordable(),
            "authorizing both rows frees the native fee"
        );
    }

    #[test]
    fn an_old_asset_whose_reserved_aggregate_exceeds_the_domain_blocks_any_send() {
        let reservations = [
            res(1, cc(1, CC_MAX), ReservationKind::Transfer),
            res(2, cc(1, CC_MAX), ReservationKind::Transfer),
        ];
        let report =
            evaluate_affordability(&[native(10)], &reservations, &[], &[native(5)]).unwrap();
        assert!(
            !report.is_affordable(),
            "CC aggregate over 2^248-1 must block"
        );
        let cc_out = report.outcome(AssetId::CurrencyCollection(1)).unwrap();
        assert_eq!(cc_out.reserved(), None, "reserved exceeds the CC domain");
        assert!(!cc_out.is_sufficient());
        assert_eq!(cc_out.reservation_components().len(), 2);
        assert!(report.outcome(AssetId::Native).unwrap().is_sufficient());
    }

    #[test]
    fn an_empty_request_with_an_overflowing_reservation_is_not_affordable() {
        let reservations = [
            res(1, cc(1, CC_MAX), ReservationKind::Transfer),
            res(2, cc(1, CC_MAX), ReservationKind::Transfer),
        ];
        let report = evaluate_affordability(&[], &reservations, &[], &[]).unwrap();
        assert!(!report.is_affordable());
        assert_eq!(
            report
                .outcome(AssetId::CurrencyCollection(1))
                .unwrap()
                .reserved(),
            None
        );
    }

    #[test]
    fn a_representable_old_only_asset_produces_a_zero_request_outcome() {
        let reservations = [res(1, cc(1, "3"), ReservationKind::Transfer)];
        let balances = [native(10), cc(1, "100")];
        let report = evaluate_affordability(&balances, &reservations, &[], &[native(5)]).unwrap();
        assert!(report.is_affordable());
        let cc_out = report.outcome(AssetId::CurrencyCollection(1)).unwrap();
        assert_eq!(dec(Some(cc_out.requested())), Some("0".to_owned()));
        assert_eq!(dec(cc_out.reserved()), Some("3".to_owned()));
        assert_eq!(dec(cc_out.available()), Some("97".to_owned()));
        assert_eq!(dec(cc_out.worst_case()), Some("3".to_owned()));
        assert!(cc_out.is_sufficient());
    }

    #[test]
    fn an_over_reserved_old_only_asset_blocks_the_send() {
        let reservations = [res(1, cc(1, "100"), ReservationKind::Transfer)];
        let balances = [native(10), cc(1, "40")];
        let report = evaluate_affordability(&balances, &reservations, &[], &[native(5)]).unwrap();
        let cc_out = report.outcome(AssetId::CurrencyCollection(1)).unwrap();
        assert_eq!(cc_out.available(), None, "S(100) > B(40)");
        assert!(!cc_out.is_sufficient());
        assert!(!report.is_affordable());
    }

    #[test]
    fn worst_case_over_balance_is_a_warning_not_a_block() {
        let reservations = [
            res(1, native(6), ReservationKind::Transfer),
            res(2, native(5), ReservationKind::Transfer),
        ];
        let overlap = [reservations[0].clone()];
        let report =
            evaluate_affordability(&[native(10)], &reservations, &overlap, &[native(4)]).unwrap();
        let out = report.outcome(AssetId::Native).unwrap();
        assert_eq!(dec(out.reserved()), Some("5".to_owned()));
        assert_eq!(dec(out.available()), Some("5".to_owned()));
        assert!(out.is_sufficient(), "4 <= 5 available");
        assert!(report.is_affordable());
        assert_eq!(dec(out.worst_case()), Some("15".to_owned()));
        assert!(out.worst_case_warns(), "W(15) > B(10)");
    }

    #[test]
    fn worst_case_beyond_the_domain_is_a_warning_not_a_block() {
        let near_max = native(NATIVE_MAX_UNITS);
        let reservations = [res(1, near_max.clone(), ReservationKind::Transfer)];
        let overlap = [reservations[0].clone()];
        let report =
            evaluate_affordability(&[near_max], &reservations, &overlap, &[native(5)]).unwrap();
        let out = report.outcome(AssetId::Native).unwrap();
        assert!(report.is_affordable());
        assert_eq!(out.worst_case(), None, "near_max + 5 exceeds 2^120-1");
        assert!(out.worst_case_warns());
    }

    #[test]
    fn cc_arithmetic_is_exact_above_the_u128_boundary() {
        let u128_plus_one = "340282366920938463463374607431768211456";
        let two_u128 = "680564733841876926926749214863536422910";
        let balances = [cc(3, two_u128)];
        let reservations = [res(1, cc(3, u128_plus_one), ReservationKind::Transfer)];
        let requested = [cc(3, u128_plus_one)];
        let report = evaluate_affordability(&balances, &reservations, &[], &requested).unwrap();
        let out = report.outcome(AssetId::CurrencyCollection(3)).unwrap();
        assert_eq!(
            dec(out.available()),
            Some("340282366920938463463374607431768211454".to_owned())
        );
        assert!(!report.is_affordable());
    }

    #[test]
    fn duplicate_and_malformed_inputs_are_refused() {
        assert_eq!(
            evaluate_affordability(&[native(1), native(2)], &[], &[], &[native(1)]).unwrap_err(),
            AffordabilityError::DuplicateAsset {
                asset: AssetId::Native
            }
        );
        let r = res(1, native(1), ReservationKind::Transfer);
        assert_eq!(
            evaluate_affordability(&[native(9)], &[r.clone(), r.clone()], &[], &[native(1)])
                .unwrap_err(),
            AffordabilityError::DuplicateReservation
        );
        assert_eq!(
            evaluate_affordability(
                &[native(9)],
                std::slice::from_ref(&r),
                &[r.clone(), r.clone()],
                &[native(1)]
            )
            .unwrap_err(),
            AffordabilityError::DuplicateOverlap
        );
        let other = res(2, native(1), ReservationKind::Transfer);
        assert_eq!(
            evaluate_affordability(&[native(9)], &[r], &[other], &[native(1)]).unwrap_err(),
            AffordabilityError::OverlapRowNotReserved
        );
    }

    #[test]
    fn distinct_cc_ids_are_independent() {
        let reservations = [
            res(1, cc(1, "50"), ReservationKind::Transfer),
            res(2, cc(2, "50"), ReservationKind::Transfer),
        ];
        let balances = [cc(1, "100"), cc(2, "10")];
        let report = evaluate_affordability(&balances, &reservations, &[], &[cc(1, "40")]).unwrap();
        assert!(
            report
                .outcome(AssetId::CurrencyCollection(1))
                .unwrap()
                .is_sufficient()
        );
        assert!(
            !report
                .outcome(AssetId::CurrencyCollection(2))
                .unwrap()
                .is_sufficient()
        );
        assert!(!report.is_affordable());
    }
}
