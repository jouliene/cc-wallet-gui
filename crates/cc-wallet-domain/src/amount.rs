use std::cmp::Ordering;
use std::fmt;

use num_bigint::BigUint;
use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::asset::{AssetId, asset_meta};
use crate::error::{WalletError, WalletResult};

const FIXED9_DECIMALS: usize = 9;

pub fn parse_send_amount(asset: AssetId, value: &str) -> WalletResult<AssetAmount> {
    if asset_meta(asset).decimals != Some(FIXED9_DECIMALS as u8) {
        return Err(WalletError::amount(
            "this currency has no approved first-release send precision",
        ));
    }

    let mut parts = value.split('.');
    let whole = parts.next().unwrap_or_default();
    let fraction = parts.next();
    if parts.next().is_some()
        || whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || (whole.len() > 1 && whole.as_bytes()[0] == b'0')
    {
        return Err(WalletError::amount(
            "amount must use canonical ASCII fixed-9 syntax",
        ));
    }
    if let Some(fraction) = fraction
        && (fraction.is_empty()
            || fraction.len() > FIXED9_DECIMALS
            || !fraction.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(WalletError::amount(
            "amount fraction must contain 1 to 9 ASCII digits",
        ));
    }

    let max_whole_digits = match asset {
        AssetId::Native => 28,
        AssetId::CurrencyCollection(id) if AssetId::CurrencyCollection(id).is_known_cc() => 66,
        AssetId::CurrencyCollection(_) => {
            return Err(WalletError::amount(
                "only currency-collection ids 1, 2, and 3 can be sent",
            ));
        }
    };
    if whole.len() > max_whole_digits {
        return Err(WalletError::amount(
            "amount whole part exceeds the asset-domain precheck",
        ));
    }

    let fraction = fraction.unwrap_or_default();
    let mut digits = String::with_capacity(whole.len() + FIXED9_DECIMALS);
    digits.push_str(whole);
    digits.push_str(fraction);
    digits.extend(std::iter::repeat_n('0', FIXED9_DECIMALS - fraction.len()));
    let canonical = digits.trim_start_matches('0');
    let canonical = if canonical.is_empty() { "0" } else { canonical };

    let amount = match asset {
        AssetId::Native => AssetAmount::native(
            native_units_from_canonical_decimal(canonical)
                .map_err(|error| WalletError::amount(error.to_string()))?,
        )
        .map_err(|error| WalletError::amount(error.to_string()))?,
        AssetId::CurrencyCollection(id) if AssetId::CurrencyCollection(id).is_known_cc() => {
            AssetAmount::currency_collection(
                id,
                CcAmount::try_from_canonical_decimal(canonical)
                    .map_err(|error| WalletError::amount(error.to_string()))?,
            )
        }
        AssetId::CurrencyCollection(_) => unreachable!("unsupported ids returned above"),
    };
    if amount.is_zero() {
        return Err(WalletError::amount("amount must be greater than zero"));
    }
    Ok(amount)
}

pub fn format_fixed9_amount(amount: &AssetAmount) -> WalletResult<String> {
    if asset_meta(amount.asset_id()).decimals != Some(FIXED9_DECIMALS as u8) {
        return Err(WalletError::amount(
            "this currency has no approved decimal display",
        ));
    }
    let digits = match amount.native_units() {
        Some(units) => units.to_string(),
        None => amount
            .cc_units()
            .expect("a non-native AssetAmount carries CC units")
            .to_canonical_decimal(),
    };
    let padded = if digits.len() <= FIXED9_DECIMALS {
        format!("{:0>width$}", digits, width = FIXED9_DECIMALS + 1)
    } else {
        digits
    };
    let split = padded.len() - FIXED9_DECIMALS;
    Ok(format!("{}.{}", &padded[..split], &padded[split..]))
}

pub fn format_base_units(amount: &AssetAmount) -> String {
    match amount.native_units() {
        Some(units) => units.to_string(),
        None => amount
            .cc_units()
            .expect("a non-native AssetAmount carries CC units")
            .to_canonical_decimal(),
    }
}

pub fn format_native_fixed9(units: u128) -> WalletResult<String> {
    let amount =
        AssetAmount::native(units).map_err(|error| WalletError::amount(error.to_string()))?;
    format_fixed9_amount(&amount)
}

const CC_MAX_DECIMAL: &str =
    "452312848583266388373324160190187140051835877600158453279131187530910662655";

pub const NATIVE_MAX_UNITS: u128 = (1u128 << 120) - 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AmountError {
    Empty,
    NonCanonicalDecimal,
    TooManyDigits,
    ExtraCurrencyOutOfDomain,
    NativeOutOfDomain,
    Overflow,
    Underflow,
    AssetMismatch,
}

impl fmt::Display for AmountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::Empty => "amount is empty",
            Self::NonCanonicalDecimal => {
                "amount must be a canonical base-10 integer: ASCII digits only, no sign, \
                 whitespace, decimal point, exponent, separators, or leading zeros"
            }
            Self::TooManyDigits => "amount has too many digits for the extra-currency domain",
            Self::ExtraCurrencyOutOfDomain => {
                "extra-currency amount exceeds the protocol maximum (2^248 - 1)"
            }
            Self::NativeOutOfDomain => "native amount exceeds the protocol maximum (2^120 - 1)",
            Self::Overflow => "amount addition overflows the asset domain",
            Self::Underflow => "amount subtraction underflows below zero",
            Self::AssetMismatch => "amounts of different assets cannot be combined or compared",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for AmountError {}

fn ensure_canonical_decimal(text: &str) -> Result<(), AmountError> {
    if text.is_empty() {
        return Err(AmountError::Empty);
    }
    if !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(AmountError::NonCanonicalDecimal);
    }
    if text.len() > 1 && text.as_bytes()[0] == b'0' {
        return Err(AmountError::NonCanonicalDecimal);
    }
    Ok(())
}

pub(crate) fn native_units_from_canonical_decimal(text: &str) -> Result<u128, AmountError> {
    ensure_canonical_decimal(text)?;
    if text.len() > 37 {
        return Err(AmountError::NativeOutOfDomain);
    }
    let value = text
        .parse::<u128>()
        .map_err(|_| AmountError::NativeOutOfDomain)?;
    if value > NATIVE_MAX_UNITS {
        return Err(AmountError::NativeOutOfDomain);
    }
    Ok(value)
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CcAmount(BigUint);

impl CcAmount {
    pub fn zero() -> Self {
        Self(BigUint::from(0u8))
    }

    pub fn from_u128(value: u128) -> Self {
        Self(BigUint::from(value))
    }

    pub fn is_zero(&self) -> bool {
        self.0.bits() == 0
    }

    pub fn try_from_canonical_decimal(text: &str) -> Result<Self, AmountError> {
        ensure_canonical_decimal(text)?;
        if text.len() > 75 {
            return Err(AmountError::TooManyDigits);
        }
        if text.len() == 75 && text > CC_MAX_DECIMAL {
            return Err(AmountError::ExtraCurrencyOutOfDomain);
        }
        let value =
            BigUint::parse_bytes(text.as_bytes(), 10).ok_or(AmountError::NonCanonicalDecimal)?;
        debug_assert!(
            value.bits() <= 248,
            "canonical-decimal bound guarantees 248 bits"
        );
        Ok(Self(value))
    }

    pub fn to_canonical_decimal(&self) -> String {
        self.0.to_str_radix(10)
    }

    pub fn from_be_bytes_31(bytes: &[u8; 31]) -> Self {
        Self(BigUint::from_bytes_be(bytes))
    }

    pub fn to_be_bytes_31(&self) -> [u8; 31] {
        let raw = self.0.to_bytes_be();
        debug_assert!(raw.len() <= 31, "248-bit domain fits in 31 bytes");
        let mut out = [0u8; 31];
        out[31 - raw.len()..].copy_from_slice(&raw);
        out
    }

    pub fn checked_add(&self, rhs: &Self) -> Option<Self> {
        let sum = &self.0 + &rhs.0;
        if sum.bits() <= 248 {
            Some(Self(sum))
        } else {
            None
        }
    }

    pub fn checked_sub(&self, rhs: &Self) -> Option<Self> {
        (self.0 >= rhs.0).then(|| Self(&self.0 - &rhs.0))
    }
}

impl fmt::Debug for CcAmount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CcAmount({})", self.to_canonical_decimal())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum AssetAmountRepr {
    Native { units: u128 },
    CurrencyCollection { id: u32, units: CcAmount },
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AssetAmount(AssetAmountRepr);

impl AssetAmount {
    pub fn native(units: u128) -> Result<Self, AmountError> {
        if units > NATIVE_MAX_UNITS {
            return Err(AmountError::NativeOutOfDomain);
        }
        Ok(Self(AssetAmountRepr::Native { units }))
    }

    pub fn currency_collection(id: u32, units: CcAmount) -> Self {
        Self(AssetAmountRepr::CurrencyCollection { id, units })
    }

    pub fn asset_id(&self) -> AssetId {
        match &self.0 {
            AssetAmountRepr::Native { .. } => AssetId::Native,
            AssetAmountRepr::CurrencyCollection { id, .. } => AssetId::CurrencyCollection(*id),
        }
    }

    pub fn native_units(&self) -> Option<u128> {
        match &self.0 {
            AssetAmountRepr::Native { units } => Some(*units),
            AssetAmountRepr::CurrencyCollection { .. } => None,
        }
    }

    pub fn cc_units(&self) -> Option<&CcAmount> {
        match &self.0 {
            AssetAmountRepr::Native { .. } => None,
            AssetAmountRepr::CurrencyCollection { units, .. } => Some(units),
        }
    }

    pub fn is_zero(&self) -> bool {
        match &self.0 {
            AssetAmountRepr::Native { units } => *units == 0,
            AssetAmountRepr::CurrencyCollection { units, .. } => units.is_zero(),
        }
    }

    pub fn checked_add_same_asset(&self, rhs: &Self) -> Result<Self, AmountError> {
        match (&self.0, &rhs.0) {
            (AssetAmountRepr::Native { units: a }, AssetAmountRepr::Native { units: b }) => {
                let sum = a.checked_add(*b).ok_or(AmountError::Overflow)?;
                Self::native(sum)
            }
            (
                AssetAmountRepr::CurrencyCollection { id: ia, units: a },
                AssetAmountRepr::CurrencyCollection { id: ib, units: b },
            ) if ia == ib => Ok(Self::currency_collection(
                *ia,
                a.checked_add(b).ok_or(AmountError::Overflow)?,
            )),
            _ => Err(AmountError::AssetMismatch),
        }
    }

    pub fn checked_sub_same_asset(&self, rhs: &Self) -> Result<Self, AmountError> {
        match (&self.0, &rhs.0) {
            (AssetAmountRepr::Native { units: a }, AssetAmountRepr::Native { units: b }) => {
                let diff = a.checked_sub(*b).ok_or(AmountError::Underflow)?;
                Self::native(diff)
            }
            (
                AssetAmountRepr::CurrencyCollection { id: ia, units: a },
                AssetAmountRepr::CurrencyCollection { id: ib, units: b },
            ) if ia == ib => Ok(Self::currency_collection(
                *ia,
                a.checked_sub(b).ok_or(AmountError::Underflow)?,
            )),
            _ => Err(AmountError::AssetMismatch),
        }
    }

    pub fn cmp_same_asset(&self, rhs: &Self) -> Result<Ordering, AmountError> {
        match (&self.0, &rhs.0) {
            (AssetAmountRepr::Native { units: a }, AssetAmountRepr::Native { units: b }) => {
                Ok(a.cmp(b))
            }
            (
                AssetAmountRepr::CurrencyCollection { id: ia, units: a },
                AssetAmountRepr::CurrencyCollection { id: ib, units: b },
            ) if ia == ib => Ok(a.cmp(b)),
            _ => Err(AmountError::AssetMismatch),
        }
    }
}

impl Serialize for CcAmount {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_canonical_decimal())
    }
}

impl<'de> Deserialize<'de> for CcAmount {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct CcAmountVisitor;

        impl Visitor<'_> for CcAmountVisitor {
            type Value = CcAmount;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a canonical base-10 extra-currency amount string")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<CcAmount, E> {
                CcAmount::try_from_canonical_decimal(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(CcAmountVisitor)
    }
}

const ASSET_AMOUNT_FIELDS: &[&str] = &["asset", "currency_id", "base_units"];

impl Serialize for AssetAmount {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match &self.0 {
            AssetAmountRepr::Native { units } => {
                let mut map = serializer.serialize_map(Some(2))?;
                map.serialize_entry("asset", "native")?;
                map.serialize_entry("base_units", &units.to_string())?;
                map.end()
            }
            AssetAmountRepr::CurrencyCollection { id, units } => {
                let mut map = serializer.serialize_map(Some(3))?;
                map.serialize_entry("asset", "currency_collection")?;
                map.serialize_entry("currency_id", id)?;
                map.serialize_entry("base_units", &units.to_canonical_decimal())?;
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for AssetAmount {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct AssetAmountVisitor;

        impl<'de> Visitor<'de> for AssetAmountVisitor {
            type Value = AssetAmount;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a tagged asset-amount object")
            }

            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<AssetAmount, M::Error> {
                let mut asset: Option<String> = None;
                let mut currency_id: Option<u32> = None;
                let mut base_units: Option<String> = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "asset" => {
                            if asset.is_some() {
                                return Err(de::Error::duplicate_field("asset"));
                            }
                            asset = Some(map.next_value()?);
                        }
                        "currency_id" => {
                            if currency_id.is_some() {
                                return Err(de::Error::duplicate_field("currency_id"));
                            }
                            currency_id = Some(map.next_value()?);
                        }
                        "base_units" => {
                            if base_units.is_some() {
                                return Err(de::Error::duplicate_field("base_units"));
                            }
                            base_units = Some(map.next_value()?);
                        }
                        other => return Err(de::Error::unknown_field(other, ASSET_AMOUNT_FIELDS)),
                    }
                }
                let asset = asset.ok_or_else(|| de::Error::missing_field("asset"))?;
                let base_units =
                    base_units.ok_or_else(|| de::Error::missing_field("base_units"))?;
                match asset.as_str() {
                    "native" => {
                        if currency_id.is_some() {
                            return Err(de::Error::custom(
                                "native asset-amount must not carry a currency_id",
                            ));
                        }
                        let units = native_units_from_canonical_decimal(&base_units)
                            .map_err(de::Error::custom)?;
                        AssetAmount::native(units).map_err(de::Error::custom)
                    }
                    "currency_collection" => {
                        let id =
                            currency_id.ok_or_else(|| de::Error::missing_field("currency_id"))?;
                        let units = CcAmount::try_from_canonical_decimal(&base_units)
                            .map_err(de::Error::custom)?;
                        Ok(AssetAmount::currency_collection(id, units))
                    }
                    other => Err(de::Error::custom(format!("unknown asset tag `{other}`"))),
                }
            }
        }

        deserializer.deserialize_map(AssetAmountVisitor)
    }
}

pub mod native_scalar {
    use std::fmt;

    use serde::de::{self, Visitor};
    use serde::ser::Error as _;
    use serde::{Deserializer, Serializer};

    use super::{AmountError, NATIVE_MAX_UNITS, native_units_from_canonical_decimal};

    pub fn serialize<S: Serializer>(value: &u128, serializer: S) -> Result<S::Ok, S::Error> {
        if *value > NATIVE_MAX_UNITS {
            return Err(S::Error::custom(AmountError::NativeOutOfDomain));
        }
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u128, D::Error> {
        struct NativeScalarVisitor;

        impl Visitor<'_> for NativeScalarVisitor {
            type Value = u128;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a canonical base-10 native amount string (<= 2^120 - 1)")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<u128, E> {
                native_units_from_canonical_decimal(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(NativeScalarVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_human_parser_and_fixed9_display_vectors() {
        for (text, expected) in [
            ("0.000000001", "1"),
            ("0.1", "100000000"),
            ("1.2", "1200000000"),
            ("1.000000001", "1000000001"),
        ] {
            let amount = parse_send_amount(AssetId::CurrencyCollection(1), text).unwrap();
            assert_eq!(format_base_units(&amount), expected);
            assert_eq!(
                format_fixed9_amount(&amount).unwrap(),
                format!("{text:0<width$}", width = text.find('.').unwrap() + 10)
            );
        }
        for zero in ["0", "0.000000000"] {
            assert!(parse_send_amount(AssetId::Native, zero).is_err());
        }
        for bad in [
            "",
            " 1",
            "1 ",
            "+1",
            "-1",
            ".1",
            "1.",
            "01",
            "1e3",
            "1_0",
            "1.0000000000",
            "1.2.3",
            "๑",
        ] {
            assert!(
                parse_send_amount(AssetId::Native, bad).is_err(),
                "must reject {bad:?}"
            );
        }
        assert!(parse_send_amount(AssetId::Native, &"1".repeat(29)).is_err());
        assert!(parse_send_amount(AssetId::CurrencyCollection(1), &"1".repeat(67)).is_err());
        assert!(parse_send_amount(AssetId::CurrencyCollection(4), "1").is_err());

        assert_eq!(
            format_native_fixed9(NATIVE_MAX_UNITS).unwrap(),
            "1329227995784915872903807060.280344575"
        );
        let cc_max = AssetAmount::currency_collection(
            1,
            CcAmount::try_from_canonical_decimal(CC_MAX_DECIMAL).unwrap(),
        );
        assert_eq!(
            format_fixed9_amount(&cc_max).unwrap(),
            "452312848583266388373324160190187140051835877600158453279131187530.910662655"
        );

        let native_max_text = "1329227995784915872903807060.280344575";
        let parsed_native_max = parse_send_amount(AssetId::Native, native_max_text).unwrap();
        assert_eq!(parsed_native_max.native_units(), Some(NATIVE_MAX_UNITS));
        assert!(
            parse_send_amount(AssetId::Native, "1329227995784915872903807060.280344576").is_err(),
            "the next native base unit above 2^120-1 must be refused"
        );

        let cc_max_text =
            "452312848583266388373324160190187140051835877600158453279131187530.910662655";
        let parsed_cc_max = parse_send_amount(AssetId::CurrencyCollection(3), cc_max_text).unwrap();
        assert_eq!(format_base_units(&parsed_cc_max), CC_MAX_DECIMAL);
        assert!(
            parse_send_amount(
                AssetId::CurrencyCollection(3),
                "452312848583266388373324160190187140051835877600158453279131187530.910662656"
            )
            .is_err(),
            "the next CC base unit above 2^248-1 must be refused"
        );
    }
}

#[cfg(test)]
mod amount_domain_tests {
    use super::*;

    fn cc(s: &str) -> CcAmount {
        CcAmount::try_from_canonical_decimal(s).unwrap()
    }

    #[test]
    fn cc_boundary_values_are_accepted_and_round_trip() {
        for s in [
            "0",
            "1",
            "18446744073709551615",
            "18446744073709551616",
            "340282366920938463463374607431768211455",
            "340282366920938463463374607431768211456",
            CC_MAX_DECIMAL,
        ] {
            assert_eq!(
                cc(s).to_canonical_decimal(),
                s,
                "canonical round-trip for {s}"
            );
        }
    }

    #[test]
    fn cc_rejects_values_above_the_domain_before_allocating() {
        assert_eq!(
            CcAmount::try_from_canonical_decimal(
                "452312848583266388373324160190187140051835877600158453279131187530910662656"
            ),
            Err(AmountError::ExtraCurrencyOutOfDomain)
        );
        assert_eq!(
            CcAmount::try_from_canonical_decimal(&"1".repeat(76)),
            Err(AmountError::TooManyDigits)
        );
    }

    #[test]
    fn cc_rejects_noncanonical_text_and_has_one_spelling_per_value() {
        for bad in [
            "", "+1", "-1", " 1", "1 ", "00", "01", "1.0", "1e3", "1_000", "1,000", "๑", "0x1",
            "0000",
        ] {
            assert!(
                CcAmount::try_from_canonical_decimal(bad).is_err(),
                "must reject {bad:?}"
            );
        }
        assert_eq!(CcAmount::zero().to_canonical_decimal(), "0");
        assert_eq!(CcAmount::from_u128(0).to_canonical_decimal(), "0");
        assert_eq!(cc("1000000000").to_canonical_decimal(), "1000000000");
    }

    #[test]
    fn cc_31_byte_boundary_is_bijective_at_the_extremes() {
        assert_eq!(CcAmount::zero().to_be_bytes_31(), [0u8; 31]);
        assert_eq!(CcAmount::from_be_bytes_31(&[0u8; 31]), CcAmount::zero());
        let max = cc(CC_MAX_DECIMAL);
        assert_eq!(max.to_be_bytes_31(), [0xFFu8; 31]);
        assert_eq!(CcAmount::from_be_bytes_31(&[0xFFu8; 31]), max);
        let mid = cc("340282366920938463463374607431768211456");
        assert_eq!(CcAmount::from_be_bytes_31(&mid.to_be_bytes_31()), mid);
    }

    #[test]
    fn cc_checked_arithmetic_crosses_the_u128_boundary_exactly() {
        let one = CcAmount::from_u128(1);
        let u128_max = CcAmount::from_u128(u128::MAX);
        let u128_plus_one = cc("340282366920938463463374607431768211456");
        assert_eq!(u128_max.checked_add(&one), Some(u128_plus_one.clone()));
        assert_eq!(u128_plus_one.checked_sub(&one), Some(u128_max));
        assert_eq!(cc(CC_MAX_DECIMAL).checked_add(&one), None);
        assert_eq!(CcAmount::zero().checked_sub(&one), None);
    }

    #[test]
    fn native_domain_bound_is_2_pow_120_minus_1() {
        assert_eq!(NATIVE_MAX_UNITS, (1u128 << 120) - 1);
        assert!(AssetAmount::native(0).is_ok());
        assert!(AssetAmount::native(NATIVE_MAX_UNITS - 1).is_ok());
        assert!(AssetAmount::native(NATIVE_MAX_UNITS).is_ok());
        assert_eq!(
            AssetAmount::native(NATIVE_MAX_UNITS + 1),
            Err(AmountError::NativeOutOfDomain)
        );
    }

    #[test]
    fn asset_amount_binds_identity_and_refuses_cross_asset_ops() {
        let native = AssetAmount::native(5).unwrap();
        let cc1 = AssetAmount::currency_collection(1, CcAmount::from_u128(5));
        let cc1b = AssetAmount::currency_collection(1, CcAmount::from_u128(3));
        let cc2 = AssetAmount::currency_collection(2, CcAmount::from_u128(5));

        assert_eq!(native.asset_id(), AssetId::Native);
        assert_eq!(cc1.asset_id(), AssetId::CurrencyCollection(1));
        assert_eq!(native.native_units(), Some(5));
        assert!(native.cc_units().is_none());
        assert_eq!(cc1.cc_units().unwrap().to_canonical_decimal(), "5");
        assert!(cc1.native_units().is_none());

        let sum = cc1.checked_add_same_asset(&cc1b).unwrap();
        assert_eq!(sum.cc_units().unwrap().to_canonical_decimal(), "8");
        assert_eq!(cc1.cmp_same_asset(&cc1b), Ok(Ordering::Greater));

        assert_eq!(
            native.checked_add_same_asset(&cc1),
            Err(AmountError::AssetMismatch)
        );
        assert_eq!(
            cc1.checked_add_same_asset(&cc2),
            Err(AmountError::AssetMismatch)
        );
        assert_eq!(
            cc1.checked_sub_same_asset(&native),
            Err(AmountError::AssetMismatch)
        );
        assert_eq!(cc1.cmp_same_asset(&cc2), Err(AmountError::AssetMismatch));
    }

    #[test]
    fn native_sum_beyond_protocol_max_is_refused_not_wrapped() {
        let near = AssetAmount::native(NATIVE_MAX_UNITS).unwrap();
        let one = AssetAmount::native(1).unwrap();
        assert_eq!(
            near.checked_add_same_asset(&one),
            Err(AmountError::NativeOutOfDomain)
        );
        assert_eq!(
            AssetAmount::native(0).unwrap().checked_sub_same_asset(&one),
            Err(AmountError::Underflow)
        );
    }

    #[test]
    fn cc_amount_serializes_as_a_canonical_string_and_rejects_numbers() {
        let a = cc("340282366920938463463374607431768211456");
        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            "\"340282366920938463463374607431768211456\""
        );
        let back: CcAmount =
            serde_json::from_str("\"340282366920938463463374607431768211456\"").unwrap();
        assert_eq!(back, a);
        let max = cc(CC_MAX_DECIMAL);
        let round =
            serde_json::from_str::<CcAmount>(&serde_json::to_string(&max).unwrap()).unwrap();
        assert_eq!(round, max);

        assert!(serde_json::from_str::<CcAmount>("123").is_err());
        assert!(serde_json::from_str::<CcAmount>("\"01\"").is_err());
        assert!(serde_json::from_str::<CcAmount>("\"-1\"").is_err());
        assert!(serde_json::from_str::<CcAmount>(&format!("\"{}\"", "1".repeat(76))).is_err());
    }

    #[test]
    fn asset_amount_tagged_wire_shapes_round_trip() {
        let native = AssetAmount::native(1_500_000_000).unwrap();
        assert_eq!(
            serde_json::to_string(&native).unwrap(),
            r#"{"asset":"native","base_units":"1500000000"}"#
        );
        assert_eq!(
            serde_json::from_str::<AssetAmount>(r#"{"asset":"native","base_units":"1500000000"}"#)
                .unwrap(),
            native
        );

        let cc_amt =
            AssetAmount::currency_collection(2, cc("340282366920938463463374607431768211456"));
        let jc = serde_json::to_string(&cc_amt).unwrap();
        assert_eq!(
            jc,
            r#"{"asset":"currency_collection","currency_id":2,"base_units":"340282366920938463463374607431768211456"}"#
        );
        assert_eq!(serde_json::from_str::<AssetAmount>(&jc).unwrap(), cc_amt);
    }

    #[test]
    fn asset_amount_deserialize_is_strict() {
        let ok = r#"{"asset":"native","base_units":"1"}"#;
        assert!(serde_json::from_str::<AssetAmount>(ok).is_ok());
        for bad in [
            r#"{"asset":"native","base_units":"1","x":1}"#,
            r#"{"asset":"native","base_units":"1","base_units":"2"}"#,
            r#"{"asset":"native"}"#,
            r#"{"base_units":"1"}"#,
            r#"{"asset":"native","currency_id":1,"base_units":"1"}"#,
            r#"{"asset":"currency_collection","base_units":"1"}"#,
            r#"{"asset":"weird","base_units":"1"}"#,
            r#"{"asset":"native","base_units":"01"}"#,
            r#"{"asset":"native","base_units":1}"#,
            r#"{"asset":"native","base_units":"1329227995784915872903807060280344576"}"#,
            r#"{"asset":"currency_collection","currency_id":"1","base_units":"1"}"#,
            r#""native""#,
        ] {
            assert!(
                serde_json::from_str::<AssetAmount>(bad).is_err(),
                "must reject {bad}"
            );
        }
    }

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct NativeScalarHolder {
        #[serde(with = "native_scalar")]
        fee: u128,
    }

    #[test]
    fn native_scalar_field_serializes_as_a_canonical_string_and_is_bounded() {
        let holder = NativeScalarHolder { fee: 1_500_000_000 };
        assert_eq!(
            serde_json::to_string(&holder).unwrap(),
            r#"{"fee":"1500000000"}"#
        );

        for units in [0u128, 1, NATIVE_MAX_UNITS] {
            let json = serde_json::to_string(&NativeScalarHolder { fee: units }).unwrap();
            let back: NativeScalarHolder = serde_json::from_str(&json).unwrap();
            assert_eq!(back.fee, units);
        }
        assert_eq!(
            serde_json::to_string(&NativeScalarHolder {
                fee: NATIVE_MAX_UNITS
            })
            .unwrap(),
            r#"{"fee":"1329227995784915872903807060280344575"}"#
        );

        for bad in [
            r#"{"fee":1500000000}"#,
            r#"{"fee":"01"}"#,
            r#"{"fee":""}"#,
            r#"{"fee":"-1"}"#,
            r#"{"fee":" 1"}"#,
            r#"{"fee":"1.0"}"#,
            r#"{"fee":"1329227995784915872903807060280344576"}"#,
        ] {
            assert!(
                serde_json::from_str::<NativeScalarHolder>(bad).is_err(),
                "must reject {bad}"
            );
        }
    }

    #[test]
    fn native_scalar_serialize_fails_closed_above_the_native_domain() {
        assert!(
            serde_json::to_string(&NativeScalarHolder {
                fee: NATIVE_MAX_UNITS + 1
            })
            .is_err(),
            "serializing 2^120 must fail closed"
        );
        assert!(
            serde_json::to_string(&NativeScalarHolder { fee: u128::MAX }).is_err(),
            "serializing u128::MAX must fail closed"
        );
        for units in [0u128, 1, NATIVE_MAX_UNITS] {
            let json = serde_json::to_string(&NativeScalarHolder { fee: units }).unwrap();
            assert_eq!(
                serde_json::from_str::<NativeScalarHolder>(&json)
                    .unwrap()
                    .fee,
                units
            );
        }
    }
}
