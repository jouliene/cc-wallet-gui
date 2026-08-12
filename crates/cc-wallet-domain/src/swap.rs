use serde::{Deserialize, Serialize};

use crate::amount::{AssetAmount, parse_send_amount};
use crate::asset::AssetId;
use crate::error::{WalletError, WalletResult};
use crate::send::SendToken;

pub const FEE_DENOM: u128 = 10_000;

pub const DEFAULT_SLIPPAGE_BPS: u16 = 50;

pub const SLIPPAGE_STEP_BPS: u16 = 10;

pub const MAX_SLIPPAGE_BPS: u16 = 1_000;

pub const SLIPPAGE_DECIMALS: usize = 2;

pub fn parse_slippage_percent(text: &str) -> Option<u16> {
    let text = text.trim().trim_end_matches('%').trim();
    let (whole_text, frac_text) = match text.split_once('.') {
        Some((whole, frac)) => (whole, frac),
        None => (text, ""),
    };
    if whole_text.is_empty() && frac_text.is_empty() {
        return None;
    }
    let digits_only = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    if !digits_only(whole_text) || !digits_only(frac_text) || frac_text.len() > SLIPPAGE_DECIMALS {
        return None;
    }
    let whole: u32 = if whole_text.is_empty() {
        0
    } else {
        whole_text.parse().ok()?
    };
    let mut hundredths_text = frac_text.to_owned();
    while hundredths_text.len() < SLIPPAGE_DECIMALS {
        hundredths_text.push('0');
    }
    let hundredths: u32 = hundredths_text.parse().ok()?;
    let bps = u16::try_from(whole.checked_mul(100)?.checked_add(hundredths)?).ok()?;
    (bps <= MAX_SLIPPAGE_BPS).then_some(bps)
}

pub fn step_slippage_bps(bps: u16, up: bool) -> u16 {
    let step = SLIPPAGE_STEP_BPS;
    let bps = bps.min(MAX_SLIPPAGE_BPS);
    let stepped = if up {
        (bps / step + 1) * step
    } else {
        (bps.saturating_sub(1)) / step * step
    };
    stepped.min(MAX_SLIPPAGE_BPS)
}

pub fn format_slippage_percent(bps: u16) -> String {
    let whole = bps / 100;
    match bps % 100 {
        0 => whole.to_string(),
        hundredths if hundredths % 10 == 0 => format!("{whole}.{}", hundredths / 10),
        hundredths => format!("{whole}.{hundredths:02}"),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwapForm {
    pub from: SendToken,
    pub to: SendToken,
    pub amount: String,
    pub slippage_bps: u16,
}

impl Default for SwapForm {
    fn default() -> Self {
        Self {
            from: SendToken::Native,
            to: SendToken::Cc(1),
            amount: String::new(),
            slippage_bps: DEFAULT_SLIPPAGE_BPS,
        }
    }
}

impl SwapForm {
    pub fn from_asset(&self) -> AssetId {
        self.from.asset_id()
    }

    pub fn to_asset(&self) -> AssetId {
        self.to.asset_id()
    }

    pub fn input(&self) -> WalletResult<AssetAmount> {
        parse_send_amount(self.from.asset_id(), &self.amount)
    }

    pub fn flip(&mut self) {
        std::mem::swap(&mut self.from, &mut self.to);
    }

    pub fn clamped_slippage_bps(&self) -> u16 {
        self.slippage_bps.min(MAX_SLIPPAGE_BPS)
    }
}

pub fn base_units_u128(amount: &AssetAmount) -> Option<u128> {
    match amount.native_units() {
        Some(units) => Some(units),
        None => amount
            .cc_units()
            .expect("a non-native AssetAmount carries CC units")
            .to_canonical_decimal()
            .parse::<u128>()
            .ok(),
    }
}

pub fn expected_out(reserve_in: u128, reserve_out: u128, dx: u128, fee_bps: u16) -> Option<u128> {
    if fee_bps as u128 >= FEE_DENOM {
        return None;
    }
    if reserve_in == 0 {
        return Some(0);
    }
    let dx_fee = dx.checked_mul(FEE_DENOM - fee_bps as u128)? / FEE_DENOM;
    if dx_fee == 0 {
        return Some(0);
    }
    let numerator = reserve_out.checked_mul(dx_fee)?;
    let denominator = reserve_in.checked_add(dx_fee)?;
    if denominator == 0 {
        return Some(0);
    }
    Some(numerator / denominator)
}

pub fn min_out_after_slippage(out: u128, slippage_bps: u16) -> Option<u128> {
    let slippage = (slippage_bps as u128).min(FEE_DENOM);
    Some(out.checked_mul(FEE_DENOM - slippage)? / FEE_DENOM)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwapQuote {
    pub in_units: u128,
    pub out_units: u128,
    pub min_out_units: u128,
    pub fee_bps: u16,
    pub slippage_bps: u16,
}

impl SwapQuote {
    pub fn is_empty(&self) -> bool {
        self.out_units == 0
    }
}

pub fn quote_swap(
    in_units: u128,
    reserve_in: u128,
    reserve_out: u128,
    fee_bps: u16,
    slippage_bps: u16,
) -> Option<SwapQuote> {
    let out_units = expected_out(reserve_in, reserve_out, in_units, fee_bps)?;
    let min_out_units = min_out_after_slippage(out_units, slippage_bps)?;
    Some(SwapQuote {
        in_units,
        out_units,
        min_out_units,
        fee_bps,
        slippage_bps,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapRequest {
    input: AssetAmount,
    output: AssetId,
    min_out_units: u128,
    slippage_bps: u16,
}

impl SwapRequest {
    pub fn new(
        input: AssetAmount,
        output: AssetId,
        min_out_units: u128,
        slippage_bps: u16,
    ) -> WalletResult<Self> {
        let in_asset = input.asset_id();
        if !in_asset.is_sendable() || !output.is_sendable() {
            return Err(WalletError::validation(
                "only the native coin and tokens 1, 2, and 3 can be swapped",
            ));
        }
        if in_asset == output {
            return Err(WalletError::validation(
                "choose two different tokens to swap",
            ));
        }
        if input.is_zero() {
            return Err(WalletError::amount("amount must be greater than zero"));
        }
        if slippage_bps > MAX_SLIPPAGE_BPS {
            return Err(WalletError::validation("slippage tolerance is too high"));
        }
        base_units_u128(&input)
            .ok_or_else(|| WalletError::amount("amount is too large to swap"))?;
        Ok(Self {
            input,
            output,
            min_out_units,
            slippage_bps,
        })
    }

    pub fn in_asset(&self) -> AssetId {
        self.input.asset_id()
    }

    pub fn in_units(&self) -> u128 {
        base_units_u128(&self.input).expect("input base units fit u128, checked in new")
    }
}

accessors!(SwapRequest {
    input: ref AssetAmount,
    output: copy AssetId,
    min_out_units: copy u128,
    slippage_bps: copy u16
});

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amount::CcAmount;

    const UNIT: u128 = 1_000_000_000;

    #[test]
    fn expected_out_matches_the_live_pool_reference_value() {
        let out = expected_out(100 * UNIT, 100 * UNIT, 10 * UNIT, 30).unwrap();
        assert_eq!(out, 9_066_108_938);
    }

    #[test]
    fn min_out_applies_slippage_as_a_floor() {
        let out = 9_066_108_938;
        assert_eq!(min_out_after_slippage(out, 50).unwrap(), 9_020_778_393);
        assert_eq!(min_out_after_slippage(out, 0).unwrap(), out);
        assert_eq!(min_out_after_slippage(out, 10_000).unwrap(), 0);
    }

    #[test]
    fn a_dust_input_the_fee_rounds_away_quotes_to_zero() {
        assert_eq!(expected_out(100 * UNIT, 100 * UNIT, 1, 30), Some(0));
    }

    #[test]
    fn an_empty_reserve_side_quotes_to_zero_not_an_error() {
        let q = quote_swap(10 * UNIT, 100 * UNIT, 0, 30, 50).unwrap();
        assert!(q.is_empty());
        assert_eq!(q.min_out_units, 0);
    }

    #[test]
    fn an_unheld_input_asset_has_no_route_rather_than_the_whole_output_reserve() {
        assert_eq!(expected_out(0, 100 * UNIT, 10 * UNIT, 30), Some(0));
        let q = quote_swap(10 * UNIT, 0, 100 * UNIT, 30, 50).unwrap();
        assert!(q.is_empty(), "no reserve on the way in is no route");
        assert_eq!(q.min_out_units, 0);
    }

    #[test]
    fn expected_out_guards_overflow_instead_of_wrapping() {
        assert_eq!(expected_out(1, u128::MAX, u128::MAX, 0), None);
    }

    #[test]
    fn quote_carries_the_fee_and_slippage_through() {
        let q = quote_swap(10 * UNIT, 100 * UNIT, 100 * UNIT, 30, 50).unwrap();
        assert_eq!(q.in_units, 10 * UNIT);
        assert_eq!(q.out_units, 9_066_108_938);
        assert_eq!(q.min_out_units, 9_020_778_393);
        assert_eq!(q.fee_bps, 30);
        assert_eq!(q.slippage_bps, 50);
        assert!(!q.is_empty());
    }

    #[test]
    fn form_flip_swaps_sides_and_keeps_the_amount() {
        let mut form = SwapForm {
            from: SendToken::Native,
            to: SendToken::Cc(2),
            amount: "10".to_owned(),
            slippage_bps: 50,
        };
        form.flip();
        assert_eq!(form.from, SendToken::Cc(2));
        assert_eq!(form.to, SendToken::Native);
        assert_eq!(form.amount, "10");
    }

    #[test]
    fn form_parses_its_input_as_the_from_asset() {
        let form = SwapForm {
            from: SendToken::Cc(1),
            to: SendToken::Native,
            amount: "1.5".to_owned(),
            slippage_bps: 50,
        };
        let input = form.input().unwrap();
        assert_eq!(input.asset_id(), AssetId::CurrencyCollection(1));
        assert_eq!(base_units_u128(&input), Some(1_500_000_000));
    }

    #[test]
    fn request_binds_a_valid_intent() {
        let input = AssetAmount::currency_collection(1, CcAmount::from_u128(10 * UNIT));
        let req =
            SwapRequest::new(input, AssetId::CurrencyCollection(2), 9_020_778_393, 50).unwrap();
        assert_eq!(req.in_asset(), AssetId::CurrencyCollection(1));
        assert_eq!(req.output(), AssetId::CurrencyCollection(2));
        assert_eq!(req.in_units(), 10 * UNIT);
        assert_eq!(req.min_out_units(), 9_020_778_393);
        assert_eq!(req.slippage_bps(), 50);
    }

    #[test]
    fn request_allows_an_unsupported_pool_token_so_the_bounce_can_be_shown() {
        let input = AssetAmount::currency_collection(3, CcAmount::from_u128(UNIT));
        assert!(SwapRequest::new(input, AssetId::Native, 0, 50).is_ok());
    }

    #[test]
    fn request_rejects_same_asset_zero_and_unsendable() {
        let native = || AssetAmount::native(UNIT).unwrap();
        assert!(SwapRequest::new(native(), AssetId::Native, 0, 50).is_err());
        assert!(
            SwapRequest::new(
                AssetAmount::native(0).unwrap(),
                AssetId::CurrencyCollection(1),
                0,
                50
            )
            .is_err()
        );
        let unsupported = AssetAmount::currency_collection(9, CcAmount::from_u128(UNIT));
        assert!(SwapRequest::new(unsupported, AssetId::Native, 0, 50).is_err());
        assert!(
            SwapRequest::new(native(), AssetId::CurrencyCollection(9), 0, 50).is_err(),
            "an unsendable output is refused too"
        );
    }

    #[test]
    fn the_arrows_step_by_a_tenth_of_a_percent_and_stop_at_the_ends() {
        assert_eq!(step_slippage_bps(DEFAULT_SLIPPAGE_BPS, true), 60);
        assert_eq!(step_slippage_bps(DEFAULT_SLIPPAGE_BPS, false), 40);
        assert_eq!(step_slippage_bps(0, false), 0, "zero is the floor");
        assert_eq!(step_slippage_bps(0, true), SLIPPAGE_STEP_BPS);
        assert_eq!(
            step_slippage_bps(MAX_SLIPPAGE_BPS, true),
            MAX_SLIPPAGE_BPS,
            "ten per cent is the ceiling"
        );
        assert_eq!(step_slippage_bps(MAX_SLIPPAGE_BPS, false), 990);
        assert_eq!(step_slippage_bps(15, true), 20);
        assert_eq!(step_slippage_bps(15, false), 10);
        assert_eq!(step_slippage_bps(57, true), 60);
        assert_eq!(step_slippage_bps(57, false), 50);
        for bps in [0u16, 1, 15, 57, 999, MAX_SLIPPAGE_BPS] {
            for up in [true, false] {
                let landed = step_slippage_bps(bps, up);
                assert!(landed <= MAX_SLIPPAGE_BPS);
                assert_eq!(
                    parse_slippage_percent(&format_slippage_percent(landed)),
                    Some(landed)
                );
            }
        }
    }

    #[test]
    fn a_typed_percentage_reads_as_basis_points() {
        assert_eq!(parse_slippage_percent("0"), Some(0));
        assert_eq!(parse_slippage_percent("0.1"), Some(10));
        assert_eq!(parse_slippage_percent("0.15"), Some(15));
        assert_eq!(parse_slippage_percent("0.57"), Some(57));
        assert_eq!(parse_slippage_percent("0.5"), Some(50));
        assert_eq!(parse_slippage_percent("1"), Some(100));
        assert_eq!(parse_slippage_percent("1.05"), Some(105));
        assert_eq!(parse_slippage_percent("10"), Some(1_000));
        assert_eq!(parse_slippage_percent("10.00"), Some(1_000));
        assert_eq!(parse_slippage_percent(" 0.5 % "), Some(50));
        assert_eq!(parse_slippage_percent(".5"), Some(50));
        assert_eq!(parse_slippage_percent("2."), Some(200));
    }

    #[test]
    fn a_tolerance_past_the_cap_or_finer_than_a_basis_point_is_refused() {
        assert_eq!(parse_slippage_percent("10.01"), None);
        assert_eq!(parse_slippage_percent("11"), None);
        assert_eq!(parse_slippage_percent("50"), None);
        assert_eq!(
            parse_slippage_percent("0.001"),
            None,
            "past one basis point"
        );
        assert_eq!(parse_slippage_percent(""), None);
        assert_eq!(parse_slippage_percent("."), None);
        assert_eq!(parse_slippage_percent("-1"), None);
        assert_eq!(parse_slippage_percent("abc"), None);
        assert_eq!(parse_slippage_percent("0,5"), None);
        assert_eq!(parse_slippage_percent("1e2"), None);
        assert_eq!(
            parse_slippage_percent("99999999999999999999"),
            None,
            "an absurd figure is refused, not wrapped"
        );
    }

    #[test]
    fn a_tolerance_round_trips_through_its_shortest_written_form() {
        for bps in [0u16, 5, 10, 15, 50, 57, 100, 105, 999, 1_000] {
            let written = format_slippage_percent(bps);
            assert_eq!(
                parse_slippage_percent(&written),
                Some(bps),
                "{bps} bps was written as {written:?}"
            );
        }
        assert_eq!(format_slippage_percent(0), "0");
        assert_eq!(format_slippage_percent(10), "0.1");
        assert_eq!(format_slippage_percent(15), "0.15");
        assert_eq!(format_slippage_percent(50), "0.5");
        assert_eq!(format_slippage_percent(100), "1");
        assert_eq!(format_slippage_percent(1_000), "10");
    }

    #[test]
    fn request_rejects_slippage_past_the_cap() {
        let input = AssetAmount::native(UNIT).unwrap();
        assert!(
            SwapRequest::new(
                input,
                AssetId::CurrencyCollection(1),
                0,
                MAX_SLIPPAGE_BPS + 1
            )
            .is_err()
        );
    }
}
