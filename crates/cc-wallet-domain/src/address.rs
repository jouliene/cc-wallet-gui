use tycho_types::models::{StdAddr, StdAddrFormat};

use crate::error::{WalletError, WalletResult};

pub fn canonicalize_recipient(address: &str) -> WalletResult<String> {
    let address = address.trim();
    if address.is_empty() {
        return Err(WalletError::validation("address is empty"));
    }
    let (parsed, _) = StdAddr::from_str_ext(address, StdAddrFormat::any())
        .map_err(|error| WalletError::validation(format!("invalid standard address: {error}")))?;
    if parsed.anycast.is_some() {
        return Err(WalletError::validation(
            "anycast recipient addresses are not supported",
        ));
    }
    if !matches!(parsed.workchain, 0 | -1) {
        return Err(WalletError::validation(
            "recipient workchain must be 0 or -1",
        ));
    }
    Ok(parsed.to_string())
}

pub fn recipient_is_valid(address: &str) -> bool {
    canonicalize_recipient(address).is_ok()
}

pub fn contact_address_is_valid(address: &str) -> bool {
    canonicalize_recipient(address).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn canonical_parser_accepts_raw_and_friendly_forms_identically() {
        let raw = "0:dddde93b1d3398f0b4305c08de9a032e0bc1b257c4ce2c72090aea1ff3e9ecfd";
        let friendly = "UQDd3ek7HTOY8LQwXAjemgMuC8GyV8TOLHIJCuof8-ns_Tyv";
        assert_eq!(canonicalize_recipient(raw).unwrap(), raw);
        assert_eq!(canonicalize_recipient(friendly).unwrap(), raw);
        assert_eq!(
            canonicalize_recipient(&format!("  0:{}  ", HASH64.to_ascii_uppercase())).unwrap(),
            format!("0:{HASH64}")
        );
    }

    #[test]
    fn unsupported_or_out_of_range_workchains_are_rejected() {
        for workchain in ["10", "127", "-5", "300"] {
            assert!(
                canonicalize_recipient(&format!("{workchain}:{HASH64}")).is_err(),
                "workchain {workchain} must be rejected"
            );
        }
        assert!(canonicalize_recipient(&format!("0:{HASH64}")).is_ok());
        assert!(canonicalize_recipient(&format!("-1:{HASH64}")).is_ok());
    }

    #[test]
    fn malformed_shapes_never_reach_the_money_path() {
        for invalid in [
            "",
            "abcdef",
            ":abcdef",
            "0:",
            "0:0123456789abcdef",
            "0:gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
        ] {
            assert!(
                canonicalize_recipient(invalid).is_err(),
                "accepted {invalid:?}"
            );
            assert!(!recipient_is_valid(invalid));
            assert!(!contact_address_is_valid(invalid));
        }
    }
}
