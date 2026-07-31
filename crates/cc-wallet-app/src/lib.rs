pub mod clipboard;
pub mod command;
pub mod controller;
pub mod event;
mod random_ids;
pub mod state;

pub use cc_wallet_chain::{
    AccountInspection, AccountTrace, AccountTx, AccountTxKind, AccountTxPage, CoinSupply,
    DecodedContract, DecodedField, DecodedValue, DestinationAccountStatus, NetworkStats, TraceEdge,
    TraceParty, TraceTx,
};
pub use cc_wallet_domain::{
    ActivityDirection, ActivityEvent, AddressBookEntry, AssetAmount, AssetId, AssetMeta,
    AssetMovement, AssetTone, CcAmount, Digest32, MAX_SLIPPAGE_BPS, SeedPhrase, SendToken,
    WalletSnapshot, all_supported_assets, asset_meta, canonicalize_recipient,
    contact_address_is_valid, fmt_duration, format_base_units, format_fixed9_amount,
    format_native_fixed9, format_slippage_percent, known_cc_assets, parse_send_amount,
};
pub use cc_wallet_storage::{StartupCwd, resolve_startup_cwd};
pub use command::{AppCommand, Password, SeedInput};
pub use controller::AppController;
pub use event::AppEvent;
pub use state::{
    AppPhase, AppState, AppTab, AuthMode, AuthPurpose, LiveStatus, RecipientCheck, SwapFigures,
    SwapReceipt,
};

pub fn seed_phrase_is_valid(phrase: &str) -> bool {
    cc_wallet_chain::validate_seed_phrase(phrase).is_ok()
}

pub fn generate_seed_phrase() -> Result<SeedInput, String> {
    cc_wallet_chain::generate_seed()
        .map(SeedPhrase::into_zeroizing)
        .map(SeedInput::from_zeroizing)
        .map_err(|error| error.to_string())
}

pub fn endpoint_is_valid(endpoint: &str) -> bool {
    canonical_endpoint(endpoint).is_ok()
}

pub fn canonical_endpoint(endpoint: &str) -> Result<String, String> {
    cc_wallet_chain::canonicalize_endpoint(endpoint)
        .map(|url| url.to_string())
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_seed_phrase_yields_twelve_valid_words() {
        let seed = generate_seed_phrase().expect("in-process RNG succeeds");
        let phrase = seed.expose_secret();
        assert_eq!(phrase.split_whitespace().count(), 12);
        assert!(seed_phrase_is_valid(phrase));
    }
}
