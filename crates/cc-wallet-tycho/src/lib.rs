pub mod ccdex;
pub mod contracts;
pub mod crypto;
pub mod elector;
pub mod emulator;
pub mod everwallet;
pub mod history;
pub mod network;
pub mod subscription;
pub mod transport;

pub use ccdex::{
    Asset as CcdexAsset, CCDEX_POOL_CONTRACT, OP_SWAP, PoolStorage, ccdex_pool_code_hash,
    decode_pool_storage, pool_storage_from_account, swap_body,
};
pub use contracts::{
    ContractAt, ContractSpec, DecodedContract, DecodedField, DecodedValue, contract_for_code_hash,
    contract_name, decode_contract_data, external_method, internal_method,
};
pub use crypto::{
    CryptoError, KeyPair, PublicKeyBytes, SecretKeyBytes, Seed, SignatureBytes, derivation_path,
    public_key_from_bytes, public_key_from_hex, signature_from_bytes, signature_from_hex,
};
pub use elector::{ELECTOR_ADDRESS, ELECTOR_CONTRACT};
pub use emulator::{
    EmulationConfig, MAX_EMULATION_MESSAGE_BOC_BYTES, MAX_SUPPORTED_ORDINARY_GAS_LIMIT,
    emulate_external_message, prepare_emulation_config, shard_account_for_emulation,
    validate_emulation_input_sizes,
};
pub use everwallet::{
    AccountInspection, CLOCK_SKEW_MARGIN_SECS, COMMENT_OP, DEFAULT_SEND_FLAGS, DEFAULT_TTL_SECS,
    DEFAULT_WORKCHAIN, EVER_WALLET_CODE_BOC, EVER_WALLET_CONTRACT, EverTransfer, EverWallet,
    IntoStdAddr, MAX_EVER_EXTRA_CURRENCY_ID, PreparedMessage, WalletState, comment_payload,
    ensure_supported_extra_currency_id as ensure_supported_ever_extra_currency_id,
    ever_wallet_code_hash, make_wallet_state_init, parse_std_addr,
};
pub use history::{
    ChainMessage, ChainTransaction, MAX_TRANSACTION_BOC_BYTES, MsgKind, parse_transaction,
};
pub use network::{CoinSupply, ElectionStake, elector_election_stake, key_block_supply};
pub use subscription::{AccountUpdate, SubscriptionEvent, account_subscription_loop};
pub use transport::{
    AccountState, AccountTimings, BlockchainConfigState, BroadcastAcknowledgement,
    LastTransactionId, LocalReason, MAX_ACCOUNT_STATE_BOC_BYTES, MAX_BLOCKCHAIN_CONFIG_BOC_BYTES,
    MAX_EXTERNAL_MESSAGE_BOC_BYTES, ObservedAccountState, ObservedBlockchainConfigState,
    ObservedNetworkTime, ObservedTransactionsList, RemoteOrTransportReason, ResolvedSendRoute,
    ResponseKind, SendAttemptOutcome, Transport, TransportKind, canonicalize_endpoint,
};

pub use anyhow::Result;
pub use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
pub use tycho_types::models::account::AccountStatus;
pub use tycho_types::models::{BlockchainConfig, SignatureContext, StdAddr};
pub use tycho_types::prelude::{Cell, CellBuilder, HashBytes};

use tycho_types::models::GlobalCapability;

pub fn signature_context_has_id(ctx: &SignatureContext) -> bool {
    ctx.capabilities
        .contains(GlobalCapability::CapSignatureWithId)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn wallet_reached_tycho_values_are_send_sync() {
        assert_send_sync::<Cell>();
        assert_send_sync::<AccountState>();
        assert_send_sync::<BlockchainConfigState>();
        assert_send_sync::<ChainTransaction>();
        assert_send_sync::<EmulationConfig>();
    }
}
