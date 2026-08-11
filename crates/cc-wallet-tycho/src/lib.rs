mod ccdex;
mod contracts;
mod crypto;
mod elector;
mod emulator;
mod encrypted_comment;
mod everwallet;
mod history;
mod network;
mod storage;
mod subscription;
mod transport;

pub use ccdex::{Asset as CcdexAsset, pool_storage_from_account, swap_body};
pub use contracts::{
    ContractAt, DecodedContract, DecodedField, DecodedValue, contract_name, external_method,
    internal_method,
};
pub use crypto::{KeyPair, Seed};
pub use elector::ELECTOR_ADDRESS;
pub use emulator::{
    EmulationConfig, emulate_external_message, prepare_emulation_config,
    shard_account_for_emulation, validate_emulation_input_sizes,
};
pub use encrypted_comment::{
    ENCRYPTED_COMMENT_OP, MAX_ENCRYPTED_COMMENT_BYTES, comment_aad, encrypted_comment_payload,
    parse_encrypted_comment,
};
pub use everwallet::{
    AccountInspection, CLOCK_SKEW_MARGIN_SECS, DEFAULT_TTL_SECS, DEFAULT_WORKCHAIN,
    EVER_WALLET_CONTRACT, EverTransfer, EverWallet, MAX_COMMENT_BYTES, WalletState,
    comment_payload, ever_wallet_code_hash, read_comment,
};
pub use history::{BounceOutcome, ChainMessage, ChainTransaction, MsgKind, parse_transaction};
pub use network::{CoinSupply, elector_election_stake, key_block_supply};
pub use storage::{
    MAX_BLOB_BYTES as MAX_STORAGE_BLOB_BYTES, MAX_RECORDS as MAX_STORAGE_RECORDS, STORAGE_CONTRACT,
    TARGET_BALANCE as STORAGE_TARGET_BALANCE, delete_body as storage_delete_body,
    put_body as storage_put_body, storage_address, storage_code_hash, storage_error_text,
    storage_from_account,
};
pub use subscription::{AccountUpdate, SubscriptionEvent, account_subscription_loop};
pub use transport::{
    AccountState, AccountTimings, BlockchainConfigState, BroadcastAcknowledgement, LocalReason,
    ObservedAccountState, ObservedNetworkTime, ResolvedSendRoute, ResponseKind, SendAttemptOutcome,
    Transport, canonicalize_endpoint,
};

pub use anyhow::Result;
pub use tycho_types::models::ComputePhaseSkipReason;
pub use tycho_types::models::StdAddr;
pub use tycho_types::models::account::AccountStatus;
pub use tycho_types::prelude::{Cell, CellBuilder};

use tycho_types::models::{GlobalCapability, SignatureContext};

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
