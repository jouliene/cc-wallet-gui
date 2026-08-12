use anyhow::{Context, Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use tycho_executor::{Executor, ExecutorParams, ParsedConfig, TxError};
use tycho_types::cell::Lazy;
use tycho_types::models::{
    Account, AccountState as CoreAccountState, BlockchainConfig, CurrencyCollection,
    GlobalCapability, OptionalAccount, ShardAccount, StdAddr, StorageInfo,
};
use tycho_types::num::Tokens;
use tycho_types::prelude::*;

use crate::history::{ChainTransaction, parse_transaction_cell};
use crate::transport::{
    AccountState, BlockchainConfigState, MAX_ACCOUNT_STATE_BOC_BYTES,
    MAX_BLOCKCHAIN_CONFIG_BOC_BYTES,
};

const EMULATION_MAX_LT: u64 = 1 << 60;

pub const MAX_SUPPORTED_ORDINARY_GAS_LIMIT: u64 = 1_000_000;

pub const MAX_EMULATION_MESSAGE_BOC_BYTES: usize = 64 * 1024;

pub fn validate_emulation_input_sizes(
    config: &BlockchainConfigState,
    state: &AccountState,
    message: &Cell,
) -> Result<()> {
    fn ensure_decoded_size(value: &str, max: usize, label: &str) -> Result<()> {
        let max_encoded = max.saturating_mul(4).div_ceil(3) + 4;
        if value.len() > max_encoded {
            anyhow::bail!("{label} BOC exceeds {max} decoded bytes");
        }
        let bytes = BASE64
            .decode(value)
            .with_context(|| format!("{label} is not canonical base64"))?;
        if bytes.len() > max {
            anyhow::bail!("{label} BOC exceeds {max} decoded bytes");
        }
        Ok(())
    }
    ensure_decoded_size(
        &config.config_boc_base64,
        MAX_BLOCKCHAIN_CONFIG_BOC_BYTES,
        "blockchain-config",
    )?;
    if let AccountState::Exists {
        account_boc_base64, ..
    } = state
    {
        ensure_decoded_size(
            account_boc_base64,
            MAX_ACCOUNT_STATE_BOC_BYTES,
            "account-state",
        )?;
    }
    let message_size = tycho_types::boc::Boc::encode(message).len();
    if message_size > MAX_EMULATION_MESSAGE_BOC_BYTES {
        anyhow::bail!(
            "external-message BOC is {message_size} bytes, above the {MAX_EMULATION_MESSAGE_BOC_BYTES}-byte emulation ceiling"
        );
    }
    Ok(())
}

pub struct EmulationConfig {
    parsed: ParsedConfig,
    full_body_in_bounced: bool,
    authority_marks_enabled: bool,
    signature_with_id: Option<i32>,
    enable_signature_domains: bool,
}

pub fn prepare_emulation_config(config: &BlockchainConfig, now: u32) -> Result<EmulationConfig> {
    for (masterchain, label) in [(false, "base workchain"), (true, "masterchain")] {
        let prices = config
            .get_gas_prices(masterchain)
            .with_context(|| format!("blockchain config lacks {label} gas prices"))?;
        if prices.gas_limit == 0 || prices.gas_limit > MAX_SUPPORTED_ORDINARY_GAS_LIMIT {
            anyhow::bail!(
                "{label} ordinary-account gas_limit {} is outside the supported 1..={MAX_SUPPORTED_ORDINARY_GAS_LIMIT} range",
                prices.gas_limit
            );
        }
    }
    let capabilities = config
        .get_global_version()
        .context("blockchain config lacks a global version (param 8)")?
        .capabilities;
    let signature_with_id = capabilities
        .contains(GlobalCapability::CapSignatureWithId)
        .then(|| config.get_global_id())
        .transpose()
        .context("blockchain config lacks a global id (param 19)")?;
    let parsed = ParsedConfig::parse(config.clone(), now)
        .context("failed to parse blockchain config for emulation")?;
    Ok(EmulationConfig {
        parsed,
        full_body_in_bounced: capabilities.contains(GlobalCapability::CapFullBodyInBounced),
        authority_marks_enabled: capabilities.contains(GlobalCapability::CapSuspendByMarks),
        signature_with_id,
        enable_signature_domains: capabilities.contains(GlobalCapability::CapSignatureDomain),
    })
}

pub fn shard_account_for_emulation(
    address: &StdAddr,
    state: &AccountState,
    min_native_balance: u128,
) -> Result<ShardAccount> {
    match state {
        AccountState::Exists {
            account,
            last_transaction_id,
            ..
        } => {
            let mut account = account.clone();
            if account.balance.tokens.into_inner() < min_native_balance {
                account.balance.tokens = Tokens::new(min_native_balance);
            }
            account.last_trans_lt = account.last_trans_lt.min(EMULATION_MAX_LT);
            let (last_trans_hash, last_trans_lt) = match last_transaction_id {
                Some(id) => (
                    id.hash
                        .parse::<HashBytes>()
                        .context("invalid last transaction hash")?,
                    id.lt.min(EMULATION_MAX_LT),
                ),
                None => (HashBytes::ZERO, 0),
            };
            Ok(ShardAccount {
                account: Lazy::new(&OptionalAccount(Some(account)))?,
                last_trans_hash,
                last_trans_lt,
            })
        }
        AccountState::NotExists { .. } => Ok(ShardAccount {
            account: Lazy::new(&OptionalAccount(Some(Account {
                address: address.clone().into(),
                storage_stat: StorageInfo::default(),
                last_trans_lt: 0,
                balance: CurrencyCollection::new(min_native_balance),
                state: CoreAccountState::Uninit,
            })))?,
            last_trans_hash: HashBytes::ZERO,
            last_trans_lt: 0,
        }),
        AccountState::Unchanged { .. } => Err(anyhow!(
            "account state is Unchanged; fetch it without a last-transaction filter"
        )),
    }
}

pub fn emulate_external_message(
    config: &EmulationConfig,
    address: &StdAddr,
    shard_account: &ShardAccount,
    message: &Cell,
    block_unixtime: u32,
) -> Result<ChainTransaction> {
    let message_size = tycho_types::boc::Boc::encode(message).len();
    if message_size > MAX_EMULATION_MESSAGE_BOC_BYTES {
        anyhow::bail!(
            "external-message BOC is {message_size} bytes, above the {MAX_EMULATION_MESSAGE_BOC_BYTES}-byte emulation ceiling"
        );
    }
    let params = ExecutorParams {
        block_unixtime,
        disable_delete_frozen_accounts: true,
        charge_action_fees_on_fail: true,
        strict_extra_currency: true,
        full_body_in_bounced: config.full_body_in_bounced,
        authority_marks_enabled: config.authority_marks_enabled,
        vm_modifiers: tycho_vm::BehaviourModifiers {
            chksig_always_succeed: true,
            signature_with_id: config.signature_with_id,
            enable_signature_domains: config.enable_signature_domains,
            ..Default::default()
        },
        ..Default::default()
    };

    let uncommitted = Executor::new(&params, &config.parsed)
        .override_special(false)
        .with_min_lt(shard_account.last_trans_lt)
        .begin_ordinary(address, true, message.clone(), shard_account)
        .map_err(|error| match error {
            TxError::Skipped => {
                anyhow!("the executor skipped the message (unpayable import or not accepted)")
            }
            TxError::Fatal(error) => error.context("emulation failed"),
        })?;
    let tx = uncommitted
        .build_uncommitted()
        .map_err(|error| anyhow!("failed to build the emulated transaction: {error}"))?;

    parse_transaction_cell(
        &CellBuilder::build_from(&tx).context("failed to encode the emulated transaction")?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;
    use crate::everwallet::{EverTransfer, EverWallet, make_wallet_state_init};
    use crate::transport::AccountTimings;
    use tycho_types::dict::Dict;
    use tycho_types::models::SignatureContext;
    use tycho_types::models::{GasLimitsPrices, GlobalVersion, MsgForwardPrices, StoragePrices};

    const NOW: u32 = 1_700_000_000;

    fn deterministic_config() -> BlockchainConfig {
        let mut config = BlockchainConfig::new_empty(HashBytes([0x55; 32]));
        config
            .set_global_version(&GlobalVersion::default())
            .unwrap();
        config.set_global_id(0).unwrap();
        config.set_workchains(&Dict::new()).unwrap();
        config.set_fundamental_addresses(&[]).unwrap();
        config
            .set_storage_prices(&[StoragePrices {
                utime_since: 0,
                bit_price_ps: 1,
                cell_price_ps: 500,
                mc_bit_price_ps: 1_000,
                mc_cell_price_ps: 500_000,
            }])
            .unwrap();
        config
            .set_gas_prices(
                true,
                &GasLimitsPrices {
                    gas_price: 655_360_000,
                    gas_limit: 1_000_000,
                    special_gas_limit: 100_000_000,
                    gas_credit: 10_000,
                    block_gas_limit: 11_000_000,
                    freeze_due_limit: 100_000_000,
                    delete_due_limit: 1_000_000_000,
                    flat_gas_limit: 1_000,
                    flat_gas_price: 10_000_000,
                },
            )
            .unwrap();
        config
            .set_gas_prices(
                false,
                &GasLimitsPrices {
                    gas_price: 65_536_000,
                    gas_limit: 1_000_000,
                    special_gas_limit: 1_000_000,
                    gas_credit: 10_000,
                    block_gas_limit: 10_000_000,
                    freeze_due_limit: 100_000_000,
                    delete_due_limit: 1_000_000_000,
                    flat_gas_limit: 1_000,
                    flat_gas_price: 1_000_000,
                },
            )
            .unwrap();
        config
            .set_msg_forward_prices(
                true,
                &MsgForwardPrices {
                    lump_price: 10_000_000,
                    bit_price: 655_360_000,
                    cell_price: 65_536_000_000,
                    ihr_price_factor: 98_304,
                    first_frac: 21_845,
                    next_frac: 21_845,
                },
            )
            .unwrap();
        config
            .set_msg_forward_prices(
                false,
                &MsgForwardPrices {
                    lump_price: 1_000_000,
                    bit_price: 65_536_000,
                    cell_price: 6_553_600_000,
                    ihr_price_factor: 98_304,
                    first_frac: 21_845,
                    next_frac: 21_845,
                },
            )
            .unwrap();
        config
    }

    fn active_wallet_state(wallet: &EverWallet) -> AccountState {
        AccountState::Exists {
            account: Account {
                address: wallet.address().clone().into(),
                storage_stat: StorageInfo::default(),
                last_trans_lt: 7,
                balance: CurrencyCollection::new(10_000_000_000),
                state: CoreAccountState::Active(
                    make_wallet_state_init(wallet.keys().public_key()).unwrap(),
                ),
            },
            account_boc_base64: String::new(),
            last_transaction_id: None,
            timings: AccountTimings {
                gen_lt: 7,
                gen_utime: NOW,
            },
        }
    }

    #[test]
    fn shard_account_override_is_deterministic_and_clamps_hostile_lt() {
        let address = StdAddr::new(0, HashBytes([0x11; 32]));
        let state = AccountState::NotExists { timings: None };
        let first = shard_account_for_emulation(&address, &state, 5_000_000_000).unwrap();
        let second = shard_account_for_emulation(&address, &state, 5_000_000_000).unwrap();

        assert_eq!(first.last_trans_lt, 0);
        assert_eq!(first.last_trans_hash, HashBytes::ZERO);
        assert_eq!(
            first.account.inner().repr_hash(),
            second.account.inner().repr_hash()
        );
    }

    #[test]
    fn hostile_gas_limit_is_rejected_before_executor_construction() {
        let mut config = deterministic_config();
        let mut prices = config.get_gas_prices(false).unwrap();
        prices.gas_limit = MAX_SUPPORTED_ORDINARY_GAS_LIMIT + 1;
        config.set_gas_prices(false, &prices).unwrap();
        let error = prepare_emulation_config(&config, NOW).err().unwrap();
        assert!(error.to_string().contains("gas_limit"));

        let accepted = prepare_emulation_config(&deterministic_config(), NOW).unwrap();
        let _ = accepted;
    }

    #[test]
    fn oversized_executor_inputs_are_rejected_before_spawn() {
        let config = deterministic_config();
        let state = BlockchainConfigState {
            global_id: 0,
            seqno: 1,
            config_boc_base64: tycho_types::boc::BocRepr::encode_base64(&config).unwrap(),
            config,
        };
        let account = AccountState::NotExists { timings: None };
        let message = CellBuilder::build_from(0u8).unwrap();
        validate_emulation_input_sizes(&state, &account, &message).unwrap();

        let mut oversized_config = state.clone();
        oversized_config.config_boc_base64 =
            BASE64.encode(vec![0u8; MAX_BLOCKCHAIN_CONFIG_BOC_BYTES + 1]);
        assert!(
            validate_emulation_input_sizes(&oversized_config, &account, &message)
                .unwrap_err()
                .to_string()
                .contains("blockchain-config BOC exceeds")
        );

        oversized_config.config_boc_base64 = "A".repeat(
            MAX_BLOCKCHAIN_CONFIG_BOC_BYTES
                .saturating_mul(4)
                .div_ceil(3)
                + 5,
        );
        assert!(
            validate_emulation_input_sizes(&oversized_config, &account, &message)
                .unwrap_err()
                .to_string()
                .contains("blockchain-config BOC exceeds")
        );

        let wallet = EverWallet::new(KeyPair::from_secret_bytes([7; 32])).unwrap();
        let mut oversized_account = active_wallet_state(&wallet);
        let AccountState::Exists {
            account_boc_base64, ..
        } = &mut oversized_account
        else {
            unreachable!();
        };
        *account_boc_base64 = BASE64.encode(vec![0u8; MAX_ACCOUNT_STATE_BOC_BYTES + 1]);
        assert!(
            validate_emulation_input_sizes(&state, &oversized_account, &message)
                .unwrap_err()
                .to_string()
                .contains("account-state BOC exceeds")
        );
    }

    fn emulate_transfer(transfer: EverTransfer) -> ChainTransaction {
        let keys = KeyPair::from_secret_bytes([7; 32]);
        let wallet = EverWallet::new(keys).unwrap();
        let prepared = wallet
            .prepare_send_currency_at(
                &transfer,
                SignatureContext::empty(),
                false,
                u64::from(NOW) * 1_000,
                60,
            )
            .unwrap();
        let state = active_wallet_state(&wallet);
        let shard = shard_account_for_emulation(wallet.address(), &state, 5_000_000_000).unwrap();
        let config = prepare_emulation_config(&deterministic_config(), NOW).unwrap();
        emulate_external_message(
            &config,
            wallet.address(),
            &shard,
            &prepared.message,
            NOW + 5,
        )
        .unwrap()
    }

    #[test]
    fn offline_native_and_cc_fee_emulation_have_stable_vectors() {
        let destination = StdAddr::new(0, HashBytes([0x22; 32]));
        let native = emulate_transfer(
            EverTransfer::new(&destination)
                .unwrap()
                .native(100_000_000)
                .unwrap(),
        );
        let mut cc_bytes = [0u8; 31];
        cc_bytes[15..].copy_from_slice(&123_456_789u128.to_be_bytes());
        let cc = emulate_transfer(
            EverTransfer::new(destination)
                .unwrap()
                .native(50_000_000)
                .unwrap()
                .cc_be_bytes(7, cc_bytes)
                .unwrap(),
        );

        assert!(native.compute_success && cc.compute_success);
        assert_eq!(native.action_success, Some(true));
        assert_eq!(cc.action_success, Some(true));
        assert!(!native.aborted && !cc.aborted);
        assert_eq!(native.total_fees_native, 6_483_000);
        assert_eq!(cc.total_fees_native, 6_660_000);
    }
}
