use std::collections::BTreeMap;

use anyhow::{Context, Result, anyhow};
use tycho_types::dict::Dict;
use tycho_types::error::Error;
use tycho_types::models::{
    Account, AccountState, BlockchainConfig, ExtraCurrencyCollection, ShardIdent,
};
use tycho_types::num::{Tokens, VarUint248};
use tycho_types::prelude::*;

const MC_STATE_EXTRA_TAG: u16 = 0xcc26;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElectionStake {
    pub election_id: u32,
    pub total_stake: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoinSupply {
    pub total: u128,
    pub extra: Option<BTreeMap<u32, String>>,
    pub seqno: u32,
    pub gen_utime: u32,
}

pub fn elector_election_stake(
    account: &Account,
    election_id: Option<u32>,
) -> Result<ElectionStake> {
    let AccountState::Active(state_init) = &account.state else {
        return Err(anyhow!("the elector account is not active"));
    };
    let data = state_init
        .data
        .as_ref()
        .context("the elector account carries no data")?;
    let mut slice = data.as_slice().context("elector data is not readable")?;

    if slice.load_bit().context("elector data is truncated")? {
        slice
            .load_reference()
            .context("elector current election is missing its cell")?;
    }
    Dict::<HashBytes, Tokens>::load_from(&mut slice).context("elector credits are undecodable")?;
    let past_elections = Dict::<u32, CellSlice>::load_from(&mut slice)
        .context("elector past elections are undecodable")?;
    Tokens::load_from(&mut slice).context("elector balance field is undecodable")?;
    let active_id = slice
        .load_u32()
        .context("elector active election id is missing")?;

    let wanted = election_id.unwrap_or(active_id);
    let mut value = past_elections
        .get(wanted)
        .context("elector past elections are undecodable")?
        .with_context(|| format!("the elector holds no election {wanted}"))?;

    value.load_u32().context("election is truncated")?;
    value.load_u32().context("election is truncated")?;
    value.load_u256().context("election is truncated")?;
    Dict::<HashBytes, CellSlice>::load_from(&mut value)
        .context("election frozen stakes are undecodable")?;
    let total_stake = Tokens::load_from(&mut value).context("election total stake is missing")?;

    Ok(ElectionStake {
        election_id: wanted,
        total_stake: total_stake.into_inner(),
    })
}

pub fn key_block_supply(block: &Cell) -> Result<CoinSupply> {
    let update = block
        .reference(2)
        .and_then(|cell| cell.reference(0))
        .context("key block carries no state update")?;
    let new_state = update
        .reference(1)
        .context("state update carries no new state")?
        .virtualize();

    let (seqno, gen_utime) = state_header(new_state)?;
    let extra = (0..new_state.reference_count())
        .filter_map(|index| new_state.reference(index))
        .find(|cell| {
            !cell.cell_type().is_pruned_branch()
                && cell.bit_len() >= 16
                && cell
                    .data()
                    .first_chunk::<2>()
                    .map(|tag| u16::from_be_bytes(*tag))
                    == Some(MC_STATE_EXTRA_TAG)
        })
        .context("the key block state keeps no masterchain extra to read the supply from")?;

    let (total, extra) = global_balance(extra)?;

    Ok(CoinSupply {
        total,
        extra,
        seqno,
        gen_utime,
    })
}

fn state_header(state: &DynCell) -> Result<(u32, u32)> {
    let mut header = state
        .as_slice()
        .context("key block state is not readable")?;
    header.load_u32().context("state is truncated")?;
    header.load_u32().context("state is truncated")?;
    ShardIdent::load_from(&mut header).context("state shard is undecodable")?;
    let seqno = header.load_u32().context("state seqno is missing")?;
    header.load_u32().context("state is truncated")?;
    let gen_utime = header.load_u32().context("state gen_utime is missing")?;
    Ok((seqno, gen_utime))
}

fn global_balance(extra: &DynCell) -> Result<(u128, Option<BTreeMap<u32, String>>)> {
    let mut slice = extra
        .as_slice()
        .context("masterchain state extra is not readable")?;
    slice.load_u16().context("state extra is truncated")?;
    if slice.load_bit().context("state extra is truncated")? {
        slice
            .load_reference()
            .context("shard hashes are missing their cell")?;
    }
    slice.load_u256().context("config address is missing")?;
    slice
        .load_reference()
        .context("config params are missing their cell")?;
    slice
        .load_reference()
        .context("state extra block info is missing")?;

    let total = Tokens::load_from(&mut slice).context("global balance is undecodable")?;
    let other = ExtraCurrencyCollection::load_from(&mut slice)
        .context("global extra balance is undecodable")?;
    Ok((
        total.into_inner(),
        extra_currency_supply_unless_pruned(&other)?,
    ))
}

fn extra_currency_supply_unless_pruned(
    collection: &ExtraCurrencyCollection,
) -> Result<Option<BTreeMap<u32, String>>> {
    let dict: &Dict<u32, VarUint248> = collection.as_dict();
    let mut supply = BTreeMap::new();
    for entry in dict.iter() {
        match entry {
            Ok((id, amount)) => {
                supply.insert(id, amount.to_string());
            }
            Err(Error::UnexpectedExoticCell) => return Ok(None),
            Err(error) => {
                return Err(error).context("an extra-currency supply entry is undecodable");
            }
        }
    }
    Ok(Some(supply))
}

/// The least a bounceable message may carry for the account it arrives at to
/// run any code at all.
///
/// A bounceable message is not credited to the account before the compute
/// phase, so the receiving side buys its gas out of what the message brought
/// and nothing else. The network sells the first `flat_gas_limit` units for a
/// flat price, and that price is indivisible: a message that cannot cover it
/// buys no gas, the compute phase is skipped as `NoGas`, and what happens next
/// depends on whether the leftovers can even pay for the bounce back.
///
/// This is arithmetic from the network's own config, not a policy — below it
/// nothing can execute, on any account, in any contract.
pub fn min_bounceable_attach(config: &BlockchainConfig, workchain: i8) -> Result<u128> {
    let prices = config
        .get_gas_prices(workchain == -1)
        .context("blockchain config lacks gas prices for the recipient's workchain")?;
    Ok(u128::from(prices.flat_gas_price))
}

#[cfg(test)]
mod tests {
    use tycho_types::merkle::make_pruned_branch;
    use tycho_types::models::GasLimitsPrices;

    use super::*;

    /// The prices this network actually charges, read off the live testnet
    /// config on 2026-08-10. A transfer of 0.0001 COIN to a masterchain wallet
    /// was skipped as `NoGas` against exactly these numbers.
    fn measured_config() -> BlockchainConfig {
        let mut config = BlockchainConfig::new_empty(HashBytes([0x55; 32]));
        let prices = |gas_price: u64, flat_gas_price: u64| GasLimitsPrices {
            gas_price,
            gas_limit: 1_000_000,
            special_gas_limit: 100_000_000,
            gas_credit: 10_000,
            block_gas_limit: 11_000_000,
            freeze_due_limit: 100_000_000,
            delete_due_limit: 1_000_000_000,
            flat_gas_limit: 1_000,
            flat_gas_price,
        };
        config
            .set_gas_prices(true, &prices(655_360_000, 10_000_000))
            .unwrap();
        config
            .set_gas_prices(false, &prices(65_536_000, 1_000_000))
            .unwrap();
        config
    }

    #[test]
    fn the_floor_is_the_flat_gas_price_of_the_recipients_own_workchain() {
        let config = measured_config();
        assert_eq!(min_bounceable_attach(&config, 0).unwrap(), 1_000_000);
        assert_eq!(min_bounceable_attach(&config, -1).unwrap(), 10_000_000);
    }

    #[test]
    fn a_config_without_gas_prices_refuses_to_invent_a_floor() {
        let empty = BlockchainConfig::new_empty(HashBytes([0x55; 32]));
        assert!(min_bounceable_attach(&empty, 0).is_err());
    }

    fn frozen_validator(stake: u128) -> Cell {
        let mut builder = CellBuilder::new();
        builder.store_u256(&HashBytes([7; 32])).unwrap();
        builder.store_u64(1).unwrap();
        Tokens::new(stake)
            .store_into(&mut builder, Cell::empty_context())
            .unwrap();
        builder.build().unwrap()
    }

    fn elector_data(active_id: u32, total_stake: u128, validators: u8) -> Cell {
        let mut frozen = Dict::<HashBytes, CellSlice>::new();
        let stakes: Vec<Cell> = (0..validators).map(|_| frozen_validator(1_000)).collect();
        for (index, stake) in stakes.iter().enumerate() {
            frozen
                .set(HashBytes([index as u8; 32]), stake.as_slice().unwrap())
                .unwrap();
        }

        let mut election = CellBuilder::new();
        election.store_u32(0).unwrap();
        election.store_u32(0).unwrap();
        election.store_u256(&HashBytes([9; 32])).unwrap();
        frozen
            .store_into(&mut election, Cell::empty_context())
            .unwrap();
        Tokens::new(total_stake)
            .store_into(&mut election, Cell::empty_context())
            .unwrap();
        Tokens::new(5)
            .store_into(&mut election, Cell::empty_context())
            .unwrap();

        let election = election.build().unwrap();
        let mut past = Dict::<u32, CellSlice>::new();
        past.set(active_id, election.as_slice().unwrap()).unwrap();

        let mut data = CellBuilder::new();
        data.store_bit_zero().unwrap();
        Dict::<HashBytes, Tokens>::new()
            .store_into(&mut data, Cell::empty_context())
            .unwrap();
        past.store_into(&mut data, Cell::empty_context()).unwrap();
        Tokens::new(69)
            .store_into(&mut data, Cell::empty_context())
            .unwrap();
        data.store_u32(active_id).unwrap();
        data.store_u256(&HashBytes([3; 32])).unwrap();
        data.build().unwrap()
    }

    fn elector_account(data: Cell) -> Account {
        Account {
            address: tycho_types::models::StdAddr::new(-1, HashBytes([0x33; 32])).into(),
            storage_stat: Default::default(),
            last_trans_lt: 0,
            balance: Default::default(),
            state: AccountState::Active(tycho_types::models::StateInit {
                split_depth: None,
                special: None,
                code: None,
                data: Some(data),
                libraries: Dict::new(),
            }),
        }
    }

    #[test]
    fn the_active_election_reports_its_frozen_stake_and_validator_count() {
        let account = elector_account(elector_data(1_784_777_441, 9_532_221_000_000_000, 17));

        let active = elector_election_stake(&account, None).unwrap();
        assert_eq!(active.election_id, 1_784_777_441);
        assert_eq!(active.total_stake, 9_532_221_000_000_000);

        let by_id = elector_election_stake(&account, Some(1_784_777_441)).unwrap();
        assert_eq!(
            by_id, active,
            "asking for the active id reads the same round"
        );
    }

    #[test]
    fn a_round_the_elector_never_held_is_an_error_not_a_zero_stake() {
        let account = elector_account(elector_data(100, 5_000, 3));
        let error = elector_election_stake(&account, Some(101)).unwrap_err();
        assert!(error.to_string().contains("no election 101"), "{error}");
    }

    #[test]
    fn an_elector_that_is_not_active_is_refused() {
        let mut account = elector_account(elector_data(1, 1, 1));
        account.state = AccountState::Uninit;
        let error = elector_election_stake(&account, None).unwrap_err();
        assert!(error.to_string().contains("not active"), "{error}");
    }

    fn state_extra(total: u128, extra: &[(u32, u128)]) -> Cell {
        let mut currencies = Dict::<u32, VarUint248>::new();
        for (id, amount) in extra {
            currencies.set(*id, VarUint248::new(*amount)).unwrap();
        }
        state_extra_with_currencies(total, currencies)
    }

    fn state_extra_with_currencies(total: u128, currencies: Dict<u32, VarUint248>) -> Cell {
        let mut builder = CellBuilder::new();
        builder.store_u16(MC_STATE_EXTRA_TAG).unwrap();
        builder.store_bit_zero().unwrap();
        builder.store_u256(&HashBytes([0x55; 32])).unwrap();
        builder.store_reference(Cell::empty_cell()).unwrap();
        builder.store_reference(Cell::empty_cell()).unwrap();
        Tokens::new(total)
            .store_into(&mut builder, Cell::empty_context())
            .unwrap();
        currencies
            .store_into(&mut builder, Cell::empty_context())
            .unwrap();
        builder.build().unwrap()
    }

    #[test]
    fn the_global_balance_is_the_native_supply_and_every_currency_supply() {
        let extra = state_extra(7_074_806_721_778_674_964, &[(1, 21_000_000), (7, 5)]);
        let (total, currencies) = global_balance(extra.as_ref()).unwrap();
        let currencies = currencies.unwrap();

        assert_eq!(total, 7_074_806_721_778_674_964);
        assert_eq!(currencies.get(&1).map(String::as_str), Some("21000000"));
        assert_eq!(currencies.get(&7).map(String::as_str), Some("5"));
    }

    #[test]
    fn a_chain_with_no_extra_currencies_reports_only_the_native_supply() {
        let (total, currencies) = global_balance(state_extra(42, &[]).as_ref()).unwrap();
        assert_eq!(total, 42);
        assert!(currencies.unwrap().is_empty());
    }

    #[test]
    fn a_key_block_that_pruned_its_currency_dict_still_gives_up_the_native_supply() {
        let mut currencies = Dict::<u32, VarUint248>::new();
        currencies.set(264, VarUint248::new(2_100_000)).unwrap();
        let pruned = make_pruned_branch(
            currencies.root().as_ref().unwrap().as_ref(),
            0,
            Cell::empty_context(),
        )
        .unwrap();
        let extra =
            state_extra_with_currencies(7_078_140_775_678_674_964, Dict::from_raw(Some(pruned)));

        let (total, currencies) = global_balance(extra.as_ref()).unwrap();
        assert_eq!(
            total, 7_078_140_775_678_674_964,
            "the native supply is in the proof and must survive a pruned currency dict"
        );
        assert!(
            currencies.is_none(),
            "a pruned dict is unknown, not an empty set of extra currencies"
        );

        let mut state = CellBuilder::new();
        state.store_u32(0).unwrap();
        state.store_u32(0).unwrap();
        ShardIdent::MASTERCHAIN
            .store_into(&mut state, Cell::empty_context())
            .unwrap();
        state.store_u32(24_415_514).unwrap();
        state.store_u32(0).unwrap();
        state.store_u32(1_786_088_161).unwrap();
        state.store_reference(extra).unwrap();
        let state = state.build().unwrap();

        let mut update = CellBuilder::new();
        update.store_reference(Cell::empty_cell()).unwrap();
        update.store_reference(state).unwrap();
        let mut wrapper = CellBuilder::new();
        wrapper.store_reference(update.build().unwrap()).unwrap();

        let mut block = CellBuilder::new();
        block.store_reference(Cell::empty_cell()).unwrap();
        block.store_reference(Cell::empty_cell()).unwrap();
        block.store_reference(wrapper.build().unwrap()).unwrap();

        let supply = key_block_supply(&block.build().unwrap()).unwrap();
        assert_eq!(supply.total, 7_078_140_775_678_674_964);
        assert_eq!(supply.seqno, 24_415_514);
        assert_eq!(supply.gen_utime, 1_786_088_161);
        assert!(supply.extra.is_none());
    }

    #[test]
    fn a_currency_dict_that_is_broken_rather_than_pruned_is_still_refused() {
        let mut broken = CellBuilder::new();
        broken.store_bit_one().unwrap();
        let extra = state_extra_with_currencies(1, Dict::from_raw(Some(broken.build().unwrap())));

        let error = global_balance(extra.as_ref()).unwrap_err();
        assert!(
            error.to_string().contains("extra-currency supply entry"),
            "an undecodable entry is not quietly read as an unknown one: {error}"
        );
    }

    #[test]
    fn a_cell_that_is_not_a_state_extra_is_refused_rather_than_read_as_a_supply() {
        let mut builder = CellBuilder::new();
        builder.store_u16(0xdead).unwrap();
        let error = global_balance(builder.build().unwrap().as_ref()).unwrap_err();
        assert!(
            error.to_string().contains("state extra"),
            "a mis-shaped cell must fail loudly, not read as a supply: {error}"
        );
    }

    #[test]
    fn a_state_header_reports_the_block_it_was_generated_for() {
        let mut builder = CellBuilder::new();
        builder.store_u32(0x9023aeee).unwrap();
        builder.store_u32(2000).unwrap();
        ShardIdent::MASTERCHAIN
            .store_into(&mut builder, Cell::empty_context())
            .unwrap();
        builder.store_u32(23_197_707).unwrap();
        builder.store_u32(0).unwrap();
        builder.store_u32(1_784_777_441).unwrap();

        let (seqno, gen_utime) = state_header(builder.build().unwrap().as_ref()).unwrap();
        assert_eq!(seqno, 23_197_707);
        assert_eq!(gen_utime, 1_784_777_441);
    }
}
