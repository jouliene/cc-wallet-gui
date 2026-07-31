use std::collections::BTreeMap;

use anyhow::{Context, Result};
use std::sync::LazyLock;
use tycho_types::models::{ExtraCurrencyCollection, StdAddr};
use tycho_types::num::{Tokens, VarUint248};
use tycho_types::prelude::*;

use crate::contracts::{ContractSpec, DecodedContract, DecodedField};
use crate::transport::AccountState;

pub const CCDEX_POOL_CONTRACT: &str = "CC-DEX Pool";

pub const CCDEX_POOL_CODE_BOC: &str = "te6ccgECLgEACBgAART/APSkE/S88sgLAQIBYgIDAgLMBAUCAUglJgIBIAYHAgFIISICASAICQIBIBscAgEgCgsCASAZGgONPiRkvAJ4FMA10nBIJFb4NMf0z/tRND6SNMP0gD6APQE0SeCEMzeAAG64wI2JoIQzN4AArrjD8j6UssPE8oAAfoC9ADJ7VSAMDQ4ADwBk/LQaeAwgAf43N/iS+Jf4mCPy0GYG0gDTH/oE0gDTH/oE0x/6UNFTdvABU0PwAVN0upVTY7rDAJFw4vLQa/gjWLvy4G8kwgDy4GwM8AVbIsED8uBoKI4QW/LQcCOCCYy6gKAXvvLgcI4SOQHAAfLgcCW68uBwUWO68uBw4lR5h1YQVhBTmPACDwCaNjb4kiLHBfLgZfiX+JgE+gDRBPAFJMED8uBoUoa78uBwUJegIsIAjhEQVhBFEElHEwjwBkdlECQQI5I4MOLCAZhGUEQw8AZANJIwMuICHCaCEMzeAAO64w8QNEAzERIB+FR6mFYRVhFTdvACIcIA8uBqIMIA8uBqVHEELfAEIMIA8uBtUgm+8uBuU3C58uBxURSgEGsQWhBJED8rED9Au/ADUYWhEEUQNEEwVCjQUtDwAyTI+lI1UjXLDzNSE8oAMSH6AjFSEPQAMcntVCRuQBXjBG1wUgWRMJE14gcQAKKSMjSOGCWDHr6UBYMfoZEF4shY+gZAFoAg9EIEA+L4LFigUAOhIML/k3T7ApWjgAz7AuLIz4WIEvpSz4QgEvQAghDM3gABzwuJyz/JgQCQ+wAB/jb4kiPHBfLgZfiXBNIA0x/6BNMAAZnSANMf+gSBAIaWbW1tWANw4gHRcG0hEIwQexBqEF8QTlQTCVE9A00d8AcKjiZReLqVUZy6wwCSOXDi8tB0EEoQOUh2RRQQO1nwBxBYXiQQNUFEA5oQTRA8ECpQh18F4gTBA/LgaPgnbxATA+43JYIQzN4ABLqPaCWCEMzeAAW6jtslghDM3gAGuo5NNfiSIscFbBLy4GX4kgL6SNH4LCDC/5N0+wKVo4AM+wLiyM+FCBP6Uo0GgAAAAAAAAAAAAAAAAABmbwACAAAAAAAAAABAzxbJgQCC+wDjDlAz4w0T4w1EBBQVFgCAUAahIaEmghA7msoAoL7y4HL4LKIgwv+TdPsClaOADPsC4gbIzsnIz4WIUkD6Us+EIBf0AHHPC2kWzMmBAJD7AAL+BYIQzN4AB7qT8sBk4fiSIscF8uBl+JcD0gDTH9MAAZfSANMfgQCHlG1tWHDiAdFTQ/AB+CdvIgmhcG1TGVE6UT8DVhEDVhBRPVE9UToDVhMD8AgEkzpsQ+MNJcIAkX+VIsIAwwDi8uBzAsED8uBoJKEnghA7msoAoL7y4HL4LBcYAJgwNPiSIccF8uBl+JIC0gDR+Cwgwv+TdPsClaOADPsC4sjPhQgT+lKNBoAAAAAAAAAAAAAAAAAAZm8AAgAAAAAAAAAAQM8WyYEAgvsAAKgxNPiSIccF8uBl+JIC0w/RIIED6Lvy4Gf4LCDC/5N0+wKVo4AM+wLiyM+FCBP6Uo0GgAAAAAAAAAAAAAAAAABmbwACAAAAAAAAAABAzxbJgQCC+wAAUFNU8AFRdbqVUVO6wwCSNXDi8tB0J1FnUWxRblFtRUYiBBA+AfAIUFIAiFAEoSDC/5N0+wKVo4AM+wLiyM+FiFIg+lLPhCAT9ACNBkAAAAAAAAAAAAAAAAAMzeAAcAAAAAAAAAAIzxbJgQCQ+wABADENDQ0ApIwMeAxAYAg9A5voZP6BNGSMHDigADcApIwMuAhwgCZyFj6BgKAIPRDlzEBgCD0WzDigAgEgHR4CASAfIAAvIEnEKKBJxCphCDBAZNfA3DgUSKgEqmEgAKMcFRwAFMEgCD0hG+lk1tsFeE0NDRxUyLBAJODH6DeBPoE0VE2gCD0eG+llFs1VQLhbCI0clNEwQCTgx+g3gL6BNFQVoAg9HhvpWwhknM03lUDgADMIMEBkVvgcFMC8AFUd2VUd2Mo8AJYoBLwA4AClFND8AEiwgDy4GxUephUepcp8AJTMLvy4HEjoRBbEEoQOUhwVGuw8AMKmThQVqAXEEZQA+Aogx6+lAiDH6GRCOLIUAj6BkB0gCD0QgOkRnBEMBKACASAjJAArQgwQGRW+BwVHdlVHdjKPACWKAS8AOADlCaOIjM0NDQ1NTUBghA7msoAoIIJuoFAoFMgu5MwMRLgEqEToFjgNCSDHr6UJIMfoZEk4lADgCD0DG+hk/oE0ZIwcOIQWhBJEDhHainwAlNQu5MwMzPgJIMevpQEgx+hkQTiUFShyAH6BkAzgCD0QgGkEoACdDD4mPAFJJJfBeHtRND6SNMP0gD6APQE0SnCAJ8QRhA1QBRQNxjwCgVEZBOSNzfiB8IBllVB8ApVEpJsIuIByPpSyw8TygAB+gL0AMntVIAIBICcoAgEgLC0CAWIpKgAptzS9qJofSRph5jpABj9ABj6AhjowACaps+1E0PpIMdMPMdIAMfoA9ATRAfiqI+1E0PpI0w/SAPoA9ATRCcMABsMAJpUowwDDAJFw4pNfCnDgIJUlwwDDAJFw4pNfCnDgU2C6lVOFusMAkXDik18KcOAnwQGTXwpw4FR0MlR0yS7wAsEBkX+dVHQyVHTDK/ACwQHDAOKTXwpw4CRURDAkVCITVE298AIiKwAaEEZEFRA4SZDwAgLwBAApttP9qJofSQY6YeY6QB9ABj6AhjowACm0QL2omh9JBjph+kAGP0AGPoCGOjA=";

static CCDEX_POOL_CODE: LazyLock<Cell> =
    LazyLock::new(|| Boc::decode_base64(CCDEX_POOL_CODE_BOC).expect("invalid CCDEX pool code BOC"));

pub fn ccdex_pool_code_hash() -> String {
    format!("{:x}", CCDEX_POOL_CODE.repr_hash())
}

pub const OP_SWAP: u32 = 0xCCDE_0001;
pub const OP_DEPOSIT: u32 = 0xCCDE_0002;
pub const OP_WITHDRAW: u32 = 0xCCDE_0003;
pub const OP_SET_FEE: u32 = 0xCCDE_0004;
pub const OP_SET_PAUSED: u32 = 0xCCDE_0005;
pub const OP_SET_OWNER: u32 = 0xCCDE_0006;
pub const OP_SKIM: u32 = 0xCCDE_0007;

pub const FEE_DENOM: u128 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Asset {
    pub is_native: bool,
    pub id: u32,
}

impl Asset {
    pub const NATIVE: Asset = Asset {
        is_native: true,
        id: 0,
    };

    pub fn cc(id: u32) -> Asset {
        Asset {
            is_native: false,
            id,
        }
    }

    fn store(&self, b: &mut CellBuilder) -> Result<()> {
        b.store_bit(self.is_native)?;
        b.store_u32(self.id)?;
        Ok(())
    }
}

pub fn swap_body(
    query_id: u64,
    in_asset: Asset,
    in_amount: u128,
    out_asset: Asset,
    min_out: u128,
    valid_until: u32,
    recipient: Option<&StdAddr>,
) -> Result<Cell> {
    let mut b = CellBuilder::new();
    b.store_u32(OP_SWAP)?;
    b.store_u64(query_id)?;
    in_asset.store(&mut b)?;
    VarUint248::new(in_amount).store_into(&mut b, Cell::empty_context())?;
    out_asset.store(&mut b)?;
    VarUint248::new(min_out).store_into(&mut b, Cell::empty_context())?;
    b.store_u32(valid_until)?;
    match recipient {
        Some(addr) => addr.store_into(&mut b, Cell::empty_context())?,
        None => b.store_small_uint(0, 2)?,
    }
    b.build().context("failed to build swap body")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolStorage {
    pub owner: String,
    pub fee_bps: u16,
    pub paused: bool,
    pub native_vault: u128,
    pub reserves: BTreeMap<u32, u128>,
}

impl PoolStorage {
    pub fn reserve_of(&self, asset: Asset) -> u128 {
        if asset.is_native {
            self.native_vault
        } else {
            self.reserves.get(&asset.id).copied().unwrap_or(0)
        }
    }

    pub fn supports(&self, asset: Asset) -> bool {
        self.reserve_of(asset) > 0
    }
}

pub fn decode_pool_storage(data: &Cell) -> Result<PoolStorage> {
    let mut cs = data.as_slice().context("pool data cell is not a slice")?;
    let owner = StdAddr::load_from(&mut cs).context("failed to read pool owner")?;
    let fee_bps = cs.load_u16().context("failed to read fee_bps")?;
    let paused = cs.load_bit().context("failed to read paused")?;
    let native_vault = Tokens::load_from(&mut cs)
        .context("failed to read native_vault")?
        .into_inner();
    let reserves_dict =
        ExtraCurrencyCollection::load_from(&mut cs).context("failed to read reserves dict")?;

    let mut reserves = BTreeMap::new();
    for entry in reserves_dict.as_dict().iter() {
        let (id, amount) = entry.context("failed to decode a reserve entry")?;
        reserves.insert(id, varuint_to_u128(&amount)?);
    }

    Ok(PoolStorage {
        owner: owner.to_string(),
        fee_bps,
        paused,
        native_vault,
        reserves,
    })
}

pub fn pool_storage_from_account(state: &AccountState) -> Result<PoolStorage> {
    let account = state
        .account()
        .context("the DEX pool account does not exist on this network")?;
    let tycho_types::models::AccountState::Active(init) = &account.state else {
        anyhow::bail!("the DEX pool is not an active contract on this network");
    };
    let data = init
        .data
        .as_ref()
        .context("the DEX pool has no data cell to read reserves from")?;
    decode_pool_storage(data)
}

fn varuint_to_u128(v: &VarUint248) -> Result<u128> {
    let (hi, lo) = v.into_words();
    anyhow::ensure!(hi == 0, "extra-currency reserve {v} exceeds u128");
    Ok(lo)
}

pub fn ccdex_pool_spec() -> ContractSpec {
    ContractSpec {
        name: CCDEX_POOL_CONTRACT,
        code_hash: Some(ccdex_pool_code_hash),
        well_known_address: None,
        decode_data: decode_pool_fields,
        external_method: |_body| None,
        internal_method: ccdex_internal_method,
    }
}

fn decode_pool_fields(data: &Cell) -> Option<DecodedContract> {
    let storage = decode_pool_storage(data).ok()?;
    let mut fields = vec![
        DecodedField::data("Owner", storage.owner.clone()),
        DecodedField::text("Fee", format!("{:.2}%", storage.fee_bps as f64 / 100.0)),
        DecodedField::text("Swaps", if storage.paused { "paused" } else { "open" }),
        DecodedField::amount("Native reserve", storage.native_vault),
    ];
    fields.extend(
        storage
            .reserves
            .iter()
            .map(|(id, units)| DecodedField::amount(format!("Reserve #{id}"), *units)),
    );
    Some(DecodedContract {
        kind: CCDEX_POOL_CONTRACT,
        fields,
    })
}

fn ccdex_internal_method(op: u32) -> Option<&'static str> {
    Some(match op {
        OP_SWAP => "swap",
        OP_DEPOSIT => "deposit",
        OP_WITHDRAW => "withdraw",
        OP_SET_FEE => "set_fee",
        OP_SET_PAUSED => "set_paused",
        OP_SET_OWNER => "set_owner",
        OP_SKIM => "skim",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pool_code_hash_matches_the_compiled_artifact() {
        assert_eq!(
            ccdex_pool_code_hash(),
            "5f5c08a95c2f1332dd6305d824d31b76f7cdb3040e3955c08d23b269ed13969b"
        );
    }

    #[test]
    fn the_spec_recognises_the_pool_by_its_code_and_names_its_ops() {
        let spec = ccdex_pool_spec();
        assert_eq!(spec.name, CCDEX_POOL_CONTRACT);
        assert!(spec.well_known_address.is_none(), "the pool is shared code");
        assert_eq!(
            (spec.code_hash.expect("recognised by code"))(),
            ccdex_pool_code_hash()
        );
        assert_eq!((spec.internal_method)(OP_SWAP), Some("swap"));
        assert_eq!((spec.internal_method)(OP_DEPOSIT), Some("deposit"));
        assert_eq!((spec.internal_method)(0x1234_5678), None);
        assert_eq!(
            (spec.external_method)(&Cell::default()),
            None,
            "the pool is driven by internal messages"
        );
    }

    #[test]
    fn swap_body_begins_with_the_op_and_query_id() {
        let body = swap_body(
            0x0102_0304_0506_0708,
            Asset::cc(1),
            10,
            Asset::cc(2),
            9,
            1_800_000_000,
            None,
        )
        .unwrap();
        let mut cs = body.as_slice().unwrap();
        assert_eq!(cs.load_u32().unwrap(), OP_SWAP);
        assert_eq!(cs.load_u64().unwrap(), 0x0102_0304_0506_0708);
        assert!(!cs.load_bit().unwrap());
        assert_eq!(cs.load_u32().unwrap(), 1);
    }

    #[test]
    fn native_asset_stores_a_zero_id() {
        let body = swap_body(1, Asset::NATIVE, 5, Asset::cc(2), 0, 0, None).unwrap();
        let mut cs = body.as_slice().unwrap();
        let _op = cs.load_u32().unwrap();
        let _q = cs.load_u64().unwrap();
        assert!(cs.load_bit().unwrap(), "native sets the is_native bit");
        assert_eq!(cs.load_u32().unwrap(), 0, "native id is 0");
    }

    #[test]
    fn pool_storage_round_trips_through_the_c4_layout() {
        let owner: StdAddr = "0:248f89d7b06fbed0a3d96302ca7d9afa6baba5ad476bbfbc0099396dd0016258"
            .parse()
            .unwrap();
        let mut reserves = ExtraCurrencyCollection::new();
        reserves
            .as_dict_mut()
            .set(1u32, VarUint248::new(100_000_000_000))
            .unwrap();
        reserves
            .as_dict_mut()
            .set(2u32, VarUint248::new(50_000_000_000))
            .unwrap();

        let mut b = CellBuilder::new();
        owner.store_into(&mut b, Cell::empty_context()).unwrap();
        b.store_u16(30).unwrap();
        b.store_bit(false).unwrap();
        Tokens::new(100_000_000_000)
            .store_into(&mut b, Cell::empty_context())
            .unwrap();
        reserves.store_into(&mut b, Cell::empty_context()).unwrap();
        let data = b.build().unwrap();

        let fields = decode_pool_fields(&data).expect("the pool's own layout decodes");
        assert_eq!(fields.kind, CCDEX_POOL_CONTRACT);
        assert_eq!(
            fields.fields,
            vec![
                DecodedField::data("Owner", owner.to_string()),
                DecodedField::text("Fee", "0.30%"),
                DecodedField::text("Swaps", "open"),
                DecodedField::amount("Native reserve", 100_000_000_000),
                DecodedField::amount("Reserve #1", 100_000_000_000),
                DecodedField::amount("Reserve #2", 50_000_000_000),
            ]
        );
        assert!(
            decode_pool_fields(&Cell::default()).is_none(),
            "a cell that is not this layout says nothing"
        );

        let storage = decode_pool_storage(&data).unwrap();
        assert_eq!(storage.owner, owner.to_string());
        assert_eq!(storage.fee_bps, 30);
        assert!(!storage.paused);
        assert_eq!(storage.native_vault, 100_000_000_000);
        assert_eq!(storage.reserve_of(Asset::cc(1)), 100_000_000_000);
        assert_eq!(storage.reserve_of(Asset::cc(2)), 50_000_000_000);
        assert_eq!(storage.reserve_of(Asset::NATIVE), 100_000_000_000);
        assert!(storage.supports(Asset::cc(1)));
        assert!(
            !storage.supports(Asset::cc(3)),
            "an absent reserve is unsupported"
        );
    }
}
