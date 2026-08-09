use std::collections::BTreeMap;
use std::sync::LazyLock;

use anyhow::{Context, Result, bail, ensure};
use tycho_types::models::{StateInit, StdAddr};
use tycho_types::num::Tokens;
use tycho_types::prelude::*;

use crate::contracts::{ContractSpec, DecodedContract, DecodedField};
use crate::transport::AccountState;

pub const STORAGE_CONTRACT: &str = "CC Storage";

pub const STORAGE_CODE_BOC: &str = "te6ccgECCwEAAY4AART/APSkE/S88sgLAQIBYgIDA/jQ7aLt+/iRkTDg+Jhu8uBrINdJwSCRMOAg10nCX/LgbdMf0z/tRND6SNMP9ATR+JIjxwXy4GUlghBXpwABuuMPAcj6UhLLD/QAye1U+JL4l/gs+CdvEFihIaCCEDuaygC+k3T7ApowghA7msoAcvsC4sjPhQj6UnDPC24SBAUGAgEgBwgAfviXggkxLQC+8uBuA9Mf1NEhwgDy4GYggBD5QG+lb6FsMfLgaFMUgCD0Dm+hMZoigwi58uBnAqQC30AUgCD0FwDeJYIQV6cAArqOSVsDghBXpwADuo46+JcB+gDRIMIA8uBs+CdvEFihIYIQO5rKAKC+8uBqyM+FCBP6Ulj6AoIQV6cAA88Liss/yYAQ+wDbMeDywGTh+JeCCTEtAL7y4G4D0x/RUAOAIPRb8uBpAqUCABTLH8s/yYEAgvsAAgFmCQoAHb6x52omh9JBjph5j6AmjAAdsNE7UTQ+kgx0w/0BDHRgAB2yaXtRND6SNMPMfQEMdGA=";

static STORAGE_CODE: LazyLock<Cell> =
    LazyLock::new(|| Boc::decode_base64(STORAGE_CODE_BOC).expect("invalid CC Storage code BOC"));

pub fn storage_code() -> Cell {
    STORAGE_CODE.clone()
}

pub fn storage_code_hash() -> String {
    format!("{:x}", STORAGE_CODE.repr_hash())
}

pub const OP_PUT: u32 = 0x57A7_0001;
pub const OP_DELETE: u32 = 0x57A7_0002;
pub const OP_WITHDRAW: u32 = 0x57A7_0003;

pub const ERR_UNKNOWN_OP: i32 = 100;
pub const ERR_NOT_OWNER: i32 = 101;
pub const ERR_BAD_ID: i32 = 102;
pub const ERR_TOO_MANY_RECORDS: i32 = 103;
pub const ERR_RECORD_TOO_BIG: i32 = 104;
pub const ERR_NOT_FOUND: i32 = 105;
pub const ERR_STORAGE_RESERVE: i32 = 106;
pub const ERR_EXTRA_CURRENCY: i32 = 107;
pub const ERR_BAD_AMOUNT: i32 = 108;
pub const ERR_MALFORMED_BODY: i32 = 109;
pub const ERR_INSUFFICIENT_ATTACH: i32 = 110;

pub const MAX_RECORDS: u16 = 512;

pub const STORAGE_WORKCHAIN: i8 = 0;

pub const TARGET_BALANCE: u128 = 1_000_000_000;

pub const MIN_OP_ATTACH: u128 = 20_000_000;

pub const MAX_RECORD_CELLS: usize = 16;

pub const BLOB_CELL_BYTES: usize = 127;

pub const MAX_BLOB_BYTES: usize = BLOB_CELL_BYTES * MAX_RECORD_CELLS;

pub fn blob_cell(bytes: &[u8]) -> Result<Cell> {
    ensure!(
        bytes.len() <= MAX_BLOB_BYTES,
        "a record of {} bytes exceeds the {MAX_BLOB_BYTES}-byte budget",
        bytes.len()
    );

    let mut chunks: Vec<&[u8]> = bytes.chunks(BLOB_CELL_BYTES).collect();
    if chunks.is_empty() {
        chunks.push(&[]);
    }

    let mut cell: Option<Cell> = None;
    for chunk in chunks.iter().rev() {
        let mut builder = CellBuilder::new();
        builder.store_raw(chunk, (chunk.len() * 8) as u16)?;
        if let Some(next) = cell.take() {
            builder.store_reference(next)?;
        }
        cell = Some(builder.build()?);
    }
    Ok(cell.expect("the chunk list is never empty"))
}

pub fn blob_bytes(cell: &Cell) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut current = cell.clone();

    for _ in 0..MAX_RECORD_CELLS {
        let mut slice = current.as_slice().context("a record cell is not a slice")?;
        let bits = slice.size_bits();
        ensure!(
            bits % 8 == 0,
            "a record cell holds {bits} bits, which is not whole bytes"
        );
        let mut buf = vec![0u8; (bits / 8) as usize];
        slice.load_raw(&mut buf, bits)?;
        out.extend_from_slice(&buf);

        match current.reference_count() {
            0 => return Ok(out),
            1 => {
                current = current
                    .reference_cloned(0)
                    .context("a record cell lost the reference it just reported")?;
            }
            other => bail!("a record cell has {other} references, expected at most one"),
        }
    }
    bail!("a record blob is deeper than the {MAX_RECORD_CELLS}-cell limit")
}

pub fn initial_data(owner: &StdAddr) -> Result<Cell> {
    let mut builder = CellBuilder::new();
    owner.store_into(&mut builder, Cell::empty_context())?;
    builder.store_u16(0)?;
    Dict::<u32, Cell>::new().store_into(&mut builder, Cell::empty_context())?;
    builder
        .build()
        .context("failed to build the initial storage data cell")
}

pub fn storage_state_init(owner: &StdAddr) -> Result<StateInit> {
    Ok(StateInit {
        split_depth: None,
        special: None,
        code: Some(storage_code()),
        data: Some(initial_data(owner)?),
        libraries: Dict::new(),
    })
}

pub fn storage_address(owner: &StdAddr) -> Result<(StdAddr, StateInit)> {
    let init = storage_state_init(owner)?;
    let cell =
        CellBuilder::build_from(&init).context("failed to serialize the storage state init")?;
    Ok((StdAddr::new(STORAGE_WORKCHAIN, *cell.repr_hash()), init))
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StorageData {
    pub owner: String,
    pub count: u16,
    pub records: BTreeMap<u32, Vec<u8>>,
}

pub fn decode_storage_data(data: &Cell) -> Result<StorageData> {
    let mut slice = data
        .as_slice()
        .context("the storage data cell is not a slice")?;
    let owner = StdAddr::load_from(&mut slice).context("failed to read the storage owner")?;
    let count = slice
        .load_u16()
        .context("failed to read the record count")?;
    let dict =
        Dict::<u32, Cell>::load_from(&mut slice).context("failed to read the records dict")?;

    let mut records = BTreeMap::new();
    for entry in dict.iter() {
        let (id, cell) = entry.context("failed to decode a record entry")?;
        records.insert(id, blob_bytes(&cell)?);
    }
    Ok(StorageData {
        owner: owner.to_string(),
        count,
        records,
    })
}

pub fn storage_from_account(state: &AccountState) -> Result<Option<StorageData>> {
    let Some(account) = state.account() else {
        return Ok(None);
    };
    let tycho_types::models::AccountState::Active(init) = &account.state else {
        return Ok(None);
    };
    let data = init
        .data
        .as_ref()
        .context("the storage account has no data cell to read")?;
    decode_storage_data(data).map(Some)
}

fn body_header(op: u32, query_id: u64) -> Result<CellBuilder> {
    let mut builder = CellBuilder::new();
    builder.store_u32(op)?;
    builder.store_u64(query_id)?;
    Ok(builder)
}

pub fn put_body(query_id: u64, id: u32, blob: &[u8]) -> Result<Cell> {
    ensure!(id > 0, "record numbers start at 1");
    let mut builder = body_header(OP_PUT, query_id)?;
    builder.store_u32(id)?;
    builder.store_reference(blob_cell(blob)?)?;
    builder.build().context("failed to build a put body")
}

pub fn delete_body(query_id: u64, id: u32) -> Result<Cell> {
    ensure!(id > 0, "record numbers start at 1");
    let mut builder = body_header(OP_DELETE, query_id)?;
    builder.store_u32(id)?;
    builder.build().context("failed to build a delete body")
}

pub fn withdraw_body(query_id: u64, amount: u128) -> Result<Cell> {
    let mut builder = body_header(OP_WITHDRAW, query_id)?;
    Tokens::new(amount).store_into(&mut builder, Cell::empty_context())?;
    builder.build().context("failed to build a withdraw body")
}

pub fn storage_spec() -> ContractSpec {
    ContractSpec {
        name: STORAGE_CONTRACT,
        code_hash: Some(storage_code_hash),
        well_known_address: None,
        decode_data: decode_storage_fields,
        external_method: |_body| None,
        internal_method: storage_internal_method,
        internal_reply: storage_internal_reply,
    }
}

fn decode_storage_fields(data: &Cell) -> Option<DecodedContract> {
    let storage = decode_storage_data(data).ok()?;
    Some(DecodedContract {
        kind: STORAGE_CONTRACT,
        fields: vec![
            DecodedField::data("Owner", storage.owner.clone()),
            DecodedField::text("Records", storage.count.to_string()),
            DecodedField::text("Contents", "encrypted"),
        ],
    })
}

fn storage_internal_method(op: u32) -> Option<&'static str> {
    Some(match op {
        OP_PUT => "put_record",
        OP_DELETE => "delete_record",
        OP_WITHDRAW => "withdraw",
        _ => return None,
    })
}

fn storage_internal_reply(op: u32) -> Option<&'static str> {
    Some(match op {
        OP_PUT => "put_record change",
        OP_DELETE => "delete_record change",
        OP_WITHDRAW => "withdraw payout",
        _ => return None,
    })
}

pub fn storage_error_text(exit_code: i32) -> Option<&'static str> {
    Some(match exit_code {
        ERR_UNKNOWN_OP => "the storage contract does not know that operation",
        ERR_NOT_OWNER => "that storage belongs to a different wallet",
        ERR_BAD_ID => "record numbers start at 1",
        ERR_TOO_MANY_RECORDS => "the storage is full",
        ERR_RECORD_TOO_BIG => "the record is too large for one entry",
        ERR_NOT_FOUND => "that record is no longer in the storage",
        ERR_STORAGE_RESERVE => "the storage must keep enough to pay its rent",
        ERR_EXTRA_CURRENCY => "the storage does not accept tokens",
        ERR_BAD_AMOUNT => "the amount must be greater than zero",
        ERR_MALFORMED_BODY => "the storage could not read that request",
        ERR_INSUFFICIENT_ATTACH => "the request did not carry enough to pay for itself",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> StdAddr {
        "0:248f89d7b06fbed0a3d96302ca7d9afa6baba5ad476bbfbc0099396dd0016258"
            .parse()
            .unwrap()
    }

    #[test]
    fn the_code_hash_matches_the_compiled_artifact() {
        assert_eq!(
            storage_code_hash(),
            "7f20b33ba1f2ee78dc471a2d10bd35cf14703f1dd1a568a10a9e02b1780b3847"
        );
    }

    #[test]
    fn a_blob_survives_the_round_trip_at_every_cell_boundary() {
        for len in [
            0,
            1,
            BLOB_CELL_BYTES - 1,
            BLOB_CELL_BYTES,
            BLOB_CELL_BYTES + 1,
            MAX_BLOB_BYTES,
        ] {
            let bytes: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let cell = blob_cell(&bytes).unwrap();
            assert_eq!(
                blob_bytes(&cell).unwrap(),
                bytes,
                "a {len}-byte record did not survive the round trip"
            );
        }
        assert!(blob_cell(&vec![0u8; MAX_BLOB_BYTES + 1]).is_err());
    }

    #[test]
    fn the_storage_address_is_a_pure_function_of_the_owner() {
        let alice = owner();
        let bob: StdAddr = "0:1111111111111111111111111111111111111111111111111111111111111111"
            .parse()
            .unwrap();

        let (a1, init) = storage_address(&alice).unwrap();
        let (a2, _) = storage_address(&alice).unwrap();
        let (b1, _) = storage_address(&bob).unwrap();

        assert_eq!(a1, a2);
        assert_ne!(a1, b1);
        assert_eq!(a1.workchain, STORAGE_WORKCHAIN);
        assert_eq!(
            a1.address.0,
            CellBuilder::build_from(&init).unwrap().repr_hash().0
        );
    }

    #[test]
    fn a_storage_lives_in_the_basechain_even_for_a_masterchain_owner() {
        let masterchain: StdAddr =
            "-1:248f89d7b06fbed0a3d96302ca7d9afa6baba5ad476bbfbc0099396dd0016258"
                .parse()
                .unwrap();
        assert_eq!(
            storage_address(&masterchain).unwrap().0.workchain,
            STORAGE_WORKCHAIN,
            "rent in the masterchain costs a thousand times more, forever"
        );
        assert_eq!(
            storage_address(&owner()).unwrap().0.workchain,
            STORAGE_WORKCHAIN
        );
    }

    #[test]
    fn a_fresh_storage_decodes_to_its_owner_and_nothing_else() {
        let owner = owner();
        let decoded = decode_storage_data(&initial_data(&owner).unwrap()).unwrap();

        assert_eq!(decoded.owner, owner.to_string());
        assert_eq!(decoded.count, 0);
        assert!(decoded.records.is_empty());
    }

    #[test]
    fn c4_round_trips_through_the_layout_the_contract_parses() {
        let owner = owner();
        let mut records = Dict::<u32, Cell>::new();
        records
            .set(1u32, blob_cell(b"sealed one").unwrap())
            .unwrap();
        records
            .set(9u32, blob_cell(&vec![7u8; 300]).unwrap())
            .unwrap();

        let mut builder = CellBuilder::new();
        owner
            .store_into(&mut builder, Cell::empty_context())
            .unwrap();
        builder.store_u16(2).unwrap();
        records
            .store_into(&mut builder, Cell::empty_context())
            .unwrap();
        let data = builder.build().unwrap();

        let decoded = decode_storage_data(&data).unwrap();
        assert_eq!(decoded.count, 2);
        assert_eq!(decoded.records[&1], b"sealed one".to_vec());
        assert_eq!(decoded.records[&9], vec![7u8; 300]);

        let fields = decode_storage_fields(&data).expect("its own layout decodes");
        assert_eq!(fields.kind, STORAGE_CONTRACT);
        assert_eq!(
            fields.fields,
            vec![
                DecodedField::data("Owner", owner.to_string()),
                DecodedField::text("Records", "2"),
                DecodedField::text("Contents", "encrypted"),
            ],
            "an explorer sees how many records there are and that it cannot read them"
        );
        assert!(decode_storage_fields(&Cell::default()).is_none());
    }

    #[test]
    fn bodies_carry_the_selector_query_id_and_fields_the_contract_reads() {
        let put = put_body(0x0102_0304_0506_0708, 42, b"payload").unwrap();
        let mut slice = put.as_slice().unwrap();
        assert_eq!(slice.load_u32().unwrap(), OP_PUT);
        assert_eq!(slice.load_u64().unwrap(), 0x0102_0304_0506_0708);
        assert_eq!(slice.load_u32().unwrap(), 42);
        assert_eq!(
            blob_bytes(&slice.load_reference_cloned().unwrap()).unwrap(),
            b"payload".to_vec()
        );

        let delete = delete_body(7, 42).unwrap();
        let mut slice = delete.as_slice().unwrap();
        assert_eq!(slice.load_u32().unwrap(), OP_DELETE);
        assert_eq!(slice.load_u64().unwrap(), 7);
        assert_eq!(slice.load_u32().unwrap(), 42);
        assert_eq!(slice.size_bits(), 0);

        let withdraw = withdraw_body(9, 1_500_000_000).unwrap();
        let mut slice = withdraw.as_slice().unwrap();
        assert_eq!(slice.load_u32().unwrap(), OP_WITHDRAW);
        assert_eq!(slice.load_u64().unwrap(), 9);
        assert_eq!(
            Tokens::load_from(&mut slice).unwrap().into_inner(),
            1_500_000_000
        );
    }

    #[test]
    fn record_zero_is_refused_before_it_reaches_the_chain() {
        assert!(put_body(1, 0, b"x").is_err());
        assert!(delete_body(1, 0).is_err());
    }

    #[test]
    fn every_op_body_clears_the_contracts_minimum_header() {
        for body in [
            put_body(1, 1, b"x").unwrap(),
            delete_body(1, 1).unwrap(),
            withdraw_body(1, 1).unwrap(),
        ] {
            assert!(body.as_slice().unwrap().size_bits() >= 96);
        }
    }

    #[test]
    fn the_ops_are_named_and_nothing_else_is() {
        let spec = storage_spec();
        assert_eq!(spec.name, STORAGE_CONTRACT);
        assert_eq!((spec.internal_method)(OP_PUT), Some("put_record"));
        assert_eq!((spec.internal_method)(OP_DELETE), Some("delete_record"));
        assert_eq!((spec.internal_method)(OP_WITHDRAW), Some("withdraw"));
        assert_eq!((spec.internal_method)(0x1234_5678), None);
        assert_eq!((spec.external_method)(&Cell::default()), None);
    }

    #[test]
    fn every_contract_error_has_words_a_user_can_act_on() {
        for code in [
            ERR_UNKNOWN_OP,
            ERR_NOT_OWNER,
            ERR_BAD_ID,
            ERR_TOO_MANY_RECORDS,
            ERR_RECORD_TOO_BIG,
            ERR_NOT_FOUND,
            ERR_STORAGE_RESERVE,
            ERR_EXTRA_CURRENCY,
            ERR_BAD_AMOUNT,
            ERR_MALFORMED_BODY,
            ERR_INSUFFICIENT_ATTACH,
        ] {
            assert!(storage_error_text(code).is_some(), "code {code} is unnamed");
        }
        assert_eq!(storage_error_text(0), None);
        assert_eq!(storage_error_text(37), None);
    }
}
