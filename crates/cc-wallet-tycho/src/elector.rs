use tycho_types::num::Tokens;
use tycho_types::prelude::*;

use crate::contracts::{ContractSpec, DecodedContract, DecodedField};

pub const ELECTOR_ADDRESS: &str =
    "-1:3333333333333333333333333333333333333333333333333333333333333333";

pub const ELECTOR_CONTRACT: &str = "Elector";

const OP_NEW_STAKE: u32 = 0x4e73_744b;
const OP_RECOVER_STAKE: u32 = 0x4765_7424;
const OP_UPGRADE_CODE: u32 = 0x4e43_6f64;
const OP_CONFIRM_VSET: u32 = 0xee76_4f4b;
const OP_REJECT_VSET: u32 = 0xee76_4f6f;

const OP_STAKE_REJECTED: u32 = 0xee6f_454c;
const OP_STAKE_ACCEPTED: u32 = 0xf374_484c;
const OP_STAKE_RECOVERED: u32 = 0xf96f_7324;
const OP_CODE_ACCEPTED: u32 = 0xce43_6f64;
const OP_NO_STAKE_TO_RECOVER: u32 = 0xffff_fffe;
const OP_ERROR: u32 = 0xffff_ffff;

pub fn elector_spec() -> ContractSpec {
    ContractSpec {
        name: ELECTOR_CONTRACT,
        code_hash: None,
        well_known_address: Some(ELECTOR_ADDRESS),
        decode_data: decode_elector_data,
        external_method: |_body| None,
        internal_method: elector_internal_method,
    }
}

fn decode_elector_data(data: &Cell) -> Option<DecodedContract> {
    let mut cs = data.as_slice().ok()?;
    let election = if cs.load_bit().ok()? {
        Some(cs.load_reference_cloned().ok()?)
    } else {
        None
    };
    for _ in 0..2 {
        if cs.load_bit().ok()? {
            cs.load_reference().ok()?;
        }
    }
    let grams = Tokens::load_from(&mut cs).ok()?.into_inner();
    let active_id = cs.load_u32().ok()?;
    let active_hash = cs.load_u256().ok()?;
    if !cs.is_data_empty() || !cs.is_refs_empty() {
        return None;
    }

    let mut fields = Vec::new();
    match election.as_ref().and_then(election_fields) {
        Some(mut election) => fields.append(&mut election),
        None if election.is_some() => return None,
        None => fields.push(DecodedField::text("Election", "none in progress")),
    }
    fields.push(DecodedField::amount("Elector holds", grams));
    fields.push(DecodedField::text("Active set", active_id.to_string()));
    fields.push(DecodedField::data(
        "Active set hash",
        format!("{active_hash:x}"),
    ));
    Some(DecodedContract {
        kind: ELECTOR_CONTRACT,
        fields,
    })
}

fn election_fields(cell: &Cell) -> Option<Vec<DecodedField>> {
    let mut cs = cell.as_slice().ok()?;
    let elect_at = cs.load_u32().ok()?;
    let elect_close = cs.load_u32().ok()?;
    let min_stake = Tokens::load_from(&mut cs).ok()?.into_inner();
    let total_stake = Tokens::load_from(&mut cs).ok()?.into_inner();
    let has_members = cs.load_bit().ok()?;
    if has_members {
        cs.load_reference().ok()?;
    }
    let failed = cs.load_bit().ok()?;
    let finished = cs.load_bit().ok()?;
    if !cs.is_data_empty() || !cs.is_refs_empty() {
        return None;
    }
    Some(vec![
        DecodedField::text(
            "Election",
            if finished {
                "finished"
            } else if failed {
                "failed"
            } else {
                "open"
            },
        ),
        DecodedField::moment("Elected for", u64::from(elect_at)),
        DecodedField::moment("Applications close", u64::from(elect_close)),
        DecodedField::amount("Minimum stake", min_stake),
        DecodedField::amount("Total staked", total_stake),
        DecodedField::text(
            "Stakes",
            if has_members {
                "some received"
            } else {
                "none yet"
            },
        ),
    ])
}

fn elector_internal_method(op: u32) -> Option<&'static str> {
    Some(match op {
        OP_NEW_STAKE => "new_stake",
        OP_RECOVER_STAKE => "recover_stake",
        OP_UPGRADE_CODE => "upgrade_code",
        OP_CONFIRM_VSET => "confirm_vset",
        OP_REJECT_VSET => "reject_vset",
        OP_STAKE_REJECTED => "stake_rejected",
        OP_STAKE_ACCEPTED => "stake_accepted",
        OP_STAKE_RECOVERED => "stake_recovered",
        OP_CODE_ACCEPTED => "code_accepted",
        OP_NO_STAKE_TO_RECOVER => "no_stake_to_recover",
        OP_ERROR => "error",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tycho_types::cell::CellBuilder;

    #[test]
    fn the_elector_names_the_requests_it_takes_and_the_answers_it_gives() {
        assert_eq!(elector_internal_method(OP_NEW_STAKE), Some("new_stake"));
        assert_eq!(
            elector_internal_method(OP_RECOVER_STAKE),
            Some("recover_stake")
        );
        assert_eq!(
            elector_internal_method(OP_STAKE_ACCEPTED),
            Some("stake_accepted"),
            "an answer is one of the elector's ops too"
        );
        assert_eq!(elector_internal_method(OP_ERROR), Some("error"));
    }

    #[test]
    fn an_op_that_is_none_of_the_electors_is_not_named() {
        assert_eq!(elector_internal_method(0x0000_0000), None);
        assert_eq!(elector_internal_method(0x1234_5678), None);
    }

    #[test]
    fn the_spec_recognises_the_elector_by_its_address_and_names_its_ops() {
        let spec = elector_spec();

        assert_eq!(spec.name, ELECTOR_CONTRACT);
        assert_eq!(spec.well_known_address, Some(ELECTOR_ADDRESS));
        assert!(
            spec.code_hash.is_none(),
            "the elector is known by where it sits, not by a code hash"
        );
        assert_eq!((spec.internal_method)(OP_NEW_STAKE), Some("new_stake"));
        assert_eq!(
            (spec.external_method)(&tycho_types::prelude::Cell::default()),
            None,
            "the elector is driven by internal messages, not external ones"
        );
    }

    #[test]
    fn the_address_is_the_masterchain_singleton_the_network_fixes() {
        assert!(ELECTOR_ADDRESS.starts_with("-1:"));
        assert_eq!(
            ELECTOR_ADDRESS.len(),
            3 + 64,
            "a workchain and a 32-byte account, in the raw form the chain reports"
        );
    }

    fn storage(election: Option<Cell>, grams: u128, active_id: u32) -> Cell {
        let mut b = CellBuilder::new();
        match election {
            Some(cell) => {
                b.store_bit_one().unwrap();
                b.store_reference(cell).unwrap();
            }
            None => b.store_bit_zero().unwrap(),
        }
        b.store_bit_zero().unwrap();
        b.store_bit_zero().unwrap();
        Tokens::new(grams)
            .store_into(&mut b, Cell::empty_context())
            .unwrap();
        b.store_u32(active_id).unwrap();
        b.store_u256(&HashBytes([0x11; 32])).unwrap();
        b.build().unwrap()
    }

    fn election(min: u128, total: u128, members: bool, failed: bool, finished: bool) -> Cell {
        let mut b = CellBuilder::new();
        b.store_u32(1_700_000_000).unwrap();
        b.store_u32(1_700_003_600).unwrap();
        Tokens::new(min)
            .store_into(&mut b, Cell::empty_context())
            .unwrap();
        Tokens::new(total)
            .store_into(&mut b, Cell::empty_context())
            .unwrap();
        if members {
            b.store_bit_one().unwrap();
            b.store_reference(Cell::default()).unwrap();
        } else {
            b.store_bit_zero().unwrap();
        }
        b.store_bit(failed).unwrap();
        b.store_bit(finished).unwrap();
        b.build().unwrap()
    }

    #[test]
    fn a_quiet_elector_reads_as_no_election_with_its_own_funds_and_set() {
        let decoded = decode_elector_data(&storage(None, 7_500_000_000, 42))
            .expect("the reference layout decodes");
        assert_eq!(decoded.kind, ELECTOR_CONTRACT);
        assert_eq!(
            decoded.fields,
            vec![
                DecodedField::text("Election", "none in progress"),
                DecodedField::amount("Elector holds", 7_500_000_000),
                DecodedField::text("Active set", "42"),
                DecodedField::data("Active set hash", format!("{:x}", HashBytes([0x11; 32]))),
            ]
        );
    }

    #[test]
    fn an_open_election_reads_out_its_terms() {
        let cell = storage(
            Some(election(10_000_000_000, 30_000_000_000, true, false, false)),
            0,
            7,
        );
        let decoded = decode_elector_data(&cell).expect("an election decodes");
        assert_eq!(
            &decoded.fields[..6],
            &[
                DecodedField::text("Election", "open"),
                DecodedField::moment("Elected for", 1_700_000_000),
                DecodedField::moment("Applications close", 1_700_003_600),
                DecodedField::amount("Minimum stake", 10_000_000_000),
                DecodedField::amount("Total staked", 30_000_000_000),
                DecodedField::text("Stakes", "some received"),
            ]
        );

        let finished = storage(Some(election(1, 1, false, false, true)), 0, 7);
        let decoded = decode_elector_data(&finished).unwrap();
        assert_eq!(
            decoded.fields[0],
            DecodedField::text("Election", "finished")
        );
        assert_eq!(decoded.fields[5], DecodedField::text("Stakes", "none yet"));

        let failed = storage(Some(election(1, 1, false, true, false)), 0, 7);
        let decoded = decode_elector_data(&failed).unwrap();
        assert_eq!(decoded.fields[0], DecodedField::text("Election", "failed"));
    }

    #[test]
    fn a_cell_that_is_not_this_layout_says_nothing_rather_than_a_wrong_number() {
        assert!(decode_elector_data(&Cell::default()).is_none());

        let mut b = CellBuilder::new();
        b.store_bit_zero().unwrap();
        b.store_bit_zero().unwrap();
        b.store_bit_zero().unwrap();
        Tokens::new(1)
            .store_into(&mut b, Cell::empty_context())
            .unwrap();
        b.store_u32(1).unwrap();
        b.store_u256(&HashBytes([0; 32])).unwrap();
        b.store_bit_one().unwrap();
        assert!(
            decode_elector_data(&b.build().unwrap()).is_none(),
            "a trailing bit is a different contract, not a detail to ignore"
        );

        let mut junk = CellBuilder::new();
        junk.store_u16(7).unwrap();
        assert!(decode_elector_data(&storage(Some(junk.build().unwrap()), 0, 1)).is_none());
    }
}
