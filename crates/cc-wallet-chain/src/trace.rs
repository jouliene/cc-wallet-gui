use std::collections::BTreeMap;

use cc_wallet_domain::{AssetMovement, Digest32};
use cc_wallet_tycho::{
    ChainMessage, ChainTransaction, ContractAt, ENCRYPTED_COMMENT_OP, MsgKind, contract_name,
    external_method, internal_method,
};

use crate::activity::message_movements;
use crate::explorer::failure_reason;
use crate::wallet_service::{ChainError, ChainResult};

pub const TRACE_MAX_TRANSACTIONS: usize = 64;

pub const TRACE_MAX_DEPTH: usize = 12;

pub const TRACE_MAX_CLIMB: usize = 12;

pub type ContractIndex = BTreeMap<String, String>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TraceParty {
    pub address: String,
    pub contract: String,
}

impl TraceParty {
    pub fn is_external(&self) -> bool {
        self.address.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TraceTx {
    pub hash: Digest32,
    pub lt: u64,
    pub time_unix: u64,
    pub fee_native: u128,
    pub success: bool,
    pub failure: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TraceEdge {
    pub from: usize,
    pub to: usize,
    pub op: String,
    pub raw_op: String,
    pub movements: Vec<AssetMovement>,
    pub fwd_fee: u128,
    pub depth: usize,
    pub tx: Option<TraceTx>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AccountTrace {
    pub root: Digest32,
    pub focus: Digest32,
    pub parties: Vec<TraceParty>,
    pub edges: Vec<TraceEdge>,
    pub total_fees_native: u128,
    pub failed: usize,
    pub unexecuted: usize,
    pub truncated: bool,
}

impl AccountTrace {
    pub fn transactions(&self) -> usize {
        self.edges.iter().filter(|edge| edge.tx.is_some()).count()
    }
}

#[derive(Debug)]
pub struct TraceNode {
    pub tx: ChainTransaction,
    pub depth: usize,
    pub children: BTreeMap<usize, usize>,
}

impl TraceNode {
    pub fn new(tx: ChainTransaction, depth: usize) -> Self {
        Self {
            tx,
            depth,
            children: BTreeMap::new(),
        }
    }
}

pub fn pending_messages(node: &TraceNode) -> Vec<(usize, String)> {
    node.tx
        .out_msgs
        .iter()
        .enumerate()
        .filter(|(_, message)| message.kind == MsgKind::Int)
        .map(|(index, message)| (index, message.hash.clone()))
        .collect()
}

pub fn flatten(
    nodes: &[TraceNode],
    focus: Digest32,
    truncated: bool,
    contracts: &ContractIndex,
) -> ChainResult<AccountTrace> {
    let root = nodes.first().ok_or_else(|| {
        ChainError::Wallet("a trace needs at least its own transaction".to_owned())
    })?;
    let root_hash = parse_hash(&root.tx.hash)?;

    let mut parties = vec![TraceParty {
        address: String::new(),
        contract: String::new(),
    }];
    let mut edges = Vec::new();

    let root_account = account_of(&root.tx);
    let root_party = party_index(&mut parties, &root_account, contracts);
    let inbound = root.tx.in_msg.as_ref();
    let inbound_src = inbound
        .and_then(|message| message.src.as_deref())
        .filter(|src| !src.is_empty());
    let from = match inbound_src {
        Some(src) => party_index(&mut parties, src, contracts),
        None => 0,
    };
    let root_at = party_at(contracts, &root_account);
    let inbound_src_at = inbound_src.map_or(ContractAt::default(), |src| party_at(contracts, src));
    edges.push(TraceEdge {
        from,
        to: root_party,
        op: inbound.map_or_else(
            || "tick-tock".to_owned(),
            |message| message_op(message, inbound_src_at, root_at),
        ),
        raw_op: inbound
            .map(|message| message_raw_op(message, root_at))
            .unwrap_or_default(),
        movements: inbound
            .map(message_movements)
            .transpose()?
            .unwrap_or_default(),
        fwd_fee: inbound.map_or(0, |message| message.fwd_fee),
        depth: 0,
        tx: Some(trace_tx(&root.tx)?),
    });

    walk_out(nodes, 0, contracts, &mut parties, &mut edges)?;

    let mut total_fees_native: u128 = 0;
    let (mut failed, mut unexecuted) = (0usize, 0usize);
    for edge in &edges {
        total_fees_native = total_fees_native
            .checked_add(edge.fwd_fee)
            .ok_or_else(|| ChainError::Wallet("trace fees overflow u128".to_owned()))?;
        match &edge.tx {
            Some(tx) => {
                total_fees_native = total_fees_native
                    .checked_add(tx.fee_native)
                    .ok_or_else(|| ChainError::Wallet("trace fees overflow u128".to_owned()))?;
                if !tx.success {
                    failed += 1;
                }
            }
            None if edge.op != "event" => unexecuted += 1,
            None => {}
        }
    }

    Ok(AccountTrace {
        root: root_hash,
        focus,
        parties,
        edges,
        total_fees_native,
        failed,
        unexecuted,
        truncated,
    })
}

fn walk_out(
    nodes: &[TraceNode],
    index: usize,
    contracts: &ContractIndex,
    parties: &mut Vec<TraceParty>,
    edges: &mut Vec<TraceEdge>,
) -> ChainResult<()> {
    let node = &nodes[index];
    let from_account = account_of(&node.tx);
    let from = party_index(parties, &from_account, contracts);
    let from_at = party_at(contracts, &from_account);
    for (message_index, message) in node.tx.out_msgs.iter().enumerate() {
        let child = node.children.get(&message_index).copied();
        let destination = match message.kind {
            MsgKind::ExtOut => "",
            _ => message.dst.as_deref().unwrap_or_default(),
        };
        let to = if destination.is_empty() {
            0
        } else {
            party_index(parties, destination, contracts)
        };
        let to_at = party_at(contracts, destination);
        edges.push(TraceEdge {
            from,
            to,
            op: message_op(message, from_at, to_at),
            raw_op: message_raw_op(message, to_at),
            movements: message_movements(message)?,
            fwd_fee: message.fwd_fee,
            depth: node.depth + 1,
            tx: child.map(|idx| trace_tx(&nodes[idx].tx)).transpose()?,
        });
        if let Some(child) = child {
            walk_out(nodes, child, contracts, parties, edges)?;
        }
    }
    Ok(())
}

pub fn account_of(tx: &ChainTransaction) -> String {
    tx.in_msg
        .as_ref()
        .and_then(|message| message.dst.clone())
        .unwrap_or_default()
}

fn party_index(parties: &mut Vec<TraceParty>, address: &str, contracts: &ContractIndex) -> usize {
    if address.is_empty() {
        return 0;
    }
    if let Some(index) = parties.iter().position(|party| party.address == address) {
        return index;
    }
    parties.push(TraceParty {
        address: address.to_owned(),
        contract: contract_name(party_at(contracts, address))
            .unwrap_or_default()
            .to_owned(),
    });
    parties.len() - 1
}

fn party_at<'a>(contracts: &'a ContractIndex, address: &'a str) -> ContractAt<'a> {
    let address = (!address.is_empty()).then_some(address);
    ContractAt {
        address,
        code_hash: address.and_then(|address| code_hash_of(contracts, address)),
    }
}

fn code_hash_of<'a>(contracts: &'a ContractIndex, address: &str) -> Option<&'a str> {
    contracts.get(address).map(String::as_str)
}

fn trace_tx(tx: &ChainTransaction) -> ChainResult<TraceTx> {
    let failure = failure_reason(tx);
    Ok(TraceTx {
        hash: parse_hash(&tx.hash)?,
        lt: tx.lt,
        time_unix: u64::from(tx.now),
        fee_native: tx.total_fees_native,
        success: failure.is_empty(),
        failure,
    })
}

fn message_op(message: &ChainMessage, src: ContractAt, dst: ContractAt) -> String {
    if message.bounced {
        return "bounce".to_owned();
    }
    match message.kind {
        MsgKind::ExtOut => "event".to_owned(),
        MsgKind::ExtIn => external_method(dst, &message.body)
            .map(|(name, _id)| name)
            .unwrap_or("external message")
            .to_owned(),
        MsgKind::Int => match body_op(message) {
            None | Some(0) => "transfer".to_owned(),
            Some(op) if op == ENCRYPTED_COMMENT_OP => "encrypted comment".to_owned(),
            Some(op) => internal_op_name(src, dst, op).unwrap_or_else(|| format!("op 0x{op:08x}")),
        },
    }
}

fn internal_op_name(src: ContractAt, dst: ContractAt, op: u32) -> Option<String> {
    internal_method(dst, op)
        .or_else(|| internal_method(src, op))
        .map(str::to_owned)
}

fn message_raw_op(message: &ChainMessage, dst: ContractAt) -> String {
    if message.bounced {
        return String::new();
    }
    let op = match message.kind {
        MsgKind::ExtIn => external_method(dst, &message.body).map(|(_name, id)| id),
        MsgKind::ExtOut | MsgKind::Int => body_op(message),
    };
    op.map_or_else(String::new, |op| format!("op 0x{op:08x}"))
}

fn body_op(message: &ChainMessage) -> Option<u32> {
    let mut slice = message.body.as_slice().ok()?;
    if slice.size_bits() < 32 {
        return None;
    }
    slice.load_u32().ok()
}

fn parse_hash(value: &str) -> ChainResult<Digest32> {
    Digest32::try_from_hex(value).map_err(|error| {
        ChainError::Wallet(format!(
            "transaction hash is not canonical 32-byte hex: {error}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use cc_wallet_tycho::{BounceOutcome, ComputePhaseSkipReason};

    use std::collections::BTreeMap;

    use cc_wallet_tycho::{Cell, CellBuilder};

    use super::*;

    const A: &str = "-1:aaaa";

    fn focus() -> Digest32 {
        Digest32::try_from_hex(&"11".repeat(32)).expect("canonical hash")
    }

    const B: &str = "-1:bbbb";
    const C: &str = "-1:cccc";

    fn message(kind: MsgKind, src: Option<&str>, dst: Option<&str>, native: u128) -> ChainMessage {
        ChainMessage {
            kind,
            hash: "1".repeat(64),
            src: src.map(str::to_owned),
            dst: dst.map(str::to_owned),
            value_native: native,
            value_extra: BTreeMap::new(),
            fwd_fee: if kind == MsgKind::Int { 7 } else { 0 },
            bounce: true,
            bounced: false,
            created_lt: 1,
            created_at: 1,
            state_init: None,
            state_init_hash: None,
            body: Cell::default(),
            body_boc_base64: String::new(),
        }
    }

    fn op_name(message: &ChainMessage) -> String {
        message_op(message, ContractAt::default(), ContractAt::default())
    }

    fn op_number(message: &ChainMessage) -> String {
        message_raw_op(message, ContractAt::default())
    }

    fn tx(hash: u8, in_msg: ChainMessage, out: Vec<ChainMessage>) -> ChainTransaction {
        ChainTransaction {
            hash: format!("{hash:02x}").repeat(32),
            lt: u64::from(hash),
            now: 1_000,
            prev_trans_lt: 0,
            total_fees_native: 1_000,
            aborted: false,
            compute_success: true,
            compute_skipped: false,
            compute_skip_reason: None,
            exit_code: 0,
            action_success: Some(true),
            action_result_code: Some(0),
            action_no_funds: Some(false),
            bounce: None,
            in_msg: Some(in_msg),
            out_msgs: out,
        }
    }

    fn two_hop() -> Vec<TraceNode> {
        let root = tx(
            0x11,
            message(MsgKind::ExtIn, None, Some(A), 0),
            vec![
                message(MsgKind::Int, Some(A), Some(B), 5_000),
                message(MsgKind::ExtOut, Some(A), None, 0),
            ],
        );
        let child = tx(
            0x22,
            message(MsgKind::Int, Some(A), Some(B), 5_000),
            Vec::new(),
        );
        let mut root_node = TraceNode::new(root, 0);
        root_node.children.insert(0, 1);
        vec![root_node, TraceNode::new(child, 1)]
    }

    #[test]
    fn the_outside_world_is_always_the_first_column() {
        let trace = flatten(&two_hop(), focus(), false, &ContractIndex::new()).unwrap();

        assert!(trace.parties[0].is_external());
        assert_eq!(
            trace.parties[1].address, A,
            "then the accounts, first seen first"
        );
        assert_eq!(trace.parties[2].address, B);
    }

    #[test]
    fn the_first_arrow_is_whatever_woke_the_first_account() {
        let trace = flatten(&two_hop(), focus(), false, &ContractIndex::new()).unwrap();

        assert_eq!(
            trace.edges[0].from, 0,
            "an external message comes from outside"
        );
        assert_eq!(trace.edges[0].to, 1);
        assert!(
            trace.edges[0].tx.is_some(),
            "and it produced the root transaction"
        );
        assert_eq!(trace.edges[0].depth, 0);
    }

    #[test]
    fn every_message_becomes_an_arrow_including_the_events_that_leave_the_chain() {
        let trace = flatten(&two_hop(), focus(), false, &ContractIndex::new()).unwrap();

        assert_eq!(trace.edges.len(), 3);
        assert_eq!((trace.edges[1].from, trace.edges[1].to), (1, 2));
        assert_eq!(
            trace.edges[1].movements[0].amount.native_units(),
            Some(5_000)
        );
        assert_eq!(trace.edges[2].op, "event");
        assert_eq!(trace.edges[2].to, 0, "an event is addressed to the outside");
        assert_eq!(trace.transactions(), 2);
        assert_eq!(
            trace.total_fees_native, 2_007,
            "both transactions' fees, plus the forward fee of the one internal message"
        );
    }

    #[test]
    fn a_trace_is_never_cheaper_than_the_send_that_started_it() {
        let trace = flatten(&two_hop(), focus(), false, &ContractIndex::new()).unwrap();

        let root = &trace.edges[0];
        let outgoing = &trace.edges[1];
        let activity_fee = root.tx.as_ref().unwrap().fee_native + outgoing.fwd_fee;

        assert!(
            trace.total_fees_native >= activity_fee,
            "the whole tree ({}) cannot cost less than its first send ({activity_fee})",
            trace.total_fees_native
        );
    }

    #[test]
    fn a_message_that_never_ran_is_counted_but_events_are_not() {
        let mut nodes = two_hop();
        nodes[0].children.clear();
        let trace = flatten(&nodes, focus(), false, &ContractIndex::new()).unwrap();

        assert_eq!(trace.unexecuted, 1, "the internal message is still waiting");
        assert!(trace.edges[1].tx.is_none());
        assert_eq!(trace.transactions(), 1);
    }

    #[test]
    fn branches_are_read_one_at_a_time_not_level_by_level() {
        let root = tx(
            0x11,
            message(MsgKind::ExtIn, None, Some(A), 0),
            vec![
                message(MsgKind::Int, Some(A), Some(B), 1),
                message(MsgKind::Int, Some(A), Some(C), 2),
            ],
        );
        let b = tx(
            0x22,
            message(MsgKind::Int, Some(A), Some(B), 1),
            vec![message(MsgKind::Int, Some(B), Some(C), 3)],
        );
        let c_from_b = tx(0x33, message(MsgKind::Int, Some(B), Some(C), 3), Vec::new());
        let c_from_a = tx(0x44, message(MsgKind::Int, Some(A), Some(C), 2), Vec::new());
        let mut root_node = TraceNode::new(root, 0);
        root_node.children.insert(0, 1);
        root_node.children.insert(1, 3);
        let mut b_node = TraceNode::new(b, 1);
        b_node.children.insert(0, 2);
        let nodes = vec![
            root_node,
            b_node,
            TraceNode::new(c_from_b, 2),
            TraceNode::new(c_from_a, 1),
        ];

        let trace = flatten(&nodes, focus(), false, &ContractIndex::new()).unwrap();

        let pairs: Vec<(usize, usize)> = trace.edges.iter().map(|e| (e.from, e.to)).collect();
        assert_eq!(
            pairs,
            vec![(0, 1), (1, 2), (2, 3), (1, 3)],
            "external→A, A→B, B→C, then A→C"
        );
        assert_eq!(
            trace.edges[2].depth, 2,
            "depth is how far down the chain it is"
        );
    }

    #[test]
    fn a_failed_transaction_is_counted_and_says_why_it_failed() {
        let mut nodes = two_hop();
        nodes[1].tx.aborted = true;
        nodes[1].tx.compute_success = false;
        nodes[1].tx.exit_code = 37;
        let trace = flatten(&nodes, focus(), false, &ContractIndex::new()).unwrap();

        assert_eq!(trace.failed, 1);
        let child = trace.edges[1].tx.as_ref().unwrap();
        assert!(!child.success);
        assert_eq!(child.failure, "exit 37");
    }

    #[test]
    fn a_first_deposit_into_an_account_with_no_code_is_not_a_failure() {
        let mut nodes = two_hop();
        nodes[1].tx.aborted = true;
        nodes[1].tx.compute_skipped = true;
        let trace = flatten(&nodes, focus(), false, &ContractIndex::new()).unwrap();

        assert_eq!(trace.failed, 0, "an aborted deposit still delivered");
        let child = trace.edges[1].tx.as_ref().unwrap();
        assert!(child.success);
        assert_eq!(child.failure, "");
    }

    #[test]
    fn a_message_that_bought_no_gas_did_not_send_the_value_home() {
        let mut nodes = two_hop();
        nodes[1].tx.aborted = true;
        nodes[1].tx.compute_skipped = true;
        nodes[1].tx.compute_skip_reason = Some(ComputePhaseSkipReason::NoGas);
        nodes[1].tx.bounce = Some(BounceOutcome::Unaffordable);
        let trace = flatten(&nodes, focus(), false, &ContractIndex::new()).unwrap();

        let child = trace.edges[1].tx.as_ref().unwrap();
        assert_eq!(
            child.failure, "",
            "nothing came back, so nothing may say it did"
        );
        assert_eq!(trace.failed, 0, "the value stayed where it landed");
    }

    #[test]
    fn value_that_came_straight_back_is_named_for_what_it_did() {
        let mut nodes = two_hop();
        nodes[1].tx.aborted = true;
        nodes[1].tx.bounce = Some(BounceOutcome::Returned);
        let trace = flatten(&nodes, focus(), false, &ContractIndex::new()).unwrap();

        let child = trace.edges[1].tx.as_ref().unwrap();
        assert!(!child.success);
        assert_eq!(child.failure, "value returned");
    }

    #[test]
    fn actions_that_could_not_be_applied_are_a_failure_of_their_own() {
        let mut nodes = two_hop();
        nodes[1].tx.action_success = Some(false);
        nodes[1].tx.action_no_funds = Some(true);
        let trace = flatten(&nodes, focus(), false, &ContractIndex::new()).unwrap();

        assert_eq!(
            trace.edges[1].tx.as_ref().unwrap().failure,
            "no funds for actions"
        );
    }

    #[test]
    fn a_body_names_its_method_by_op_and_never_prints_what_it_carries() {
        let mut with_op = message(MsgKind::Int, Some(A), Some(B), 1);
        let mut builder = CellBuilder::new();
        builder.store_u32(0x02ed_f6b4).unwrap();
        with_op.body = builder.build().unwrap();
        assert_eq!(op_name(&with_op), "op 0x02edf6b4");

        let mut commented = message(MsgKind::Int, Some(A), Some(B), 1);
        let mut builder = CellBuilder::new();
        builder.store_u32(0).unwrap();
        builder.store_raw(b"rent", 32).unwrap();
        commented.body = builder.build().unwrap();
        assert_eq!(
            op_name(&commented),
            "transfer",
            "a note rides along with a transfer; it does not rename it, and the trace \
             is no place to print it"
        );

        let mut sealed = message(MsgKind::Int, Some(A), Some(B), 1);
        let mut builder = CellBuilder::new();
        builder.store_u32(ENCRYPTED_COMMENT_OP).unwrap();
        sealed.body = builder.build().unwrap();
        assert_eq!(op_name(&sealed), "encrypted comment");

        let empty = message(MsgKind::Int, Some(A), Some(B), 1);
        assert_eq!(op_name(&empty), "transfer", "an empty body is a transfer");

        let mut bounced = message(MsgKind::Int, Some(B), Some(A), 1);
        bounced.bounced = true;
        assert_eq!(op_name(&bounced), "bounce");
    }

    #[test]
    fn a_message_carries_the_number_it_begins_with_as_well_as_its_name() {
        let mut with_op = message(MsgKind::Int, Some(A), Some(B), 1);
        let mut builder = CellBuilder::new();
        builder.store_u32(0x02ed_f6b4).unwrap();
        with_op.body = builder.build().unwrap();
        assert_eq!(op_name(&with_op), "op 0x02edf6b4");
        assert_eq!(op_number(&with_op), "op 0x02edf6b4");

        let mut commented = message(MsgKind::Int, Some(A), Some(B), 1);
        let mut builder = CellBuilder::new();
        builder.store_u32(0).unwrap();
        builder.store_raw(b"rent", 32).unwrap();
        commented.body = builder.build().unwrap();
        assert_eq!(
            op_number(&commented),
            "op 0x00000000",
            "a transfer with a comment begins with a real zero, and says so"
        );

        let empty = message(MsgKind::Int, Some(A), Some(B), 1);
        assert_eq!(
            op_number(&empty),
            "",
            "a body too short to hold a number has none to switch to"
        );

        let mut unknown_external = message(MsgKind::ExtIn, None, Some(A), 0);
        let mut builder = CellBuilder::new();
        builder.store_u32(0x1234_5678).unwrap();
        unknown_external.body = builder.build().unwrap();
        assert_eq!(
            op_number(&unknown_external),
            "",
            "an unrecognised external body begins with a signature, not an op"
        );

        let mut event = message(MsgKind::ExtOut, Some(A), None, 0);
        let mut builder = CellBuilder::new();
        builder.store_u32(0x501c_8aa7).unwrap();
        event.body = builder.build().unwrap();
        assert_eq!(
            op_number(&event),
            "op 0x501c8aa7",
            "and an event, all of which are drawn alike, is told apart by its id"
        );
    }

    #[test]
    fn a_named_external_method_is_switched_for_the_number_its_name_stands_for() {
        use cc_wallet_tycho::external_method;

        let named_id = |raw: Option<(&'static str, u32)>| {
            raw.map_or_else(String::new, |(_name, id)| format!("op 0x{id:08x}"))
        };
        assert_eq!(
            named_id(Some(("sendTransaction", 0x0a1b_2c3d))),
            "op 0x0a1b2c3d",
            "a recognised external method wears its id in the op's own shape"
        );
        assert_eq!(
            named_id(external_method(ContractAt::default(), &Cell::default())),
            "",
            "a body we cannot name offers no number in its place"
        );
    }

    #[test]
    fn a_method_is_named_by_the_contract_it_is_called_on() {
        use cc_wallet_tycho::{EVER_WALLET_CONTRACT, ever_wallet_code_hash};

        let mut contracts = ContractIndex::new();
        contracts.insert(A.to_owned(), ever_wallet_code_hash());
        let trace = flatten(&two_hop(), focus(), false, &contracts).unwrap();

        assert_eq!(
            trace.edges[0].op, "external message",
            "a body that is not a call we know is not given a name"
        );
        assert_eq!(
            trace.parties[1].contract, EVER_WALLET_CONTRACT,
            "and the column says what the account runs"
        );

        let unknown = flatten(&two_hop(), focus(), false, &ContractIndex::new()).unwrap();
        assert_eq!(unknown.edges[0].op, "external message");
        assert_eq!(unknown.parties[1].contract, "");
    }

    #[test]
    fn an_internal_message_keeps_its_op_when_the_contract_is_a_stranger() {
        let mut with_op = message(MsgKind::Int, Some(A), Some(B), 1);
        let mut builder = CellBuilder::new();
        builder.store_u32(0x02ed_f6b4).unwrap();
        with_op.body = builder.build().unwrap();

        assert_eq!(op_name(&with_op), "op 0x02edf6b4");
        assert_eq!(
            op_name(&message(MsgKind::Int, Some(A), Some(B), 1)),
            "transfer",
            "a body with no function id at all is a plain transfer"
        );
    }

    #[test]
    fn an_electors_op_is_named_from_whichever_end_of_the_message_knows_it() {
        use cc_wallet_tycho::ELECTOR_ADDRESS;

        let elector = ContractAt::by_address(ELECTOR_ADDRESS);
        let outsider = ContractAt::default();

        let mut new_stake = message(MsgKind::Int, Some(A), Some(ELECTOR_ADDRESS), 1);
        let mut builder = CellBuilder::new();
        builder.store_u32(0x4e73_744b).unwrap();
        new_stake.body = builder.build().unwrap();
        assert_eq!(message_op(&new_stake, outsider, elector), "new_stake");
        assert_eq!(message_raw_op(&new_stake, elector), "op 0x4e73744b");

        let mut accepted = message(MsgKind::Int, Some(ELECTOR_ADDRESS), Some(A), 1);
        let mut builder = CellBuilder::new();
        builder.store_u32(0xf374_484c).unwrap();
        accepted.body = builder.build().unwrap();
        assert_eq!(
            message_op(&accepted, elector, outsider),
            "stake_accepted",
            "an answer is named from the side that sent it"
        );
        assert_eq!(message_raw_op(&accepted, outsider), "op 0xf374484c");
    }

    #[test]
    fn the_elector_is_known_by_where_it_sits_even_when_its_code_is_never_read() {
        use cc_wallet_tycho::ELECTOR_ADDRESS;

        let mut new_stake = message(MsgKind::Int, Some(A), Some(ELECTOR_ADDRESS), 1);
        let mut builder = CellBuilder::new();
        builder.store_u32(0x4e73_744b).unwrap();
        new_stake.body = builder.build().unwrap();
        let root = tx(
            0x11,
            message(MsgKind::ExtIn, None, Some(A), 0),
            vec![new_stake.clone()],
        );
        let child = tx(0x22, new_stake, Vec::new());
        let mut root_node = TraceNode::new(root, 0);
        root_node.children.insert(0, 1);
        let nodes = vec![root_node, TraceNode::new(child, 1)];

        let trace = flatten(&nodes, focus(), false, &ContractIndex::new()).unwrap();

        let elector = trace
            .parties
            .iter()
            .find(|party| party.address == ELECTOR_ADDRESS)
            .expect("the elector took part in the trace");
        assert_eq!(
            elector.contract, "Elector",
            "recognised by its address with no code hash to go on"
        );
        assert_eq!(
            trace.edges[1].op, "new_stake",
            "and the message that reached it is named, not a bare number"
        );
        assert_eq!(trace.edges[1].raw_op, "op 0x4e73744b");
    }

    #[test]
    fn a_trace_of_nothing_is_an_error_not_an_empty_diagram() {
        assert!(flatten(&[], focus(), false, &ContractIndex::new()).is_err());
    }
}

#[cfg(test)]
mod op_naming_tests {
    use super::*;
    use cc_wallet_tycho::{storage_code_hash, storage_delete_body};

    fn int_msg(body: cc_wallet_tycho::Cell) -> ChainMessage {
        ChainMessage {
            kind: MsgKind::Int,
            hash: String::new(),
            src: None,
            dst: None,
            value_native: 0,
            value_extra: BTreeMap::new(),
            fwd_fee: 0,
            bounce: true,
            bounced: false,
            created_lt: 0,
            created_at: 0,
            state_init: None,
            state_init_hash: None,
            body_boc_base64: String::new(),
            body,
        }
    }

    #[test]
    fn method_says_the_same_thing_as_raw_op_in_either_direction() {
        let code = storage_code_hash();
        let message = int_msg(storage_delete_body(1, 1).unwrap());
        let known = ContractAt::by_code(&code);
        let raw = message_raw_op(&message, known);

        assert_eq!(
            message_op(&message, ContractAt::default(), known),
            "delete_record"
        );
        assert_eq!(
            message_op(&message, known, ContractAt::default()),
            "delete_record",
            "a contract answering with the op it was called with is still that op"
        );
        assert_eq!(raw, "op 0x57a70002");
        assert_eq!(
            message_raw_op(&message, ContractAt::default()),
            raw,
            "and the raw op does not depend on who is asked either"
        );
    }
}
