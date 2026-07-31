use cc_wallet_chain::TychoWalletService;
use cc_wallet_domain::EndpointAddressInputs;
use cc_wallet_tycho::{Cell, ContractAt, ELECTOR_ADDRESS, MsgKind, internal_method};

fn endpoint() -> String {
    std::env::var("CC_WALLET_ENDPOINT")
        .unwrap_or_else(|_| "https://rpc-testnet.tychoprotocol.com".to_owned())
}

fn validator() -> String {
    std::env::var("CC_WALLET_ADDRESS").unwrap_or_else(|_| {
        "-1:1108d043b5ea3c62579deb2bd1d5cc6298b67be580ba84641d39b38d33bf53fe".to_owned()
    })
}

fn first_op(body: &Cell) -> Option<u32> {
    let mut slice = body.as_slice().ok()?;
    if slice.size_bits() < 32 {
        return None;
    }
    slice.load_u32().ok()
}

fn elector_name(op: u32) -> String {
    internal_method(ContractAt::by_address(ELECTOR_ADDRESS), op)
        .map(str::to_owned)
        .unwrap_or_else(|| format!("op 0x{op:08x} (unnamed)"))
}

fn is_elector(address: &Option<String>) -> bool {
    address.as_deref() == Some(ELECTOR_ADDRESS)
}

#[tokio::test]
#[ignore = "requires a live network + a validator address with stake history"]
async fn a_validators_stake_is_named_in_its_trace() {
    let service = TychoWalletService::default();
    let endpoint = endpoint();
    let inputs = EndpointAddressInputs::new(endpoint.clone(), validator())
        .expect("the validator address is canonical");

    let mut before_lt: Option<u64> = None;
    let mut stake_tx: Option<(String, u32)> = None;
    let mut scanned = 0usize;
    'paging: for _ in 0..40 {
        let txs = service
            .load_transactions(&inputs, 100, before_lt)
            .await
            .expect("load_transactions failed")
            .transactions;
        if txs.is_empty() {
            break;
        }
        scanned += txs.len();
        let oldest = txs.last().map(|t| t.lt);
        for tx in &txs {
            for out in &tx.out_msgs {
                if out.kind == MsgKind::Int
                    && is_elector(&out.dst)
                    && let Some(op) = first_op(&out.body)
                    && op != 0
                {
                    println!(
                        "[stake] tx {} sends {} to the elector",
                        &tx.hash[..12],
                        elector_name(op)
                    );
                    stake_tx = Some((tx.hash.clone(), op));
                    break 'paging;
                }
            }
            if let Some(m) = &tx.in_msg
                && is_elector(&m.src)
                && let Some(op) = first_op(&m.body)
                && op != 0
            {
                println!(
                    "[answer] tx {} received {} from the elector",
                    &tx.hash[..12],
                    elector_name(op)
                );
            }
        }
        match oldest {
            Some(lt) if Some(lt) != before_lt => before_lt = Some(lt),
            _ => break,
        }
    }
    println!("[scanned] {scanned} validator transactions");

    let (hash, op) =
        stake_tx.expect("no stake message to the elector found in this validator's history");

    let trace = service
        .trace_transaction(endpoint, hash.clone())
        .await
        .expect("trace_transaction failed");

    println!("\n--- trace of {} ---", &hash[..12]);
    for (i, party) in trace.parties.iter().enumerate() {
        let who = if party.address.is_empty() {
            "<outside>".to_owned()
        } else if party.address.len() > 14 {
            format!(
                "{}…{}",
                &party.address[..8],
                &party.address[party.address.len() - 4..]
            )
        } else {
            party.address.clone()
        };
        println!("  party {i}: {who}  [{}]", party.contract);
    }
    for edge in &trace.edges {
        println!(
            "  {} -> {}: {:<22} raw={}",
            edge.from, edge.to, edge.op, edge.raw_op
        );
    }

    let named = trace.edges.iter().any(|e| e.op == elector_name(op));
    let elector_party = trace
        .parties
        .iter()
        .any(|p| p.address == ELECTOR_ADDRESS && p.contract == "Elector");
    assert!(elector_party, "the elector column is recognised by address");
    assert!(named, "the stake op is named in the diagram");
    println!(
        "\n[ok] elector recognised by address, and its op named: {}",
        elector_name(op)
    );
}
