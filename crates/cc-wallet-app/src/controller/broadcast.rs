use cc_wallet_chain::CandidateBroadcastOutcome;

pub(super) fn broadcast_reached_node(outcome: &CandidateBroadcastOutcome) -> bool {
    matches!(
        outcome,
        CandidateBroadcastOutcome::NodeResponseObserved { .. }
            | CandidateBroadcastOutcome::MayHaveBroadcast { .. }
    )
}

pub(super) fn outcome_detail(outcome: &CandidateBroadcastOutcome) -> String {
    match outcome {
        CandidateBroadcastOutcome::NotTransmitted { detail, .. }
        | CandidateBroadcastOutcome::MayHaveBroadcast { detail }
        | CandidateBroadcastOutcome::NodeResponseObserved { detail, .. } => detail.clone(),
    }
}

pub(super) async fn probe_destination(
    chain: &dyn cc_wallet_chain::ChainService,
    inputs: &cc_wallet_domain::EndpointAddressInputs,
    address: String,
) -> Option<cc_wallet_chain::DestinationReport> {
    tokio::time::timeout(
        std::time::Duration::from_secs(12),
        chain.check_destination(inputs, address),
    )
    .await
    .ok()
    .and_then(Result::ok)
}
