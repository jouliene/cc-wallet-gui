use std::time::Instant;

use cc_wallet_chain::{
    AccountInspection, AccountTrace, AccountTxPage, AccountUpdate, CandidateBroadcastOutcome,
    ChainError, DestinationReport, FeeEstimate, NetworkStats, PoolSnapshot, PreparedChainSend,
};
use cc_wallet_domain::{
    ActivityEvent, Digest32, EndpointTransactionEvidence, StorageOp, StorageSnapshot,
    ValidatorCycle, WalletSnapshot,
};

#[derive(Debug)]
pub enum AppEvent {
    WalletLoaded {
        generation: u64,
        request_id: u64,
        snapshot: WalletSnapshot,
    },
    WalletAutoLoaded {
        generation: u64,
        request_id: u64,
        snapshot: WalletSnapshot,
    },
    WalletAutoLoadFailed {
        generation: u64,
        request_id: u64,
        error: String,
    },
    WalletLoadFailed {
        generation: u64,
        request_id: u64,
        error: String,
    },
    SubscriptionReady {
        generation: u64,
        uuid: String,
    },
    SubscriptionUpdate {
        generation: u64,
        update: AccountUpdate,
    },
    SubscriptionFailed {
        generation: u64,
        error: String,
    },
    SendPrepared {
        generation: u64,
        expected_ticket_digest: Digest32,
        risk_grant_required: bool,
        prepared: PreparedChainSend,
    },
    CandidateBroadcastFinished {
        generation: u64,
        prepared: PreparedChainSend,
        candidate_index: usize,
        outcome: CandidateBroadcastOutcome,
    },
    SendFailed {
        generation: u64,
        error: ChainError,
    },
    DestinationChecked {
        generation: u64,
        seq: u64,
        address: String,
        report: Option<DestinationReport>,
    },
    ChatPeerKeyLoaded {
        generation: u64,
        seq: u64,
        peer: String,
        key: Option<[u8; 32]>,
    },
    ValidatorClockLoaded {
        generation: u64,
        seq: u64,
        cycle: Option<ValidatorCycle>,
    },
    NetworkStatsLoaded {
        generation: u64,
        seq: u64,
        stats: Option<NetworkStats>,
    },
    AccountInspected {
        generation: u64,
        seq: u64,
        address: String,
        result: Result<AccountInspection, String>,
    },
    AccountTransactionsLoaded {
        generation: u64,
        seq: u64,
        address: String,
        result: Result<AccountTxPage, String>,
    },
    TraceLoaded {
        generation: u64,
        seq: u64,
        transaction_hash: String,
        result: Result<AccountTrace, String>,
    },
    FeeEstimated {
        generation: u64,
        seq: u64,
        estimate: FeeEstimate,
    },
    MaxFeeEstimated {
        generation: u64,
        seq: u64,
        estimate: FeeEstimate,
    },
    FeeEstimateFailed {
        generation: u64,
        seq: u64,
    },
    TransactionsLoaded {
        generation: u64,
        fetch_id: u64,
        head_refresh_only: bool,
        events: Vec<ActivityEvent>,
        integrity_error: Option<String>,
        incomplete: bool,
        gap: bool,
        deepest_lt: Option<u64>,
    },
    EndpointHistoryScanned {
        generation: u64,
        fetch_id: u64,
        head_refresh_only: bool,
        observations: Vec<EndpointTransactionEvidence>,
        scan_start_before_lt: Option<u64>,
        scan_stop_at: Option<u64>,
        scan_age_cutoff: Option<u64>,
        continuation_before_lt: Option<u64>,
        deepest_lt: Option<u64>,
        gap: bool,
    },
    RiskContextLoaded {
        generation: u64,
        authorization_digest: Digest32,
        snapshot: WalletSnapshot,
    },
    RiskContextFailed {
        generation: u64,
        authorization_digest: Digest32,
        error: String,
    },
    EndpointTested {
        for_network: i32,
        url: String,
        reachable: bool,
        reported_network_id: Option<i32>,
        matches_wallet: bool,
        error: Option<String>,
    },
    SwapPoolLoaded {
        generation: u64,
        seq: u64,
        snapshot: PoolSnapshot,
    },
    SwapPoolFailed {
        generation: u64,
        seq: u64,
        error: String,
    },
    SwapFinished {
        generation: u64,
        result: Result<BroadcastDispatch, ChainError>,
    },
    StorageLoaded {
        generation: u64,
        seq: u64,
        snapshot: StorageSnapshot,
    },
    StorageLoadFailed {
        generation: u64,
        seq: u64,
        error: String,
    },
    StorageFinished {
        generation: u64,
        op: StorageOp,
        result: Result<BroadcastDispatch, ChainError>,
    },
    Error(String),
}

/// An external message this wallet put on the wire, and when it went. Both the
/// swap and the storage pages hand one back so the row it becomes in Activity
/// can be told how long the chain took to accept it.
#[derive(Debug)]
pub struct BroadcastDispatch {
    pub outcome: CandidateBroadcastOutcome,
    pub ext_msg_hash: Digest32,
    pub broadcast_started_at: Instant,
}
