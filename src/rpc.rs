// src/rpc.rs
use axum::{routing::{get, post}, Router, extract::{Path, State}, Json};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use hex;
use crate::node::Node;
use crate::types::{CommitTx, AvailTx, RevealTx, Transaction, AccessList, StateKey};
use crate::mempool::AdmissionError;
use std::collections::HashMap;
use time::OffsetDateTime;

#[derive(Serialize)]
struct StatusResp {
    height: u64,
    tip: String,
}

#[derive(Serialize)]
struct BalanceResp {
    address: String,
    balance: u64,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum AccessKey {
    Balance { address: String },
    Nonce   { address: String },
}

#[derive(Deserialize)]
struct AccessListReq {
    reads:  Vec<AccessKey>,
    writes: Vec<AccessKey>,
}

#[derive(Clone)]
pub struct AppState {
    pub node: std::sync::Arc<std::sync::Mutex<crate::node::Node>>,
    pub faucet: std::sync::Arc<std::sync::Mutex<FaucetLimiter>>,
}

#[derive(Debug)]
pub struct FaucetLimiter {
    daily_limit: u64,
    // addr(lowercased) -> (day_index, used_today)
    book: HashMap<String, (u64, u64)>,
}

#[derive(Deserialize)]
struct FaucetReq {
    address: String,
    // optional; if omitted, defaults to 100_000
    amount: Option<u64>,
}

#[derive(Serialize)]
struct FaucetResp {
    credited: u64,
    balance: u64,
    day_used: u64,
    day_limit: u64,
}

impl FaucetLimiter {
    pub fn new(daily_limit: u64) -> Self {
        Self { daily_limit, book: HashMap::new() }
    }
    fn today() -> u64 {
        (OffsetDateTime::now_utc().unix_timestamp() / 86_400) as u64
    }
    pub fn try_reserve(&mut self, addr: &str, amount: u64) -> Result<(), String> {
        let today = Self::today();
        let key = addr.to_lowercase();
        let entry = self.book.entry(key).or_insert((today, 0));
        if entry.0 != today {
            entry.0 = today;
            entry.1 = 0;
        }
        let used = entry.1;
        if used.saturating_add(amount) > self.daily_limit {
            return Err(format!("daily limit exceeded: used {used}, request {amount}, limit {}", self.daily_limit));
        }
        entry.1 = used + amount;
        Ok(())
    }
}

fn to_state_keys(v: Vec<AccessKey>) -> Vec<StateKey> {
    v.into_iter().map(|k| match k {
        AccessKey::Balance { address } => StateKey::Balance(address),
        AccessKey::Nonce   { address } => StateKey::Nonce(address),
    }).collect()
}

#[derive(Deserialize)]
struct CommitReq {
    commitment: String,
    sender: String,
    access_list: AccessListReq,
    ciphertext_hash: String,
    pubkey: String,           
    sig: String,              
    fee_bid: Option<u128>,
}

#[derive(Deserialize)]
struct AvailReq {
    commitment: String,
    sender: String,
    pubkey: String, // hex 32
    sig: String,    // hex 64
    fee_bid: Option<u128>,
}

#[derive(Deserialize)]
struct RevealReq {
    from: String,
    to: String,
    amount: u64,
    nonce: u64,
    salt: String,     
    sender: String,
    fee_bid: Option<u128>,
}

#[derive(Serialize)]
struct SubmitResp { txid: String }

fn hex32(s: &str) -> [u8; 32] {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let mut out = [0u8; 32];
    let bytes = hex::decode(s).expect("bad hex");
    assert!(bytes.len() == 32, "need 32 bytes");
    out.copy_from_slice(&bytes);
    out
}

fn hex64(s: &str) -> [u8; 64] {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let mut out = [0u8; 64];
    let bytes = hex::decode(s).expect("bad hex");
    assert!(bytes.len() == 64, "need 64 bytes");
    out.copy_from_slice(&bytes);
    out
}

fn hex48(s: &str) -> [u8; 48] {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let mut out = [0u8; 48];
    let bytes = hex::decode(s).expect("bad hex");
    assert!(bytes.len() == 48, "need 48 bytes");
    out.copy_from_slice(&bytes);
    out
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/status", get(status))
        .route("/consensus", get(consensus_status))
        // Debug endpoints
        .route("/debug/mempool", get(debug_mempool))
        .route("/debug/hotstuff", get(debug_hotstuff))
        .route("/debug/block_store", get(debug_block_store))
        .route("/debug/pending_commits", get(debug_pending_commits))
        .route("/debug/leader", get(debug_leader))
        .route("/debug/last_apply_error", get(debug_last_apply_error))
        .route("/balance/:addr", get(balance))
        .route("/mempool/commit", post(submit_commit))
        .route("/mempool/avail",  post(submit_avail))
        .route("/mempool/reveal", post(submit_reveal))
        .route("/faucet/claim",   post(faucet_claim))
        .with_state(state)
}

async fn health() -> &'static str { "ok" }

async fn status(State(state): State<AppState>) -> Json<StatusResp> {
    let node = state.node.lock().unwrap();
    let tip = hex::encode(node.tip_hash());
    Json(StatusResp { height: node.height(), tip })
}

#[derive(Serialize)]
struct ConsensusStatusResp {
    enabled: bool,
    validator_id: Option<u64>,
    view: Option<u64>,
    high_qc_view: Option<u64>,
    locked_view: Option<u64>,
    locked_block: Option<String>,
    pacemaker_base_timeout_ms: Option<u64>,
    pacemaker_current_timeout_ms: Option<u64>,
    p2p_peer_id: Option<String>,
    connected_peers: Option<usize>,
}

async fn consensus_status(State(state): State<AppState>) -> Json<ConsensusStatusResp> {
    let node = state.node.lock().unwrap();
    let mut resp = ConsensusStatusResp {
        enabled: false,
        validator_id: None,
        view: None,
        high_qc_view: None,
        locked_view: None,
        locked_block: None,
        pacemaker_base_timeout_ms: None,
        pacemaker_current_timeout_ms: None,
        p2p_peer_id: None,
        connected_peers: None,
    };

    if let Some(hs) = node.hotstuff() {
        resp.enabled = true;
        resp.validator_id = Some(hs.validator_id as u64);
        resp.view = Some(hs.state.current_view);
        resp.high_qc_view = Some(hs.state.high_qc.view);
        resp.locked_view = Some(hs.state.locked_block.1);
        resp.locked_block = Some(hex::encode(hs.state.locked_block.0));
        resp.pacemaker_base_timeout_ms = Some(hs.state.pacemaker.base_timeout_ms);
        resp.pacemaker_current_timeout_ms = Some(hs.state.pacemaker.current_timeout_ms);
    }

    if let Some(net) = node.consensus_network() {
        resp.p2p_peer_id = Some(net.peer_id().to_string());
        resp.connected_peers = Some(net.connected_peers());
    }

    Json(resp)
}

async fn balance(State(state): State<AppState>, Path(addr): Path<String>) -> Json<BalanceResp> {
    let node = state.node.lock().unwrap();
    Json(BalanceResp { address: addr.clone(), balance: node.balance_of(&addr) })
}

// --------------- Debug endpoints ---------------

#[derive(Serialize)]
struct MempoolDebugResp {
    commits: usize,
    avails: usize,
    reveals: usize,
}

async fn debug_mempool(State(state): State<AppState>) -> Json<MempoolDebugResp> {
    let node = state.node.lock().unwrap();
    let (commits, avails, reveals) = node.debug_mempool_counts();
    Json(MempoolDebugResp { commits, avails, reveals })
}

#[derive(Serialize)]
struct AggregatorEntryResp {
    view: u64,
    block_id: String,
    votes: usize,
    quorum: usize,
}

#[derive(Serialize)]
struct HotStuffDebugResp {
    current_view: Option<u64>,
    high_qc_view: Option<u64>,
    locked_view: Option<u64>,
    validator_id: Option<u64>,
    aggregators: Vec<AggregatorEntryResp>,
    parent_index_len: Option<usize>,
}

async fn debug_hotstuff(State(state): State<AppState>) -> Json<HotStuffDebugResp> {
    let node = state.node.lock().unwrap();
    let mut resp = HotStuffDebugResp {
        current_view: None,
        high_qc_view: None,
        locked_view: None,
        validator_id: None,
        aggregators: Vec::new(),
        parent_index_len: None,
    };
    if let Some(hs) = node.hotstuff() {
        resp.current_view = Some(hs.state.current_view);
        resp.high_qc_view = Some(hs.state.high_qc.view);
        resp.locked_view = Some(hs.state.locked_block.1);
        resp.validator_id = Some(hs.validator_id as u64);
        resp.parent_index_len = node.debug_parent_index_len();
    }
    if let Some(entries) = node.debug_hotstuff_aggregators() {
        for (view, bid, votes, quorum) in entries {
            resp.aggregators.push(AggregatorEntryResp { view, block_id: hex::encode(bid), votes, quorum });
        }
    }
    Json(resp)
}

#[derive(Serialize)]
struct BlockStoreEntryResp {
    id: String,
    height: u64,
    view: u64,
    parent: String,
    justify_view: u64,
}

#[derive(Serialize)]
struct BlockStoreDebugResp {
    total: usize,
    sample: Vec<BlockStoreEntryResp>,
}

async fn debug_block_store(State(state): State<AppState>) -> Json<BlockStoreDebugResp> {
    let node = state.node.lock().unwrap();
    let sample = node.debug_block_store_sample(20);
    let mut out = Vec::new();
    for (id, h, v, parent, jv) in sample {
        out.push(BlockStoreEntryResp { id: hex::encode(id), height: h, view: v, parent: hex::encode(parent), justify_view: jv });
    }
    Json(BlockStoreDebugResp { total: out.len(), sample: out })
}

#[derive(Serialize)]
struct PendingCommitsResp { commits: Vec<String> }

async fn debug_pending_commits(State(state): State<AppState>) -> Json<PendingCommitsResp> {
    let node = state.node.lock().unwrap();
    let commits = node.debug_pending_commits().into_iter().map(|h| hex::encode(h)).collect();
    Json(PendingCommitsResp { commits })
}

#[derive(Serialize)]
struct LeaderDebugResp {
    current_view: Option<u64>,
    leader_id: Option<u64>,
    mine: Option<u64>,
    last_proposed_view: Option<u64>,
}

async fn debug_leader(State(state): State<AppState>) -> Json<LeaderDebugResp> {
    let node = state.node.lock().unwrap();
    let mut resp = LeaderDebugResp { current_view: None, leader_id: None, mine: None, last_proposed_view: node.debug_last_proposed_view() };
    if let Some(hs) = node.hotstuff() {
        let n = hs.validator_pks.len();
        let leader = crate::p2p::simple_leader_election(hs.state.current_view, n);
        resp.current_view = Some(hs.state.current_view);
        resp.leader_id = Some(leader as u64);
        resp.mine = Some(hs.validator_id as u64);
    }
    Json(resp)
}

#[derive(Serialize)]
struct LastApplyErrorResp { error: Option<String> }

async fn debug_last_apply_error(State(state): State<AppState>) -> Json<LastApplyErrorResp> {
    let node = state.node.lock().unwrap();
    Json(LastApplyErrorResp { error: node.debug_last_apply_error() })
}

async fn submit_commit(State(state): State<AppState>, Json(req): Json<CommitReq>) -> Result<Json<SubmitResp>, (StatusCode, String)> {
    let mut al = AccessList { reads: to_state_keys(req.access_list.reads), writes: to_state_keys(req.access_list.writes) };
    al.canonicalize();

    // Create a mock encrypted payload for RPC testing
    // In production, this should come from the request or be computed properly
    let mock_encrypted_payload = crate::mempool::encrypted::ThresholdCiphertext {
        ephemeral_pk: [0u8; 48],
        encrypted_data: hex::decode(&req.ciphertext_hash).unwrap_or_else(|_| vec![0u8; 64]),
        tag: [0u8; 32],
        epoch: 0, // Should be set to current epoch
    };
    
    let commit = CommitTx {
        commitment:        hex32(&req.commitment),
        sender:            req.sender,
        access_list:       al,
        encrypted_payload: mock_encrypted_payload,
        pubkey:            hex32(&req.pubkey),
        sig:               hex64(&req.sig),
    };

    let fee = req.fee_bid.unwrap_or(1);
    let node = state.node.lock().unwrap();
    let txid = node.rpc_insert_commit(commit, fee).map_err(adm_err)?;
    Ok(Json(SubmitResp { txid: hex::encode(txid.0) }))
}

async fn submit_avail(State(state): State<AppState>, Json(req): Json<AvailReq>) -> Result<Json<SubmitResp>, (StatusCode, String)> {
    let avail = AvailTx {
        commitment:   hex32(&req.commitment),
        sender:       req.sender,
        payload_hash: [0u8; 32], // Mock payload hash - should be computed from actual encrypted payload
        payload_size: 64,        // Mock payload size
        pubkey:       hex32(&req.pubkey),
        sig:          hex64(&req.sig),
    };
    let fee = req.fee_bid.unwrap_or(1);
    let node = state.node.lock().unwrap();
    let txid = node.rpc_insert_avail(avail, fee).map_err(adm_err)?;
    Ok(Json(SubmitResp { txid: hex::encode(txid.0) }))
}

async fn submit_reveal(State(state): State<AppState>, Json(req): Json<RevealReq>) -> Result<Json<SubmitResp>, (StatusCode, String)> {
    let tx = Transaction::transfer(&req.from, &req.to, req.amount, req.nonce);
    let reveal = RevealTx { tx, salt: hex32(&req.salt), sender: req.sender };
    let fee = req.fee_bid.unwrap_or(1);
    let node = state.node.lock().unwrap();
    let txid = node.rpc_insert_reveal(reveal, fee).map_err(adm_err)?;
    Ok(Json(SubmitResp { txid: hex::encode(txid.0) }))
}

// POST /faucet/claim  {"address":"0x....","amount":12345}
async fn faucet_claim(
    axum::extract::State(state): axum::extract::State<AppState>,
    axum::Json(req): axum::Json<FaucetReq>,
) -> Result<axum::Json<FaucetResp>, (StatusCode, String)> {
    let amount = req.amount.unwrap_or(100_000);
    if amount == 0 {
        return Err((StatusCode::BAD_REQUEST, "amount must be > 0".into()));
    }

    // rate-limit accounting
    let (used_after, limit) = {
        let mut limiter = state.faucet.lock().unwrap();
        limiter.try_reserve(&req.address, amount)
            .map_err(|e| (StatusCode::TOO_MANY_REQUESTS, e))?;
        // read back the “used today”
        let key = req.address.to_lowercase();
        let (day, used) = *limiter.book.get(&key).unwrap();
        (used, limiter.daily_limit)
    };

    // credit balance directly
    let new_balance = {
        let mut node = state.node.lock().unwrap();
        node.credit_balance_direct(&req.address, amount)
    };

    Ok(axum::Json(FaucetResp {
        credited: amount,
        balance: new_balance,
        day_used: used_after,
        day_limit: limit,
    }))
}

fn adm_err(e: AdmissionError) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, format!("admission error: {:?}", e))
}
