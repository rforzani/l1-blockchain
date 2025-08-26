// src/rpc.rs
use axum::{routing::{get, post}, Router, extract::{Path, State}, Json};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use hex;
use crate::node::Node;
use crate::types::{CommitTx, AvailTx, RevealTx, Transaction, AccessList, StateKey};
use crate::mempool::AdmissionError;

#[derive(Clone)]
pub struct AppState {
    pub node: Arc<Mutex<Node>>,
}

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
        .route("/balance/:addr", get(balance))
        .route("/mempool/commit", post(submit_commit))
        .route("/mempool/avail",  post(submit_avail))
        .route("/mempool/reveal", post(submit_reveal))
        .with_state(state)
}

async fn health() -> &'static str { "ok" }

async fn status(State(state): State<AppState>) -> Json<StatusResp> {
    let node = state.node.lock().unwrap();
    let tip = hex::encode(node.tip_hash());
    Json(StatusResp { height: node.height(), tip })
}

async fn balance(State(state): State<AppState>, Path(addr): Path<String>) -> Json<BalanceResp> {
    let node = state.node.lock().unwrap();
    Json(BalanceResp { address: addr.clone(), balance: node.balance_of(&addr) })
}

async fn submit_commit(State(state): State<AppState>, Json(req): Json<CommitReq>) -> Result<Json<SubmitResp>, (StatusCode, String)> {
    let mut al = AccessList { reads: to_state_keys(req.access_list.reads), writes: to_state_keys(req.access_list.writes) };
    al.canonicalize();

    let commit = CommitTx {
        commitment:      hex32(&req.commitment),
        sender:          req.sender,
        access_list:     al,
        ciphertext_hash: hex32(&req.ciphertext_hash),
        pubkey:          hex32(&req.pubkey),
        sig:             hex64(&req.sig),
    };

    let fee = req.fee_bid.unwrap_or(1);
    let node = state.node.lock().unwrap();
    let txid = node.rpc_insert_commit(commit, fee).map_err(adm_err)?;
    Ok(Json(SubmitResp { txid: hex::encode(txid.0) }))
}

async fn submit_avail(State(state): State<AppState>, Json(req): Json<AvailReq>) -> Result<Json<SubmitResp>, (StatusCode, String)> {
    let avail = AvailTx {
        commitment: hex32(&req.commitment),
        sender:     req.sender,
        pubkey:     hex32(&req.pubkey),
        sig:        hex64(&req.sig),
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

fn adm_err(e: AdmissionError) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, format!("admission error: {:?}", e))
}