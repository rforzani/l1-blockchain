// src/mempool/mod.rs

#![allow(dead_code)]

use std::{collections::HashSet, sync::{Arc, RwLock}};

use crate::types::{Tx, RevealTx};
pub mod queues;
pub mod select;
mod tests;

#[derive(Clone, Debug)]
pub struct MempoolConfig {
    pub max_avails_per_block: u32,
    pub max_reveals_per_block: u32,
    pub max_commits_per_block: u32,
    pub max_pending_commits_per_account: u32,
    pub commit_ttl_blocks: u32,
    pub reveal_window_blocks: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TxId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CommitmentId(pub [u8; 32]);

/// Errors that can happen when adding a tx to the mempool (admission).
#[derive(Clone, Debug)]
pub enum AdmissionError {
    InvalidSignature,
    BadAccessList,
    NonceGap,
    MempoolFullForAccount,
    TooLarge,
    Duplicate,
    Stale,
    NotYetValid,
    MismatchedCommitment,
    WrongTxType, // <-- if insert_* gets the wrong variant
}

/// What the selector returns to the block builder.
#[derive(Clone, Debug)]
pub struct BlockCandidate {
    /// Commits & Avails go into the block's "transactions" area.
    pub txs: Vec<Tx>,
    /// Reveals go into the block's "reveals" area (separate ordering).
    pub reveals: Vec<RevealTx>,
}

/// Per-block caps (slot-based for now; we'll add gas later).
#[derive(Clone, Copy, Debug)]
pub struct BlockSelectionLimits {
    pub max_avails: u32,
    pub max_reveals: u32,
    pub max_commits: u32,
}

/// Read-only view of chain state needed by selection (your node implements this).
pub trait StateView: Send + Sync {
    fn current_height(&self) -> u64;

    /// Return commitments that are BOTH due and available at `height`.
    fn commitments_due_and_available(&self, height: u64) -> Vec<CommitmentId>;

    /// For a sender address (hex "0x…"), what's the next required nonce for reveals?
    fn reveal_nonce_required(&self, sender: &str) -> u64;
}

/// Errors that can happen during block selection.
#[derive(Debug)]
pub enum SelectError {
    /// Inclusion list couldn't be satisfied because some reveals are missing.
    InclusionListUnmet { missing: Vec<CommitmentId> },
    /// Nothing in the mempool was eligible to build a block.
    NothingToDo,
}

/// Public mempool interface. Implementations live behind this trait.
pub trait Mempool: Send + Sync {
    /// Typed inserts with admission context.
    fn insert_commit(&self, tx: Tx, current_height: u64, fee_bid: u128) -> Result<TxId, AdmissionError>;
    fn insert_avail(&self,  tx: Tx, current_height: u64, fee_bid: u128) -> Result<TxId, AdmissionError>;
    fn insert_reveal(&self, tx: RevealTx, current_height: u64, fee_bid: u128) -> Result<TxId, AdmissionError>;

    fn select_block(
        &self,
        state: &dyn StateView,
        limits: BlockSelectionLimits,
    ) -> Result<BlockCandidate, SelectError>;

    /// Mark included txs after a block is finalized, so we can evict them.
    fn mark_included(&self, _txs: &[TxId], _height: u64);

    /// Periodic cleanup (TTL, windows, etc.).
    fn evict_stale(&self, _current_height: u64);
}

/// --------------------- Simple in-memory implementation ---------------------

pub struct MempoolImpl {
    config: MempoolConfig,
    queues: RwLock<queues::Queues>,
}

impl MempoolImpl {
    pub fn new(config: MempoolConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            queues: RwLock::new(queues::Queues::default()),
        })
    }
}

impl Mempool for MempoolImpl {
    fn insert_commit(&self, tx: Tx, current_height: u64, fee_bid: u128) -> Result<TxId, AdmissionError> {
        match tx {
            Tx::Commit(c) => {
                let mut q = self.queues.write().unwrap();
                q.insert_commit_minimal(&c, current_height, fee_bid, self.config.max_pending_commits_per_account)
            }
            _ => Err(AdmissionError::WrongTxType),
        }
    }

    fn insert_avail(&self, tx: Tx, current_height: u64, fee_bid: u128) -> Result<TxId, AdmissionError> {
        match tx {
            Tx::Avail(a) => {
                let mut q = self.queues.write().unwrap();
                q.insert_avail_minimal(&a, current_height, fee_bid)
            }
            _ => Err(AdmissionError::WrongTxType),
        }
    }

    fn insert_reveal(&self, r: RevealTx, current_height: u64, fee_bid: u128) -> Result<TxId, AdmissionError> {
        let mut q = self.queues.write().unwrap();
        q.insert_reveal_minimal(&r, current_height, fee_bid)
    }

    fn select_block(
        &self,
        state: &dyn StateView,
        limits: BlockSelectionLimits,
    ) -> Result<BlockCandidate, SelectError> {
        // Assumption: StateView returns IL in canonical, deterministic order.
        let height = state.current_height();
        let il = state.commitments_due_and_available(height);
    
        let q = self.queues.read().expect("mempool queues poisoned");
    
        // --- Mandatory reveals for IL ---
    
        // Early fail if any IL commitment lacks a reveal.
        let mut missing = Vec::new();
        for c in &il {
            let have_any = q.reveals.by_commitment.get(c).map(|m| !m.is_empty()).unwrap_or(false);
            if !have_any {
                missing.push(*c);
            }
        }
        if !missing.is_empty() {
            return Err(SelectError::InclusionListUnmet { missing });
        }
    
        // Pick the *respective* reveal for each IL commitment deterministically.
        let mut reveals = Vec::with_capacity(il.len());
        for c in &il {
            let map = q.reveals.by_commitment.get(c).expect("exists and non-empty");
            let (_, txid) = map.iter().next().expect("non-empty map");
            match q.reveals.payload_by_id.get(txid) {
                Some(reveal) => reveals.push(reveal.clone()),
                None => return Err(SelectError::InclusionListUnmet { missing: vec![*c] }),
            }
        }
    
        // Enforce reveal cap: IL must fit entirely.
        if (reveals.len() as u32) > limits.max_reveals {
            return Err(SelectError::InclusionListUnmet { missing: il });
        }
    
        // --- Avails: ready_at <= height, fee-desc order, skip IL commitments ---
    
        // Build a small skip set of IL commitments.
        let il_set: HashSet<_> = il.iter().copied().collect();
    
        let mut txs: Vec<Tx> = Vec::new();
        let mut avails_added: u32 = 0;
    
        if limits.max_avails > 0 {
            // fee_order key = (neg_fee, sender). Iteration is highest-fee-first by construction.
            for (_, txid) in q.avails.fee_order.iter() {
                if avails_added >= limits.max_avails {
                    break;
                }
                // Peek metadata to check eligibility.
                let meta = match q.avails.by_id.get(txid) {
                    Some(m) => m,
                    None => continue, // inconsistent index; skip defensively
                };
                // Skip if this commitment is already due/available (IL), or not yet ready.
                if il_set.contains(&meta.commitment) || meta.ready_at > height {
                    continue;
                }
                // Fetch payload and push.
                if let Some(avail) = q.avails.payload_by_id.get(txid) {
                    txs.push(Tx::Avail(avail.clone()));
                    avails_added += 1;
                }
            }
        }

        // --- Commits: fee-desc order, deterministic tiebreakers ---

        let mut commits_added: u32 = 0;

        if limits.max_commits > 0 {
            // fee_order key = (neg_fee, sender). Iteration is highest-fee-first by construction.
            for (_, txid) in q.commits.fee_order.iter() {
                if commits_added >= limits.max_commits {
                    break;
                }
                // Fetch payload; skip if any index inconsistency.
                if let Some(commit_tx) = q.commits.payload_by_id.get(txid) {
                    // (Optional future: consult StateView for per-account pending limit)
                    txs.push(Tx::Commit(commit_tx.clone()));
                    commits_added += 1;
                }
            }
        }
    
        Ok(BlockCandidate { txs, reveals })
    }
    

    fn mark_included(&self, _txs: &[TxId], _height: u64) {
        // no-op for now
    }

    fn evict_stale(&self, _current_height: u64) {
        // no-op for now
    }
}
