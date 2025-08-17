// src/mempool/mod.rs

#![allow(dead_code)]

use std::sync::{Arc, RwLock};

use crate::types::{Tx, RevealTx};
pub mod queues;
pub mod select;

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
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
                q.insert_commit_minimal(&c, current_height, fee_bid)
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
        _limits: BlockSelectionLimits,
    ) -> Result<BlockCandidate, SelectError> {
        // Minimal logic: enforce Inclusion List only.
        // If any due+available commitment lacks a reveal in the mempool, return InclusionListUnmet.
        let height = state.current_height();
        let il = state.commitments_due_and_available(height);

        let q = self.queues.read().unwrap();
        let mut missing = Vec::new();
        for c in il {
            let have_any = q.reveals.by_commitment.get(&c).map(|m| !m.is_empty()).unwrap_or(false);
            if !have_any {
                missing.push(c);
            }
        }

        if !missing.is_empty() {
            return Err(SelectError::InclusionListUnmet { missing });
        }

        // For now return an empty candidate; we'll fill it in the next step.
        Ok(BlockCandidate { txs: Vec::new(), reveals: Vec::new() })
    }

    fn mark_included(&self, _txs: &[TxId], _height: u64) {
        // no-op for now
    }

    fn evict_stale(&self, _current_height: u64) {
        // no-op for now
    }
}
