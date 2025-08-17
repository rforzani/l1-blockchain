// src/mempool/mod.rs

use crate::types::Transaction;

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

/// Lightweight ids so we don't pass big structs around.
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
}

/// What the selector returns to the block builder.
#[derive(Clone, Debug)]
pub struct BlockCandidate {
    /// Commits & Avails go into the block's "transactions" area.
    pub txs: Vec<Transaction>,
    /// Reveals go into the block's "reveals" area (separate ordering).
    pub reveals: Vec<Transaction>,
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
    fn insert_commit(&self, _tx: Transaction) -> Result<TxId, AdmissionError> { todo!() }
    fn insert_avail(&self, _tx: Transaction) -> Result<TxId, AdmissionError> { todo!() }
    fn insert_reveal(&self, _tx: Transaction) -> Result<TxId, AdmissionError> { todo!() }

    fn select_block(
        &self,
        _state: &dyn StateView,
        _limits: BlockSelectionLimits,
    ) -> Result<BlockCandidate, SelectError> { todo!() }

    /// Mark included txs after a block is finalized, so we can evict them.
    fn mark_included(&self, _txs: &[TxId], _height: u64) { todo!() }

    /// Periodic cleanup (TTL, windows, etc.).
    fn evict_stale(&self, _current_height: u64) { todo!() }
}