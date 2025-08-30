// src/mempool/mod.rs

use std::sync::{Arc, RwLock};

use crate::codec::{access_list_bytes, tx_bytes};
use crate::crypto::commitment_hash;
use crate::state::CHAIN_ID;
use crate::types::{RevealTx, Tx, Address};
use crate::fees::{FeeState, lane_base, Lane};
pub mod queues;
use queues::{AvailQueue, CommitQueue, RevealQueue};
pub mod workers;
pub use workers::{Batch, BatchStore};
pub mod encrypted;
pub use encrypted::{ThresholdEngine, ThresholdCiphertext, ThresholdShare, ThresholdError};

#[derive(Clone, Debug)]
pub struct MempoolConfig {
    pub max_avails_per_block: u32,
    pub max_reveals_per_block: u32,
    pub max_commits_per_block: u32,
    pub max_pending_commits_per_account: u32,
    pub commit_ttl_blocks: u32,
    pub reveal_window_blocks: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TxId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CommitmentId(pub [u8; 32]);

/// Errors that can happen when adding a tx to the mempool (admission).
pub trait BalanceView {
    fn balance_of(&self, who: &Address) -> u64;
}

#[derive(Clone, Debug, PartialEq, Eq)]
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
    InsufficientBalance { want: u64, have: u64, lane: &'static str },
    WrongTxType, // <-- if insert_* gets the wrong variant
}

#[inline]
fn ensure_affordable(
    view: &dyn BalanceView,
    who: &Address,
    want: u64,
    lane: &'static str,
) -> Result<(), AdmissionError> {
    let have = view.balance_of(who);
    if have < want {
        return Err(AdmissionError::InsufficientBalance { want, have, lane });
    }
    Ok(())
}

/// What the selector returns to the block builder.
#[derive(Clone, Debug)]
pub struct BlockCandidate {
    /// Commits & Avails go into the block's "transactions" area.
    pub txs: Vec<Tx>,
    /// Reveals go into the block's "reveals" area (separate ordering).
    pub reveals: Vec<RevealTx>,

    pub commit_ids: Vec<TxId>,
    pub avail_ids:  Vec<TxId>,
    pub reveal_ids: Vec<TxId>,
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

    /// was the Commit for c included already?
    fn commit_on_chain(&self, c: CommitmentId) -> bool;

    /// was the Avail for c included already?
    fn avail_on_chain(&self, c: CommitmentId) -> bool;

    /// inside [start,end] window?
    fn avail_allowed_at(&self, height: u64, c: CommitmentId) -> bool;

    /// remaining pending-commit slots for sender
    fn pending_commit_room(&self, sender: &str) -> u32;
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
    fn insert_commit(
        &self,
        tx: Tx,
        current_height: u64,
        fee_bid: u128,
        view: &dyn BalanceView,
        fee_state: &FeeState,
    ) -> Result<TxId, AdmissionError>;
    fn insert_avail(
        &self,
        tx: Tx,
        current_height: u64,
        fee_bid: u128,
        view: &dyn BalanceView,
        fee_state: &FeeState,
    ) -> Result<TxId, AdmissionError>;
    fn insert_reveal(
        &self,
        tx: RevealTx,
        current_height: u64,
        fee_bid: u128,
        view: &dyn BalanceView,
        fee_state: &FeeState,
    ) -> Result<TxId, AdmissionError>;

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
    commits: RwLock<CommitQueue>,
    avails: RwLock<AvailQueue>,
    reveals: RwLock<RevealQueue>,
}

/// Minimal view of a queued item exposed to revalidation predicates.
pub struct QueuedItem<'a> {
    pub lane: Lane,
    pub sender: &'a Address,
}

impl MempoolImpl {
    pub fn new(config: MempoolConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            commits: RwLock::new(CommitQueue::default()),
            avails: RwLock::new(AvailQueue::default()),
            reveals: RwLock::new(RevealQueue::default()),
        })
    }

    pub fn pending_commits_for_sender(&self, sender: &str) -> u32 {
        let commits = self.commits.read().unwrap();
        match commits.pending_per_owner.get(sender).copied() {
            Some(v) => u32::try_from(v).unwrap_or(u32::MAX), // saturate if ever > u32::MAX
            None => 0,
        }
    }

    pub fn config(&self) -> &MempoolConfig {
        &self.config
    }

    pub fn debug_read(
        &self,
    ) -> (
        std::sync::RwLockReadGuard<'_, CommitQueue>,
        std::sync::RwLockReadGuard<'_, AvailQueue>,
        std::sync::RwLockReadGuard<'_, RevealQueue>,
    ) {
        (
            self.commits.read().unwrap(),
            self.avails.read().unwrap(),
            self.reveals.read().unwrap(),
        )
    }

    pub fn debug_write(
        &self,
    ) -> (
        std::sync::RwLockWriteGuard<'_, CommitQueue>,
        std::sync::RwLockWriteGuard<'_, AvailQueue>,
        std::sync::RwLockWriteGuard<'_, RevealQueue>,
    ) {
        (
            self.commits.write().unwrap(),
            self.avails.write().unwrap(),
            self.reveals.write().unwrap(),
        )
    }

    /// Generic revalidation that lets the caller decide what "valid" means.
    /// The predicate receives a lightweight item view with lane and sender.
    pub fn revalidate<F>(&self, mut keep: F)
    where
        F: FnMut(QueuedItem<'_>) -> bool,
    {
        {
            let mut q = self.commits.write().unwrap();
            q.retain_by(|sender| keep(QueuedItem { lane: Lane::Commit, sender }));
        }
        {
            let mut q = self.avails.write().unwrap();
            q.retain_by(|sender| keep(QueuedItem { lane: Lane::Avail, sender }));
        }
        {
            let mut q = self.reveals.write().unwrap();
            q.retain_by(|sender| keep(QueuedItem { lane: Lane::Exec, sender }));
        }
    }

    /// Convenience wrapper that drops entries whose owners can't afford the current base fees.
    pub fn revalidate_affordability(&self, view: &dyn BalanceView, fs: &FeeState) {
        self.revalidate(|it| {
            let want = match it.lane {
                Lane::Commit => fs.commit_base,
                Lane::Avail  => fs.avail_base,
                Lane::Exec   => fs.exec_base,
            };
            view.balance_of(it.sender) >= want
        });
    }
}

impl Mempool for MempoolImpl {
    fn insert_commit(
        &self,
        tx: Tx,
        current_height: u64,
        fee_bid: u128,
        view: &dyn BalanceView,
        fee_state: &FeeState,
    ) -> Result<TxId, AdmissionError> {
        let Tx::Commit(c) = tx else { return Err(AdmissionError::WrongTxType) };
        
        // Validate encrypted payload structure
        c.encrypted_payload.verify()
            .map_err(|_| AdmissionError::BadAccessList)?; // Reuse existing error type
        
        // TODO: In production, add epoch validation to ensure the encrypted payload
        // is for the current committee epoch
        
        let want = lane_base(fee_state, Lane::Commit);
        ensure_affordable(view, &c.sender, want, "commit")?;
        let mut commits = self.commits.write().unwrap();
        commits.insert_commit_minimal(
            &c,
            current_height,
            fee_bid,
            self.config.max_pending_commits_per_account,
        )
    }

    fn insert_avail(
        &self,
        tx: Tx,
        current_height: u64,
        fee_bid: u128,
        view: &dyn BalanceView,
        fee_state: &FeeState,
    ) -> Result<TxId, AdmissionError> {
        let Tx::Avail(a) = tx else { return Err(AdmissionError::WrongTxType) };
        
        // Basic payload validation - ensure size is reasonable and hash is non-zero
        if a.payload_size == 0 || a.payload_size > 1_048_576 { // Max 1MB
            return Err(AdmissionError::BadAccessList); // Reuse existing error type
        }
        if a.payload_hash == [0u8; 32] {
            return Err(AdmissionError::BadAccessList); // Payload hash should not be all zeros
        }
        
        let want = lane_base(fee_state, Lane::Avail);
        ensure_affordable(view, &a.sender, want, "avail")?;
        let mut avails = self.avails.write().unwrap();
        avails.insert_avail_minimal(&a, current_height, fee_bid)
    }

    fn insert_reveal(
        &self,
        r: RevealTx,
        current_height: u64,
        fee_bid: u128,
        view: &dyn BalanceView,
        fee_state: &FeeState,
    ) -> Result<TxId, AdmissionError> {
        let want = lane_base(fee_state, Lane::Exec); // reveals pay exec base
        ensure_affordable(view, &r.sender, want, "exec")?;
        let tx_ser = tx_bytes(&r.tx);
        let al_bytes = access_list_bytes(&r.tx.access_list);
        let cmt = commitment_hash(&tx_ser, &al_bytes, &r.salt, CHAIN_ID);

        {
            let commits = self.commits.read().unwrap();
            RevealQueue::precheck_reveal_locked(&commits, &r, &cmt)?;
        }

        let mut reveals = self.reveals.write().unwrap();
        let id = reveals.insert_reveal_minimal(&r, &cmt, current_height, fee_bid);
        Ok(id)
    }

    fn select_block(
        &self,
        state: &dyn StateView,
        limits: BlockSelectionLimits,
    ) -> Result<BlockCandidate, SelectError> {
        // Assumption: StateView returns IL in canonical, deterministic order.
        let height = state.current_height();
        let il = state.commitments_due_and_available(height);

        let commits: std::sync::RwLockReadGuard<'_, CommitQueue> =
            self.commits.read().expect("commit queue poisoned");
        let avails = self.avails.read().expect("avail queue poisoned");
        let reveals = self.reveals.read().expect("reveal queue poisoned");

        // --- Mandatory reveals for IL ---

        // Early fail if any IL commitment lacks a reveal.
        let mut missing = Vec::new();
        for c in &il {
            let have_any = reveals
                .by_commitment
                .get(c)
                .map(|m| !m.is_empty())
                .unwrap_or(false);
            if !have_any {
                missing.push(*c);
            }
        }
        if !missing.is_empty() {
            return Err(SelectError::InclusionListUnmet { missing });
        }

        use std::collections::{HashMap, HashSet};

        let mut next_required: HashMap<String, u64> = HashMap::new();
        let mut selected_ids: HashSet<crate::mempool::TxId> = HashSet::new();
        let mut selected_reveals: Vec<crate::types::RevealTx> = Vec::with_capacity(il.len());
        let mut missing_due_to_nonce: Vec<crate::mempool::CommitmentId> = Vec::new();
        let mut reveal_ids: Vec<TxId> = Vec::new();

        for c in &il {
            // Deterministically inspect the candidate reveals for this commitment.
            // Map: BTreeMap<(sender, nonce), TxId>
            let map = reveals
                .by_commitment
                .get(c)
                .expect("exists and non-empty checked earlier");

            // Choose a sender deterministically: the lexicographically-smallest (sender, nonce) pair.
            let ((sender0, _nonce0), _txid0) = map.iter().next().expect("non-empty");

            // Pull (or fetch) this sender's required nonce
            let req = *next_required
                .entry(sender0.clone())
                .or_insert_with(|| state.reveal_nonce_required(&sender0));

            // We must include the reveal whose (sender == sender0) AND (nonce == req).
            // (Because pre-admission enforces that reveals for a commitment come from the true owner,
            //  all valid entries should share the same sender; this lookup is O(log n) in the BTreeMap.)
            if let Some(txid) = map.get(&(sender0.clone(), req)) {
                match reveals.payload_by_id.get(txid) {
                    Some((r, _cmt)) => {
                        selected_reveals.push(r.clone());
                        selected_ids.insert(*txid);
                        reveal_ids.push(*txid);
                        *next_required.get_mut(sender0.as_str()).unwrap() = req + 1;
                    }
                    None => {
                        tracing::warn!(
                            "mempool: missing payload for IL reveal txid={:?}; skipping",
                            txid
                        );
                        continue;
                    }
                }
            } else {
                missing_due_to_nonce.push(*c);
            }
        }

        // If any IL commitment couldn't be satisfied at the required nonce, selection must fail.
        if !missing_due_to_nonce.is_empty() {
            return Err(SelectError::InclusionListUnmet {
                missing: missing_due_to_nonce,
            });
        }

        // Enforce reveal cap: IL must fit entirely.
        if (selected_reveals.len() as u32) > limits.max_reveals {
            return Err(SelectError::InclusionListUnmet { missing: il });
        }

        // --- Extra (non-IL) reveals with nonce continuity and fee order ---

        let mut remaining = limits
            .max_reveals
            .saturating_sub(selected_reveals.len() as u32);

        if remaining > 0 {
            use std::collections::HashSet;
            let il_set: HashSet<_> = il.iter().copied().collect();

            // selected_ids is already seeded from the IL loop — no extra seeding needed here.

            // Walk global fee_order (highest fee first, deterministic tie-breakers).
            for (_fee_key, txid) in reveals.fee_order.iter() {
                if remaining == 0 {
                    break;
                }
                if selected_ids.contains(txid) {
                    continue;
                }

                let meta = match reveals.by_id.get(txid) {
                    Some(m) => m,
                    None => continue,
                };

                if il_set.contains(&meta.commitment) {
                    continue;
                }

                let req = *next_required
                    .entry(meta.sender.clone())
                    .or_insert_with(|| state.reveal_nonce_required(&meta.sender));

                if meta.nonce != req {
                    continue;
                }

                if let Some((reveal, _cmt)) = reveals.payload_by_id.get(txid) {
                    selected_reveals.push(reveal.clone());
                    selected_ids.insert(*txid);
                    reveal_ids.push(*txid);
                    *next_required.get_mut(&meta.sender).unwrap() = req + 1;
                    remaining -= 1;
                }
            }
        }

        // --- Avails: ready_at <= height, fee-desc order, skip IL commitments ---

        // Build a small skip set of IL commitments.
        let il_set: HashSet<_> = il.iter().copied().collect();

        let mut txs: Vec<Tx> = Vec::new();
        let mut avails_added: u32 = 0;
        let mut avail_ids : Vec<TxId> = Vec::new();

        // Gather all avails whose ready_at is <= height.
        let mut ready_ids = HashSet::new();
        for (_h, set) in avails.ready_index.range(..=height) {
            for txid in set {
                ready_ids.insert(*txid);
            }
        }

        for (_fee_key, txid) in avails.fee_order.iter() {
            if avails_added >= limits.max_avails {
                break;
            }
            if !ready_ids.contains(txid) {
                continue;
            }
            let meta = match avails.by_id.get(txid) {
                Some(m) => m,
                None => continue,
            };
            if il_set.contains(&meta.commitment) {
                continue;
            }

            // STATE VIEW CHECK BEFORE APPENDING AN AVAIL TRANSACTION
            if !state.commit_on_chain(meta.commitment) {
                continue; // skip until commit is on-chain
            }
            if state.avail_on_chain(meta.commitment) {
                continue; // skip duplicate avail
            }
            if !state.avail_allowed_at(height, meta.commitment) {
                continue; // outside allowed window
            }

            if let Some(avail) = avails.payload_by_id.get(txid) {
                txs.push(Tx::Avail(avail.clone()));
                avails_added += 1;
                avail_ids.push(*txid);
            }
        }

        // --- Commits: fee-desc order, deterministic tiebreakers ---

        let mut commits_added: u32 = 0;
        let mut commit_ids : Vec<TxId> = Vec::new();

        if limits.max_commits > 0 {
            // fee_order key = (neg_fee, sender). Iteration is highest-fee-first by construction.
            for (_, txid) in commits.fee_order.iter() {
                if commits_added >= limits.max_commits {
                    break;
                }

                // Fetch payload; skip if any index inconsistency.
                if let Some(commit_tx) = commits.payload_by_id.get(txid) {
                    // Respect per-account pending room exposed by StateView
                    if state.pending_commit_room(&commit_tx.sender) == 0 {
                        continue;
                    }
                    txs.push(Tx::Commit(commit_tx.clone()));
                    commit_ids.push(*txid);
                    commits_added += 1;
                }
            }
        }

        Ok(BlockCandidate {
            txs,
            reveals: selected_reveals,
            commit_ids: commit_ids,
            avail_ids: avail_ids,
            reveal_ids: reveal_ids            
        })
    }

    fn mark_included(&self, txs: &[TxId], _height: u64) {
        let mut commits = self.commits.write().expect("commit queue poisoned");
        let mut avails = self.avails.write().expect("avail queue poisoned");
        let mut reveals = self.reveals.write().expect("reveal queue poisoned");
        for id in txs {
            if commits.evict_by_id(id) {
                continue;
            }
            if avails.evict_by_id(id) {
                continue;
            }
            let _ = reveals.evict_by_id(id);
        }
    }

    fn evict_stale(&self, current_height: u64) {
        // For now we reuse commit_ttl_blocks for Avails too; can be split later.
        let commit_ttl = self.config.commit_ttl_blocks;
        let reveal_win = self.config.reveal_window_blocks;

        let purged_commits = {
            let mut commits = self.commits.write().expect("commit queue poisoned");
            commits.purge_older_than(current_height, commit_ttl)
        };
        let purged_avails = {
            let mut avails = self.avails.write().expect("avail queue poisoned");
            avails.purge_older_than(current_height, commit_ttl)
        };
        let purged_reveals = {
            let mut reveals = self.reveals.write().expect("reveal queue poisoned");
            reveals.purge_older_than(current_height, reveal_win)
        };

        // (Optional) log or trace these counts.
        let _ = (purged_commits, purged_avails, purged_reveals);
    }
}
