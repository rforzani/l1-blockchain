// src/mempool/queues.rs

use std::collections::hash_map::Entry;
use std::collections::{HashMap, BTreeMap};

use crate::types::Hash;
use crate::mempool::{TxId, CommitmentId};
use crate::codec::{tx_enum_bytes, tx_bytes, access_list_bytes};
use crate::crypto::{hash_bytes_sha256, commitment_hash, is_hex_addr};
use crate::state::{CHAIN_ID, MAX_AL_READS, MAX_AL_WRITES};
use crate::types::{Tx, CommitTx, AvailTx, RevealTx, StateKey};
use super::AdmissionError;

/// --- Queue item shapes ---
/// These are small, immutable records we store once a tx passes basic prechecks.
/// We keep only what's needed for fast selection; the full tx stays elsewhere if needed.

/// A queued Commit (owner-signed)
pub struct CommitQueueItem {
    pub id: TxId,
    pub commitment: CommitmentId,   // equals the on-chain commitment
    pub sender: String,             // "0x..." hex
    pub access_list_digest: Hash,   // hash of canonical AL bytes
    pub fee_bid: u128,              // placeholder for future fee markets
    pub arrival_height: u64,        // when the node first saw it
}

/// A queued Avail (owner-signed)
pub struct AvailQueueItem {
    pub id: TxId,
    pub commitment: CommitmentId,
    pub sender: String,             // must match commitment owner (STF enforces)
    pub ready_at: u64,              // height when avail becomes valid
    pub fee_bid: u128,
    pub arrival_height: u64,
}

/// A queued Reveal (block-body item)
pub struct RevealQueueItem {
    pub id: TxId,
    pub commitment: CommitmentId,   // recomputed from (tx_bytes, AL, salt)
    pub sender: String,             // must equal tx.from (STF enforces)
    pub nonce: u64,                 // tx.nonce (needed for ordering)
    pub access_list_digest: Hash,   // digest used when recomputing commitment
    pub fee_bid: u128,
    pub arrival_height: u64,
}

/// Enum to introspect what was evicted
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvictKind { Commit, Avail, Reveal, None }

/// --- Minimal indices (no behavior yet) ---
/// We'll flesh these out later; for now they make types visible and compile.

pub struct CommitQueue {
    /// primary storage
    pub by_id: HashMap<TxId, CommitQueueItem>,
    /// lookup by commitment
    pub by_commitment: HashMap<CommitmentId, TxId>,
    /// fee-ordered view for greedy selection (negated fee to sort desc via BTreeMap ascending order)
    pub fee_order: BTreeMap<(i128, String), TxId>, // key: (-fee_bid as i128, sender)
    /// pending commits per owner
    pub pending_per_owner: HashMap<String, usize>,
    /// transaction payload mapped to its id
    pub payload_by_id: HashMap<TxId, CommitTx>,

}

pub struct AvailQueue {
    pub by_id: HashMap<TxId, AvailQueueItem>,
    pub by_commitment: HashMap<CommitmentId, TxId>,
    pub fee_order: BTreeMap<(i128, String), TxId>,
    pub payload_by_id: HashMap<TxId, AvailTx>,
}

pub struct RevealQueue {
    pub by_id: HashMap<TxId, RevealQueueItem>,
    /// All reveals for a commitment, ordered by (sender, nonce)
    pub by_commitment: HashMap<CommitmentId, BTreeMap<(String, u64), TxId>>,
    /// fee-ordered view for extra (non-mandatory) reveals
    pub fee_order: BTreeMap<(i128, String, u64), TxId>, // (-fee, sender, nonce)
    /// transaction payload mapped to its id
    pub payload_by_id: HashMap<TxId, RevealTx>,
}

/// A tiny helper to build TxId from any bytes (stable 32-byte hash).
/// We'll use this during admission.
pub fn txid_from(bytes: &[u8]) -> TxId {
    TxId(hash_bytes_sha256(bytes))
}

/// Lightweight container holding all three queues.
/// (We won't implement methods yet.)
pub struct Queues {
    pub commits: CommitQueue,
    pub avails:  AvailQueue,
    pub reveals: RevealQueue,
}

impl CommitQueueItem {
    fn key_for_fee_order(&self) -> (i128, String) {
        (-(self.fee_bid as i128), self.sender.clone())
    }
}
impl AvailQueueItem {
    fn key_for_fee_order(&self) -> (i128, String) {
        (-(self.fee_bid as i128), self.sender.clone())
    }
}
impl RevealQueueItem {
    fn key_for_fee_order(&self) -> (i128, String, u64) {
        (-(self.fee_bid as i128), self.sender.clone(), self.nonce)
    }
}

impl Queues {
    fn precheck_commit(&self, c: &CommitTx, max_pending: u32) -> Result<(), AdmissionError> {
        if !is_hex_addr(&c.sender) {
            return Err(AdmissionError::InvalidSignature);
        }
        if c.access_list.reads.len() > MAX_AL_READS || c.access_list.writes.len() > MAX_AL_WRITES {
            return Err(AdmissionError::BadAccessList);
        }
        for k in c.access_list.reads.iter().chain(c.access_list.writes.iter()) {
            let addr = match k {
                StateKey::Balance(a) | StateKey::Nonce(a) => a,
            };
            if !is_hex_addr(addr) {
                return Err(AdmissionError::BadAccessList);
            }
        }
        let bal = StateKey::Balance(c.sender.clone());
        let nonce = StateKey::Nonce(c.sender.clone());
        let reads = &c.access_list.reads;
        let writes = &c.access_list.writes;
        let has_req = reads.contains(&bal) && writes.contains(&bal) && reads.contains(&nonce) && writes.contains(&nonce);
        if !has_req {
            return Err(AdmissionError::BadAccessList);
        }
        let cnt = self.commits.pending_per_owner.get(&c.sender).copied().unwrap_or(0);
        if cnt >= max_pending as usize {
            return Err(AdmissionError::MempoolFullForAccount);
        }
        if self.commits.by_commitment.contains_key(&CommitmentId(c.commitment)) {
            return Err(AdmissionError::Duplicate);
        }
        Ok(())
    }

    fn precheck_avail(&self, a: &AvailTx) -> Result<(), AdmissionError> {
        if !is_hex_addr(&a.sender) {
            return Err(AdmissionError::InvalidSignature);
        }
        if self.avails.by_commitment.contains_key(&CommitmentId(a.commitment)) {
            return Err(AdmissionError::Duplicate);
        }
        Ok(())
    }

    fn precheck_reveal(&self, r: &RevealTx, cmt: &Hash) -> Result<(), AdmissionError> {
        if r.sender != r.tx.from {
            return Err(AdmissionError::InvalidSignature);
        }
        if !self
            .commits
            .by_commitment
            .contains_key(&CommitmentId(*cmt))
        {
            return Err(AdmissionError::MismatchedCommitment);
        }
        if r.tx.access_list.reads.len() > MAX_AL_READS
            || r.tx.access_list.writes.len() > MAX_AL_WRITES
        {
            return Err(AdmissionError::BadAccessList);
        }
        Ok(())
    }

    /// Insert a Commit into the indexes after prechecking.
    pub fn insert_commit_minimal(&mut self, c: &CommitTx, current_height: u64, fee_bid: u128, max_pending: u32) -> Result<TxId, AdmissionError> {
        self.precheck_commit(c, max_pending)?;

        let enc = tx_enum_bytes(&Tx::Commit(c.clone()));
        let id = txid_from(&enc);

        let al_bytes = access_list_bytes(&c.access_list);
        let al_digest = hash_bytes_sha256(&al_bytes);

        let item = CommitQueueItem {
            id,
            commitment: CommitmentId(c.commitment),
            sender: c.sender.clone(),
            access_list_digest: al_digest,
            fee_bid,
            arrival_height: current_height,
        };

        self.commits.by_commitment.insert(CommitmentId(c.commitment), id);
        self.commits.fee_order.insert(item.key_for_fee_order(), id);
        self.commits.by_id.insert(id, item);
        *self.commits.pending_per_owner.entry(c.sender.clone()).or_insert(0) += 1;
        self.commits.payload_by_id.insert(id, c.clone());
        Ok(id)
    }

    /// Insert an Avail. We don't compute ready_at here (need state); set it to current_height for now.
    pub fn insert_avail_minimal(&mut self, a: &AvailTx, current_height: u64, fee_bid: u128) -> Result<TxId, AdmissionError> {
        self.precheck_avail(a)?;

        let enc = tx_enum_bytes(&Tx::Avail(a.clone()));
        let id = txid_from(&enc);

        let item = AvailQueueItem {
            id,
            commitment: CommitmentId(a.commitment),
            sender: a.sender.clone(),
            ready_at: current_height,
            fee_bid,
            arrival_height: current_height,
        };

        self.avails.by_commitment.insert(CommitmentId(a.commitment), id);
        self.avails.fee_order.insert(item.key_for_fee_order(), id);
        self.avails.by_id.insert(id, item);
        self.avails.payload_by_id.insert(id, a.clone());
        Ok(id)
    }

    /// Insert a Reveal. We compute the commitment from (tx_bytes, AL bytes, salt) the same way the STF does.
    pub fn insert_reveal_minimal(&mut self, r: &RevealTx, current_height: u64, fee_bid: u128) -> Result<TxId, AdmissionError> {
        let mut buf = tx_bytes(&r.tx);
        buf.extend_from_slice(&r.salt);
        let id = txid_from(&buf);

        let tx_ser = tx_bytes(&r.tx);
        let al_bytes = access_list_bytes(&r.tx.access_list);
        let cmt = commitment_hash(&tx_ser, &al_bytes, &r.salt, CHAIN_ID);

        self.precheck_reveal(r, &cmt)?;

        let al_digest = hash_bytes_sha256(&al_bytes);

        let item = RevealQueueItem {
            id,
            commitment: CommitmentId(cmt),
            sender: r.sender.clone(),
            nonce: r.tx.nonce,
            access_list_digest: al_digest,
            fee_bid,
            arrival_height: current_height,
        };

        self.reveals
            .by_commitment
            .entry(CommitmentId(cmt))
            .or_insert_with(BTreeMap::new)
            .insert((item.sender.clone(), item.nonce), id);

        self.reveals.fee_order.insert(item.key_for_fee_order(), id);
        self.reveals.by_id.insert(id, item);
        self.reveals.payload_by_id.insert(id, r.clone());
        Ok(id)
    }

    pub fn evict_any(&mut self, id: &crate::mempool::TxId) -> EvictKind {
        if self.commits.evict_by_id(id) {
            EvictKind::Commit
        } else if self.avails.evict_by_id(id) {
            EvictKind::Avail
        } else if self.reveals.evict_by_id(id) {
            EvictKind::Reveal
        } else {
            EvictKind::None
        }
    }
}

impl CommitQueue {
    pub fn purge_older_than(&mut self, current_height: u64, ttl_blocks: u32) -> usize {
        let cutoff = current_height.saturating_sub(ttl_blocks as u64);
        let ids: Vec<_> = self
            .by_id
            .iter()
            .filter_map(|(id, item)| (item.arrival_height <= cutoff).then_some(*id))
            .collect();
        for id in &ids {
            let _ = self.evict_by_id(id);
        }
        ids.len()
    }

    /// Remove a commit by TxId from all indices; decrement pending counter.
    pub fn evict_by_id(&mut self, id: &crate::mempool::TxId) -> bool {
        if let Some(item) = self.by_id.remove(id) {
            // secondary indices
            self.by_commitment.remove(&item.commitment);
            self.fee_order.remove(&item.key_for_fee_order());
            self.payload_by_id.remove(id);

            // decrement per-owner pending counter (never underflow)
            if let Entry::Occupied(mut e) = self.pending_per_owner.entry(item.sender) {
                let v = e.get_mut();
                if *v > 0 { *v -= 1; }
                if *v == 0 { e.remove_entry(); }
            }
            true
        } else {
            false
        }
    }
}

impl AvailQueue {
    pub fn purge_older_than(&mut self, current_height: u64, ttl_blocks: u32) -> usize {
        let cutoff = current_height.saturating_sub(ttl_blocks as u64);
        let ids: Vec<_> = self
            .by_id
            .iter()
            .filter_map(|(id, item)| (item.arrival_height <= cutoff).then_some(*id))
            .collect();
        for id in &ids {
            let _ = self.evict_by_id(id);
        }
        ids.len()
    }

    /// Remove an avail by TxId from all indices.
    pub fn evict_by_id(&mut self, id: &crate::mempool::TxId) -> bool {
        if let Some(item) = self.by_id.remove(id) {
            self.by_commitment.remove(&item.commitment);
            self.fee_order.remove(&item.key_for_fee_order());
            self.payload_by_id.remove(id);
            true
        } else {
            false
        }
    }
}

impl RevealQueue {
    /// Remove a reveal by TxId from all indices.
    pub fn evict_by_id(&mut self, id: &crate::mempool::TxId) -> bool {
        if let Some(item) = self.by_id.remove(id) {
            if let Some(tree) = self.by_commitment.get_mut(&item.commitment) {
                tree.remove(&(item.sender.clone(), item.nonce));
                if tree.is_empty() {
                    // Optional: free empty bucket
                    self.by_commitment.remove(&item.commitment);
                }
            }
            self.fee_order.remove(&item.key_for_fee_order());
            self.payload_by_id.remove(id);
            true
        } else {
            false
        }
    }

    pub fn purge_older_than(&mut self, current_height: u64, window_blocks: u32) -> usize {
        let cutoff = current_height.saturating_sub(window_blocks as u64);
        let ids: Vec<_> = self
            .by_id
            .iter()
            .filter_map(|(id, item)| (item.arrival_height <= cutoff).then_some(*id))
            .collect();
        for id in &ids {
            let _ = self.evict_by_id(id);
        }
        ids.len()
    }
}

impl Default for CommitQueue {
    fn default() -> Self {
        Self {
            by_id: HashMap::new(),
            by_commitment: HashMap::new(),
            fee_order: BTreeMap::new(),
            pending_per_owner: HashMap::new(),
            payload_by_id: HashMap::new()
        }
    }
}

impl Default for AvailQueue {
    fn default() -> Self {
        Self {
            by_id: HashMap::new(),
            by_commitment: HashMap::new(),
            fee_order: BTreeMap::new(),
            payload_by_id: HashMap::new()
        }
    }
}

impl Default for RevealQueue {
    fn default() -> Self {
        Self {
            by_id: HashMap::new(),
            by_commitment: HashMap::new(),
            fee_order: BTreeMap::new(),
            payload_by_id: HashMap::new()
        }
    }
}

impl Default for Queues {
    fn default() -> Self {
        Self {
            commits: CommitQueue::default(),
            avails: AvailQueue::default(),
            reveals: RevealQueue::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_queues_are_empty() {
        let q = Queues::default();

        // Commits
        assert!(q.commits.by_id.is_empty());
        assert!(q.commits.by_commitment.is_empty());
        assert!(q.commits.fee_order.is_empty());
        assert!(q.commits.pending_per_owner.is_empty());
        assert!(q.commits.payload_by_id.is_empty());

        // Avails
        assert!(q.avails.by_id.is_empty());
        assert!(q.avails.by_commitment.is_empty());
        assert!(q.avails.fee_order.is_empty());
        assert!(q.avails.payload_by_id.is_empty());

        // Reveals
        assert!(q.reveals.by_id.is_empty());
        assert!(q.reveals.by_commitment.is_empty());
        assert!(q.reveals.fee_order.is_empty());
        assert!(q.reveals.payload_by_id.is_empty());
    }
}
