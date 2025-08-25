use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

use sha2::{Digest, Sha256};

use crate::codec::tx_enum_bytes;
use crate::pos::registry::ValidatorId;
use crate::types::{Tx, Hash};

/// A batch of transactions produced by workers.
#[derive(Clone, Debug)]
pub struct Batch {
    /// Digest identifying this batch.
    pub id: Hash,
    /// Transactions carried by this batch.
    pub txs: Vec<Tx>,
    /// Parent batch digests forming a DAG.
    pub parents: Vec<Hash>,
    /// Worker/validator that produced the batch.
    pub producer_id: ValidatorId,
    /// Signature attesting to the batch contents.
    pub signature: [u8; 64],
}

impl Batch {
    /// Construct a new batch, deriving its id as a SHA256 digest of the
    /// transactions, parent digests, producer id and signature.
    pub fn new(txs: Vec<Tx>, parents: Vec<Hash>, producer_id: ValidatorId, signature: [u8; 64]) -> Self {
        let mut hasher = Sha256::new();
        for tx in &txs {
            hasher.update(tx_enum_bytes(tx));
        }
        for p in &parents {
            hasher.update(p);
        }
        hasher.update(producer_id.to_le_bytes());
        hasher.update(signature);
        let id: Hash = hasher.finalize().into();
        Self { id, txs, parents, producer_id, signature }
    }
}

/// In-memory storage for batches forming a DAG. The store keeps only the
/// payloads locally; consensus blocks reference batches by digest.
#[derive(Default)]
pub struct BatchStore {
    batches: RwLock<HashMap<Hash, Batch>>,            // id -> batch
    children: RwLock<HashMap<Hash, HashSet<Hash>>>,   // parent -> {child ids}
}

impl BatchStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a batch and wire it into the parent/child DAG. Existing batches
    /// are replaced.
    pub fn insert(&self, batch: Batch) {
        let id = batch.id;
        {
            let mut b = self.batches.write().unwrap();
            b.insert(id, batch.clone());
        }
        if !batch.parents.is_empty() {
            let mut children = self.children.write().unwrap();
            for p in &batch.parents {
                children.entry(*p).or_default().insert(id);
            }
        }
    }

    /// Fetch a batch by digest.
    pub fn get(&self, id: &Hash) -> Option<Batch> {
        self.batches.read().unwrap().get(id).cloned()
    }

    /// Return children digests for a given parent digest.
    pub fn children_of(&self, id: &Hash) -> Vec<Hash> {
        self.children
            .read()
            .unwrap()
            .get(id)
            .cloned()
            .map(|s| s.into_iter().collect())
            .unwrap_or_default()
    }
}
