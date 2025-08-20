//src/chain.rs

use crate::codec::{header_bytes, header_signing_bytes};
use crate::crypto::{addr_from_pubkey, addr_hex, hash_bytes_sha256, verify_ed25519};
use crate::fees::{update_commit_base, update_exec_base, FeeState, FEE_PARAMS};
use crate::stf::{process_block, BlockResult, BlockError};
use crate::state::{Available, Balances, Commitments, Nonces, DECRYPTION_DELAY, REVEAL_WINDOW, ZERO_ADDRESS};
use crate::types::{Block, Event, Hash, Receipt};
use crate::verify::verify_block_roots;
use std::collections::{HashMap, HashSet, BTreeMap};

pub struct Chain {
    pub tip_hash: Hash,
    pub height: u64,
    pub fee_state: FeeState,
    pub burned_total: u64,
    commit_included_at: HashMap<Hash, u64>,
    avail_included: HashSet<Hash>,
    avail_due: BTreeMap<u64, Vec<Hash>>,
    commit_deadline: HashMap<Hash, u64>,
}

pub struct ApplyResult {
    pub receipts: Vec<Receipt>,
    pub gas_total: u64,
    pub events: Vec<Event>,
    pub exec_reveals_used: u32,
    pub commits_used: u32,
}

impl Chain {
    pub fn new() -> Self {
        Self {
            tip_hash: [0u8;32],
            height: 0,
            fee_state: FeeState::from_defaults(),
            burned_total: 0,
            commit_included_at: HashMap::new(),
            avail_included: HashSet::new(),
            avail_due: BTreeMap::new(),
            commit_deadline: HashMap::new(),
        }
    }

    pub fn apply_block(
        &mut self,
        block: &Block,
        balances: &mut Balances,
        nonces: &mut Nonces,
        commitments: &mut Commitments,
        available: &mut Available,
    ) -> Result<ApplyResult, BlockError> {
        // basic height check
        if block.header.height != self.height + 1 {
            return Err(BlockError::BadHeight {
                expected: self.height + 1,
                got: block.header.height,
            });
        }

        // Parent guard: the block we just built must link to our tip
        if block.header.parent_hash != self.tip_hash {
            return Err(BlockError::HeaderMismatch(
                format!(
                    "parent mismatch: expected {}, got {}",
                    hex::encode(self.tip_hash),
                    hex::encode(block.header.parent_hash),
                )
            ));
        }

        // Signature verification
        {
            let preimage = header_signing_bytes(&block.header);
            let ok = verify_ed25519(
                &block.header.proposer_pubkey,
                &block.header.signature,
                &preimage,
            );
            if !ok {
                return Err(BlockError::IntrinsicInvalid("bad block signature".into()));
            }
        }

        let mut sim_balances = balances.clone();
        let mut sim_nonces = nonces.clone();
        let mut sim_commitments = commitments.clone();
        let mut sim_available = available.clone();

        let proposer_addr = addr_hex(&addr_from_pubkey(&block.header.proposer_pubkey));

        // process with current tip as parent
        let res = process_block(
            block,
            &mut sim_balances,
            &mut sim_nonces,
            &mut sim_commitments,
            &mut sim_available,
            &self.fee_state,
            &proposer_addr,
            &mut self.burned_total,
        )?;

        verify_block_roots(&block.header, block, &res.receipts)
            .map_err(BlockError::RootMismatch)?;

        *balances = sim_balances;
        *nonces = sim_nonces;
        *commitments = sim_commitments;
        *available = sim_available;

        for ev in &res.events {
            match ev {
                Event::CommitStored { commitment, .. } => {
                    self.commit_included_at.insert(*commitment, block.header.height);
                }
                Event::AvailabilityRecorded { commitment } => {
                    if let Some(&inc) = self.commit_included_at.get(commitment) {
                        let ready_at = inc + DECRYPTION_DELAY;
                        let deadline = ready_at + REVEAL_WINDOW;
                        self.avail_included.insert(*commitment);
                        self.commit_deadline.insert(*commitment, deadline);
                        self.avail_due.entry(deadline).or_default().push(*commitment);
                    }
                }
                Event::CommitConsumed { commitment } | Event::CommitExpired { commitment } => {
                    if let Some(deadline) = self.commit_deadline.remove(commitment) {
                        if let Some(vec) = self.avail_due.get_mut(&deadline) {
                            vec.retain(|c| c != commitment);
                            if vec.is_empty() {
                                self.avail_due.remove(&deadline);
                            }
                        }
                    }
                }
            }
        }

        let next_exec = update_exec_base(
            self.fee_state.exec_base,
            res.exec_reveals_used,
            FEE_PARAMS.exec_target_reveals_per_block,
            FEE_PARAMS.exec_max_change_denominator,
            FEE_PARAMS.exec_min_base,
            FEE_PARAMS.exec_damping_bps,
        );

        // 3) update self state
        self.tip_hash = hash_bytes_sha256(&header_bytes(&block.header));
        self.height = block.header.height;
        self.fee_state.exec_base = next_exec;
        self.fee_state.commit_base = update_commit_base(
            self.fee_state.commit_base,
            res.commits_used,
        );
        Ok(ApplyResult { receipts: res.receipts, gas_total: res.gas_total, events: res.events, exec_reveals_used: res.exec_reveals_used, commits_used: res.commits_used })
    }

    /// Check if a commitment has been included on-chain.
    pub fn commit_on_chain(&self, c: &Hash) -> bool {
        self.commit_included_at.contains_key(c)
    }

    /// Check if an Avail for the commitment has been included.
    pub fn avail_on_chain(&self, c: &Hash) -> bool {
        self.avail_included.contains(c)
    }

    /// Whether an Avail is allowed at `height` for commitment `c`.
    pub fn avail_allowed_at(&self, height: u64, c: &Hash) -> bool {
        if let Some(&included_at) = self.commit_included_at.get(c) {
            let ready_at = included_at + DECRYPTION_DELAY;
            let deadline = ready_at + REVEAL_WINDOW;
            height >= ready_at && height <= deadline
        } else {
            false
        }
    }

    /// Commitments that are due (deadline == `height`) and already available.
    pub fn commitments_due_and_available(&self, height: u64) -> Vec<Hash> {
        self.avail_due.get(&height).cloned().unwrap_or_default()
    }
}

#[cfg(test)]

mod tests {
    use super::*;
}