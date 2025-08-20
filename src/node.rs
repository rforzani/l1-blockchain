// src/node.rs
use crate::mempool::{BalanceView, BlockSelectionLimits, CommitmentId, Mempool, MempoolImpl, SelectError, StateView, TxId};
use crate::state::{Balances, Nonces, Commitments, Available};
use crate::chain::{ApplyResult, Chain};
use crate::stf::process_block;
use crate::types::Block;
use std::sync::Arc;
use ed25519_dalek::{SigningKey, Signer};
use crate::crypto::{addr_from_pubkey, addr_hex};
use crate::codec::header_signing_bytes;
use crate::codec::{receipt_bytes, tx_enum_bytes};
use crate::crypto::hash_bytes_sha256;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct StateBalanceView<'a> {
    balances: &'a Balances,
}

impl<'a> BalanceView for StateBalanceView<'a> {
    fn balance_of(&self, who: &crate::types::Address) -> u64 {
        *self.balances.get(who).unwrap_or(&0)
    }
}

/// The TxIds that were selected for this block, per lane.
pub struct SelectedIds {
    pub commit: Vec<TxId>,
    pub avail:  Vec<TxId>,
    pub reveal: Vec<TxId>,
}

/// The product of block production: a block plus the IDs needed for mark_included.
pub struct BuiltBlock {
    pub block: Block,
    pub selected_ids: SelectedIds,
}

#[derive(Debug)]
pub enum ProduceError {
    Selection(SelectError),
    HeaderBuild(String)
}

pub struct Node {
    chain: Chain,
    balances: Balances,
    nonces: Nonces,
    commitments: Commitments,
    available: Available,
    mempool: Arc<MempoolImpl>,
    // keys for signing the block header
    signer: SigningKey,
    proposer_pubkey: [u8; 32],
}

struct NodeStateView<'a> {
    chain: &'a Chain,
    nonces: &'a Nonces,
    mempool: &'a MempoolImpl,
}

impl<'a> StateView for NodeStateView<'a> {
    fn current_height(&self) -> u64 {
        self.chain.height
    }

    fn commitments_due_and_available(&self, h: u64) -> Vec<CommitmentId> {
        self
            .chain
            .commitments_due_and_available(h)
            .into_iter()
            .map(CommitmentId)
            .collect()
    }

    fn reveal_nonce_required(&self, sender: &str) -> u64 {
        *self.nonces.get(sender).unwrap_or(&0)
    }

    fn commit_on_chain(&self, c: CommitmentId) -> bool {
        self.chain.commit_on_chain(&c.0)
    }

    fn avail_on_chain(&self, c: CommitmentId) -> bool {
        self.chain.avail_on_chain(&c.0)
    }

    fn avail_allowed_at(&self, height: u64, c: CommitmentId) -> bool {
        self.chain.avail_allowed_at(height, &c.0)
    }

    fn pending_commit_room(&self, sender: &str) -> u32 {
        let used = self.mempool.pending_commits_for_sender(sender);
        self.mempool.config().max_pending_commits_per_account.saturating_sub(used)
    }
}

impl Node {
    pub fn new(mempool: Arc<MempoolImpl>, signer: SigningKey) -> Self {
        let proposer_pubkey = signer.verifying_key().to_bytes();
        Self {
            chain: Chain::new(),
            balances: Default::default(),
            nonces: Default::default(),
            commitments: Default::default(),
            available: Default::default(),
            mempool,
            signer,
            proposer_pubkey,
        }
    }

    #[inline]
    fn now_ts() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }

    pub fn height(&self) -> u64 {
        self.chain.height
    }

    pub fn fee_state(&self) -> &crate::fees::FeeState {
        &self.chain.fee_state
    }

    pub fn set_commit_fee_base(&mut self, base: u64) {
        self.chain.fee_state.commit_base = base;
    }

    pub fn burned_total(&self) -> u64 {
        self.chain.burned_total
    }

    pub fn balance_of(&self, who: &str) -> u64 {
        *self.balances.get(who).unwrap_or(&0)
    }

    pub fn set_balance(&mut self, who: String, amount: u64) {
        self.balances.insert(who, amount);
    }

 /// Build exactly one block from the current head and mempool.
    /// Reads chain/mempool, does not mutate state.
    pub fn produce_one_block(&self, limits: BlockSelectionLimits) -> Result<BuiltBlock, ProduceError> {
        // 0) Prune stale items before building any view or selecting.
        if self.chain.height > 0 {
            self.mempool.evict_stale(self.chain.height);
        }

        // 1) State view for selection
        let sv = NodeStateView {
            chain:   &self.chain,
            nonces:  &self.nonces,
            mempool: &self.mempool,
        };

        // 2) Select candidates from mempool
        let cand = self
            .mempool
            .select_block(&sv, limits)
            .map_err(ProduceError::Selection)?;

        let next_height = self.chain.height + 1;

        // 3) Build a block with an unsigned header carrying only fields the STF needs (height).
        //    Roots and gas_used will be computed by STF below and then written into the header.
        let mut block = crate::types::Block {
            header: crate::types::BlockHeader {
                parent_hash:     self.chain.tip_hash,
                height:          next_height,
                proposer_pubkey: self.proposer_pubkey,
                txs_root:        [0u8; 32], // filled after STF run
                receipts_root:   [0u8; 32], // filled after STF run
                gas_used:        0,         // filled after STF run
                randomness:      self.chain.tip_hash, // or your randomness source
                reveal_set_root: [0u8; 32], // filled after STF run
                il_root:         [0u8; 32], // filled after STF run
                exec_base_fee:   self.chain.fee_state.exec_base,
                commit_base_fee: self.chain.fee_state.commit_base,
                avail_base_fee:  self.chain.fee_state.avail_base,
                timestamp:       Self::now_ts(),
                signature:       [0u8; 64], // filled after signing below
            },
            transactions: cand.txs.clone(),
            reveals:      cand.reveals.clone(),
        };

        // 4) Simulate execution to compute canonical roots/gas/receipts (does not mutate Chain)
        let mut sim_balances    = self.balances.clone();
        let mut sim_nonces      = self.nonces.clone();
        let mut sim_commitments = self.commitments.clone();
        let mut sim_available   = self.available.clone();

        // Fee recipient: derive once from our pubkey
        let proposer_addr = addr_hex(&addr_from_pubkey(&self.proposer_pubkey));
        let mut burned_dummy = 0u64;

        // Use your STF function that returns body results (roots, receipts, gas, counts, events)
        let body = process_block(
            &block,
            &mut sim_balances,
            &mut sim_nonces,
            &mut sim_commitments,
            &mut sim_available,
            &self.chain.fee_state,
            &proposer_addr,
            &mut burned_dummy,
        ).map_err(|e| ProduceError::HeaderBuild(format!("body simulation failed: {e:?}")))?;

        // 5) Fill header with the computed roots and gas
        block.header.txs_root        = body.txs_root;
        block.header.receipts_root   = body.receipts_root;
        block.header.reveal_set_root = body.reveal_set_root;
        block.header.il_root         = body.il_root;
        block.header.gas_used        = body.gas_total;

        // 6) Sign the header and attach signature
        let preimage = header_signing_bytes(&block.header);
        let sig      = self.signer.sign(&preimage).to_bytes();
        block.header.signature = sig;

        // 7) Return the fully-formed block + selected IDs (for mark_included after apply)
        Ok(BuiltBlock {
            block,
            selected_ids: SelectedIds {
                commit: cand.commit_ids,
                avail:  cand.avail_ids,
                reveal: cand.reveal_ids,
            },
        })
    }

    pub fn produce_and_apply_once(
        &mut self,
        limits: BlockSelectionLimits,
    ) -> Result<(BuiltBlock, ApplyResult), ProduceError> {
        let built = self.produce_one_block(limits)?;
        // Apply
        let res = self.chain.apply_block(
            &built.block,
            &mut self.balances,
            &mut self.nonces,
            &mut self.commitments,
            &mut self.available,
        ).map_err(|e| ProduceError::HeaderBuild(format!("apply failed: {e:?}")))?;

        // Mark included BEFORE maintenance
        let all_ids: Vec<TxId> = built
            .selected_ids
            .commit.iter()
            .chain(&built.selected_ids.avail)
            .chain(&built.selected_ids.reveal)
            .cloned()
            .collect();
        self.mempool.mark_included(&all_ids, self.chain.height);

        // Maintenance (affordability + TTL) with POST-APPLY balances/fees
        let view = StateBalanceView { balances: &self.balances };
        self.mempool.revalidate_affordability(&view, &self.chain.fee_state);
        self.mempool.evict_stale(self.chain.height);

        Ok((built, res))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

}
