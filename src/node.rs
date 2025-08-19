// src/node.rs
use crate::mempool::{BalanceView, BlockSelectionLimits, CommitmentId, Mempool, MempoolImpl, SelectError, StateView, TxId};
use crate::state::{Balances, Nonces, Commitments, Available};
use crate::chain::{Chain};
use crate::types::Block;
use crate::stf::{BlockResult, BlockError};
use std::sync::Arc;

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
    HeaderBuild(String),
    StateUnavailable,
}

pub struct Node {
    pub chain: Chain,
    pub balances: Balances,
    pub nonces: Nonces,
    pub commitments: Commitments,
    pub available: Available,
    pub mempool: Arc<MempoolImpl>,
}

struct NodeStateView<'a> {
    height: u64,
    nonces: &'a Nonces,
    mempool: &'a MempoolImpl,
}

impl<'a> StateView for NodeStateView<'a> {
    fn current_height(&self) -> u64 {
        self.height
    }

    fn commitments_due_and_available(&self, _h: u64) -> Vec<CommitmentId> {
        // TODO: hook real inclusion list when you have it.
        Vec::new()
    }

    fn reveal_nonce_required(&self, sender: &str) -> u64 {
        // Pull from your node-held on-chain nonces map.
        *self.nonces.get(sender).unwrap_or(&0)
    }

    fn commit_on_chain(&self, _c: CommitmentId) -> bool {
        // TODO: ask Chain when implemented. Tests run fine with `true` for now.
        true
    }

    fn avail_on_chain(&self, _c: CommitmentId) -> bool {
        // TODO: implement when Avail indexing lands. Default `false`.
        false
    }

    fn avail_allowed_at(&self, _height: u64, _c: CommitmentId) -> bool {
        // If you later enforce availability windows on-chain, wire it here.
        true
    }

    fn pending_commit_room(&self, sender: &str) -> u32 {
        // Keep selection honest w.r.t per-account pending cap using mempool’s own counter.
        // (Add the two tiny read-only accessors below if you don't already have them.)
        let used = self.mempool.pending_commits_for_sender(sender);
        self.mempool.config().max_pending_commits_per_account.saturating_sub(used)
    }
}

impl Node {
    pub fn new(mempool: Arc<MempoolImpl>) -> Self {
        Self {
            chain: Chain::new(),
            balances: Default::default(),
            nonces: Default::default(),
            commitments: Default::default(),
            available: Default::default(),
            mempool,
        }
    }

    /// Build exactly one block from the current head and mempool.
    /// Reads chain/mempool, does not mutate state.
    pub fn produce_one_block(&self, limits: BlockSelectionLimits) -> Result<BuiltBlock, ProduceError> {
        // 1) Build a minimal state view from what Node already has.
        let sv = NodeStateView {
            height: self.chain.height,
            nonces: &self.nonces,
            mempool: &self.mempool,
        };
    
        // 2) Ask mempool to select candidates.
        let cand = self.mempool
            .select_block(&sv, limits)
            .map_err(ProduceError::Selection)?;
    
        // 3) Assemble the block header/body
        let block = Block {
            block_number: self.chain.height + 1,
            transactions: cand.txs.clone(),
            reveals: cand.reveals.clone(),
        };
    
        // 4) Return the block plus the precise IDs for mark_included.
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
    ) -> Result<(BuiltBlock, BlockResult), ProduceError> {
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
