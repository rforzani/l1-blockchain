// src/node.rs
use crate::mempool::{BalanceView, Mempool, MempoolImpl};
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

pub struct Node {
    pub chain: Chain,
    pub balances: Balances,
    pub nonces: Nonces,
    pub commitments: Commitments,
    pub available: Available,
    pub mempool: Arc<MempoolImpl>,
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

    /// Apply a block, then clean the mempool using the latest fees & balances.
    pub fn apply_block_and_maintain(&mut self, block: &Block) -> Result<BlockResult, BlockError> {
        let res = self.chain.apply_block(
            block,
            &mut self.balances,
            &mut self.nonces,
            &mut self.commitments,
            &mut self.available,
        )?;

        // 1) Drop entries that can no longer afford the *current* base fees
        let view = StateBalanceView { balances: &self.balances };
        self.mempool.revalidate_affordability(&view, &self.chain.fee_state);

        // 2) Usual upkeep (TTL, reveal windows, etc.)
        self.mempool.evict_stale(self.chain.height);

        Ok(res)
    }
}
