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

    fn simulate_block(
        &self,
        limits: BlockSelectionLimits,
    ) -> Result<(BuiltBlock, ApplyResult, Balances, Nonces, Commitments, Available, u64), ProduceError> {
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
        let mut sim_burned_total = self.chain.burned_total;

        // Use your STF function that returns body results (roots, receipts, gas, counts, events)
        let body = process_block(
            &block,
            &mut sim_balances,
            &mut sim_nonces,
            &mut sim_commitments,
            &mut sim_available,
            &self.chain.fee_state,
            &proposer_addr,
            &mut sim_burned_total,
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

        let apply = ApplyResult {
            receipts: body.receipts.clone(),
            gas_total: body.gas_total,
            events: body.events.clone(),
            exec_reveals_used: body.exec_reveals_used,
            commits_used: body.commits_used,
            burned_total: sim_burned_total
        };

        Ok((
            BuiltBlock {
                block,
                selected_ids: SelectedIds {
                    commit: cand.commit_ids,
                    avail:  cand.avail_ids,
                    reveal: cand.reveal_ids,
                },
            },
            apply,
            sim_balances,
            sim_nonces,
            sim_commitments,
            sim_available,
            sim_burned_total,
        ))
    }

    pub fn produce_block(
        &mut self,
        limits: BlockSelectionLimits,
    ) -> Result<(BuiltBlock, ApplyResult), ProduceError> {
        let (
            built,
            apply,
            balances,
            nonces,
            commitments,
            available,
            burned_total,
        ) = self.simulate_block(limits)?;

        let res = self.chain
            .commit_simulated_block(
                &built.block,
                apply.clone(),
                balances.clone(),
                nonces.clone(),
                commitments.clone(),
                available.clone(),
            )
            .map_err(|e| ProduceError::HeaderBuild(format!("commit failed: {e:?}")))?;

        self.balances = balances;
        self.nonces = nonces;
        self.commitments = commitments;
        self.available = available;
        let _ = burned_total; // state already applied via commit_simulated_block

        let all_ids: Vec<TxId> = built
            .selected_ids
            .commit.iter()
            .chain(&built.selected_ids.avail)
            .chain(&built.selected_ids.reveal)
            .cloned()
            .collect();
        self.mempool.mark_included(&all_ids, self.chain.height);

        let view = StateBalanceView { balances: &self.balances };
        self.mempool.revalidate_affordability(&view, &self.chain.fee_state);
        self.mempool.evict_stale(self.chain.height);

        Ok((built, res))
    }

    #[deprecated(note = "use produce_block")]
    pub fn produce_one_block(
        &self,
        limits: BlockSelectionLimits,
    ) -> Result<BuiltBlock, ProduceError> {
        let (built, _, _, _, _, _, _) = self.simulate_block(limits)?;
        Ok(built)
    }

    #[deprecated(note = "use produce_block")]
    pub fn produce_and_apply_once(
        &mut self,
        limits: BlockSelectionLimits,
    ) -> Result<(BuiltBlock, ApplyResult), ProduceError> {
        self.produce_block(limits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
use crate::mempool::{MempoolConfig, BlockSelectionLimits, BalanceView};
use crate::fees::FeeState;
use crate::types::{Transaction, Tx, CommitTx, RevealTx, Address};
use crate::stf::PROCESS_BLOCK_CALLS;
    use crate::codec::{tx_bytes, access_list_bytes, string_bytes};
    use crate::crypto::{commitment_hash, commit_signing_preimage, addr_from_pubkey, addr_hex};

    struct TestBalanceView;
    impl BalanceView for TestBalanceView {
        fn balance_of(&self, _who: &Address) -> u64 { u64::MAX }
    }

    fn addr(i: u8) -> String {
        format!("0x{:02x}{:02x}000000000000000000000000000000000000", i, i)
    }

    fn make_pair(signer: &SigningKey, nonce: u64) -> (CommitTx, RevealTx) {
        let sender = addr_hex(&addr_from_pubkey(&signer.verifying_key().to_bytes()));
        let tx = Transaction::transfer(&sender, &addr(200), 1, nonce);
        let mut salt = [0u8; 32];
        salt[0] = 7; salt[1] = 7;
        let tx_ser = tx_bytes(&tx);
        let al_bytes = access_list_bytes(&tx.access_list);
        let commitment = commitment_hash(&tx_ser, &al_bytes, &salt, crate::state::CHAIN_ID);
        let sender_bytes = string_bytes(&sender);
        let preimage = commit_signing_preimage(
            &commitment,
            &[0u8; 32],
            &sender_bytes,
            &al_bytes,
            crate::state::CHAIN_ID,
        );
        let sig = signer.sign(&preimage).to_bytes();
        let commit = CommitTx {
            commitment,
            sender: sender.clone(),
            access_list: tx.access_list.clone(),
            ciphertext_hash: [0u8; 32],
            pubkey: signer.verifying_key().to_bytes(),
            sig,
        };
        let reveal = RevealTx { tx, salt, sender };
        (commit, reveal)
    }

    #[test]
    fn stale_entries_not_selected() {
        let cfg = MempoolConfig {
            max_avails_per_block: 10,
            max_reveals_per_block: 10,
            max_commits_per_block: 10,
            max_pending_commits_per_account: 10,
            commit_ttl_blocks: 2,
            reveal_window_blocks: 2,
        };
        let mp = MempoolImpl::new(cfg);
        let mut node = Node::new(mp.clone(), SigningKey::from_bytes(&[1u8; 32]));

        let bv = TestBalanceView;

        // stale pair at height 0
        let sk1 = SigningKey::from_bytes(&[2u8; 32]);
        let _sender1 = addr_hex(&addr_from_pubkey(&sk1.verifying_key().to_bytes()));
        let (c1, r1) = make_pair(&sk1, 0);
        mp.insert_commit(Tx::Commit(c1), 0, 1, &bv, &FeeState::from_defaults()).unwrap();
        mp.insert_reveal(r1, 0, 1, &bv, &FeeState::from_defaults()).unwrap();

        // fresh pair at height 2
        let sk2 = SigningKey::from_bytes(&[3u8; 32]);
        let sender2 = addr_hex(&addr_from_pubkey(&sk2.verifying_key().to_bytes()));
        let (c2, r2) = make_pair(&sk2, 0);
        mp.insert_commit(Tx::Commit(c2.clone()), 2, 1, &bv, &FeeState::from_defaults()).unwrap();
        mp.insert_reveal(r2.clone(), 2, 1, &bv, &FeeState::from_defaults()).unwrap();

        // chain height so first pair is stale
        node.chain.height = 3;
        node.mempool.evict_stale(node.chain.height);

        let sv = NodeStateView { chain: &node.chain, nonces: &node.nonces, mempool: &node.mempool };
        let limits = BlockSelectionLimits { max_avails: 10, max_reveals: 10, max_commits: 10 };
        let cand = node.mempool.select_block(&sv, limits).expect("select");
        assert_eq!(cand.txs.len(), 1);
        assert_eq!(cand.reveals.len(), 1);
        match &cand.txs[0] {
            Tx::Commit(c) => assert_eq!(c.sender, sender2),
            _ => panic!("unexpected tx variant"),
        }
        assert_eq!(cand.reveals[0].sender, sender2);
    }

    #[test]
    fn commit_simulated_block_updates_state() {
        let cfg = MempoolConfig {
            max_avails_per_block: 10,
            max_reveals_per_block: 10,
            max_commits_per_block: 10,
            max_pending_commits_per_account: 10,
            commit_ttl_blocks: 2,
            reveal_window_blocks: 2,
        };
        let mp = MempoolImpl::new(cfg);
        let mut node = Node::new(mp.clone(), SigningKey::from_bytes(&[2u8; 32]));
        let bv = TestBalanceView;
        let tx_sk = SigningKey::from_bytes(&[4u8; 32]);
        let sender = addr_hex(&addr_from_pubkey(&tx_sk.verifying_key().to_bytes()));
        node.set_balance(sender.clone(), 1000);
        let (c, _r) = make_pair(&tx_sk, 0);
        mp.insert_commit(Tx::Commit(c.clone()), 0, 1, &bv, &FeeState::from_defaults()).unwrap();
        let limits = BlockSelectionLimits { max_avails: 10, max_reveals: 10, max_commits: 10 };
        node.produce_block(limits).expect("produce");
        assert_eq!(node.height(), 1);
        assert_eq!(node.balance_of(&sender), 999);
        assert!(node.chain.commit_on_chain(&c.commitment));
    }

    #[test]
    fn process_block_called_once() {
        let cfg = MempoolConfig {
            max_avails_per_block: 10,
            max_reveals_per_block: 10,
            max_commits_per_block: 10,
            max_pending_commits_per_account: 10,
            commit_ttl_blocks: 2,
            reveal_window_blocks: 2,
        };
        let mp = MempoolImpl::new(cfg);
        let mut node = Node::new(mp.clone(), SigningKey::from_bytes(&[3u8; 32]));
        let bv = TestBalanceView;
        let tx_sk = SigningKey::from_bytes(&[5u8; 32]);
        let sender = addr_hex(&addr_from_pubkey(&tx_sk.verifying_key().to_bytes()));
        node.set_balance(sender.clone(), 1000);
        let (c, _r) = make_pair(&tx_sk, 0);
        mp.insert_commit(Tx::Commit(c), 0, 1, &bv, &FeeState::from_defaults()).unwrap();
        PROCESS_BLOCK_CALLS.with(|c| c.set(0));
        let limits = BlockSelectionLimits { max_avails: 10, max_reveals: 10, max_commits: 10 };
        node.produce_block(limits).unwrap();
        PROCESS_BLOCK_CALLS.with(|c| assert_eq!(c.get(), 1));
    }
}
