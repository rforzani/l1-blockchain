//src/chain.rs

use crate::stf::{process_block, BlockResult, BlockError};
use crate::state::{Balances, Commitments, Nonces};
use crate::types::{Block, Hash};
use crate::verify::verify_block_roots;

pub struct Chain {
    pub tip_hash: Hash,
    pub height: u64,
}

impl Chain {
    pub fn new() -> Self {
        Self { tip_hash: [0u8;32], height: 0 }
    }

    // Returns BlockResult on success (so caller can inspect roots, receipts, etc.)
    pub fn apply_block(
        &mut self,
        block: &Block,
        balances: &mut Balances,
        nonces: &mut Nonces,
        commitments: &mut Commitments
    ) -> Result<BlockResult, BlockError> {
        // 1) basic height check
        if block.block_number != self.height + 1 {
            return Err(BlockError::BadHeight {
                expected: self.height + 1,
                got: block.block_number,
            });
        }

        let mut sim_balances = balances.clone();
        let mut sim_nonces = nonces.clone();
        let mut sim_commitments = commitments.clone();

        // 2) process with current tip as parent
        let res = process_block(block, &mut sim_balances, &mut sim_nonces, &mut sim_commitments, &self.tip_hash)?;

        // Parent guard: the block we just built must link to our tip
        if res.header.parent_hash != self.tip_hash {
            return Err(BlockError::HeaderMismatch(
                format!(
                    "parent mismatch: expected {}, got {}",
                    hex::encode(self.tip_hash),
                    hex::encode(res.header.parent_hash),
                )
            ));
        }

        verify_block_roots(&res.header, block, &res.receipts).map_err(|e| BlockError::RootMismatch(e))?;

        *balances = sim_balances;
        *nonces = sim_nonces;
        *commitments = sim_commitments;

        // 3) advance tip
        self.tip_hash = res.block_hash;
        self.height = block.block_number;
        Ok(res)
    }
}

#[cfg(test)]

#[test]
fn apply_block1_advances_tip() {
    use std::collections::HashMap;
    use crate::chain::Chain;
    use crate::state::{Balances, Nonces, Commitments};
    use crate::types::{Block, Tx, CommitTx, Hash, AccessList, StateKey};

    // 1) state
    let mut balances: Balances = HashMap::from([
        ("Alice".to_string(), 100), // enough to pay COMMIT_FEE
    ]);
    let mut nonces: Nonces = Default::default();
    let mut comm: Commitments = Default::default();

    // 2) chain (genesis)
    let mut chain = Chain::new();
    assert_eq!(chain.height, 0);
    assert_eq!(chain.tip_hash, [0u8; 32]);

    let al = AccessList {
        reads: vec![ StateKey::Balance("Alice".into())],
        writes: vec![ StateKey::Balance("Alice".into())],
    };

    // 3) block #1 with a single Commit (plain transfers are disabled)
    let commitment: Hash = [1u8; 32];
    let b1 = Block::new(
        vec![Tx::Commit(CommitTx {
            commitment,
            expires_at: 5,
            sender: "Alice".into(),
            access_list: al
        })],
        1,
    );

    // 4) apply
    let res = chain
        .apply_block(&b1, &mut balances, &mut nonces, &mut comm)
        .expect("block 1 should apply");

    // 5) asserts
    assert_eq!(chain.height, 1);
    assert_eq!(chain.tip_hash, res.block_hash);
    assert_eq!(res.header.height, 1);
    assert_eq!(res.header.parent_hash, [0u8; 32]);
}

#[test]
fn applying_same_height_fails() {
    use crate::state::{Balances, Nonces, Commitments};
    use crate::types::Block;

    let mut balances: Balances = Default::default();
    let mut nonces: Nonces = Default::default();
    let mut comm: Commitments = Default::default();
    let mut chain = Chain::new();

    // apply block 1
    let b1 = Block::new(Vec::new(), 1);
    chain.apply_block(&b1, &mut balances, &mut nonces, &mut comm).expect("b1 ok");

    // try another block numbered 1
    let b1_again = Block::new(Vec::new(), 1);
    let err = chain.apply_block(&b1_again, &mut balances, &mut nonces, &mut comm).expect_err("should fail on bad height");

    assert!(err == BlockError::BadHeight { expected: 2, got: 1 }, "got err: {}", err);
}

#[test]
fn applying_2_blocks_works_correctly() {
    use std::collections::HashMap;
    use crate::chain::Chain;
    use crate::state::{Balances, Nonces, Commitments};
    use crate::types::{Block, Transaction, Tx, CommitTx, RevealTx, Hash, StateKey, AccessList};
    use crate::codec::tx_bytes;
    use crate::crypto::commitment_hash;

    // Inner tx to be revealed in block 2
    let tx = Transaction::transfer("Alice", "Bob", 10, 0);
    let salt: Hash = [3u8; 32];
    let cmt = commitment_hash(&tx_bytes(&tx), &salt);

    let al = AccessList {
        reads: vec![ StateKey::Balance("Alice".into()),  StateKey::Balance("Bob".into()), StateKey::Nonce("Alice".into()) ],
        writes: vec![ StateKey::Balance("Alice".into()),  StateKey::Balance("Bob".into()), StateKey::Nonce("Alice".into()) ],
    };

    // Block 1: commit
    let b1 = Block::new(
        vec![Tx::Commit(CommitTx {
            commitment: cmt,
            expires_at: 5,
            sender: "Alice".into(),
            access_list: al
        })],
        1,
    );

    // Block 2: reveal (executes the inner transfer)
    let b2 = Block::new(
        vec![Tx::Reveal(RevealTx {
            tx: tx.clone(),
            salt,
            sender: "Alice".into(),
        })],
        2,
    );

    let mut chain = Chain::new();
    let mut balances: Balances = HashMap::from([
        ("Alice".to_string(), 100),
        ("Bob".to_string(), 50),
    ]);
    let mut nonces: Nonces = Default::default();
    let mut comm: Commitments = Default::default();

    let res1 = chain.apply_block(&b1, &mut balances, &mut nonces, &mut comm).expect("b1 ok");
    let res2 = chain.apply_block(&b2, &mut balances, &mut nonces, &mut comm).expect("b2 ok");

    assert_eq!(chain.height, 2);
    assert_eq!(res2.header.parent_hash, res1.block_hash);
}

#[test]
fn tamper_block_no_state_change() {
    use std::collections::HashMap;
    use crate::state::{Balances, Nonces, Commitments, COMMIT_FEE};
    use crate::types::{Block, Tx, CommitTx, Hash, AccessList, StateKey};
    use crate::stf::process_block;
    use crate::verify::verify_block_roots;

    // Genesis parent
    let parent: Hash = [0u8; 32];

    let al = AccessList {
        reads: vec![ StateKey::Balance("Alice".into())],
        writes: vec![ StateKey::Balance("Alice".into())],
    };

    // Build a simple block at height 1 with a single Commit
    let commitment: Hash = [9u8; 32];
    let block = Block::new(
        vec![Tx::Commit(CommitTx {
            commitment,
            expires_at: 5,
            sender: "Alice".into(),
            access_list: al
        })],
        1,
    );

    // Local state for execution
    let mut balances: Balances = HashMap::from([
        ("Alice".to_string(), 100), // can pay COMMIT_FEE
    ]);
    let mut nonces: Nonces = Default::default();
    let mut commitments: Commitments = Default::default();

    // Build block results (builder path)
    let res = process_block(&block, &mut balances, &mut nonces, &mut commitments, &parent)
        .expect("ok");

    // Sanity: commit fee burned, nonce unchanged (optional)
    assert_eq!(balances["Alice"], 100 - COMMIT_FEE);
    assert_eq!(*nonces.get("Alice").unwrap_or(&0), 0);

    // Tamper the header we 'received' from the network
    let mut bad_header = res.header.clone();
    bad_header.receipts_root[0] ^= 1; // flip one bit

    // Verify should now fail
    let err = verify_block_roots(&bad_header, &block, &res.receipts)
        .expect_err("verification must fail on header tamper");
    assert!(err.contains("mismatch"));
}