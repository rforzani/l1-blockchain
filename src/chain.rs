//src/chain.rs

use crate::stf::{process_block, BlockResult, BlockError};
use crate::state::{Available, Balances, Commitments, Nonces};
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
        commitments: &mut Commitments,
        available: &mut Available,  
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
        let mut sim_available = available.clone();

        // 2) process with current tip as parent
        let res = process_block(block, &mut sim_balances, &mut sim_nonces, &mut sim_commitments, &mut sim_available, &self.tip_hash)?;

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
        *available = sim_available;

        // 3) updsate self state
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
    use crate::state::{Balances, Nonces, Commitments, Available};
    use crate::types::{Block, Tx, CommitTx, Hash, AccessList, StateKey};

    // 1) state
    let mut balances: Balances = HashMap::from([
        ("Alice".to_string(), 100), // enough to pay COMMIT_FEE
    ]);
    let mut nonces: Nonces = Default::default();
    let mut comm: Commitments = Default::default();
    let mut avail: Available  = Default::default();

    // 2) chain (genesis)
    let mut chain = Chain::new();
    assert_eq!(chain.height, 0);
    assert_eq!(chain.tip_hash, [0u8; 32]);

    let al = AccessList {
        reads:  vec![ StateKey::Balance("Alice".into()) ],
        writes: vec![ StateKey::Balance("Alice".into()) ],
    };

    // 3) block #1 with a single Commit
    let commitment: Hash = [1u8; 32];
    let b1 = Block::new(
        vec![Tx::Commit(CommitTx {
            commitment,
            sender: "Alice".into(),
            ciphertext_hash: [0u8; 32],
            access_list: al,
        })],
        1,
    );

    // 4) apply
    let res = chain
        .apply_block(&b1, &mut balances, &mut nonces, &mut comm, &mut avail)
        .expect("block 1 should apply");

    // 5) asserts
    assert_eq!(chain.height, 1);
    assert_eq!(chain.tip_hash, res.block_hash);
    assert_eq!(res.header.height, 1);
    assert_eq!(res.header.parent_hash, [0u8; 32]);
}

#[test]
fn applying_same_height_fails() {
    use crate::chain::Chain;
    use crate::state::{Balances, Nonces, Commitments, Available};
    use crate::types::Block;
    use crate::stf::BlockError;

    let mut balances: Balances = Default::default();
    let mut nonces: Nonces = Default::default();
    let mut comm: Commitments = Default::default();
    let mut avail: Available  = Default::default();
    let mut chain = Chain::new();

    // apply block 1
    let b1 = Block::new(Vec::new(), 1);
    chain
        .apply_block(&b1, &mut balances, &mut nonces, &mut comm, &mut avail)
        .expect("b1 ok");

    // try another block numbered 1
    let b1_again = Block::new(Vec::new(), 1);
    let err = chain
        .apply_block(&b1_again, &mut balances, &mut nonces, &mut comm, &mut avail)
        .expect_err("should fail on bad height");

    match err {
        BlockError::BadHeight { expected, got } => {
            assert_eq!(expected, 2);
            assert_eq!(got, 1);
        }
        other => panic!("expected BadHeight, got {:?}", other),
    }
}

#[test]
fn applying_2_blocks_works_correctly() {
    use std::collections::HashMap;
    use crate::chain::Chain;
    use crate::state::{Balances, Nonces, Commitments, Available, DECRYPTION_DELAY, REVEAL_WINDOW};
    use crate::types::{Block, Transaction, Tx, CommitTx, RevealTx, Hash, StateKey, AccessList, AvailTx};
    use crate::codec::tx_bytes;
    use crate::crypto::commitment_hash;

    // Inner tx to be revealed
    let tx = Transaction::transfer("Alice", "Bob", 10, 0);
    let salt: Hash = [3u8; 32];
    let cmt = commitment_hash(&tx_bytes(&tx), &salt);

    let al = AccessList {
        reads:  vec![ StateKey::Balance("Alice".into()) ],
        writes: vec![ StateKey::Balance("Alice".into()) ],
    };

    // Block 1: commit
    let b1 = Block::new(
        vec![Tx::Commit(CommitTx {
            commitment: cmt,
            sender: "Alice".into(),
            ciphertext_hash: [0u8; 32],
            access_list: al,
        })],
        1,
    );

    // Block ready_at: Avail + Reveal (earliest allowed)
    let ready_at = 1 + DECRYPTION_DELAY;
    let b2 = Block::new(
        vec![
            Tx::Avail(AvailTx { commitment: cmt }),
            Tx::Reveal(RevealTx { tx: tx.clone(), salt, sender: "Alice".into() }),
        ],
        ready_at,
    );

    let mut chain = Chain::new();
    let mut balances: Balances = HashMap::from([
        ("Alice".to_string(), 100),
        ("Bob".to_string(), 50),
    ]);
    let mut nonces: Nonces = Default::default();
    let mut comm: Commitments = Default::default();
    let mut avail: Available  = Default::default();

    let res1 = chain.apply_block(&b1, &mut balances, &mut nonces, &mut comm, &mut avail).expect("b1 ok");
    let res2 = chain.apply_block(&b2, &mut balances, &mut nonces, &mut comm, &mut avail).expect("b2 ok");

    assert_eq!(chain.height, ready_at);
    assert_eq!(res2.header.parent_hash, res1.block_hash);

    // Optional: if REVEAL_WINDOW > 0, we can still add an empty block at deadline to ensure no IL due remains.
    let _deadline = ready_at + REVEAL_WINDOW;
}

#[test]
fn tamper_block_no_state_change() {
    use std::collections::HashMap;
    use crate::state::{Balances, Nonces, Commitments, Available, COMMIT_FEE};
    use crate::types::{Block, Tx, CommitTx, Hash, AccessList, StateKey};
    use crate::stf::process_block;
    use crate::verify::verify_block_roots;

    // Genesis parent
    let parent: Hash = [0u8; 32];

    let al = AccessList {
        reads:  vec![StateKey::Balance("Alice".into())],
        writes: vec![StateKey::Balance("Alice".into())],
    };

    // Block #1 with a single Commit
    let commitment: Hash = [9u8; 32];
    let block = Block::new(
        vec![Tx::Commit(CommitTx {
            commitment,
            sender: "Alice".into(),
            ciphertext_hash: [0u8; 32],
            access_list: al,
        })],
        1,
    );

    // Local state
    let mut balances: Balances = HashMap::from([("Alice".to_string(), 100)]);
    let mut nonces: Nonces = Default::default();
    let mut commitments: Commitments = Default::default();
    let mut available:   Available   = Default::default();

    // Build (builder path)
    let res = process_block(
        &block,
        &mut balances,
        &mut nonces,
        &mut commitments,
        &mut available, // ← NEW
        &parent,
    ).expect("ok");

    // Sanity: commit fee burned, nonce unchanged
    assert_eq!(balances["Alice"], 100 - COMMIT_FEE);
    assert_eq!(*nonces.get("Alice").unwrap_or(&0), 0);

    // Tamper header
    let mut bad_header = res.header.clone();
    bad_header.receipts_root[0] ^= 1;

    // Verify should fail
    let err = verify_block_roots(&bad_header, &block, &res.receipts)
        .expect_err("verification must fail on header tamper");
    assert!(err.contains("mismatch"));
}

#[test]
fn inclusion_list_due_must_be_included() {
    use std::collections::HashMap;
    use crate::chain::Chain;
    use crate::state::{Balances, Nonces, Commitments, Available, DECRYPTION_DELAY, REVEAL_WINDOW};
    use crate::types::{Block, Tx, CommitTx, RevealTx, AvailTx, Transaction, AccessList, StateKey, Hash};
    use crate::codec::tx_bytes;
    use crate::crypto::commitment_hash;
    use crate::stf::BlockError;

    // helper: fill chain with empty blocks up to (but not including) `target`
    fn advance_to(
        chain: &mut Chain,
        balances: &mut Balances,
        nonces: &mut Nonces,
        comms: &mut Commitments,
        avail: &mut Available,
        target: u64,
    ) {
        while chain.height + 1 < target {
            let b = Block::new(Vec::new(), chain.height + 1);
            chain.apply_block(&b, balances, nonces, comms, avail).expect("advance");
        }
    }

    // --- State ---
    let mut balances: Balances = HashMap::from([("Alice".into(), 100)]);
    let mut nonces: Nonces = Default::default();
    let mut comm: Commitments = Default::default();
    let mut avail: Available  = Default::default();

    // --- Chain ---
    let mut chain = Chain::new();

    let al = AccessList {
        reads:  vec![ StateKey::Balance("Alice".into()) ],
        writes: vec![ StateKey::Balance("Alice".into()) ],
    };

    // Build inner tx + salt so we can compute the matching commitment
    let inner = Transaction::transfer("Alice", "Bob", 10, 0);
    let salt: Hash = [9u8; 32];
    let cmt  = commitment_hash(&tx_bytes(&inner), &salt);

    // ---- Block 1: Commit ----
    let b1 = Block::new(vec![
        Tx::Commit(CommitTx {
            commitment: cmt,
            sender: "Alice".into(),
            ciphertext_hash: [2u8;32],
            access_list: al.clone(),
        })
    ], 1);
    chain.apply_block(&b1, &mut balances, &mut nonces, &mut comm, &mut avail)
         .expect("b1 applies");

    // Compute heights from params
    let ready_at = 1 + DECRYPTION_DELAY;
    let due      = ready_at + REVEAL_WINDOW;

    // If ready_at < due, post availability earlier; otherwise, we'll include it in the due block.
    if ready_at < due {
        advance_to(&mut chain, &mut balances, &mut nonces, &mut comm, &mut avail, ready_at);
        let b_ready = Block::new(vec![ Tx::Avail(AvailTx { commitment: cmt }) ], ready_at);
        chain.apply_block(&b_ready, &mut balances, &mut nonces, &mut comm, &mut avail)
             .expect("availability block applies");
    }

    // ---- Block due: WITHOUT Reveal → must fail ----
    advance_to(&mut chain, &mut balances, &mut nonces, &mut comm, &mut avail, due);
    let mut b_due_missing_txs = Vec::new();
    if ready_at == due {
        // availability must be present in this same block for enforcement to trigger
        b_due_missing_txs.push(Tx::Avail(AvailTx { commitment: cmt }));
    }
    let b_due_missing = Block::new(b_due_missing_txs, due);
    let err = chain
        .apply_block(&b_due_missing, &mut balances, &mut nonces, &mut comm, &mut avail)
        .expect_err("must fail due to missing reveal");

    match err {
        BlockError::IntrinsicInvalid(msg) => assert!(msg.contains("missing required reveal")),
        other => panic!("expected IntrinsicInvalid, got {:?}", other),
    }

    // ---- Block due: WITH Reveal → success ----
    // (height hasn't advanced after the failed apply, so we can reuse the same `due` height)
    let mut b_due_with_txs = Vec::new();
    if ready_at == due {
        b_due_with_txs.push(Tx::Avail(AvailTx { commitment: cmt }));
    }
    b_due_with_txs.push(Tx::Reveal(RevealTx { tx: inner.clone(), salt, sender: "Alice".into() }));

    let b_due_with = Block::new(b_due_with_txs, due);
    chain.apply_block(&b_due_with, &mut balances, &mut nonces, &mut comm, &mut avail)
         .expect("due block applies with reveal");
}