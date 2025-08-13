//src/chain.rs

use crate::stf::{process_block, BlockResult, BlockError};
use crate::state::{Nonces, Balances};
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

        // 2) process with current tip as parent
        let res = process_block(block, &mut sim_balances, &mut sim_nonces, &self.tip_hash)?;

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
    use crate::state::{Balances, Nonces};
    use crate::types::{Block, Transaction};

    // 1) state
    let mut balances: Balances = HashMap::from([
        ("Alice".to_string(), 100),
        ("Bob".to_string(), 50),
    ]);
    let mut nonces: Nonces = Default::default();

    // 2) chain
    let mut chain = Chain::new();
    assert_eq!(chain.height, 0);
    assert_eq!(chain.tip_hash, [0u8; 32]);

    // 3) block #1 with two txs (reuse your constructor)
    let tx1 = Transaction::transfer("Alice", "Bob", 20, 0);
    let tx2 = Transaction::transfer("Bob", "Alice", 10, 0);
    let b1 = Block::new(vec![tx1.into(), tx2.into()], 1);

    // 4) apply
    let res = chain.apply_block(&b1, &mut balances, &mut nonces).expect("block 1 should apply");

    // 5) asserts
    assert_eq!(chain.height, 1);
    assert_eq!(chain.tip_hash, res.block_hash);
    assert_eq!(res.header.height, 1);
    assert_eq!(res.header.parent_hash, [0u8; 32]);
}

#[test]
fn applying_same_height_fails() {
    use crate::state::{Balances, Nonces};
    use crate::types::Block;

    let mut balances: Balances = Default::default();
    let mut nonces: Nonces = Default::default();
    let mut chain = Chain::new();

    // apply block 1
    let b1 = Block::new(Vec::new(), 1);
    chain.apply_block(&b1, &mut balances, &mut nonces).expect("b1 ok");

    // try another block numbered 1
    let b1_again = Block::new(Vec::new(), 1);
    let err = chain.apply_block(&b1_again, &mut balances, &mut nonces).expect_err("should fail on bad height");

    assert!(err == BlockError::BadHeight { expected: 2, got: 1 }, "got err: {}", err);
}

#[test]
fn apllying_2_blocks_works_correctly() {
    use std::collections::HashMap;
    use crate::state::{Balances, Nonces};
    use crate::types::{Block, Transaction};

    let b1 = Block::new(vec![
        Transaction::transfer("Alice", "Bob", 10, 0).into(),
    ], 1);
    
    let b2 = Block::new(vec![
        Transaction::transfer("Bob", "Alice", 5, 0).into(),
    ], 2);

    let mut chain = Chain::new();
    let mut balances: Balances = HashMap::from([
        ("Alice".to_string(), 100),
        ("Bob".to_string(), 50),
    ]);
    let mut nonces: Nonces = Default::default();

    let res1 = chain.apply_block(&b1, &mut balances, &mut nonces).expect("b1 ok");
    let res2 = chain.apply_block(&b2, &mut balances, &mut nonces).expect("b2 ok");

    assert_eq!(chain.height, 2);
    assert_eq!(res2.header.parent_hash, res1.block_hash);
}

#[test]
fn tamper_block_no_state_change() {
    use std::collections::HashMap;
    use crate::types::{Transaction};

    // Genesis parent
    let parent: Hash = [0u8; 32];

    // Build a simple block at height 1
    let block = Block::new(vec![
        Transaction::transfer("Bob", "Alice", 5, 0).into()
    ], 1);

    // Local state for execution
    let mut balances: Balances = HashMap::from([
        ("Alice".to_string(), 100),
        ("Bob".to_string(), 50),
    ]);
    let mut nonces: Nonces = Default::default();

    // Build block results (builder path)
    let res = process_block(&block, &mut balances, &mut nonces, &parent)
        .expect("ok");

    // Tamper the header we 'received' from the network
    let mut bad_header = res.header.clone();
    bad_header.receipts_root[0] ^= 1; // flip one bit

    // Verify should now fail
    let err = verify_block_roots(&bad_header, &block, &res.receipts)
        .expect_err("verification must fail on header tamper");
    assert!(err.contains("mismatch"));
}