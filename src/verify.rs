//src/verify.rs

use crate::types::{Receipt, Block, BlockHeader, Hash};

pub fn compute_roots_for(block: &Block, receipts: &[Receipt]) -> (Hash, Hash) {
    use crate::codec::{tx_enum_bytes, receipt_bytes};
    use crate::crypto::{hash_bytes_sha256, merkle_root};
    use crate::types::Hash;

    let tx_hashes: Vec<Hash> = block
        .transactions
        .iter()
        .map(|tx| hash_bytes_sha256(&tx_enum_bytes(tx)))
        .collect();

    let receipt_hashes: Vec<Hash> = receipts
        .iter()
        .map(|r| hash_bytes_sha256(&receipt_bytes(r)))
        .collect();

    (merkle_root(&tx_hashes), merkle_root(&receipt_hashes))
}

pub fn verify_block_roots(header: &BlockHeader, block: &Block, receipts: &[Receipt]) -> Result<(), String> {
    let (txs_root, receipts_root) = compute_roots_for(block, receipts);
    if txs_root != header.txs_root || receipts_root != header.receipts_root {
        return Err("header mismatch: roots".to_string());
    }
    Ok(())
}

#[cfg(test)]

#[test]
fn verify_block_roots_catches_tamper() {
    use std::collections::HashMap;
    use crate::state::{Balances, Nonces, Commitments};
    use crate::stf::process_block;
    use crate::types::{Block, Tx, CommitTx, Hash, AccessList, StateKey};
    use crate::verify::verify_block_roots;

    // State
    let mut balances: Balances = HashMap::from([("Alice".into(), 100_u64)]);
    let mut nonces: Nonces = Default::default();
    let mut comm: Commitments = Default::default();

    let al = AccessList {
        reads: vec![ StateKey::Balance("Alice".into())],
        writes: vec![ StateKey::Balance("Alice".into())],
    };

    // Block 1 with a single Commit (opaque commitment is fine here)
    let commitment: Hash = [42u8; 32];
    let block = Block::new(
        vec![Tx::Commit(CommitTx {
            commitment,
            expires_at: 5,
            sender: "Alice".into(),
            access_list: al
        })],
        1,
    );

    // Build (builder path)
    let parent = [0u8; 32];
    let res = process_block(&block, &mut balances, &mut nonces, &mut comm, &parent)
        .expect("ok");

    // Verify (ok)
    verify_block_roots(&res.header, &block, &res.receipts).expect("roots match");

    // Tamper one receipt
    let mut bad_receipts = res.receipts.clone();
    bad_receipts[0].gas_used += 1;

    // Verify (must fail)
    let err = verify_block_roots(&res.header, &block, &bad_receipts).unwrap_err();
    assert!(err.contains("mismatch"));
}