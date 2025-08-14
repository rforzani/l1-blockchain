//src/verify.rs

use crate::{codec::{receipt_bytes, tx_bytes, tx_enum_bytes}, crypto::{hash_bytes_sha256, merkle_root}, types::{Block, BlockHeader, Hash, Receipt}};

pub fn compute_roots_for(block: &Block, receipts: &[Receipt]) -> (Hash, Hash, Hash) {
    // txs_root from block.transactions (reveals are NOT part of txs_root)
    let tx_hashes: Vec<Hash> = block
        .transactions
        .iter()
        .map(|tx| hash_bytes_sha256(&tx_enum_bytes(tx)))
        .collect();

    // receipts_root from all receipts (commits/avails + reveals)
    let receipt_hashes: Vec<Hash> = receipts
        .iter()
        .map(|r| hash_bytes_sha256(&receipt_bytes(r)))
        .collect();

    // reveal_set_root from block.reveals: leaf = H(commitment || tx_hash)
    let mut pairs: Vec<(Hash, Hash)> = block
        .reveals
        .iter()
        .map(|r| {
            let ser = tx_bytes(&r.tx);
            let cmt = crate::crypto::commitment_hash(&ser, &r.salt);
            let txh = hash_bytes_sha256(&ser);
            (cmt, txh)
        })
        .collect();

    // canonical ordering by commitment
    pairs.sort_by(|(c1, _), (c2, _)| c1.cmp(c2));

    let reveal_leaves: Vec<Hash> = pairs
        .into_iter()
        .map(|(cmt, txh)| {
            let mut buf = Vec::with_capacity(64);
            buf.extend_from_slice(&cmt);
            buf.extend_from_slice(&txh);
            hash_bytes_sha256(&buf)
        })
        .collect();

    (
        merkle_root(&tx_hashes),
        merkle_root(&receipt_hashes),
        merkle_root(&reveal_leaves),
    )
}

pub fn verify_block_roots(header: &BlockHeader, block: &Block, receipts: &[Receipt]) -> Result<(), String> {
    let (txs_root, receipts_root, reveals_root) = compute_roots_for(block, receipts);
    if txs_root != header.txs_root || receipts_root != header.receipts_root || reveals_root != header.reveal_set_root {
        return Err("header mismatch: roots".to_string());
    }
    Ok(())
}

#[cfg(test)]

#[test]
fn verify_block_roots_catches_tamper() {
    use std::collections::HashMap;
    use crate::state::{Balances, Nonces, Commitments, Available};
    use crate::stf::process_block;
    use crate::types::{Block, Tx, CommitTx, Hash, AccessList, StateKey};
    use crate::verify::verify_block_roots;

    // State
    let mut balances: Balances = HashMap::from([("Alice".into(), 100_u64)]);
    let mut nonces: Nonces = Default::default();
    let mut comm: Commitments = Default::default();
    let mut avail: Available  = Default::default();

    let al = AccessList {
        reads:  vec![StateKey::Balance("Alice".into())],
        writes: vec![StateKey::Balance("Alice".into())],
    };

    // Block 1 with a single Commit (opaque commitment is fine here)
    let commitment: Hash = [42u8; 32];
    let block = Block::new(
        vec![Tx::Commit(CommitTx {
            commitment,
            sender: "Alice".into(),
            ciphertext_hash: [0u8; 32],
            access_list: al,
        })],
        1,
    );

    // Genesis parent
    let parent: Hash = [0u8; 32];

    // Build (builder path)
    let res = process_block(
        &block,
        &mut balances,
        &mut nonces,
        &mut comm,
        &mut avail,
        &parent
    ).expect("ok");

    // Verify (ok)
    verify_block_roots(&res.header, &block, &res.receipts).expect("roots match");

    // Tamper one receipt (commit produced a receipt at index 0)
    let mut bad_receipts = res.receipts.clone();
    bad_receipts[0].gas_used += 1;

    // Verify (must fail)
    let err = verify_block_roots(&res.header, &block, &bad_receipts).unwrap_err();
    assert!(err.contains("mismatch"));
}