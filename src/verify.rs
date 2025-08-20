//src/verify.rs

use crate::{codec::{receipt_bytes, tx_bytes, tx_enum_bytes, access_list_bytes}, crypto::{hash_bytes_sha256, merkle_root}, state::CHAIN_ID, types::{Block, BlockHeader, Hash, Receipt}};

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
            let al_bytes = access_list_bytes(&r.tx.access_list);
            let cmt = crate::crypto::commitment_hash(&ser, &al_bytes, &r.salt, CHAIN_ID);
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
mod tests {
    use super::*;
    
}