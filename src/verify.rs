//src/verify.rs

use crate::{
    codec::{access_list_bytes, receipt_bytes, tx_bytes, tx_enum_bytes},
    crypto::{hash_bytes_sha256, merkle_root},
    state::CHAIN_ID,
    types::{Block, BlockHeader, Hash, Receipt},
};

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

pub fn verify_block_roots(
    header: &BlockHeader,
    block: &Block,
    receipts: &[Receipt],
) -> Result<(), String> {
    let (txs_root, receipts_root, reveals_root) = compute_roots_for(block, receipts);
    if txs_root != header.txs_root
        || receipts_root != header.receipts_root
        || reveals_root != header.reveal_set_root
    {
        return Err("header mismatch: roots".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AccessList, Block, BlockHeader, CommitTx, ExecOutcome, Receipt, Tx};

    #[test]
    fn verify_block_roots_catches_tamper() {
        // Build a block with one commit transaction and its receipt
        let al = AccessList {
            reads: vec![],
            writes: vec![],
        };
        let commit = CommitTx {
            commitment: [1u8; 32],
            sender: "alice".into(),
            access_list: al,
            ciphertext_hash: [2u8; 32],
            pubkey: [3u8; 32],
            sig: [4u8; 64],
        };

        let txs = vec![Tx::Commit(commit)];
        let header = BlockHeader {
            parent_hash: [0u8; 32],
            height: 1,
            txs_root: [0u8; 32],
            receipts_root: [0u8; 32],
            gas_used: 0,
            randomness: [0u8; 32],
            reveal_set_root: [0u8; 32],
            il_root: [0u8; 32],
            exec_base_fee: 0,
            commit_base_fee: 0,
            avail_base_fee: 0,
            timestamp: 0,
            slot: 0,
            epoch: 0,
            proposer_id: 1,
            signature: [0u8; 64],
        };

        let mut block = Block::new(txs, header);
        let mut receipts = vec![Receipt {
            outcome: ExecOutcome::Success,
            gas_used: 0,
            error: None,
        }];

        // Compute the correct roots and embed them in the header
        let (tx_root, receipt_root, reveal_root) = compute_roots_for(&block, &receipts);
        block.header.txs_root = tx_root;
        block.header.receipts_root = receipt_root;
        block.header.reveal_set_root = reveal_root;

        // Sanity check: verification passes with matching receipts
        assert!(verify_block_roots(&block.header, &block, &receipts).is_ok());

        // Tamper with the receipts after the header roots were set
        receipts[0].gas_used = 1;

        // Now verification should fail due to mismatched receipts_root
        assert!(verify_block_roots(&block.header, &block, &receipts).is_err());
    }
}
