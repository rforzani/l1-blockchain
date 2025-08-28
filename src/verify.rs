//src/verify.rs

use crate::{
    codec::{access_list_bytes, receipt_bytes, tx_bytes, tx_enum_bytes},
    crypto::{hash_bytes_sha256, merkle_root},
    mempool::BatchStore,
    mempool::encrypted::ThresholdCiphertext,
    state::CHAIN_ID,
    types::{Block, BlockHeader, Hash, Receipt},
};

pub fn compute_roots_for(block: &Block, batches: &BatchStore, receipts: &[Receipt]) -> (Hash, Hash, Hash) {
    // Gather all transactions: direct + via batches, de-duplicated by tx hash (must match STF processing)
    use std::collections::HashSet as StdHashSet;
    // Start with in-block transactions intact
    let mut txs: Vec<crate::types::Tx> = block.transactions.clone();
    let mut seen_in_block: StdHashSet<Hash> = StdHashSet::new();
    for tx in &block.transactions {
        let h = hash_bytes_sha256(&tx_enum_bytes(tx));
        seen_in_block.insert(h);
    }
    // Append batch transactions only if not already present in block.transactions
    for d in &block.batch_digests {
        if let Some(batch) = batches.get(d) {
            for tx in batch.txs {
                let h = hash_bytes_sha256(&tx_enum_bytes(&tx));
                if !seen_in_block.contains(&h) {
                    txs.push(tx);
                }
            }
        }
    }
    // txs_root from all transactions (reveals are NOT part of txs_root)
    let tx_hashes: Vec<Hash> = txs
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
    batches: &BatchStore,
    receipts: &[Receipt],
) -> Result<(), String> {
    let (txs_root, receipts_root, reveals_root) = compute_roots_for(block, batches, receipts);
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
    use crate::{chain::DEFAULT_BUNDLE_LEN, types::{AccessList, Block, BlockHeader, CommitTx, ExecOutcome, Receipt, Tx, QC}};
    use crate::crypto::bls::BlsSignatureBytes;
    use bitvec::vec::BitVec;

    fn fake_vrf_fields(proposer_id: u64) -> ([u8; 32], [u8; 32], Vec<u8>) {
        let mut m = Vec::with_capacity(16 + 8);
        m.extend_from_slice(b"fake-vrf-preout");
        m.extend_from_slice(&proposer_id.to_be_bytes());
        let preout = hash_bytes_sha256(&m);
    
        let out = hash_bytes_sha256(&preout);
    
        let mut proof = Vec::with_capacity(33);
        proof.extend_from_slice(&preout);
        proof.push(0x01);
    
        (out, preout, proof)
    }

    #[test]
    fn verify_block_roots_catches_tamper() {
        // Build a block with one commit transaction and its receipt
        let al = AccessList { reads: vec![], writes: vec![] };
        let commit = CommitTx {
            commitment: [1u8; 32],
            sender: "alice".into(),
            access_list: al,
            encrypted_payload: ThresholdCiphertext {
                ephemeral_pk: [0u8; 48],
                encrypted_data: vec![2u8; 32],
                tag: [0u8; 32],
                epoch: 1,
            },
            pubkey: [3u8; 32],
            sig: [4u8; 64],
        };
    
        let txs = vec![Tx::Commit(commit)];
    
        // --- VORTEX (VRF) FIELDS ---
        // For this unit test, we synthesize deterministic VRF data.
        // Policy: slot == height (dev), epoch 0. Bundle length = DEFAULT_BUNDLE_LEN.
        let height: u64 = 1;
        let slot:   u64 = height;
        let epoch:  u64 = 0;
        let r: u8 = DEFAULT_BUNDLE_LEN;
    
        // Proposer identity for the header
        let proposer_id: u64 = 1;
    
        let (vrf_output, vrf_preout, vrf_proof) = fake_vrf_fields(proposer_id);
    
        // Header with Vortex fields populated (signature not needed for root checks)
        let header = BlockHeader {
            parent_hash:     [0u8; 32],
            height,
            txs_root:        [0u8; 32],
            receipts_root:   [0u8; 32],
            gas_used:        0,
            randomness:      [0u8; 32],
            reveal_set_root: [0u8; 32],
            il_root:         [0u8; 32],
            exec_base_fee:   0,
            commit_base_fee: 0,
            avail_base_fee:  0,
            timestamp:       0,
            slot,
            epoch,
            proposer_id,
            bundle_len:  r,
            vrf_output,
            vrf_proof,
            vrf_preout,
            view: 0,
            justify_qc_hash: [0u8;32],
            signature: [0u8; 64],
        };

        fn dummy_qc() -> QC {
            QC { view: 0, block_id: [0u8;32], agg_sig: BlsSignatureBytes([0u8;96]), bitmap: BitVec::new() }
        }
        let mut block = Block::new(txs, header, dummy_qc());
    
        // One matching receipt initially
        let mut receipts = vec![Receipt {
            outcome: ExecOutcome::Success,
            gas_used: 0,
            error: None,
        }];
    
        // Compute the correct roots and embed them in the header
        let store = BatchStore::new();
        let (tx_root, receipt_root, reveal_root) = compute_roots_for(&block, &store, &receipts);
        block.header.txs_root        = tx_root;
        block.header.receipts_root   = receipt_root;
        block.header.reveal_set_root = reveal_root;
    
        // Sanity: passes when receipts match
        assert!(verify_block_roots(&block.header, &block, &store, &receipts).is_ok());
    
        // Tamper with receipts AFTER roots are embedded
        receipts[0].gas_used = 1;
    
        // Now verification should fail due to mismatched receipts_root
        assert!(verify_block_roots(&block.header, &block, &store, &receipts).is_err());
    }
}
