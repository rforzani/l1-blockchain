use l1_blockchain::mempool::workers::{Batch, BatchStore};
use l1_blockchain::pos::registry::ValidatorId;
use l1_blockchain::types::{Block, BlockHeader, CommitTx, QC, Tx, AccessList};
use l1_blockchain::crypto::bls::BlsSignatureBytes;
use bitvec::vec::BitVec;

fn dummy_block() -> Block {
    Block {
        transactions: vec![],
        reveals: vec![],
        batch_digests: vec![],
        header: BlockHeader {
            parent_hash: [0u8;32],
            height: 1,
            txs_root: [0u8;32],
            receipts_root: [0u8;32],
            gas_used: 0,
            randomness: [0u8;32],
            reveal_set_root: [0u8;32],
            il_root: [0u8;32],
            exec_base_fee: 0,
            commit_base_fee: 0,
            avail_base_fee: 0,
            timestamp: 0,
            slot: 0,
            epoch: 0,
            proposer_id: 0,
            signature: [0u8;64],
            bundle_len: 0,
            vrf_output: [0u8;32],
            vrf_proof: Vec::new(),
            vrf_preout: [0u8;32],
            view: 0,
            justify_qc_hash: [0u8;32],
        },
        justify_qc: QC { view:0, block_id:[0u8;32], agg_sig:BlsSignatureBytes([0u8;96]), bitmap: BitVec::new() }
    }
}

fn sample_commit() -> Tx {
    let commit = CommitTx {
        commitment: [1u8;32],
        sender: "alice".into(),
        access_list: AccessList { reads: vec![], writes: vec![] },
        ciphertext_hash: [2u8;32],
        pubkey: [3u8;32],
        sig: [4u8;64],
    };
    Tx::Commit(commit)
}

#[test]
fn batches_persist_and_retrievable() {
    let store = BatchStore::new();
    let tx = sample_commit();
    let batch = Batch::new(vec![tx.clone()], vec![], ValidatorId::from(1u64), [0u8;64]);
    let digest = batch.id;
    store.insert(batch);
    let got = store.get(&digest).expect("batch stored");
    assert_eq!(got.txs.len(), 1);
    assert_eq!(got.txs[0], tx);
}

#[test]
fn block_resolves_batches_by_digest() {
    let store = BatchStore::new();
    let tx = sample_commit();
    let batch = Batch::new(vec![tx.clone()], vec![], ValidatorId::from(1u64), [0u8;64]);
    let digest = batch.id;
    store.insert(batch);

    let mut block = dummy_block();
    block.batch_digests.push(digest);

    let fetched: Vec<Tx> = block
        .batch_digests
        .iter()
        .flat_map(|d| store.get(d).unwrap().txs.clone())
        .collect();
    assert_eq!(fetched, vec![tx]);
}
