use std::collections::HashMap;

use bitvec::vec::BitVec;
use l1_blockchain::codec::header_id;
use l1_blockchain::consensus::{BlockStore, HotStuff};
use l1_blockchain::crypto::bls::{BlsAggregate, BlsSigner, verify_qc, vote_msg};
use l1_blockchain::types::{Block, BlockHeader, HotStuffState, Pacemaker, QC};

// simple block store for tests
struct DummyStore {
    parents: HashMap<[u8; 32], [u8; 32]>,
}

impl BlockStore for DummyStore {
    fn is_descendant(&self, candidate_parent: &[u8; 32], ancestor: &[u8; 32]) -> bool {
        let mut cur = *candidate_parent;
        while let Some(p) = self.parents.get(&cur) {
            if p == ancestor {
                return true;
            }
            cur = *p;
        }
        false
    }

    fn get_parent(&self, block_id: &[u8; 32]) -> Option<[u8; 32]> {
        self.parents.get(block_id).cloned()
    }
}

fn build_qc(id: [u8; 32], view: u64, signers: &[BlsSigner]) -> QC {
    let mut agg = BlsAggregate::new();
    let mut bitmap = BitVec::repeat(false, signers.len());
    for (i, s) in signers.iter().enumerate() {
        let msg = vote_msg(&id, view);
        let sig = s.sign(&msg);
        agg.push(&sig.0);
        bitmap.set(i, true);
    }
    let agg_sig = agg.finalize().unwrap();
    QC {
        view,
        block_id: id,
        agg_sig,
        bitmap,
    }
}

#[test]
fn proposal_triggers_qc_creation() {
    let n = 3;
    let sks: Vec<[u8; 32]> = (0..n).map(|i| [i as u8 + 1; 32]).collect();
    let signers: Vec<BlsSigner> = sks
        .iter()
        .map(|sk| BlsSigner::from_sk_bytes(sk).unwrap())
        .collect();
    let pks: Vec<[u8; 48]> = signers.iter().map(|s| s.public_key_bytes()).collect();

    // QC for parent block id=1
    let root: [u8; 32] = [0u8; 32];
    let block1_id: [u8; 32] = [1u8; 32];
    let qc1 = build_qc(block1_id, 1, &signers);

    // pacemaker state
    let mut base_pm = Pacemaker::new(1000, 10000, 2, 1);
    base_pm.on_enter_view(0);

    // create validators
    let mut validators: Vec<HotStuff> = sks
        .iter()
        .enumerate()
        .map(|(i, sk)| {
            let state = HotStuffState {
                current_view: 2,
                locked_block: (root, 0),
                high_qc: qc1.clone(),
                pacemaker: base_pm.clone(),
            };
            HotStuff::new(
                state,
                pks.clone(),
                i as u64,
                Some(BlsSigner::from_sk_bytes(sk).unwrap()),
            )
        })
        .collect();

    // block store knows parent lineage
    let mut store = DummyStore {
        parents: HashMap::new(),
    };
    store.parents.insert(block1_id, root);

    // leader proposes block2 with parent=block1 and justify=qc1
    let leader = 0usize;
    let block = validators[leader]
        .maybe_propose(true, |qc| {
            let header = BlockHeader {
                parent_hash: block1_id,
                height: 2,
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
                proposer_id: leader as u64,
                bundle_len: 0,
                vrf_preout: [0u8; 32],
                vrf_output: [0u8; 32],
                vrf_proof: vec![],
                view: 0,
                justify_qc_hash: [0u8; 32],
                signature: [0u8; 64],
            };
            Block {
                transactions: vec![],
                reveals: vec![],
                header,
                justify_qc: qc.clone(),
            }
        })
        .expect("leader proposes");

    let bid = header_id(&block.header);

    // validators vote and leader aggregates
    let mut qc2 = None;
    for i in 0..n {
        let vote = validators[i].maybe_vote(&store, &block).expect("vote");
        if let Some(q) = validators[leader].on_vote(vote) {
            qc2 = Some(q);
        }
    }
    let qc2 = qc2.expect("qc");
    assert_eq!(qc2.block_id, bid);
    assert_eq!(qc2.view, block.header.view);
    verify_qc(&qc2.block_id, qc2.view, &qc2.agg_sig, &qc2.bitmap, &pks).unwrap();
}
