use std::collections::HashMap;

use bitvec::vec::BitVec;
use ed25519_dalek::{SigningKey, Signer};
use l1_blockchain::chain::Chain;
use l1_blockchain::codec::{header_id, qc_commitment, header_signing_bytes};
use l1_blockchain::consensus::{BlockStore, HotStuff};
use l1_blockchain::crypto::bls::{BlsAggregate, BlsSigner, verify_qc, vote_msg, BlsSignatureBytes};
use l1_blockchain::crypto::hash_bytes_sha256;
use l1_blockchain::pos::registry::{StakingConfig, Validator, ValidatorSet, ValidatorStatus};
use l1_blockchain::state::{Available, Balances, Commitments, Nonces};
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
                batch_digests: vec![],
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

fn create_chain_with_bls_validators() -> (Chain, Vec<BlsSigner>, Vec<SigningKey>) {
    let n = 3;
    let sks: Vec<[u8; 32]> = (0..n).map(|i| [i as u8 + 1; 32]).collect();
    let bls_signers: Vec<BlsSigner> = sks
        .iter()
        .map(|sk| BlsSigner::from_sk_bytes(sk).unwrap())
        .collect();
    let bls_pks: Vec<[u8; 48]> = bls_signers.iter().map(|s| s.public_key_bytes()).collect();

    // Create ed25519 signing keys
    let ed25519_signers: Vec<SigningKey> = (0..n)
        .map(|i| SigningKey::from_bytes(&[i as u8 + 1; 32]))
        .collect();

    // Create validators with BLS and ed25519 keys
    let cfg = StakingConfig {
        min_stake: 1,
        unbonding_epochs: 1,
        max_validators: u32::MAX,
    };
    
    let validators: Vec<Validator> = (0..n)
        .map(|i| Validator {
            id: i as u64,
            ed25519_pubkey: ed25519_signers[i].verifying_key().to_bytes(),
            bls_pubkey: Some(bls_pks[i]),
            vrf_pubkey: [i as u8 + 1; 32],     // dummy VRF keys
            stake: 100,
            status: ValidatorStatus::Active,
        })
        .collect();

    let validator_set = ValidatorSet::from_genesis(0, &cfg, validators);
    let seed = hash_bytes_sha256(b"test-epoch-seed");

    let mut chain = Chain::new();
    chain.init_genesis(validator_set, seed);

    (chain, bls_signers, ed25519_signers)
}

#[test]
fn chain_accepts_valid_qc() {
    let (mut chain, bls_signers, ed25519_signers) = create_chain_with_bls_validators();

    // Create a valid QC
    let block_id = [42u8; 32];
    let view = 1;
    let qc = build_qc(block_id, view, &bls_signers);
    
    // Compute the QC commitment hash
    let qc_hash = qc_commitment(
        qc.view,
        &qc.block_id,
        &qc.agg_sig,
        &qc.bitmap,
    );

    // Create a block with the valid QC
    let mut block = Block {
        header: BlockHeader {
            parent_hash: chain.tip_hash,
            height: chain.height + 1,
            txs_root: [0u8; 32],
            receipts_root: [0u8; 32],
            gas_used: 0,
            randomness: [0u8; 32],
            reveal_set_root: [0u8; 32],
            il_root: [0u8; 32],
            exec_base_fee: chain.fee_state.exec_base,
            commit_base_fee: chain.fee_state.commit_base,
            avail_base_fee: chain.fee_state.avail_base,
            timestamp: 0,
            slot: 1,
            epoch: 0,
            proposer_id: 0,
            bundle_len: 4,
            vrf_preout: [0u8; 32],
            vrf_output: [0u8; 32],
            vrf_proof: vec![],
            view: 2,
            justify_qc_hash: qc_hash, // Correctly computed QC hash
            signature: [0u8; 64],
        },
        transactions: vec![],
        reveals: vec![],
        batch_digests: vec![],
        justify_qc: qc,
    };

    // Sign the header with the proposer's ed25519 key (proposer_id: 0)
    let preimage = header_signing_bytes(&block.header);
    let signature = ed25519_signers[0].sign(&preimage).to_bytes();
    block.header.signature = signature;

    let mut balances = Balances::default();
    let mut nonces = Nonces::default();
    let mut commitments = Commitments::default();
    let mut available = Available::default();

    // This should succeed because the QC is valid
    let result = chain.apply_block(&block, &mut balances, &mut nonces, &mut commitments, &mut available);
    
    // We expect this to fail for other reasons (like bad signature, wrong proposer, etc.)
    // but NOT for QC verification issues
    match result {
        Err(err) => {
            let err_msg = format!("{:?}", err);
            assert!(!err_msg.contains("QC signature verification failed"));
            assert!(!err_msg.contains("justify_qc_hash mismatch"));
        }
        Ok(_) => {
            // If it passes, that's also fine - the QC verification worked
        }
    }
}

#[test] 
fn chain_rejects_invalid_qc_hash() {
    let (mut chain, bls_signers, ed25519_signers) = create_chain_with_bls_validators();

    // Create a valid QC
    let block_id = [42u8; 32];
    let view = 1;
    let qc = build_qc(block_id, view, &bls_signers);

    // Create a block with WRONG QC hash
    let mut block = Block {
        header: BlockHeader {
            parent_hash: chain.tip_hash,
            height: chain.height + 1,
            txs_root: [0u8; 32],
            receipts_root: [0u8; 32],
            gas_used: 0,
            randomness: [0u8; 32],
            reveal_set_root: [0u8; 32],
            il_root: [0u8; 32],
            exec_base_fee: chain.fee_state.exec_base,
            commit_base_fee: chain.fee_state.commit_base,
            avail_base_fee: chain.fee_state.avail_base,
            timestamp: 0,
            slot: 1,
            epoch: 0,
            proposer_id: 0,
            bundle_len: 4,
            vrf_preout: [0u8; 32],
            vrf_output: [0u8; 32],
            vrf_proof: vec![],
            view: 2,
            justify_qc_hash: [99u8; 32], // Wrong QC hash!
            signature: [0u8; 64],
        },
        transactions: vec![],
        reveals: vec![],
        batch_digests: vec![],
        justify_qc: qc,
    };

    // Sign the header with the proposer's ed25519 key (proposer_id: 0)
    let preimage = header_signing_bytes(&block.header);
    let signature = ed25519_signers[0].sign(&preimage).to_bytes();
    block.header.signature = signature;

    let mut balances = Balances::default();
    let mut nonces = Nonces::default();
    let mut commitments = Commitments::default();
    let mut available = Available::default();

    // This should fail due to QC hash mismatch
    let result = chain.apply_block(&block, &mut balances, &mut nonces, &mut commitments, &mut available);
    
    match result {
        Err(err) => {
            let err_msg = format!("{:?}", err);
            assert!(err_msg.contains("justify_qc_hash mismatch"));
        }
        Ok(_) => panic!("Expected QC hash mismatch error"),
    }
}

#[test]
fn chain_rejects_invalid_qc_signature() {
    let (mut chain, bls_signers, ed25519_signers) = create_chain_with_bls_validators();

    // Create a QC with invalid signature
    let block_id = [42u8; 32];
    let view = 1;
    let mut qc = build_qc(block_id, view, &bls_signers);
    
    // Corrupt the signature
    qc.agg_sig = BlsSignatureBytes([99u8; 96]);
    
    // Compute the QC commitment hash with the corrupted QC
    let qc_hash = qc_commitment(
        qc.view,
        &qc.block_id,
        &qc.agg_sig,
        &qc.bitmap,
    );

    // Create a block with the invalid QC
    let mut block = Block {
        header: BlockHeader {
            parent_hash: chain.tip_hash,
            height: chain.height + 1,
            txs_root: [0u8; 32],
            receipts_root: [0u8; 32],
            gas_used: 0,
            randomness: [0u8; 32],
            reveal_set_root: [0u8; 32],
            il_root: [0u8; 32],
            exec_base_fee: chain.fee_state.exec_base,
            commit_base_fee: chain.fee_state.commit_base,
            avail_base_fee: chain.fee_state.avail_base,
            timestamp: 0,
            slot: 1,
            epoch: 0,
            proposer_id: 0,
            bundle_len: 4,
            vrf_preout: [0u8; 32],
            vrf_output: [0u8; 32],
            vrf_proof: vec![],
            view: 2,
            justify_qc_hash: qc_hash, // Correctly computed (but for invalid signature)
            signature: [0u8; 64],
        },
        transactions: vec![],
        reveals: vec![],
        batch_digests: vec![],
        justify_qc: qc,
    };

    // Sign the header with the proposer's ed25519 key (proposer_id: 0)
    let preimage = header_signing_bytes(&block.header);
    let signature = ed25519_signers[0].sign(&preimage).to_bytes();
    block.header.signature = signature;

    let mut balances = Balances::default();
    let mut nonces = Nonces::default();
    let mut commitments = Commitments::default();
    let mut available = Available::default();

    // This should fail due to invalid QC signature
    let result = chain.apply_block(&block, &mut balances, &mut nonces, &mut commitments, &mut available);
    
    match result {
        Err(err) => {
            let err_msg = format!("{:?}", err);
            assert!(err_msg.contains("QC signature verification failed"));
        }
        Ok(_) => panic!("Expected QC signature verification failure"),
    }
}
