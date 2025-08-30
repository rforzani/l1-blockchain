use l1_blockchain::consensus::dev_loop::DevNode;
use l1_blockchain::mempool::{MempoolImpl, MempoolConfig};
use l1_blockchain::node::Node;
use l1_blockchain::pos::registry::{Validator, ValidatorStatus};
use l1_blockchain::crypto::bls::BlsSigner;
use l1_blockchain::types::{HotStuffState, Pacemaker, QC};
use l1_blockchain::crypto::hash_bytes_sha256;
use ed25519_dalek::SigningKey;

#[tokio::test]
async fn pacemaker_timeout_broadcasts_view_change() {
    // Two validators with simple keys
    let bls0 = BlsSigner::from_sk_bytes(&[10u8; 32]).unwrap();
    let bls1 = BlsSigner::from_sk_bytes(&[11u8; 32]).unwrap();
    let active_pks = vec![bls0.public_key_bytes(), bls1.public_key_bytes()];

    // Validator set
    let validators = vec![
        Validator { id: 0, ed25519_pubkey: SigningKey::from_bytes(&[1u8;32]).verifying_key().to_bytes(), bls_pubkey: Some(active_pks[0]), vrf_pubkey: hash_bytes_sha256(&[200u8;32]), stake: 1_000_000, status: ValidatorStatus::Active },
        Validator { id: 1, ed25519_pubkey: SigningKey::from_bytes(&[2u8;32]).verifying_key().to_bytes(), bls_pubkey: Some(active_pks[1]), vrf_pubkey: hash_bytes_sha256(&[201u8;32]), stake: 1_000_000, status: ValidatorStatus::Active },
    ];

    // Mempool cfg
    let cfg = MempoolConfig { max_avails_per_block: 10, max_reveals_per_block: 10, max_commits_per_block: 10, max_pending_commits_per_account: 10, commit_ttl_blocks: 16, reveal_window_blocks: 16 };
    
    // Nodes
    let mut n0 = Node::new(MempoolImpl::new(cfg.clone()), SigningKey::from_bytes(&[1u8;32]));
    let mut n1 = Node::new(MempoolImpl::new(cfg.clone()), SigningKey::from_bytes(&[2u8;32]));

    // Init VRF and shared validator set
    let vrf0 = l1_blockchain::crypto::vrf::SchnorrkelVrfSigner::from_deterministic_seed([7u8;32]);
    let vrf1 = l1_blockchain::crypto::vrf::SchnorrkelVrfSigner::from_deterministic_seed([8u8;32]);
    n0.set_vrf_signer(vrf0); n1.set_vrf_signer(vrf1);
    n0.init_with_shared_validator_set(validators.clone(), bls0.clone());
    n1.init_with_shared_validator_set(validators.clone(), bls1.clone());

    // Genesis QC
    // Use minimal bitmap with both validators marked true (2 peers)
    use bitvec::vec::BitVec;
    let mut bm = BitVec::repeat(false, 2);
    bm.set(0, true); bm.set(1, true);
    let qc = QC { view: 0, block_id: [0u8;32], agg_sig: bls0.sign(&[0u8]).clone(), bitmap: bm };

    // HotStuff state for both
    let now_ms = (n0.now_unix() as u128) * 1000;
    let mut pm0 = Pacemaker::new(100, 10_000, 3, 2, 1, 1);
    pm0.on_enter_view(now_ms.saturating_sub(500)); // ensure expired
    let hs0 = HotStuffState { current_view: 1, locked_block: ([0u8;32], 0), high_qc: qc.clone(), pacemaker: pm0 };
    let mut pm1 = Pacemaker::new(100, 10_000, 3, 2, 1, 1);
    pm1.on_enter_view(now_ms);
    let hs1 = HotStuffState { current_view: 1, locked_block: ([0u8;32], 0), high_qc: qc.clone(), pacemaker: pm1 };
    n0.set_hotstuff(l1_blockchain::consensus::HotStuff::new(hs0, active_pks.clone(), 0, Some(bls0)));
    n1.set_hotstuff(l1_blockchain::consensus::HotStuff::new(hs1, active_pks.clone(), 1, Some(bls1)));

    // Network with direct delivery
    let nets = l1_blockchain::p2p::create_test_network(vec![0,1]).await.unwrap();
    n0.set_consensus_network(nets[0].clone());
    n1.set_consensus_network(nets[1].clone());
    // Subscribe on n1 to observe view-change
    let mut rx1 = n1.consensus_network().unwrap().subscribe();

    // Trigger timeout broadcast from n0
    n0.check_pacemaker_timeout().unwrap();

    // Receive a view-change on n1
    let msg = tokio::time::timeout(std::time::Duration::from_millis(200), rx1.recv()).await
        .expect("timely recv")
        .expect("message");

    match msg {
        l1_blockchain::p2p::ConsensusMessage::ViewChange { view, sender_id, timeout_qc } => {
            assert_eq!(sender_id, 0);
            assert_eq!(view, 1);
            assert!(timeout_qc.is_some());
        }
        other => panic!("unexpected message: {:?}", other),
    }
}
