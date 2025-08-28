//! Local devnet: spin up multiple validators with RPC + P2P HotStuff
//!
//! - Starts N validators (default 3) in a single process
//! - Each validator has its own RPC port (base 8545 + idx)
//! - Nodes discover each other via libp2p (using the in-crate P2P helper)
//! - Runs HotStuff consensus end-to-end (proposal, votes, QC broadcast)
//!
//! Usage:
//!   cargo run --bin localnet_multi -- [N] [RPC_BASE]
//! Example:
//!   cargo run --bin localnet_multi -- 4 9000

use std::{env, sync::{Arc, Mutex}};

use axum::Router;
use ed25519_dalek::SigningKey;
use tokio::{net::TcpListener, time::{Duration, interval}};

use l1_blockchain::{
    consensus::{HotStuff, dev_loop::DEFAULT_LIMITS},
    crypto::{hash_bytes_sha256},
    crypto::bls::{BlsSigner, BlsAggregate, vote_msg},
    crypto::vrf::SchnorrkelVrfSigner,
    mempool::{MempoolConfig, MempoolImpl},
    node::{Node, PacemakerConfig},
    p2p::create_test_network,
    pos::registry::{Validator, ValidatorStatus, ValidatorId},
    rpc::{self, AppState, FaucetLimiter},
    types::{HotStuffState, QC},
};

fn build_mempool_config() -> MempoolConfig {
    MempoolConfig {
        max_avails_per_block: 1024,
        max_reveals_per_block: 1024,
        max_commits_per_block: 1024,
        max_pending_commits_per_account: 1024,
        commit_ttl_blocks: 16,
        reveal_window_blocks: 16,
    }
}

fn make_validators(n: usize) -> (Vec<Validator>, Vec<BlsSigner>, Vec<[u8;32]>) {
    // Deterministically derive ed25519 keys and BLS keys for dev
    let mut vals = Vec::with_capacity(n);
    let mut bls_signers = Vec::with_capacity(n);
    let mut ed_seeds = Vec::with_capacity(n);
    for i in 0..n {
        let ed = SigningKey::from_bytes(&[(i as u8).wrapping_add(1); 32]);
        let ed_pk = ed.verifying_key().to_bytes();
        ed_seeds.push([(i as u8).wrapping_add(1); 32]);

        let bls_sk = [(i as u8).wrapping_add(10); 32];
        let bls = BlsSigner::from_sk_bytes(&bls_sk).expect("valid bls sk");
        let vrf_pub = hash_bytes_sha256(&[(i as u8).wrapping_add(100); 32]);

        vals.push(Validator {
            id: i as ValidatorId,
            ed25519_pubkey: ed_pk,
            bls_pubkey: Some(bls.public_key_bytes()),
            vrf_pubkey: vrf_pub,
            stake: 1_000_000,
            status: ValidatorStatus::Active,
        });
        bls_signers.push(bls);
    }
    (vals, bls_signers, ed_seeds)
}

fn make_genesis_qc(signers: &[BlsSigner]) -> QC {
    let block_id = [0u8; 32];
    let view = 0u64;
    let msg = vote_msg(&block_id, view);
    let mut agg = BlsAggregate::new();
    let mut bitmap = bitvec::vec::BitVec::repeat(false, signers.len());
    for (i, s) in signers.iter().enumerate() {
        let sig = s.sign(&msg);
        agg.push(&sig.0);
        bitmap.set(i, true);
    }
    QC { view, block_id, agg_sig: agg.finalize().expect("non-empty"), bitmap }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Parse CLI args: N validators and base RPC port
    let args: Vec<String> = env::args().collect();
    let n: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(3);
    let rpc_base: u16 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(8545);

    // Build shared validator set and keys
    let (validators, bls_signers, ed_seeds) = make_validators(n);
    let genesis_qc = make_genesis_qc(&bls_signers);

    // Build nodes
    let mut nodes: Vec<Arc<Mutex<Node>>> = Vec::with_capacity(n);
    for i in 0..n {
        let mp = MempoolImpl::new(build_mempool_config());
        let ed = SigningKey::from_bytes(&ed_seeds[i]);
        let mut node = Node::new(mp.clone(), ed);

        // VRF signer
        let vrf = SchnorrkelVrfSigner::from_deterministic_seed([(i as u8).wrapping_add(7); 32]);
        node.set_vrf_signer(vrf);

        // Shared validator set and my BLS signer
        node.init_with_shared_validator_set(validators.clone(), bls_signers[i].clone());

        // Configure HotStuff
        let active_bls_pks: Vec<[u8; 48]> = validators.iter().map(|v| v.bls_pubkey.expect("bls")).collect();
        let now_ms: u128 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let mut pacemaker = l1_blockchain::types::Pacemaker::new(1000, 10000, 3, 2);
        pacemaker.on_enter_view(now_ms);

        let hs_state = HotStuffState {
            current_view: 1,
            locked_block: ([0u8; 32], 0),
            high_qc: genesis_qc.clone(),
            pacemaker,
        };
        let hotstuff = HotStuff::new(hs_state, active_bls_pks, i as ValidatorId, Some(bls_signers[i].clone()));
        node.set_hotstuff(hotstuff);

        // Align slot clock for deterministic dev behavior
        node.align_clock_for_test();

        nodes.push(Arc::new(Mutex::new(node)));
    }

    // Wire up P2P consensus networking across validators
    {
        let ids: Vec<ValidatorId> = (0..n as u64).collect();
        let networks = create_test_network(ids).await?;
        for (i, net) in networks.into_iter().enumerate() {
            nodes[i].lock().unwrap().set_consensus_network(net);
        }
    }

    // Spawn per-node production loops: block production, consensus processing, pacemaker
    for (i, node) in nodes.iter().cloned().enumerate() {
        // Block production once per slot
        tokio::spawn(async move {
            // Use the node's configured slot duration
            let slot_ms = { node.lock().unwrap().slot_ms() };
            let mut tick = interval(Duration::from_millis(slot_ms));
            loop {
                tick.tick().await;
                let mut n = node.lock().unwrap();
                let _ = n.produce_block(DEFAULT_LIMITS.clone());
            }
        });

        // Fast consensus message processing + pacemaker timeout checks
        let node2 = nodes[i].clone();
        tokio::spawn(async move {
            let mut tick = interval(Duration::from_millis(100));
            loop {
                tick.tick().await;
                let mut n = node2.lock().unwrap();
                let _ = n.process_consensus_messages();
                let _ = n.check_pacemaker_timeout();
            }
        });
    }

    // Spawn RPC servers for each validator
    let mut rpc_handles = Vec::with_capacity(n);
    for i in 0..n {
        let node = nodes[i].clone();
        let port = rpc_base + (i as u16);
        let app_state = AppState { node, faucet: Arc::new(Mutex::new(FaucetLimiter::new(1_000_000))) };
        let app: Router = rpc::router(app_state);
        println!("RPC[{}] listening on http://127.0.0.1:{}", i, port);
        let addr = format!("127.0.0.1:{}", port);
        let handle = tokio::spawn(async move {
            let listener = TcpListener::bind(&addr).await.expect("bind rpc");
            axum::serve(listener, app).await.expect("rpc serve");
        });
        rpc_handles.push(handle);
    }

    // Keep running until Ctrl+C
    tokio::signal::ctrl_c().await.expect("listen for ctrl_c");
    println!("Shutting down localnet_multi...");
    Ok(())
}
