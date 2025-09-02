//! Local devnet: spin up multiple validators with RPC + P2P HotStuff
//!
//! - Starts N validators (default 3) and M observers (default 0) in a single process
//! - Each validator has its own RPC port (base 8545 + idx)
//! - Nodes discover each other via libp2p (using the in-crate P2P helper)
//! - Runs HotStuff consensus end-to-end (proposal, votes, QC broadcast)
//!
//! Usage:
//!   cargo run --bin localnet_multi -- [N_VALIDATORS] [N_OBSERVERS] [RPC_BASE]
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
        // Use the exact same deterministic seed scheme as nodes for VRF so proofs verify
        let vrf_signer = SchnorrkelVrfSigner::from_deterministic_seed([(i as u8).wrapping_add(7); 32]);
        let vrf_pub = vrf_signer.public_bytes();

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
    // Parse CLI args: N validators, M observers, and base RPC port
    let args: Vec<String> = env::args().collect();
    let n_validators: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(3);
    let n_observers: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
    let rpc_base: u16 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(8545);

    // Build shared validator set and keys
    let (validators, bls_signers, ed_seeds) = make_validators(n_validators);
    let genesis_qc = make_genesis_qc(&bls_signers);

    // Build nodes
    let total = n_validators + n_observers;
    let mut nodes: Vec<Arc<Mutex<Node>>> = Vec::with_capacity(total);
    // Precompute ed25519 seeds for observers as well
    let mut ed_all: Vec<[u8; 32]> = Vec::with_capacity(total);
    ed_all.extend_from_slice(&ed_seeds);
    for j in 0..n_observers {
        ed_all.push([((n_validators + j) as u8).wrapping_add(1); 32]);
    }

    for i in 0..total {
        let mp = MempoolImpl::new(build_mempool_config());
        let ed = SigningKey::from_bytes(&ed_all[i]);
        let mut node = Node::new(mp.clone(), ed);

        // VRF signer
        let vrf = SchnorrkelVrfSigner::from_deterministic_seed([(i as u8).wrapping_add(7); 32]);
        node.set_vrf_signer(vrf);

        // Shared validator set installed on all nodes. Observers are not included in this set.
        // For nodes beyond n_validators, provide a throwaway BLS signer for genesis install only.
        let my_bls_install = if i < n_validators {
            bls_signers[i].clone()
        } else {
            let sk = [((i as u8).wrapping_add(10)); 32];
            BlsSigner::from_sk_bytes(&sk).expect("valid bls sk")
        };
        node.init_with_shared_validator_set(validators.clone(), my_bls_install.clone());

        // Configure HotStuff
        let active_bls_pks: Vec<[u8; 48]> = validators.iter().map(|v| v.bls_pubkey.expect("bls")).collect();
        let now_ms: u128 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let mut pacemaker = l1_blockchain::types::Pacemaker::new(500, 8000, 3, 2, 1, 1);
        pacemaker.on_enter_view(now_ms);

        let hs_state = HotStuffState {
            current_view: 1,
            locked_block: ([0u8; 32], 0),
            high_qc: genesis_qc.clone(),
            pacemaker,
        };
        // Observers (i >= n_validators) do not have a BLS signer in HotStuff to suppress voting traffic.
        let hotstuff = HotStuff::new(
            hs_state,
            active_bls_pks,
            i as ValidatorId,
            if i < n_validators { Some(my_bls_install) } else { None }
        );
        node.set_hotstuff(hotstuff);

        // Shorter slot period for faster dev loops: set 500ms and align clock
        node.set_slot_ms(500);
        node.align_clock_for_test();

        let arc = Arc::new(Mutex::new(node));
        {
            let mut guard = arc.lock().unwrap();
            // Already set above; ensure state reflects these settings
            guard.set_slot_ms(500);
            guard.align_clock_for_test();
        }
        nodes.push(arc);
    }

    // Wire up P2P consensus networking across all nodes (validators + observers)
    {
        let ids: Vec<ValidatorId> = (0..total as u64).collect();
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

        // Fast consensus message processing: await messages and handle immediately
        let node2 = nodes[i].clone();
        tokio::spawn(async move {
            // Obtain a dedicated subscription to the consensus network
            let mut rx_opt = { node2.lock().unwrap().consensus_network().map(|net| net.subscribe()) };
            let mut poll = interval(Duration::from_millis(50));
            loop {
                if let Some(rx) = rx_opt.as_mut() {
                    tokio::select! {
                        biased;
                        // Process incoming consensus messages immediately
                        msg = rx.recv() => {
                            match msg {
                                Ok(msg) => {
                                    let mut n = node2.lock().unwrap();
                                    let _ = n.process_consensus_message(msg);
                                    let _ = n.check_pacemaker_timeout();
                                }
                                Err(_) => {
                                    // Re-subscribe on channel closed
                                    rx_opt = { node2.lock().unwrap().consensus_network().map(|net| net.subscribe()) };
                                    tokio::time::sleep(Duration::from_millis(5)).await;
                                }
                            }
                        }
                        // Periodic poll to drive timeouts and pending work even if no messages
                        _ = poll.tick() => {
                            let mut n = node2.lock().unwrap();
                            let _ = n.process_consensus_messages();
                            let _ = n.check_pacemaker_timeout();
                        }
                    }
                } else {
                    // No network yet; backoff a bit and retry
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    rx_opt = { node2.lock().unwrap().consensus_network().map(|net| net.subscribe()) };
                }
            }
        });
    }

    // Spawn RPC servers for each node
    let mut rpc_handles = Vec::with_capacity(total);
    for i in 0..total {
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
