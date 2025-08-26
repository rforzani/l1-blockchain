use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;
use tokio::{net::TcpListener, time::{sleep, Duration}};

use l1_blockchain::{
    rpc,
    node::Node,
    mempool::{MempoolConfig, MempoolImpl},
    crypto::vrf::SchnorrkelVrfSigner,
    consensus::dev_loop::DEFAULT_LIMITS
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // --- Build node ---
    let mp = MempoolImpl::new(MempoolConfig {
        max_avails_per_block: 1024,
        max_reveals_per_block: 1024,
        max_commits_per_block: 1024,
        max_pending_commits_per_account: 1024,
        commit_ttl_blocks: 16,
        reveal_window_blocks: 16,
    });

    // dev-only key; replace in real nets
    let signer = SigningKey::from_bytes(&[1u8; 32]);
    let mut node = Node::new(mp.clone(), signer);

    // deterministic VRF for dev
    let vrf = SchnorrkelVrfSigner::from_deterministic_seed([7u8; 32]);
    node.set_vrf_signer(vrf);

    // single-validator genesis with stake
    node.install_self_as_genesis_validator(1, 1_000_000);

    // make slot policy line up with tests/dev (so WrongSlot won't trip)
    node.align_clock_for_test();

    // share the node with RPC + block loop
    let shared = Arc::new(Mutex::new(node));

    // --- Block production loop: 1 block / second ---
    {
        let shared2 = shared.clone();
        tokio::spawn(async move {
            loop {
                {
                    let mut n = shared2.lock().unwrap();
                    // Ignore the result here for dev; errors will be visible in logs
                    let _ = n.produce_block(DEFAULT_LIMITS.clone());
                }
                sleep(Duration::from_millis(1000)).await;
            }
        });
    }

    // --- RPC server (Axum 0.7) ---
    let app = rpc::router(rpc::AppState { node: shared });
    let listener = TcpListener::bind("127.0.0.1:8545").await?;
    println!("RPC listening on http://127.0.0.1:8545");
    axum::serve(listener, app).await?;
    Ok(())
}
