use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;
use tokio::{net::TcpListener, time::Duration};

use l1_blockchain::{
    consensus::dev_loop::DEFAULT_LIMITS, crypto::vrf::SchnorrkelVrfSigner, mempool::{MempoolConfig, MempoolImpl}, node::Node, rpc::{self, AppState, FaucetLimiter}
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

    // Use 500ms slots for local dev and align
    node.set_slot_ms(500);
    node.align_clock_for_test();

    // share the node with RPC + block loop
    let shared = Arc::new(Mutex::new(node));

    // --- Block production loop: one block per 500ms slot ---
    {
        let shared2 = shared.clone();
        tokio::spawn(async move {
            // Use `interval` so that block production stays aligned to the
            // 1-second slot boundary even if producing a block takes time.
            let mut ticker = tokio::time::interval(Duration::from_millis(500));
            loop {
                ticker.tick().await;
                let mut n = shared2.lock().unwrap();
                // Ignore the result here for dev; errors will be visible in logs
                let _ = n.produce_block(DEFAULT_LIMITS.clone());
            }
        });
    }

    // --- RPC server (Axum 0.7) ---
    let app_state = AppState {
        node: shared,
        // e.g., 1_000_000 units/day/address cap — adjust to your token’s decimals
        faucet: Arc::new(Mutex::new(FaucetLimiter::new(1_000_000))),
    };
    let app = rpc::router(app_state);
    let listener = TcpListener::bind("127.0.0.1:8545").await?;
    println!("RPC listening on http://127.0.0.1:8545");
    axum::serve(listener, app).await?;
    Ok(())
}
