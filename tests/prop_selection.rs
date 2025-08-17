//! Property test for IL reveal nonce correctness, external (integration) test.
//! Run: `cargo test --test prop_selection -- --nocapture`

use proptest::prelude::*;
use std::sync::Arc;

// ===== Adjust the crate name if needed (Cargo.toml [package].name; hyphen -> underscore) =====
use l1_blockchain::mempool::{
    AdmissionError, BlockSelectionLimits, CommitmentId, Mempool, MempoolConfig, MempoolImpl, StateView, TxId
};
use l1_blockchain::types::{RevealTx, Transaction, AccessList};

// -------------------- Small helpers for this test --------------------

/// Strategy to generate arbitrary CommitmentId (wrapper over [u8; 32]).
fn arb_commitment_id() -> impl Strategy<Value = CommitmentId> {
    any::<[u8; 32]>().prop_map(CommitmentId)
}

/// Dummy StateView used only in this property test.
struct SV {
    height: u64,
    il: Vec<CommitmentId>,
}

impl StateView for SV {
    fn current_height(&self) -> u64 { self.height }

    fn commitments_due_and_available(&self, _h: u64) -> Vec<CommitmentId> {
        self.il.clone()
    }

    fn reveal_nonce_required(&self, _sender: &str) -> u64 { 0 }

    // Permissive defaults so selection isn't blocked by state checks here
    fn commit_on_chain(&self, _c: CommitmentId) -> bool { true }
    fn avail_on_chain(&self, _c: CommitmentId) -> bool { false }
    fn avail_allowed_at(&self, _height: u64, _c: CommitmentId) -> bool { true }
    fn pending_commit_room(&self, _sender: &str) -> u32 { u32::MAX }
}

/// Build a minimal RevealTx for a given sender & nonce.
/// NOTE: Your `Transaction` requires {from, to, amount, nonce, access_list}.
fn make_reveal_tx(sender: String, nonce: u64) -> RevealTx {
    RevealTx {
        sender: sender.clone(),
        salt: [0u8; 32],
        tx: Transaction {
            // Use sender as `from`, a fixed dummy as `to`
            from: sender.clone(),
            to: "to_dummy".to_string(),
            amount: 1u64, // adjust if your `amount` is a different type
            nonce,
            access_list: AccessList::for_transfer(&sender, "to_dummy"),
        },
    }
}

/// Insert a reveal for a specific commitment, using the mempool API.
/// Returns Ok(TxId) if admission succeeded; Err(_) if it failed prechecks.
fn insert_reveal_for_commitment(
    mem: &Arc<MempoolImpl>,
    _commit: CommitmentId, // not needed directly; commit is re-derived in your mempool from the reveal
    sender: &str,
    nonce: u64,
    height: u64,
    fee_bid: u128,
) -> Result<TxId, AdmissionError> {
    let r = make_reveal_tx(sender.to_owned(), nonce);
    // Your mempool has `insert_reveal(&RevealTx, height, fee_bid)`
    mem.insert_reveal(r, height, fee_bid)
}

fn cfg() -> MempoolConfig {
    MempoolConfig {
        max_avails_per_block: 1024,
        max_reveals_per_block: 2048,
        max_commits_per_block: 4096,
        max_pending_commits_per_account: 2, // small for tests
        commit_ttl_blocks: 100,
        reveal_window_blocks: 50,
    }
}

// -------------------- The property test --------------------

proptest! {
    /// IL must succeed iff each IL commitment has a reveal at the required nonce (0 in this SV).
    #[test]
    fn prop_il_reveals_nonce_correctness(
        // keep IL smallish for speed; your selection logic is O(k) in IL size
        il in proptest::collection::vec(arb_commitment_id(), 1..5),
        // a single short sender is sufficient to stress nonce behavior
        sender in "[a-z]{1,6}",
        // if true: include correct nonce=0 for *every* IL commitment; otherwise insert wrong nonce=1 for all
        include_required in any::<bool>(),
    ) {
        let height = 123;
        let state = SV { height, il: il.clone() };

        // MempoolImpl::new requires a MempoolConfig and returns Arc<MempoolImpl>
        // If MempoolConfig::default() doesn't exist, construct the fields explicitly.
        let mem: Arc<MempoolImpl> = MempoolImpl::new(cfg());
        let fee_bid: u128 = 1_000;

        // Insert reveals for each IL commitment:
        for &c in &il {
            if include_required {
                // Correct nonce that matches SV.reveal_nonce_required() == 0
                let _ = insert_reveal_for_commitment(&mem, c, &sender, 0, height, fee_bid);
            } else {
                // Only wrong nonce present → selection must fail with InclusionListUnmet
                let _ = insert_reveal_for_commitment(&mem, c, &sender, 1, height, fee_bid);
            }
        }

        // Select a block with enough capacity to include all IL reveals
        let limits = BlockSelectionLimits {
            max_reveals: 1_000,
            max_avails: 0,
            max_commits: 0,
        };

        let out = mem.select_block(&state, limits);

        if include_required {
            prop_assert!(out.is_ok(), "selection should succeed when every IL commitment has a reveal at required nonce=0");
            let blk = out.unwrap();
            // In this SV, payload-missing isn’t simulated, so count should match IL size
            prop_assert_eq!(blk.reveals.len(), il.len(), "all IL reveals should be included");
        } else {
            // Missing required nonce for at least one IL → must fail
            use l1_blockchain::mempool::SelectError;
            prop_assert!(matches!(out, Err(SelectError::InclusionListUnmet{..})),
                "selection must fail with InclusionListUnmet when required nonce is missing");
        }
    }
}