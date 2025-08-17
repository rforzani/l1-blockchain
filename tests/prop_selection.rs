//! Property test for IL reveal nonce correctness, external (integration) test.
//! Run: `cargo test --test prop_selection -- --nocapture`

use proptest::prelude::*;
use std::sync::Arc;

// ===== Adjust the crate name if needed (Cargo.toml [package].name; hyphen -> underscore) =====
use l1_blockchain::mempool::{
    AdmissionError, BlockSelectionLimits, CommitmentId, Mempool, MempoolConfig, MempoolImpl, StateView,
};
use l1_blockchain::types::{RevealTx, Transaction, AccessList, CommitTx, Tx};
use l1_blockchain::codec::{access_list_bytes, tx_bytes};
use l1_blockchain::crypto::commitment_hash;
use l1_blockchain::state::CHAIN_ID;

// -------------------- Small helpers for this test --------------------

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

/// Build a minimal RevealTx for a given sender, nonce and salt.
fn make_reveal_tx(sender: String, nonce: u64, salt: [u8;32]) -> RevealTx {
    let to = "0x0000000000000000000000000000000000000001".to_string();
    RevealTx {
        sender: sender.clone(),
        salt,
        tx: Transaction {
            from: sender.clone(),
            to: to.clone(),
            amount: 1u64,
            nonce,
            access_list: AccessList::for_transfer(&sender, &to),
        },
    }
}

/// Insert a commit + reveal pair into the mempool and return the commitment id.
fn insert_commit_and_reveal(
    mem: &Arc<MempoolImpl>,
    sender: &str,
    nonce: u64,
    salt: [u8;32],
    height: u64,
    fee_bid: u128,
) -> Result<CommitmentId, AdmissionError> {
    let r = make_reveal_tx(sender.to_owned(), nonce, salt);
    let tx_ser = tx_bytes(&r.tx);
    let al_bytes = access_list_bytes(&r.tx.access_list);
    let cmt = commitment_hash(&tx_ser, &al_bytes, &r.salt, CHAIN_ID);

    let commit = CommitTx {
        commitment: cmt,
        sender: sender.to_owned(),
        access_list: r.tx.access_list.clone(),
        ciphertext_hash: [0u8;32],
        pubkey: [0u8;32],
        sig: [0u8;64],
    };

    mem.insert_commit(Tx::Commit(commit), height, fee_bid)?;
    mem.insert_reveal(r, height, fee_bid)?;
    Ok(CommitmentId(cmt))
}

fn cfg() -> MempoolConfig {
    MempoolConfig {
        max_avails_per_block: 1024,
        max_reveals_per_block: 2048,
        max_commits_per_block: 4096,
        max_pending_commits_per_account: 10, // allow multiple commits per account in tests
        commit_ttl_blocks: 100,
        reveal_window_blocks: 50,
    }
}

// -------------------- The property test --------------------

proptest! {
    /// IL must succeed iff each IL commitment has a reveal at the required nonce (0 in this SV).
    #[test]
    fn prop_il_reveals_nonce_correctness(
        // Random salts to derive distinct commitments
        salts in proptest::collection::vec(any::<[u8;32]>(), 1..5),
        // generate a valid hex sender address
        sender in any::<[u8;20]>().prop_map(|b| format!("0x{}", hex::encode(b))),
        // if true: include correct nonce=0 for *every* IL commitment; otherwise insert wrong nonce=1 for all
        include_required in any::<bool>(),
    ) {
        let height = 123;
        let mem: Arc<MempoolImpl> = MempoolImpl::new(cfg());
        let fee_bid: u128 = 1_000;

        // Insert commit+reveal for each salt and collect the resulting commitments for the IL
        let mut il: Vec<CommitmentId> = Vec::new();
        for (i, salt) in salts.into_iter().enumerate() {
            let n = if include_required { i as u64 } else { i as u64 + 1 };
            match insert_commit_and_reveal(&mem, &sender, n, salt, height, fee_bid) {
                Ok(c) => il.push(c),
                Err(AdmissionError::Duplicate) => continue,
                Err(e) => panic!("insert: {:?}", e),
            }
        }

        let state = SV { height, il: il.clone() };

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
            prop_assert_eq!(blk.reveals.len(), il.len(), "all IL reveals should be included");
        } else {
            // Missing required nonce for at least one IL → must fail
            use l1_blockchain::mempool::SelectError;
            prop_assert!(matches!(out, Err(SelectError::InclusionListUnmet{..})),
                "selection must fail with InclusionListUnmet when required nonce is missing");
        }
    }
}

