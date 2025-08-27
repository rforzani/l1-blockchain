//! Property test for IL reveal nonce correctness, external (integration) test.
//! Run: `cargo test --test prop_selection -- --nocapture`

use proptest::prelude::*;
use std::sync::Arc;
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};

// ===== Adjust the crate name if needed (Cargo.toml [package].name; hyphen -> underscore) =====
use l1_blockchain::codec::{access_list_bytes, tx_bytes};
use l1_blockchain::crypto::commitment_hash;
use l1_blockchain::mempool::{
    AdmissionError, BlockSelectionLimits, CommitmentId, Mempool, MempoolConfig, MempoolImpl,
    StateView, BalanceView,
};
use l1_blockchain::state::CHAIN_ID;
use l1_blockchain::types::{AccessList, AvailTx, CommitTx, RevealTx, Transaction, Tx, Address, Hash};
use l1_blockchain::crypto::bls::BlsSigner;
use l1_blockchain::fees::FeeState;
use l1_blockchain::mempool::encrypted::ThresholdCiphertext;

// -------------------- Small helpers for this test --------------------

// Helper to create mock encrypted payloads for testing
fn mock_threshold_ciphertext() -> ThresholdCiphertext {
    let ephemeral_pk = BlsSigner::from_sk_bytes(&[1u8; 32])
        .expect("valid sk")
        .public_key_bytes();
    ThresholdCiphertext {
        ephemeral_pk,
        encrypted_data: vec![0u8; 32],
        tag: [0u8; 32],
        epoch: 1,
    }
}

/// Dummy StateView used only in this property test.
struct SV {
    height: u64,
    il: Vec<CommitmentId>,
}

struct TestBalanceView;
impl BalanceView for TestBalanceView {
    fn balance_of(&self, _who: &Address) -> u64 { u64::MAX }
}

impl StateView for SV {
    fn current_height(&self) -> u64 {
        self.height
    }

    fn commitments_due_and_available(&self, _h: u64) -> Vec<CommitmentId> {
        self.il.clone()
    }

    fn reveal_nonce_required(&self, _sender: &str) -> u64 {
        0
    }

    // Permissive defaults so selection isn't blocked by state checks here
    fn commit_on_chain(&self, _c: CommitmentId) -> bool {
        true
    }
    fn avail_on_chain(&self, _c: CommitmentId) -> bool {
        false
    }
    fn avail_allowed_at(&self, _height: u64, _c: CommitmentId) -> bool {
        true
    }
    fn pending_commit_room(&self, _sender: &str) -> u32 {
        u32::MAX
    }
}

/// Build a minimal RevealTx for a given sender, nonce and salt.
fn make_reveal_tx(sender: String, nonce: u64, salt: [u8; 32]) -> RevealTx {
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

proptest! {
    #[test]
    fn prop_il_reveal_payload_missing(
        salt in any::<[u8;32]>(),
        sender in any::<[u8;20]>().prop_map(|b| format!("0x{}", hex::encode(b))),
    ) {
        let height = 42;
        let mem: Arc<MempoolImpl> = MempoolImpl::new(cfg());
        let fee_bid: u128 = 1_000;

        let commit_id = insert_commit_and_reveal(&mem, &sender, 0, salt, height, fee_bid)
            .expect("insert commit+reveal");

        {
            let (_c, _a, mut reveals) = mem.debug_write();
            let txid_opt = reveals
                .by_commitment
                .get(&commit_id)
                .and_then(|tree| tree.values().next().copied());
            if let Some(txid) = txid_opt {
                reveals.payload_by_id.remove(&txid);
            }
        }

        let state = SV { height, il: vec![commit_id] };
        let limits = BlockSelectionLimits { max_reveals: 10, max_avails: 0, max_commits: 0 };
        let blk = mem.select_block(&state, limits).expect("selection ok");
        prop_assert_eq!(blk.reveals.len(), 0);
    }
}

proptest! {
    #[test]
    fn prop_block_selection_deterministic(
        salts in proptest::collection::vec(any::<[u8;32]>(), 0..=6),
        seed1 in any::<[u8;32]>(),
        seed2 in any::<[u8;32]>(),
    ) {
        let cfg = cfg();
        let mp1: Arc<MempoolImpl> = MempoolImpl::new(cfg.clone());
        let mp2: Arc<MempoolImpl> = MempoolImpl::new(cfg);

        // Build identical tx triples for both mempools
        let mut triples = Vec::new();
        for (i, salt) in salts.iter().enumerate() {
            let sender = format!("0x{:040x}", i + 1);
            let (commit, avail, reveal, cid) = build_triple(sender, 0, *salt);
            triples.push((commit, avail, reveal, cid));
        }

        // Helper to produce shuffled operations ensuring commits precede reveals
        fn shuffled_ops(seed: [u8;32], n: usize) -> Vec<(usize, u8)> {
            let mut ops: Vec<(usize, u8)> = Vec::new();
            for i in 0..n {
                ops.push((i, 0)); // commit
                ops.push((i, 1)); // avail
                ops.push((i, 2)); // reveal
            }
            let mut rng = StdRng::from_seed(seed);
            ops.shuffle(&mut rng);

            for idx in 0..n {
                let mut cpos = None;
                let mut rpos = None;
                for (pos, (ti, kind)) in ops.iter().enumerate() {
                    if *ti == idx {
                        match kind {
                            0 => cpos = Some(pos),
                            2 => rpos = Some(pos),
                            _ => {}
                        }
                    }
                }
                if let (Some(c), Some(r)) = (cpos, rpos) {
                    if c > r {
                        ops.swap(c, r);
                    }
                }
            }
            ops
        }

        let n = triples.len();
        let ops1 = shuffled_ops(seed1, n);
        for (idx, kind) in ops1 {
            let (ref c, ref a, ref r, _) = triples[idx];
            match kind {
                0 => { mp1.insert_commit(c.clone(), 0, 1, &TestBalanceView{}, &FeeState::from_defaults()).unwrap(); }
                1 => { mp1.insert_avail(a.clone(), 0, 1, &TestBalanceView{}, &FeeState::from_defaults()).unwrap(); }
                _ => { mp1.insert_reveal(r.clone(), 0, 1, &TestBalanceView{}, &FeeState::from_defaults()).unwrap(); }
            }
        }

        let ops2 = shuffled_ops(seed2, n);
        for (idx, kind) in ops2 {
            let (ref c, ref a, ref r, _) = triples[idx];
            match kind {
                0 => { mp2.insert_commit(c.clone(), 0, 1, &TestBalanceView{}, &FeeState::from_defaults()).unwrap(); }
                1 => { mp2.insert_avail(a.clone(), 0, 1, &TestBalanceView{}, &FeeState::from_defaults()).unwrap(); }
                _ => { mp2.insert_reveal(r.clone(), 0, 1, &TestBalanceView{}, &FeeState::from_defaults()).unwrap(); }
            }
        }

        // Select blocks with identical state view and limits
        let il: Vec<CommitmentId> = triples.iter().map(|t| t.3).collect();
        let state = SV { height: 0, il };
        let limits = BlockSelectionLimits { max_reveals: 1024, max_avails: 1024, max_commits: 1024 };

        let blk1 = mp1.select_block(&state, limits).expect("mp1 select");
        let blk2 = mp2.select_block(&state, limits).expect("mp2 select");

        prop_assert_eq!(blk1.reveals, blk2.reveals);
        prop_assert_eq!(blk1.txs, blk2.txs);
    }
}

proptest! {
    #[test]
    fn prop_extra_reveals_nonce_continuity(
        salts in proptest::collection::vec(any::<[u8;32]>(), 2),
        sender in any::<[u8;20]>().prop_map(|b| format!("0x{}", hex::encode(b))),
    ) {
        let height = 55;
        let mem: Arc<MempoolImpl> = MempoolImpl::new(cfg());
        let fee_bid: u128 = 1_000;

        let il_commit = insert_commit_and_reveal(&mem, &sender, 0, salts[0], height, fee_bid)
            .expect("il insert");

        insert_commit_and_reveal(&mem, &sender, 2, salts[1], height, fee_bid)
            .expect("extra insert");

        let state = SV { height, il: vec![il_commit] };
        let limits = BlockSelectionLimits { max_reveals: 5, max_avails: 0, max_commits: 0 };
        let blk = mem.select_block(&state, limits).expect("selection ok");
        prop_assert_eq!(blk.reveals.len(), 1);
        prop_assert_eq!(blk.reveals[0].tx.nonce, 0);
    }
}

proptest! {
    #[test]
    fn prop_fee_ordering_for_extras(
        salts in proptest::collection::vec(any::<[u8;32]>(), 3),
        sender in any::<[u8;20]>().prop_map(|b| format!("0x{}", hex::encode(b))),
    ) {
        let height = 60;
        let mem: Arc<MempoolImpl> = MempoolImpl::new(cfg());
        let fees = [1u128, 3, 2];

        for i in 0..3 {
            insert_commit_and_reveal(&mem, &sender, 0, salts[i], height, fees[i])
                .expect("insert extra");
        }

        let state = SV { height, il: vec![] };
        let limits = BlockSelectionLimits { max_reveals: 1, max_avails: 0, max_commits: 0 };
        let blk = mem.select_block(&state, limits).expect("selection ok");
        prop_assert_eq!(blk.reveals.len(), 1);
        prop_assert_eq!(blk.reveals[0].salt, salts[1]);
    }
}

proptest! {
    #[test]
    fn prop_reveal_cap_enforced(
        salts in proptest::collection::vec(any::<[u8;32]>(), 4),
        sender in any::<[u8;20]>().prop_map(|b| format!("0x{}", hex::encode(b))),
    ) {
        let height = 77;
        let mem: Arc<MempoolImpl> = MempoolImpl::new(cfg());
        let fee_bid: u128 = 1_000;

        let il_commit = insert_commit_and_reveal(&mem, &sender, 0, salts[0], height, fee_bid)
            .expect("il insert");
        for (i, salt) in salts[1..].iter().enumerate() {
            insert_commit_and_reveal(&mem, &sender, (i + 1) as u64, *salt, height, fee_bid)
                .expect("extra insert");
        }

        let state = SV { height, il: vec![il_commit] };
        let limits = BlockSelectionLimits { max_reveals: 2, max_avails: 0, max_commits: 0 };
        let blk = mem.select_block(&state, limits).expect("selection ok");
        prop_assert_eq!(blk.reveals.len(), 2);
        prop_assert_eq!(blk.reveals[0].tx.nonce, 0);
        prop_assert_eq!(blk.reveals[1].tx.nonce, 1);
    }
}

proptest! {
    #[test]
    fn prop_avails_ordering(
        commitments in proptest::collection::vec(any::<[u8;32]>(), 3),
        sender in any::<[u8;20]>().prop_map(|b| format!("0x{}", hex::encode(b))),
    ) {
        let mem: Arc<MempoolImpl> = MempoolImpl::new(cfg());
        let height = 88;
        let fees = [5u128, 20, 10];

        let a0 = AvailTx { commitment: commitments[0], sender: sender.clone(), payload_hash: [1u8; 32], payload_size: 100, pubkey: [0u8;32], sig: [0u8;64] };
        let a1 = AvailTx { commitment: commitments[1], sender: sender.clone(), payload_hash: [1u8; 32], payload_size: 100, pubkey: [0u8;32], sig: [0u8;64] };
        let a2 = AvailTx { commitment: commitments[2], sender: sender.clone(), payload_hash: [1u8; 32], payload_size: 100, pubkey: [0u8;32], sig: [0u8;64] };

        mem.insert_avail(Tx::Avail(a0.clone()), height, fees[0], &TestBalanceView{}, &FeeState::from_defaults()).unwrap();
        mem.insert_avail(Tx::Avail(a1.clone()), height, fees[1], &TestBalanceView{}, &FeeState::from_defaults()).unwrap();
        // not ready yet
        mem.insert_avail(Tx::Avail(a2.clone()), height + 1, fees[2], &TestBalanceView{}, &FeeState::from_defaults()).unwrap();

        let state = SV { height, il: vec![] };
        let limits = BlockSelectionLimits { max_reveals: 0, max_avails: 10, max_commits: 0 };
        let blk = mem.select_block(&state, limits).expect("selection ok");
        prop_assert_eq!(blk.txs.len(), 2);
        match (&blk.txs[0], &blk.txs[1]) {
            (Tx::Avail(x), Tx::Avail(y)) => {
                prop_assert_eq!(x.commitment, commitments[1]);
                prop_assert_eq!(y.commitment, commitments[0]);
            }
            _ => prop_assert!(false, "expected avail txs"),
        }
    }
}

proptest! {
    #[test]
    fn prop_commit_cap_enforced(
        salts in proptest::collection::vec(any::<[u8;32]>(), 3),
        sender in any::<[u8;20]>().prop_map(|b| format!("0x{}", hex::encode(b))),
    ) {
        let height = 99;
        let mem: Arc<MempoolImpl> = MempoolImpl::new(cfg());
        let fees = [1u128, 5, 3];
        let mut ids = Vec::new();

        for i in 0..3 {
            let id = insert_commit_only(&mem, &sender, i as u64, salts[i], height, fees[i])
                .expect("commit insert");
            ids.push(id);
        }

        let state = SV { height, il: vec![] };
        let limits = BlockSelectionLimits { max_reveals: 0, max_avails: 0, max_commits: 1 };
        let blk = mem.select_block(&state, limits).expect("selection ok");
        prop_assert_eq!(blk.txs.len(), 1);
        match &blk.txs[0] {
            Tx::Commit(c) => {
                prop_assert_eq!(c.commitment, ids[1].0);
            }
            _ => prop_assert!(false, "expected commit tx"),
        }
    }
}

/// Insert a commit + reveal pair into the mempool and return the commitment id.
fn insert_commit_and_reveal(
    mem: &Arc<MempoolImpl>,
    sender: &str,
    nonce: u64,
    salt: [u8; 32],
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
        encrypted_payload: mock_threshold_ciphertext(),
        pubkey: [0u8; 32],
        sig: [0u8; 64],
    };

    mem.insert_commit(Tx::Commit(commit), height, fee_bid, &TestBalanceView{}, &FeeState::from_defaults())?;
    mem.insert_reveal(r, height, fee_bid, &TestBalanceView{}, &FeeState::from_defaults())?;
    Ok(CommitmentId(cmt))
}

/// Insert only a commit (no reveal) and return its commitment id.
fn insert_commit_only(
    mem: &Arc<MempoolImpl>,
    sender: &str,
    nonce: u64,
    salt: [u8; 32],
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
        encrypted_payload: mock_threshold_ciphertext(),
        pubkey: [0u8; 32],
        sig: [0u8; 64],
    };

    mem.insert_commit(Tx::Commit(commit), height, fee_bid, &TestBalanceView{}, &FeeState::from_defaults())?;
    Ok(CommitmentId(cmt))
}

/// Construct a commit, avail, and reveal triple for a given sender and nonce.
fn build_triple(
    sender: String,
    nonce: u64,
    salt: [u8; 32],
) -> (Tx, Tx, RevealTx, CommitmentId) {
    let reveal = make_reveal_tx(sender.clone(), nonce, salt);
    let tx_ser = tx_bytes(&reveal.tx);
    let al_bytes = access_list_bytes(&reveal.tx.access_list);
    let cmt = commitment_hash(&tx_ser, &al_bytes, &reveal.salt, CHAIN_ID);

    let commit = CommitTx {
        commitment: cmt,
        sender: sender.clone(),
        access_list: reveal.tx.access_list.clone(),
        encrypted_payload: mock_threshold_ciphertext(),
        pubkey: [0u8; 32],
        sig: [0u8; 64],
    };

    let avail = AvailTx {
        commitment: cmt,
        sender: sender.clone(),
        payload_hash: [1u8; 32],
        payload_size: 100,
        pubkey: [0u8; 32],
        sig: [0u8; 64],
    };

    (Tx::Commit(commit), Tx::Avail(avail), reveal, CommitmentId(cmt))
}

fn cfg() -> MempoolConfig {
    MempoolConfig {
        max_avails_per_block: 1024,
        max_reveals_per_block: 2048,
        max_commits_per_block: 4096,
        max_pending_commits_per_account: 20, // allow multiple commits per account in tests
        commit_ttl_blocks: 100,
        reveal_window_blocks: 50,
    }
}

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

proptest! {
    #[test]
    fn prop_il_limits_and_duplicates(
        reveal_data in proptest::collection::vec((any::<[u8;32]>(), any::<bool>()), 0..=12),
        sender in any::<[u8;20]>().prop_map(|b| format!("0x{}", hex::encode(b))),
        max_reveals in 0u32..=16u32,
        max_avails in 0u32..=16u32,
        max_commits in 0u32..=16u32,
    ) {
        let height = 200u64;
        let mem: Arc<MempoolImpl> = MempoolImpl::new(cfg());
        let fee_bid: u128 = 1_000;

        // insert commit+reveal pairs, optionally attempting duplicate reveals
        let mut il: Vec<CommitmentId> = Vec::new();
        for (i, (salt, dup)) in reveal_data.iter().enumerate() {
            match insert_commit_and_reveal(&mem, &sender, i as u64, *salt, height, fee_bid) {
                Ok(id) => {
                    if *dup {
                        // attempt to insert a duplicate reveal for the same (sender, nonce, commitment)
                        let dup_rev = make_reveal_tx(sender.clone(), i as u64, *salt);
                        let _ = mem.insert_reveal(dup_rev, height, fee_bid, &TestBalanceView{}, &FeeState::from_defaults());
                    }
                    il.push(id);
                }
                Err(AdmissionError::Duplicate) => {
                    // ignore duplicates from repeated salts
                }
                Err(e) => panic!("unexpected insert error: {:?}", e),
            }
        }

        let state = SV { height, il: il.clone() };
        let limits = BlockSelectionLimits { max_reveals, max_avails, max_commits };
        let res = mem.select_block(&state, limits);

        if il.is_empty() {
            let blk = res.expect("empty IL must succeed");
            prop_assert!(blk.reveals.len() <= max_reveals as usize);

            let avail_count = blk
                .txs
                .iter()
                .filter(|tx| matches!(tx, Tx::Avail(_)))
                .count();
            let commit_count = blk
                .txs
                .iter()
                .filter(|tx| matches!(tx, Tx::Commit(_)))
                .count();
            prop_assert!(avail_count <= max_avails as usize);
            prop_assert!(commit_count <= max_commits as usize);
        } else if max_reveals as usize >= il.len() {
            let blk = res.expect("selection should succeed when cap is sufficient");
            prop_assert!(blk.reveals.len() >= il.len());
            prop_assert!(blk.reveals.len() <= max_reveals as usize);

            let avail_count = blk
                .txs
                .iter()
                .filter(|tx| matches!(tx, Tx::Avail(_)))
                .count();
            let commit_count = blk
                .txs
                .iter()
                .filter(|tx| matches!(tx, Tx::Commit(_)))
                .count();
            prop_assert!(avail_count <= max_avails as usize);
            prop_assert!(commit_count <= max_commits as usize);
        } else {
            use l1_blockchain::mempool::SelectError;
            match res {
                Err(SelectError::InclusionListUnmet { .. }) => {}
                other => prop_assert!(false, "expected InclusionListUnmet, got {:?}", other),
            }
        }
    }
}