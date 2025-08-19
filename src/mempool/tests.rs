// src/mempool/tests.rs
#![allow(unused)]

use std::{collections::HashMap, sync::Arc};

use crate::mempool::{
    BlockSelectionLimits, CommitmentId, Mempool, MempoolConfig, MempoolImpl, SelectError, TxId,
    BalanceView,
};
use crate::codec::{tx_bytes, access_list_bytes};
use crate::crypto::{hash_bytes_sha256, commitment_hash};
use crate::state::CHAIN_ID;
use crate::types::{
    Tx, CommitTx, AvailTx, RevealTx, Transaction, AccessList, StateKey, Hash, Address,
};
use crate::fees::FeeState;

// -------------------------- tiny helpers for building txs --------------------------

struct TestBalanceView;
impl BalanceView for TestBalanceView {
    fn balance_of(&self, _who: &Address) -> u64 { u64::MAX }
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

fn limits() -> BlockSelectionLimits {
    BlockSelectionLimits {
        max_avails: 1024,
        max_reveals: 2048,
        max_commits: 4096,
    }
}

// Minimal, valid hex address strings (20 bytes => 40 hex chars after "0x")
fn addr(i: u8) -> String {
    format!("0x{:02x}{:02x}000000000000000000000000000000000000", i, i)
}

// Build an AccessList that includes required Balance/Nonce entries for `sender`.
fn al_for_sender(sender: &str) -> AccessList {
    AccessList {
        reads: vec![
            StateKey::Balance(sender.to_string()),
            StateKey::Nonce(sender.to_string()),
        ],
        writes: vec![
            StateKey::Balance(sender.to_string()),
            StateKey::Nonce(sender.to_string()),
        ],
    }
}

// Build a simple Transaction (plaintext) that matches what the STF expects.
fn make_tx(from: &str, to: &str, value: u64, nonce: u64) -> Transaction {
    Transaction {
        from: from.to_string(),
        to: to.to_string(),
        amount: value,
        nonce,
        access_list: al_for_sender(from),
    }
}

// Compute a commitment exactly like the chain does: H(dom || chain_id || tx_bytes || salt || H(AL))
fn compute_commitment(tx: &Transaction, salt: &Hash) -> Hash {
    let tx_ser = tx_bytes(tx);
    let al_bytes = access_list_bytes(&tx.access_list);
    commitment_hash(&tx_ser, &al_bytes, salt, CHAIN_ID)
}

// Make a CommitTx whose commitment matches (tx, salt)
fn make_commit(from: &str, nonce: u64) -> (CommitTx, Transaction, Hash, Hash) {
    let to = addr(200);
    let tx = make_tx(from, &to, 1, nonce);
    let mut salt = [0u8; 32];
    salt[0] = 7; salt[1] = 7; // fixed for determinism
    let commitment = compute_commitment(&tx, &salt);

    let commit = CommitTx {
        commitment,
        sender: from.to_string(),
        access_list: tx.access_list.clone(),
        ciphertext_hash: hash_bytes_sha256(b"placeholder-ciphertext"),
        pubkey: [0u8; 32],
        sig: [0u8; 64],
    };
    (commit, tx, salt, commitment)
}

// Make an AvailTx for a given commitment/sender
fn make_avail(from: &str, commitment: Hash) -> AvailTx {
    AvailTx {
        commitment,
        sender: from.to_string(),
        pubkey: [0u8; 32],
        sig: [0u8; 64],
    }
}

// Make a RevealTx for the given (tx, salt, sender)
fn make_reveal(from: &str, tx: Transaction, salt: Hash) -> RevealTx {
    RevealTx {
        tx,
        salt,
        sender: from.to_string(),
    }
}

// ------------- a tiny fake StateView for selection tests -------------
#[derive(Default)]
struct SV {
    height: u64,
    il: Vec<CommitmentId>,
    reveal_nonces: HashMap<String, u64>,
    pending_room: HashMap<String, u32>,
}

impl crate::mempool::StateView for SV {
    fn current_height(&self) -> u64 {
        self.height
    }

    fn commitments_due_and_available(&self, _h: u64) -> Vec<CommitmentId> {
        self.il.clone()
    }

    fn reveal_nonce_required(&self, sender: &str) -> u64 {
        self.reveal_nonces.get(sender).copied().unwrap_or(0)
    }

    fn commit_on_chain(&self, _c: CommitmentId) -> bool {
        true
    }

    fn avail_on_chain(&self, _c: CommitmentId) -> bool {
        false
    }

    fn avail_allowed_at(&self, _height: u64, _c: CommitmentId) -> bool {
        true
    }

    fn pending_commit_room(&self, sender: &str) -> u32 {
        self.pending_room.get(sender).copied().unwrap_or(u32::MAX)
    }
}

// ---------------------------------- TESTS ----------------------------------

#[test]
fn commit_admission_happy_path() {
    let mp = MempoolImpl::new(cfg());
    let sender = addr(1);
    let (c, _tx, _salt, _cm) = make_commit(&sender, 0);
    let id = mp.insert_commit(Tx::Commit(c), 100, 1, &TestBalanceView{}, &FeeState::from_defaults()).expect("commit admitted");
    // smoke-check: TxId is 32 bytes (we can at least destructure it)
    let TxId(bytes) = id;
    assert_eq!(bytes.len(), 32);
}

#[test]
fn commit_bad_access_list_rejected() {
    let mp = MempoolImpl::new(cfg());
    let sender = addr(2);
    let (mut c_bad, _tx, _salt, _cm) = make_commit(&sender, 0);
    // Break AL: remove required entries to trigger BadAccessList
    c_bad.access_list.reads.clear();
    c_bad.access_list.writes.clear();
    let err = mp.insert_commit(Tx::Commit(c_bad), 100, 1, &TestBalanceView{}, &FeeState::from_defaults()).unwrap_err();
    matches_bad_access_list(err);
}

#[test]
fn commit_duplicate_rejected() {
    let mp = MempoolImpl::new(cfg());
    let sender = addr(3);
    let (c1, _tx, _salt, cm) = make_commit(&sender, 0);
    let mut c2 = c1.clone();
    c2.commitment = cm; // same commitment
    mp.insert_commit(Tx::Commit(c1), 100, 1, &TestBalanceView{}, &FeeState::from_defaults()).expect("first commit");
    let err = mp.insert_commit(Tx::Commit(c2), 100, 1, &TestBalanceView{}, &FeeState::from_defaults()).unwrap_err();
    assert!(matches!(err, crate::mempool::AdmissionError::Duplicate));
}

#[test]
fn commit_pending_cap_enforced() {
    let mut cfg = cfg();
    cfg.max_pending_commits_per_account = 2;
    let mp = MempoolImpl::new(cfg);
    let sender = addr(4);

    // Two commits should pass
    for n in 0..2 {
        let (c, _, _, _) = make_commit(&sender, n);
        mp.insert_commit(Tx::Commit(c), 100, 1, &TestBalanceView{}, &FeeState::from_defaults()).expect("admit");
    }

    // Third should hit the cap
    let (c3, _, _, _) = make_commit(&sender, 2);
    let err = mp.insert_commit(Tx::Commit(c3), 100, 1, &TestBalanceView{}, &FeeState::from_defaults()).unwrap_err();
    assert!(matches!(err, crate::mempool::AdmissionError::MempoolFullForAccount));
}

#[test]
fn reveal_sender_mismatch_rejected() {
    let mp = MempoolImpl::new(cfg());
    let good_sender = addr(5);
    let bad_sender  = addr(6);

    let to = addr(7);
    let tx = make_tx(&bad_sender, &to, 1, 0); // inner tx from != r.sender
    let r = RevealTx {
        sender: good_sender.clone(),
        tx,
        salt: [9u8; 32],
    };
    let err = mp.insert_reveal(r, 100, 1, &TestBalanceView{}, &FeeState::from_defaults()).unwrap_err();
    assert!(matches!(err, crate::mempool::AdmissionError::InvalidSignature));
}

#[test]
fn reveal_commitment_mismatch_rejected() {
    let mp = MempoolImpl::new(cfg());
    let sender = addr(8);

    // Build a matching commit with salt=[7;32]
    let (c, tx, _salt7, _cm) = make_commit(&sender, 0);
    mp.insert_commit(Tx::Commit(c), 100, 1, &TestBalanceView{}, &FeeState::from_defaults()).expect("commit admitted");

    // Reveal uses a different salt to force mismatch
    let mut salt8 = [0u8; 32];
    salt8[0] = 8;
    let r_bad = make_reveal(&sender, tx, salt8);
    let err = mp.insert_reveal(r_bad, 101, 1, &TestBalanceView{}, &FeeState::from_defaults()).unwrap_err();
    assert!(matches!(err, crate::mempool::AdmissionError::MismatchedCommitment));
}

#[test]
fn mark_included_evicts_and_decrements() {
    let mp = MempoolImpl::new(cfg());
    let sender = addr(42);

    // insert 2 commits for same sender
    let (c1, _, _, _) = make_commit(&sender, 0);
    let (c2, _, _, _) = make_commit(&sender, 1);
    let id1 = mp.insert_commit(Tx::Commit(c1), 100, 10, &TestBalanceView{}, &FeeState::from_defaults()).unwrap();
    let id2 = mp.insert_commit(Tx::Commit(c2), 100, 20, &TestBalanceView{}, &FeeState::from_defaults()).unwrap();

    // before: pending count should be 2
    {
        let (commits, _avails, _reveals) = mp.debug_read();
        let cnt = commits.pending_per_owner.get(&sender).copied().unwrap_or(0);
        assert_eq!(cnt, 2);
    }

    // mark the first included
    mp.mark_included(&[id1], 101);

    // after: 1 left; id1 gone; id2 remains
    {
        let (commits, _avails, _reveals) = mp.debug_read();
        assert!(commits.by_id.get(&id1).is_none());
        assert!(commits.by_id.get(&id2).is_some());
        let cnt = commits.pending_per_owner.get(&sender).copied().unwrap_or(0);
        assert_eq!(cnt, 1);
    }
}

#[test]
fn queues_index_coherence() {
    let mp = MempoolImpl::new(cfg());
    let sender = addr(9);

    let (c1, _, _, cm1) = make_commit(&sender, 0);
    let (c2, _, _, cm2) = make_commit(&sender, 1);
    mp.insert_commit(Tx::Commit(c1), 100, 10, &TestBalanceView{}, &FeeState::from_defaults()).unwrap();
    mp.insert_commit(Tx::Commit(c2), 100, 20, &TestBalanceView{}, &FeeState::from_defaults()).unwrap();

    // Use debug accessor to inspect internal queues.
    let (commits, _avails, _reveals) = mp.debug_read();
    assert_eq!(commits.by_id.len(), 2);
    assert_eq!(commits.by_commitment.len(), 2);
    assert_eq!(commits.fee_order.len(), 2);
    assert!(commits.by_commitment.contains_key(&CommitmentId(cm1)));
    assert!(commits.by_commitment.contains_key(&CommitmentId(cm2)));
}

#[test]
fn selection_inclusion_list_missing() {
    let mp = MempoolImpl::new(cfg());
    let fake_commitment = CommitmentId([1u8; 32]);
    let sv = SV { height: 123, il: vec![fake_commitment], ..Default::default() };
    let err = mp.select_block(&sv, limits()).unwrap_err();
    match err {
        SelectError::InclusionListUnmet { missing } => {
            assert_eq!(missing, vec![fake_commitment]);
        }
        _ => panic!("expected InclusionListUnmet"),
    }
}

#[test]
fn selection_missing_reveal_payload_logged_and_skipped() {
    let mp = MempoolImpl::new(cfg());
    let sender = addr(60);
    let (c, tx, salt, cm) = make_commit(&sender, 0);
    mp.insert_commit(Tx::Commit(c), 100, 1, &TestBalanceView{}, &FeeState::from_defaults()).unwrap();
    let r = make_reveal(&sender, tx, salt);
    let rid = mp.insert_reveal(r, 100, 1, &TestBalanceView{}, &FeeState::from_defaults()).unwrap();

    {
        let mut reveals = mp.reveals.write().unwrap();
        reveals.payload_by_id.remove(&rid);
    }

    let sv = SV { height: 101, il: vec![CommitmentId(cm)], ..Default::default() };
    let block = mp
        .select_block(&sv, limits())
        .expect("selection should succeed despite missing payload");
    assert!(block.reveals.is_empty(), "reveal with missing payload skipped");
}

#[test]
fn avail_ready_index_and_eviction() {
    let mp = MempoolImpl::new(cfg());
    let sender1 = addr(10);
    let sender2 = addr(11);

    let (_c1, _tx1, _salt1, cm1) = make_commit(&sender1, 0);
    let (_c2, _tx2, _salt2, cm2) = make_commit(&sender2, 0);
    let a1 = make_avail(&sender1, cm1);
    let a2 = make_avail(&sender2, cm2);

    let id1 = mp.insert_avail(Tx::Avail(a1.clone()), 100, 1, &TestBalanceView{}, &FeeState::from_defaults()).unwrap();
    let id2 = mp.insert_avail(Tx::Avail(a2.clone()), 100, 1, &TestBalanceView{}, &FeeState::from_defaults()).unwrap();

    {
        let (_commits, avails, _reveals) = mp.debug_read();
        let set = avails.ready_index.get(&100).expect("bucket exists");
        assert!(set.contains(&id1));
        assert!(set.contains(&id2));
    }

    {
        let mut avails_lock = mp.avails.write().unwrap();
        avails_lock.evict_by_id(&id1);
    }

    {
        let (_commits, avails, _reveals) = mp.debug_read();
        let set = avails.ready_index.get(&100).expect("bucket exists after eviction");
        assert!(!set.contains(&id1));
        assert!(set.contains(&id2));
    }
}

#[test]
fn avail_selection_deterministic_and_non_destructive() {
    let mp = MempoolImpl::new(cfg());
    let sender = addr(12);

    let (_c1, _tx1, _salt1, cm1) = make_commit(&sender, 0);
    let (_c2, _tx2, _salt2, cm2) = make_commit(&sender, 1);
    let a_high = make_avail(&sender, cm1);
    let a_low = make_avail(&sender, cm2);

    mp.insert_avail(Tx::Avail(a_high.clone()), 0, 10, &TestBalanceView{}, &FeeState::from_defaults()).unwrap();
    mp.insert_avail(Tx::Avail(a_low.clone()), 0, 5, &TestBalanceView{}, &FeeState::from_defaults()).unwrap();

    let state = SV { height: 0, il: vec![], ..Default::default() };
    let lim = limits();

    let block1 = mp.select_block(&state, lim).expect("first selection");
    assert_eq!(block1.txs, vec![Tx::Avail(a_high.clone()), Tx::Avail(a_low.clone())]);

    let block2 = mp.select_block(&state, lim).expect("second selection");
    assert_eq!(block2.txs, block1.txs);
}

#[test]
fn evict_stale_drops_old_entries_and_updates_pending_count() {
    // Tight TTLs so we can see evictions clearly.
    let mut cfg = cfg();
    cfg.commit_ttl_blocks = 5;
    cfg.reveal_window_blocks = 3;

    let mp = MempoolImpl::new(cfg);
    let sender = addr(55);

    // Two commits from the same sender:
    // - c1 at height 100 (age at purge=2) => remains
    // - c2 at height 96  (age at purge=6) => evicted
    let (c1, _tx1, _salt1, _cm1) = make_commit(&sender, 0);
    let (c2,  tx2,  salt2, _cm2) = make_commit(&sender, 1);

    let id1 = mp.insert_commit(Tx::Commit(c1), 100, 1, &TestBalanceView{}, &FeeState::from_defaults()).unwrap();
    let id2 = mp.insert_commit(Tx::Commit(c2),  96, 1, &TestBalanceView{}, &FeeState::from_defaults()).unwrap();

    // Matching reveal for c2 (uses the same tx2 + salt2), and make it old enough to purge.
    let r2 = make_reveal(&sender, tx2, salt2);
    let _rid2 = mp.insert_reveal(r2, 95, 1, &TestBalanceView{}, &FeeState::from_defaults()).unwrap();

    // Before purge: pending commits = 2, one reveal present
    {
        let (commits, _avails, reveals) = mp.debug_read();
        let cnt = commits.pending_per_owner.get(&sender).copied().unwrap_or(0);
        assert_eq!(cnt, 2, "expected two pending commits before purge");
        assert_eq!(reveals.by_id.len(), 1, "expected one reveal before purge");
    }

    // Purge at height 102:
    // - commit at 96 (age 6) should drop (ttl=5)
    // - reveal at 95 (age 7) should drop (window=3)
    mp.evict_stale(102);

    // After purge:
    {
        let (commits, _avails, reveals) = mp.debug_read();

        // c1 remains, c2 evicted
        assert!(commits.by_id.get(&id1).is_some(), "c1 should remain");
        assert!(commits.by_id.get(&id2).is_none(), "c2 should be evicted");

        // pending count decremented to 1
        let cnt = commits.pending_per_owner.get(&sender).copied().unwrap_or(0);
        assert_eq!(cnt, 1, "pending count should decrement after eviction");

        // reveal queue emptied by TTL
        assert_eq!(reveals.by_id.len(), 0, "reveals should be purged");
    }
}

// ---------------------- StateView-check specific tests ----------------------

#[test]
fn il_reveal_at_wrong_nonce_fails() {
    let mp = MempoolImpl::new(cfg());
    let sender = addr(70);
    let (c, tx, salt, cm) = make_commit(&sender, 0);
    mp.insert_commit(Tx::Commit(c), 0, 1, &TestBalanceView{}, &FeeState::from_defaults()).unwrap();
    let r = make_reveal(&sender, tx, salt);
    mp.insert_reveal(r, 0, 1, &TestBalanceView{}, &FeeState::from_defaults()).unwrap();

    let mut reveal_nonces = HashMap::new();
    reveal_nonces.insert(sender.clone(), 1);
    let sv = SV {
        height: 0,
        il: vec![CommitmentId(cm)],
        reveal_nonces,
        ..Default::default()
    };

    let err = mp.select_block(&sv, limits()).unwrap_err();
    assert!(matches!(err, SelectError::InclusionListUnmet { .. }));
}

#[test]
fn avail_outside_window_skipped() {
    let mp = MempoolImpl::new(cfg());
    let sender = addr(71);
    let (_c, _tx, _salt, cm) = make_commit(&sender, 0);
    let a = make_avail(&sender, cm);
    mp.insert_avail(Tx::Avail(a), 20, 1, &TestBalanceView{}, &FeeState::from_defaults()).unwrap();

    let sv = SV { height: 10, il: vec![], ..Default::default() };
    let block = mp.select_block(&sv, limits()).unwrap();
    assert!(block.txs.is_empty(), "avail not ready should be skipped");
}

#[test]
fn avail_duplicate_skipped_when_reveal_forced() {
    let mp = MempoolImpl::new(cfg());
    let sender = addr(72);
    let (c, tx, salt, cm) = make_commit(&sender, 0);
    let commit_id = mp.insert_commit(Tx::Commit(c), 0, 1, &TestBalanceView{}, &FeeState::from_defaults()).unwrap();
    let a = make_avail(&sender, cm);
    mp.insert_avail(Tx::Avail(a.clone()), 0, 1, &TestBalanceView{}, &FeeState::from_defaults()).unwrap();
    let r = make_reveal(&sender, tx, salt);
    mp.insert_reveal(r.clone(), 0, 1, &TestBalanceView{}, &FeeState::from_defaults()).unwrap();
    mp.mark_included(&[commit_id], 1);

    let sv = SV { height: 0, il: vec![CommitmentId(cm)], ..Default::default() };
    let block = mp.select_block(&sv, limits()).unwrap();
    assert!(block.txs.is_empty(), "avail with IL commitment should be skipped");
    assert_eq!(block.reveals, vec![r]);
}

#[test]
fn commit_skipped_when_sender_at_pending_cap() {
    let mp = MempoolImpl::new(cfg());
    let sender = addr(73);
    let (c, _tx, _salt, _cm) = make_commit(&sender, 0);
    mp.insert_commit(Tx::Commit(c), 0, 1, &TestBalanceView{}, &FeeState::from_defaults()).unwrap();
    let mut pending_room = HashMap::new();
    pending_room.insert(sender.clone(), 0);
    let sv = SV { height: 0, il: vec![], pending_room, ..Default::default() };
    let block = mp.select_block(&sv, limits()).unwrap();
    assert!(block.txs.is_empty(), "commit should be skipped when sender at cap");
}

#[test]
fn extra_reveal_nonce_continuity_enforced() {
    let mp = MempoolImpl::new(cfg());
    let sender = addr(74);
    let (c0, tx0, salt0, _cm0) = make_commit(&sender, 0);
    let (c1, tx1, salt1, _cm1) = make_commit(&sender, 1);
    let id0 = mp.insert_commit(Tx::Commit(c0), 0, 1, &TestBalanceView{}, &FeeState::from_defaults()).unwrap();
    let id1 = mp.insert_commit(Tx::Commit(c1), 0, 1, &TestBalanceView{}, &FeeState::from_defaults()).unwrap();
    let r1 = make_reveal(&sender, tx1, salt1);
    mp.insert_reveal(r1, 0, 10, &TestBalanceView{}, &FeeState::from_defaults()).unwrap();
    let r0 = make_reveal(&sender, tx0, salt0);
    mp.insert_reveal(r0.clone(), 0, 1, &TestBalanceView{}, &FeeState::from_defaults()).unwrap();
    mp.mark_included(&[id0, id1], 1);

    let mut reveal_nonces = HashMap::new();
    reveal_nonces.insert(sender.clone(), 0);
    let sv = SV { height: 0, il: vec![], reveal_nonces, ..Default::default() };
    let block = mp.select_block(&sv, limits()).unwrap();
    assert_eq!(block.reveals.len(), 1);
    assert_eq!(block.reveals[0].tx.nonce, 0);
    assert!(block.txs.is_empty());
}


// ------------------------------ tiny assertions ------------------------------

fn matches_bad_access_list(err: crate::mempool::AdmissionError) {
    match err {
        crate::mempool::AdmissionError::BadAccessList => {}
        other => panic!("expected BadAccessList, got {:?}", other),
    }
}

#[test]
fn concurrent_insert_select_benchmark() {
    use std::thread;
    use std::time::Instant;

    let mp = MempoolImpl::new(cfg());
    let start = Instant::now();

    let insert_mp = mp.clone();
    let inserter = thread::spawn(move || {
        for i in 0..200 {
            let sender = addr((i % 10) as u8);
            let (c, tx, salt, cm) = make_commit(&sender, i as u64);
            let _ = insert_mp.insert_commit(Tx::Commit(c), 0, 1, &TestBalanceView{}, &FeeState::from_defaults());
            let a = make_avail(&sender, cm);
            let _ = insert_mp.insert_avail(Tx::Avail(a), 0, 1, &TestBalanceView{}, &FeeState::from_defaults());
            let r = make_reveal(&sender, tx, salt);
            let _ = insert_mp.insert_reveal(r, 0, 1, &TestBalanceView{}, &FeeState::from_defaults());
        }
    });

    let select_mp = mp.clone();
    let selector = thread::spawn(move || {
        let state = SV { height: 0, il: vec![], ..Default::default() };
        let lim = limits();
        for _ in 0..200 {
            let _ = select_mp.select_block(&state, lim);
        }
    });

    inserter.join().unwrap();
    selector.join().unwrap();

    println!("concurrent insert/select took {:?}", start.elapsed());
}

// --------------------------- revalidate_affordability tests ---------------------------

/// A BalanceView that returns 0 for everyone (forces unaffordable paths
/// if your default lane base fees are > 0).
struct ZeroBalanceView;
impl BalanceView for ZeroBalanceView {
    fn balance_of(&self, _who: &Address) -> u64 { 0 }
}

/// A BalanceView backed by a map so we can simulate per-address balances.
struct MapBalanceView<'a> {
    map: &'a HashMap<Address, u64>,
}
impl<'a> BalanceView for MapBalanceView<'a> {
    fn balance_of(&self, who: &Address) -> u64 {
        *self.map.get(who).unwrap_or(&0)
    }
}

/// Helper: insert one tx per lane for `sender`.
fn seed_all_lanes(mp: &MempoolImpl, sender: &str) -> (TxId, TxId, TxId) {
    let (c, tx, salt, cm) = make_commit(sender, 0);
    let a = make_avail(sender, cm);
    let r = make_reveal(sender, tx, salt);

    let id_commit = mp.insert_commit(Tx::Commit(c), 1, /*at_height*/ 1, &TestBalanceView{}, &FeeState::from_defaults())
        .expect("commit admitted");
    let id_avail  = mp.insert_avail(Tx::Avail(a), 1, /*ready_at*/ 1, &TestBalanceView{}, &FeeState::from_defaults())
        .expect("avail admitted");
    let id_reveal = mp.insert_reveal(r, 1, /*at_height*/ 1, &TestBalanceView{}, &FeeState::from_defaults())
        .expect("reveal admitted");

    (id_commit, id_avail, id_reveal)
}

#[test]
fn revalidate_with_zero_balance_prunes_some_or_all() {
    let mp = MempoolImpl::new(cfg());
    let alice = addr(90);
    let bob   = addr(91);

    // Seed a few entries for two senders.
    seed_all_lanes(&mp, &alice);
    seed_all_lanes(&mp, &bob);

    // Snapshot sizes before.
    let (before_c, before_a, before_r) = {
        let (c, a, r) = mp.debug_read();
        (c.by_id.len(), a.by_id.len(), r.by_id.len())
    };

    // Run revalidation with ZeroBalanceView (everyone broke).
    mp.revalidate_affordability(&ZeroBalanceView, &FeeState::from_defaults());

    // After revalidation, counts must never increase and should usually drop.
    let (after_c, after_a, after_r) = {
        let (c, a, r) = mp.debug_read();
        (c.by_id.len(), a.by_id.len(), r.by_id.len())
    };

    assert!(after_c <= before_c, "commit count should not increase");
    assert!(after_a <= before_a, "avail count should not increase");
    assert!(after_r <= before_r, "reveal count should not increase");
    // At least one lane should have pruned something in typical configs.
    assert!(
        (after_c < before_c) || (after_a < before_a) || (after_r < before_r),
        "expected at least one lane to prune with zero balance"
    );
}

#[test]
fn revalidate_with_large_balances_keeps_entries() {
    let mp = MempoolImpl::new(cfg());
    let alice = addr(92);

    seed_all_lanes(&mp, &alice);

    // Large balances for everyone.
    let mut balances = HashMap::<Address, u64>::new();
    balances.insert(alice.clone(), u64::MAX / 2);

    let (c0, a0, r0) = {
        let (c, a, r) = mp.debug_read();
        (c.by_id.len(), a.by_id.len(), r.by_id.len())
    };

    mp.revalidate_affordability(&MapBalanceView { map: &balances }, &FeeState::from_defaults());

    let (c1, a1, r1) = {
        let (c, a, r) = mp.debug_read();
        (c.by_id.len(), a.by_id.len(), r.by_id.len())
    };

    assert_eq!(c1, c0, "commit lane unchanged with ample balances");
    assert_eq!(a1, a0, "avail lane unchanged with ample balances");
    assert_eq!(r1, r0, "reveal lane unchanged with ample balances");
}

#[test]
fn revalidate_is_idempotent_for_same_inputs() {
    let mp = MempoolImpl::new(cfg());
    let alice = addr(93);
    seed_all_lanes(&mp, &alice);

    let mut balances = HashMap::<Address, u64>::new();
    balances.insert(alice.clone(), 1_000_000);
    let view = MapBalanceView { map: &balances };
    let fees = FeeState::from_defaults();

    mp.revalidate_affordability(&view, &fees);
    let (c1, a1, r1) = {
        let (c, a, r) = mp.debug_read();
        (c.by_id.len(), a.by_id.len(), r.by_id.len())
    };

    mp.revalidate_affordability(&view, &fees);
    let (c2, a2, r2) = {
        let (c, a, r) = mp.debug_read();
        (c.by_id.len(), a.by_id.len(), r.by_id.len())
    };

    assert_eq!((c1, a1, r1), (c2, a2, r2), "second pass should not mutate state");
}

#[test]
fn revalidate_prunes_only_underfunded_senders() {
    let mp = MempoolImpl::new(cfg());
    let rich = addr(94);
    let poor = addr(95);

    // One of each lane per sender.
    seed_all_lanes(&mp, &rich);
    seed_all_lanes(&mp, &poor);

    // Rich has funds, poor does not.
    let mut balances = HashMap::<Address, u64>::new();
    balances.insert(rich.clone(), 1_000_000);
    balances.insert(poor.clone(), 0);
    let view = MapBalanceView { map: &balances };

    // Before
    let (before_c, before_a, before_r) = {
        let (c, a, r) = mp.debug_read();
        (c.by_id.len(), a.by_id.len(), r.by_id.len())
    };

    mp.revalidate_affordability(&view, &FeeState::from_defaults());

    // After: counts must not increase, and at least one should drop.
    let (after_c, after_a, after_r) = {
        let (c, a, r) = mp.debug_read();
        (c.by_id.len(), a.by_id.len(), r.by_id.len())
    };

    assert!(after_c <= before_c && after_a <= before_a && after_r <= before_r);
    assert!(
        (after_c < before_c) || (after_a < before_a) || (after_r < before_r),
        "expected at least one lane to prune for underfunded sender"
    );

    // Optional internal coherence check: for each lane, indices stay aligned.
    let (commits, avails, reveals) = mp.debug_read();
    assert_eq!(commits.by_id.len(), commits.fee_order.len(), "commit indices coherent after prune");
    assert_eq!(avails.by_id.len(),  avails.fee_order.len(),  "avail indices coherent after prune");
    assert_eq!(reveals.by_id.len(), reveals.fee_order.len(), "reveal indices coherent after prune");
}