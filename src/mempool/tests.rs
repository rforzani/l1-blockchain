// src/mempool/tests.rs
#![allow(unused)]

use std::sync::Arc;

use crate::mempool::{
    BlockSelectionLimits, CommitmentId, Mempool, MempoolConfig, MempoolImpl, SelectError, TxId,
};
use crate::codec::{tx_bytes, access_list_bytes};
use crate::crypto::{hash_bytes_sha256, commitment_hash};
use crate::state::CHAIN_ID;
use crate::types::{
    Tx, CommitTx, AvailTx, RevealTx, Transaction, AccessList, StateKey, Hash,
};

// -------------------------- tiny helpers for building txs --------------------------

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
struct SV {
    height: u64,
    il: Vec<CommitmentId>,
}
impl crate::mempool::StateView for SV {
    fn current_height(&self) -> u64 { self.height }
    fn commitments_due_and_available(&self, _h: u64) -> Vec<CommitmentId> { self.il.clone() }
    fn reveal_nonce_required(&self, _sender: &str) -> u64 { 0 }
}

// ---------------------------------- TESTS ----------------------------------

#[test]
fn commit_admission_happy_path() {
    let mp = MempoolImpl::new(cfg());
    let sender = addr(1);
    let (c, _tx, _salt, _cm) = make_commit(&sender, 0);
    let id = mp.insert_commit(Tx::Commit(c), 100, 1).expect("commit admitted");
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
    let err = mp.insert_commit(Tx::Commit(c_bad), 100, 1).unwrap_err();
    matches_bad_access_list(err);
}

#[test]
fn commit_duplicate_rejected() {
    let mp = MempoolImpl::new(cfg());
    let sender = addr(3);
    let (c1, _tx, _salt, cm) = make_commit(&sender, 0);
    let mut c2 = c1.clone();
    c2.commitment = cm; // same commitment
    mp.insert_commit(Tx::Commit(c1), 100, 1).expect("first commit");
    let err = mp.insert_commit(Tx::Commit(c2), 100, 1).unwrap_err();
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
        mp.insert_commit(Tx::Commit(c), 100, 1).expect("admit");
    }

    // Third should hit the cap
    let (c3, _, _, _) = make_commit(&sender, 2);
    let err = mp.insert_commit(Tx::Commit(c3), 100, 1).unwrap_err();
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
    let err = mp.insert_reveal(r, 100, 1).unwrap_err();
    assert!(matches!(err, crate::mempool::AdmissionError::InvalidSignature));
}

#[test]
fn reveal_commitment_mismatch_rejected() {
    let mp = MempoolImpl::new(cfg());
    let sender = addr(8);

    // Build a matching commit with salt=[7;32]
    let (c, tx, _salt7, _cm) = make_commit(&sender, 0);
    mp.insert_commit(Tx::Commit(c), 100, 1).expect("commit admitted");

    // Reveal uses a different salt to force mismatch
    let mut salt8 = [0u8; 32];
    salt8[0] = 8;
    let r_bad = make_reveal(&sender, tx, salt8);
    let err = mp.insert_reveal(r_bad, 101, 1).unwrap_err();
    assert!(matches!(err, crate::mempool::AdmissionError::MismatchedCommitment));
}

#[test]
fn mark_included_evicts_and_decrements() {
    let mp = MempoolImpl::new(cfg());
    let sender = addr(42);

    // insert 2 commits for same sender
    let (c1, _, _, _) = make_commit(&sender, 0);
    let (c2, _, _, _) = make_commit(&sender, 1);
    let id1 = mp.insert_commit(Tx::Commit(c1), 100, 10).unwrap();
    let id2 = mp.insert_commit(Tx::Commit(c2), 100, 20).unwrap();

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
    mp.insert_commit(Tx::Commit(c1), 100, 10).unwrap();
    mp.insert_commit(Tx::Commit(c2), 100, 20).unwrap();

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
    let sv = SV { height: 123, il: vec![fake_commitment] };
    let err = mp.select_block(&sv, limits()).unwrap_err();
    match err {
        SelectError::InclusionListUnmet { missing } => {
            assert_eq!(missing, vec![fake_commitment]);
        }
        _ => panic!("expected InclusionListUnmet"),
    }
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

    let id1 = mp.insert_commit(Tx::Commit(c1), 100, 1).unwrap();
    let id2 = mp.insert_commit(Tx::Commit(c2),  96, 1).unwrap();

    // Matching reveal for c2 (uses the same tx2 + salt2), and make it old enough to purge.
    let r2 = make_reveal(&sender, tx2, salt2);
    let _rid2 = mp.insert_reveal(r2, 95, 1).unwrap();

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
            let _ = insert_mp.insert_commit(Tx::Commit(c), 0, 1);
            let a = make_avail(&sender, cm);
            let _ = insert_mp.insert_avail(Tx::Avail(a), 0, 1);
            let r = make_reveal(&sender, tx, salt);
            let _ = insert_mp.insert_reveal(r, 0, 1);
        }
    });

    let select_mp = mp.clone();
    let selector = thread::spawn(move || {
        let state = SV { height: 0, il: vec![] };
        let lim = limits();
        for _ in 0..200 {
            let _ = select_mp.select_block(&state, lim);
        }
    });

    inserter.join().unwrap();
    selector.join().unwrap();

    println!("concurrent insert/select took {:?}", start.elapsed());
}
