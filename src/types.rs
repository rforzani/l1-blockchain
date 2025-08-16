// src/types.rs

#[derive(Debug, Clone, PartialEq)]
pub struct Transaction {
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub nonce: u64,
    pub access_list: AccessList
}

impl Transaction {
    pub fn new(from: impl Into<String>, to: impl Into<String>, amount: u64, nonce: u64, access_list: AccessList) -> Self {
        Self { from: from.into(), to: to.into(), amount, nonce, access_list }
    }
    pub fn transfer(from: impl Into<String>, to: impl Into<String>, amount: u64, nonce: u64) -> Self {
        let from_s = from.into();
        let to_s = to.into();
        let al = AccessList::for_transfer(&from_s, &to_s);
        Transaction { from: from_s, to: to_s, amount, nonce, access_list: al }
    }
}

#[derive(Debug, Clone)]
pub struct Block {
    pub transactions: Vec<Tx>,
    pub reveals: Vec<RevealTx>,
    pub block_number: u64,
}

impl Block {
    pub fn new_with_reveals(txs: Vec<Tx>, reveals: Vec<RevealTx>, n: u64) -> Self {
        Self { transactions: txs, reveals, block_number: n }
    }
    pub fn new(txs: Vec<Tx>, n: u64) -> Self {
        Self::new_with_reveals(txs, Vec::new(), n) // keep old call sites working
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ExecOutcome {
    Success,
    Revert, // valid tx but no state writes (besides fees/nonces)
}

#[derive(Debug, Clone)]
pub struct Receipt {
    pub outcome: ExecOutcome,
    pub gas_used: u64,
    pub error: Option<String>, // Some(reason) if Revert
}

pub type Hash = [u8; 32];

#[derive(Debug, Clone)]
pub struct BlockHeader {
    pub parent_hash: Hash,
    pub height: u64,
    pub txs_root: Hash,
    pub receipts_root: Hash,
    pub gas_used: u64,
    pub randomness: Hash,
    pub reveal_set_root: Hash,
    pub il_root: Hash
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]

/* Rules:
	•	Under‑declare (write/read a key not listed) ⇒ IntrinsicInvalid.
	•	Over‑declare (declare but don’t touch) ⇒ allowed (hurts parallelism, not correctness).
	•	Scheduler lock order: for each tx, lock writes first (sorted), then reads, to avoid deadlocks.
 */
pub enum StateKey {
    Balance(String),
    Nonce(String),
}

/*
What an access list is (and why you need it)

When you run transactions in parallel, you must know which parts of state each tx will read and write ahead of time. That way the scheduler can:
	•	run txs together when their writes don’t conflict,
	•	serialize txs that touch the same keys, and
	•	keep execution deterministic.

That declared set is the access list.
 */
#[derive(Debug, Clone, PartialEq)]
pub struct AccessList {
    pub reads: Vec<StateKey>,
    pub writes: Vec<StateKey>,
}

#[inline]
fn key_order<'a>(k: &'a StateKey) -> (u8, &'a str) {
    match k {
        StateKey::Balance(a) => (0, a.as_str()),
        StateKey::Nonce(a)   => (1, a.as_str()),
    }
}

impl AccessList {
    /// Sort + dedup in-place to canonical form.
    pub fn canonicalize(&mut self) {
        self.reads.sort_by(|a,b| key_order(a).cmp(&key_order(b)));
        self.reads.dedup();
        self.writes.sort_by(|a,b| key_order(a).cmp(&key_order(b)));
        self.writes.dedup();
    }

    pub fn for_transfer(from: &str, to: &str) -> Self {
        AccessList {
            reads: vec![
                StateKey::Balance(from.to_string()),
                StateKey::Balance(to.to_string()),
                StateKey::Nonce(from.to_string()),
            ],
            writes: vec![
                StateKey::Balance(from.to_string()),
                StateKey::Balance(to.to_string()),
                StateKey::Nonce(from.to_string()),
            ],
        }
    }

    #[inline]
    fn contains_sorted(slice: &[StateKey], key: &StateKey) -> bool {
        use core::cmp::Ordering;
        slice.binary_search_by(|k| {
            let ko = key_order(k);
            let qo = key_order(key);
            if ko < qo { Ordering::Less } else if ko > qo { Ordering::Greater } else { Ordering::Equal }
        }).is_ok()
    }

    /// Return true if each `required` key appears in **reads and writes**.
    pub fn covers(&self, required: &[StateKey]) -> bool {
        required.iter().all(|k| {
            Self::contains_sorted(&self.reads, k) && Self::contains_sorted(&self.writes, k)
        })
    }

    /// Convenience: require sender balance read+write (commit fee).
    pub fn require_sender_balance_rw(&self, sender: &str) -> bool {
        let k = StateKey::Balance(sender.to_string());
        println!("{:?}", k);
        println!("{}", Self::contains_sorted(&self.reads, &k));
        Self::contains_sorted(&self.reads, &k) && Self::contains_sorted(&self.writes, &k)
    }

    /// Convenience: require sender nonce read+write (reveal path).
    pub fn require_sender_nonce_rw(&self, sender: &str) -> bool {
        let k = StateKey::Nonce(sender.to_string());
        Self::contains_sorted(&self.reads, &k) && Self::contains_sorted(&self.writes, &k)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CommitTx {
    pub commitment: Hash,
    pub sender: String,
    pub access_list: AccessList,
    pub ciphertext_hash: Hash,
    pub pubkey: [u8; 32], 
    pub sig: [u8; 64]
}

#[derive(Debug, Clone, PartialEq)]
pub struct AvailTx { 
    pub commitment: Hash,
    pub sender: String, 
    pub pubkey: [u8; 32], 
    pub sig: [u8; 64]
}

#[derive(Debug, Clone, PartialEq)]
pub struct RevealTx {
    pub tx: Transaction,
    pub salt: Hash,
    pub sender: String
}

#[derive(Debug, Clone, PartialEq)]
pub enum Tx {
    Commit(CommitTx),
    Avail(AvailTx),
}

#[derive(Debug, Clone)]
pub struct CommitmentMeta {
    pub owner: String,
    pub expires_at: u64,
    pub consumed: bool,
    pub included_at: u64,
    pub access_list: AccessList,
}

#[derive(Debug, Clone)]
pub enum Event {
    CommitStored { commitment: Hash, owner: String, expires_at: u64 },
    CommitConsumed { commitment: Hash },
    CommitExpired { commitment: Hash },
    AvailabilityRecorded { commitment: Hash }
}