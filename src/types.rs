// src/types.rs

#[derive(Debug, Clone)]
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
}

#[derive(Debug, Clone)]
pub struct Block {
    pub transactions: Vec<Transaction>,
    pub block_number: u64
}

impl Block {
    pub fn new(transactions: impl Into<Vec<Transaction>>, block_number: u64) -> Self {
        Self { transactions: transactions.into(), block_number }
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
    pub gas_used: u64
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
#[derive(Debug, Clone)]
pub struct AccessList {
    pub reads: Vec<StateKey>,
    pub writes: Vec<StateKey>,
}