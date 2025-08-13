// src/stf.rs

use crate::crypto::commitment_hash;
use crate::crypto::merkle_root;
use crate::crypto::hash_bytes_sha256;
use crate::state::Commitments;
use crate::state::COMMIT_FEE;
use crate::state::{Balances, Nonces};
use crate::codec::{tx_enum_bytes, receipt_bytes, header_bytes, tx_bytes};
use crate::types::CommitmentMeta;
use crate::types::{Block, Receipt, ExecOutcome, Hash, BlockHeader, Transaction, StateKey, Tx, Event, RevealTx, CommitTx};
use crate::gas::BASE_FEE_PER_TX;
use std::fmt;

#[derive(Debug)]
pub enum TxError {
    IntrinsicInvalid(String),
}

#[derive(Debug, PartialEq)]
pub enum BlockError {
    IntrinsicInvalid(String),
    HeaderMismatch(String),
    BadHeight { expected: u64, got: u64 },
    RootMismatch(String)
}

impl fmt::Display for BlockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockError::IntrinsicInvalid(e) => write!(f, "Intrinsic invalid: {}", e),
            BlockError::HeaderMismatch(e)   => write!(f, "Header mismatch: {}", e),
            BlockError::RootMismatch(e)     => write!(f, "Root mismatch: {}", e),
            BlockError::BadHeight { expected, got } =>
                write!(f, "Bad height: expected {}, got {}", expected, got),
        }
    }
}

impl std::error::Error for BlockError {}

#[derive(Debug)]
pub struct BlockResult { 
    pub receipts: Vec<Receipt>, 
    pub gas_total: u64,
    pub txs_root: Hash,
    pub receipts_root: Hash,
    pub header: BlockHeader,
    pub block_hash: Hash,
    pub events: Vec<Event>
}

/// Process a single transaction against the balances map.
pub fn process_transaction(
    tx: &Transaction,
    balances: &mut Balances,
    nonces: &mut Nonces,
) -> Result<Receipt, TxError>
{
    let sender: String = tx.from.clone();

    let expected: u64 = *nonces.get(&sender).unwrap_or(&0);

    if tx.nonce != expected {
        return Err(TxError::IntrinsicInvalid(
            format!("bad nonce: expected {}, got {}", expected, tx.nonce)
        ));
    }

    let required = [
        StateKey::Nonce(tx.from.clone()),
        StateKey::Balance(tx.from.clone()),
        StateKey::Balance(tx.to.clone()),
    ];

    if !tx.access_list.covers(&required) {
        return Err(TxError::IntrinsicInvalid("access list missing required key".to_string()));
    }

    let receiver: String = tx.to.clone();

    let sender_bal= balances.entry(sender).or_insert(0);
    
    if *sender_bal < BASE_FEE_PER_TX {
        return Err(TxError::IntrinsicInvalid(
            "insufficient funds to pay gas fee".to_string()
        ));
    }
    
    *sender_bal -= BASE_FEE_PER_TX;

    let error: Option<String>;
    let outcome: ExecOutcome;

    if *sender_bal >= tx.amount {
        // Success path
        *sender_bal -= tx.amount;
        *balances.entry(receiver).or_insert(0) += tx.amount;
        outcome = ExecOutcome::Success;
        error = None;
    } else {
        // Revert path
        outcome = ExecOutcome::Revert;
        error = Some("insufficient funds for transfer".to_string());
    }

    *nonces.entry(tx.from.clone()).or_insert(0) = expected + 1;

    Ok(Receipt { outcome, gas_used: BASE_FEE_PER_TX, error: error })
}

fn process_commit(
    c: &CommitTx,
    balances: &mut Balances,
    commitments: &mut Commitments,
    current_height: u64,
    events: &mut Vec<Event>,
) -> Result<Receipt, TxError> {
    let required = [
        StateKey::Balance(c.sender.clone())
    ];

    if !c.access_list.covers(&required) {
        return Err(TxError::IntrinsicInvalid("access list missing required key".to_string()));
    }

    let sender = c.sender.clone();
    let bal = balances.entry(sender.clone()).or_insert(0);
    if *bal < COMMIT_FEE {
        return Err(TxError::IntrinsicInvalid("insufficient funds to pay commit fee".to_string()));
    }
    *bal -= COMMIT_FEE;

    // 2) reject duplicate active commitment
    if let Some(meta) = commitments.get(&c.commitment) {
        if !meta.consumed {
            return Err(TxError::IntrinsicInvalid("duplicate commitment".to_string()));
        }
    }

    // 3) store commitment metadata
    commitments.insert(
        c.commitment,
        CommitmentMeta {
            owner: sender.clone(),
            expires_at: c.expires_at,
            consumed: false,
            included_at: current_height,
        },
    );

    // 4) event
    events.push(Event::CommitStored {
        commitment: c.commitment,
        owner: sender,
        expires_at: c.expires_at,
    });

    // 5) receipt
    Ok(Receipt { outcome: ExecOutcome::Success, gas_used: BASE_FEE_PER_TX, error: None })
}

fn process_reveal(
    r: &RevealTx,
    balances: &mut Balances,
    nonces: &mut Nonces,
    current_height: u64,
    commitments: &mut Commitments,
    events: &mut Vec<Event>,
) -> Result<Receipt, TxError> {
    let required = [
        StateKey::Nonce(r.tx.from.clone()),
        StateKey::Balance(r.tx.from.clone()),
        StateKey::Balance(r.tx.to.clone()),
    ];
    
    if !r.tx.access_list.covers(&required) {
        return Err(TxError::IntrinsicInvalid("access list missing required key".to_string()));
    }
    // Sender sanity
    if r.sender != r.tx.from {
        return Err(TxError::IntrinsicInvalid("reveal sender != tx.from".to_string()));
    }

    let cmt = commitment_hash(&tx_bytes(&r.tx), &r.salt);
    
    {
        let meta = commitments.get_mut(&cmt)
            .ok_or_else(|| TxError::IntrinsicInvalid("no such commitment".to_string()))?;
    
        if meta.owner != r.sender {
            return Err(TxError::IntrinsicInvalid("owner mismatch".to_string()));
        }
        if meta.consumed {
            return Err(TxError::IntrinsicInvalid("commit already consumed".to_string()));
        }
        if current_height <= meta.included_at {
            return Err(TxError::IntrinsicInvalid("same block reveal".to_string()));
        }
        if current_height > meta.expires_at {
            return Err(TxError::IntrinsicInvalid("commit expired".to_string()));
        }
    
        meta.consumed = true;  // borrow consumed now
    }

    events.push(Event::CommitConsumed { commitment: cmt });

    process_transaction(&r.tx, balances, nonces)
}

pub fn process_block(block: &Block, balances: &mut Balances, nonces: &mut Nonces, commitments: &mut Commitments, parent_hash: &Hash) -> Result<BlockResult, BlockError> {
    let mut receipts : Vec<Receipt> = Vec::new();
    let mut gas_total : u64 = 0;

    let mut txs_hashes : Vec<Hash> = Vec::new();
    let mut receipt_hashes : Vec<Hash> = Vec::new();
    let mut events: Vec<Event> = Vec::new();

    for (i, tx) in block.transactions.iter().enumerate() {
        let rcpt_res = match tx {
            Tx::Transfer(_) => {
                return Err(BlockError::IntrinsicInvalid(
                    "plain transfers disabled".to_string()
                ));
            }
            Tx::Commit(c)   => process_commit(c, balances, commitments, block.block_number, &mut events),
            Tx::Reveal(r)   => process_reveal(r, balances, nonces, block.block_number, commitments, &mut events),
        };

        match rcpt_res {
            Ok(receipt) => {
                gas_total += receipt.gas_used;
                txs_hashes.push(hash_bytes_sha256(&tx_enum_bytes(tx)));
                receipt_hashes.push(hash_bytes_sha256(&receipt_bytes(&receipt)));
                receipts.push(receipt);
            }
            Err(TxError::IntrinsicInvalid(e)) => {
                return Err(BlockError::IntrinsicInvalid(format!(
                    "block={} tx_index={} error={}", block.block_number, i + 1, e
                )));
            }
        }
    }

    let txs_root = merkle_root(&txs_hashes);
    let receipts_root = merkle_root(&receipt_hashes);

    let header = BlockHeader {
        parent_hash: *parent_hash,                
        height: block.block_number,
        txs_root,
        receipts_root,
        gas_used: gas_total,
        randomness: *parent_hash, // placeholder TB CHANGED later with VRF
    };
    
    let block_hash = hash_bytes_sha256(&header_bytes(&header));

    Ok(BlockResult { receipts, gas_total, txs_root, receipts_root, header, block_hash, events })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AccessList, Transaction};
    use std::collections::HashMap;

    #[test]
    fn transfer_via_commit_reveal_success() {
        use std::collections::HashMap;
        use crate::chain::Chain;
        use crate::codec::tx_bytes;
        use crate::crypto::commitment_hash;
        use crate::state::{Balances, Nonces, Commitments, COMMIT_FEE};
        use crate::types::{
            Transaction, Tx, CommitTx, RevealTx, Block, ExecOutcome, Hash,
        };
        use crate::stf::BASE_FEE_PER_TX;
    
        // Initial state
        let mut balances: Balances = HashMap::from([
            ("Alice".to_string(), 100),
            ("Bob".to_string(), 50),
        ]);
        
        let al = AccessList {
            reads: vec![ StateKey::Balance("Alice".into()),  StateKey::Balance("Bob".into()), StateKey::Nonce("Alice".into()) ],
            writes: vec![ StateKey::Balance("Alice".into()),  StateKey::Balance("Bob".into()), StateKey::Nonce("Alice".into()) ],
        };

        let mut nonces: Nonces = Default::default();
        let mut commitments: Commitments = Default::default();
        let mut chain = Chain::new();
    
        // Inner plaintext transfer (to be revealed later)
        let tx = Transaction::transfer("Alice", "Bob", 30, 0);
    
        // Salt and commitment
        let salt: Hash = [7u8; 32];
        let cmt = commitment_hash(&tx_bytes(&tx), &salt);
    
        // --- Block 1: Commit ---
        let b1 = Block::new(
            vec![Tx::Commit(CommitTx {
                commitment: cmt,
                expires_at: 5,       // any height >= 2 and <= 1+EXPIRY_WINDOW is fine for the test
                sender: "Alice".into(),
                access_list: al
            })],
            1,
        );
        let _res1 = chain
            .apply_block(&b1, &mut balances, &mut nonces, &mut commitments)
            .expect("block 1 (commit) should apply");
    
        // After commit: only commit fee is burned, nonce unchanged
        assert_eq!(balances["Alice"], 100 - COMMIT_FEE);
        assert_eq!(balances["Bob"], 50);
        assert_eq!(*nonces.get("Alice").unwrap_or(&0), 0);
    
        // --- Block 2: Reveal (executes the transfer) ---
        let b2 = Block::new(
            vec![Tx::Reveal(RevealTx {
                tx: tx.clone(),
                salt,
                sender: "Alice".into(),
            })],
            2,
        );
        let res2 = chain
            .apply_block(&b2, &mut balances, &mut nonces, &mut commitments)
            .expect("block 2 (reveal) should apply");
    
        // Receipt checks
        assert_eq!(res2.receipts.len(), 1);
        let rcpt = &res2.receipts[0];
        assert_eq!(rcpt.outcome, ExecOutcome::Success);
        assert_eq!(rcpt.gas_used, BASE_FEE_PER_TX);
    
        // Final balances:
        // Alice: 100 - COMMIT_FEE(1) - BASE_FEE(1) - 30 = 68
        // Bob:   50 + 30 = 80
        assert_eq!(balances["Alice"], 68);
        assert_eq!(balances["Bob"], 80);
    
        // Nonce consumed on reveal (not on commit)
        assert_eq!(*nonces.get("Alice").unwrap(), 1);
    }

    #[test]
    fn transfer_gas_paid_no_balance_revert() {
        let mut balances = HashMap::from([
            ("Alice".to_string(), 20),
            ("Bob".to_string(), 50),
        ]);
        let mut nonces = Default::default();

        let tx = Transaction::transfer("Alice","Bob", 30,0);
        let rcpt = process_transaction(&tx, &mut balances, &mut nonces).expect("valid but reverts");
        assert_eq!(rcpt.outcome, ExecOutcome::Revert);
        assert!(rcpt.error.is_some());
        assert_eq!(balances["Alice"], 19);
        assert_eq!(balances["Bob"], 50);
        assert_eq!(*nonces.get("Alice").unwrap(), 1);
    }

    #[test]
    fn intrinsic_invalid_when_cannot_pay_fee() {
        let mut balances = HashMap::from([
            ("Alice".to_string(), 0),
            ("Bob".to_string(), 50),
        ]);
        let mut nonces: HashMap<String, u64> = Default::default();
    
        let tx = Transaction::transfer("Alice", "Bob", 1, 0);
    
        match process_transaction(&tx, &mut balances, &mut nonces) {
            Err(TxError::IntrinsicInvalid(msg)) => {
                assert!(msg.contains("insufficient funds"));
            }
            _ => panic!("Expected intrinsic invalid error"),
        }
    
        // Balances unchanged
        assert_eq!(balances["Alice"], 0);
        assert_eq!(balances["Bob"], 50);
    
        // Nonces unchanged
        assert_eq!(nonces.get("Alice"), None);
    }

    #[test]
    fn underdeclared_accesslist_fails() {
        use crate::types::AccessList;

        let mut balances = HashMap::from([
            ("Alice".to_string(), 100),
            ("Bob".to_string(), 50),
        ]);
        let mut nonces: HashMap<String, u64> = Default::default();
        let al = AccessList {
            reads: vec![ StateKey::Balance("Alice".into()), StateKey::Nonce("Alice".into()) ],
            writes: vec![ StateKey::Balance("Alice".into()), StateKey::Nonce("Alice".into()) ],
        };

        let tx = Transaction::new("Alice", "Bob", 1, 0, al);

        match process_transaction(&tx, &mut balances, &mut nonces) {
            Err(TxError::IntrinsicInvalid(msg)) => {
                assert!(msg.contains("missing required key"));
            }
            _ => panic!("Expected intrinsic invalid error"),
        }

           // Balances unchanged
           assert_eq!(balances["Alice"], 100);
           assert_eq!(balances["Bob"], 50);
       
           // Nonces unchanged
           assert_eq!(nonces.get("Alice"), None);
    }

    #[test]
    fn overdeclared_accesslist_succeeds() {
        use crate::types::AccessList;

        let mut balances = HashMap::from([
            ("Alice".to_string(), 100),
            ("Bob".to_string(), 50),
        ]);
        let mut nonces: HashMap<String, u64> = Default::default();
        let al = AccessList {
            reads: vec![ StateKey::Balance("Alice".into()), StateKey::Balance("Bob".into()), StateKey::Nonce("Alice".into()), StateKey::Nonce("Bob".into()) ],
            writes: vec![ StateKey::Balance("Alice".into()), StateKey::Balance("Bob".into()), StateKey::Nonce("Alice".into()), StateKey::Nonce("Bob".into()) ],
        };

        let tx = Transaction::new("Alice", "Bob", 1, 0, al);

        match process_transaction(&tx, &mut balances, &mut nonces) {
            Err(_) => {
                panic!("Unexpected Error")
            },
            Ok(receipt) => {
                assert_eq!(receipt.outcome, ExecOutcome::Success)
            }
        }

           // Balances unchanged
           assert_eq!(balances["Alice"], 98);
           assert_eq!(balances["Bob"], 51);
       
           // Nonces unchanged
           assert_eq!(nonces.get("Alice"), Some(1).as_ref());
    }
}