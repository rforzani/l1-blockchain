// src/stf.rs

use crate::crypto::merkle_root;
use crate::crypto::hash_bytes_sha256;
use crate::state::{Balances, Nonces};
use crate::codec::{tx_bytes, receipt_bytes, header_bytes};
use crate::types::{Block, Receipt, ExecOutcome, Hash, BlockHeader, StateKey, AccessList};
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
}

/// Process a single transaction against the balances map.
pub fn process_transaction(
    tx: &crate::types::Transaction,
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

pub fn process_block(block: &Block, balances: &mut Balances, nonces: &mut Nonces, parent_hash: &Hash) -> Result<BlockResult, BlockError> {
    let mut receipts : Vec<Receipt> = Vec::new();
    let mut gas_total : u64 = 0;

    let mut txs_hashes : Vec<Hash> = Vec::new();
    let mut receipt_hashes : Vec<Hash> = Vec::new();

    for (i, tx) in block.transactions.iter().enumerate() {
        match process_transaction(tx, balances, nonces) {
            Ok(receipt) => { 
                gas_total = gas_total + receipt.gas_used; 
                txs_hashes.push(hash_bytes_sha256(&tx_bytes(tx))); 
                receipt_hashes.push(hash_bytes_sha256(&receipt_bytes(&receipt))); 
                receipts.push(receipt); 
            }
            Err(TxError::IntrinsicInvalid(e)) => {
                return Err(BlockError::IntrinsicInvalid(format!(
                    "block={} tx_index={} error={}",
                    block.block_number,
                    i + 1,
                    e
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
    };
    
    let block_hash = hash_bytes_sha256(&header_bytes(&header));

    Ok(BlockResult { receipts, gas_total, txs_root, receipts_root, header, block_hash })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Transaction;
    use std::collections::HashMap;

    #[test]
    fn transfer_transaction_successful() {
        let mut balances = HashMap::from([
            ("Alice".to_string(), 100),
            ("Bob".to_string(), 50),
        ]);
        let mut nonces = Default::default();
        let al = AccessList {
            reads: vec![StateKey::Balance("Alice".into()), StateKey::Balance("Bob".into()), StateKey::Nonce("Alice".into())],
            writes: vec![StateKey::Balance("Alice".into()), StateKey::Balance("Bob".into()), StateKey::Nonce("Alice".into())]
        };
        let tx = Transaction::new("Alice","Bob", 30, 0, al);
        let rcpt = process_transaction(&tx, &mut balances, &mut nonces).expect("valid");
        assert_eq!(rcpt.outcome, ExecOutcome::Success);
        assert_eq!(rcpt.gas_used, BASE_FEE_PER_TX);
        assert_eq!(balances["Alice"], 69);
        assert_eq!(balances["Bob"], 80);
        assert_eq!(*nonces.get("Alice").unwrap(), 1);
    }

    #[test]
    fn transfer_gas_paid_no_balance_revert() {
        let mut balances = HashMap::from([
            ("Alice".to_string(), 20),
            ("Bob".to_string(), 50),
        ]);
        let mut nonces = Default::default();

        let al = AccessList {
            reads: vec![StateKey::Balance("Alice".into()), StateKey::Balance("Bob".into()), StateKey::Nonce("Alice".into())],
            writes: vec![StateKey::Balance("Alice".into()), StateKey::Balance("Bob".into()), StateKey::Nonce("Alice".into())],
        };

        let tx = Transaction::new("Alice","Bob", 30,0, al);
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

        let al = AccessList {
            reads: vec![StateKey::Balance("Alice".into()), StateKey::Balance("Bob".into()), StateKey::Nonce("Alice".into())],
            writes: vec![StateKey::Balance("Alice".into()), StateKey::Balance("Bob".into()), StateKey::Nonce("Alice".into())],
        };
    
        let tx = Transaction::new("Alice", "Bob", 1, 0, al);
    
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
}
