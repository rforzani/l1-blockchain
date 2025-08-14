// src/stf.rs

use crate::crypto::commitment_hash;
use crate::crypto::merkle_root;
use crate::crypto::hash_bytes_sha256;
use crate::state::Available;
use crate::state::Commitments;
use crate::state::COMMIT_FEE;
use crate::state::DECRYPTION_DELAY;
use crate::state::REVEAL_WINDOW;
use crate::state::{Balances, Nonces};
use crate::codec::{tx_enum_bytes, receipt_bytes, header_bytes, tx_bytes};
use crate::types::AvailTx;
use crate::types::CommitmentMeta;
use crate::types::{Block, Receipt, ExecOutcome, Hash, BlockHeader, Transaction, StateKey, Tx, Event, RevealTx, CommitTx};
use crate::gas::BASE_FEE_PER_TX;
use std::collections::HashSet;
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

fn process_avail(
    a: &AvailTx,
    commitments: &Commitments,
    available: &mut Available,
    current_height: u64,
    events: &mut Vec<Event>,
) -> Result<Receipt, TxError> {
    // sanity: commitment exists & not consumed
    let meta = commitments.get(&a.commitment)
        .ok_or_else(|| TxError::IntrinsicInvalid("no such commitment".into()))?;
    if meta.consumed {
        return Err(TxError::IntrinsicInvalid("already consumed".into()));
    }
    
    let ready_at = meta.included_at + DECRYPTION_DELAY;
    if current_height < ready_at { return Err(TxError::IntrinsicInvalid("avail too early".into())); }

    available.insert(a.commitment);
    events.push(Event::AvailabilityRecorded { commitment: a.commitment });
    Ok(Receipt { outcome: ExecOutcome::Success, gas_used: 0, error: None })
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

    let ready_at   = current_height + DECRYPTION_DELAY;
    let deadline   = ready_at + REVEAL_WINDOW; 

    // 3) store commitment metadata
    commitments.insert(
        c.commitment,
        CommitmentMeta {
            owner: sender.clone(),
            expires_at: deadline,
            consumed: false,
            included_at: current_height,
        },
    );

    // 4) event
    events.push(Event::CommitStored {
        commitment: c.commitment,
        owner: sender,
        expires_at: deadline,
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
    
        // -----  delay + window -----
        let ready_at = meta.included_at + DECRYPTION_DELAY;
        if current_height < ready_at {
            return Err(TxError::IntrinsicInvalid("reveal too early".to_string()));
        }
    
        let deadline = ready_at + REVEAL_WINDOW;
        if current_height > deadline {
            return Err(TxError::IntrinsicInvalid("reveal outside window".to_string()));
        }
        // --------------------------------
    
        meta.consumed = true; // borrow consumed now
    }

    events.push(Event::CommitConsumed { commitment: cmt });

    process_transaction(&r.tx, balances, nonces)
}

pub fn process_block(block: &Block, balances: &mut Balances, nonces: &mut Nonces, commitments: &mut Commitments, available: &mut Available, parent_hash: &Hash) -> Result<BlockResult, BlockError> {
    let mut receipts : Vec<Receipt> = Vec::new();
    let mut gas_total : u64 = 0;

    let mut txs_hashes : Vec<Hash> = Vec::new();
    let mut receipt_hashes : Vec<Hash> = Vec::new();
    let mut events: Vec<Event> = Vec::new();
    let mut revealed_pairs: Vec<(Hash, Hash)> = Vec::new(); // (commitment, tx_hash)

    // Track reveals we actually include in THIS block
    let mut revealed_this_block: HashSet<Hash> = HashSet::new();
    let mut il_due: Vec<Hash> = Vec::new();
    
    for (cmt, meta) in commitments.iter() {
        if meta.consumed { continue; }
        let ready_at  = meta.included_at + DECRYPTION_DELAY;
        let deadline  = ready_at + REVEAL_WINDOW;
        if block.block_number == deadline && available.contains(cmt) {
            il_due.push(*cmt); // due AND explicitly available
        }
    }
    il_due.sort();

    for (i, tx) in block.transactions.iter().enumerate() {
        let rcpt_res = match tx {
            Tx::Transfer(_) => {
                return Err(BlockError::IntrinsicInvalid(
                    "plain transfers disabled".to_string()
                ));
            }
            Tx::Commit(c)   => process_commit(c, balances, commitments, block.block_number, &mut events),
            Tx::Reveal(r) => {
                let rcpt_res = process_reveal(r, balances, nonces, block.block_number, commitments, &mut events);

                if let Ok(_) = rcpt_res {
                    let tx_ser = tx_bytes(&r.tx);
                    let cmt    = commitment_hash(&tx_ser, &r.salt);
                    let txh    = hash_bytes_sha256(&tx_ser);
                    revealed_pairs.push((cmt, txh));
                    revealed_this_block.insert(cmt);  
                }

                rcpt_res
            }
            Tx::Avail(a) => {
                process_avail(a, commitments, available, block.block_number, &mut events)
            }
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

    // turn (commitment, tx_hash) → leaf = H(commitment || tx_hash)
    let mut leaves: Vec<(Hash, Hash)> = revealed_pairs;  // keep commitment for sorting
    leaves.sort_by(|(c1, _), (c2, _)| c1.cmp(c2)); // sort by commitment

    let reveal_leaves: Vec<Hash> = leaves.into_iter().map(|(cmt, txh)| {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&cmt);
        buf.extend_from_slice(&txh);
        hash_bytes_sha256(&buf)
    }).collect();

    let reveal_set_root = merkle_root(&reveal_leaves);
    let txs_root = merkle_root(&txs_hashes);
    let receipts_root = merkle_root(&receipt_hashes);

    for c in &il_due {
        if !revealed_this_block.contains(c) {
            return Err(BlockError::IntrinsicInvalid("missing required reveal from inclusion list".to_string()));
        }
    }
    
    let il_leaves: Vec<Hash> = il_due.iter().map(|c| hash_bytes_sha256(c)).collect();
    let il_root = merkle_root(&il_leaves);

    let header = BlockHeader {
        parent_hash: *parent_hash,                
        height: block.block_number,
        txs_root,
        receipts_root,
        gas_used: gas_total,
        randomness: *parent_hash, // placeholder TB CHANGED later with VRF
        reveal_set_root: reveal_set_root,
        il_root
    };
    
    let block_hash = hash_bytes_sha256(&header_bytes(&header));

    Ok(BlockResult { receipts, gas_total, txs_root, receipts_root, header, block_hash, events })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Transaction};
    use std::collections::HashMap;

    #[test]
    fn transfer_via_commit_reveal_success() {
        use std::collections::HashMap;
        use crate::chain::Chain;
        use crate::codec::tx_bytes;
        use crate::crypto::commitment_hash;
        use crate::state::{Balances, Nonces, Commitments, Available, COMMIT_FEE, DECRYPTION_DELAY, REVEAL_WINDOW};
        use crate::types::{Transaction, Tx, CommitTx, RevealTx, AvailTx, Block, ExecOutcome, Hash, AccessList, StateKey,};
        use crate::stf::BASE_FEE_PER_TX;
    
        // helper: fill chain with empty blocks up to (but not including) `target`
        fn advance_to(
            chain: &mut Chain,
            balances: &mut Balances,
            nonces: &mut Nonces,
            comms: &mut Commitments,
            avail: &mut Available,
            target: u64,
        ) {
            while chain.height + 1 < target {
                let b = Block::new(Vec::new(), chain.height + 1);
                chain.apply_block(&b, balances, nonces, comms, avail).expect("advance");
            }
        }
    
        // Initial state
        let mut balances: Balances = HashMap::from([
            ("Alice".to_string(), 100),
            ("Bob".to_string(), 50),
        ]);
        let mut nonces: Nonces = Default::default();
        let mut commitments: Commitments = Default::default();
        let mut available:   Available   = Default::default();
        let mut chain = Chain::new();
    
        // Access list for commit (touches Alice’s balance to pay commit fee)
        let al = AccessList {
            reads:  vec![ StateKey::Balance("Alice".into()) ],
            writes: vec![ StateKey::Balance("Alice".into()) ],
        };
    
        // Inner plaintext transfer (to be revealed later)
        let tx = Transaction::transfer("Alice", "Bob", 30, 0);
    
        // Salt and commitment
        let salt: Hash = [7u8; 32];
        let cmt = commitment_hash(&tx_bytes(&tx), &salt);
    
        // ---- Block 1: Commit ----
        let b1 = Block::new(
            vec![Tx::Commit(CommitTx {
                commitment: cmt,
                sender: "Alice".into(),
                ciphertext_hash: [0u8; 32],
                access_list: al,
            })],
            1,
        );
        chain
            .apply_block(&b1, &mut balances, &mut nonces, &mut commitments, &mut available)
            .expect("block 1 (commit) should apply");
    
        // After commit: only commit fee is burned, nonce unchanged
        assert_eq!(balances["Alice"], 100 - COMMIT_FEE);
        assert_eq!(balances["Bob"], 50);
        assert_eq!(*nonces.get("Alice").unwrap_or(&0), 0);
    
        // Compute ready/due heights
        let ready_at = 1 + DECRYPTION_DELAY;
        let deadline = ready_at + REVEAL_WINDOW;
    
        // Advance sequentially up to ready_at
        advance_to(&mut chain, &mut balances, &mut nonces, &mut commitments, &mut available, ready_at);
    
        // ---- Block ready_at: Avail + Reveal (earliest allowed) ----
        let b_ready = Block::new(
            vec![
                Tx::Avail(AvailTx { commitment: cmt }),
                Tx::Reveal(RevealTx { tx: tx.clone(), salt, sender: "Alice".into() }),
            ],
            ready_at,
        );
        let res2 = chain
            .apply_block(&b_ready, &mut balances, &mut nonces, &mut commitments, &mut available)
            .expect("block ready_at (avail + reveal) should apply");
    
        // Receipt checks (Avail + Reveal)
        assert_eq!(res2.receipts.len(), 2);
        let rcpt_reveal = res2.receipts.last().unwrap();
        assert_eq!(rcpt_reveal.outcome, ExecOutcome::Success);
        assert_eq!(rcpt_reveal.gas_used, BASE_FEE_PER_TX);
    
        // Final balances:
        // Alice: 100 - COMMIT_FEE(1) - BASE_FEE(1) - 30 = 68
        // Bob:   50 + 30 = 80
        assert_eq!(balances["Alice"], 68);
        assert_eq!(balances["Bob"], 80);
    
        // Nonce consumed on reveal (not on commit)
        assert_eq!(*nonces.get("Alice").unwrap(), 1);
    
        // Optionally advance to deadline and apply an empty block (no dues remain)
        if deadline > ready_at {
            advance_to(&mut chain, &mut balances, &mut nonces, &mut commitments, &mut available, deadline);
            let b_deadline = Block::new(Vec::new(), deadline);
            chain
                .apply_block(&b_deadline, &mut balances, &mut nonces, &mut commitments, &mut available)
                .expect("deadline block should apply (no due reveals left)");
        }
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