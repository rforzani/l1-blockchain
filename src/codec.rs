// src/codec.rs

use crate::types::{AccessList, BlockHeader, ExecOutcome, Receipt, StateKey, Transaction};
use crate::types::{Tx};

pub const CODEC_VERSION: u8 = 1;
pub const DOM_TX: &[u8] = b"TX";
pub const DOM_RCPT: &[u8] = b"RCPT";
pub const DOM_HDR: &[u8] = b"HDR";
const TAG_TRANSFER: u8 = 0;
const TAG_COMMIT:   u8 = 1;
const TAG_AVAIL:    u8 = 2;

// --- helpers: write primitives deterministically ---

// append a u64 to a Vec<u8> in little-endian.
fn put_u64(dst: &mut Vec<u8>, x: u64) {
    dst.extend_from_slice(&x.to_le_bytes());
}

pub fn put_u32(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_le_bytes());
}

// append a string as length (u32 LE) + UTF-8 bytes.
fn put_str(dst: &mut Vec<u8>, s: &str) {
    let len = s.len() as u32;
    dst.extend_from_slice(&len.to_le_bytes()); // 4 bytes
    dst.extend_from_slice(s.as_bytes());       // the bytes
}


// --- public encoders used for hashing ---
pub fn tx_bytes(tx: &Transaction) -> Vec<u8> {
    let mut v = vec![CODEC_VERSION];
    v.extend_from_slice(DOM_TX);
    put_str(&mut v, &tx.from);
    put_str(&mut v, &tx.to);
    put_u64(&mut v, tx.amount);
    put_u64(&mut v, tx.nonce);
    v
}

pub fn receipt_bytes(r: &Receipt) -> Vec<u8> {
    let mut v = vec![CODEC_VERSION];
    v.extend_from_slice(DOM_RCPT);

    // outcome
    let tag: u8 = match r.outcome {
        ExecOutcome::Success => 0,
        ExecOutcome::Revert => 1,
    };
    v.push(tag);

    // gas_used
    put_u64(&mut v, r.gas_used);

    // error string (empty if None)
    match &r.error {
        Some(e) => put_str(&mut v, e),
        None => put_str(&mut v, ""),
    }

    v
}

fn put_access_list(v: &mut Vec<u8>, al: &AccessList) {
    // Make canonical copies: sort reads and writes by (tag, name)
    fn key_order<'a>(k: &'a StateKey) -> (u8, &'a str) {
        match k {
            StateKey::Balance(acct) => (0, acct.as_str()),
            StateKey::Nonce(acct)   => (1, acct.as_str()),
        }
    }

    let mut reads = al.reads.clone();
    let mut writes = al.writes.clone();

    
    reads.sort_by(|a, b| key_order(a).cmp(&key_order(b)));
    writes.sort_by(|a, b| key_order(a).cmp(&key_order(b)));

    // Encode counts (u32) then items
    fn put_keys(v: &mut Vec<u8>, ks: &[StateKey]) {
        let n = ks.len() as u32;
        v.extend_from_slice(&n.to_le_bytes());
        for k in ks {
            match k {
                StateKey::Balance(acct) => {
                    v.push(0);           // tag for Balance
                    put_str(v, acct);    // len + bytes
                }
                StateKey::Nonce(acct) => {
                    v.push(1);           // tag for Nonce
                    put_str(v, acct);
                }
            }
        }
    }

    put_keys(v, &reads);
    put_keys(v, &writes);
}

pub fn header_bytes(h: &BlockHeader) -> Vec<u8> {
    let mut v = vec![CODEC_VERSION];
    v.extend_from_slice(DOM_HDR);
    
    v.extend_from_slice(&h.parent_hash);
    put_u64(&mut v, h.height);
    v.extend_from_slice(&h.txs_root);
    v.extend_from_slice(&h.receipts_root);
    put_u64(&mut v, h.gas_used);
    v.extend_from_slice(&h.randomness);       
    v.extend_from_slice(&h.reveal_set_root);
    v.extend_from_slice(&h.il_root);

    v
}

pub fn put_bytes(v: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(v, bytes.len() as u32);      // 4-byte little-endian length
    v.extend_from_slice(bytes);
}

pub fn tx_enum_bytes(tx: &Tx) -> Vec<u8> {
    let mut v = Vec::new();
    v.push(CODEC_VERSION);
    match tx {
        Tx::Commit(c) => {
            v.push(TAG_COMMIT);
            // 32B commitment
            v.extend_from_slice(&c.commitment);
            // 32B ciphertext hash
            v.extend_from_slice(&c.ciphertext_hash);
            // sender
            put_str(&mut v, &c.sender);
            // canonical AL
            put_access_list(&mut v, &c.access_list);
        }
        Tx::Avail(a) => {
            v.push(TAG_AVAIL);
            v.extend_from_slice(&a.commitment);
        }
    }
    v
}