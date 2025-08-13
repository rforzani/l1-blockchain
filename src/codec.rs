// src/codec.rs

use crate::types::{Transaction, Receipt, ExecOutcome, BlockHeader};

pub const CODEC_VERSION: u8 = 1;
pub const DOM_TX: &[u8] = b"TX";
pub const DOM_RCPT: &[u8] = b"RCPT";
pub const DOM_HDR: &[u8] = b"HDR";

// --- helpers: write primitives deterministically ---

// append a u64 to a Vec<u8> in little-endian.
fn put_u64(dst: &mut Vec<u8>, x: u64) {
    dst.extend_from_slice(&x.to_le_bytes());
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

pub fn header_bytes(h: &BlockHeader) -> Vec<u8> {
    let mut v = vec![CODEC_VERSION];
    v.extend_from_slice(DOM_HDR);
    
    v.extend_from_slice(&h.parent_hash); 
    put_u64(&mut v, h.height);   
    v.extend_from_slice(&h.txs_root);    
    v.extend_from_slice(&h.receipts_root);
    put_u64(&mut v, h.gas_used);        

    v
}