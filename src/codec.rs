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
pub fn put_u64(dst: &mut Vec<u8>, x: u64) {
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
            v.extend_from_slice(&c.commitment);        // 32
            v.extend_from_slice(&c.ciphertext_hash);   // 32
            put_str(&mut v, &c.sender);                // canonical
            put_access_list(&mut v, &c.access_list);   // canonical
            v.extend_from_slice(&c.pubkey);            // 32
            v.extend_from_slice(&c.sig);               // 64
        }
        Tx::Avail(a) => {
            v.push(TAG_AVAIL);
            v.extend_from_slice(&a.commitment);        // 32
            put_str(&mut v, &a.sender);                // canonical
            v.extend_from_slice(&a.pubkey);            // 32
            v.extend_from_slice(&a.sig);               // 64
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Tx, CommitTx, AvailTx, AccessList, StateKey, Hash};

    // ---------- tiny manual decoder (for tests only) ----------

    fn rd_u32(i: &mut usize, b: &[u8]) -> Result<u32, &'static str> {
        if *i + 4 > b.len() { return Err("truncated u32"); }
        let v = u32::from_le_bytes(b[*i..*i+4].try_into().unwrap());
        *i += 4;
        Ok(v)
    }
    fn rd_u64(i: &mut usize, b: &[u8]) -> Result<u64, &'static str> {
        if *i + 8 > b.len() { return Err("truncated u64"); }
        let v = u64::from_le_bytes(b[*i..*i+8].try_into().unwrap());
        *i += 8;
        Ok(v)
    }
    fn rd_fixed<const N: usize>(i: &mut usize, b: &[u8]) -> Result<[u8; N], &'static str> {
        if *i + N > b.len() { return Err("truncated fixed"); }
        let mut out = [0u8; N];
        out.copy_from_slice(&b[*i..*i+N]);
        *i += N;
        Ok(out)
    }
    fn rd_str(i: &mut usize, b: &[u8]) -> Result<String, &'static str> {
        let n = rd_u32(i, b)? as usize;
        if *i + n > b.len() { return Err("truncated str"); }
        let s = std::str::from_utf8(&b[*i..*i+n]).map_err(|_| "utf8")?;
        *i += n;
        Ok(s.to_string())
        // NOTE: this mirrors put_str (len + bytes)
    }

    fn decode_access_list(i: &mut usize, b: &[u8]) -> Result<AccessList, &'static str> {
        fn rd_keys(i: &mut usize, b: &[u8]) -> Result<Vec<StateKey>, &'static str> {
            let n = rd_u32(i, b)? as usize;
            let mut out = Vec::with_capacity(n);
            for _ in 0..n {
                if *i >= b.len() { return Err("truncated key tag"); }
                let tag = b[*i]; *i += 1;
                match tag {
                    0 => { // Balance
                        let acct = rd_str(i, b)?;
                        out.push(StateKey::Balance(acct));
                    }
                    1 => { // Nonce
                        let acct = rd_str(i, b)?;
                        out.push(StateKey::Nonce(acct));
                    }
                    _ => return Err("bad key tag"),
                }
            }
            Ok(out)
        }
        let reads = rd_keys(i, b)?;
        let writes = rd_keys(i, b)?;
        Ok(AccessList { reads, writes })
    }

    fn decode_tx(bytes: &[u8]) -> Result<Tx, String> {
        let mut i = 0usize;

        // version
        if i >= bytes.len() { return Err("empty".into()); }
        let ver = bytes[i]; i += 1;
        if ver != CODEC_VERSION {
            return Err("version mismatch".into());
        }

        if i >= bytes.len() { return Err("truncated tag".into()); }
        let tag = bytes[i]; i += 1;

        match tag {
            TAG_COMMIT => {
                let commitment: Hash      = rd_fixed::<32>(&mut i, bytes).map_err(|e| e.to_string())?;
                let ciphertext_hash: Hash = rd_fixed::<32>(&mut i, bytes).map_err(|e| e.to_string())?;
                let sender = rd_str(&mut i, bytes).map_err(|e| e.to_string())?;
                let access_list = decode_access_list(&mut i, bytes).map_err(|e| e.to_string())?;
                let pubkey: [u8; 32] = rd_fixed::<32>(&mut i, bytes).map_err(|e| e.to_string())?;
                let sig:    [u8; 64] = rd_fixed::<64>(&mut i, bytes).map_err(|e| e.to_string())?;

                Ok(Tx::Commit(CommitTx {
                    commitment, ciphertext_hash, sender, access_list, pubkey, sig
                }))
            }
            TAG_AVAIL => {
                let commitment: Hash = rd_fixed::<32>(&mut i, bytes).map_err(|e| e.to_string())?;
                let sender = rd_str(&mut i, bytes).map_err(|e| e.to_string())?;
                let pubkey: [u8; 32] = rd_fixed::<32>(&mut i, bytes).map_err(|e| e.to_string())?;
                let sig:    [u8; 64] = rd_fixed::<64>(&mut i, bytes).map_err(|e| e.to_string())?;
                Ok(Tx::Avail(AvailTx { commitment, sender, pubkey, sig }))
            }
            _ => Err("unknown tag".into()),
        }
    }

    // ---------- helpers for constructing test data ----------
    fn nz32(b: u8) -> [u8; 32] { [b; 32] }
    fn nz64(b: u8) -> [u8; 64] { [b; 64] }
    fn dummy_al() -> AccessList {
        AccessList {
            reads:  vec![StateKey::Balance("Alice".into()), StateKey::Nonce("Alice".into())],
            writes: vec![StateKey::Balance("Bob".into())],
        }
    }

    // ========== TESTS ==========

    #[test]
    fn codec_roundtrip_commit_manual_decode() {
        let tx = Tx::Commit(CommitTx {
            commitment:      nz32(0x11),
            ciphertext_hash: nz32(0x22),
            sender:          "Alice".into(),
            access_list:     dummy_al(),
            pubkey:          nz32(0xA1),
            sig:             nz64(0xB2),
        });

        let enc = tx_enum_bytes(&tx);
        let dec = decode_tx(&enc).expect("decode commit");
        assert_eq!(tx, dec, "commit round-trip mismatch");
    }

    #[test]
    fn codec_roundtrip_avail_manual_decode() {
        let tx = Tx::Avail(AvailTx {
            commitment: nz32(0x33),
            sender:     "Alice".into(),
            pubkey:     nz32(0xC3),
            sig:        nz64(0xD4),
        });

        let enc = tx_enum_bytes(&tx);
        let dec = decode_tx(&enc).expect("decode avail");
        assert_eq!(tx, dec, "avail round-trip mismatch");
    }

    #[test]
    fn codec_rejects_wrong_version() {
        let tx = Tx::Avail(AvailTx {
            commitment: nz32(0x44),
            sender:     "Alice".into(),
            pubkey:     nz32(0xE5),
            sig:        nz64(0xF6),
        });
        let mut enc = tx_enum_bytes(&tx);
        enc[0] = CODEC_VERSION.wrapping_add(1); // flip version

        let err = decode_tx(&enc).expect_err("should reject unknown version");
        assert!(err.contains("version"), "expected version error, got: {err}");
    }

    #[test]
    fn codec_rejects_truncated_buffer() {
        let tx = Tx::Commit(CommitTx {
            commitment:      nz32(0x55),
            ciphertext_hash: nz32(0x66),
            sender:          "Alice".into(),
            access_list:     dummy_al(),
            pubkey:          nz32(0x77),
            sig:             nz64(0x88),
        });
        let mut enc = tx_enum_bytes(&tx);
        enc.truncate(enc.len().saturating_sub(1)); // drop last byte

        let err = decode_tx(&enc).expect_err("should reject truncated");
        // Accept any of these keywords to keep the test flexible across minor changes
        assert!(
            err.contains("truncated") || err.contains("underflow") || err.contains("unexpected"),
            "expected truncation-like error, got: {err}"
        );
    }
}