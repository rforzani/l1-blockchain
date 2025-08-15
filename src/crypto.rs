//src/crypto.rs

use sha2::{Digest, Sha256};
use crate::{chain, types::Hash};

const DOM_ORDER:  &[u8] = b"ORDER";
const COMMIT_DOMAIN: &[u8] = b"CAR_COMMIT_V1";
const REVEAL_PAIR_DOMAIN: &[u8] = b"CAR_REVEAL_PAIR_V1";

pub fn commitment_hash(tx_bytes: &[u8], salt: &Hash, chain_id: u64) -> Hash {
    // capacity = domain + chain_id(8) + tx + salt(32)
    let mut buf = Vec::with_capacity(COMMIT_DOMAIN.len() + 8 + tx_bytes.len() + 32);
    buf.extend_from_slice(COMMIT_DOMAIN);
    buf.extend_from_slice(&chain_id.to_le_bytes());
    buf.extend_from_slice(tx_bytes);
    buf.extend_from_slice(salt);
    H(&buf)
}

pub fn reveal_order_key(commitment: &Hash, randomness: &Hash) -> Hash {
    let mut buf = Vec::with_capacity(DOM_ORDER.len() + 32 + 32);
    buf.extend_from_slice(DOM_ORDER);
    buf.extend_from_slice(commitment);
    buf.extend_from_slice(randomness);
    H(&buf)
}

pub fn hash_reveal_pair(commitment: &Hash, tx_hash: &Hash) -> Hash {
    // capacity = domain + commitment(32) + tx_hash(32)
    let mut buf = Vec::with_capacity(REVEAL_PAIR_DOMAIN.len() + 32 + 32);
    buf.extend_from_slice(REVEAL_PAIR_DOMAIN);
    buf.extend_from_slice(commitment);
    buf.extend_from_slice(tx_hash);
    H(&buf)
}

fn H(bytes: &[u8]) -> Hash {
    hash_bytes_sha256(bytes)
}

pub fn hash_bytes_sha256(data: &[u8]) -> Hash {
    // 1. Create a new SHA-256 hasher
    let mut hasher = Sha256::new();

    // 2. Feed it our bytes
    hasher.update(data);

    // 3. Finalize and get the hash as a fixed-size array
    let result = hasher.finalize(); // returns a GenericArray<u8, 32>

    // 4. Convert to our Hash type ([u8; 32])
    result.into()
}

fn parent_hash(left: &Hash, right: &Hash) -> Hash {
    let mut buf = Vec::with_capacity(4 + 32 + 32);
    buf.extend_from_slice(b"MRKL");
    buf.extend_from_slice(left);
    buf.extend_from_slice(right);
    H(&buf)
}

pub fn merkle_root(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => {
            // Convention: empty tree → hash of empty bytes
            H(&[])
        }
        1 => leaves[0],
        _ => {
            let mut level: Vec<[u8; 32]>  = leaves.to_vec();
            while level.len() > 1 {
                if level.len() % 2 == 1 {
                    let last = *level.last().unwrap();
                    level.push(last);
                }
                let mut next: Vec<Hash> = Vec::with_capacity(level.len() / 2);
                for pair in level.chunks(2) {
                    let left: &Hash = &pair[0];
                    let right: &Hash = &pair[1];
                    next.push(parent_hash(left, right));
                }
                level = next;
            }
            
            return level[0];
        }
    }
}