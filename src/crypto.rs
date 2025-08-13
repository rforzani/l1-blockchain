//src/crypto.rs

use sha2::{Digest, Sha256};
use crate::types::Hash;

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
    hash_bytes_sha256(&buf)
}

pub fn merkle_root(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => {
            // Convention: empty tree → hash of empty bytes
            hash_bytes_sha256(&[])
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