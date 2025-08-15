//src/crypto.rs

use sha2::{Digest, Sha256};
use crate::{chain, types::Hash};
use ed25519_dalek::{Signature, VerifyingKey, Verifier};

const DOM_ORDER:  &[u8] = b"ORDER";
const COMMIT_DOMAIN: &[u8] = b"CAR_COMMIT_V1";
const REVEAL_PAIR_DOMAIN: &[u8] = b"CAR_REVEAL_PAIR_V1";
const SIGN_COMMIT_DOMAIN: &[u8] = b"SIGN_COMMIT_V1";
const SIGN_AVAIL_DOMAIN:  &[u8] = b"SIGN_AVAIL_V1";

pub fn verify_ed25519(pubkey: &[u8; 32], sig_bytes: &[u8; 64], msg: &[u8]) -> bool {
    // VerifyingKey is fallible
    let pk = match VerifyingKey::from_bytes(pubkey) {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    // Signature::from_bytes is infallible in v2 (takes [u8; 64])
    let sig = Signature::from_bytes(sig_bytes);

    pk.verify(msg, &sig).is_ok()
}

pub fn commit_signing_preimage(
    commitment: &Hash,     
    ciphertext_hash: &Hash,
    sender_bytes: &[u8],
    access_list_bytes: &[u8],
    chain_id: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(SIGN_COMMIT_DOMAIN.len() + 32 + 32 + sender_bytes.len() + access_list_bytes.len() + 8);
    buf.extend_from_slice(SIGN_COMMIT_DOMAIN);
    buf.extend_from_slice(&chain_id.to_le_bytes());
    buf.extend_from_slice(commitment);
    buf.extend_from_slice(ciphertext_hash);
    buf.extend_from_slice(sender_bytes);
    buf.extend_from_slice(access_list_bytes);
    buf
}

pub fn avail_signing_preimage(
    commitment: &Hash,  
    sender_bytes: &[u8],
    chain_id: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(SIGN_AVAIL_DOMAIN.len() + 8 + 32 + sender_bytes.len());
    buf.extend_from_slice(SIGN_AVAIL_DOMAIN);
    buf.extend_from_slice(&chain_id.to_le_bytes());
    buf.extend_from_slice(commitment);
    buf.extend_from_slice(sender_bytes);
    buf
}

pub fn commitment_hash(tx_bytes: &[u8], salt: &Hash, chain_id: u64) -> Hash {
    // capacity = domain + chain_id(8) + tx + salt(32)
    let mut buf = Vec::with_capacity(COMMIT_DOMAIN.len() + 8 + tx_bytes.len() + 32);
    buf.extend_from_slice(COMMIT_DOMAIN);
    buf.extend_from_slice(&chain_id.to_le_bytes());
    buf.extend_from_slice(tx_bytes);
    buf.extend_from_slice(salt);
    hash(&buf)
}

pub fn reveal_order_key(commitment: &Hash, randomness: &Hash) -> Hash {
    let mut buf = Vec::with_capacity(DOM_ORDER.len() + 32 + 32);
    buf.extend_from_slice(DOM_ORDER);
    buf.extend_from_slice(commitment);
    buf.extend_from_slice(randomness);
    hash(&buf)
}

pub fn hash_reveal_pair(commitment: &Hash, tx_hash: &Hash) -> Hash {
    // capacity = domain + commitment(32) + tx_hash(32)
    let mut buf = Vec::with_capacity(REVEAL_PAIR_DOMAIN.len() + 32 + 32);
    buf.extend_from_slice(REVEAL_PAIR_DOMAIN);
    buf.extend_from_slice(commitment);
    buf.extend_from_slice(tx_hash);
    hash(&buf)
}

fn hash(bytes: &[u8]) -> Hash {
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
    hash(&buf)
}

pub fn merkle_root(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => {
            // Convention: empty tree → hash of empty bytes
            hash(&[])
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

#[cfg(test)]
pub mod test_sig {
    use super::*;
    use ed25519_dalek::{SigningKey, VerifyingKey, Signer};
    use crate::codec::{string_bytes, access_list_bytes};
    use crate::state::CHAIN_ID;
    use crate::types::{AccessList, Hash};

    /// Deterministic keypair from a fixed 32-byte seed (no RNG needed)
    pub fn keypair_from_seed(seed: [u8; 32]) -> (SigningKey, VerifyingKey) {
        let sk = SigningKey::from_bytes(&seed);   // <-- v2 API
        let vk = VerifyingKey::from(&sk);
        (sk, vk)
    }

    /// Build the commit preimage and return (pubkey, signature)
    pub fn sign_commit_fields(
        sk: &SigningKey,
        sender: &str,
        access_list: &AccessList,
        commitment: &Hash,
        ciphertext_hash: &Hash,
    ) -> ([u8;32], [u8;64]) {
        let sender_bytes = string_bytes(sender);
        let al_bytes     = access_list_bytes(access_list);
        let pre          = commit_signing_preimage(commitment, ciphertext_hash, &sender_bytes, &al_bytes, CHAIN_ID);
        let sig          = sk.sign(&pre).to_bytes();     // v2: to_bytes() -> [u8;64]
        (VerifyingKey::from(sk).to_bytes(), sig)
    }

    /// Build the avail preimage and return (pubkey, signature)
    pub fn sign_avail_fields(
        sk: &SigningKey,
        sender: &str,
        commitment: &Hash,
    ) -> ([u8;32], [u8;64]) {
        let sender_bytes = string_bytes(sender);
        let pre          = avail_signing_preimage(commitment, &sender_bytes, CHAIN_ID);
        let sig          = sk.sign(&pre).to_bytes();
        (VerifyingKey::from(sk).to_bytes(), sig)
    }
}