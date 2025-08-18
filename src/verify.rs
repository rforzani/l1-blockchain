//src/verify.rs

use crate::{codec::{receipt_bytes, tx_bytes, tx_enum_bytes, access_list_bytes}, crypto::{hash_bytes_sha256, merkle_root}, state::CHAIN_ID, types::{Block, BlockHeader, Hash, Receipt}};

pub fn compute_roots_for(block: &Block, receipts: &[Receipt]) -> (Hash, Hash, Hash) {
    // txs_root from block.transactions (reveals are NOT part of txs_root)
    let tx_hashes: Vec<Hash> = block
        .transactions
        .iter()
        .map(|tx| hash_bytes_sha256(&tx_enum_bytes(tx)))
        .collect();

    // receipts_root from all receipts (commits/avails + reveals)
    let receipt_hashes: Vec<Hash> = receipts
        .iter()
        .map(|r| hash_bytes_sha256(&receipt_bytes(r)))
        .collect();

    // reveal_set_root from block.reveals: leaf = H(commitment || tx_hash)
    let mut pairs: Vec<(Hash, Hash)> = block
        .reveals
        .iter()
        .map(|r| {
            let ser = tx_bytes(&r.tx);
            let al_bytes = access_list_bytes(&r.tx.access_list);
            let cmt = crate::crypto::commitment_hash(&ser, &al_bytes, &r.salt, CHAIN_ID);
            let txh = hash_bytes_sha256(&ser);
            (cmt, txh)
        })
        .collect();

    // canonical ordering by commitment
    pairs.sort_by(|(c1, _), (c2, _)| c1.cmp(c2));

    let reveal_leaves: Vec<Hash> = pairs
        .into_iter()
        .map(|(cmt, txh)| {
            let mut buf = Vec::with_capacity(64);
            buf.extend_from_slice(&cmt);
            buf.extend_from_slice(&txh);
            hash_bytes_sha256(&buf)
        })
        .collect();

    (
        merkle_root(&tx_hashes),
        merkle_root(&receipt_hashes),
        merkle_root(&reveal_leaves),
    )
}

pub fn verify_block_roots(header: &BlockHeader, block: &Block, receipts: &[Receipt]) -> Result<(), String> {
    let (txs_root, receipts_root, reveals_root) = compute_roots_for(block, receipts);
    if txs_root != header.txs_root || receipts_root != header.receipts_root || reveals_root != header.reveal_set_root {
        return Err("header mismatch: roots".to_string());
    }
    Ok(())
}

#[cfg(test)]

#[test]
fn verify_block_roots_catches_tamper() {
    use std::collections::HashMap;
    use ed25519_dalek::{SigningKey, VerifyingKey, Signer as _};
    use crate::fees::FeeState;
    use crate::state::{Balances, Nonces, Commitments, Available, CHAIN_ID};
    use crate::stf::process_block;
    use crate::types::{Block, Tx, CommitTx, Hash, AccessList, StateKey};
    use crate::verify::verify_block_roots;
    use crate::codec::{string_bytes, access_list_bytes};
    use crate::crypto::{commit_signing_preimage, addr_from_pubkey, addr_hex};

    // Keypair and sender address
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let vk = VerifyingKey::from(&sk);
    let pk_bytes = vk.to_bytes();
    let sender = addr_hex(&addr_from_pubkey(&pk_bytes));

    // State
    let mut balances: Balances = HashMap::from([(sender.clone(), 100_u64)]);
    let mut nonces: Nonces = Default::default();
    let mut comm: Commitments = Default::default();
    let mut avail: Available  = Default::default();

    let al = AccessList {
        reads:  vec![StateKey::Balance(sender.clone()), StateKey::Nonce(sender.clone())],
        writes: vec![StateKey::Balance(sender.clone()), StateKey::Nonce(sender.clone())],
    };

    // Sign the commit
    let sender_bytes = string_bytes(&sender);
    let al_bytes     = access_list_bytes(&al);
    let commitment: Hash = [42u8; 32];
    let ciphertext_hash: Hash = [0u8; 32];
    let pre = commit_signing_preimage(&commitment, &ciphertext_hash, &sender_bytes, &al_bytes, CHAIN_ID);
    let sig = sk.sign(&pre).to_bytes();

    let block = Block::new(
        vec![Tx::Commit(CommitTx {
            commitment,
            sender: sender.clone(),
            ciphertext_hash,
            access_list: al,
            pubkey: pk_bytes,
            sig,
        })],
        1,
    );

    // Genesis parent
    let parent: Hash = [0u8; 32];
    
    let fee_state = FeeState::from_defaults();

    // Build (builder path)
    let res = process_block(
        &block,
        &mut balances,
        &mut nonces,
        &mut comm,
        &mut avail,
        &parent,
        &fee_state
    ).expect("ok");

    // Verify (ok)
    verify_block_roots(&res.header, &block, &res.receipts).expect("roots match");

    // Tamper one receipt (commit produced a receipt at index 0)
    let mut bad_receipts = res.receipts.clone();
    bad_receipts[0].gas_used += 1;

    // Verify (must fail)
    let err = verify_block_roots(&res.header, &block, &bad_receipts).unwrap_err();
    assert!(err.contains("mismatch"));
}