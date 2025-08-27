//! Integration tests for threshold encryption in the full blockchain context

use l1_blockchain::chain::Chain;
use l1_blockchain::codec::{access_list_bytes, tx_bytes};
use l1_blockchain::crypto::bls::BlsSigner;
use l1_blockchain::crypto::{commitment_hash, hash_bytes_sha256};
use l1_blockchain::fees::FeeState;
use l1_blockchain::mempool::encrypted::dkg;
use l1_blockchain::mempool::{ThresholdCiphertext, ThresholdEngine, ThresholdShare};
use l1_blockchain::pos::registry::{Validator, ValidatorSet, ValidatorStatus};
use l1_blockchain::state::CHAIN_ID;
use l1_blockchain::state::{Available, Balances, Commitments, Nonces};
use l1_blockchain::stf::{process_block, process_commit};
use l1_blockchain::types::{
    AccessList, AvailTx, Block, BlockHeader, CommitTx, Event, Hash, RevealTx, Transaction, Tx,
};
use std::collections::HashMap;

/// Create a test validator set with threshold encryption capabilities
fn create_test_validator_set(n_validators: usize, epoch: u64) -> (ValidatorSet, ThresholdEngine) {
    let mut validators = Vec::new();
    let mut bls_pubkeys = Vec::new();

    for i in 1..=n_validators {
        let sk_bytes = [i as u8; 32];
        let bls_signer = BlsSigner::from_sk_bytes(&sk_bytes).unwrap();
        let bls_pubkey = bls_signer.public_key_bytes();

        validators.push(Validator {
            id: i as u64,
            ed25519_pubkey: [i as u8; 32],
            bls_pubkey: Some(bls_pubkey),
            vrf_pubkey: [i as u8; 32],
            stake: 1000,
            status: ValidatorStatus::Active,
        });

        bls_pubkeys.push(bls_pubkey);
    }

    let validator_set = ValidatorSet {
        validators,
        epoch,
        total_stake: n_validators as u128 * 1000,
    };

    // Set up threshold encryption
    let threshold = (n_validators * 2) / 3 + 1; // Byzantine fault tolerance
    let threshold_pk = dkg::generate_threshold_public_key(&bls_pubkeys, epoch, threshold).unwrap();

    let mut engine = ThresholdEngine::new();
    engine.update_public_key(threshold_pk).unwrap();

    // Generate private shares
    let master_seed = [42u8; 32];
    let validator_ids: Vec<_> = (1..=n_validators).map(|i| i as u64).collect();
    let private_shares =
        dkg::generate_private_shares(&validator_ids, &master_seed, epoch, threshold);

    for (validator_id, share) in private_shares {
        engine.add_validator_share(validator_id, share);
    }

    (validator_set, engine)
}

/// Create a test chain with threshold encryption
fn create_test_chain() -> Chain {
    let (validator_set, threshold_engine) = create_test_validator_set(4, 0);
    let mut chain = Chain::new();
    chain.init_genesis(validator_set, [42u8; 32]);
    chain.threshold_engine = threshold_engine;
    chain
}

#[test]
fn test_full_commit_avail_decrypt_flow() {
    let mut chain = create_test_chain();
    let mut balances = Balances::new();
    let mut nonces = Nonces::new();
    let mut commitments = Commitments::new();
    let mut available = Available::new();

    // Set up initial balance
    let sender = "0x1234567890123456789012345678901234567890";
    balances.insert(sender.to_string(), 10_000);

    let fee_state = FeeState {
        commit_base: 100,
        avail_base: 50,
        exec_base: 25,
    };

    // 1. Create and process a commit transaction with encrypted payload
    let original_tx_data = b"secret transaction payload for testing";
    let encrypted_payload = chain.threshold_engine.encrypt(original_tx_data, 0).unwrap();

    let commit_tx = CommitTx {
        commitment: [1u8; 32], // Mock commitment hash
        sender: sender.to_string(),
        access_list: AccessList {
            reads: vec![],
            writes: vec![],
        },
        encrypted_payload: encrypted_payload.clone(),
        pubkey: [2u8; 32],
        sig: [3u8; 64],
    };

    // Process commit transaction
    let mut events = Vec::new();
    let mut burned_total = 0u64;
    let proposer = "0xproposer123456789012345678901234567890".to_string();

    let commit_receipt = process_commit(
        &commit_tx,
        &mut balances,
        &mut commitments,
        1, // current_height
        &mut events,
        &fee_state,
        &proposer,
        &mut burned_total,
    )
    .unwrap();

    // Verify commit was processed
    assert_eq!(
        commit_receipt.outcome,
        l1_blockchain::types::ExecOutcome::Success
    );
    assert!(commitments.contains_key(&commit_tx.commitment));
    let meta = commitments.get(&commit_tx.commitment).unwrap();
    assert!(!meta.is_decrypted);
    assert_eq!(
        meta.encrypted_payload.commitment_hash(),
        encrypted_payload.commitment_hash()
    );

    // 2. Generate threshold shares from validators
    let validator_ids = vec![1, 2, 3]; // Enough for 2-of-3 threshold (with 4 validators, threshold is 3)
    let mut threshold_shares = Vec::new();

    for &validator_id in &validator_ids {
        let share = chain
            .threshold_engine
            .generate_share(&encrypted_payload, validator_id)
            .unwrap();
        threshold_shares.push(share.clone());

        // Add share to chain (simulates receiving shares from validators)
        let can_decrypt = chain
            .add_threshold_share(commit_tx.commitment, share)
            .unwrap();
        if validator_id == 3 {
            // After third share
            assert!(can_decrypt); // Should have enough shares now
        }
    }

    // 3. Create and process availability transaction
    let payload_hash = encrypted_payload.commitment_hash();
    let avail_tx = AvailTx {
        commitment: commit_tx.commitment,
        sender: sender.to_string(),
        payload_hash,
        payload_size: encrypted_payload.size() as u64,
        pubkey: [4u8; 32],
        sig: [5u8; 64],
    };

    // Process the avail transaction to mark commitment as available
    let avail_receipt = l1_blockchain::stf::process_avail(
        &avail_tx,
        &mut commitments,
        &mut available,
        10, // current_height (after decryption delay)
        &mut events,
        &mut balances,
        &fee_state,
        &proposer,
        &mut burned_total,
    )
    .unwrap();

    assert_eq!(
        avail_receipt.outcome,
        l1_blockchain::types::ExecOutcome::Success
    );
    assert!(available.contains(&commit_tx.commitment));

    // 4. Test block processing with threshold decryption
    let block = Block {
        header: BlockHeader {
            height: 15, // Past decryption delay
            parent_hash: [0u8; 32],
            txs_root: [0u8; 32],
            receipts_root: [0u8; 32],
            reveal_set_root: [0u8; 32],
            il_root: [0u8; 32],
            gas_used: 0,
            randomness: [0u8; 32],
            exec_base_fee: 25,
            commit_base_fee: 100,
            avail_base_fee: 50,
            timestamp: 0,
            slot: 0,
            epoch: 0,
            proposer_id: 1,
            signature: [0u8; 64],
            bundle_len: 1,
            vrf_preout: [0u8; 32],
            vrf_output: [0u8; 32],
            vrf_proof: vec![],
            view: 0,
            justify_qc_hash: [0u8; 32],
        },
        transactions: vec![],
        batch_digests: vec![],
        reveals: vec![],
        justify_qc: l1_blockchain::types::QC {
            view: 0,
            block_id: [0u8; 32],
            agg_sig: l1_blockchain::crypto::bls::BlsSignatureBytes([0u8; 96]),
            bitmap: bitvec::vec::BitVec::new(),
        },
    };

    let mut sim_commitments = commitments.clone();
    let mut sim_available = available.clone();
    let mut sim_balances = balances.clone();
    let mut sim_nonces = nonces.clone();
    let mut sim_burned = burned_total;

    // Process block - this should trigger threshold decryption
    let result = process_block(
        &block,
        &chain.batch_store,
        &mut sim_balances,
        &mut sim_nonces,
        &mut sim_commitments,
        &mut sim_available,
        &fee_state,
        &proposer,
        &mut sim_burned,
        &chain.threshold_engine,
        &chain,
    )
    .unwrap();

    // Verify threshold decryption occurred
    let decrypted_meta = sim_commitments.get(&commit_tx.commitment).unwrap();
    assert!(decrypted_meta.is_decrypted);
    assert!(!decrypted_meta.decryption_shares.is_empty());

    // Check that ThresholdDecryptionComplete event was emitted
    let decryption_events: Vec<_> = result
        .events
        .iter()
        .filter(|e| matches!(e, Event::ThresholdDecryptionComplete { .. }))
        .collect();
    assert_eq!(decryption_events.len(), 1);
}

#[test]
fn test_insufficient_threshold_shares() {
    let mut chain = create_test_chain();
    let mut balances = Balances::new();
    let mut commitments = Commitments::new();
    let mut available = Available::new();

    let sender = "0x1234567890123456789012345678901234567890";
    balances.insert(sender.to_string(), 10_000);

    let fee_state = FeeState {
        commit_base: 100,
        avail_base: 50,
        exec_base: 25,
    };

    // Create encrypted transaction
    let original_tx_data = b"secret transaction payload";
    let encrypted_payload = chain.threshold_engine.encrypt(original_tx_data, 0).unwrap();

    let commit_tx = CommitTx {
        commitment: [1u8; 32],
        sender: sender.to_string(),
        access_list: AccessList {
            reads: vec![],
            writes: vec![],
        },
        encrypted_payload: encrypted_payload.clone(),
        pubkey: [2u8; 32],
        sig: [3u8; 64],
    };

    // Process commit
    let mut events = Vec::new();
    let mut burned_total = 0u64;
    let proposer = "0xproposer123456789012345678901234567890".to_string();

    process_commit(
        &commit_tx,
        &mut balances,
        &mut commitments,
        1,
        &mut events,
        &fee_state,
        &proposer,
        &mut burned_total,
    )
    .unwrap();

    // Add only insufficient shares (2 out of required 3)
    for validator_id in 1..=2 {
        let share = chain
            .threshold_engine
            .generate_share(&encrypted_payload, validator_id)
            .unwrap();
        let can_decrypt = chain
            .add_threshold_share(commit_tx.commitment, share)
            .unwrap();
        assert!(!can_decrypt); // Should not have enough shares yet
    }

    // Mark as available
    available.insert(commit_tx.commitment);

    // Process block - should NOT trigger decryption due to insufficient shares
    let block = Block {
        header: BlockHeader {
            height: 15, // Past decryption delay
            parent_hash: [0u8; 32],
            txs_root: [0u8; 32],
            receipts_root: [0u8; 32],
            reveal_set_root: [0u8; 32],
            il_root: [0u8; 32],
            gas_used: 0,
            randomness: [0u8; 32],
            exec_base_fee: 25,
            commit_base_fee: 100,
            avail_base_fee: 50,
            timestamp: 0,
            slot: 0,
            epoch: 0,
            proposer_id: 1,
            signature: [0u8; 64],
            bundle_len: 1,
            vrf_preout: [0u8; 32],
            vrf_output: [0u8; 32],
            vrf_proof: vec![],
            view: 0,
            justify_qc_hash: [0u8; 32],
        },
        transactions: vec![],
        batch_digests: vec![],
        reveals: vec![],
        justify_qc: l1_blockchain::types::QC {
            view: 0,
            block_id: [0u8; 32],
            agg_sig: l1_blockchain::crypto::bls::BlsSignatureBytes([0u8; 96]),
            bitmap: bitvec::vec::BitVec::new(),
        },
    };

    let mut sim_commitments = commitments.clone();
    let mut sim_available = available.clone();
    let mut sim_balances = balances.clone();
    let mut sim_nonces = Nonces::new();
    let mut sim_burned = burned_total;

    let result = process_block(
        &block,
        &chain.batch_store,
        &mut sim_balances,
        &mut sim_nonces,
        &mut sim_commitments,
        &mut sim_available,
        &fee_state,
        &proposer,
        &mut sim_burned,
        &chain.threshold_engine,
        &chain,
    )
    .unwrap();

    // Verify NO decryption occurred
    let meta = sim_commitments.get(&commit_tx.commitment).unwrap();
    assert!(!meta.is_decrypted);

    // Check that NO ThresholdDecryptionComplete event was emitted
    let decryption_events: Vec<_> = result
        .events
        .iter()
        .filter(|e| matches!(e, Event::ThresholdDecryptionComplete { .. }))
        .collect();
    assert_eq!(decryption_events.len(), 0);
}

#[test]
fn test_duplicate_share_rejection() {
    let mut chain = create_test_chain();
    let original_tx_data = b"test transaction";
    let encrypted_payload = chain.threshold_engine.encrypt(original_tx_data, 0).unwrap();
    let commitment = [1u8; 32];

    // Add initial share
    let share1 = chain
        .threshold_engine
        .generate_share(&encrypted_payload, 1)
        .unwrap();
    let result1 = chain.add_threshold_share(commitment, share1.clone());
    assert!(result1.is_ok());

    // Try to add duplicate share from same validator
    let result2 = chain.add_threshold_share(commitment, share1);
    assert!(result2.is_err());
    assert!(result2.unwrap_err().contains("Duplicate share"));
}

#[test]
fn test_invalid_validator_share_rejection() {
    let mut chain = create_test_chain();
    let original_tx_data = b"test transaction";
    let encrypted_payload = chain.threshold_engine.encrypt(original_tx_data, 0).unwrap();
    let commitment = [1u8; 32];

    // Try to add share from invalid validator (ID 999 doesn't exist)
    let invalid_share = ThresholdShare {
        validator_id: 999,
        share_bytes: [0u8; 48],
        proof: [1u8; 96],
        epoch: 0,
    };

    let result = chain.add_threshold_share(commitment, invalid_share);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("invalid validator"));
}

#[test]
fn test_epoch_mismatch_rejection() {
    let mut chain = create_test_chain();
    let original_tx_data = b"test transaction";
    let encrypted_payload = chain.threshold_engine.encrypt(original_tx_data, 0).unwrap();
    let commitment = [1u8; 32];

    // Create share with wrong epoch
    let mut share = chain
        .threshold_engine
        .generate_share(&encrypted_payload, 1)
        .unwrap();
    share.epoch = 999; // Wrong epoch

    let result = chain.add_threshold_share(commitment, share);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("epoch"));
}

#[test]
fn test_share_cleanup() {
    let mut chain = create_test_chain();
    let mut commitments = Commitments::new();

    // Create commitment
    let original_tx_data = b"test transaction";
    let encrypted_payload = chain.threshold_engine.encrypt(original_tx_data, 0).unwrap();
    let commitment = [1u8; 32];

    // Add commitment meta
    commitments.insert(
        commitment,
        l1_blockchain::types::CommitmentMeta {
            owner: "0x123".to_string(),
            expires_at: 100,
            consumed: false,
            included_at: 1,
            access_list: AccessList {
                reads: vec![],
                writes: vec![],
            },
            encrypted_payload: encrypted_payload.clone(),
            decryption_shares: vec![],
            is_decrypted: false,
        },
    );

    // Add share
    let share = chain
        .threshold_engine
        .generate_share(&encrypted_payload, 1)
        .unwrap();
    chain.add_threshold_share(commitment, share).unwrap();

    // Verify share exists
    assert!(chain.get_threshold_shares(&commitment).is_some());

    // Mark commitment as consumed
    commitments.get_mut(&commitment).unwrap().consumed = true;

    // Clean up shares
    chain.cleanup_old_shares(&commitments);

    // Verify share was removed
    assert!(chain.get_threshold_shares(&commitment).is_none());
}

#[test]
fn test_byzantine_fault_tolerance_threshold() {
    // Test with 7 validators (can tolerate 2 Byzantine faults)
    let (validator_set, threshold_engine) = create_test_validator_set(7, 0);
    let mut chain = Chain::new();
    chain.init_genesis(validator_set, [42u8; 32]);
    chain.threshold_engine = threshold_engine;

    let original_tx_data = b"byzantine fault tolerance test";
    let encrypted_payload = chain.threshold_engine.encrypt(original_tx_data, 0).unwrap();
    let commitment = [1u8; 32];

    // Add shares from exactly the threshold number of validators (5 out of 7)
    for validator_id in 1..=5 {
        let share = chain
            .threshold_engine
            .generate_share(&encrypted_payload, validator_id)
            .unwrap();
        let can_decrypt = chain.add_threshold_share(commitment, share).unwrap();

        if validator_id == 5 {
            assert!(can_decrypt); // Should have enough shares after the 5th
        } else {
            assert!(!can_decrypt); // Should not have enough before the 5th
        }
    }

    // Verify we can decrypt with collected shares
    let shares = chain.get_threshold_shares(&commitment).unwrap();
    let decrypted = chain
        .threshold_engine
        .decrypt(&encrypted_payload, shares)
        .unwrap();
    assert_eq!(decrypted, original_tx_data);
}
