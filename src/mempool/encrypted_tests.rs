//! Comprehensive tests for the threshold encryption system

use super::encrypted::*;
use super::encrypted::dkg;
use crate::crypto::bls::BlsSigner;
use crate::types::{CommitTx, AvailTx, Hash};
use std::collections::HashMap;

/// Test data structure for setting up mock validators
struct MockValidator {
    id: crate::pos::registry::ValidatorId,
    bls_signer: BlsSigner,
    threshold_key_share: [u8; 32],
}

impl MockValidator {
    fn new(id: crate::pos::registry::ValidatorId, seed: u8) -> Self {
        // Generate proper BLS12-381 private key with sufficient entropy
        let mut sk_bytes = [0u8; 32];
        for i in 0..32 {
            sk_bytes[i] = seed.wrapping_add(i as u8).wrapping_mul(7); // Add entropy and variation
        }
        // Ensure the key is in valid scalar field by modding with a known good value
        sk_bytes[31] &= 0x1f; // Reduce the high byte to ensure valid scalar
        
        let bls_signer = BlsSigner::from_sk_bytes(&sk_bytes).unwrap();
        let threshold_key_share = [seed.wrapping_add(100); 32]; // Distinct from BLS key
        
        Self {
            id,
            bls_signer,
            threshold_key_share,
        }
    }
    
    fn bls_public_key(&self) -> [u8; 48] {
        self.bls_signer.public_key_bytes()
    }
}

/// Setup a test scenario with N validators
fn setup_test_validators(n: usize) -> Vec<MockValidator> {
    (1..=n)
        .map(|i| MockValidator::new(i as crate::pos::registry::ValidatorId, i as u8))
        .collect()
}

/// Create a threshold public key and engine setup from mock validators
fn setup_threshold_system(validators: &[MockValidator], threshold: usize, epoch: u64) -> (ThresholdPublicKey, ThresholdEngine, HashMap<crate::pos::registry::ValidatorId, [u8; 32]>) {
    // Collect BLS public keys
    let validator_pks: Vec<[u8; 48]> = validators.iter().map(|v| v.bls_public_key()).collect();
    
    // Generate threshold public key
    let threshold_pk = dkg::generate_threshold_public_key(&validator_pks, epoch, threshold)
        .expect("Failed to generate threshold public key");
    
    // Set up threshold engine
    let mut engine = ThresholdEngine::new();
    engine.update_public_key(threshold_pk.clone()).unwrap();
    
    // Generate and distribute private shares
    let master_seed = [42u8; 32];
    let validator_ids: Vec<_> = validators.iter().map(|v| v.id).collect();
    let private_shares = dkg::generate_private_shares(&validator_ids, &master_seed, epoch, threshold);
    
    for (validator_id, share) in &private_shares {
        engine.add_validator_share(*validator_id, *share);
    }
    
    (threshold_pk, engine, private_shares)
}

#[test]
fn test_threshold_encryption_basic_flow() {
    let validators = setup_test_validators(4);
    let threshold = 3; // 3-of-4 threshold
    let epoch = 0;
    
    let (threshold_pk, engine, _private_shares) = setup_threshold_system(&validators, threshold, epoch);
    
    let test_data = b"secret transaction data for testing";
    
    // Encrypt
    let ciphertext = engine.encrypt(test_data, epoch).unwrap();
    assert_eq!(ciphertext.epoch, epoch);
    assert!(!ciphertext.encrypted_data.is_empty());
    
    // Generate shares from enough validators (meeting threshold)
    let mut shares = Vec::new();
    for validator in &validators[..threshold] {
        let share = engine.generate_share(&ciphertext, validator.id).unwrap();
        assert_eq!(share.validator_id, validator.id);
        assert_eq!(share.epoch, epoch);
        shares.push(share);
    }
    
    // Decrypt
    let decrypted = engine.decrypt(&ciphertext, &shares).unwrap();
    assert_eq!(decrypted, test_data);
}

#[test]
fn test_insufficient_shares_failure() {
    let validators = setup_test_validators(4);
    let threshold = 3;
    let epoch = 0;
    
    let (_threshold_pk, engine, _private_shares) = setup_threshold_system(&validators, threshold, epoch);
    
    let test_data = b"secret transaction data";
    let ciphertext = engine.encrypt(test_data, epoch).unwrap();
    
    // Generate shares from insufficient validators (below threshold)
    let mut shares = Vec::new();
    for validator in &validators[..threshold-1] { // One less than threshold
        let share = engine.generate_share(&ciphertext, validator.id).unwrap();
        shares.push(share);
    }
    
    // Should fail due to insufficient shares
    let result = engine.decrypt(&ciphertext, &shares);
    assert!(matches!(result, Err(ThresholdError::InsufficientShares { have: 2, need: 3 })));
}

#[test]
fn test_wrong_epoch_rejection() {
    let validators = setup_test_validators(4);
    let threshold = 3;
    let epoch = 0;
    
    let (_threshold_pk, engine, _private_shares) = setup_threshold_system(&validators, threshold, epoch);
    
    let test_data = b"secret transaction data";
    
    // Try to encrypt with wrong epoch
    let wrong_epoch = 999;
    let result = engine.encrypt(test_data, wrong_epoch);
    assert!(matches!(result, Err(ThresholdError::InvalidEpoch)));
}

#[test]
fn test_ciphertext_commitment_uniqueness() {
    let validators = setup_test_validators(4);
    let threshold = 3;
    let epoch = 0;
    
    let (_threshold_pk, engine, _private_shares) = setup_threshold_system(&validators, threshold, epoch);
    
    let data1 = b"first transaction";
    let data2 = b"second transaction";
    
    let ct1 = engine.encrypt(data1, epoch).unwrap();
    let ct2 = engine.encrypt(data2, epoch).unwrap();
    
    // Different data should produce different commitment hashes
    assert_ne!(ct1.commitment_hash(), ct2.commitment_hash());
    
    // Same ciphertext should produce same hash
    assert_eq!(ct1.commitment_hash(), ct1.commitment_hash());
}

#[test]
fn test_share_validation() {
    let validators = setup_test_validators(4);
    let threshold = 3;
    let epoch = 0;
    
    let (_threshold_pk, engine, _private_shares) = setup_threshold_system(&validators, threshold, epoch);
    
    let test_data = b"secret transaction data";
    let ciphertext = engine.encrypt(test_data, epoch).unwrap();
    
    // Generate a valid share
    let valid_share = engine.generate_share(&ciphertext, validators[0].id).unwrap();
    
    // Valid share should pass validation
    assert!(valid_share.verify(&ciphertext).is_ok());
    
    // Create invalid share with wrong epoch
    let mut invalid_share = valid_share.clone();
    invalid_share.epoch = 999;
    assert!(invalid_share.verify(&ciphertext).is_err());
}

#[test]
fn test_dkg_key_generation() {
    let validators = setup_test_validators(5);
    let threshold = 4; // 4-of-5 threshold
    let epoch = 1;
    
    let validator_pks: Vec<[u8; 48]> = validators.iter().map(|v| v.bls_public_key()).collect();
    
    // Generate threshold public key
    let threshold_pk = dkg::generate_threshold_public_key(&validator_pks, epoch, threshold).unwrap();
    assert_eq!(threshold_pk.epoch, epoch);
    assert_eq!(threshold_pk.threshold, threshold);
    
    // Generate private shares
    let master_seed = [123u8; 32];
    let validator_ids: Vec<_> = validators.iter().map(|v| v.id).collect();
    let private_shares = dkg::generate_private_shares(&validator_ids, &master_seed, epoch, threshold);
    
    assert_eq!(private_shares.len(), validators.len());
    
    // All shares should be distinct
    let share_values: Vec<_> = private_shares.values().collect();
    for i in 0..share_values.len() {
        for j in (i+1)..share_values.len() {
            assert_ne!(share_values[i], share_values[j]);
        }
    }
    
    // Verify share consistency
    assert!(dkg::verify_share_consistency(&threshold_pk, &private_shares).is_ok());
}

#[test]
fn test_integration_with_commit_tx() {
    let validators = setup_test_validators(3);
    let threshold = 2; // 2-of-3 threshold
    let epoch = 0;
    
    let (_threshold_pk, engine, _private_shares) = setup_threshold_system(&validators, threshold, epoch);
    
    // Create mock transaction data
    let tx_data = b"mock transaction payload";
    let encrypted_payload = engine.encrypt(tx_data, epoch).unwrap();
    
    // Create CommitTx with encrypted payload
    let commit_tx = CommitTx {
        commitment: [1u8; 32], // Mock commitment
        sender: "0x1234567890123456789012345678901234567890".to_string(),
        access_list: crate::types::AccessList { reads: vec![], writes: vec![] },
        encrypted_payload: encrypted_payload.clone(),
        pubkey: [2u8; 32],
        sig: [3u8; 64],
    };
    
    // Verify the encrypted payload is properly embedded
    assert_eq!(commit_tx.encrypted_payload.epoch, epoch);
    assert!(!commit_tx.encrypted_payload.encrypted_data.is_empty());
    
    // Generate shares for decryption
    let mut shares = Vec::new();
    for validator in &validators[..threshold] {
        let share = engine.generate_share(&commit_tx.encrypted_payload, validator.id).unwrap();
        shares.push(share);
    }
    
    // Verify decryption works
    let decrypted = engine.decrypt(&commit_tx.encrypted_payload, &shares).unwrap();
    assert_eq!(decrypted, tx_data);
}

#[test]
fn test_integration_with_avail_tx() {
    let validators = setup_test_validators(3);
    let threshold = 2;
    let epoch = 0;
    
    let (_threshold_pk, engine, _private_shares) = setup_threshold_system(&validators, threshold, epoch);
    
    let tx_data = b"availability transaction data";
    let encrypted_payload = engine.encrypt(tx_data, epoch).unwrap();
    let payload_hash = encrypted_payload.commitment_hash();
    
    // Create AvailTx with payload reference
    let avail_tx = AvailTx {
        commitment: [4u8; 32], // Mock commitment hash
        sender: "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd".to_string(),
        payload_hash,
        payload_size: encrypted_payload.size() as u64,
        pubkey: [5u8; 32],
        sig: [6u8; 64],
    };
    
    // Verify payload hash matches
    assert_eq!(avail_tx.payload_hash, payload_hash);
    assert!(avail_tx.payload_size > 0);
}

#[test]
fn test_byzantine_fault_tolerance() {
    let validators = setup_test_validators(7); // 7 validators
    let threshold = 5; // Need 5 shares (can tolerate 2 Byzantine faults)
    let epoch = 0;
    
    let (_threshold_pk, engine, _private_shares) = setup_threshold_system(&validators, threshold, epoch);
    
    let test_data = b"byzantine fault tolerance test";
    let ciphertext = engine.encrypt(test_data, epoch).unwrap();
    
    // Generate shares from exactly the threshold number of validators
    let mut shares = Vec::new();
    for validator in &validators[..threshold] {
        let share = engine.generate_share(&ciphertext, validator.id).unwrap();
        shares.push(share);
    }
    
    // Should succeed with exactly threshold shares
    let decrypted = engine.decrypt(&ciphertext, &shares).unwrap();
    assert_eq!(decrypted, test_data);
    
    // Test with more than threshold (should still work)
    let mut extra_shares = shares.clone();
    for validator in &validators[threshold..threshold+1] {
        let share = engine.generate_share(&ciphertext, validator.id).unwrap();
        extra_shares.push(share);
    }
    
    let decrypted_extra = engine.decrypt(&ciphertext, &extra_shares).unwrap();
    assert_eq!(decrypted_extra, test_data);
}

#[test]
fn test_multiple_epochs() {
    let validators = setup_test_validators(4);
    let threshold = 3;
    
    // Test with different epochs
    for epoch in 0..3 {
        let (_threshold_pk, engine, _private_shares) = setup_threshold_system(&validators, threshold, epoch);
        
        let test_data = format!("epoch {} test data", epoch).into_bytes();
        let ciphertext = engine.encrypt(&test_data, epoch).unwrap();
        
        assert_eq!(ciphertext.epoch, epoch);
        
        // Generate shares for this epoch
        let mut shares = Vec::new();
        for validator in &validators[..threshold] {
            let share = engine.generate_share(&ciphertext, validator.id).unwrap();
            assert_eq!(share.epoch, epoch);
            shares.push(share);
        }
        
        let decrypted = engine.decrypt(&ciphertext, &shares).unwrap();
        assert_eq!(decrypted, test_data);
    }
}

#[test]
fn test_large_transaction_data() {
    let validators = setup_test_validators(4);
    let threshold = 3;
    let epoch = 0;
    
    let (_threshold_pk, engine, _private_shares) = setup_threshold_system(&validators, threshold, epoch);
    
    // Test with large transaction data (64KB)
    let large_data: Vec<u8> = (0..65536).map(|i| (i % 256) as u8).collect();
    
    let ciphertext = engine.encrypt(&large_data, epoch).unwrap();
    assert!(ciphertext.size() > 65536); // Should be larger due to encryption overhead
    
    let mut shares = Vec::new();
    for validator in &validators[..threshold] {
        let share = engine.generate_share(&ciphertext, validator.id).unwrap();
        shares.push(share);
    }
    
    let decrypted = engine.decrypt(&ciphertext, &shares).unwrap();
    assert_eq!(decrypted, large_data);
}

#[test]
fn test_malformed_public_key_rejected() {
    let validators = setup_test_validators(1);
    let mut validator_pks: Vec<[u8; 48]> =
        validators.iter().map(|v| v.bls_public_key()).collect();

    // Push malformed key bytes that are not a valid BLS12-381 point
    validator_pks.push([0u8; 48]);

    let result = dkg::generate_threshold_public_key(&validator_pks, 0, 1);
    assert!(matches!(result, Err(ThresholdError::InvalidPublicKey)));
}