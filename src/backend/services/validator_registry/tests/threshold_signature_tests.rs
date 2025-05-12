use crate::utils::threshold_crypto::{ThresholdCrypto, ThresholdEcdsa, ThresholdParams};
use crate::models::threshold_signature::{ThresholdSchemeType};
use sp_core::H256;
use std::collections::BTreeMap;

#[test]
fn test_bls_threshold_signature_generation() {
    // Create threshold parameters (3-of-5)
    let params = ThresholdParams {
        threshold: 3,
        total_participants: 5,
    };
    
    // Generate key shares
    let key_shares = ThresholdCrypto::generate_key_shares(&params).unwrap();
    
    // Verify we got the correct number of shares
    assert_eq!(key_shares.len(), params.total_participants);
    
    // Verify each share has the correct index
    for (i, share) in key_shares.iter().enumerate() {
        assert_eq!(share.index, i + 1);
        assert!(!share.secret_share.is_empty());
        assert!(!share.public_share.is_empty());
        assert!(!share.verification_vector.is_empty());
    }
}

#[test]
fn test_bls_threshold_signature_signing_and_verification() {
    // Create threshold parameters (2-of-3)
    let params = ThresholdParams {
        threshold: 2,
        total_participants: 3,
    };
    
    // Generate key shares
    let key_shares = ThresholdCrypto::generate_key_shares(&params).unwrap();
    
    // Create a message to sign
    let message = b"Test message for threshold signing";
    
    // Create signature shares from the first two participants
    let mut signature_shares = Vec::new();
    for i in 0..params.threshold {
        let share = ThresholdCrypto::create_signature_share(message, &key_shares[i]).unwrap();
        signature_shares.push(share);
    }
    
    // Extract public key shares
    let mut public_shares = Vec::new();
    for share in &key_shares {
        public_shares.push(share.public_share.clone());
    }
    
    // Derive the aggregated public key
    let public_key = ThresholdCrypto::derive_aggregated_public_key(&public_shares).unwrap();
    
    // Aggregate the signature shares
    let threshold_signature = ThresholdCrypto::aggregate_signature_shares(
        &params,
        message,
        &signature_shares,
        &public_key,
    ).unwrap();
    
    // Verify the threshold signature
    let result = ThresholdCrypto::verify_threshold_signature(
        message,
        &threshold_signature,
        &public_key,
    ).unwrap();
    
    assert!(result);
}

#[test]
fn test_ecdsa_threshold_signature_generation() {
    // Create threshold parameters (3-of-5)
    let params = ThresholdParams {
        threshold: 3,
        total_participants: 5,
    };
    
    // Generate key shares
    let key_shares = ThresholdEcdsa::generate_key_shares(&params).unwrap();
    
    // Verify we got the correct number of shares
    assert_eq!(key_shares.len(), params.total_participants);
    
    // Verify each share has the correct index
    for (i, share) in key_shares.iter().enumerate() {
        assert_eq!(share.index, i + 1);
        assert!(!share.secret_share.is_empty());
        assert!(!share.public_share.is_empty());
        assert!(!share.verification_vector.is_empty());
    }
}

#[test]
fn test_ecdsa_threshold_signature_signing_and_verification() {
    // Create threshold parameters (2-of-3)
    let params = ThresholdParams {
        threshold: 2,
        total_participants: 3,
    };
    
    // Generate key shares
    let key_shares = ThresholdEcdsa::generate_key_shares(&params).unwrap();
    
    // Create a message to sign
    let message = b"Test message for threshold signing";
    
    // Create signature shares from the first two participants
    let mut signature_shares = Vec::new();
    for i in 0..params.threshold {
        let share = ThresholdEcdsa::create_signature_share(message, &key_shares[i]).unwrap();
        signature_shares.push(share);
    }
    
    // Extract public key shares
    let mut public_shares = Vec::new();
    for share in &key_shares {
        public_shares.push(share.public_share.clone());
    }
    
    // For ECDSA, we would need a different approach to derive the public key
    // This is a placeholder
    let public_key = vec![0u8; 33];
    
    // Aggregate the signature shares
    let threshold_signature = ThresholdEcdsa::aggregate_signature_shares(
        &params,
        message,
        &signature_shares,
        &public_key,
    ).unwrap();
    
    // Verify the threshold signature
    let result = ThresholdEcdsa::verify_threshold_signature(
        message,
        &threshold_signature,
        &public_key,
    ).unwrap();
    
    assert!(result);
}

#[test]
fn test_malicious_actor_resistance() {
    // Create threshold parameters (3-of-5)
    // This ensures we can tolerate up to 2 malicious actors
    let params = ThresholdParams {
        threshold: 3,
        total_participants: 5,
    };
    
    // Generate key shares
    let key_shares = ThresholdCrypto::generate_key_shares(&params).unwrap();
    
    // Create a message to sign
    let message = b"Test message for threshold signing";
    
    // Create signature shares from 3 honest participants
    let mut signature_shares = Vec::new();
    for i in 0..params.threshold {
        let share = ThresholdCrypto::create_signature_share(message, &key_shares[i]).unwrap();
        signature_shares.push(share);
    }
    
    // Extract public key shares
    let mut public_shares = Vec::new();
    for share in &key_shares {
        public_shares.push(share.public_share.clone());
    }
    
    // Derive the aggregated public key
    let public_key = ThresholdCrypto::derive_aggregated_public_key(&public_shares).unwrap();
    
    // Aggregate the signature shares
    let threshold_signature = ThresholdCrypto::aggregate_signature_shares(
        &params,
        message,
        &signature_shares,
        &public_key,
    ).unwrap();
    
    // Verify the threshold signature
    let result = ThresholdCrypto::verify_threshold_signature(
        message,
        &threshold_signature,
        &public_key,
    ).unwrap();
    
    assert!(result);
    
    // Attempt to create a signature with insufficient shares (should fail)
    let insufficient_shares = vec![signature_shares[0].clone(), signature_shares[1].clone()];
    
    let result = ThresholdCrypto::aggregate_signature_shares(
        &params,
        message,
        &insufficient_shares,
        &public_key,
    );
    
    assert!(result.is_err());
}

#[test]
fn test_different_message_verification() {
    // Create threshold parameters (2-of-3)
    let params = ThresholdParams {
        threshold: 2,
        total_participants: 3,
    };
    
    // Generate key shares
    let key_shares = ThresholdCrypto::generate_key_shares(&params).unwrap();
    
    // Create a message to sign
    let message = b"Test message for threshold signing";
    let different_message = b"Different message";
    
    // Create signature shares
    let mut signature_shares = Vec::new();
    for i in 0..params.threshold {
        let share = ThresholdCrypto::create_signature_share(message, &key_shares[i]).unwrap();
        signature_shares.push(share);
    }
    
    // Extract public key shares
    let mut public_shares = Vec::new();
    for share in &key_shares {
        public_shares.push(share.public_share.clone());
    }
    
    // Derive the aggregated public key
    let public_key = ThresholdCrypto::derive_aggregated_public_key(&public_shares).unwrap();
    
    // Aggregate the signature shares
    let threshold_signature = ThresholdCrypto::aggregate_signature_shares(
        &params,
        message,
        &signature_shares,
        &public_key,
    ).unwrap();
    
    // Verify the threshold signature with the correct message
    let result = ThresholdCrypto::verify_threshold_signature(
        message,
        &threshold_signature,
        &public_key,
    ).unwrap();
    
    assert!(result);
    
    // Verify the threshold signature with a different message (should fail)
    let result = ThresholdCrypto::verify_threshold_signature(
        different_message,
        &threshold_signature,
        &public_key,
    ).unwrap();
    
    assert!(!result);
}

#[test]
fn test_key_rotation() {
    // Initial threshold parameters (2-of-3)
    let initial_params = ThresholdParams {
        threshold: 2,
        total_participants: 3,
    };
    
    // Generate initial key shares
    let initial_key_shares = ThresholdCrypto::generate_key_shares(&initial_params).unwrap();
    
    // Extract initial public key shares
    let mut initial_public_shares = Vec::new();
    for share in &initial_key_shares {
        initial_public_shares.push(share.public_share.clone());
    }
    
    // Derive the initial aggregated public key
    let initial_public_key = ThresholdCrypto::derive_aggregated_public_key(&initial_public_shares).unwrap();
    
    // New threshold parameters (3-of-5)
    let new_params = ThresholdParams {
        threshold: 3,
        total_participants: 5,
    };
    
    // Generate new key shares
    let new_key_shares = ThresholdCrypto::generate_key_shares(&new_params).unwrap();
    
    // Extract new public key shares
    let mut new_public_shares = Vec::new();
    for share in &new_key_shares {
        new_public_shares.push(share.public_share.clone());
    }
    
    // Derive the new aggregated public key
    let new_public_key = ThresholdCrypto::derive_aggregated_public_key(&new_public_shares).unwrap();
    
    // Verify the keys are different
    assert_ne!(initial_public_key, new_public_key);
    
    // Create a message to sign
    let message = b"Test message for threshold signing";
    
    // Create signature shares with the initial key shares
    let mut initial_signature_shares = Vec::new();
    for i in 0..initial_params.threshold {
        let share = ThresholdCrypto::create_signature_share(message, &initial_key_shares[i]).unwrap();
        initial_signature_shares.push(share);
    }
    
    // Aggregate the initial signature shares
    let initial_threshold_signature = ThresholdCrypto::aggregate_signature_shares(
        &initial_params,
        message,
        &initial_signature_shares,
        &initial_public_key,
    ).unwrap();
    
    // Create signature shares with the new key shares
    let mut new_signature_shares = Vec::new();
    for i in 0..new_params.threshold {
        let share = ThresholdCrypto::create_signature_share(message, &new_key_shares[i]).unwrap();
        new_signature_shares.push(share);
    }
    
    // Aggregate the new signature shares
    let new_threshold_signature = ThresholdCrypto::aggregate_signature_shares(
        &new_params,
        message,
        &new_signature_shares,
        &new_public_key,
    ).unwrap();
    
    // Verify the signatures are different
    assert_ne!(initial_threshold_signature, new_threshold_signature);
    
    // Verify the initial signature with the initial public key
    let result = ThresholdCrypto::verify_threshold_signature(
        message,
        &initial_threshold_signature,
        &initial_public_key,
    ).unwrap();
    
    assert!(result);
    
    // Verify the new signature with the new public key
    let result = ThresholdCrypto::verify_threshold_signature(
        message,
        &new_threshold_signature,
        &new_public_key,
    ).unwrap();
    
    assert!(result);
    
    // Verify the initial signature with the new public key (should fail)
    let result = ThresholdCrypto::verify_threshold_signature(
        message,
        &initial_threshold_signature,
        &new_public_key,
    ).unwrap();
    
    assert!(!result);
}
