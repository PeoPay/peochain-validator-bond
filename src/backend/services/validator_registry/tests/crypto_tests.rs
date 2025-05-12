use sp_core::{sr25519, Pair, H256};
use crate::utils::crypto::CryptoUtils;

#[test]
fn test_signature_verification() {
    let (pair, _) = sr25519::Pair::generate();
    let public = pair.public();
    let message = b"test message";
    let signature = pair.sign(message);

    let result = CryptoUtils::verify_signature(
        public.as_ref(),
        message,
        signature.as_ref(),
    ).unwrap();

    assert!(result);
}

#[test]
fn test_merkle_proof() {
    // Create a simple Merkle tree
    let leaf1: H256 = sp_core::blake2_256(b"leaf1").into();
    let leaf2: H256 = sp_core::blake2_256(b"leaf2").into();
    let leaf3: H256 = sp_core::blake2_256(b"leaf3").into();
    let leaf4: H256 = sp_core::blake2_256(b"leaf4").into();

    let hash12 = CryptoUtils::hash_pair(&leaf1, &leaf2);
    let hash34 = CryptoUtils::hash_pair(&leaf3, &leaf4);
    let root = CryptoUtils::hash_pair(&hash12, &hash34);

    // Create and verify proof for leaf1
    let proof = vec![leaf2, hash34];
    let result = CryptoUtils::verify_merkle_proof(
        root,
        &proof,
        leaf1,
    ).unwrap();

    assert!(result);
}

#[test]
fn test_escrow_address_derivation() {
    let (pair, _) = sr25519::Pair::generate();
    let public = pair.public();
    let nonce = 1u32;

    let address = CryptoUtils::derive_escrow_address(
        public.as_ref(),
        nonce,
    ).unwrap();

    assert_eq!(address.len(), 32);
}
