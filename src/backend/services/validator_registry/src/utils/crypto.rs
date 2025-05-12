use anyhow::Result;
use sp_core::{crypto::Pair, sr25519, H256};

pub struct CryptoUtils;

impl CryptoUtils {
    pub fn verify_signature(
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        let public = sr25519::Public::from_slice(public_key)?;
        let sig = sr25519::Signature::from_slice(signature)?;
        
        Ok(public.verify(&sig, message))
    }

    pub fn verify_merkle_proof(
        root: H256,
        proof: &[H256],
        leaf: H256,
    ) -> Result<bool> {
        let mut current = leaf;
        
        for proof_element in proof {
            current = if current <= *proof_element {
                Self::hash_pair(&current, proof_element)
            } else {
                Self::hash_pair(proof_element, &current)
            };
        }
        
        Ok(current == root)
    }

    pub fn hash_pair(left: &H256, right: &H256) -> H256 {
        let mut input = Vec::with_capacity(64);
        input.extend_from_slice(left.as_bytes());
        input.extend_from_slice(right.as_bytes());
        
        sp_core::blake2_256(&input).into()
    }

    pub fn derive_escrow_address(
        public_key: &[u8],
        nonce: u32,
    ) -> Result<[u8; 32]> {
        let mut input = Vec::with_capacity(36);
        input.extend_from_slice(public_key);
        input.extend_from_slice(&nonce.to_be_bytes());
        
        Ok(sp_core::blake2_256(&input))
    }
}
