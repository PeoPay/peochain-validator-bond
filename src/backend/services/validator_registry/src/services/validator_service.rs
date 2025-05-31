use anyhow::{Result, anyhow, Context};
use sp_core::{
    crypto::{AccountId32 as AccountId, Pair, Public, Ss58Codec},
    sr25519,
    H256,
};
use sp_runtime::traits::Verify;
use crate::models::validator::{ValidatorEscrow, EscrowStatus, PerformanceProof, SlashableOffense};
use std::convert::TryFrom;

pub struct ValidatorService {
    // Dependencies will be injected
}

impl ValidatorService {
    pub async fn register_validator(
        &self,
        public_key: Vec<u8>,
        proof_of_escrow: Vec<u8>,
    ) -> Result<H256> {
        // Validate escrow cryptographically - no human judgment
        self.verify_escrow_proof(&proof_of_escrow, &public_key)?;
        
        // Generate deterministic validator ID
        let validator_id = self.generate_validator_id(&public_key);
        
        // Create escrow instance - no funds transferred
        let escrow = ValidatorEscrow {
            validator_id,
            public_key,
            escrow_address: self.derive_escrow_address(&proof_of_escrow)?,
            timelock_height: self.get_current_block() + self.get_timelock_period(),
            status: EscrowStatus::Active,
        };
        
        // Store validator - no approval queue
        self.store_validator(escrow).await?;
        
        Ok(validator_id)
    }

    pub async fn verify_performance(
        &self,
        proof: &PerformanceProof,
    ) -> Result<bool> {
        // Pure cryptographic verification
        if !self.is_valid_block_range(proof.block_range) {
            return Ok(false);
        }

        if !self.is_validator_in_subnet(proof.validator_id, proof.subnet_id).await? {
            return Ok(false);
        }

        if !self.verify_participation_signatures(proof).await? {
            return Ok(false);
        }

        Ok(self.verify_merkle_inclusion(&proof.merkle_proof, proof.subnet_id, proof.block_range).await?)
    }

    pub async fn process_slashing(
        &self,
        validator_id: H256,
        offense: SlashableOffense,
    ) -> Result<()> {
        // Verify slashing evidence cryptographically
        self.verify_slashing_evidence(validator_id, &offense).await?;

        // Calculate slash amount algorithmically - no discretion
        let slash_amount = match &offense {
            SlashableOffense::Equivocation { .. } => self.get_equivocation_slash_amount(),
            SlashableOffense::InvalidAttestation { .. } => self.get_invalid_attestation_slash_amount(),
        };

        // Execute slashing against escrow
        self.execute_escrow_slash(validator_id, slash_amount).await?;

        Ok(())
    }
    
    /// Verify cryptographic evidence for slashing
    async fn verify_slashing_evidence(&self, validator_id: H256, offense: &SlashableOffense) -> Result<()> {
        // Get the validator's public key
        let validator_public_key = self.get_validator_public_key(validator_id).await?;
        
        match offense {
            SlashableOffense::Equivocation { 
                block_number, 
                first_signature, 
                second_signature 
            } => {
                // For equivocation, we need to verify both signatures are from the same validator
                // but for different blocks at the same height
                let first_message = format!("block:{}:first", block_number).into_bytes();
                let second_message = format!("block:{}:second", block_number).into_bytes();
                
                let first_sig = sr25519::Signature::try_from(first_signature.as_slice())
                    .map_err(|e| anyhow!("Invalid first signature format: {}", e))?;
                    
                let second_sig = sr25519::Signature::try_from(second_signature.as_slice())
                    .map_err(|e| anyhow!("Invalid second signature format: {}", e))?;
                
                // Verify both signatures are valid and from the same validator
                let first_valid = sp_io::crypto::sr25519_verify(
                    &first_sig,
                    &first_message,
                    &validator_public_key,
                );
                
                let second_valid = sp_io::crypto::sr25519_verify(
                    &second_sig,
                    &second_message,
                    &validator_public_key,
                );
                
                if !first_valid || !second_valid {
                    return Err(anyhow!("Invalid signatures in equivocation proof"));
                }
                
                Ok(())
            },
            SlashableOffense::InvalidAttestation { 
                block_number, 
                invalid_hash, 
                correct_hash, 
                signature 
            } => {
                // For invalid attestation, verify the signature is valid but the content is incorrect
                // The message should be the block number and the invalid hash
                let mut message = block_number.to_be_bytes().to_vec();
                message.extend_from_slice(invalid_hash.as_bytes());
                
                let sig = sr25519::Signature::try_from(signature.as_slice())
                    .map_err(|e| anyhow!("Invalid signature format: {}", e))?;
                
                // Verify the signature is valid
                if !sp_io::crypto::sr25519_verify(
                    &sig,
                    &message,
                    &validator_public_key,
                ) {
                    return Err(anyhow!("Invalid signature in attestation proof"));
                }
                
                // Verify the hash is actually incorrect
                let expected_message = {
                    let mut m = block_number.to_be_bytes().to_vec();
                    m.extend_from_slice(correct_hash.as_bytes());
                    m
                };
                
                // The signature should not verify against the correct message
                let is_double_signing = sp_io::crypto::sr25519_verify(
                    &sig,
                    &expected_message,
                    &validator_public_key,
                );
                
                if is_double_signing {
                    return Err(anyhow!("Signature is valid for correct hash"));
                }
                
                Ok(())
            },
        }
    }

    /// Verify the participation signatures in the performance proof
    async fn verify_participation_signatures(&self, proof: &PerformanceProof) -> Result<bool> {
        // The message is a combination of validator_id, subnet_id, and block_range
        let mut message = Vec::new();
        message.extend_from_slice(&proof.validator_id.as_bytes());
        message.extend_from_slice(&proof.subnet_id.to_be_bytes());
        message.extend_from_slice(&proof.block_range.0.to_be_bytes());
        message.extend_from_slice(&proof.block_range.1.to_be_bytes());
        
        // Verify each signature from the subnet validators
        for (validator_id, signature_bytes) in &proof.subnet_signatures {
            // Get the validator's public key from storage
            let validator_public_key = self.get_validator_public_key(*validator_id).await?;
            
            // Parse the signature
            let signature = sr25519::Signature::try_from(signature_bytes.as_slice())
                .map_err(|e| anyhow!("Invalid signature format: {}", e))?;
                
            // Verify the signature
            if !sp_io::crypto::sr25519_verify(
                &signature,
                &message,
                &validator_public_key,
            ) {
                return Ok(false);
            }
        }
        
        // Verify we have enough signatures (at least 2/3 of the subnet)
        let total_validators = self.get_subnet_validator_count(proof.subnet_id).await?;
        let required_signatures = (total_validators * 2 + 2) / 3; // 2/3 rounded up
        
        Ok(proof.subnet_signatures.len() >= required_signatures)
    }

    fn generate_validator_id(&self, public_key: &[u8]) -> H256 {
        // Create a deterministic ID by hashing the public key
        let mut hasher = sp_core::hashing::blake2_256::Hasher::new();
        hasher.update(b"validator_id:");
        hasher.update(public_key);
        H256::from_slice(&hasher.finalize())
    }

    async fn store_validator(&self, escrow: ValidatorEscrow) -> Result<()> {
        // In a real implementation, this would store to a database
        // For now, we'll just log the validator registration
        tracing::info!(
            "Registering validator {} with escrow at {}",
            hex::encode(&escrow.validator_id),
            escrow.escrow_address.to_ss58check()
        );
        Ok(())
    }
    
    fn derive_escrow_address(&self, proof: &[u8]) -> Result<AccountId> {
        // Derive an SS58 address from the proof (which should be a signature)
        // In a real implementation, this would use a key derivation function
        let hash = sp_core::hashing::blake2_256(proof);
        let public = sr25519::Public::from_raw(hash);
        Ok(AccountId::from(public))
    }
    
    // Helper methods that would be implemented in a real system
    async fn get_validator_public_key(&self, validator_id: H256) -> Result<sr25519::Public> {
        // In a real implementation, this would fetch from storage
        // For now, we'll return a dummy public key
        Ok(sr25519::Public::from_raw([0u8; 32]))
    }
    
    async fn get_subnet_validator_count(&self, subnet_id: u32) -> Result<usize> {
        // In a real implementation, this would query the subnet state
        Ok(10) // Dummy value
    }
    
    fn is_valid_block_range(&self, _range: (u32, u32)) -> bool {
        // In a real implementation, this would check against the current block height
        true
    }
    
    async fn is_validator_in_subnet(&self, _validator_id: H256, _subnet_id: u32) -> Result<bool> {
        // In a real implementation, this would check the validator's subnet membership
        Ok(true)
    }
    
    async fn verify_merkle_inclusion(&self, _proof: &[H256], _subnet_id: u32, _range: (u32, u32)) -> Result<bool> {
        // In a real implementation, this would verify the Merkle proof
        Ok(true)
    }
    
    fn get_equivocation_slash_amount(&self) -> u128 {
        // In a real implementation, this would return the configured slash amount
        1000 // Dummy value
    }
    
    fn get_invalid_attestation_slash_amount(&self) -> u128 {
        // In a real implementation, this would return the configured slash amount
        500 // Dummy value
    }
    
    async fn execute_escrow_slash(&self, _validator_id: H256, _amount: u128) -> Result<()> {
        // In a real implementation, this would execute the slash on the escrow contract
        Ok(())
    }

    // Private helper methods
    async fn verify_escrow_proof(&self, proof: &[u8], public_key: &[u8]) -> Result<bool> {
        // The proof should be a signature of the public key by the escrow account
        // The message format is: b"escrow_proof:" + public_key
        let mut message = b"escrow_proof:".to_vec();
        message.extend_from_slice(public_key);
        
        // Try to parse the public key
        let pubkey = sr25519::Public::try_from(public_key)
            .map_err(|e| anyhow::anyhow!("Invalid public key: {}", e))?;
            
        // The proof should be a valid signature
        let signature = sr25519::Signature::try_from(proof)
            .map_err(|e| anyhow::anyhow!("Invalid signature format: {}", e))?;
            
        // Verify the signature
        Ok(sp_io::crypto::sr25519_verify(
            &signature,
            &message,
            &pubkey,
        ))
    }
}
