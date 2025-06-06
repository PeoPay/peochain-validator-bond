use anyhow::{Result, anyhow, Context};
use sp_core::{
    crypto::{AccountId32 as AccountId, Pair, Public, Ss58Codec},
    sr25519,
    H256,
};
use sp_runtime::traits::Verify;
use crate::models::validator::{ValidatorEscrow, EscrowStatus, PerformanceProof, SlashableOffense};
use std::{convert::TryFrom, time::Duration};
use tokio::{
    sync::mpsc,
    task::{self, JoinHandle},
    time::timeout,
};
use tracing::{info_span, Instrument, warn};
use async_trait::async_trait;

// Timeout constants
const DB_OPERATION_TIMEOUT: Duration = Duration::from_secs(5);
const CPU_TASK_TIMEOUT: Duration = Duration::from_secs(10);

#[async_trait]
pub trait ValidatorStore: Send + Sync + 'static {
    async fn store_validator(&self, escrow: ValidatorEscrow) -> Result<()>;
    async fn get_validator_public_key(&self, validator_id: H256) -> Result<sr25519::Public>;
    async fn get_subnet_validator_count(&self, subnet_id: u32) -> Result<usize>;
    async fn is_validator_in_subnet(&self, validator_id: H256, subnet_id: u32) -> Result<bool>;
    async fn execute_escrow_slash(&self, validator_id: H256, amount: u128) -> Result<()>;
}

// CPU-bound operations that can be offloaded to a blocking task
struct CpuIntensiveTasks;

pub struct ValidatorService<S> {
    store: S,
    cpu_task_tx: mpsc::Sender<CpuTask>,
}

type CpuTaskResult = Result<Vec<u8>>;
type CpuTask = Box<dyn FnOnce() -> CpuTaskResult + Send + 'static>;

impl<S> ValidatorService<S>
where
    S: ValidatorStore + Clone + 'static,
{

impl CpuIntensiveTasks {
    fn verify_escrow_proof(proof: &[u8], public_key: &[u8]) -> Result<bool> {
        // Proof format: signature over (public_key) using sr25519
        if proof.len() != 64 {
            return Ok(false);
        }

        let signature = sr25519::Signature::from_slice(proof);
        let pubkey = sr25519::Public::try_from(public_key)
            .map_err(|e| anyhow!("Invalid public key: {}", e))?;
        Ok(sp_io::crypto::sr25519_verify(&signature, public_key, &pubkey))
    }
    
    fn generate_validator_id(public_key: &[u8]) -> H256 {
        // Implementation of CPU-intensive ID generation
        sp_core::hashing::blake2_256(public_key).into()
    }
    
    fn derive_escrow_address(proof: &[u8]) -> Result<AccountId> {
        // Implementation of CPU-intensive address derivation
        // ...
        Ok(AccountId::from(sp_core::hashing::blake2_256(proof)))
    }
    
    fn is_valid_block_range(range: (u32, u32)) -> bool {
        // Implementation of CPU-intensive range validation
        range.0 < range.1 && (range.1 - range.0) <= 1000
    }
    
    fn get_equivocation_slash_amount() -> u128 {
        // Implementation of slash amount calculation
        1000
    }
    
    fn get_invalid_attestation_slash_amount() -> u128 {
        // Implementation of slash amount calculation
        500
    }
}

impl<S> ValidatorService<S>
where
    S: ValidatorStore + Clone + 'static,
{
    pub async fn register_validator(
        &self,
        public_key: Vec<u8>,
        proof_of_escrow: Vec<u8>,
    ) -> Result<H256> {
        let span = info_span!("register_validator");
        async move {
            // Offload CPU-intensive proof verification to a blocking task
            let is_valid = self.offload_cpu_task(move || {
                CpuIntensiveTasks::verify_escrow_proof(&proof_of_escrow, &public_key)
            })
            .await??;

            if !is_valid {
                return Err(anyhow!("Invalid escrow proof"));
            }
            
            // Generate deterministic validator ID (CPU-bound)
            let validator_id = self.offload_cpu_task(move || {
                Ok(CpuIntensiveTasks::generate_validator_id(&public_key))
            })
            .await??;
            
            // Derive escrow address (CPU-bound)
            let escrow_address = self.offload_cpu_task(move || {
                CpuIntensiveTasks::derive_escrow_address(&proof_of_escrow)
            })
            .await??;
            
            // Create escrow instance - no funds transferred
            let escrow = ValidatorEscrow {
                validator_id,
                public_key,
                escrow_address,
                timelock_height: self.get_current_block() + self.get_timelock_period(),
                status: EscrowStatus::Active,
            };
            
            // Store validator with timeout
            timeout(DB_OPERATION_TIMEOUT, self.store.store_validator(escrow))
                .await??;
            
            Ok(validator_id)
        }
        .instrument(span)
        .await
    }

    pub async fn verify_performance(
        &self,
        proof: PerformanceProof,
    ) -> Result<bool> {
        let span = info_span!("verify_performance", validator_id = ?proof.validator_id);
        async move {
            // Fast path: validate block range (CPU-bound)
            if !CpuIntensiveTasks::is_valid_block_range(proof.block_range) {
                return Ok(false);
            }

            // Check validator in subnet with timeout
            let is_in_subnet = timeout(
                DB_OPERATION_TIMEOUT,
                self.store.is_validator_in_subnet(proof.validator_id, proof.subnet_id),
            )
            .await??;

            if !is_in_subnet {
                return Ok(false);
            }

            // Offload CPU-intensive signature verification
            let signatures_valid = self.verify_participation_signatures(&proof).await?;
            if !signatures_valid {
                return Ok(false);
            }

            // Verify merkle inclusion with timeout
            let merkle_valid = timeout(
                DB_OPERATION_TIMEOUT,
                self.verify_merkle_inclusion(&proof.merkle_proof, proof.subnet_id, proof.block_range),
            )
            .await??;

            Ok(merkle_valid)
        }
        .instrument(span)
        .await
    }

    pub async fn process_slashing(
        &self,
        validator_id: H256,
        offense: SlashableOffense,
    ) -> Result<()> {
        let span = info_span!("process_slashing", validator_id = ?validator_id);
        async move {
            // Verify slashing evidence with timeout
            timeout(
                CPU_TASK_TIMEOUT,
                self.verify_slashing_evidence(validator_id, &offense),
            )
            .await??;

            // Calculate slash amount (CPU-bound)
            let slash_amount = self.offload_cpu_task(move || {
                Ok(match &offense {
                    SlashableOffense::Equivocation { .. } => CpuIntensiveTasks::get_equivocation_slash_amount(),
                    SlashableOffense::InvalidAttestation { .. } => CpuIntensiveTasks::get_invalid_attestation_slash_amount(),
                })
            })
            .await??;

            // Execute slashing with timeout
            timeout(
                DB_OPERATION_TIMEOUT,
                self.store.execute_escrow_slash(validator_id, slash_amount),
            )
            .await??;

            Ok(())
        }
        .instrument(span)
        .await
    }
    
    /// Verify cryptographic evidence for slashing
    async fn offload_cpu_task<T: Send + 'static, F: FnOnce() -> Result<T> + Send + 'static>(
        &self,
        task: F,
    ) -> Result<T> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        
        // Send the task to the CPU worker
        self.cpu_task_tx
            .send(Box::new(move || {
                let result = task();
                let _ = tx.send(result);
            }))
            .await
            .map_err(|_| anyhow!("Failed to send CPU task"))?;
            
        // Wait for the result with a timeout
        match timeout(CPU_TASK_TIMEOUT, rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(anyhow!("CPU task failed to return result")),
            Err(_) => Err(anyhow!("CPU task timed out")),
        }
    }
    
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
        // Get total validators count with timeout
        let total_validators = timeout(
            DB_OPERATION_TIMEOUT,
            self.store.get_subnet_validator_count(proof.subnet_id),
        )
        .await??;
        
        // Early return if not enough signatures
        let required_signatures = (total_validators * 2 + 2) / 3;
        if proof.subnet_signatures.len() < required_signatures {
            return Ok(false);
        }

        // Prepare message for signature verification (CPU-bound)
        let message = self.offload_cpu_task({
            let validator_id = proof.validator_id;
            let subnet_id = proof.subnet_id;
            let block_range = proof.block_range;
            
            move || {
                let mut message = Vec::new();
                message.extend_from_slice(&validator_id.as_bytes());
                message.extend_from_slice(&subnet_id.to_be_bytes());
                message.extend_from_slice(&block_range.0.to_be_bytes());
                message.extend_from_slice(&block_range.1.to_be_bytes());
                Ok(message)
            }
        })
        .await??;

        // Process signatures in parallel
        let mut tasks = Vec::with_capacity(proof.subnet_signatures.len());
        
        for (validator_id, signature_bytes) in &proof.subnet_signatures {
            let store = self.store.clone();
            let validator_id = *validator_id;
            let signature_bytes = signature_bytes.clone();
            let message = message.clone();
            
            let task = tokio::spawn(async move {
                // Get public key with timeout
                let public_key = timeout(
                    DB_OPERATION_TIMEOUT,
                    store.get_validator_public_key(validator_id)
                ).await??;
                
                // Verify signature (CPU-bound)
                let is_valid = task::spawn_blocking(move || {
                    let signature = sr25519::Signature::try_from(signature_bytes.as_slice())
                        .map_err(|e| anyhow!("Invalid signature format: {}", e))?;
                        
                    Ok(sp_io::crypto::sr25519_verify(
                        &signature,
                        &message,
                        &public_key,
                    ))
                })
                .await??;
                
                Ok::<_, anyhow::Error>(is_valid)
            });
            
            tasks.push(task);
        }
        
        // Wait for all tasks to complete and count valid signatures
        let mut valid_signatures = 0;
        for task in tasks {
            match task.await {
                Ok(Ok(true)) => valid_signatures += 1,
                Ok(Ok(false)) => {}
                Ok(Err(e)) => warn!("Error verifying signature: {}", e),
                Err(e) => warn!("Task panicked: {}", e),
            }
            
            // Early exit if we have enough valid signatures
            if valid_signatures >= required_signatures {
                return Ok(true);
            }
        }
        
        Ok(valid_signatures >= required_signatures)
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
        // In this simplified example we derive an address by hashing the proof
        Ok(AccountId::from(sp_core::hashing::blake2_256(proof)))
    }
}
