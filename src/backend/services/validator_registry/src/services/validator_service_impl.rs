use crate::{
    models::validator::{ValidatorEscrow, PerformanceProof, SlashableOffense},
    services::validator_service::{ValidatorService, ValidatorStore, CpuIntensiveTasks},
};
use anyhow::{Result, anyhow};
use sp_core::{sr25519, H256};
use std::sync::Arc;
use tokio::{
    sync::{mpsc, oneshot},
    task,
};
use tracing::info;

/// Implementation of the ValidatorService with async/await support
pub struct ValidatorServiceImpl<S> {
    store: S,
    cpu_worker: task::JoinHandle<()>,
    cpu_task_tx: mpsc::Sender<Box<dyn FnOnce() + Send + 'static>>,
}

impl<S> ValidatorServiceImpl<S>
where
    S: ValidatorStore + Clone + Send + 'static,
{
    /// Create a new ValidatorService with the given store
    pub fn new(store: S) -> Self {
        // Create a channel for CPU-bound tasks
        let (cpu_task_tx, mut cpu_task_rx) = mpsc::channel(32);
        
        // Spawn a CPU worker thread
        let cpu_worker = task::spawn_blocking(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Failed to build runtime for CPU worker");
                
            rt.block_on(async {
                while let Some(task) = cpu_task_rx.recv().await {
                    task();
                }
            });
        });

        Self {
            store,
            cpu_worker,
            cpu_task_tx,
        }
    }
    
    /// Get a reference to the underlying store
    pub fn store(&self) -> &S {
        &self.store
    }
}

#[async_trait::async_trait]
impl<S> ValidatorService for ValidatorServiceImpl<S>
where
    S: ValidatorStore + Clone + Send + Sync + 'static,
{
    async fn register_validator(
        &self,
        public_key: Vec<u8>,
        proof_of_escrow: Vec<u8>,
    ) -> Result<H256> {
        // Implementation from the refactored code
        let is_valid = self.offload_cpu_task(move || {
            CpuIntensiveTasks::verify_escrow_proof(&proof_of_escrow, &public_key)
        })
        .await??;

        if !is_valid {
            return Err(anyhow!("Invalid escrow proof"));
        }
        
        let validator_id = self.offload_cpu_task(move || {
            Ok(CpuIntensiveTasks::generate_validator_id(&public_key))
        })
        .await??;
        
        let escrow_address = self.offload_cpu_task(move || {
            CpuIntensiveTasks::derive_escrow_address(&proof_of_escrow)
        })
        .await??;
        
        let escrow = ValidatorEscrow {
            validator_id,
            public_key,
            escrow_address,
            timelock_height: self.get_current_block() + self.get_timelock_period(),
            status: crate::models::validator::EscrowStatus::Active,
        };
        
        self.store.store_validator(escrow).await?;
        
        Ok(validator_id)
    }
    
    // Other trait methods would be implemented here...
}

impl<S> Drop for ValidatorServiceImpl<S> {
    fn drop(&mut self) {
        // Close the CPU task channel to signal the worker to exit
        self.cpu_task_tx.close_channel();
        
        // Wait for the worker to finish
        if let Err(e) = futures::executor::block_on(async {
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                self.cpu_worker,
            )
            .await
        }) {
            tracing::error!("Failed to wait for CPU worker to finish: {:?}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use mockall::mock;
    use std::sync::Arc;
    
    mock! {
        pub TestStore {}
        
        #[async_trait]
        impl ValidatorStore for TestStore {
            async fn store_validator(&self, escrow: ValidatorEscrow) -> Result<()>;
            async fn get_validator_public_key(&self, validator_id: H256) -> Result<sr25519::Public>;
            async fn get_subnet_validator_count(&self, subnet_id: u32) -> Result<usize>;
            async fn is_validator_in_subnet(&self, validator_id: H256, subnet_id: u32) -> Result<bool>;
            async fn execute_escrow_slash(&self, validator_id: H256, amount: u128) -> Result<()>;
        }
    }
    
    #[tokio::test]
    async fn test_register_validator() {
        let mut mock_store = MockTestStore::new();
        
        // Setup mock expectations
        mock_store.expect_store_validator()
            .times(1)
            .returning(|_| Ok(()));
            
        let service = ValidatorServiceImpl::new(mock_store);
        
        // Test with dummy data
        let public_key = vec![0u8; 32];
        let proof = vec![1u8; 64];
        
        let result = service.register_validator(public_key, proof).await;
        assert!(result.is_ok());
    }
}
