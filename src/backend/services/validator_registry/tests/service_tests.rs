use anyhow::Result;
use mockall::predicate::*;
use mockall::mock;
use sp_core::{H256, sr25519, Pair};
use std::sync::Arc;

use validator_registry::{
    models::{
        validator::{ValidatorEscrow, EscrowStatus, PerformanceProof, SlashableOffense},
        subnet::{SubnetAssignment, SubnetRotation, ValidatorSubnetProof},
        reward::{RewardClaim, ValidatorReward, RewardDistribution},
    },
    services::{
        validator_service::ValidatorService,
        subnet_service::SubnetService,
        reward_service::RewardService,
    },
    repositories::traits::*,
};

// Mock repositories
mock! {
    pub ValidatorRepo {}
    #[async_trait]
    impl ValidatorRepository for ValidatorRepo {
        async fn store_validator(&self, escrow: ValidatorEscrow) -> Result<()>;
        async fn get_validator(&self, validator_id: H256) -> Result<Option<ValidatorEscrow>>;
        async fn update_validator_status(&self, validator_id: H256, status: EscrowStatus) -> Result<()>;
        async fn list_active_validators(&self) -> Result<Vec<ValidatorEscrow>>;
    }
}

mock! {
    pub SubnetRepo {}
    #[async_trait]
    impl SubnetRepository for SubnetRepo {
        async fn store_subnet_assignments(&self, assignments: Vec<SubnetAssignment>) -> Result<()>;
        async fn get_subnet_assignments(&self, epoch: u32) -> Result<Vec<SubnetAssignment>>;
        async fn store_subnet_rotation(&self, rotation: SubnetRotation) -> Result<()>;
        async fn get_latest_rotation(&self) -> Result<Option<SubnetRotation>>;
        async fn get_validator_subnet(&self, validator_id: H256, epoch: u32) -> Result<Option<u32>>;
    }
}

mock! {
    pub RewardRepo {}
    #[async_trait]
    impl RewardRepository for RewardRepo {
        async fn store_reward(&self, reward: ValidatorReward) -> Result<()>;
        async fn get_validator_rewards(&self, validator_id: H256, epoch: u32) -> Result<Vec<ValidatorReward>>;
        async fn store_distribution(&self, distribution: RewardDistribution) -> Result<()>;
        async fn get_epoch_distribution(&self, epoch: u32) -> Result<Option<RewardDistribution>>;
        async fn list_pending_rewards(&self, epoch: u32) -> Result<Vec<ValidatorReward>>;
    }
}

// Test helpers
fn generate_test_validator() -> ValidatorEscrow {
    let (pair, _) = sr25519::Pair::generate();
    let public = pair.public();
    
    ValidatorEscrow {
        validator_id: H256::random(),
        public_key: public.as_ref().to_vec(),
        escrow_address: [0u8; 32],
        timelock_height: 100,
        status: EscrowStatus::Active,
    }
}

#[tokio::test]
async fn test_validator_registration() -> Result<()> {
    // Setup mock repository
    let mut mock_repo = MockValidatorRepo::new();
    
    // Expect store_validator to be called once
    mock_repo.expect_store_validator()
        .times(1)
        .returning(|_| Ok(()));
    
    // Create service with mock repository
    let service = ValidatorService::new(Arc::new(mock_repo));
    
    // Test data
    let (pair, _) = sr25519::Pair::generate();
    let public_key = pair.public().as_ref().to_vec();
    let proof_of_escrow = vec![1, 2, 3, 4]; // Mock proof
    
    // Call service method
    let result = service.register_validator(public_key, proof_of_escrow).await;
    
    // Verify result
    assert!(result.is_ok());
    
    Ok(())
}

#[tokio::test]
async fn test_subnet_rotation() -> Result<()> {
    // Setup mock repositories
    let mut mock_subnet_repo = MockSubnetRepo::new();
    
    // Expect get_current_assignments to be called once
    mock_subnet_repo.expect_get_subnet_assignments()
        .times(1)
        .returning(|_| Ok(vec![]));
    
    // Expect store_subnet_assignments to be called once
    mock_subnet_repo.expect_store_subnet_assignments()
        .times(1)
        .returning(|_| Ok(()));
    
    // Expect store_subnet_rotation to be called once
    mock_subnet_repo.expect_store_subnet_rotation()
        .times(1)
        .returning(|_| Ok(()));
    
    // Create service with mock repository
    let service = SubnetService::new(Arc::new(mock_subnet_repo));
    
    // Test data
    let current_epoch = 14400; // Should trigger rotation
    
    // Call service method
    let result = service.rotate_subnets(current_epoch).await;
    
    // Verify result
    assert!(result.is_ok());
    let rotation = result.unwrap();
    assert!(rotation.is_some());
    
    Ok(())
}

#[tokio::test]
async fn test_reward_distribution() -> Result<()> {
    // Setup mock repositories
    let mut mock_reward_repo = MockRewardRepo::new();
    
    // Expect list_pending_rewards to be called once
    let validator_id = H256::random();
    let reward = ValidatorReward {
        validator_id,
        amount: 1_000_000_000,
        performance_score: 9800,
        epoch: 1,
    };
    
    mock_reward_repo.expect_list_pending_rewards()
        .times(1)
        .returning(move |_| Ok(vec![reward.clone()]));
    
    // Expect store_distribution to be called once
    mock_reward_repo.expect_store_distribution()
        .times(1)
        .returning(|_| Ok(()));
    
    // Create service with mock repository
    let service = RewardService::new(Arc::new(mock_reward_repo));
    
    // Test data
    let epoch = 1;
    
    // Call service method
    let result = service.distribute_epoch_rewards(epoch).await;
    
    // Verify result
    assert!(result.is_ok());
    let distribution = result.unwrap();
    assert_eq!(distribution.epoch, epoch);
    assert_eq!(distribution.total_reward, 1_000_000_000);
    assert_eq!(distribution.distributions.len(), 1);
    
    Ok(())
}
