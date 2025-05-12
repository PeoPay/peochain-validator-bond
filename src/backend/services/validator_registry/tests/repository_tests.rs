use anyhow::Result;
use sp_core::{H256, sr25519, Pair};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::sync::Arc;

use validator_registry::{
    models::{
        validator::{ValidatorEscrow, EscrowStatus},
        subnet::{SubnetAssignment, SubnetRotation},
        reward::{ValidatorReward, RewardDistribution},
    },
    repositories::{
        traits::{ValidatorRepository, SubnetRepository, RewardRepository},
        postgres::{
            PostgresValidatorRepository, PostgresSubnetRepository, PostgresRewardRepository,
        },
    },
};

// Test helpers
async fn setup_test_db() -> Result<PgPool> {
    // Use a unique schema for each test run to isolate tests
    let schema_name = format!("test_{}", uuid::Uuid::new_v4().to_string().replace("-", ""));
    
    // Connect to default postgres database
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect("postgres://postgres:postgres@localhost/postgres")
        .await?;
    
    // Create schema and apply migrations
    sqlx::query(&format!("CREATE SCHEMA {}", schema_name))
        .execute(&pool)
        .await?;
    
    // Apply migrations to the test schema
    let migration_sql = include_str!("../migrations/20250512_initial_schema.sql");
    sqlx::query(&format!("SET search_path TO {}", schema_name))
        .execute(&pool)
        .await?;
    sqlx::query(migration_sql)
        .execute(&pool)
        .await?;
    
    Ok(pool)
}

async fn teardown_test_db(pool: &PgPool, schema_name: &str) -> Result<()> {
    // Drop the test schema
    sqlx::query(&format!("DROP SCHEMA {} CASCADE", schema_name))
        .execute(pool)
        .await?;
    
    Ok(())
}

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
async fn test_validator_repository() -> Result<()> {
    // Setup
    let pool = setup_test_db().await?;
    let repo = PostgresValidatorRepository::new(pool.clone());
    
    // Test data
    let validator = generate_test_validator();
    let validator_id = validator.validator_id;
    
    // Test store_validator
    repo.store_validator(validator.clone()).await?;
    
    // Test get_validator
    let retrieved = repo.get_validator(validator_id).await?;
    assert!(retrieved.is_some());
    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.validator_id, validator_id);
    assert_eq!(retrieved.public_key, validator.public_key);
    
    // Test update_validator_status
    let new_status = EscrowStatus::Withdrawing { release_height: 200 };
    repo.update_validator_status(validator_id, new_status.clone()).await?;
    
    let updated = repo.get_validator(validator_id).await?;
    assert!(updated.is_some());
    let updated = updated.unwrap();
    
    match updated.status {
        EscrowStatus::Withdrawing { release_height } => {
            assert_eq!(release_height, 200);
        },
        _ => panic!("Expected Withdrawing status"),
    }
    
    // Test list_active_validators
    // First, add another active validator
    let validator2 = generate_test_validator();
    repo.store_validator(validator2.clone()).await?;
    
    // Then add an inactive validator
    let mut validator3 = generate_test_validator();
    validator3.status = EscrowStatus::Released;
    repo.store_validator(validator3.clone()).await?;
    
    let active_validators = repo.list_active_validators().await?;
    assert_eq!(active_validators.len(), 1); // Only validator2 should be active
    
    Ok(())
}

#[tokio::test]
async fn test_subnet_repository() -> Result<()> {
    // Setup
    let pool = setup_test_db().await?;
    let repo = PostgresSubnetRepository::new(pool.clone());
    
    // Test data
    let epoch = 1;
    let subnet_id = 0;
    let validator_ids = vec![H256::random(), H256::random(), H256::random()];
    
    let assignment = SubnetAssignment {
        subnet_id,
        epoch,
        validator_set: validator_ids.clone(),
    };
    
    // Test store_subnet_assignments
    repo.store_subnet_assignments(vec![assignment.clone()]).await?;
    
    // Test get_subnet_assignments
    let assignments = repo.get_subnet_assignments(epoch).await?;
    assert_eq!(assignments.len(), 1);
    assert_eq!(assignments[0].subnet_id, subnet_id);
    assert_eq!(assignments[0].epoch, epoch);
    assert_eq!(assignments[0].validator_set, validator_ids);
    
    // Test store_subnet_rotation
    let rotation = SubnetRotation {
        epoch,
        rotation_seed: H256::random(),
        previous_assignments: vec![],
        new_assignments: vec![assignment.clone()],
    };
    
    repo.store_subnet_rotation(rotation.clone()).await?;
    
    // Test get_latest_rotation
    let latest_rotation = repo.get_latest_rotation().await?;
    assert!(latest_rotation.is_some());
    let latest_rotation = latest_rotation.unwrap();
    assert_eq!(latest_rotation.epoch, epoch);
    assert_eq!(latest_rotation.new_assignments.len(), 1);
    
    // Test get_validator_subnet
    let validator_id = validator_ids[0];
    let subnet = repo.get_validator_subnet(validator_id, epoch).await?;
    assert!(subnet.is_some());
    assert_eq!(subnet.unwrap(), subnet_id);
    
    Ok(())
}

#[tokio::test]
async fn test_reward_repository() -> Result<()> {
    // Setup
    let pool = setup_test_db().await?;
    let repo = PostgresRewardRepository::new(pool.clone());
    
    // Test data
    let validator_id = H256::random();
    let epoch = 1;
    let reward = ValidatorReward {
        validator_id,
        amount: 1_000_000_000,
        performance_score: 9800,
        epoch,
    };
    
    // Test store_reward
    repo.store_reward(reward.clone()).await?;
    
    // Test get_validator_rewards
    let rewards = repo.get_validator_rewards(validator_id, epoch).await?;
    assert_eq!(rewards.len(), 1);
    assert_eq!(rewards[0].validator_id, validator_id);
    assert_eq!(rewards[0].amount, reward.amount);
    assert_eq!(rewards[0].performance_score, reward.performance_score);
    
    // Test list_pending_rewards
    let pending_rewards = repo.list_pending_rewards(epoch).await?;
    assert_eq!(pending_rewards.len(), 1);
    
    // Test store_distribution
    let distribution = RewardDistribution {
        epoch,
        total_reward: reward.amount,
        distributions: vec![reward.clone()],
    };
    
    repo.store_distribution(distribution.clone()).await?;
    
    // Test get_epoch_distribution
    let retrieved_distribution = repo.get_epoch_distribution(epoch).await?;
    assert!(retrieved_distribution.is_some());
    let retrieved_distribution = retrieved_distribution.unwrap();
    assert_eq!(retrieved_distribution.epoch, epoch);
    assert_eq!(retrieved_distribution.total_reward, reward.amount);
    
    // After distribution, there should be no pending rewards
    let pending_rewards = repo.list_pending_rewards(epoch).await?;
    assert_eq!(pending_rewards.len(), 0);
    
    Ok(())
}

// Integration test that uses all repositories together
#[tokio::test]
async fn test_repository_integration() -> Result<()> {
    // Setup
    let pool = setup_test_db().await?;
    let validator_repo = Arc::new(PostgresValidatorRepository::new(pool.clone()));
    let subnet_repo = Arc::new(PostgresSubnetRepository::new(pool.clone()));
    let reward_repo = Arc::new(PostgresRewardRepository::new(pool.clone()));
    
    // 1. Register validators
    let validators = vec![
        generate_test_validator(),
        generate_test_validator(),
        generate_test_validator(),
    ];
    
    for validator in &validators {
        validator_repo.store_validator(validator.clone()).await?;
    }
    
    // 2. Assign to subnets
    let epoch = 1;
    let subnet_id = 0;
    let validator_ids: Vec<H256> = validators.iter().map(|v| v.validator_id).collect();
    
    let assignment = SubnetAssignment {
        subnet_id,
        epoch,
        validator_set: validator_ids.clone(),
    };
    
    subnet_repo.store_subnet_assignments(vec![assignment.clone()]).await?;
    
    // 3. Submit rewards
    for validator in &validators {
        let reward = ValidatorReward {
            validator_id: validator.validator_id,
            amount: 1_000_000_000,
            performance_score: 9800,
            epoch,
        };
        
        reward_repo.store_reward(reward).await?;
    }
    
    // 4. Distribute rewards
    let pending_rewards = reward_repo.list_pending_rewards(epoch).await?;
    assert_eq!(pending_rewards.len(), 3);
    
    let total_reward: u128 = pending_rewards.iter().map(|r| r.amount).sum();
    
    let distribution = RewardDistribution {
        epoch,
        total_reward,
        distributions: pending_rewards.clone(),
    };
    
    reward_repo.store_distribution(distribution).await?;
    
    // 5. Verify distribution
    let pending_rewards = reward_repo.list_pending_rewards(epoch).await?;
    assert_eq!(pending_rewards.len(), 0);
    
    Ok(())
}
