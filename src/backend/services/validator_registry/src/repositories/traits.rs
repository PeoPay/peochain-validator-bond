use async_trait::async_trait;
use anyhow::Result;
use sp_core::H256;

use crate::models::{
    validator::{ValidatorEscrow, EscrowStatus},
    subnet::{SubnetAssignment, SubnetRotation},
    reward::{ValidatorReward, RewardDistribution},
};

#[async_trait]
pub trait ValidatorRepository: Send + Sync {
    async fn store_validator(&self, escrow: ValidatorEscrow) -> Result<()>;
    async fn get_validator(&self, validator_id: H256) -> Result<Option<ValidatorEscrow>>;
    async fn update_validator_status(&self, validator_id: H256, status: EscrowStatus) -> Result<()>;
    async fn list_active_validators(&self) -> Result<Vec<ValidatorEscrow>>;
}

#[async_trait]
pub trait SubnetRepository: Send + Sync {
    async fn store_subnet_assignments(&self, assignments: Vec<SubnetAssignment>) -> Result<()>;
    async fn get_subnet_assignments(&self, epoch: u32) -> Result<Vec<SubnetAssignment>>;
    async fn store_subnet_rotation(&self, rotation: SubnetRotation) -> Result<()>;
    async fn get_latest_rotation(&self) -> Result<Option<SubnetRotation>>;
    async fn get_validator_subnet(&self, validator_id: H256, epoch: u32) -> Result<Option<u32>>;
}

#[async_trait]
pub trait RewardRepository: Send + Sync {
    async fn store_reward(&self, reward: ValidatorReward) -> Result<()>;
    async fn get_validator_rewards(&self, validator_id: H256, epoch: u32) -> Result<Vec<ValidatorReward>>;
    async fn store_distribution(&self, distribution: RewardDistribution) -> Result<()>;
    async fn get_epoch_distribution(&self, epoch: u32) -> Result<Option<RewardDistribution>>;
    async fn list_pending_rewards(&self, epoch: u32) -> Result<Vec<ValidatorReward>>;
}
