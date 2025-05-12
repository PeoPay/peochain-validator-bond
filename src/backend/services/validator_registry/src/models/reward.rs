use serde::{Deserialize, Serialize};
use sp_core::H256;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardClaim {
    pub validator_id: H256,
    pub epoch: u32,
    pub performance_score: u32, // 0-10000 basis points (0-100%)
    pub proof: PerformanceProof,
    pub subnet_proof: ValidatorSubnetProof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardDistribution {
    pub epoch: u32,
    pub total_reward: u128,
    pub distributions: Vec<ValidatorReward>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorReward {
    pub validator_id: H256,
    pub amount: u128,
    pub performance_score: u32,
}

// Constants for reward calculation
pub const BASE_REWARD_PER_EPOCH: u128 = 1_000_000_000; // 1 PEO
pub const MIN_PERFORMANCE_THRESHOLD: u32 = 9500; // 95%
