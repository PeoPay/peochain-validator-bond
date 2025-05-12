use serde::{Deserialize, Serialize};
use sp_core::H256;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubnetAssignment {
    pub subnet_id: u32,
    pub epoch: u32,
    pub validator_set: Vec<H256>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubnetRotation {
    pub epoch: u32,
    pub rotation_seed: H256,
    pub previous_assignments: Vec<SubnetAssignment>,
    pub new_assignments: Vec<SubnetAssignment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSubnetProof {
    pub validator_id: H256,
    pub subnet_id: u32,
    pub epoch: u32,
    pub merkle_proof: Vec<H256>,
}

// Constants for subnet configuration
pub const SUBNET_ROTATION_PERIOD: u32 = 14400; // ~2 days in blocks
pub const MIN_VALIDATORS_PER_SUBNET: u32 = 10;
pub const MAX_VALIDATORS_PER_SUBNET: u32 = 100;
