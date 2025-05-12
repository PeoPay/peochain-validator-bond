use serde::{Deserialize, Serialize};
use sp_core::{crypto::AccountId32 as AccountId, H256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorEscrow {
    pub validator_id: H256,
    pub public_key: Vec<u8>,
    pub escrow_address: AccountId,
    pub timelock_height: u32,
    pub status: EscrowStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EscrowStatus {
    Active,
    Withdrawing { release_height: u32 },
    Released,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceProof {
    pub validator_id: H256,
    pub subnet_id: u32,
    pub block_range: (u32, u32),
    pub participation_bitmap: Vec<u8>,
    pub subnet_signatures: Vec<(H256, Vec<u8>)>,
    pub merkle_proof: Vec<H256>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SlashableOffense {
    Equivocation {
        block_number: u32,
        first_signature: Vec<u8>,
        second_signature: Vec<u8>,
    },
    InvalidAttestation {
        block_number: u32,
        invalid_hash: H256,
        correct_hash: H256,
        signature: Vec<u8>,
    },
}
