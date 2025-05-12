use codec::{Decode, Encode};
use sp_runtime::{MultiSignature, RuntimeDebug};

/// Balance type
pub type Balance = u128;

/// Block number type
pub type BlockNumber = u32;

/// Validator identifier derived from public key
#[derive(Encode, Decode, Clone, Copy, PartialEq, Eq, RuntimeDebug)]
pub struct ValidatorId(pub [u8; 32]);

/// Escrow proof provided by validators during registration
#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug)]
pub struct ProofOfEscrow<AccountId, Balance, BlockNumber, Signature> {
    /// The escrow address (typically a multisig or threshold signature address)
    pub escrow_address: [u8; 32],
    /// The amount bonded in the escrow
    pub amount: Balance,
    /// The timelock expiry height
    pub timelock_height: BlockNumber,
    /// Cryptographic proof of escrow control
    pub proof: Signature,
    /// The validator account that controls the escrow
    pub controller: AccountId,
}

/// Performance proof submitted by validators
#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug)]
pub struct PerformanceProof<Signature> {
    /// The validator's unique identifier
    pub validator_id: ValidatorId,
    /// The epoch number this proof applies to
    pub epoch: u32,
    /// The block range this proof covers
    pub block_range: (u32, u32),
    /// The participation bitmap (1 bit per block)
    pub participation: Vec<u8>,
    /// Cryptographic proof of participation
    pub proof: Signature,
}

/// Threshold signature parameters
#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug)]
pub struct ThresholdParams {
    /// The threshold value (minimum signers required)
    pub threshold: u32,
    /// The total number of participants
    pub total_participants: u32,
}

/// Subnet identifier
#[derive(Encode, Decode, Clone, Copy, PartialEq, Eq, RuntimeDebug)]
pub struct SubnetId(pub u32);

/// Performance record for a validator in a specific epoch
#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, Default)]
pub struct PerformanceRecord {
    /// The number of blocks the validator participated in
    pub participation_count: u32,
    /// The total number of blocks in the epoch
    pub total_blocks: u32,
    /// The last block the validator participated in
    pub last_participation_block: u32,
}
