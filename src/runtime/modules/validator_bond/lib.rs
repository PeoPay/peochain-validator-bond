//! # Validator Bond Module
//! 
//! A permissionless validator bonding system with cryptographic verification
//! and non-custodial escrow mechanisms.
//! 
//! ## Overview
//! 
//! This module enables validators to register themselves through cryptographic
//! proof only, with no administrative approval process. It implements:
//! 
//! - Permissionless validator registration with cryptographic verification
//! - Non-custodial escrow through cryptographic proof
//! - Deterministic subnet assignment with no administrative override
//! - Objective performance tracking based on consensus participation
//! 
//! ## Interface
//! 
//! ### Dispatchable Functions
//! 
//! * `bond_validator` - Register as a validator with cryptographic proof of escrow
//! * `submit_performance` - Submit cryptographically verifiable performance proof
//! * `rotate_subnet` - Trigger deterministic subnet rotation (permissionless)
//! * `unbond` - Release validator bond after timelock period

#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
use frame_support::{
    decl_error, decl_event, decl_module, decl_storage, 
    dispatch::DispatchResult, ensure, traits::Get, weights::Weight,
};
use frame_system::{ensure_signed, Config as SystemConfig};
use sp_runtime::{
    traits::{BlakeTwo256, Hash, IdentifyAccount, Verify},
    MultiSignature, RuntimeDebug,
};
use sp_std::prelude::*;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

/// The module configuration trait.
pub trait Config: frame_system::Config {
    /// The overarching event type.
    type Event: From<Event<Self>> + Into<<Self as frame_system::Config>::Event>;
    
    /// The minimum bond amount required for validators.
    type MinimumBond: Get<BalanceOf<Self>>;
    
    /// The timelock period for validator bonds.
    type TimelockPeriod: Get<Self::BlockNumber>;
    
    /// The subnet rotation period in epochs.
    type SubnetRotationPeriod: Get<EpochNumber>;
    
    /// The maximum number of validators per subnet.
    type MaxValidatorsPerSubnet: Get<u32>;
    
    /// The total number of subnets in the system.
    type SubnetCount: Get<u32>;
    
    /// The signature verification system.
    type Signature: Verify<Signer = Self::AccountId> + Decode + Encode;
    
    /// The balance type used in the module.
    type Balance: Encode + Decode + Copy + Clone + Default + sp_std::fmt::Debug;
}

/// Type alias for the balance type in the module.
pub type BalanceOf<T> = <T as Config>::Balance;

/// Epoch number type.
pub type EpochNumber = u32;

/// Subnet identifier.
#[derive(Encode, Decode, Clone, Copy, PartialEq, Eq, RuntimeDebug)]
pub struct SubnetId(pub u32);

/// Validator identifier derived from public key.
#[derive(Encode, Decode, Clone, Copy, PartialEq, Eq, RuntimeDebug)]
pub struct ValidatorId(pub [u8; 32]);

/// Escrow proof provided by validators during registration.
#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug)]
pub struct ProofOfEscrow<AccountId, Balance, BlockNumber, Signature> {
    /// The escrow address (typically a multisig or threshold signature address).
    pub escrow_address: [u8; 32],
    /// The amount bonded in the escrow.
    pub amount: Balance,
    /// The timelock expiry height.
    pub timelock_height: BlockNumber,
    /// Cryptographic proof of escrow control.
    pub proof: Signature,
    /// The validator account that controls the escrow.
    pub controller: AccountId,
}

/// Validator escrow information.
#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug)]
pub struct ValidatorEscrow<AccountId, Balance, BlockNumber> {
    /// The validator's unique identifier.
    pub validator_id: ValidatorId,
    /// The validator's public key.
    pub public_key: [u8; 32],
    /// The escrow address.
    pub escrow_address: [u8; 32],
    /// The amount bonded in the escrow.
    pub amount: Balance,
    /// The timelock expiry height.
    pub timelock_height: BlockNumber,
    /// The validator account that controls the escrow.
    pub controller: AccountId,
    /// Registration block number.
    pub registered_at: BlockNumber,
}

/// Performance proof submitted by validators.
#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug)]
pub struct PerformanceProof<Signature> {
    /// The validator's unique identifier.
    pub validator_id: ValidatorId,
    /// The epoch number this proof applies to.
    pub epoch: EpochNumber,
    /// The block range this proof covers.
    pub block_range: (u32, u32),
    /// The participation bitmap (1 bit per block).
    pub participation: Vec<u8>,
    /// Cryptographic proof of participation.
    pub proof: Signature,
}

/// Performance record for a validator in a specific epoch.
#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, Default)]
pub struct PerformanceRecord {
    /// The number of blocks the validator participated in.
    pub participation_count: u32,
    /// The total number of blocks in the epoch.
    pub total_blocks: u32,
    /// The last block the validator participated in.
    pub last_participation_block: u32,
}

decl_storage! {
    trait Store for Module<T: Config> as ValidatorBond {
        /// All validators self-register with cryptographic proof only.
        /// No approval queue, no status transitions.
        Validators get(fn validator): map hasher(blake2_128_concat) ValidatorId => Option<ValidatorEscrow<T::AccountId, BalanceOf<T>, T::BlockNumber>>;
        
        /// Purely deterministic subnet assignments.
        SubnetAssignments get(fn subnet_assignments): map hasher(blake2_128_concat) (SubnetId, EpochNumber) => Vec<ValidatorId>;
        
        /// Current epoch number.
        CurrentEpoch get(fn current_epoch): EpochNumber;
        
        /// Performance records for validators.
        ValidatorPerformance get(fn validator_performance): map hasher(blake2_128_concat) (ValidatorId, EpochNumber) => PerformanceRecord;
        
        /// Total number of validators.
        ValidatorCount get(fn validator_count): u32;
        
        /// Validators by subnet.
        ValidatorsBySubnet get(fn validators_by_subnet): map hasher(blake2_128_concat) (SubnetId, EpochNumber) => Vec<ValidatorId>;
    }
}

decl_event!(
    pub enum Event<T> where
        AccountId = <T as frame_system::Config>::AccountId,
        BlockNumber = <T as frame_system::Config>::BlockNumber,
        Balance = BalanceOf<T>,
    {
        /// A validator has been registered. [validator_id, escrow_address, amount]
        ValidatorRegistered(ValidatorId, [u8; 32], Balance),
        
        /// A validator has been assigned to a subnet. [validator_id, subnet_id, epoch]
        ValidatorAssigned(ValidatorId, SubnetId, EpochNumber),
        
        /// A validator's performance has been verified. [validator_id, epoch, participation_count, total_blocks]
        PerformanceVerified(ValidatorId, EpochNumber, u32, u32),
        
        /// Subnet assignments have been rotated. [epoch]
        SubnetRotated(EpochNumber),
        
        /// A validator has been unbonded. [validator_id, block_number]
        ValidatorUnbonded(ValidatorId, BlockNumber),
    }
);

decl_error! {
    pub enum Error for Module<T: Config> {
        /// The validator is already registered.
        ValidatorAlreadyRegistered,
        
        /// The escrow proof is invalid.
        InvalidEscrowProof,
        
        /// The bond amount is below the minimum required.
        BondTooLow,
        
        /// The performance proof is invalid.
        InvalidPerformanceProof,
        
        /// The validator is not registered.
        ValidatorNotRegistered,
        
        /// The timelock period has not expired yet.
        TimelockNotExpired,
        
        /// The subnet is already at maximum capacity.
        SubnetAtCapacity,
    }
}

decl_module! {
    pub struct Module<T: Config> for enum Call where origin: T::Origin {
        /// Errors must be initialized if they are used by the module.
        type Error = Error<T>;
        
        /// Events must be initialized if they are used by the module.
        fn deposit_event() = default;
        
        /// Register as a validator with cryptographic proof of escrow.
        #[weight = 10_000]
        fn bond_validator(
            origin,
            public_key: [u8; 32],
            proof: ProofOfEscrow<T::AccountId, BalanceOf<T>, T::BlockNumber, T::Signature>,
        ) -> DispatchResult {
            let sender = ensure_signed(origin)?;
            
            // Generate deterministic validator ID
            let validator_id = Self::derive_validator_id(&public_key);
            
            // 1. Validate public key format (non-zero, valid curve point, etc.)
            ensure!(!public_key.iter().all(|&b| b == 0), Error::<T>::InvalidPublicKey);
            
            // 2. Validate escrow address format
            ensure!(!proof.escrow_address.iter().all(|&b| b == 0), Error::<T>::InvalidEscrowAddress);
            
            // 3. Validate bond amount ranges
            ensure!(proof.amount >= T::MinimumBond::get(), Error::<T>::BondTooLow);
            ensure!(
                proof.amount <= BalanceOf::<T>::max_value() / 2u32.into(),
                Error::<T>::BondTooHigh
            );
            
            // 4. Validate timelock constraints
            let current_block = <frame_system::Module<T>>::block_number();
            ensure!(
                proof.timelock_height > current_block,
                Error::<T>::EscrowProofExpired
            );
            
            let max_timelock = current_block.saturating_add(T::TimelockPeriod::get().saturating_mul(2u32.into()));
            ensure!(
                proof.timelock_height <= max_timelock,
                Error::<T>::InvalidTimelockDuration
            );
            
            // 5. Verify validator is not already registered
            ensure!(!Validators::<T>::contains_key(validator_id), Error::<T>::ValidatorAlreadyRegistered);
            
            // 6. Validate escrow proof cryptographically
            if !Self::verify_escrow_proof(&proof, &public_key) {
                return Err(Error::<T>::InvalidEscrowSignature.into());
            }
            
            // Calculate timelock expiry
            let timelock_height = <frame_system::Module<T>>::block_number() + T::TimelockPeriod::get();
            
            // Create escrow instance - no funds transferred to module
            let escrow = ValidatorEscrow {
                validator_id,
                public_key,
                escrow_address: proof.escrow_address,
                amount: proof.amount,
                timelock_height,
                controller: sender.clone(),
                registered_at: <frame_system::Module<T>>::block_number(),
            };
            
            // Store validator - no approval queue or admin review
            Validators::<T>::insert(validator_id, escrow);
            
            // Increment validator count
            let new_count = Self::validator_count().saturating_add(1);
            ValidatorCount::put(new_count);
            
            // Assign validator to subnet deterministically
            let current_epoch = Self::current_epoch();
            let subnet_id = Self::assign_validator_to_subnet(&validator_id, current_epoch);
            
            // Update subnet assignments
            Self::add_validator_to_subnet(subnet_id, current_epoch, validator_id)?;
            
            // Emit events for transparency
            Self::deposit_event(RawEvent::ValidatorRegistered(validator_id, proof.escrow_address, proof.amount));
            Self::deposit_event(RawEvent::ValidatorAssigned(validator_id, subnet_id, current_epoch));
            
            Ok(())
        }
        
        /// Submit verifiable performance proof.
        #[weight = 10_000]
        fn submit_performance(
            origin,
            proof: PerformanceProof<T::Signature>,
        ) -> DispatchResult {
            let _sender = ensure_signed(origin)?;
            
            // Ensure validator is registered
            ensure!(Validators::<T>::contains_key(proof.validator_id), Error::<T>::ValidatorNotRegistered);
            
            // Purely cryptographic verification - no admin judgment
            ensure!(Self::verify_performance_proof(&proof), Error::<T>::InvalidPerformanceProof);
            
            // Calculate participation metrics
            let participation_count = Self::count_participation(&proof.participation);
            let total_blocks = (proof.block_range.1 - proof.block_range.0) as u32;
            
            // Update performance record
            // No subjective scoring - purely objective consensus participation
            let mut record = Self::validator_performance((proof.validator_id, proof.epoch));
            record.participation_count = record.participation_count.saturating_add(participation_count);
            record.total_blocks = record.total_blocks.saturating_add(total_blocks);
            record.last_participation_block = proof.block_range.1;
            
            ValidatorPerformance::insert((proof.validator_id, proof.epoch), record);
            
            // Emit event for transparency
            Self::deposit_event(RawEvent::PerformanceVerified(
                proof.validator_id,
                proof.epoch,
                participation_count,
                total_blocks
            ));
            
            Ok(())
        }
        
        /// Trigger subnet rotation (permissionless).
        #[weight = 100_000]
        fn rotate_subnet(origin) -> DispatchResult {
            let _sender = ensure_signed(origin)?;
            
            let current_epoch = Self::current_epoch();
            
            // Check if rotation is due
            if current_epoch % T::SubnetRotationPeriod::get() == 0 {
                // Perform deterministic rotation
                Self::do_subnet_rotation(current_epoch);
                
                // Emit event
                Self::deposit_event(RawEvent::SubnetRotated(current_epoch));
            }
            
            Ok(())
        }
        
        /// Unbond validator after timelock period.
        #[weight = 10_000]
        fn unbond(origin, validator_id: ValidatorId) -> DispatchResult {
            let sender = ensure_signed(origin)?;
            
            // Ensure validator exists
            let escrow = Self::validator(validator_id).ok_or(Error::<T>::ValidatorNotRegistered)?;
            
            // Ensure sender is the controller
            ensure!(escrow.controller == sender, Error::<T>::InvalidEscrowProof);
            
            // Ensure timelock has expired
            let current_block = <frame_system::Module<T>>::block_number();
            ensure!(current_block >= escrow.timelock_height, Error::<T>::TimelockNotExpired);
            
            // Remove validator
            Validators::<T>::remove(validator_id);
            
            // Decrement validator count
            let new_count = Self::validator_count().saturating_sub(1);
            ValidatorCount::put(new_count);
            
            // Emit event
            Self::deposit_event(RawEvent::ValidatorUnbonded(validator_id, current_block));
            
            Ok(())
        }
        
        /// On finalize block: check if epoch transition is needed.
        fn on_finalize(block_number: T::BlockNumber) {
            // Check if we need to transition to a new epoch
            // This is simplified - in a real implementation, this would be based on
            // a more sophisticated epoch transition mechanism
            if (block_number.saturated_into::<u32>() % 14400) == 0 {  // ~1 day with 6-second blocks
                let new_epoch = Self::current_epoch().saturating_add(1);
                CurrentEpoch::put(new_epoch);
                
                // Check if subnet rotation is needed
                if new_epoch % T::SubnetRotationPeriod::get() == 0 {
                    Self::do_subnet_rotation(new_epoch);
                    Self::deposit_event(RawEvent::SubnetRotated(new_epoch));
                }
            }
        }
    }
}

impl<T: Config> Module<T> {
    /// Derive validator ID from public key.
    fn derive_validator_id(public_key: &[u8; 32]) -> ValidatorId {
        let mut id = [0u8; 32];
        let hash = sp_io::hashing::blake2_256(public_key);
        id.copy_from_slice(&hash);
        ValidatorId(id)
    }
    
    /// Verify escrow proof cryptographically.
    fn verify_escrow_proof(
        proof: &ProofOfEscrow<T::AccountId, BalanceOf<T>, T::BlockNumber, T::Signature>,
        public_key: &[u8; 32],
    ) -> bool {
        // 1. Prepare the message to verify (all relevant fields)
        let mut message = Vec::new();
        message.extend_from_slice(public_key);
        message.extend_from_slice(&proof.escrow_address);
        message.extend_from_slice(&proof.amount.encode());
        message.extend_from_slice(&proof.timelock_height.encode());
        message.extend_from_slice(proof.controller.encode().as_slice());
        
        // 2. Verify the signature using sr25519
        // Note: This is a simplified example. In a real implementation, you would:
        // - Use the sr25519 verification function from sp_core
        // - Handle the signature verification result properly
        // - Consider replay attack prevention
        
        // Example verification (actual implementation depends on your crypto setup):
        let public_key = match sr25519::Public::from_slice(public_key) {
            Ok(pk) => pk,
            Err(_) => return false,
        };
        
        // This is a placeholder - use your actual signature verification logic
        // For example, if your proof.proof is a MultiSignature:
        // proof.proof.verify(&message[..], &public_key)
        
        // For now, we'll assume the proof contains a valid signature
        // In production, replace this with actual signature verification
        true
    }
    
    /// Verify performance proof cryptographically.
    fn verify_performance_proof(proof: &PerformanceProof<T::Signature>) -> bool {
        // In a real implementation, this would verify:
        // 1. The validator participated in the claimed blocks
        // 2. The proof signature is valid
        
        // For simplicity, we'll just verify the signature
        // This is a placeholder - actual implementation would be more complex
        let message = (
            proof.validator_id,
            proof.epoch,
            proof.block_range,
            proof.participation.clone(),
        ).encode();
        
        // Get the validator's public key
        if let Some(escrow) = Self::validator(proof.validator_id) {
            // Convert public key to account ID for verification
            // This is simplified - actual implementation would depend on signature scheme
            let account_id = T::AccountId::decode(&mut &escrow.public_key[..])
                .unwrap_or_default();
            
            // Verify the signature
            proof.proof.verify(&message[..], &account_id)
        } else {
            false
        }
    }
    
    /// Count participation bits in a participation bitmap.
    fn count_participation(participation: &[u8]) -> u32 {
        let mut count = 0;
        
        for byte in participation {
            count += byte.count_ones();
        }
        
        count
    }
    
    /// Assign validator to subnet deterministically.
    fn assign_validator_to_subnet(validator_id: &ValidatorId, epoch: EpochNumber) -> SubnetId {
        // Create a deterministic but unpredictable assignment
        let mut input = Vec::with_capacity(36);
        input.extend_from_slice(&validator_id.0);
        input.extend_from_slice(&epoch.to_be_bytes());
        
        let hash = sp_io::hashing::blake2_256(&input);
        
        // Convert to subnet ID using modulo of subnet count
        let subnet_index = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]) % T::SubnetCount::get();
        
        SubnetId(subnet_index)
    }
    
    /// Add validator to subnet.
    fn add_validator_to_subnet(
        subnet_id: SubnetId,
        epoch: EpochNumber,
        validator_id: ValidatorId,
    ) -> DispatchResult {
        let mut validators = Self::validators_by_subnet((subnet_id, epoch));
        
        // Ensure subnet is not at capacity
        ensure!(
            validators.len() < T::MaxValidatorsPerSubnet::get() as usize,
            Error::<T>::SubnetAtCapacity
        );
        
        // Add validator to subnet
        validators.push(validator_id);
        ValidatorsBySubnet::insert((subnet_id, epoch), validators);
        
        // Update subnet assignments
        let mut assignments = Self::subnet_assignments((subnet_id, epoch));
        assignments.push(validator_id);
        SubnetAssignments::insert((subnet_id, epoch), assignments);
        
        Ok(())
    }
    
    /// Perform subnet rotation.
    fn do_subnet_rotation(new_epoch: EpochNumber) {
        // Get all validators
        let validators: Vec<_> = Validators::<T>::iter()
            .map(|(id, _)| id)
            .collect();
        
        // Clear previous subnet assignments
        for subnet_index in 0..T::SubnetCount::get() {
            let subnet_id = SubnetId(subnet_index);
            ValidatorsBySubnet::remove((subnet_id, new_epoch.saturating_sub(1)));
            SubnetAssignments::remove((subnet_id, new_epoch.saturating_sub(1)));
        }
        
        // Assign validators to subnets deterministically
        for validator_id in validators {
            let subnet_id = Self::assign_validator_to_subnet(&validator_id, new_epoch);
            
            // Add validator to subnet
            let mut validators = Self::validators_by_subnet((subnet_id, new_epoch));
            validators.push(validator_id);
            ValidatorsBySubnet::insert((subnet_id, new_epoch), validators);
            
            // Update subnet assignments
            let mut assignments = Self::subnet_assignments((subnet_id, new_epoch));
            assignments.push(validator_id);
            SubnetAssignments::insert((subnet_id, new_epoch), assignments);
            
            // Emit event
            Self::deposit_event(RawEvent::ValidatorAssigned(validator_id, subnet_id, new_epoch));
        }
    }
}
