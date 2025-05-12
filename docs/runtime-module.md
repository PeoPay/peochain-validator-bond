# PeoChain Validator Bond Runtime Module

## Architecture Overview

The Validator Bond Runtime Module implements a truly permissionless validator registration and bonding system with no administrative control points. This document outlines the core architecture, design principles, and implementation details.

## Core Principles

1. **Cryptographic Verification Only**: All validation is performed through cryptographic proof, not subjective judgment
2. **No Administrative Control**: There are no approval queues, status transitions, or administrative overrides
3. **Deterministic Subnet Assignment**: Validator assignment to subnets is fully deterministic and unpredictable
4. **Objective Performance Tracking**: Performance is measured through cryptographically verifiable consensus participation only

## Module Structure

The runtime module consists of the following key components:

### Storage Items

```rust
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
```

### Dispatchable Functions

The module exposes the following dispatchable functions:

1. **`bond_validator`**: Register as a validator with cryptographic proof of escrow
2. **`submit_performance`**: Submit cryptographically verifiable performance proof
3. **`rotate_subnet`**: Trigger deterministic subnet rotation (permissionless)
4. **`unbond`**: Release validator bond after timelock period

### Key Types

```rust
/// Validator identifier derived from public key.
pub struct ValidatorId(pub [u8; 32]);

/// Escrow proof provided by validators during registration.
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

/// Performance proof submitted by validators.
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
```

## Key Workflows

### Validator Registration

1. Validator creates a non-custodial escrow (either multisig or threshold signature)
2. Validator generates cryptographic proof of escrow control
3. Validator submits registration transaction with public key and escrow proof
4. Runtime verifies the proof cryptographically (no human judgment)
5. Validator is immediately registered and assigned to a subnet deterministically

```rust
// Example registration flow
fn bond_validator(
    origin,
    public_key: [u8; 32],
    proof: ProofOfEscrow<T::AccountId, BalanceOf<T>, T::BlockNumber, T::Signature>,
) -> DispatchResult {
    let sender = ensure_signed(origin)?;
    
    // Generate deterministic validator ID
    let validator_id = Self::derive_validator_id(&public_key);
    
    // Ensure validator is not already registered
    ensure!(!Validators::<T>::contains_key(validator_id), Error::<T>::ValidatorAlreadyRegistered);
    
    // Ensure bond amount meets minimum requirement
    ensure!(proof.amount >= T::MinimumBond::get(), Error::<T>::BondTooLow);
    
    // Validate escrow cryptographically - no human judgment
    ensure!(Self::verify_escrow_proof(&proof, &public_key), Error::<T>::InvalidEscrowProof);
    
    // Create and store validator
    // ...
    
    // Assign to subnet deterministically
    // ...
    
    Ok(())
}
```

### Deterministic Subnet Assignment

Subnet assignment is fully deterministic and based on a cryptographic hash of the validator ID and epoch number:

```rust
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
```

### Performance Verification

Performance is verified through cryptographic proof only:

```rust
fn verify_performance_proof(proof: &PerformanceProof<T::Signature>) -> bool {
    // In a real implementation, this would verify:
    // 1. The validator participated in the claimed blocks
    // 2. The proof signature is valid
    
    let message = (
        proof.validator_id,
        proof.epoch,
        proof.block_range,
        proof.participation.clone(),
    ).encode();
    
    // Get the validator's public key
    if let Some(escrow) = Self::validator(proof.validator_id) {
        // Convert public key to account ID for verification
        let account_id = T::AccountId::decode(&mut &escrow.public_key[..])
            .unwrap_or_default();
        
        // Verify the signature
        proof.proof.verify(&message[..], &account_id)
    } else {
        false
    }
}
```

## Subnet Rotation

Subnet assignments are rotated periodically to ensure fair distribution of validators:

```rust
fn do_subnet_rotation(new_epoch: EpochNumber) {
    // Get all validators
    let validators: Vec<_> = Validators::<T>::iter()
        .map(|(id, _)| id)
        .collect();
    
    // Clear previous subnet assignments
    // ...
    
    // Assign validators to subnets deterministically
    for validator_id in validators {
        let subnet_id = Self::assign_validator_to_subnet(&validator_id, new_epoch);
        
        // Add validator to subnet
        // ...
    }
}
```

## Security Considerations

### Non-custodial Escrow

The validator bond is held in a non-custodial escrow, which can be implemented as:

1. **2-of-2 Multisig**: Requiring signatures from both the validator and the network
2. **Threshold Signature**: Requiring a threshold of signatures from a set of participants

### Timelock Period

Validator bonds are subject to a timelock period to prevent rapid unbonding:

```rust
// Ensure timelock has expired
let current_block = <frame_system::Module<T>>::block_number();
ensure!(current_block >= escrow.timelock_height, Error::<T>::TimelockNotExpired);
```

### Cryptographic Verification

All operations are verified cryptographically, with no subjective judgment:

```rust
// Validate escrow cryptographically - no human judgment
ensure!(Self::verify_escrow_proof(&proof, &public_key), Error::<T>::InvalidEscrowProof);
```

## Integration with CLI

The runtime module is designed to be used with the CLI tool, which provides a direct interface for validators to interact with the chain without administrative intermediaries.

## Conclusion

The Validator Bond Runtime Module implements a truly permissionless validator registration and bonding system with no administrative control points. By relying on cryptographic verification and deterministic assignment, it ensures that the validator marketplace is fair, transparent, and resistant to centralization.
