use crate::{mock::*, Error, PerformanceProof, ProofOfEscrow, SubnetId, ValidatorId};
use frame_support::{assert_noop, assert_ok};
use sp_core::{sr25519, Pair};
use sp_runtime::MultiSignature;

// Helper function to generate a random public key
fn random_public_key() -> [u8; 32] {
    let pair = sr25519::Pair::generate().0;
    let public = pair.public();
    let mut result = [0u8; 32];
    result.copy_from_slice(public.as_ref());
    result
}

// Helper function to generate a valid escrow proof
fn generate_escrow_proof(
    controller: &sr25519::Pair,
    escrow_address: [u8; 32],
    amount: u64,
    timelock_height: u64,
) -> ProofOfEscrow<AccountId, u64, u64, MultiSignature> {
    let message = (escrow_address, amount, timelock_height).encode();
    let signature = controller.sign(&message);
    
    ProofOfEscrow {
        escrow_address,
        amount,
        timelock_height,
        proof: MultiSignature::Sr25519(signature),
        controller: controller.public(),
    }
}

// Helper function to generate a valid performance proof
fn generate_performance_proof(
    validator_id: ValidatorId,
    epoch: u32,
    block_range: (u32, u32),
    participation: Vec<u8>,
    signer: &sr25519::Pair,
) -> PerformanceProof<MultiSignature> {
    let message = (validator_id, epoch, block_range, participation.clone()).encode();
    let signature = signer.sign(&message);
    
    PerformanceProof {
        validator_id,
        epoch,
        block_range,
        participation,
        proof: MultiSignature::Sr25519(signature),
    }
}

#[test]
fn bond_validator_works() {
    new_test_ext().execute_with(|| {
        // Generate a random public key and controller
        let public_key = random_public_key();
        let controller = sr25519::Pair::generate().0;
        
        // Generate a random escrow address
        let escrow_address = [1u8; 32];
        
        // Create a valid escrow proof
        let proof = generate_escrow_proof(
            &controller,
            escrow_address,
            2000, // Above minimum bond
            100,  // Arbitrary timelock height
        );
        
        // Bond the validator
        assert_ok!(ValidatorBond::bond_validator(
            Origin::signed(controller.public()),
            public_key,
            proof
        ));
        
        // Derive the validator ID
        let validator_id = ValidatorId(sp_io::hashing::blake2_256(&public_key));
        
        // Check that the validator was registered
        assert!(ValidatorBond::validator(validator_id).is_some());
        
        // Check that the validator count was incremented
        assert_eq!(ValidatorBond::validator_count(), 1);
        
        // Check that the validator was assigned to a subnet
        let current_epoch = ValidatorBond::current_epoch();
        let subnet_id = ValidatorBond::assign_validator_to_subnet(&validator_id, current_epoch);
        
        let validators_in_subnet = ValidatorBond::validators_by_subnet((subnet_id, current_epoch));
        assert!(validators_in_subnet.contains(&validator_id));
    });
}

#[test]
fn bond_validator_fails_with_low_bond() {
    new_test_ext().execute_with(|| {
        // Generate a random public key and controller
        let public_key = random_public_key();
        let controller = sr25519::Pair::generate().0;
        
        // Generate a random escrow address
        let escrow_address = [1u8; 32];
        
        // Create an escrow proof with too low bond
        let proof = generate_escrow_proof(
            &controller,
            escrow_address,
            500, // Below minimum bond
            100, // Arbitrary timelock height
        );
        
        // Attempt to bond the validator
        assert_noop!(
            ValidatorBond::bond_validator(
                Origin::signed(controller.public()),
                public_key,
                proof
            ),
            Error::<Test>::BondTooLow
        );
    });
}

#[test]
fn submit_performance_works() {
    new_test_ext().execute_with(|| {
        // First, register a validator
        let public_key = random_public_key();
        let controller = sr25519::Pair::generate().0;
        let escrow_address = [1u8; 32];
        
        let proof = generate_escrow_proof(
            &controller,
            escrow_address,
            2000,
            100,
        );
        
        assert_ok!(ValidatorBond::bond_validator(
            Origin::signed(controller.public()),
            public_key,
            proof
        ));
        
        // Derive the validator ID
        let validator_id = ValidatorId(sp_io::hashing::blake2_256(&public_key));
        
        // Generate a performance proof
        let epoch = ValidatorBond::current_epoch();
        let block_range = (1, 101); // 100 blocks
        let participation = vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F]; // 100 bits set
        
        let performance_proof = generate_performance_proof(
            validator_id,
            epoch,
            block_range,
            participation,
            &controller
        );
        
        // Submit the performance proof
        assert_ok!(ValidatorBond::submit_performance(
            Origin::signed(controller.public()),
            performance_proof
        ));
        
        // Check that the performance record was updated
        let record = ValidatorBond::validator_performance((validator_id, epoch));
        assert_eq!(record.participation_count, 100);
        assert_eq!(record.total_blocks, 100);
        assert_eq!(record.last_participation_block, 101);
    });
}

#[test]
fn unbond_works_after_timelock() {
    new_test_ext().execute_with(|| {
        // First, register a validator
        let public_key = random_public_key();
        let controller = sr25519::Pair::generate().0;
        let escrow_address = [1u8; 32];
        
        let proof = generate_escrow_proof(
            &controller,
            escrow_address,
            2000,
            100, // Timelock height
        );
        
        assert_ok!(ValidatorBond::bond_validator(
            Origin::signed(controller.public()),
            public_key,
            proof
        ));
        
        // Derive the validator ID
        let validator_id = ValidatorId(sp_io::hashing::blake2_256(&public_key));
        
        // Advance blocks to pass timelock
        frame_system::Module::<Test>::set_block_number(101);
        
        // Unbond the validator
        assert_ok!(ValidatorBond::unbond(
            Origin::signed(controller.public()),
            validator_id
        ));
        
        // Check that the validator was removed
        assert!(ValidatorBond::validator(validator_id).is_none());
        
        // Check that the validator count was decremented
        assert_eq!(ValidatorBond::validator_count(), 0);
    });
}

#[test]
fn unbond_fails_before_timelock() {
    new_test_ext().execute_with(|| {
        // First, register a validator
        let public_key = random_public_key();
        let controller = sr25519::Pair::generate().0;
        let escrow_address = [1u8; 32];
        
        let proof = generate_escrow_proof(
            &controller,
            escrow_address,
            2000,
            100, // Timelock height
        );
        
        assert_ok!(ValidatorBond::bond_validator(
            Origin::signed(controller.public()),
            public_key,
            proof
        ));
        
        // Derive the validator ID
        let validator_id = ValidatorId(sp_io::hashing::blake2_256(&public_key));
        
        // Set block number before timelock expiry
        frame_system::Module::<Test>::set_block_number(99);
        
        // Attempt to unbond the validator
        assert_noop!(
            ValidatorBond::unbond(
                Origin::signed(controller.public()),
                validator_id
            ),
            Error::<Test>::TimelockNotExpired
        );
    });
}

#[test]
fn rotate_subnet_works() {
    new_test_ext().execute_with(|| {
        // Register multiple validators
        for _ in 0..5 {
            let public_key = random_public_key();
            let controller = sr25519::Pair::generate().0;
            let escrow_address = [1u8; 32];
            
            let proof = generate_escrow_proof(
                &controller,
                escrow_address,
                2000,
                100,
            );
            
            assert_ok!(ValidatorBond::bond_validator(
                Origin::signed(controller.public()),
                public_key,
                proof
            ));
        }
        
        // Check validator count
        assert_eq!(ValidatorBond::validator_count(), 5);
        
        // Set epoch to rotation period
        let rotation_epoch = SubnetRotationPeriod::get();
        ValidatorBond::set_current_epoch(rotation_epoch);
        
        // Trigger subnet rotation
        let rotator = sr25519::Pair::generate().0;
        assert_ok!(ValidatorBond::rotate_subnet(
            Origin::signed(rotator.public())
        ));
        
        // Check that validators were assigned to subnets
        let mut total_assigned = 0;
        for subnet_index in 0..SubnetCount::get() {
            let subnet_id = SubnetId(subnet_index);
            let validators = ValidatorBond::validators_by_subnet((subnet_id, rotation_epoch));
            total_assigned += validators.len();
        }
        
        // All validators should be assigned
        assert_eq!(total_assigned, 5);
    });
}

impl ValidatorBond {
    // Helper function for tests to set the current epoch
    pub fn set_current_epoch(epoch: u32) {
        CurrentEpoch::put(epoch);
    }
}
