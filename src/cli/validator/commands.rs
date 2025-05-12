use crate::{
    api::PeoChainApi,
    types::{Balance, BlockNumber, PerformanceProof, ProofOfEscrow, ThresholdParams, ValidatorId},
};
use sp_core::{crypto::Pair as PairTrait, sr25519, Pair, H256};
use sp_runtime::MultiSignature;
use std::{fs, path::Path};

/// Error type for validator commands
#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Api(String),
    Crypto(String),
    Parse(String),
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(err) => write!(f, "IO error: {}", err),
            Error::Api(err) => write!(f, "API error: {}", err),
            Error::Crypto(err) => write!(f, "Crypto error: {}", err),
            Error::Parse(err) => write!(f, "Parse error: {}", err),
        }
    }
}

impl std::error::Error for Error {}

/// Commands for validator operations
pub struct ValidatorCommands;

impl ValidatorCommands {
    /// Generate validator keys
    pub fn generate_keys(output_path: &Path) -> Result<(), Error> {
        // Create output directory if it doesn't exist
        if !output_path.exists() {
            fs::create_dir_all(output_path)?;
        }

        // Generate keypair
        let pair = sr25519::Pair::generate().0;
        let public = pair.public();

        // Write secret key with strong encryption
        let password = prompt_password("Enter encryption password: ")?;
        let confirm_password = prompt_password("Confirm password: ")?;

        if password != confirm_password {
            return Err(Error::Parse("Passwords do not match".to_string()));
        }

        let encrypted = pair
            .to_encrypted_json(password.as_bytes())
            .map_err(|e| Error::Crypto(format!("Failed to encrypt key: {}", e)))?;

        fs::write(output_path.join("validator.key"), encrypted)?;

        // Write public key
        let public_bytes = public.as_ref();
        fs::write(output_path.join("validator.pub"), hex::encode(public_bytes))?;

        println!("Generated validator keys at {}", output_path.display());
        println!("Public key: {}", hex::encode(public_bytes));
        println!("Keep your key file and password secure!");

        Ok(())
    }

    /// Create a non-custodial escrow
    pub fn create_escrow(
        node_url: &str,
        amount: Balance,
        timelock_period: BlockNumber,
    ) -> Result<H256, Error> {
        // Connect to node
        let api = PeoChainApi::new(node_url).map_err(|e| Error::Api(e.to_string()))?;

        // Create non-custodial 2-of-2 multisig with network
        let escrow_id = api
            .create_non_custodial_escrow(amount, timelock_period)
            .map_err(|e| Error::Api(e.to_string()))?;

        println!("Created escrow with ID: {}", escrow_id);
        println!("Amount: {}", amount);
        println!("Timelock period: {} blocks", timelock_period);

        Ok(escrow_id)
    }

    /// Register as a validator
    pub fn register_validator(
        node_url: &str,
        key_path: &Path,
        escrow_id: H256,
    ) -> Result<H256, Error> {
        // Load keypair
        let password = prompt_password("Enter encryption password: ")?;
        let key_data = fs::read_to_string(key_path)?;
        
        let pair = sr25519::Pair::from_encrypted_json(
            &key_data,
            password.as_bytes(),
        ).map_err(|e| Error::Crypto(format!("Failed to decrypt key: {}", e)))?;

        // Connect to node
        let api = PeoChainApi::new(node_url).map_err(|e| Error::Api(e.to_string()))?;

        // Get escrow details
        let (escrow_address, amount, timelock_height) = api
            .get_escrow_details(escrow_id)
            .map_err(|e| Error::Api(e.to_string()))?;

        // Generate escrow proof cryptographically
        let message = (escrow_address, amount, timelock_height).encode();
        let signature = pair.sign(&message);
        
        let proof = ProofOfEscrow {
            escrow_address,
            amount,
            timelock_height,
            proof: MultiSignature::Sr25519(signature),
            controller: pair.public(),
        };

        // Submit transaction to register validator
        let public_key = {
            let mut key = [0u8; 32];
            key.copy_from_slice(pair.public().as_ref());
            key
        };
        
        let tx_hash = api
            .register_validator(public_key, proof)
            .map_err(|e| Error::Api(e.to_string()))?;

        println!("Submitted validator registration transaction: {}", tx_hash);
        println!("Your validator will be active immediately upon transaction confirmation");

        Ok(tx_hash)
    }

    /// Submit performance proof
    pub fn submit_performance(
        node_url: &str,
        key_path: &Path,
        epoch: u32,
        block_range: (u32, u32),
        participation: Vec<u8>,
    ) -> Result<H256, Error> {
        // Load keypair
        let password = prompt_password("Enter encryption password: ")?;
        let key_data = fs::read_to_string(key_path)?;
        
        let pair = sr25519::Pair::from_encrypted_json(
            &key_data,
            password.as_bytes(),
        ).map_err(|e| Error::Crypto(format!("Failed to decrypt key: {}", e)))?;

        // Connect to node
        let api = PeoChainApi::new(node_url).map_err(|e| Error::Api(e.to_string()))?;

        // Get validator ID
        let public_key = {
            let mut key = [0u8; 32];
            key.copy_from_slice(pair.public().as_ref());
            key
        };
        
        let validator_id = api
            .get_validator_id(public_key)
            .map_err(|e| Error::Api(e.to_string()))?;

        // Create and sign performance proof
        let message = (validator_id, epoch, block_range, participation.clone()).encode();
        let signature = pair.sign(&message);
        
        let proof = PerformanceProof {
            validator_id,
            epoch,
            block_range,
            participation,
            proof: MultiSignature::Sr25519(signature),
        };

        // Submit performance proof
        let tx_hash = api
            .submit_performance(proof)
            .map_err(|e| Error::Api(e.to_string()))?;

        println!("Submitted performance proof transaction: {}", tx_hash);
        println!("Epoch: {}", epoch);
        println!("Block range: {} to {}", block_range.0, block_range.1);

        Ok(tx_hash)
    }

    /// Unbond validator
    pub fn unbond(
        node_url: &str,
        key_path: &Path,
        validator_id: ValidatorId,
    ) -> Result<H256, Error> {
        // Load keypair
        let password = prompt_password("Enter encryption password: ")?;
        let key_data = fs::read_to_string(key_path)?;
        
        let pair = sr25519::Pair::from_encrypted_json(
            &key_data,
            password.as_bytes(),
        ).map_err(|e| Error::Crypto(format!("Failed to decrypt key: {}", e)))?;

        // Connect to node
        let api = PeoChainApi::new(node_url).map_err(|e| Error::Api(e.to_string()))?;

        // Submit unbond transaction
        let tx_hash = api
            .unbond(validator_id, pair)
            .map_err(|e| Error::Api(e.to_string()))?;

        println!("Submitted unbond transaction: {}", tx_hash);
        println!("Validator ID: {:?}", validator_id);

        Ok(tx_hash)
    }

    /// Create threshold escrow
    pub fn create_threshold_escrow(
        node_url: &str,
        amount: Balance,
        threshold: u32,
        participants: u32,
        timelock_period: BlockNumber,
    ) -> Result<H256, Error> {
        // Connect to node
        let api = PeoChainApi::new(node_url).map_err(|e| Error::Api(e.to_string()))?;
        
        // Generate threshold parameters
        let params = ThresholdParams {
            threshold,
            total_participants: participants,
        };
        
        // Create threshold escrow with network
        let escrow_id = api
            .create_threshold_escrow(amount, timelock_period, params)
            .map_err(|e| Error::Api(e.to_string()))?;
        
        println!("Created threshold escrow with ID: {}", escrow_id);
        println!("Amount: {}", amount);
        println!("Threshold: {}/{}", threshold, participants);
        println!("Timelock period: {} blocks", timelock_period);
        
        Ok(escrow_id)
    }
}

// Helper function to prompt for password
fn prompt_password(prompt: &str) -> Result<String, Error> {
    use rpassword::read_password;
    print!("{}", prompt);
    std::io::Write::flush(&mut std::io::stdout())?;
    let password = read_password().map_err(|e| Error::Io(std::io::Error::new(
        std::io::ErrorKind::Other,
        format!("Failed to read password: {}", e),
    )))?;
    Ok(password)
}
