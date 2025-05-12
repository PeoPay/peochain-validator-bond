use crate::types::{PerformanceProof, ProofOfEscrow, ThresholdParams, ValidatorId};
use sp_core::{sr25519, Pair, H256};
use sp_runtime::MultiSignature;
use std::error::Error as StdError;
use subxt::{
    ClientBuilder, DefaultConfig, PairSigner,
    sp_core::crypto::Ss58Codec,
    sp_runtime::traits::IdentifyAccount,
};

/// API client for interacting with PeoChain
pub struct PeoChainApi {
    client: subxt::Client<DefaultConfig>,
}

/// Error type for API operations
#[derive(Debug)]
pub enum ApiError {
    Subxt(subxt::Error),
    Custom(String),
}

impl From<subxt::Error> for ApiError {
    fn from(err: subxt::Error) -> Self {
        ApiError::Subxt(err)
    }
}

impl From<String> for ApiError {
    fn from(err: String) -> Self {
        ApiError::Custom(err)
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::Subxt(err) => write!(f, "Substrate error: {}", err),
            ApiError::Custom(err) => write!(f, "API error: {}", err),
        }
    }
}

impl StdError for ApiError {}

impl PeoChainApi {
    /// Create a new API client
    pub fn new(node_url: &str) -> Result<Self, ApiError> {
        let client = ClientBuilder::new()
            .set_url(node_url)
            .build()
            .map_err(ApiError::Subxt)?
            .to_owned();

        Ok(Self { client })
    }

    /// Create a non-custodial escrow
    pub async fn create_non_custodial_escrow(
        &self,
        amount: u128,
        timelock_period: u32,
    ) -> Result<H256, ApiError> {
        // In a real implementation, this would:
        // 1. Create a 2-of-2 multisig with the network
        // 2. Lock funds in the escrow
        // 3. Return the escrow ID
        
        // This is a placeholder implementation
        // In a real system, we would call the appropriate runtime API
        
        #[subxt::subxt(runtime_metadata_path = "metadata.scale")]
        pub mod peochain {
            #[subxt::subxt(module = "ValidatorBond")]
            pub mod validator_bond {
                use super::runtime_types;
                
                #[derive(Debug, subxt::Call)]
                pub struct CreateEscrowCall {
                    pub amount: u128,
                    pub timelock_period: u32,
                }
            }
        }
        
        // Create a signer from the default account
        let signer = PairSigner::new(sr25519::Pair::generate().0);
        
        // Create the call
        let call = peochain::validator_bond::CreateEscrowCall {
            amount,
            timelock_period,
        };
        
        // Submit the transaction
        let tx_hash = self.client
            .tx()
            .sign_and_submit_default(&call, &signer)
            .await?;
            
        Ok(tx_hash)
    }

    /// Get escrow details
    pub async fn get_escrow_details(
        &self,
        escrow_id: H256,
    ) -> Result<([u8; 32], u128, u32), ApiError> {
        // In a real implementation, this would:
        // 1. Query the escrow details from the chain
        // 2. Return the escrow address, amount, and timelock height
        
        // This is a placeholder implementation
        // In a real system, we would call the appropriate runtime API
        
        #[subxt::subxt(runtime_metadata_path = "metadata.scale")]
        pub mod peochain {
            #[subxt::subxt(module = "ValidatorBond")]
            pub mod validator_bond {
                use super::runtime_types;
                
                #[derive(Debug, subxt::StorageEntry)]
                pub struct EscrowsEntry {
                    pub escrow_id: ::subxt::sp_core::H256,
                }
                
                #[derive(Debug, PartialEq, Eq, codec::Encode, codec::Decode)]
                pub struct EscrowDetails {
                    pub escrow_address: [u8; 32],
                    pub amount: u128,
                    pub timelock_height: u32,
                }
            }
        }
        
        // Query the escrow details
        let entry = peochain::validator_bond::EscrowsEntry { escrow_id };
        let details: Option<peochain::validator_bond::EscrowDetails> = self.client
            .storage()
            .fetch(&entry)
            .await?;
            
        match details {
            Some(details) => Ok((
                details.escrow_address,
                details.amount,
                details.timelock_height,
            )),
            None => Err(ApiError::Custom(format!("Escrow not found: {:?}", escrow_id))),
        }
    }

    /// Register as a validator
    pub async fn register_validator(
        &self,
        public_key: [u8; 32],
        proof: ProofOfEscrow<sp_core::sr25519::Public, u128, u32, MultiSignature>,
    ) -> Result<H256, ApiError> {
        // In a real implementation, this would:
        // 1. Submit a transaction to register as a validator
        // 2. Return the transaction hash
        
        // This is a placeholder implementation
        // In a real system, we would call the appropriate runtime API
        
        #[subxt::subxt(runtime_metadata_path = "metadata.scale")]
        pub mod peochain {
            #[subxt::subxt(module = "ValidatorBond")]
            pub mod validator_bond {
                use super::runtime_types;
                
                #[derive(Debug, subxt::Call)]
                pub struct BondValidatorCall {
                    pub public_key: [u8; 32],
                    pub proof: runtime_types::validator_bond::ProofOfEscrow<
                        ::subxt::sp_core::sr25519::Public,
                        u128,
                        u32,
                        ::subxt::sp_runtime::MultiSignature,
                    >,
                }
            }
        }
        
        // Create a signer from the account that controls the escrow
        let signer = PairSigner::new(sr25519::Pair::from_string("//Alice", None).unwrap());
        
        // Create the call
        let call = peochain::validator_bond::BondValidatorCall {
            public_key,
            proof,
        };
        
        // Submit the transaction
        let tx_hash = self.client
            .tx()
            .sign_and_submit_default(&call, &signer)
            .await?;
            
        Ok(tx_hash)
    }

    /// Get validator ID from public key
    pub async fn get_validator_id(
        &self,
        public_key: [u8; 32],
    ) -> Result<ValidatorId, ApiError> {
        // In a real implementation, this would:
        // 1. Query the validator ID from the chain
        // 2. Return the validator ID
        
        // This is a placeholder implementation
        // In a real system, we would call the appropriate runtime API
        
        // Derive validator ID from public key using the same algorithm as the runtime
        let hash = sp_io::hashing::blake2_256(&public_key);
        let mut id = [0u8; 32];
        id.copy_from_slice(&hash);
        
        Ok(ValidatorId(id))
    }

    /// Submit performance proof
    pub async fn submit_performance(
        &self,
        proof: PerformanceProof<MultiSignature>,
    ) -> Result<H256, ApiError> {
        // In a real implementation, this would:
        // 1. Submit a transaction with the performance proof
        // 2. Return the transaction hash
        
        // This is a placeholder implementation
        // In a real system, we would call the appropriate runtime API
        
        #[subxt::subxt(runtime_metadata_path = "metadata.scale")]
        pub mod peochain {
            #[subxt::subxt(module = "ValidatorBond")]
            pub mod validator_bond {
                use super::runtime_types;
                
                #[derive(Debug, subxt::Call)]
                pub struct SubmitPerformanceCall {
                    pub proof: runtime_types::validator_bond::PerformanceProof<
                        ::subxt::sp_runtime::MultiSignature,
                    >,
                }
            }
        }
        
        // Create a signer from the default account
        let signer = PairSigner::new(sr25519::Pair::generate().0);
        
        // Create the call
        let call = peochain::validator_bond::SubmitPerformanceCall {
            proof,
        };
        
        // Submit the transaction
        let tx_hash = self.client
            .tx()
            .sign_and_submit_default(&call, &signer)
            .await?;
            
        Ok(tx_hash)
    }

    /// Unbond validator
    pub async fn unbond(
        &self,
        validator_id: ValidatorId,
        pair: sr25519::Pair,
    ) -> Result<H256, ApiError> {
        // In a real implementation, this would:
        // 1. Submit a transaction to unbond the validator
        // 2. Return the transaction hash
        
        // This is a placeholder implementation
        // In a real system, we would call the appropriate runtime API
        
        #[subxt::subxt(runtime_metadata_path = "metadata.scale")]
        pub mod peochain {
            #[subxt::subxt(module = "ValidatorBond")]
            pub mod validator_bond {
                use super::runtime_types;
                
                #[derive(Debug, subxt::Call)]
                pub struct UnbondCall {
                    pub validator_id: runtime_types::validator_bond::ValidatorId,
                }
            }
        }
        
        // Create a signer from the provided keypair
        let signer = PairSigner::new(pair);
        
        // Create the call
        let call = peochain::validator_bond::UnbondCall {
            validator_id,
        };
        
        // Submit the transaction
        let tx_hash = self.client
            .tx()
            .sign_and_submit_default(&call, &signer)
            .await?;
            
        Ok(tx_hash)
    }

    /// Create threshold escrow
    pub async fn create_threshold_escrow(
        &self,
        amount: u128,
        timelock_period: u32,
        params: ThresholdParams,
    ) -> Result<H256, ApiError> {
        // In a real implementation, this would:
        // 1. Create a threshold signature escrow
        // 2. Lock funds in the escrow
        // 3. Return the escrow ID
        
        // This is a placeholder implementation
        // In a real system, we would call the appropriate runtime API
        
        #[subxt::subxt(runtime_metadata_path = "metadata.scale")]
        pub mod peochain {
            #[subxt::subxt(module = "ValidatorBond")]
            pub mod validator_bond {
                use super::runtime_types;
                
                #[derive(Debug, subxt::Call)]
                pub struct CreateThresholdEscrowCall {
                    pub amount: u128,
                    pub timelock_period: u32,
                    pub threshold: u32,
                    pub total_participants: u32,
                }
            }
        }
        
        // Create a signer from the default account
        let signer = PairSigner::new(sr25519::Pair::generate().0);
        
        // Create the call
        let call = peochain::validator_bond::CreateThresholdEscrowCall {
            amount,
            timelock_period,
            threshold: params.threshold,
            total_participants: params.total_participants,
        };
        
        // Submit the transaction
        let tx_hash = self.client
            .tx()
            .sign_and_submit_default(&call, &signer)
            .await?;
            
        Ok(tx_hash)
    }
}
