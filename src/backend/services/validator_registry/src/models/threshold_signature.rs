use serde::{Deserialize, Serialize};
use sp_core::H256;
use uuid::Uuid;
use std::collections::BTreeMap;

/// Represents a threshold signature scheme configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdSchemeConfig {
    /// Unique identifier for the threshold scheme
    pub id: Uuid,
    /// Type of threshold signature scheme (BLS or ECDSA)
    pub scheme_type: ThresholdSchemeType,
    /// Threshold parameters
    pub params: ThresholdParams,
    /// Creation timestamp
    pub created_at: i64,
    /// Last update timestamp
    pub updated_at: i64,
}

/// Type of threshold signature scheme
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ThresholdSchemeType {
    /// BLS threshold signature scheme
    BLS,
    /// ECDSA threshold signature scheme
    ECDSA,
}

/// Threshold parameters for the signature scheme
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdParams {
    /// Minimum number of participants required for signing
    pub threshold: usize,
    /// Total number of participants
    pub total_participants: usize,
}

/// Represents a participant in a threshold signature scheme
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdParticipant {
    /// Unique identifier for the participant
    pub id: Uuid,
    /// Reference to the threshold scheme
    pub scheme_id: Uuid,
    /// Index of the participant (1-indexed)
    pub index: usize,
    /// Public key share
    pub public_share: Vec<u8>,
    /// Verification vector for the share
    pub verification_vector: Vec<Vec<u8>>,
    /// Creation timestamp
    pub created_at: i64,
}

/// Represents a key share for a validator in a threshold scheme
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorKeyShare {
    /// Unique identifier for the key share
    pub id: Uuid,
    /// Reference to the validator
    pub validator_id: H256,
    /// Reference to the threshold scheme
    pub scheme_id: Uuid,
    /// Index of the participant (1-indexed)
    pub participant_index: usize,
    /// Encrypted secret key share (encrypted with validator's public key)
    pub encrypted_secret_share: Vec<u8>,
    /// Creation timestamp
    pub created_at: i64,
    /// Last update timestamp
    pub updated_at: i64,
}

/// Represents a signature share from a validator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureShare {
    /// Unique identifier for the signature share
    pub id: Uuid,
    /// Reference to the validator
    pub validator_id: H256,
    /// Reference to the threshold scheme
    pub scheme_id: Uuid,
    /// Index of the participant (1-indexed)
    pub participant_index: usize,
    /// Message that was signed
    pub message_hash: H256,
    /// Signature share data
    pub share: Vec<u8>,
    /// Creation timestamp
    pub created_at: i64,
}

/// Represents a complete threshold signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdSignature {
    /// Unique identifier for the threshold signature
    pub id: Uuid,
    /// Reference to the threshold scheme
    pub scheme_id: Uuid,
    /// Message that was signed
    pub message_hash: H256,
    /// Aggregated signature
    pub signature: Vec<u8>,
    /// Indices of participants who contributed to the signature
    pub participant_indices: Vec<usize>,
    /// Creation timestamp
    pub created_at: i64,
}

/// Represents a threshold signing session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningSession {
    /// Unique identifier for the signing session
    pub id: Uuid,
    /// Reference to the threshold scheme
    pub scheme_id: Uuid,
    /// Message to be signed
    pub message_hash: H256,
    /// Status of the signing session
    pub status: SigningSessionStatus,
    /// Collected signature shares
    pub signature_shares: BTreeMap<usize, Vec<u8>>,
    /// Resulting threshold signature (if completed)
    pub threshold_signature: Option<Vec<u8>>,
    /// Creation timestamp
    pub created_at: i64,
    /// Last update timestamp
    pub updated_at: i64,
    /// Expiration timestamp
    pub expires_at: i64,
}

/// Status of a signing session
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SigningSessionStatus {
    /// Session is active and collecting signature shares
    Active,
    /// Session has completed successfully
    Completed,
    /// Session has failed
    Failed,
    /// Session has expired
    Expired,
}

/// Represents a key rotation event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotationEvent {
    /// Unique identifier for the key rotation
    pub id: Uuid,
    /// Reference to the threshold scheme
    pub scheme_id: Uuid,
    /// Previous threshold parameters
    pub previous_params: ThresholdParams,
    /// New threshold parameters
    pub new_params: ThresholdParams,
    /// Status of the key rotation
    pub status: KeyRotationStatus,
    /// Creation timestamp
    pub created_at: i64,
    /// Last update timestamp
    pub updated_at: i64,
}

/// Status of a key rotation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeyRotationStatus {
    /// Key rotation is in progress
    InProgress,
    /// Key rotation has completed successfully
    Completed,
    /// Key rotation has failed
    Failed,
}
