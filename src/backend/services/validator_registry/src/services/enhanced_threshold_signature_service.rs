use anyhow::Result;
use sp_core::H256;
use uuid::Uuid;
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::models::threshold_signature::{
    ThresholdSchemeConfig, ThresholdSchemeType, ThresholdParams,
    ThresholdParticipant, ValidatorKeyShare, SignatureShare,
    ThresholdSignature, SigningSession, SigningSessionStatus,
    KeyRotationEvent, KeyRotationStatus,
};
use crate::repositories::threshold_signature_repository::ThresholdSignatureRepository;
use crate::repositories::transactional_threshold_signature_repository::TransactionalThresholdSignatureRepository;
use crate::utils::threshold_crypto::{ThresholdCrypto, ThresholdEcdsa, ThresholdParams as CryptoParams, KeyShare};

/// Enhanced service for managing threshold signatures with transactional support
pub struct EnhancedThresholdSignatureService {
    repository: Arc<dyn ThresholdSignatureRepository + Send + Sync>,
    transactional_repository: Arc<TransactionalThresholdSignatureRepository>,
    active_sessions: Arc<RwLock<BTreeMap<Uuid, SigningSession>>>,
}

impl EnhancedThresholdSignatureService {
    /// Create a new enhanced threshold signature service
    pub fn new(
        repository: Arc<dyn ThresholdSignatureRepository + Send + Sync>,
        transactional_repository: Arc<TransactionalThresholdSignatureRepository>,
    ) -> Self {
        Self {
            repository,
            transactional_repository,
            active_sessions: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }
    
    /// Create a new threshold signature scheme with transactional support
    pub async fn create_threshold_scheme(
        &self,
        scheme_type: ThresholdSchemeType,
        threshold: usize,
        total_participants: usize,
    ) -> Result<Uuid> {
        // Validate parameters
        if threshold == 0 || total_participants == 0 || threshold > total_participants {
            return Err(anyhow::anyhow!("Invalid threshold parameters"));
        }
        
        // Create scheme configuration
        let now = chrono::Utc::now().timestamp();
        let scheme_id = Uuid::new_v4();
        
        let scheme = ThresholdSchemeConfig {
            id: scheme_id,
            scheme_type: scheme_type.clone(),
            params: ThresholdParams {
                threshold,
                total_participants,
            },
            created_at: now,
            updated_at: now,
        };
        
        // Generate key shares
        let crypto_params = CryptoParams {
            threshold,
            total_participants,
        };
        
        let key_shares = match scheme_type {
            ThresholdSchemeType::BLS => ThresholdCrypto::generate_key_shares(&crypto_params)?,
            ThresholdSchemeType::ECDSA => ThresholdEcdsa::generate_key_shares(&crypto_params)?,
        };
        
        // Create participants
        let mut participants = Vec::with_capacity(key_shares.len());
        
        for key_share in key_shares {
            let participant = ThresholdParticipant {
                id: Uuid::new_v4(),
                scheme_id,
                index: key_share.index,
                public_share: key_share.public_share.clone(),
                verification_vector: key_share.verification_vector.clone(),
                created_at: now,
            };
            
            participants.push(participant);
        }
        
        // Store scheme and participants in a single transaction
        self.transactional_repository.create_threshold_scheme_with_participants(scheme, participants).await
    }
    
    /// Assign key shares to validators with transactional support
    pub async fn assign_key_shares(
        &self,
        scheme_id: Uuid,
        validator_ids: &[H256],
        encrypted_shares: &[Vec<u8>],
    ) -> Result<()> {
        // Validate input
        if validator_ids.len() != encrypted_shares.len() {
            return Err(anyhow::anyhow!("Validator IDs and encrypted shares count mismatch"));
        }
        
        // Get scheme configuration
        let scheme = self.repository.get_threshold_scheme(scheme_id).await?
            .ok_or_else(|| anyhow::anyhow!("Threshold scheme not found"))?;
        
        // Get participants
        let participants = self.repository.get_threshold_participants(scheme_id).await?;
        
        if participants.len() != scheme.params.total_participants {
            return Err(anyhow::anyhow!("Participants count mismatch"));
        }
        
        // Create key shares for validators
        let now = chrono::Utc::now().timestamp();
        let mut key_shares = Vec::with_capacity(validator_ids.len());
        
        for (i, (validator_id, encrypted_share)) in validator_ids.iter().zip(encrypted_shares.iter()).enumerate() {
            if i >= participants.len() {
                break;
            }
            
            let participant = &participants[i];
            
            let key_share = ValidatorKeyShare {
                id: Uuid::new_v4(),
                validator_id: *validator_id,
                scheme_id,
                participant_index: participant.index,
                encrypted_secret_share: encrypted_share.clone(),
                created_at: now,
                updated_at: now,
            };
            
            key_shares.push(key_share);
        }
        
        // Store key shares in a single transaction
        self.transactional_repository.assign_key_shares_tx(key_shares).await
    }
    
    /// Start a new signing session
    pub async fn start_signing_session(
        &self,
        scheme_id: Uuid,
        message_hash: H256,
    ) -> Result<Uuid> {
        // Get scheme configuration
        let scheme = self.repository.get_threshold_scheme(scheme_id).await?
            .ok_or_else(|| anyhow::anyhow!("Threshold scheme not found"))?;
        
        // Check if there's already an active session for this message
        let existing_signature = self.repository.get_threshold_signature(scheme_id, message_hash).await?;
        
        if existing_signature.is_some() {
            return Err(anyhow::anyhow!("Signature already exists for this message"));
        }
        
        // Create a new signing session
        let now = chrono::Utc::now().timestamp();
        let session_id = Uuid::new_v4();
        
        let session = SigningSession {
            id: session_id,
            scheme_id,
            message_hash,
            status: SigningSessionStatus::Active,
            signature_shares: BTreeMap::new(),
            threshold_signature: None,
            created_at: now,
            updated_at: now,
            expires_at: now + 3600, // 1 hour expiration
        };
        
        // Store the session
        self.repository.create_signing_session(session.clone()).await?;
        
        // Add to active sessions
        let mut active_sessions = self.active_sessions.write().await;
        active_sessions.insert(session_id, session);
        
        Ok(session_id)
    }
    
    /// Submit a signature share to a signing session with transactional support
    pub async fn submit_signature_share(
        &self,
        session_id: Uuid,
        validator_id: H256,
        share: Vec<u8>,
    ) -> Result<bool> {
        // Get the signing session
        let session = self.repository.get_signing_session(session_id).await?
            .ok_or_else(|| anyhow::anyhow!("Signing session not found"))?;
        
        if session.status != SigningSessionStatus::Active {
            return Err(anyhow::anyhow!("Signing session is not active"));
        }
        
        // Get the validator's key share
        let key_share = self.repository.get_validator_key_share(validator_id, session.scheme_id).await?
            .ok_or_else(|| anyhow::anyhow!("Validator key share not found"))?;
        
        // Get scheme configuration
        let scheme = self.repository.get_threshold_scheme(session.scheme_id).await?
            .ok_or_else(|| anyhow::anyhow!("Threshold scheme not found"))?;
        
        // Create the signature share
        let now = chrono::Utc::now().timestamp();
        let signature_share = SignatureShare {
            id: Uuid::new_v4(),
            validator_id,
            scheme_id: session.scheme_id,
            participant_index: key_share.participant_index,
            message_hash: session.message_hash,
            share: share.clone(),
            created_at: now,
        };
        
        // Update the session with the new share
        let mut updated_session = session.clone();
        updated_session.signature_shares.insert(key_share.participant_index, share);
        updated_session.updated_at = now;
        
        // Check if we have enough shares to create a threshold signature
        let threshold_reached = updated_session.signature_shares.len() >= scheme.params.threshold;
        
        let mut threshold_signature = None;
        
        if threshold_reached {
            // Get all participants for the scheme
            let participants = self.repository.get_threshold_participants(session.scheme_id).await?;
            
            // Extract public key shares
            let mut public_shares = Vec::with_capacity(participants.len());
            for participant in &participants {
                public_shares.push(participant.public_share.clone());
            }
            
            // Derive the aggregated public key
            let public_key = match scheme.scheme_type {
                ThresholdSchemeType::BLS => ThresholdCrypto::derive_aggregated_public_key(&public_shares)?,
                ThresholdSchemeType::ECDSA => {
                    // For ECDSA, we would need a different approach
                    // This is a placeholder
                    Vec::new()
                },
            };
            
            // Convert signature shares to the format expected by the crypto module
            let mut crypto_shares = Vec::with_capacity(updated_session.signature_shares.len());
            for (index, share) in &updated_session.signature_shares {
                crypto_shares.push(crate::utils::threshold_crypto::SignatureShare {
                    index: *index,
                    share: share.clone(),
                });
            }
            
            // Aggregate the signature shares
            let crypto_params = CryptoParams {
                threshold: scheme.params.threshold,
                total_participants: scheme.params.total_participants,
            };
            
            let message = session.message_hash.as_bytes();
            
            let aggregated_signature = match scheme.scheme_type {
                ThresholdSchemeType::BLS => ThresholdCrypto::aggregate_signature_shares(
                    &crypto_params,
                    message,
                    &crypto_shares,
                    &public_key,
                )?,
                ThresholdSchemeType::ECDSA => ThresholdEcdsa::aggregate_signature_shares(
                    &crypto_params,
                    message,
                    &crypto_shares,
                    &public_key,
                )?,
            };
            
            // Update the session with the threshold signature
            updated_session.threshold_signature = Some(aggregated_signature.clone());
            updated_session.status = SigningSessionStatus::Completed;
            
            // Create the threshold signature
            threshold_signature = Some(ThresholdSignature {
                id: Uuid::new_v4(),
                scheme_id: session.scheme_id,
                message_hash: session.message_hash,
                signature: aggregated_signature,
                participant_indices: updated_session.signature_shares.keys().cloned().collect(),
                created_at: now,
            });
        }
        
        // Store the signature share, update the session, and potentially store the threshold signature
        // in a single transaction
        self.transactional_repository.process_signature_share(
            signature_share,
            updated_session.clone(),
            threshold_signature,
        ).await?;
        
        // Update active sessions
        let mut active_sessions = self.active_sessions.write().await;
        if threshold_reached {
            active_sessions.remove(&session_id);
        } else {
            active_sessions.insert(session_id, updated_session);
        }
        
        Ok(threshold_reached)
    }
    
    /// Verify a threshold signature
    pub async fn verify_threshold_signature(
        &self,
        scheme_id: Uuid,
        message_hash: H256,
        signature: &[u8],
    ) -> Result<bool> {
        // Get scheme configuration
        let scheme = self.repository.get_threshold_scheme(scheme_id).await?
            .ok_or_else(|| anyhow::anyhow!("Threshold scheme not found"))?;
        
        // Get all participants for the scheme
        let participants = self.repository.get_threshold_participants(scheme_id).await?;
        
        // Extract public key shares
        let mut public_shares = Vec::with_capacity(participants.len());
        for participant in &participants {
            public_shares.push(participant.public_share.clone());
        }
        
        // Derive the aggregated public key
        let public_key = match scheme.scheme_type {
            ThresholdSchemeType::BLS => ThresholdCrypto::derive_aggregated_public_key(&public_shares)?,
            ThresholdSchemeType::ECDSA => {
                // For ECDSA, we would need a different approach
                // This is a placeholder
                Vec::new()
            },
        };
        
        // Verify the signature
        let message = message_hash.as_bytes();
        
        let result = match scheme.scheme_type {
            ThresholdSchemeType::BLS => ThresholdCrypto::verify_threshold_signature(
                message,
                signature,
                &public_key,
            )?,
            ThresholdSchemeType::ECDSA => ThresholdEcdsa::verify_threshold_signature(
                message,
                signature,
                &public_key,
            )?,
        };
        
        Ok(result)
    }
    
    /// Initiate a key rotation for a threshold scheme
    pub async fn initiate_key_rotation(
        &self,
        scheme_id: Uuid,
        new_threshold: Option<usize>,
        new_total_participants: Option<usize>,
    ) -> Result<Uuid> {
        // Get the current scheme
        let current_scheme = self.repository.get_threshold_scheme(scheme_id).await?
            .ok_or_else(|| anyhow::anyhow!("Threshold scheme not found"))?;
        
        // Determine new parameters
        let new_threshold = new_threshold.unwrap_or(current_scheme.params.threshold);
        let new_total_participants = new_total_participants.unwrap_or(current_scheme.params.total_participants);
        
        // Validate parameters
        if new_threshold == 0 || new_total_participants == 0 || new_threshold > new_total_participants {
            return Err(anyhow::anyhow!("Invalid threshold parameters"));
        }
        
        // Create a key rotation event
        let now = chrono::Utc::now().timestamp();
        let rotation_id = Uuid::new_v4();
        
        let rotation = KeyRotationEvent {
            id: rotation_id,
            scheme_id,
            previous_params: current_scheme.params.clone(),
            new_params: ThresholdParams {
                threshold: new_threshold,
                total_participants: new_total_participants,
            },
            status: KeyRotationStatus::InProgress,
            created_at: now,
            updated_at: now,
        };
        
        // Store the rotation event
        self.repository.store_key_rotation_event(rotation).await?;
        
        Ok(rotation_id)
    }
    
    /// Complete a key rotation with transactional support
    pub async fn complete_key_rotation(
        &self,
        rotation_id: Uuid,
    ) -> Result<()> {
        // Get the key rotation event
        let event = self.repository.get_key_rotation_events(rotation_id).await?
            .into_iter()
            .find(|e| e.id == rotation_id)
            .ok_or_else(|| anyhow::anyhow!("Key rotation event not found"))?;
        
        if event.status != KeyRotationStatus::InProgress {
            return Err(anyhow::anyhow!("Key rotation is not in progress"));
        }
        
        // Get the current scheme
        let current_scheme = self.repository.get_threshold_scheme(event.scheme_id).await?
            .ok_or_else(|| anyhow::anyhow!("Threshold scheme not found"))?;
        
        // Create a new scheme with the new parameters
        let now = chrono::Utc::now().timestamp();
        let new_scheme_id = Uuid::new_v4();
        
        let new_scheme = ThresholdSchemeConfig {
            id: new_scheme_id,
            scheme_type: current_scheme.scheme_type.clone(),
            params: event.new_params.clone(),
            created_at: now,
            updated_at: now,
        };
        
        // Generate new key shares
        let crypto_params = CryptoParams {
            threshold: event.new_params.threshold,
            total_participants: event.new_params.total_participants,
        };
        
        let key_shares = match current_scheme.scheme_type {
            ThresholdSchemeType::BLS => ThresholdCrypto::generate_key_shares(&crypto_params)?,
            ThresholdSchemeType::ECDSA => ThresholdEcdsa::generate_key_shares(&crypto_params)?,
        };
        
        // Create new participants
        let mut new_participants = Vec::with_capacity(key_shares.len());
        
        for key_share in key_shares {
            let participant = ThresholdParticipant {
                id: Uuid::new_v4(),
                scheme_id: new_scheme_id,
                index: key_share.index,
                public_share: key_share.public_share.clone(),
                verification_vector: key_share.verification_vector.clone(),
                created_at: now,
            };
            
            new_participants.push(participant);
        }
        
        // Complete the key rotation in a single transaction
        self.transactional_repository.complete_key_rotation_tx(
            event,
            new_scheme,
            new_participants,
        ).await?;
        
        Ok(())
    }
    
    /// Clean up expired signing sessions
    pub async fn cleanup_expired_sessions(&self) -> Result<usize> {
        let now = chrono::Utc::now().timestamp();
        let mut count = 0;
        
        // Get all active schemes
        let schemes = self.repository.get_all_threshold_schemes().await?;
        
        for scheme in schemes {
            // Get active sessions for the scheme
            let active_sessions = self.repository.get_active_signing_sessions(scheme.id).await?;
            
            for session in active_sessions {
                if session.expires_at < now {
                    // Update session status to expired
                    let mut updated_session = session.clone();
                    updated_session.status = SigningSessionStatus::Expired;
                    updated_session.updated_at = now;
                    
                    self.repository.update_signing_session(updated_session).await?;
                    
                    // Remove from active sessions
                    let mut active_sessions = self.active_sessions.write().await;
                    active_sessions.remove(&session.id);
                    
                    count += 1;
                }
            }
        }
        
        Ok(count)
    }
}
