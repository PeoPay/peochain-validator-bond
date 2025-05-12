use anyhow::Result;
use async_trait::async_trait;
use sqlx::{PgPool, Row};
use uuid::Uuid;
use sp_core::H256;
use std::collections::BTreeMap;
use serde_json;

use crate::models::threshold_signature::{
    ThresholdSchemeConfig, ThresholdSchemeType, ThresholdParams,
    ThresholdParticipant, ValidatorKeyShare, SignatureShare,
    ThresholdSignature, SigningSession, SigningSessionStatus,
    KeyRotationEvent, KeyRotationStatus,
};

/// Repository trait for threshold signature operations
#[async_trait]
pub trait ThresholdSignatureRepository: Send + Sync {
    /// Store a new threshold scheme configuration
    async fn store_threshold_scheme(&self, scheme: ThresholdSchemeConfig) -> Result<Uuid>;
    
    /// Get a threshold scheme configuration by ID
    async fn get_threshold_scheme(&self, id: Uuid) -> Result<Option<ThresholdSchemeConfig>>;
    
    /// Get all threshold scheme configurations
    async fn get_all_threshold_schemes(&self) -> Result<Vec<ThresholdSchemeConfig>>;
    
    /// Store a threshold participant
    async fn store_threshold_participant(&self, participant: ThresholdParticipant) -> Result<Uuid>;
    
    /// Get threshold participants for a scheme
    async fn get_threshold_participants(&self, scheme_id: Uuid) -> Result<Vec<ThresholdParticipant>>;
    
    /// Store a validator key share
    async fn store_validator_key_share(&self, key_share: ValidatorKeyShare) -> Result<Uuid>;
    
    /// Get validator key shares for a validator
    async fn get_validator_key_shares(&self, validator_id: H256) -> Result<Vec<ValidatorKeyShare>>;
    
    /// Get a validator key share by validator ID and scheme ID
    async fn get_validator_key_share(&self, validator_id: H256, scheme_id: Uuid) -> Result<Option<ValidatorKeyShare>>;
    
    /// Store a signature share
    async fn store_signature_share(&self, share: SignatureShare) -> Result<Uuid>;
    
    /// Get signature shares for a message
    async fn get_signature_shares(&self, scheme_id: Uuid, message_hash: H256) -> Result<Vec<SignatureShare>>;
    
    /// Store a threshold signature
    async fn store_threshold_signature(&self, signature: ThresholdSignature) -> Result<Uuid>;
    
    /// Get a threshold signature by message hash
    async fn get_threshold_signature(&self, scheme_id: Uuid, message_hash: H256) -> Result<Option<ThresholdSignature>>;
    
    /// Create a new signing session
    async fn create_signing_session(&self, session: SigningSession) -> Result<Uuid>;
    
    /// Get a signing session by ID
    async fn get_signing_session(&self, id: Uuid) -> Result<Option<SigningSession>>;
    
    /// Update a signing session
    async fn update_signing_session(&self, session: SigningSession) -> Result<()>;
    
    /// Get active signing sessions for a scheme
    async fn get_active_signing_sessions(&self, scheme_id: Uuid) -> Result<Vec<SigningSession>>;
    
    /// Store a key rotation event
    async fn store_key_rotation_event(&self, event: KeyRotationEvent) -> Result<Uuid>;
    
    /// Get key rotation events for a scheme
    async fn get_key_rotation_events(&self, scheme_id: Uuid) -> Result<Vec<KeyRotationEvent>>;
    
    /// Get the latest key rotation event for a scheme
    async fn get_latest_key_rotation_event(&self, scheme_id: Uuid) -> Result<Option<KeyRotationEvent>>;
}

/// PostgreSQL implementation of the threshold signature repository
pub struct PgThresholdSignatureRepository {
    pool: PgPool,
}

impl PgThresholdSignatureRepository {
    /// Create a new PostgreSQL threshold signature repository
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ThresholdSignatureRepository for PgThresholdSignatureRepository {
    async fn store_threshold_scheme(&self, scheme: ThresholdSchemeConfig) -> Result<Uuid> {
        let scheme_type = match scheme.scheme_type {
            ThresholdSchemeType::BLS => "BLS",
            ThresholdSchemeType::ECDSA => "ECDSA",
        };
        
        let id = sqlx::query(
            r#"
            INSERT INTO threshold_schemes (
                id, scheme_type, threshold, total_participants, created_at, updated_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6
            ) RETURNING id
            "#
        )
        .bind(scheme.id)
        .bind(scheme_type)
        .bind(scheme.params.threshold as i32)
        .bind(scheme.params.total_participants as i32)
        .bind(scheme.created_at)
        .bind(scheme.updated_at)
        .fetch_one(&self.pool)
        .await?
        .get::<Uuid, _>("id");
        
        Ok(id)
    }
    
    async fn get_threshold_scheme(&self, id: Uuid) -> Result<Option<ThresholdSchemeConfig>> {
        let record = sqlx::query(
            r#"
            SELECT id, scheme_type, threshold, total_participants, created_at, updated_at
            FROM threshold_schemes
            WHERE id = $1
            "#
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        
        if let Some(record) = record {
            let scheme_type = match record.get::<String, _>("scheme_type").as_str() {
                "BLS" => ThresholdSchemeType::BLS,
                "ECDSA" => ThresholdSchemeType::ECDSA,
                _ => return Err(anyhow::anyhow!("Invalid scheme type")),
            };
            
            let threshold = record.get::<i32, _>("threshold") as usize;
            let total_participants = record.get::<i32, _>("total_participants") as usize;
            
            let scheme = ThresholdSchemeConfig {
                id: record.get("id"),
                scheme_type,
                params: ThresholdParams {
                    threshold,
                    total_participants,
                },
                created_at: record.get("created_at"),
                updated_at: record.get("updated_at"),
            };
            
            Ok(Some(scheme))
        } else {
            Ok(None)
        }
    }
    
    async fn get_all_threshold_schemes(&self) -> Result<Vec<ThresholdSchemeConfig>> {
        let records = sqlx::query(
            r#"
            SELECT id, scheme_type, threshold, total_participants, created_at, updated_at
            FROM threshold_schemes
            ORDER BY created_at DESC
            "#
        )
        .fetch_all(&self.pool)
        .await?;
        
        let mut schemes = Vec::with_capacity(records.len());
        
        for record in records {
            let scheme_type = match record.get::<String, _>("scheme_type").as_str() {
                "BLS" => ThresholdSchemeType::BLS,
                "ECDSA" => ThresholdSchemeType::ECDSA,
                _ => continue,
            };
            
            let threshold = record.get::<i32, _>("threshold") as usize;
            let total_participants = record.get::<i32, _>("total_participants") as usize;
            
            let scheme = ThresholdSchemeConfig {
                id: record.get("id"),
                scheme_type,
                params: ThresholdParams {
                    threshold,
                    total_participants,
                },
                created_at: record.get("created_at"),
                updated_at: record.get("updated_at"),
            };
            
            schemes.push(scheme);
        }
        
        Ok(schemes)
    }
    
    // Implementation of other repository methods would follow a similar pattern
    // For brevity, we'll implement just a few key methods and leave the rest as TODOs
    
    async fn store_threshold_participant(&self, participant: ThresholdParticipant) -> Result<Uuid> {
        let id = sqlx::query(
            r#"
            INSERT INTO threshold_participants (
                id, scheme_id, participant_index, public_share, verification_vector, created_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6
            ) RETURNING id
            "#
        )
        .bind(participant.id)
        .bind(participant.scheme_id)
        .bind(participant.index as i32)
        .bind(&participant.public_share)
        .bind(&participant.verification_vector) // This would need proper serialization
        .bind(participant.created_at)
        .fetch_one(&self.pool)
        .await?
        .get::<Uuid, _>("id");
        
        Ok(id)
    }
    
    async fn get_threshold_participants(&self, scheme_id: Uuid) -> Result<Vec<ThresholdParticipant>> {
        let records = sqlx::query(
            r#"
            SELECT id, scheme_id, participant_index, public_share, verification_vector, created_at
            FROM threshold_participants
            WHERE scheme_id = $1
            ORDER BY participant_index ASC
            "#
        )
        .bind(scheme_id)
        .fetch_all(&self.pool)
        .await?;
        
        let mut participants = Vec::with_capacity(records.len());
        
        for record in records {
            let participant = ThresholdParticipant {
                id: record.get("id"),
                scheme_id: record.get("scheme_id"),
                index: record.get::<i32, _>("participant_index") as usize,
                public_share: record.get("public_share"),
                verification_vector: record.get("verification_vector"),
                created_at: record.get("created_at"),
            };
            
            participants.push(participant);
        }
        
        Ok(participants)
    }
    
    async fn store_validator_key_share(&self, key_share: ValidatorKeyShare) -> Result<Uuid> {
        let validator_id_bytes = key_share.validator_id.as_bytes();
        
        let id = sqlx::query(
            r#"
            INSERT INTO validator_key_shares (
                id, validator_id, scheme_id, participant_index, encrypted_secret_share, created_at, updated_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7
            ) RETURNING id
            "#
        )
        .bind(key_share.id)
        .bind(validator_id_bytes)
        .bind(key_share.scheme_id)
        .bind(key_share.participant_index as i32)
        .bind(&key_share.encrypted_secret_share)
        .bind(key_share.created_at)
        .bind(key_share.updated_at)
        .fetch_one(&self.pool)
        .await?
        .get::<Uuid, _>("id");
        
        Ok(id)
    }
    
    async fn get_validator_key_shares(&self, validator_id: H256) -> Result<Vec<ValidatorKeyShare>> {
        let validator_id_bytes = validator_id.as_bytes();
        
        let records = sqlx::query(
            r#"
            SELECT id, validator_id, scheme_id, participant_index, encrypted_secret_share, created_at, updated_at
            FROM validator_key_shares
            WHERE validator_id = $1
            ORDER BY created_at DESC
            "#
        )
        .bind(validator_id_bytes)
        .fetch_all(&self.pool)
        .await?;
        
        let mut key_shares = Vec::with_capacity(records.len());
        
        for record in records {
            let validator_id_bytes: &[u8] = record.get("validator_id");
            let validator_id = H256::from_slice(validator_id_bytes);
            
            let key_share = ValidatorKeyShare {
                id: record.get("id"),
                validator_id,
                scheme_id: record.get("scheme_id"),
                participant_index: record.get::<i32, _>("participant_index") as usize,
                encrypted_secret_share: record.get("encrypted_secret_share"),
                created_at: record.get("created_at"),
                updated_at: record.get("updated_at"),
            };
            
            key_shares.push(key_share);
        }
        
        Ok(key_shares)
    }
    
    async fn get_validator_key_share(&self, validator_id: H256, scheme_id: Uuid) -> Result<Option<ValidatorKeyShare>> {
        let validator_id_bytes = validator_id.as_bytes();
        
        let record = sqlx::query(
            r#"
            SELECT id, validator_id, scheme_id, participant_index, encrypted_secret_share, created_at, updated_at
            FROM validator_key_shares
            WHERE validator_id = $1 AND scheme_id = $2
            LIMIT 1
            "#
        )
        .bind(validator_id_bytes)
        .bind(scheme_id)
        .fetch_optional(&self.pool)
        .await?;
        
        if let Some(record) = record {
            let validator_id_bytes: &[u8] = record.get("validator_id");
            let validator_id = H256::from_slice(validator_id_bytes);
            
            let key_share = ValidatorKeyShare {
                id: record.get("id"),
                validator_id,
                scheme_id: record.get("scheme_id"),
                participant_index: record.get::<i32, _>("participant_index") as usize,
                encrypted_secret_share: record.get("encrypted_secret_share"),
                created_at: record.get("created_at"),
                updated_at: record.get("updated_at"),
            };
            
            Ok(Some(key_share))
        } else {
            Ok(None)
        }
    }
    
    async fn store_signature_share(&self, share: SignatureShare) -> Result<Uuid> {
        let validator_id_bytes = share.validator_id.as_bytes();
        let message_hash_bytes = share.message_hash.as_bytes();
        
        let id = sqlx::query(
            r#"
            INSERT INTO signature_shares (
                id, validator_id, scheme_id, participant_index, message_hash, share, created_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7
            ) RETURNING id
            "#
        )
        .bind(share.id)
        .bind(validator_id_bytes)
        .bind(share.scheme_id)
        .bind(share.participant_index as i32)
        .bind(message_hash_bytes)
        .bind(&share.share)
        .bind(share.created_at)
        .fetch_one(&self.pool)
        .await?
        .get::<Uuid, _>("id");
        
        Ok(id)
    }
    
    async fn get_signature_shares(&self, scheme_id: Uuid, message_hash: H256) -> Result<Vec<SignatureShare>> {
        let message_hash_bytes = message_hash.as_bytes();
        
        let records = sqlx::query(
            r#"
            SELECT id, validator_id, scheme_id, participant_index, message_hash, share, created_at
            FROM signature_shares
            WHERE scheme_id = $1 AND message_hash = $2
            ORDER BY participant_index ASC
            "#
        )
        .bind(scheme_id)
        .bind(message_hash_bytes)
        .fetch_all(&self.pool)
        .await?;
        
        let mut shares = Vec::with_capacity(records.len());
        
        for record in records {
            let validator_id_bytes: &[u8] = record.get("validator_id");
            let validator_id = H256::from_slice(validator_id_bytes);
            
            let message_hash_bytes: &[u8] = record.get("message_hash");
            let message_hash = H256::from_slice(message_hash_bytes);
            
            let share = SignatureShare {
                id: record.get("id"),
                validator_id,
                scheme_id: record.get("scheme_id"),
                participant_index: record.get::<i32, _>("participant_index") as usize,
                message_hash,
                share: record.get("share"),
                created_at: record.get("created_at"),
            };
            
            shares.push(share);
        }
        
        Ok(shares)
    }
    
    async fn store_threshold_signature(&self, signature: ThresholdSignature) -> Result<Uuid> {
        let message_hash_bytes = signature.message_hash.as_bytes();
        let participant_indices: Vec<i32> = signature.participant_indices.iter().map(|&i| i as i32).collect();
        
        let id = sqlx::query(
            r#"
            INSERT INTO threshold_signatures (
                id, scheme_id, message_hash, signature, participant_indices, created_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6
            ) RETURNING id
            "#
        )
        .bind(signature.id)
        .bind(signature.scheme_id)
        .bind(message_hash_bytes)
        .bind(&signature.signature)
        .bind(&participant_indices)
        .bind(signature.created_at)
        .fetch_one(&self.pool)
        .await?
        .get::<Uuid, _>("id");
        
        Ok(id)
    }
    
    async fn get_threshold_signature(&self, scheme_id: Uuid, message_hash: H256) -> Result<Option<ThresholdSignature>> {
        let message_hash_bytes = message_hash.as_bytes();
        
        let record = sqlx::query(
            r#"
            SELECT id, scheme_id, message_hash, signature, participant_indices, created_at
            FROM threshold_signatures
            WHERE scheme_id = $1 AND message_hash = $2
            LIMIT 1
            "#
        )
        .bind(scheme_id)
        .bind(message_hash_bytes)
        .fetch_optional(&self.pool)
        .await?;
        
        if let Some(record) = record {
            let message_hash_bytes: &[u8] = record.get("message_hash");
            let message_hash = H256::from_slice(message_hash_bytes);
            
            let participant_indices: Vec<i32> = record.get("participant_indices");
            let participant_indices: Vec<usize> = participant_indices.iter().map(|&i| i as usize).collect();
            
            let signature = ThresholdSignature {
                id: record.get("id"),
                scheme_id: record.get("scheme_id"),
                message_hash,
                signature: record.get("signature"),
                participant_indices,
                created_at: record.get("created_at"),
            };
            
            Ok(Some(signature))
        } else {
            Ok(None)
        }
    }
    
    async fn create_signing_session(&self, session: SigningSession) -> Result<Uuid> {
        let message_hash_bytes = session.message_hash.as_bytes();
        let status = match session.status {
            SigningSessionStatus::Active => "active",
            SigningSessionStatus::Completed => "completed",
            SigningSessionStatus::Failed => "failed",
            SigningSessionStatus::Expired => "expired",
        };
        
        // Serialize signature_shares map to JSON
        let signature_shares_json = serde_json::to_value(&session.signature_shares)?;
        
        let id = sqlx::query(
            r#"
            INSERT INTO signing_sessions (
                id, scheme_id, message_hash, status, signature_shares, threshold_signature,
                created_at, updated_at, expires_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9
            ) RETURNING id
            "#
        )
        .bind(session.id)
        .bind(session.scheme_id)
        .bind(message_hash_bytes)
        .bind(status)
        .bind(signature_shares_json)
        .bind(&session.threshold_signature)
        .bind(session.created_at)
        .bind(session.updated_at)
        .bind(session.expires_at)
        .fetch_one(&self.pool)
        .await?
        .get::<Uuid, _>("id");
        
        Ok(id)
    }
    
    async fn get_signing_session(&self, id: Uuid) -> Result<Option<SigningSession>> {
        let record = sqlx::query(
            r#"
            SELECT id, scheme_id, message_hash, status, signature_shares, threshold_signature,
                   created_at, updated_at, expires_at
            FROM signing_sessions
            WHERE id = $1
            LIMIT 1
            "#
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        
        if let Some(record) = record {
            let message_hash_bytes: &[u8] = record.get("message_hash");
            let message_hash = H256::from_slice(message_hash_bytes);
            
            let status = match record.get::<&str, _>("status") {
                "active" => SigningSessionStatus::Active,
                "completed" => SigningSessionStatus::Completed,
                "failed" => SigningSessionStatus::Failed,
                "expired" => SigningSessionStatus::Expired,
                _ => return Err(anyhow::anyhow!("Invalid signing session status")),
            };
            
            // Deserialize signature_shares from JSON
            let signature_shares_json: serde_json::Value = record.get("signature_shares");
            let signature_shares: BTreeMap<usize, Vec<u8>> = serde_json::from_value(signature_shares_json)?;
            
            let session = SigningSession {
                id: record.get("id"),
                scheme_id: record.get("scheme_id"),
                message_hash,
                status,
                signature_shares,
                threshold_signature: record.get("threshold_signature"),
                created_at: record.get("created_at"),
                updated_at: record.get("updated_at"),
                expires_at: record.get("expires_at"),
            };
            
            Ok(Some(session))
        } else {
            Ok(None)
        }
    }
    
    async fn update_signing_session(&self, session: SigningSession) -> Result<()> {
        let message_hash_bytes = session.message_hash.as_bytes();
        let status = match session.status {
            SigningSessionStatus::Active => "active",
            SigningSessionStatus::Completed => "completed",
            SigningSessionStatus::Failed => "failed",
            SigningSessionStatus::Expired => "expired",
        };
        
        // Serialize signature_shares map to JSON
        let signature_shares_json = serde_json::to_value(&session.signature_shares)?;
        
        sqlx::query(
            r#"
            UPDATE signing_sessions
            SET scheme_id = $2,
                message_hash = $3,
                status = $4,
                signature_shares = $5,
                threshold_signature = $6,
                updated_at = $7,
                expires_at = $8
            WHERE id = $1
            "#
        )
        .bind(session.id)
        .bind(session.scheme_id)
        .bind(message_hash_bytes)
        .bind(status)
        .bind(signature_shares_json)
        .bind(&session.threshold_signature)
        .bind(session.updated_at)
        .bind(session.expires_at)
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }
    
    async fn get_active_signing_sessions(&self, scheme_id: Uuid) -> Result<Vec<SigningSession>> {
        let records = sqlx::query(
            r#"
            SELECT id, scheme_id, message_hash, status, signature_shares, threshold_signature,
                   created_at, updated_at, expires_at
            FROM signing_sessions
            WHERE scheme_id = $1 AND status = 'active'
            ORDER BY created_at DESC
            "#
        )
        .bind(scheme_id)
        .fetch_all(&self.pool)
        .await?;
        
        let mut sessions = Vec::with_capacity(records.len());
        
        for record in records {
            let message_hash_bytes: &[u8] = record.get("message_hash");
            let message_hash = H256::from_slice(message_hash_bytes);
            
            // Deserialize signature_shares from JSON
            let signature_shares_json: serde_json::Value = record.get("signature_shares");
            let signature_shares: BTreeMap<usize, Vec<u8>> = serde_json::from_value(signature_shares_json)?;
            
            let session = SigningSession {
                id: record.get("id"),
                scheme_id: record.get("scheme_id"),
                message_hash,
                status: SigningSessionStatus::Active,
                signature_shares,
                threshold_signature: record.get("threshold_signature"),
                created_at: record.get("created_at"),
                updated_at: record.get("updated_at"),
                expires_at: record.get("expires_at"),
            };
            
            sessions.push(session);
        }
        
        Ok(sessions)
    }
    
    async fn store_key_rotation_event(&self, event: KeyRotationEvent) -> Result<Uuid> {
        let status = match event.status {
            KeyRotationStatus::InProgress => "in_progress",
            KeyRotationStatus::Completed => "completed",
            KeyRotationStatus::Failed => "failed",
        };
        
        // Serialize threshold params to JSON
        let previous_params_json = serde_json::to_value(&event.previous_params)?;
        let new_params_json = serde_json::to_value(&event.new_params)?;
        
        let id = sqlx::query(
            r#"
            INSERT INTO key_rotation_events (
                id, scheme_id, previous_params, new_params, status, created_at, updated_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7
            ) RETURNING id
            "#
        )
        .bind(event.id)
        .bind(event.scheme_id)
        .bind(previous_params_json)
        .bind(new_params_json)
        .bind(status)
        .bind(event.created_at)
        .bind(event.updated_at)
        .fetch_one(&self.pool)
        .await?
        .get::<Uuid, _>("id");
        
        Ok(id)
    }
    
    async fn get_key_rotation_events(&self, scheme_id: Uuid) -> Result<Vec<KeyRotationEvent>> {
        let records = sqlx::query(
            r#"
            SELECT id, scheme_id, previous_params, new_params, status, created_at, updated_at
            FROM key_rotation_events
            WHERE scheme_id = $1
            ORDER BY created_at DESC
            "#
        )
        .bind(scheme_id)
        .fetch_all(&self.pool)
        .await?;
        
        let mut events = Vec::with_capacity(records.len());
        
        for record in records {
            let status = match record.get::<&str, _>("status") {
                "in_progress" => KeyRotationStatus::InProgress,
                "completed" => KeyRotationStatus::Completed,
                "failed" => KeyRotationStatus::Failed,
                _ => return Err(anyhow::anyhow!("Invalid key rotation status")),
            };
            
            // Deserialize threshold params from JSON
            let previous_params_json: serde_json::Value = record.get("previous_params");
            let new_params_json: serde_json::Value = record.get("new_params");
            
            let previous_params: ThresholdParams = serde_json::from_value(previous_params_json)?;
            let new_params: ThresholdParams = serde_json::from_value(new_params_json)?;
            
            let event = KeyRotationEvent {
                id: record.get("id"),
                scheme_id: record.get("scheme_id"),
                previous_params,
                new_params,
                status,
                created_at: record.get("created_at"),
                updated_at: record.get("updated_at"),
            };
            
            events.push(event);
        }
        
        Ok(events)
    }
    
    async fn get_latest_key_rotation_event(&self, scheme_id: Uuid) -> Result<Option<KeyRotationEvent>> {
        let record = sqlx::query(
            r#"
            SELECT id, scheme_id, previous_params, new_params, status, created_at, updated_at
            FROM key_rotation_events
            WHERE scheme_id = $1
            ORDER BY created_at DESC
            LIMIT 1
            "#
        )
        .bind(scheme_id)
        .fetch_optional(&self.pool)
        .await?;
        
        if let Some(record) = record {
            let status = match record.get::<&str, _>("status") {
                "in_progress" => KeyRotationStatus::InProgress,
                "completed" => KeyRotationStatus::Completed,
                "failed" => KeyRotationStatus::Failed,
                _ => return Err(anyhow::anyhow!("Invalid key rotation status")),
            };
            
            // Deserialize threshold params from JSON
            let previous_params_json: serde_json::Value = record.get("previous_params");
            let new_params_json: serde_json::Value = record.get("new_params");
            
            let previous_params: ThresholdParams = serde_json::from_value(previous_params_json)?;
            let new_params: ThresholdParams = serde_json::from_value(new_params_json)?;
            
            let event = KeyRotationEvent {
                id: record.get("id"),
                scheme_id: record.get("scheme_id"),
                previous_params,
                new_params,
                status,
                created_at: record.get("created_at"),
                updated_at: record.get("updated_at"),
            };
            
            Ok(Some(event))
        } else {
            Ok(None)
        }
    }
}
