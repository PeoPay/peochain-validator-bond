use crate::repositories::threshold_signature_repository::{ThresholdSignatureRepository, PgThresholdSignatureRepository};
use crate::models::threshold_signature::{
    ThresholdSchemeConfig, ThresholdSchemeType, ThresholdParams,
    ThresholdParticipant, ValidatorKeyShare, SignatureShare,
    ThresholdSignature, SigningSession, SigningSessionStatus,
    KeyRotationEvent, KeyRotationStatus,
};
use sp_core::H256;
use uuid::Uuid;
use std::collections::BTreeMap;
use sqlx::{postgres::PgPoolOptions, PgPool};
use anyhow::Result;

// Helper function to create a test database pool
async fn create_test_pool() -> Result<PgPool> {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/peochain_test".to_string());
    
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;
    
    // Create the necessary tables if they don't exist
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS threshold_schemes (
            id UUID PRIMARY KEY,
            scheme_type TEXT NOT NULL,
            threshold INTEGER NOT NULL,
            total_participants INTEGER NOT NULL,
            created_at BIGINT NOT NULL,
            updated_at BIGINT NOT NULL
        );
        
        CREATE TABLE IF NOT EXISTS threshold_participants (
            id UUID PRIMARY KEY,
            scheme_id UUID NOT NULL REFERENCES threshold_schemes(id),
            participant_index INTEGER NOT NULL,
            public_share BYTEA NOT NULL,
            verification_vector BYTEA[] NOT NULL,
            created_at BIGINT NOT NULL,
            UNIQUE(scheme_id, participant_index)
        );
        
        CREATE TABLE IF NOT EXISTS validator_key_shares (
            id UUID PRIMARY KEY,
            validator_id BYTEA NOT NULL,
            scheme_id UUID NOT NULL REFERENCES threshold_schemes(id),
            participant_index INTEGER NOT NULL,
            encrypted_secret_share BYTEA NOT NULL,
            created_at BIGINT NOT NULL,
            updated_at BIGINT NOT NULL,
            UNIQUE(validator_id, scheme_id)
        );
        
        CREATE TABLE IF NOT EXISTS signature_shares (
            id UUID PRIMARY KEY,
            validator_id BYTEA NOT NULL,
            scheme_id UUID NOT NULL REFERENCES threshold_schemes(id),
            participant_index INTEGER NOT NULL,
            message_hash BYTEA NOT NULL,
            share BYTEA NOT NULL,
            created_at BIGINT NOT NULL,
            UNIQUE(validator_id, scheme_id, message_hash)
        );
        
        CREATE TABLE IF NOT EXISTS threshold_signatures (
            id UUID PRIMARY KEY,
            scheme_id UUID NOT NULL REFERENCES threshold_schemes(id),
            message_hash BYTEA NOT NULL,
            signature BYTEA NOT NULL,
            participant_indices INTEGER[] NOT NULL,
            created_at BIGINT NOT NULL,
            UNIQUE(scheme_id, message_hash)
        );
        
        CREATE TABLE IF NOT EXISTS signing_sessions (
            id UUID PRIMARY KEY,
            scheme_id UUID NOT NULL REFERENCES threshold_schemes(id),
            message_hash BYTEA NOT NULL,
            status TEXT NOT NULL,
            signature_shares JSONB NOT NULL,
            threshold_signature BYTEA,
            created_at BIGINT NOT NULL,
            updated_at BIGINT NOT NULL,
            expires_at BIGINT NOT NULL,
            UNIQUE(scheme_id, message_hash)
        );
        
        CREATE TABLE IF NOT EXISTS key_rotation_events (
            id UUID PRIMARY KEY,
            scheme_id UUID NOT NULL REFERENCES threshold_schemes(id),
            previous_params JSONB NOT NULL,
            new_params JSONB NOT NULL,
            status TEXT NOT NULL,
            created_at BIGINT NOT NULL,
            updated_at BIGINT NOT NULL
        );
        "#
    )
    .execute(&pool)
    .await?;
    
    Ok(pool)
}

// Helper function to clean up the test database
async fn cleanup_test_database(pool: &PgPool) -> Result<()> {
    sqlx::query(
        r#"
        TRUNCATE TABLE key_rotation_events CASCADE;
        TRUNCATE TABLE signing_sessions CASCADE;
        TRUNCATE TABLE threshold_signatures CASCADE;
        TRUNCATE TABLE signature_shares CASCADE;
        TRUNCATE TABLE validator_key_shares CASCADE;
        TRUNCATE TABLE threshold_participants CASCADE;
        TRUNCATE TABLE threshold_schemes CASCADE;
        "#
    )
    .execute(pool)
    .await?;
    
    Ok(())
}

#[tokio::test]
async fn test_threshold_scheme_crud() -> Result<()> {
    let pool = create_test_pool().await?;
    let repo = PgThresholdSignatureRepository::new(pool.clone());
    
    // Clean up before test
    cleanup_test_database(&pool).await?;
    
    // Create a threshold scheme
    let scheme_id = Uuid::new_v4();
    let now = chrono::Utc::now().timestamp();
    
    let scheme = ThresholdSchemeConfig {
        id: scheme_id,
        scheme_type: ThresholdSchemeType::BLS,
        params: ThresholdParams {
            threshold: 3,
            total_participants: 5,
        },
        created_at: now,
        updated_at: now,
    };
    
    // Store the scheme
    let stored_id = repo.store_threshold_scheme(scheme.clone()).await?;
    assert_eq!(stored_id, scheme_id);
    
    // Get the scheme
    let retrieved_scheme = repo.get_threshold_scheme(scheme_id).await?;
    assert!(retrieved_scheme.is_some());
    
    let retrieved_scheme = retrieved_scheme.unwrap();
    assert_eq!(retrieved_scheme.id, scheme_id);
    assert!(matches!(retrieved_scheme.scheme_type, ThresholdSchemeType::BLS));
    assert_eq!(retrieved_scheme.params.threshold, 3);
    assert_eq!(retrieved_scheme.params.total_participants, 5);
    
    // Get all schemes
    let all_schemes = repo.get_all_threshold_schemes().await?;
    assert_eq!(all_schemes.len(), 1);
    assert_eq!(all_schemes[0].id, scheme_id);
    
    // Clean up after test
    cleanup_test_database(&pool).await?;
    
    Ok(())
}

#[tokio::test]
async fn test_threshold_participant_crud() -> Result<()> {
    let pool = create_test_pool().await?;
    let repo = PgThresholdSignatureRepository::new(pool.clone());
    
    // Clean up before test
    cleanup_test_database(&pool).await?;
    
    // Create a threshold scheme
    let scheme_id = Uuid::new_v4();
    let now = chrono::Utc::now().timestamp();
    
    let scheme = ThresholdSchemeConfig {
        id: scheme_id,
        scheme_type: ThresholdSchemeType::BLS,
        params: ThresholdParams {
            threshold: 3,
            total_participants: 5,
        },
        created_at: now,
        updated_at: now,
    };
    
    repo.store_threshold_scheme(scheme).await?;
    
    // Create a participant
    let participant_id = Uuid::new_v4();
    let participant = ThresholdParticipant {
        id: participant_id,
        scheme_id,
        index: 1,
        public_share: vec![1, 2, 3, 4],
        verification_vector: vec![vec![5, 6, 7, 8]],
        created_at: now,
    };
    
    // Store the participant
    let stored_id = repo.store_threshold_participant(participant.clone()).await?;
    assert_eq!(stored_id, participant_id);
    
    // Get participants for the scheme
    let participants = repo.get_threshold_participants(scheme_id).await?;
    assert_eq!(participants.len(), 1);
    assert_eq!(participants[0].id, participant_id);
    assert_eq!(participants[0].scheme_id, scheme_id);
    assert_eq!(participants[0].index, 1);
    assert_eq!(participants[0].public_share, vec![1, 2, 3, 4]);
    
    // Clean up after test
    cleanup_test_database(&pool).await?;
    
    Ok(())
}

#[tokio::test]
async fn test_validator_key_share_crud() -> Result<()> {
    let pool = create_test_pool().await?;
    let repo = PgThresholdSignatureRepository::new(pool.clone());
    
    // Clean up before test
    cleanup_test_database(&pool).await?;
    
    // Create a threshold scheme
    let scheme_id = Uuid::new_v4();
    let now = chrono::Utc::now().timestamp();
    
    let scheme = ThresholdSchemeConfig {
        id: scheme_id,
        scheme_type: ThresholdSchemeType::BLS,
        params: ThresholdParams {
            threshold: 3,
            total_participants: 5,
        },
        created_at: now,
        updated_at: now,
    };
    
    repo.store_threshold_scheme(scheme).await?;
    
    // Create a validator key share
    let key_share_id = Uuid::new_v4();
    let validator_id = H256::random();
    
    let key_share = ValidatorKeyShare {
        id: key_share_id,
        validator_id,
        scheme_id,
        participant_index: 1,
        encrypted_secret_share: vec![1, 2, 3, 4],
        created_at: now,
        updated_at: now,
    };
    
    // Store the key share
    let stored_id = repo.store_validator_key_share(key_share.clone()).await?;
    assert_eq!(stored_id, key_share_id);
    
    // Get key shares for the validator
    let key_shares = repo.get_validator_key_shares(validator_id).await?;
    assert_eq!(key_shares.len(), 1);
    assert_eq!(key_shares[0].id, key_share_id);
    assert_eq!(key_shares[0].validator_id, validator_id);
    assert_eq!(key_shares[0].scheme_id, scheme_id);
    
    // Get a specific key share
    let retrieved_key_share = repo.get_validator_key_share(validator_id, scheme_id).await?;
    assert!(retrieved_key_share.is_some());
    
    let retrieved_key_share = retrieved_key_share.unwrap();
    assert_eq!(retrieved_key_share.id, key_share_id);
    assert_eq!(retrieved_key_share.validator_id, validator_id);
    assert_eq!(retrieved_key_share.scheme_id, scheme_id);
    assert_eq!(retrieved_key_share.participant_index, 1);
    assert_eq!(retrieved_key_share.encrypted_secret_share, vec![1, 2, 3, 4]);
    
    // Clean up after test
    cleanup_test_database(&pool).await?;
    
    Ok(())
}

#[tokio::test]
async fn test_signature_share_crud() -> Result<()> {
    let pool = create_test_pool().await?;
    let repo = PgThresholdSignatureRepository::new(pool.clone());
    
    // Clean up before test
    cleanup_test_database(&pool).await?;
    
    // Create a threshold scheme
    let scheme_id = Uuid::new_v4();
    let now = chrono::Utc::now().timestamp();
    
    let scheme = ThresholdSchemeConfig {
        id: scheme_id,
        scheme_type: ThresholdSchemeType::BLS,
        params: ThresholdParams {
            threshold: 3,
            total_participants: 5,
        },
        created_at: now,
        updated_at: now,
    };
    
    repo.store_threshold_scheme(scheme).await?;
    
    // Create a signature share
    let share_id = Uuid::new_v4();
    let validator_id = H256::random();
    let message_hash = H256::random();
    
    let share = SignatureShare {
        id: share_id,
        validator_id,
        scheme_id,
        participant_index: 1,
        message_hash,
        share: vec![1, 2, 3, 4],
        created_at: now,
    };
    
    // Store the signature share
    let stored_id = repo.store_signature_share(share.clone()).await?;
    assert_eq!(stored_id, share_id);
    
    // Get signature shares for the message
    let shares = repo.get_signature_shares(scheme_id, message_hash).await?;
    assert_eq!(shares.len(), 1);
    assert_eq!(shares[0].id, share_id);
    assert_eq!(shares[0].validator_id, validator_id);
    assert_eq!(shares[0].scheme_id, scheme_id);
    assert_eq!(shares[0].message_hash, message_hash);
    assert_eq!(shares[0].share, vec![1, 2, 3, 4]);
    
    // Clean up after test
    cleanup_test_database(&pool).await?;
    
    Ok(())
}

#[tokio::test]
async fn test_threshold_signature_crud() -> Result<()> {
    let pool = create_test_pool().await?;
    let repo = PgThresholdSignatureRepository::new(pool.clone());
    
    // Clean up before test
    cleanup_test_database(&pool).await?;
    
    // Create a threshold scheme
    let scheme_id = Uuid::new_v4();
    let now = chrono::Utc::now().timestamp();
    
    let scheme = ThresholdSchemeConfig {
        id: scheme_id,
        scheme_type: ThresholdSchemeType::BLS,
        params: ThresholdParams {
            threshold: 3,
            total_participants: 5,
        },
        created_at: now,
        updated_at: now,
    };
    
    repo.store_threshold_scheme(scheme).await?;
    
    // Create a threshold signature
    let signature_id = Uuid::new_v4();
    let message_hash = H256::random();
    
    let signature = ThresholdSignature {
        id: signature_id,
        scheme_id,
        message_hash,
        signature: vec![1, 2, 3, 4],
        participant_indices: vec![1, 2, 3],
        created_at: now,
    };
    
    // Store the threshold signature
    let stored_id = repo.store_threshold_signature(signature.clone()).await?;
    assert_eq!(stored_id, signature_id);
    
    // Get the threshold signature
    let retrieved_signature = repo.get_threshold_signature(scheme_id, message_hash).await?;
    assert!(retrieved_signature.is_some());
    
    let retrieved_signature = retrieved_signature.unwrap();
    assert_eq!(retrieved_signature.id, signature_id);
    assert_eq!(retrieved_signature.scheme_id, scheme_id);
    assert_eq!(retrieved_signature.message_hash, message_hash);
    assert_eq!(retrieved_signature.signature, vec![1, 2, 3, 4]);
    assert_eq!(retrieved_signature.participant_indices, vec![1, 2, 3]);
    
    // Clean up after test
    cleanup_test_database(&pool).await?;
    
    Ok(())
}

#[tokio::test]
async fn test_signing_session_crud() -> Result<()> {
    let pool = create_test_pool().await?;
    let repo = PgThresholdSignatureRepository::new(pool.clone());
    
    // Clean up before test
    cleanup_test_database(&pool).await?;
    
    // Create a threshold scheme
    let scheme_id = Uuid::new_v4();
    let now = chrono::Utc::now().timestamp();
    
    let scheme = ThresholdSchemeConfig {
        id: scheme_id,
        scheme_type: ThresholdSchemeType::BLS,
        params: ThresholdParams {
            threshold: 3,
            total_participants: 5,
        },
        created_at: now,
        updated_at: now,
    };
    
    repo.store_threshold_scheme(scheme).await?;
    
    // Create a signing session
    let session_id = Uuid::new_v4();
    let message_hash = H256::random();
    
    let mut signature_shares = BTreeMap::new();
    signature_shares.insert(1, vec![1, 2, 3, 4]);
    signature_shares.insert(2, vec![5, 6, 7, 8]);
    
    let session = SigningSession {
        id: session_id,
        scheme_id,
        message_hash,
        status: SigningSessionStatus::Active,
        signature_shares,
        threshold_signature: None,
        created_at: now,
        updated_at: now,
        expires_at: now + 3600,
    };
    
    // Store the signing session
    let stored_id = repo.create_signing_session(session.clone()).await?;
    assert_eq!(stored_id, session_id);
    
    // Get the signing session
    let retrieved_session = repo.get_signing_session(session_id).await?;
    assert!(retrieved_session.is_some());
    
    let retrieved_session = retrieved_session.unwrap();
    assert_eq!(retrieved_session.id, session_id);
    assert_eq!(retrieved_session.scheme_id, scheme_id);
    assert_eq!(retrieved_session.message_hash, message_hash);
    assert!(matches!(retrieved_session.status, SigningSessionStatus::Active));
    assert_eq!(retrieved_session.signature_shares.len(), 2);
    assert_eq!(retrieved_session.signature_shares.get(&1).unwrap(), &vec![1, 2, 3, 4]);
    assert_eq!(retrieved_session.signature_shares.get(&2).unwrap(), &vec![5, 6, 7, 8]);
    
    // Update the signing session
    let mut updated_session = retrieved_session.clone();
    updated_session.status = SigningSessionStatus::Completed;
    updated_session.threshold_signature = Some(vec![9, 10, 11, 12]);
    updated_session.updated_at = now + 10;
    
    repo.update_signing_session(updated_session.clone()).await?;
    
    // Get the updated signing session
    let retrieved_updated_session = repo.get_signing_session(session_id).await?;
    assert!(retrieved_updated_session.is_some());
    
    let retrieved_updated_session = retrieved_updated_session.unwrap();
    assert_eq!(retrieved_updated_session.id, session_id);
    assert!(matches!(retrieved_updated_session.status, SigningSessionStatus::Completed));
    assert_eq!(retrieved_updated_session.threshold_signature, Some(vec![9, 10, 11, 12]));
    assert_eq!(retrieved_updated_session.updated_at, now + 10);
    
    // Get active signing sessions
    let active_sessions = repo.get_active_signing_sessions(scheme_id).await?;
    assert_eq!(active_sessions.len(), 0); // Session is now completed
    
    // Clean up after test
    cleanup_test_database(&pool).await?;
    
    Ok(())
}

#[tokio::test]
async fn test_key_rotation_event_crud() -> Result<()> {
    let pool = create_test_pool().await?;
    let repo = PgThresholdSignatureRepository::new(pool.clone());
    
    // Clean up before test
    cleanup_test_database(&pool).await?;
    
    // Create a threshold scheme
    let scheme_id = Uuid::new_v4();
    let now = chrono::Utc::now().timestamp();
    
    let scheme = ThresholdSchemeConfig {
        id: scheme_id,
        scheme_type: ThresholdSchemeType::BLS,
        params: ThresholdParams {
            threshold: 3,
            total_participants: 5,
        },
        created_at: now,
        updated_at: now,
    };
    
    repo.store_threshold_scheme(scheme).await?;
    
    // Create a key rotation event
    let event_id = Uuid::new_v4();
    
    let event = KeyRotationEvent {
        id: event_id,
        scheme_id,
        previous_params: ThresholdParams {
            threshold: 3,
            total_participants: 5,
        },
        new_params: ThresholdParams {
            threshold: 4,
            total_participants: 7,
        },
        status: KeyRotationStatus::InProgress,
        created_at: now,
        updated_at: now,
    };
    
    // Store the key rotation event
    let stored_id = repo.store_key_rotation_event(event.clone()).await?;
    assert_eq!(stored_id, event_id);
    
    // Get key rotation events
    let events = repo.get_key_rotation_events(scheme_id).await?;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].id, event_id);
    assert_eq!(events[0].scheme_id, scheme_id);
    assert!(matches!(events[0].status, KeyRotationStatus::InProgress));
    assert_eq!(events[0].previous_params.threshold, 3);
    assert_eq!(events[0].previous_params.total_participants, 5);
    assert_eq!(events[0].new_params.threshold, 4);
    assert_eq!(events[0].new_params.total_participants, 7);
    
    // Get the latest key rotation event
    let latest_event = repo.get_latest_key_rotation_event(scheme_id).await?;
    assert!(latest_event.is_some());
    
    let latest_event = latest_event.unwrap();
    assert_eq!(latest_event.id, event_id);
    
    // Clean up after test
    cleanup_test_database(&pool).await?;
    
    Ok(())
}

#[tokio::test]
async fn test_edge_cases() -> Result<()> {
    let pool = create_test_pool().await?;
    let repo = PgThresholdSignatureRepository::new(pool.clone());
    
    // Clean up before test
    cleanup_test_database(&pool).await?;
    
    // Test getting a non-existent threshold scheme
    let non_existent_id = Uuid::new_v4();
    let result = repo.get_threshold_scheme(non_existent_id).await?;
    assert!(result.is_none());
    
    // Test getting threshold participants for a non-existent scheme
    let participants = repo.get_threshold_participants(non_existent_id).await?;
    assert_eq!(participants.len(), 0);
    
    // Test getting validator key shares for a non-existent validator
    let non_existent_validator_id = H256::random();
    let key_shares = repo.get_validator_key_shares(non_existent_validator_id).await?;
    assert_eq!(key_shares.len(), 0);
    
    // Test getting a non-existent validator key share
    let result = repo.get_validator_key_share(non_existent_validator_id, non_existent_id).await?;
    assert!(result.is_none());
    
    // Test getting signature shares for a non-existent message
    let non_existent_message_hash = H256::random();
    let shares = repo.get_signature_shares(non_existent_id, non_existent_message_hash).await?;
    assert_eq!(shares.len(), 0);
    
    // Test getting a non-existent threshold signature
    let result = repo.get_threshold_signature(non_existent_id, non_existent_message_hash).await?;
    assert!(result.is_none());
    
    // Test getting a non-existent signing session
    let non_existent_session_id = Uuid::new_v4();
    let result = repo.get_signing_session(non_existent_session_id).await?;
    assert!(result.is_none());
    
    // Test getting active signing sessions for a non-existent scheme
    let sessions = repo.get_active_signing_sessions(non_existent_id).await?;
    assert_eq!(sessions.len(), 0);
    
    // Test getting key rotation events for a non-existent scheme
    let events = repo.get_key_rotation_events(non_existent_id).await?;
    assert_eq!(events.len(), 0);
    
    // Test getting the latest key rotation event for a non-existent scheme
    let result = repo.get_latest_key_rotation_event(non_existent_id).await?;
    assert!(result.is_none());
    
    // Clean up after test
    cleanup_test_database(&pool).await?;
    
    Ok(())
}

#[tokio::test]
async fn test_concurrent_operations() -> Result<()> {
    let pool = create_test_pool().await?;
    let repo = PgThresholdSignatureRepository::new(pool.clone());
    
    // Clean up before test
    cleanup_test_database(&pool).await?;
    
    // Create a threshold scheme
    let scheme_id = Uuid::new_v4();
    let now = chrono::Utc::now().timestamp();
    
    let scheme = ThresholdSchemeConfig {
        id: scheme_id,
        scheme_type: ThresholdSchemeType::BLS,
        params: ThresholdParams {
            threshold: 3,
            total_participants: 5,
        },
        created_at: now,
        updated_at: now,
    };
    
    repo.store_threshold_scheme(scheme).await?;
    
    // Concurrently create multiple participants
    let mut handles = Vec::new();
    
    for i in 1..=5 {
        let repo_clone = PgThresholdSignatureRepository::new(pool.clone());
        let scheme_id_clone = scheme_id;
        
        let handle = tokio::spawn(async move {
            let participant_id = Uuid::new_v4();
            let now = chrono::Utc::now().timestamp();
            
            let participant = ThresholdParticipant {
                id: participant_id,
                scheme_id: scheme_id_clone,
                index: i,
                public_share: vec![i as u8, (i + 1) as u8, (i + 2) as u8, (i + 3) as u8],
                verification_vector: vec![vec![(i * 2) as u8, (i * 2 + 1) as u8]],
                created_at: now,
            };
            
            repo_clone.store_threshold_participant(participant).await
        });
        
        handles.push(handle);
    }
    
    // Wait for all operations to complete
    for handle in handles {
        handle.await??;
    }
    
    // Verify all participants were created
    let participants = repo.get_threshold_participants(scheme_id).await?;
    assert_eq!(participants.len(), 5);
    
    // Verify participants are sorted by index
    for (i, participant) in participants.iter().enumerate() {
        assert_eq!(participant.index, i + 1);
    }
    
    // Clean up after test
    cleanup_test_database(&pool).await?;
    
    Ok(())
}
