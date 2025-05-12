use async_trait::async_trait;
use anyhow::Result;
use sp_core::H256;
use sqlx::PgPool;

use crate::models::validator::{ValidatorEscrow, EscrowStatus};
use crate::repositories::traits::ValidatorRepository;

pub struct PostgresValidatorRepository {
    pool: PgPool,
}

impl PostgresValidatorRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ValidatorRepository for PostgresValidatorRepository {
    async fn store_validator(&self, escrow: ValidatorEscrow) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO validators (
                validator_id, public_key, escrow_address, 
                timelock_height, status
            ) VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (validator_id) 
            DO UPDATE SET
                public_key = EXCLUDED.public_key,
                escrow_address = EXCLUDED.escrow_address,
                timelock_height = EXCLUDED.timelock_height,
                status = EXCLUDED.status
            "#,
            escrow.validator_id.as_bytes(),
            escrow.public_key,
            escrow.escrow_address.as_ref(),
            escrow.timelock_height as i32,
            serde_json::to_value(&escrow.status)?
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_validator(&self, validator_id: H256) -> Result<Option<ValidatorEscrow>> {
        let record = sqlx::query!(
            r#"
            SELECT 
                validator_id, public_key, escrow_address,
                timelock_height, status
            FROM validators
            WHERE validator_id = $1
            "#,
            validator_id.as_bytes()
        )
        .fetch_optional(&self.pool)
        .await?;

        match record {
            Some(r) => Ok(Some(ValidatorEscrow {
                validator_id: H256::from_slice(r.validator_id.as_slice()),
                public_key: r.public_key,
                escrow_address: r.escrow_address.as_slice().try_into()?,
                timelock_height: r.timelock_height as u32,
                status: serde_json::from_value(r.status)?,
            })),
            None => Ok(None),
        }
    }

    async fn update_validator_status(&self, validator_id: H256, status: EscrowStatus) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE validators
            SET status = $1
            WHERE validator_id = $2
            "#,
            serde_json::to_value(&status)?,
            validator_id.as_bytes()
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn list_active_validators(&self) -> Result<Vec<ValidatorEscrow>> {
        let records = sqlx::query!(
            r#"
            SELECT 
                validator_id, public_key, escrow_address,
                timelock_height, status
            FROM validators
            WHERE status->>'type' = 'Active'
            "#
        )
        .fetch_all(&self.pool)
        .await?;

        let mut validators = Vec::with_capacity(records.len());
        for r in records {
            validators.push(ValidatorEscrow {
                validator_id: H256::from_slice(r.validator_id.as_slice()),
                public_key: r.public_key,
                escrow_address: r.escrow_address.as_slice().try_into()?,
                timelock_height: r.timelock_height as u32,
                status: serde_json::from_value(r.status)?,
            });
        }

        Ok(validators)
    }
}
