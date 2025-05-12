use async_trait::async_trait;
use anyhow::Result;
use sp_core::H256;
use sqlx::PgPool;

use crate::models::subnet::{SubnetAssignment, SubnetRotation};
use crate::repositories::traits::SubnetRepository;

pub struct PostgresSubnetRepository {
    pool: PgPool,
}

impl PostgresSubnetRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SubnetRepository for PostgresSubnetRepository {
    async fn store_subnet_assignments(&self, assignments: Vec<SubnetAssignment>) -> Result<()> {
        let mut tx = self.pool.begin().await?;

        for assignment in assignments {
            sqlx::query!(
                r#"
                INSERT INTO subnet_assignments (
                    subnet_id, epoch, validator_set
                ) VALUES ($1, $2, $3)
                ON CONFLICT (subnet_id, epoch)
                DO UPDATE SET validator_set = EXCLUDED.validator_set
                "#,
                assignment.subnet_id as i32,
                assignment.epoch as i32,
                serde_json::to_value(&assignment.validator_set)?
            )
            .execute(&mut tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    async fn get_subnet_assignments(&self, epoch: u32) -> Result<Vec<SubnetAssignment>> {
        let records = sqlx::query!(
            r#"
            SELECT subnet_id, epoch, validator_set
            FROM subnet_assignments
            WHERE epoch = $1
            "#,
            epoch as i32
        )
        .fetch_all(&self.pool)
        .await?;

        let mut assignments = Vec::with_capacity(records.len());
        for r in records {
            assignments.push(SubnetAssignment {
                subnet_id: r.subnet_id as u32,
                epoch: r.epoch as u32,
                validator_set: serde_json::from_value(r.validator_set)?,
            });
        }

        Ok(assignments)
    }

    async fn store_subnet_rotation(&self, rotation: SubnetRotation) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO subnet_rotations (
                epoch, rotation_seed, previous_assignments, new_assignments
            ) VALUES ($1, $2, $3, $4)
            ON CONFLICT (epoch)
            DO UPDATE SET
                rotation_seed = EXCLUDED.rotation_seed,
                previous_assignments = EXCLUDED.previous_assignments,
                new_assignments = EXCLUDED.new_assignments
            "#,
            rotation.epoch as i32,
            rotation.rotation_seed.as_bytes(),
            serde_json::to_value(&rotation.previous_assignments)?,
            serde_json::to_value(&rotation.new_assignments)?
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_latest_rotation(&self) -> Result<Option<SubnetRotation>> {
        let record = sqlx::query!(
            r#"
            SELECT 
                epoch, rotation_seed, previous_assignments, new_assignments
            FROM subnet_rotations
            ORDER BY epoch DESC
            LIMIT 1
            "#
        )
        .fetch_optional(&self.pool)
        .await?;

        match record {
            Some(r) => Ok(Some(SubnetRotation {
                epoch: r.epoch as u32,
                rotation_seed: H256::from_slice(r.rotation_seed.as_slice()),
                previous_assignments: serde_json::from_value(r.previous_assignments)?,
                new_assignments: serde_json::from_value(r.new_assignments)?,
            })),
            None => Ok(None),
        }
    }

    async fn get_validator_subnet(&self, validator_id: H256, epoch: u32) -> Result<Option<u32>> {
        let record = sqlx::query!(
            r#"
            SELECT subnet_id
            FROM subnet_assignments
            WHERE epoch = $1
            AND validator_set @> $2
            "#,
            epoch as i32,
            serde_json::to_value(&validator_id.as_bytes())?
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(record.map(|r| r.subnet_id as u32))
    }
}
