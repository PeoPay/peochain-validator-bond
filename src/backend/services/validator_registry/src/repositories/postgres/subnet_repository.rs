use async_trait::async_trait;
use anyhow::{Result, Context};
use sp_core::H256;
use sqlx::{PgPool, postgres::PgPoolOptions, types::Json};
use std::time::Duration;

use crate::models::subnet::{SubnetAssignment, SubnetRotation};
use crate::repositories::traits::SubnetRepository;

pub struct PostgresSubnetRepository {
    pool: PgPool,
    // Prepared statements
    get_assignments_stmt: String,
    get_validator_subnet_stmt: String,
    get_latest_rotation_stmt: String,
    store_rotation_stmt: String,
}

impl PostgresSubnetRepository {
    pub async fn new(database_url: &str, max_connections: u32) -> Result<Self> {
        // Configure connection pool with optimal settings
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .min_connections(2)
            .max_lifetime(Duration::from_secs(30 * 60)) // 30 minutes
            .idle_timeout(Duration::from_secs(10 * 60)) // 10 minutes
            .connect(database_url)
            .await
            .context("Failed to create database connection pool")?;

        // Prepare statements
        let get_assignments_stmt = r#"
            SELECT subnet_id, epoch, validator_set
            FROM subnet_assignments
            WHERE epoch = $1
        "#.to_string();

        let get_validator_subnet_stmt = r#"
            SELECT subnet_id
            FROM subnet_assignments
            WHERE epoch = $1
            AND validator_set @> $2
        "#.to_string();

        let get_latest_rotation_stmt = r#"
            SELECT epoch, rotation_seed, previous_assignments, new_assignments
            FROM subnet_rotations
            ORDER BY epoch DESC
            LIMIT 1
        "#.to_string();

        let store_rotation_stmt = r#"
            INSERT INTO subnet_rotations (
                epoch, rotation_seed, previous_assignments, new_assignments
            ) VALUES ($1, $2, $3, $4)
            ON CONFLICT (epoch)
            DO UPDATE SET
                rotation_seed = EXCLUDED.rotation_seed,
                previous_assignments = EXCLUDED.previous_assignments,
                new_assignments = EXCLUDED.new_assignments
        "#.to_string();

        Ok(Self {
            pool,
            get_assignments_stmt,
            get_validator_subnet_stmt,
            get_latest_rotation_stmt,
            store_rotation_stmt,
        })
    }
}

#[async_trait]
impl SubnetRepository for PostgresSubnetRepository {
    async fn store_subnet_assignments(&self, assignments: Vec<SubnetAssignment>) -> Result<()> {
        if assignments.is_empty() {
            return Ok(());
        }

        let mut tx = self.pool.begin().await?;
        
        // Use a single query with UNNEST for batch insert
        let mut subnet_ids = Vec::with_capacity(assignments.len());
        let mut epochs = Vec::with_capacity(assignments.len());
        let mut validator_sets = Vec::with_capacity(assignments.len());
        
        for assignment in assignments {
            subnet_ids.push(assignment.subnet_id as i32);
            epochs.push(assignment.epoch as i32);
            validator_sets.push(Json(assignment.validator_set));
        }
        
        sqlx::query(
            r#"
            INSERT INTO subnet_assignments (subnet_id, epoch, validator_set)
            SELECT * FROM UNNEST($1::integer[], $2::integer[], $3::jsonb[])
            ON CONFLICT (subnet_id, epoch) 
            DO UPDATE SET validator_set = EXCLUDED.validator_set
            "#
        )
        .bind(&subnet_ids[..])
        .bind(&epochs[..])
        .bind(&validator_sets[..])
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    async fn get_subnet_assignments(&self, epoch: u32) -> Result<Vec<SubnetAssignment>> {
        let records = sqlx::query_with(&self.get_assignments_stmt, &[&(epoch as i32)])
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
        sqlx::query_with(
            &self.store_rotation_stmt,
            &[
                &(rotation.epoch as i32),
                &rotation.rotation_seed.as_bytes(),
                &serde_json::to_value(&rotation.previous_assignments)?,
                &serde_json::to_value(&rotation.new_assignments)?,
            ],
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_latest_rotation(&self) -> Result<Option<SubnetRotation>> {
        let record = sqlx::query_with(&self.get_latest_rotation_stmt, &[] as &[&(i32; 0)])
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
        let record = sqlx::query_with(
            &self.get_validator_subnet_stmt,
            &[
                &(epoch as i32),
                &serde_json::to_value(&[validator_id.as_bytes()])?,
            ],
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(record.map(|r| r.subnet_id as u32))
    }
}
