use async_trait::async_trait;
use anyhow::Result;
use sp_core::H256;
use sqlx::PgPool;

use crate::models::reward::{ValidatorReward, RewardDistribution};
use crate::repositories::traits::RewardRepository;

pub struct PostgresRewardRepository {
    pool: PgPool,
}

impl PostgresRewardRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RewardRepository for PostgresRewardRepository {
    async fn store_reward(&self, reward: ValidatorReward) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO validator_rewards (
                validator_id, amount, performance_score, epoch,
                distributed
            ) VALUES ($1, $2, $3, $4, false)
            ON CONFLICT (validator_id, epoch)
            DO UPDATE SET
                amount = EXCLUDED.amount,
                performance_score = EXCLUDED.performance_score
            "#,
            reward.validator_id.as_bytes(),
            reward.amount as i64,
            reward.performance_score as i32,
            reward.epoch as i32
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_validator_rewards(&self, validator_id: H256, epoch: u32) -> Result<Vec<ValidatorReward>> {
        let records = sqlx::query!(
            r#"
            SELECT 
                validator_id, amount, performance_score, epoch
            FROM validator_rewards
            WHERE validator_id = $1 AND epoch = $2
            "#,
            validator_id.as_bytes(),
            epoch as i32
        )
        .fetch_all(&self.pool)
        .await?;

        let mut rewards = Vec::with_capacity(records.len());
        for r in records {
            rewards.push(ValidatorReward {
                validator_id: H256::from_slice(r.validator_id.as_slice()),
                amount: r.amount as u128,
                performance_score: r.performance_score as u32,
                epoch: r.epoch as u32,
            });
        }

        Ok(rewards)
    }

    async fn store_distribution(&self, distribution: RewardDistribution) -> Result<()> {
        let mut tx = self.pool.begin().await?;

        // Store distribution record
        sqlx::query!(
            r#"
            INSERT INTO reward_distributions (
                epoch, total_reward, distributions
            ) VALUES ($1, $2, $3)
            ON CONFLICT (epoch)
            DO UPDATE SET
                total_reward = EXCLUDED.total_reward,
                distributions = EXCLUDED.distributions
            "#,
            distribution.epoch as i32,
            distribution.total_reward as i64,
            serde_json::to_value(&distribution.distributions)?
        )
        .execute(&mut tx)
        .await?;

        // Mark rewards as distributed
        sqlx::query!(
            r#"
            UPDATE validator_rewards
            SET distributed = true
            WHERE epoch = $1
            "#,
            distribution.epoch as i32
        )
        .execute(&mut tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    async fn get_epoch_distribution(&self, epoch: u32) -> Result<Option<RewardDistribution>> {
        let record = sqlx::query!(
            r#"
            SELECT epoch, total_reward, distributions
            FROM reward_distributions
            WHERE epoch = $1
            "#,
            epoch as i32
        )
        .fetch_optional(&self.pool)
        .await?;

        match record {
            Some(r) => Ok(Some(RewardDistribution {
                epoch: r.epoch as u32,
                total_reward: r.total_reward as u128,
                distributions: serde_json::from_value(r.distributions)?,
            })),
            None => Ok(None),
        }
    }

    async fn list_pending_rewards(&self, epoch: u32) -> Result<Vec<ValidatorReward>> {
        let records = sqlx::query!(
            r#"
            SELECT 
                validator_id, amount, performance_score, epoch
            FROM validator_rewards
            WHERE epoch = $1 AND distributed = false
            "#,
            epoch as i32
        )
        .fetch_all(&self.pool)
        .await?;

        let mut rewards = Vec::with_capacity(records.len());
        for r in records {
            rewards.push(ValidatorReward {
                validator_id: H256::from_slice(r.validator_id.as_slice()),
                amount: r.amount as u128,
                performance_score: r.performance_score as u32,
                epoch: r.epoch as u32,
            });
        }

        Ok(rewards)
    }
}
