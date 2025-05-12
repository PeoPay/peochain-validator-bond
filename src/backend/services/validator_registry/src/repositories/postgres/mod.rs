mod validator_repository;
mod subnet_repository;
mod reward_repository;

pub use validator_repository::PostgresValidatorRepository;
pub use subnet_repository::PostgresSubnetRepository;
pub use reward_repository::PostgresRewardRepository;

use sqlx::PgPool;

pub struct PostgresConfig {
    pub connection_string: String,
    pub max_connections: u32,
}

pub async fn create_pool(config: &PostgresConfig) -> sqlx::Result<PgPool> {
    PgPool::builder()
        .max_connections(config.max_connections)
        .build(&config.connection_string)
        .await
}
