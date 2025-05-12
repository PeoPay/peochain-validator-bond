use anyhow::Result;
use sqlx::{PgPool, Transaction, Postgres};
use std::sync::Arc;

/// Transaction manager for handling database transactions
pub struct TransactionManager {
    pool: Arc<PgPool>,
}

impl TransactionManager {
    /// Create a new transaction manager
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
    
    /// Begin a new transaction
    pub async fn begin_transaction(&self) -> Result<Transaction<'static, Postgres>> {
        let transaction = self.pool.begin().await?;
        Ok(transaction)
    }
    
    /// Execute a function within a transaction
    /// If the function returns an error, the transaction is rolled back
    /// Otherwise, the transaction is committed
    pub async fn with_transaction<F, T>(&self, f: F) -> Result<T>
    where
        F: for<'a> FnOnce(Transaction<'a, Postgres>) -> Result<(Transaction<'a, Postgres>, T)>,
    {
        let tx = self.begin_transaction().await?;
        
        match f(tx).await {
            Ok((tx, result)) => {
                tx.commit().await?;
                Ok(result)
            }
            Err(err) => {
                // Transaction will be automatically rolled back when dropped
                Err(err)
            }
        }
    }
}
