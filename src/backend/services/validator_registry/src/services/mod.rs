use async_trait::async_trait;
use anyhow::Result;

#[async_trait]
pub trait BaseService<T> {
    async fn create(&self, item: &T) -> Result<T>;
    async fn update(&self, item: &T) -> Result<T>;
    async fn delete(&self, id: &str) -> Result<()>;
    async fn get(&self, id: &str) -> Result<Option<T>>;
}
