use async_trait::async_trait;
use anyhow::Result;

#[async_trait]
pub trait BaseRepository<T> {
    async fn create(&self, item: &T) -> Result<T>;
    async fn update(&self, item: &T) -> Result<T>;
    async fn delete(&self, id: &str) -> Result<()>;
    async fn find_by_id(&self, id: &str) -> Result<Option<T>>;
}
