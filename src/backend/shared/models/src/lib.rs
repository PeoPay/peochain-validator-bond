pub mod validator;
pub mod bond;
pub mod performance;
pub mod reward;
pub mod network;

// Common shared types and traits
pub trait Identifiable {
    fn id(&self) -> &str;
}

pub trait Timestamped {
    fn created_at(&self) -> chrono::DateTime<chrono::Utc>;
    fn updated_at(&self) -> chrono::DateTime<chrono::Utc>;
}
