use thiserror::Error;

#[derive(Error, Debug)]
pub enum ServiceError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Unauthorized access")]
    Unauthorized,

    #[error("Internal server error")]
    InternalError,
}

pub type Result<T> = std::result::Result<T, ServiceError>;
