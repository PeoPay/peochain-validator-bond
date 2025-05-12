use tracing_subscriber;
use anyhow::Result;

mod models;
mod repositories;
mod services;
mod api;
mod utils;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing subscriber
    tracing_subscriber::fmt::init();

    // Application startup logic
    tracing::info!("Starting bond_management service");

    Ok(())
}
