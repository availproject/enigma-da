use axum::{
    Router,
    routing::{get, post},
};
use std::sync::Arc;
use tower_http::trace::TraceLayer;

use crate::api::{decrypt, encrypt, health, quote};
use crate::config::ServiceConfig;
use crate::tracer::{TracingConfig, init_tracer};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<ServiceConfig>,
}
pub mod api;
pub mod config;

pub mod error;
pub mod tracer;
pub mod types;
pub mod utils;

#[cfg(test)]
mod tests;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracer(TracingConfig::default());
    tracing::info!("Starting encryption server and services...");

    // Load configuration
    let config = ServiceConfig::from_env();

    tracing::info!("Data store initialized");

    // Create application state with async trait objects
    let app_state = AppState {
        config: Arc::new(config.clone()),
    };

    // Application routes
    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/encrypt", post(encrypt))
        .route("/v1/decrypt", post(decrypt))
        .route("/v1/quote", get(quote))
        .layer(TraceLayer::new_for_http())
        .with_state(app_state);

    let addr = format!("{}:{}", config.server.host, config.server.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    tracing::info!(address = %addr, "Encryption server listening");

    // Set up graceful shutdown
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

    // Handle shutdown signals
    tokio::spawn(async move {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to listen for ctrl+c");
        tracing::info!("Received shutdown signal");
        let _ = shutdown_tx.send(());
    });

    // Start the server with graceful shutdown
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            shutdown_rx.await.ok();
            tracing::info!("Shutting down server...");
        })
        .await?;

    tracing::info!("Server shutdown complete");
    Ok(())
}
