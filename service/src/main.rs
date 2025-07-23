use axum::{
    Router,
    routing::{get, post},
};
use std::sync::Arc;
use tower_http::trace::TraceLayer;

use crate::api::{
    decrypt, encrypt, get_decrypt_request_status, get_reencrypt_request_status,
    get_register_app_request_status, quote, reencrypt, register,
};
use crate::config::ServiceConfig;
use crate::db::async_store::AsyncDataStore;
use crate::network::async_manager::AsyncNetworkManager;
use crate::tracer::{TracingConfig, init_tracer};
use crate::traits::{DataStore, NetworkManager, WorkerManager};
use crate::worker::async_manager::AsyncWorkerManager;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<ServiceConfig>,
    pub data_store: Arc<dyn DataStore + Send + Sync>,
    pub network_manager: Arc<dyn NetworkManager + Send + Sync>,
    pub worker_manager: Arc<dyn WorkerManager + Send + Sync>,
}

pub mod api;
pub mod config;
pub mod db;
pub mod error;
pub mod handler;
pub mod network;
pub mod network_manager;
pub mod p2p;
pub mod tracer;
pub mod traits;
pub mod types;
pub mod worker;

#[cfg(test)]
mod tests;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracer(TracingConfig::default());
    tracing::info!("Starting encryption server...");

    // Load configuration
    let config = ServiceConfig::from_env();

    // Initialize async components with trait objects
    let data_store: Arc<dyn DataStore + Send + Sync> = Arc::new(
        AsyncDataStore::from_path(&config.database.path, config.clone())
            .expect("Failed to create async data store"),
    );
    let network_manager: Arc<dyn NetworkManager + Send + Sync> = Arc::new(
        AsyncNetworkManager::from_config(
            config.p2p.port,
            config.p2p.node_name.clone(),
            config.clone(),
        )
        .await
        .expect("Failed to create async network manager"),
    );
    let worker_manager: Arc<dyn WorkerManager + Send + Sync> = Arc::new(
        AsyncWorkerManager::new(data_store.clone(), network_manager.clone(), &config.clone())
            .expect("Failed to create async worker manager"),
    );

    // Create application state with async trait objects
    let app_state = AppState {
        config: Arc::new(config.clone()),
        data_store,
        network_manager,
        worker_manager,
    };

    // Application routes
    let app = Router::new()
        .route("/v1/register", post(register))
        .route("/v1/encrypt", post(encrypt))
        .route("/v1/decrypt", post(decrypt))
        .route("/v1/quote", get(quote))
        .route("/v1/private-key", post(reencrypt))
        .route("/v1/decrypt-status", get(get_decrypt_request_status))
        .route("/v1/register-status", get(get_register_app_request_status))
        .route("/v1/private-key-status", get(get_reencrypt_request_status))
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
