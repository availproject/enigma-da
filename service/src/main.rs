use axum::{
    Router,
    routing::{get, post},
};
use std::sync::Arc;
use tokio::sync::Mutex;
use tower_http::trace::TraceLayer;

#[derive(Clone)]
pub struct AppState {
    pub data_store: Arc<DataStore>,
    pub network_manager: Arc<Mutex<NetworkManager>>,
    pub worker_manager: Arc<Mutex<JobWorker>>,
}

pub mod api;
pub mod db;
pub mod error;
pub mod handler;
pub mod network_manager;
pub mod p2p;
pub mod tracer;
pub mod types;
use crate::{api::get_decrypt_request_status, handler::worker::JobWorker};
use api::{decrypt, encrypt, quote, reencrypt, register};
use db::store::DataStore;
use network_manager::NetworkManager;
use tracer::{TracingConfig, init_tracer};

#[cfg(test)]
mod tests;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracer(TracingConfig::default());
    tracing::info!("Starting encryption server...");

    // Initialize key store
    let data_store = Arc::new(DataStore::new("keystore_db").unwrap());
    tracing::info!("Key store initialized");

    // Initialize network manager
    let network_manager = NetworkManager::new(3001, "encryption-service-node".to_string()).await?;
    tracing::info!("Network manager initialized");

    // Initialize worker manager
    let worker_manager = Arc::new(Mutex::new(JobWorker::new(
        data_store.clone(),
        network_manager.clone(),
    )));
    tracing::info!("Worker manager initialized");

    // Create application state
    let app_state = AppState {
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
        .layer(TraceLayer::new_for_http())
        .with_state(app_state);

    let addr = "0.0.0.0:3000";
    let listener = tokio::net::TcpListener::bind(addr).await?;

    tracing::info!(address = %addr, "Encryption server listening");
    axum::serve(listener, app).await?;

    Ok(())
}
