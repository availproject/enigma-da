use axum::{
    routing::{get, post},
    Router,
};
use std::sync::Arc;
use tokio::sync::Mutex;
use tower_http::trace::TraceLayer;

#[derive(Clone)]
pub struct AppState {
    pub key_store: Arc<KeyStore>,
    pub network_manager: Arc<Mutex<NetworkManager>>,
}

pub mod api;
pub mod error;
pub mod key_store;
pub mod network_manager;
pub mod p2p;
pub mod tracer;
pub mod types;

use api::{decrypt, encrypt, quote, reencrypt, register};
use key_store::KeyStore;
use network_manager::NetworkManager;
use tracer::{init_tracer, TracingConfig};

#[cfg(test)]
mod tests;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracer(TracingConfig::default());
    tracing::info!("Starting encryption server...");

    // Initialize key store
    let key_store = Arc::new(KeyStore::new("keystore_db").unwrap());
    tracing::info!("Key store initialized");

    // Initialize network manager
    let network_manager = NetworkManager::new(3001, "encryption-service-node".to_string()).await?;
    tracing::info!("Network manager initialized");

    // Create application state
    let app_state = AppState {
        key_store,
        network_manager,
    };

    // Application routes
    let app = Router::new()
        .route("/v1/register", post(register))
        .route("/v1/encrypt", post(encrypt))
        .route("/v1/decrypt", post(decrypt))
        .route("/v1/quote", get(quote))
        .route("/v1/private-key", post(reencrypt))
        .layer(TraceLayer::new_for_http())
        .with_state(app_state);

    let addr = "0.0.0.0:3000";
    let listener = tokio::net::TcpListener::bind(addr).await?;

    tracing::info!(address = %addr, "Encryption server listening");
    axum::serve(listener, app).await?;

    Ok(())
}
