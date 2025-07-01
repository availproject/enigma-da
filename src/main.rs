use axum::{
    routing::{get, post},
    Router,
};
use std::sync::Arc;
use tower_http::trace::TraceLayer;

pub mod api;
pub mod error;
pub mod key_store;
pub mod tracer;
pub mod types;

use api::{decrypt, encrypt, quote, register};
use key_store::KeyStore;
use tracer::{init_tracer, TracingConfig};

#[tokio::main]
async fn main() {
    init_tracer(TracingConfig::default());
    tracing::info!("Starting encryption server...");

    // Initialize key store
    let key_store = Arc::new(KeyStore::new("keystore_db").unwrap());
    tracing::info!("Key store initialized");

    // Application routes
    let app = Router::new()
        .route("/v1/register", post(register))
        .route("/v1/encrypt", post(encrypt))
        .route("/v1/decrypt", post(decrypt))
        .route("/v1/quote", get(quote))
        .layer(TraceLayer::new_for_http())
        .with_state(key_store);

    let addr = "0.0.0.0:3000";
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    tracing::info!(address = %addr, "Encryption server listening");
    axum::serve(listener, app).await.unwrap();
}
