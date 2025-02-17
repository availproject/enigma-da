use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, fmt::format::FmtSpan};

mod error;
mod storage;
mod types;
mod crypto;

use error::AppError;
use storage::KeyStorage;
use types::{RegisterRequest, RegisterResponse, EncryptRequest};
use crypto::generate_keypair;

#[tokio::main]
async fn main() {
    // Initialize tracing with JSON formatting and spans
    tracing_subscriber::registry()
    .with(
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "encryption_server=debug,tower_http=debug".into()),
    )
    .with(
        tracing_subscriber::fmt::layer()
            .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
            .with_file(true)
            .with_line_number(true)
            .with_target(true)
            .with_thread_ids(true)
            .with_thread_names(true)
            .with_ansi(false)
    )
    .init();

    tracing::info!("Starting encryption server...");

    // Initialize storage
    let storage = Arc::new(KeyStorage::new());
    tracing::info!("Key storage initialized");

    // Build our application with a route
    let app = Router::new()
        .route("/v1/register", post(register))
        .route("/v1/encrypt", post(encrypt))
        .route("/v1/quote", get(quote))
        .layer(TraceLayer::new_for_http())
        .with_state(storage);

    // Run it
    let addr = "127.0.0.1:3000";
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap();
    
    tracing::info!(address = %addr, "Server listening");
    axum::serve(listener, app).await.unwrap();
}

async fn register(
    State(storage): State<Arc<KeyStorage>>,
    Json(request): Json<RegisterRequest>,
) -> Result<impl IntoResponse, AppError> {
    let request_span = tracing::info_span!("register_request", app_id = request.app_id);
    let _guard = request_span.enter();

    tracing::debug!("Generating new keypair");
    let (public_key, private_key) = generate_keypair()?;
    
    tracing::debug!("Generated keypair successfully");
    
    storage.store_keys(request.app_id, &public_key, &private_key).await?;
    tracing::info!(app_id = request.app_id, "Successfully registered new app");
    
    Ok(Json(RegisterResponse {
        app_id: request.app_id,
        public_key,
    }))
}

async fn encrypt(
    State(storage): State<Arc<KeyStorage>>,
    Json(request): Json<EncryptRequest>,
) -> Result<impl IntoResponse, AppError> {
    let request_span = tracing::info_span!("encrypt_request", 
        app_id = request.app_id,
        plaintext_length = request.plaintext.len()
    );
    let _guard = request_span.enter();

    tracing::debug!("Retrieving public key for encryption");
    let public_key = storage.get_public_key(request.app_id).await?;
    
    tracing::debug!("Encrypting plaintext");
    let encrypted = ecies::encrypt(&public_key, &request.plaintext)
        .map_err(|e| {
            tracing::error!(error = %e, "Encryption failed");
            AppError::EncryptionError(e.to_string())
        })?;
    
    tracing::info!(
        app_id = request.app_id,
        plaintext_length = request.plaintext.len(),
        ciphertext_length = encrypted.len(),
        "Successfully encrypted data"
    );
    
    Ok(Json(encrypted))
}

async fn quote() -> impl IntoResponse {
    let span = tracing::info_span!("generate_quote");
    let _guard = span.enter();

    tracing::debug!("Generating random quote bytes");
    let random_bytes: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
    
    tracing::info!(
        quote_length = random_bytes.len(),
        "Successfully generated quote"
    );
    
    Json(random_bytes)
}