use crate::error::AppError;
use crate::key_store::KeyStore;
use crate::types::{RegisterRequest, RegisterResponse};
use axum::{
    extract::State,
    response::IntoResponse,
    Json, 
};
use std::sync::Arc;

pub async fn register(
    State(key_store): State<Arc<KeyStore>>,
    Json(request): Json<RegisterRequest>,
) -> Result<impl IntoResponse, AppError> {
    let request_span = tracing::info_span!("register_request", app_id = request.app_id);
    let _guard = request_span.enter();

    // Check if app_id is already registered
    match key_store.get_public_key(request.app_id) {
        Ok(existing_key) => {
            tracing::warn!(app_id = request.app_id, "App ID already registered");
            return Ok(Json(RegisterResponse {
                app_id: request.app_id,
                public_key: existing_key,
            }));
        }
        Err(AppError::KeyNotFound(_)) => {
            tracing::info!(app_id = request.app_id, "App ID not found, proceeding with registration");
        }
        Err(e) => {
            tracing::error!(error = ?e, "Database error during public key lookup");
            return Err(e); 
        }
    }

    println!("app id not found");

    tracing::debug!("Generating new keypair");
    let (private_key, public_key) = ecies::utils::generate_keypair();

    if private_key.serialize().is_empty() || public_key.serialize().is_empty() {
        tracing::error!("Generated empty keypair");
        return Err(AppError::InvalidKey("Generated keypair is invalid".into()));
    }

    // Try to store the keys
    if let Err(e) = key_store.store_keys(
        request.app_id,
        &public_key.serialize(),
        &private_key.serialize(),
    ) {
        tracing::error!(error = ?e, "Failed to store keys");
        return Err(e);
    }

    tracing::info!(app_id = request.app_id, "Successfully registered new app");

    Ok(Json(RegisterResponse {
        app_id: request.app_id,
        public_key: public_key.serialize().to_vec(),
    }))
}
