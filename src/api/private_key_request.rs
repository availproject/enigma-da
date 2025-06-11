use std::sync::Arc;
use axum::{extract::State, response::IntoResponse, Json};
use crate::{error::AppError, key_store::KeyStore, types::{PrivateKeyRequest, PrivateKeyResponse}};

pub async fn private_key_request(
    State(key_store): State<Arc<KeyStore>>,
    Json(request): Json<PrivateKeyRequest>,
) -> Result<impl IntoResponse, AppError> {
    let request_span = tracing::info_span!(
        "private_key_request",
        app_id = request.app_id,
        public_key_length = request.public_key.len()
    );
    let _guard = request_span.enter();

    tracing::debug!("Retrieving private key for app id: {}", request.app_id);
    let private_key = key_store.get_private_key(request.app_id).map_err(|e| {
        tracing::error!(error = %e, "Failed to retrieve private key");
        AppError::KeyNotFound(request.app_id)
    })?;

    tracing::debug!("Encrypting private key");
    let encrypted_private_key = ecies::encrypt(&request.public_key, &private_key).map_err(|e| {
        tracing::error!(error = %e, "Failed to encrypt private key");
        AppError::EncryptionError(e.to_string())
    })?;

    let key_size = ecies::config::get_ephemeral_key_size();
    let (ephemeral_pub_key, ciphertext) = encrypted_private_key.split_at(key_size);

    tracing::info!(app_id = request.app_id, "Successfully retrieved and encrypted private key");

    Ok(Json(PrivateKeyResponse {
        ephemeral_pub_key: ephemeral_pub_key.to_vec(),
        ciphertext: ciphertext.to_vec(),
    }))
}