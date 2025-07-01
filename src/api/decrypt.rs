use crate::error::AppError;
use crate::key_store::KeyStore;
use crate::types::{DecryptRequest, DecryptResponse};
use axum::{extract::State, response::IntoResponse, Json};
use std::sync::Arc;

pub async fn decrypt(
    State(key_store): State<Arc<KeyStore>>,
    Json(request): Json<DecryptRequest>,
) -> Result<impl IntoResponse, AppError> {
    let request_span = tracing::info_span!(
        "decrypt_request",
        app_id = request.app_id,
        ciphertext_length = request.ciphertext.len()
    );
    let _guard = request_span.enter();

    tracing::debug!("Retrieving private key for decryption");
    let private_key = key_store.get_private_key(request.app_id).map_err(|e| {
        tracing::error!(error = %e, "Failed to retrieve private key");
        AppError::KeyNotFound(request.app_id)
    })?;

    tracing::debug!("Decrypting ciphertext");
    let mut full_ciphertext = request.ephemeral_pub_key.clone();
    full_ciphertext.extend_from_slice(&request.ciphertext);

    tracing::debug!(
        "Attempting to decrypt ciphertext for app_id {}",
        request.app_id
    );

    let plaintext = ecies::decrypt(&private_key, &full_ciphertext).map_err(|e| {
        tracing::error!(error = %e, "Decryption failed");
        AppError::DecryptionError(e.to_string())
    })?;

    tracing::info!(
        app_id = request.app_id,
        ciphertext_length = request.ciphertext.len(),
        plaintext_length = plaintext.len(),
        "Successfully decrypted data"
    );

    Ok(Json(DecryptResponse { plaintext }))
}
