use crate::error::AppError;
use crate::key_store::KeyStore;
use crate::types::EncryptRequest;
use axum::{
    extract::State,
    response::IntoResponse,
    Json, 
};
use std::sync::Arc;

pub async fn encrypt(
    State(key_store): State<Arc<KeyStore>>,
    Json(request): Json<EncryptRequest>,
) -> Result<impl IntoResponse, AppError> {
    let request_span = tracing::info_span!("encrypt_request", 
        app_id = request.app_id,
        plaintext_length = request.plaintext.len()
    );
    let _guard = request_span.enter();

    tracing::debug!("Retrieving public key for encryption");
    let public_key = key_store.get_public_key(request.app_id).await?;
    
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