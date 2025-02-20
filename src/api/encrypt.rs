use crate::error::AppError;
use crate::key_store::KeyStore;
use crate::types::{EncryptRequest, EncryptResponse};
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
    let ecies_result = ecies::encrypt(&public_key, &request.plaintext)
        .map_err(|e| {
            tracing::error!(error = %e, "Encryption failed");
            AppError::EncryptionError(e.to_string())
        })?;
    
    let key_size = ecies::config::get_ephemeral_key_size();
    let (ephemeral_pub_key, ciphertext) = ecies_result.split_at(key_size);
    
    tracing::info!(
        app_id = request.app_id,
        plaintext_length = request.plaintext.len(),
        ciphertext_length = ciphertext.len(),
        "Successfully encrypted data"
    );
    
    Ok(Json(EncryptResponse{
        ciphertext: ciphertext.to_vec(),
        signature: "Signature".to_string(),
        ephemeral_pub_key: ephemeral_pub_key.to_vec()
    }))
}