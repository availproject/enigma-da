use crate::error::AppError;
use crate::types::DecryptRequest;
use crate::utils::get_key;

use alloy::hex;
use axum::{Json, response::IntoResponse};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptRequestData {
    pub app_id: String,
    pub ciphertext_array: Vec<u8>,
    pub ephemeral_pub_key_array: Vec<u8>,
    pub decrypted_array: Option<Vec<u8>>,
}

pub async fn decrypt(Json(request): Json<DecryptRequest>) -> Result<impl IntoResponse, AppError> {
    let request_span = tracing::info_span!(
        "decrypt_request",
        app_id = request.turbo_da_app_id.to_string(),
        ciphertext_length = request.ciphertext.len(),
        turbo_da_app_id = request.turbo_da_app_id.to_string()
    );
    let _guard = request_span.enter();

    // Input validation
    if request.ciphertext.is_empty() || request.ephemeral_pub_key.is_empty() {
        tracing::warn!(
            app_id = request.turbo_da_app_id.to_string(),
            "Empty ciphertext or ephemeral public key"
        );
        return Err(AppError::InvalidInput(
            "Ciphertext and ephemeral public key must not be empty".into(),
        ));
    }

    tracing::debug!(
        "Attempting to decrypt ciphertext for app_id {}",
        request.turbo_da_app_id
    );

    let account = get_key(request.turbo_da_app_id).await?;

    let decryption_key = account.credential().to_bytes().to_vec();

    tracing::debug!("Decryption key: {}", hex::encode(decryption_key.clone()));
    let decrypted_data = ecies::decrypt(&decryption_key, &request.ciphertext).map_err(|e| {
        tracing::error!(error = %e, "Failed to decrypt data");
        AppError::EncryptionError(e.to_string())
    })?;

    Ok(Json(DecryptRequestData {
        app_id: request.turbo_da_app_id.to_string(),
        ciphertext_array: request.ciphertext,
        ephemeral_pub_key_array: request.ephemeral_pub_key,
        decrypted_array: Some(decrypted_data),
    }))
}
