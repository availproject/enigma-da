use crate::types::DecryptRequest;
use crate::utils::get_key;
use crate::{error::AppError, types::DecryptRequestData};

use alloy::hex;
use axum::{Json, response::IntoResponse};

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

    tracing::info!("Decryption key: {}", hex::encode(decryption_key.clone()));
    let mut full_ciphertext = request.ephemeral_pub_key.clone();
    full_ciphertext.extend_from_slice(&request.ciphertext);

    let decrypted_data = ecies::decrypt(&decryption_key, &full_ciphertext).map_err(|e| {
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
