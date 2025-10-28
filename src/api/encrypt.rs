use crate::{
    error::AppError,
    types::{EncryptRequest, EncryptResponse},
    utils::get_key,
};
use alloy::{primitives::utils::keccak256, signers::Signer};
use axum::{Json, response::IntoResponse};
use uuid::Uuid;

pub async fn encrypt(Json(request): Json<EncryptRequest>) -> Result<impl IntoResponse, AppError> {
    // Input validation
    if request.plaintext.is_empty() {
        tracing::warn!(
            app_id = request.turbo_da_app_id.to_string(),
            "Empty plaintext provided"
        );
        return Err(AppError::InvalidInput("Plaintext cannot be empty".into()));
    }

    if request.turbo_da_app_id == Uuid::new_v4() {
        tracing::warn!("Invalid app_id: 0");
        return Err(AppError::InvalidInput("app_id cannot be 0".into()));
    }

    let request_span = tracing::info_span!(
        "encrypt_request",
        app_id = request.turbo_da_app_id.to_string(),
        plaintext_length = request.plaintext.len(),
        turbo_da_app_id = request.turbo_da_app_id.to_string()
    );
    let _guard = request_span.enter();

    tracing::debug!("Retrieving public key for encryption");
    let account = get_key(request.turbo_da_app_id).await?;

    let public_key = account
        .credential()
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();

    tracing::debug!("Encrypting plaintext");
    let ecies_result = ecies::encrypt(&public_key, &request.plaintext).map_err(|e| {
        tracing::error!(error = %e, "Encryption failed");
        AppError::EncryptionError(e.to_string())
    })?;

    let key_size = ecies::config::get_ephemeral_key_size();
    let (ephemeral_pub_key, ciphertext) = ecies_result.split_at(key_size);

    let message_hash = keccak256(ciphertext);
    let signature_ciphertext = account.sign_hash(&message_hash).await.map_err(|e| {
        tracing::error!(error = %e, "Failed to sign message hash");
        AppError::EncryptionError(format!("Failed to sign message hash: {}", e))
    })?;

    let message_hash_plaintext = keccak256(&request.plaintext);
    let signature_plaintext_hash =
        account
            .sign_hash(&message_hash_plaintext)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to sign message hash");
                AppError::EncryptionError(format!("Failed to sign message hash: {}", e))
            })?;

    tracing::info!(
        app_id = request.turbo_da_app_id.to_string(),
        plaintext_length = request.plaintext.len(),
        ciphertext_length = ciphertext.len(),
        "Successfully encrypted data"
    );

    Ok(Json(EncryptResponse {
        ciphertext: ciphertext.to_vec(),
        ciphertext_hash: message_hash.to_vec(),
        plaintext_hash: message_hash_plaintext.to_vec(),
        address: account.address(),
        signature_ciphertext_hash: signature_ciphertext,
        signature_plaintext_hash: signature_plaintext_hash,
        ephemeral_pub_key: ephemeral_pub_key.to_vec(),
    }))
}
