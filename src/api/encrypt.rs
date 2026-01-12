use crate::{
    db,
    error::AppError,
    types::{EncryptRequest, EncryptResponse},
    utils,
};
use alloy::{primitives::utils::keccak256, signers::Signer};
use axum::{Json, extract::State, response::IntoResponse};
use sqlx::SqlitePool;
use uuid::Uuid;

pub async fn encrypt(
    State(pool): State<SqlitePool>,
    Json(request): Json<EncryptRequest>,
) -> Result<impl IntoResponse, AppError> {
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

    let has_participants = db::has_participants(&pool, &request.turbo_da_app_id.to_string())
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to check participants");
            AppError::Database(format!("Failed to check participants: {}", e))
        })?;

    if !has_participants {
        tracing::warn!(
            app_id = request.turbo_da_app_id.to_string(),
            "No registered participants for app_id"
        );
        return Err(AppError::InvalidInput(
            "No registered participants found. Please register participants first.".into(),
        ));
    }

    let request_span = tracing::info_span!(
        "encrypt_request",
        app_id = request.turbo_da_app_id.to_string(),
        plaintext_length = request.plaintext.len(),
        turbo_da_app_id = request.turbo_da_app_id.to_string()
    );
    let _guard = request_span.enter();

    // Use shared encryption function
    tracing::debug!("Encrypting plaintext using shared utils::encrypt()");
    let ecies_result = utils::encrypt(request.turbo_da_app_id, &request.plaintext).await?;

    let key_size = ecies::config::get_ephemeral_key_size();
    let (ephemeral_pub_key, ciphertext) = ecies_result.split_at(key_size);

    // Get account for signing
    tracing::debug!("Retrieving key for signing");
    let account = utils::get_key(request.turbo_da_app_id).await?;

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
