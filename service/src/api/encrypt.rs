use crate::AppState;
use crate::error::AppError;
use crate::types::{EncryptRequest, EncryptResponse};
use alloy::hex;
use alloy::signers::Signer;
use alloy_primitives::utils::keccak256;
use axum::{Json, extract::State, response::IntoResponse};
use dstack_sdk::dstack_client::GetKeyResponse;
use dstack_sdk::ethereum::to_account;
use dstack_sdk::tappd_client::TappdClient;

pub async fn encrypt(
    State(state): State<AppState>,
    Json(request): Json<EncryptRequest>,
) -> Result<impl IntoResponse, AppError> {
    // Input validation
    if request.plaintext.is_empty() {
        tracing::warn!(app_id = request.app_id, "Empty plaintext provided");
        return Err(AppError::InvalidInput("Plaintext cannot be empty".into()));
    }

    if request.app_id == 0 {
        tracing::warn!("Invalid app_id: 0");
        return Err(AppError::InvalidInput("app_id cannot be 0".into()));
    }

    let request_span = tracing::info_span!(
        "encrypt_request",
        app_id = request.app_id,
        plaintext_length = request.plaintext.len(),
        turbo_da_app_id = request.turbo_da_app_id.to_string()
    );
    let _guard = request_span.enter();

    // activate below code when run within TEE
    let client = TappdClient::new(None);
    let key = client
        .derive_key(request.app_id.to_string().as_str())
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to retrieve key");
            AppError::KeyGenerationError(format!("Failed to retrieve key: {}", e))
        })?;

    // Ensure key length is even (required for hex::decode)
    let adjusted_key = key.decode_key().map_err(|e| {
        tracing::error!(error = %e, "Failed to decode key");
        AppError::KeyGenerationError(format!("Failed to decode key: {}", e))
    })?;

    let key_response = GetKeyResponse {
        key: hex::encode(adjusted_key),
        signature_chain: key.certificate_chain,
    };

    let account = to_account(&key_response).map_err(|e| {
        tracing::error!(error = %e, "Failed to convert key to account");
        AppError::KeyGenerationError(format!("Failed to convert key to account: {}", e))
    })?;

    tracing::debug!("Retrieving public key for encryption");
    let public_key = state
        .data_store
        .get_public_key(request.app_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to retrieve public key");
            AppError::KeyNotFound(request.app_id)
        })?;

    tracing::debug!("Encrypting plaintext");
    let ecies_result = ecies::encrypt(&public_key, &request.plaintext).map_err(|e| {
        tracing::error!(error = %e, "Encryption failed");
        AppError::EncryptionError(e.to_string())
    })?;

    let key_size = ecies::config::get_ephemeral_key_size();
    let (ephemeral_pub_key, ciphertext) = ecies_result.split_at(key_size);

    // activate below code when run within TEE
    let message_hash = keccak256(ciphertext);
    let signature = account.sign_hash(&message_hash).await.map_err(|e| {
        tracing::error!(error = %e, "Failed to sign message hash");
        AppError::EncryptionError(format!("Failed to sign message hash: {}", e))
    })?;

    tracing::info!(
        app_id = request.app_id,
        plaintext_length = request.plaintext.len(),
        ciphertext_length = ciphertext.len(),
        "Successfully encrypted data"
    );

    Ok(Json(EncryptResponse {
        ciphertext: ciphertext.to_vec(),
        address: account.address(),
        signature: signature,
        ephemeral_pub_key: ephemeral_pub_key.to_vec(),
    }))
}
