use crate::AppState;
use crate::error::AppError;
use crate::types::{EncryptRequest, EncryptResponse};
use alloy::signers::Signer;
use alloy_primitives::utils::keccak256;
use axum::{Json, extract::State, response::IntoResponse};
use dstack_sdk::dstack_client::DstackClient;
use dstack_sdk::ethereum::to_account;

pub async fn encrypt(
    State(state): State<AppState>,
    Json(request): Json<EncryptRequest>,
) -> Result<impl IntoResponse, AppError> {
    let request_span = tracing::info_span!(
        "encrypt_request",
        app_id = request.app_id,
        plaintext_length = request.plaintext.len(),
        turbo_da_app_id = request.turbo_da_app_id.to_string()
    );
    let _guard = request_span.enter();

    // activate below code when run within TEE
    let client = DstackClient::new(None);
    let key = client
        .get_key(Some(request.app_id.to_string()), None)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to retrieve key");
        })
        .expect("Failed to retrieve key");

    let account = to_account(&key)
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to convert key to account");
        })
        .expect("Failed to convert key to account");

    tracing::debug!("Retrieving public key for encryption");
    let public_key = state
        .key_store
        .get_public_key(request.app_id)
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
    let signature = account
        .sign_hash(&message_hash)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to sign message hash");
        })
        .expect("Failed to sign message hash");

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
