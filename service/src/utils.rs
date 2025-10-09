use alloy::{hex, signers::local::LocalSigner};
use dstack_sdk::{
    dstack_client::{DstackClient, GetKeyResponse},
    ethereum::to_account,
};
use k256::ecdsa::SigningKey;
use uuid::Uuid;

use crate::error::AppError;

pub(crate) async fn get_key(turbo_da_app_id: Uuid) -> Result<LocalSigner<SigningKey>, AppError> {
    let client = DstackClient::new(None);
    let key = client
        .get_key(Some(turbo_da_app_id.to_string()), None)
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
        signature_chain: key.signature_chain,
    };

    let account = to_account(&key_response).map_err(|e| {
        tracing::error!(error = %e, "Failed to convert key to account");
        AppError::KeyGenerationError(format!("Failed to convert key to account: {}", e))
    })?;

    Ok(account)
}
