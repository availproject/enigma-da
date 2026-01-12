use alloy::{hex, signers::local::LocalSigner};
use alloy_primitives::{Address, Signature};
use dstack_sdk::{
    dstack_client::{DstackClient, GetKeyResponse},
    ethereum::to_account,
};

use crate::{error::AppError, types::QuoteResponse};
use k256::ecdsa::SigningKey;
use uuid::Uuid;

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

pub(crate) async fn encrypt(turbo_da_app_id: Uuid, plaintext: &[u8]) -> Result<Vec<u8>, AppError> {
    tracing::info!(
        app_id = %turbo_da_app_id,
        "Starting MPC encryption process"
    );

    let account = get_key(turbo_da_app_id).await?;

    let public_key = account
        .credential()
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();

    let ciphertext = ecies::encrypt(&public_key, plaintext).map_err(|e| {
        tracing::error!(error = %e, "ECIES encryption failed");
        AppError::EncryptionError(format!("ECIES encryption failed: {}", e))
    })?;

    tracing::info!(
        app_id = %turbo_da_app_id,
        ciphertext_length = ciphertext.len(),
        "Encryption completed successfully"
    );

    Ok(ciphertext)
}

pub(crate) async fn decrypt(turbo_da_app_id: Uuid, ciphertext: &[u8]) -> Result<Vec<u8>, AppError> {
    tracing::info!(
        app_id = %turbo_da_app_id,
        "Starting MPC decryption process"
    );

    let account = get_key(turbo_da_app_id).await?;

    let private_key_bytes = account.credential().to_bytes();

    let plaintext = ecies::decrypt(&private_key_bytes, ciphertext).map_err(|e| {
        tracing::error!(error = %e, "ECIES decryption failed");
        AppError::DecryptionError(format!("ECIES decryption failed: {}", e))
    })?;

    tracing::info!(
        app_id = %turbo_da_app_id,
        plaintext_length = plaintext.len(),
        "Decryption completed successfully"
    );

    Ok(plaintext)
}

pub async fn quote(data: Vec<u8>) -> Result<QuoteResponse, AppError> {
    let client = DstackClient::new(None);

    let quote_resp = client.get_quote(data).await.map_err(|e| {
        tracing::error!(error = ?e, "Failed to generate quote");
        AppError::QuoteGenerationFailed(e.to_string())
    })?;

    tracing::info!(
        quote_length = quote_resp.event_log.len(),
        "Successfully generated quote"
    );

    Ok(QuoteResponse { quote: quote_resp })
}

pub(crate) fn verify_ecdsa_signature(
    message: &str,
    signature_hex: &str,
    expected_address: &str,
) -> Result<bool, AppError> {
    println!("signatre hex {signature_hex}");
    let signature = signature_hex.parse::<Signature>().map_err(|e| {
        tracing::error!(error = %e, "Failed to parse signature");
        AppError::InvalidInput(format!("Invalid signature format: {}", e))
    })?;

    let expected_addr = expected_address.parse::<Address>().map_err(|e| {
        tracing::error!(error = %e, "Failed to parse address");
        AppError::InvalidInput(format!("Invalid address format: {}", e))
    })?;

    let recovered_addr = signature.recover_address_from_msg(message).map_err(|e| {
        tracing::error!(error = %e, "Failed to recover address from signature");
        AppError::InvalidInput(format!("Signature recovery failed: {}", e))
    })?;

    let is_valid = recovered_addr == expected_addr;

    if is_valid {
        tracing::debug!(
            expected = %expected_addr,
            recovered = %recovered_addr,
            "ECDSA signature verified successfully"
        );
    } else {
        tracing::warn!(
            expected = %expected_addr,
            recovered = %recovered_addr,
            "ECDSA signature verification failed - address mismatch"
        );
    }

    Ok(is_valid)
}
