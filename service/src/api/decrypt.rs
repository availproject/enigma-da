use crate::AppState;
use crate::error::AppError;
use crate::p2p::node::NodeCommand;
use crate::types::{DecryptRequest, DecryptResponse};
use axum::{Json, extract::State, response::IntoResponse};

pub async fn decrypt(
    State(state): State<AppState>,
    Json(request): Json<DecryptRequest>,
) -> Result<impl IntoResponse, AppError> {
    let request_span = tracing::info_span!(
        "decrypt_request",
        app_id = request.app_id,
        ciphertext_length = request.ciphertext.len(),
        turbo_da_app_id = request.turbo_da_app_id.to_string()
    );
    let _guard = request_span.enter();

    // Input validation
    if request.ciphertext.is_empty() || request.ephemeral_pub_key.is_empty() {
        tracing::warn!(
            app_id = request.app_id,
            "Empty ciphertext or ephemeral public key"
        );
        return Err(AppError::InvalidInput(
            "Ciphertext and ephemeral public key must not be empty".into(),
        ));
    }

    // Retrieve private key
    tracing::debug!("Retrieving private key for app_id {}", request.app_id);
    let private_key = match state.key_store.get_private_key(request.app_id) {
        Ok(key) => key,
        Err(AppError::KeyNotFound(_)) => {
            tracing::warn!(app_id = request.app_id, "Private key not found");
            return Err(AppError::KeyNotFound(request.app_id));
        }
        Err(e) => {
            tracing::error!(error = ?e, "Database error while retrieving private key");
            return Err(e);
        }
    };

    // Construct full ciphertext for ECIES decryption
    let mut full_ciphertext = request.ephemeral_pub_key.clone();
    full_ciphertext.extend_from_slice(&request.ciphertext);

    tracing::debug!(
        "Attempting to decrypt ciphertext for app_id {}",
        request.app_id
    );

    let plaintext = ecies::decrypt(&private_key, &full_ciphertext).map_err(|e| {
        tracing::error!(error = ?e, "Decryption failed for app_id {}", request.app_id);
        AppError::DecryptionError(e.to_string())
    })?;

    // Send a command to the network node after successful decryption
    if let Err(e) = state
        .network_manager
        .lock()
        .await
        .send_command(NodeCommand::StoreShard {
            app_id: request.app_id.to_string(),
            shard_index: 0u32, // You can customize this based on your needs
            shard: String::from_utf8_lossy(&plaintext).to_string(),
        })
        .await
    {
        tracing::warn!(error = %e, "Failed to send command to network node");
    }

    tracing::info!(
        app_id = request.app_id,
        ciphertext_length = request.ciphertext.len(),
        plaintext_length = plaintext.len(),
        "Successfully decrypted data"
    );

    Ok(Json(DecryptResponse { plaintext }))
}
