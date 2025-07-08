use crate::AppState;
use crate::{
    error::AppError,
    types::{PrivateKeyRequest, PrivateKeyResponse},
};
use axum::{extract::State, response::IntoResponse, Json};

pub async fn reencrypt(
    State(state): State<AppState>,
    Json(request): Json<PrivateKeyRequest>,
) -> Result<impl IntoResponse, AppError> {
    let request_span = tracing::info_span!(
        "reencrypt",
        app_id = request.app_id,
        public_key_length = request.public_key.len()
    );
    let _guard = request_span.enter();

    tracing::debug!("Retrieving private key for app id: {}", request.app_id);
    let private_key = state
        .key_store
        .get_private_key(request.app_id)
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to retrieve private key");
            AppError::KeyNotFound(request.app_id)
        })?;

    tracing::debug!("Encrypting private key");
    let (ephemeral_pub_key, ciphertext) = encrypt_private_key(&private_key, &request.public_key)?;

    tracing::info!(
        app_id = request.app_id,
        "Successfully retrieved and encrypted private key"
    );

    Ok(Json(PrivateKeyResponse {
        ephemeral_pub_key: ephemeral_pub_key.to_vec(),
        ciphertext: ciphertext.to_vec(),
    }))
}

pub fn encrypt_private_key(
    private_key: &[u8],
    public_key: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), AppError> {
    let encrypted_private_key = ecies::encrypt(public_key, private_key).map_err(|e| {
        tracing::error!(error = %e, "Failed to encrypt private key");
        AppError::EncryptionError(e.to_string())
    })?;

    let key_size = ecies::config::get_ephemeral_key_size();
    let (ephemeral_pub_key, ciphertext) = encrypted_private_key.split_at(key_size);

    Ok((ephemeral_pub_key.to_vec(), ciphertext.to_vec()))
}
