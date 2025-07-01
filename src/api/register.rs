use crate::error::AppError;
// use crate::key_store::KeyStore;
use crate::types::{RegisterRequest, RegisterResponse};
use axum::{
    // extract::State,
    response::IntoResponse,
    Json,
};
use keygen::keygen;

pub async fn register(
    // State(key_store): State<Arc<KeyStore>>,
    Json(request): Json<RegisterRequest>,
) -> Result<impl IntoResponse, AppError> {
    let request_span = tracing::info_span!("register_request", app_id = request.app_id);
    let _guard = request_span.enter();

    tracing::debug!("Generating new keypair");
    let public_key = (keygen(
        request.k,
        request.n,
        "ECIESThreshold",
        "./conf",
        true,
        request.app_id,
    ))
    .map_err(|e| AppError::KeyGenerationError(e.to_string()))?;

    // let (private_key, public_key) = ecies::utils::generate_keypair();

    tracing::debug!("Generated keypair successfully");

    // let _ = key_store.store_keys(request.app_id, &public_key.serialize(), &private_key.serialize());
    tracing::info!(app_id = request.app_id, "Successfully registered new app");

    Ok(Json(RegisterResponse {
        app_id: request.app_id,
        public_key: public_key,
    }))
}
