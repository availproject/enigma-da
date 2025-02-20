use crate::crypto::generate_keypair;
use crate::error::AppError;
use crate::key_store::KeyStore;
use crate::types::{RegisterRequest, RegisterResponse};
use axum::{
    extract::State,
    response::IntoResponse,
    Json, 
};
use std::sync::Arc;

pub async fn register(
    State(key_store): State<Arc<KeyStore>>,
    Json(request): Json<RegisterRequest>,
) -> Result<impl IntoResponse, AppError> {
    let request_span = tracing::info_span!("register_request", app_id = request.app_id);
    let _guard = request_span.enter();

    tracing::debug!("Generating new keypair");
    let (public_key, private_key) = generate_keypair()?;
    
    tracing::debug!("Generated keypair successfully");
    
    key_store.store_keys(request.app_id, &public_key, &private_key).await?;
    tracing::info!(app_id = request.app_id, "Successfully registered new app");
    
    Ok(Json(RegisterResponse {
        app_id: request.app_id,
        public_key,
    }))
}