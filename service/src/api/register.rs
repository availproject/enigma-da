use crate::AppState;
use crate::error::AppError;
use crate::types::{RegisterRequest, RegisterResponse};
use axum::{Json, extract::State, response::IntoResponse};
use keygen::keygen;

pub async fn register(
    State(state): State<AppState>,
    Json(request): Json<RegisterRequest>,
) -> Result<impl IntoResponse, AppError> {
    let request_span = tracing::info_span!("register_request", app_id = request.app_id);
    let _guard = request_span.enter();

    // Check if app_id is already registered
    match state.data_store.get_public_key(request.app_id) {
        Ok(existing_key) => {
            tracing::warn!(app_id = request.app_id, "App ID already registered");
            return Ok(Json(RegisterResponse {
                app_id: request.app_id,
                public_key: existing_key,
            }));
        }
        Err(e) if e.to_string().contains("Public key not found") => {
            tracing::info!(
                app_id = request.app_id,
                "App ID not found, proceeding with registration"
            );
        }
        Err(e) => {
            tracing::error!(error = ?e, "Database error during public key lookup");
            return Err(AppError::Database(e.to_string()));
        }
    }

    println!("app id not found");

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

    tracing::debug!("Generated keypair successfully");

    if let Err(e) = state
        .data_store
        .store_public_key(request.app_id, &public_key)
    {
        tracing::error!(error = ?e, "Failed to store keys");
        return Err(AppError::Database(e.to_string()));
    }
    tracing::info!(app_id = request.app_id, "Successfully registered new app");

    Ok(Json(RegisterResponse {
        app_id: request.app_id,
        public_key: public_key,
    }))
}
