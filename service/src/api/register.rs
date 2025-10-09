use crate::AppState;
use crate::db::types::{RegisterAppRequestData, RequestStatus};
use crate::error::AppError;
use crate::handler::worker::JobType;
use crate::types::{
    GetRegisterAppRequestStatusRequest, GetRegisterAppRequestStatusResponse, RegisterAppRequest,
    RegisterResponse,
};
use crate::utils::get_key;
use axum::extract::Query;
use axum::{Json, extract::State, response::IntoResponse};
use dstack_sdk::dstack_client::DstackClient;
use uuid::Uuid;

pub async fn register(
    State(state): State<AppState>,
    Json(request): Json<RegisterAppRequest>,
) -> Result<impl IntoResponse, AppError> {
    // Input validation
    if request.turbo_da_app_id.is_nil() {
        tracing::warn!("Invalid app_id: 0");
        return Err(AppError::InvalidInput("app_id cannot be 0".into()));
    }

    let request_span = tracing::info_span!(
        "register_request",
        app_id = request.turbo_da_app_id.to_string()
    );
    let _guard = request_span.enter();

    // Check if app_id is already registered
    match state
        .data_store
        .get_public_key(request.turbo_da_app_id)
        .await
    {
        Ok(_) => {
            tracing::warn!(
                app_id = request.turbo_da_app_id.to_string(),
                "App ID already registered"
            );
            return Ok(Json(RegisterResponse {
                turbo_da_app_id: request.turbo_da_app_id,
                job_id: Uuid::from_u128(0),
            }));
        }
        Err(e) if e.to_string().contains("Public key not found") => {
            tracing::info!(
                app_id = request.turbo_da_app_id.to_string(),
                "App ID not found, proceeding with registration"
            );
        }
        Err(e) => {
            tracing::error!(error = ?e, "Database error during public key lookup");
            return Err(AppError::Database(e.to_string()));
        }
    }

    let job_id = Uuid::new_v4();

    state
        .data_store
        .store_register_app_request(RegisterAppRequestData {
            app_id: request.turbo_da_app_id.to_string(),
            job_id,
            status: RequestStatus::Pending,
            public_key: None,
        })
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to store register app request");
            AppError::Database(e.to_string())
        })?;

    let account = get_key(request.turbo_da_app_id).await?;

    println!("no issues till here");

    tracing::info!(
        app_id = request.turbo_da_app_id.to_string(),
        "Successfully sent register app request"
    );

    Ok(Json(RegisterResponse {
        turbo_da_app_id: request.turbo_da_app_id,
        job_id: job_id,
    }))
}
