use crate::AppState;
use crate::db::types::{RegisterAppRequestData, RequestStatus};
use crate::error::AppError;
use crate::handler::worker::JobType;
use crate::types::{
    GetRegisterAppRequestStatusRequest, GetRegisterAppRequestStatusResponse, RegisterAppRequest,
    RegisterResponse,
};
use axum::{Json, extract::State, response::IntoResponse};
use uuid::Uuid;

pub async fn register(
    State(state): State<AppState>,
    Json(request): Json<RegisterAppRequest>,
) -> Result<impl IntoResponse, AppError> {
    // Input validation
    if request.app_id == 0 {
        tracing::warn!("Invalid app_id: 0");
        return Err(AppError::InvalidInput("app_id cannot be 0".into()));
    }

    let request_span = tracing::info_span!("register_request", app_id = request.app_id);
    let _guard = request_span.enter();

    // Check if app_id is already registered
    match state.data_store.get_public_key(request.app_id).await {
        Ok(_) => {
            tracing::warn!(app_id = request.app_id, "App ID already registered");
            return Ok(Json(RegisterResponse {
                app_id: request.app_id,
                job_id: Uuid::from_u128(0),
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

    let job_id = Uuid::new_v4();

    state
        .data_store
        .store_register_app_request(RegisterAppRequestData {
            app_id: request.app_id.to_string(),
            job_id,
            status: RequestStatus::Pending,
            public_key: None,
        })
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to store register app request");
            AppError::Database(e.to_string())
        })?;

    state
        .worker_manager
        .send_job(JobType::RegisterApp(request.app_id, job_id))
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to send register app request to worker");
            AppError::Internal(e.to_string())
        })?;

    tracing::info!(
        app_id = request.app_id,
        "Successfully sent register app request"
    );

    Ok(Json(RegisterResponse {
        app_id: request.app_id,
        job_id: job_id,
    }))
}

pub async fn get_register_app_request_status(
    State(state): State<AppState>,
    Json(request): Json<GetRegisterAppRequestStatusRequest>,
) -> Result<impl IntoResponse, AppError> {
    let request_span = tracing::info_span!(
        "get_register_app_request_status",
        job_id = request.job_id.to_string()
    );
    let _guard = request_span.enter();

    let register_app_request = state
        .data_store
        .get_register_app_request(request.job_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get register app request status");
            AppError::Database(e.to_string())
        })?;

    if register_app_request.is_none() {
        tracing::error!(
            job_id = request.job_id.to_string(),
            "Register app request not found"
        );
        return Err(AppError::RequestNotFound(format!(
            "Register app request not found for job id: {}",
            request.job_id
        )));
    }

    Ok(Json(GetRegisterAppRequestStatusResponse {
        request: register_app_request.unwrap(),
    }))
}
