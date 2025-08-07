use crate::AppState;
use crate::db::types::{DecryptRequestData, RequestStatus};
use crate::error::AppError;
use crate::handler::worker::JobType;
use crate::types::{
    DecryptRequest, DecryptResponse, GetDecryptRequestStatusRequest,
    GetDecryptRequestStatusResponse,
};
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

    let job_id = uuid::Uuid::new_v4();
    let request_data = DecryptRequestData {
        app_id: request.app_id.to_string(),
        ciphertext_array: request.ciphertext.clone(),
        ephemeral_pub_key_array: request.ephemeral_pub_key.clone(),
        job_id,
        status: RequestStatus::Pending,
        decrypted_array: None,
    };

    state
        .data_store
        .store_decrypt_request(request_data)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to store decrypt request");
            AppError::Database(e.to_string())
        })?;

    tracing::debug!(
        "Attempting to decrypt ciphertext for app_id {}",
        request.app_id
    );

    // Send the request to the worker
    state
        .worker_manager
        .send_job(JobType::DecryptJob(
            request.app_id,
            job_id,
            request.ciphertext.clone(),
            request.ephemeral_pub_key.clone(),
        ))
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to send decrypt job to worker");
            AppError::Internal(e.to_string())
        })?;

    tracing::info!(
        app_id = request.app_id,
        job_id = job_id.to_string(),
        "Successfully sent decrypt job to worker"
    );

    Ok(Json(DecryptResponse { job_id }))
}

pub async fn get_decrypt_request_status(
    State(state): State<AppState>,
    Json(request): Json<GetDecryptRequestStatusRequest>,
) -> Result<impl IntoResponse, AppError> {
    let request_span = tracing::info_span!(
        "get_decrypt_request_status",
        job_id = request.job_id.to_string(),
    );
    let _guard = request_span.enter();

    let decrypt_request = state
        .data_store
        .get_decrypt_request(request.job_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get decrypt request status");
            AppError::Database(e.to_string())
        })?;

    if decrypt_request.is_none() {
        tracing::error!(
            job_id = request.job_id.to_string(),
            "Decrypt request not found"
        );
        return Err(AppError::RequestNotFound(format!(
            "Decrypt request not found for job id: {}",
            request.job_id.to_string()
        )));
    }

    Ok(Json(GetDecryptRequestStatusResponse {
        request: decrypt_request.unwrap(),
    }))
}
