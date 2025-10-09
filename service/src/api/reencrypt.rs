// use crate::AppState;
// use crate::db::types::{ReencryptRequestData, RequestStatus};
// use crate::types::{GetReencryptRequestStatusRequest, GetReencryptRequestStatusResponse};
// use crate::{
//     error::AppError,
//     types::{PrivateKeyRequest, PrivateKeyResponse},
// };
// use axum::{Json, extract::State, response::IntoResponse};

// pub async fn reencrypt(
//     State(state): State<AppState>,
//     Json(request): Json<PrivateKeyRequest>,
// ) -> Result<impl IntoResponse, AppError> {
//     let request_span = tracing::info_span!(
//         "reencrypt",
//         app_id = request.turbo_da_app_id.to_string(),
//         public_key_length = request.public_key.len()
//     );
//     let _guard = request_span.enter();

//     if request.public_key.is_empty() {
//         return Err(AppError::InvalidInput("Public key cannot be empty".into()));
//     }

//     let job_id = uuid::Uuid::new_v4();
//     let request_data = ReencryptRequestData {
//         app_id: request.turbo_da_app_id.to_string(),
//         job_id,
//         status: RequestStatus::Pending,
//         ephemeral_pub_key: None,
//         private_key_ciphertext: None,
//     };

//     state
//         .data_store
//         .store_reencrypt_request(request_data)
//         .await
//         .map_err(|e| {
//             tracing::error!(error = %e, "Failed to store reencrypt request");
//             AppError::Database(e.to_string())
//         })?;

//     tracing::info!(
//         app_id = request.turbo_da_app_id.to_string(),
//         job_id = job_id.to_string(),
//         "Successfully sent reencrypt job to worker"
//     );

//     Ok(Json(PrivateKeyResponse { job_id }))
// }

// pub async fn get_reencrypt_request_status(
//     State(state): State<AppState>,
//     Json(request): Json<GetReencryptRequestStatusRequest>,
// ) -> Result<impl IntoResponse, AppError> {
//     let request_span = tracing::info_span!(
//         "get_reencrypt_request_status",
//         job_id = request.job_id.to_string(),
//     );
//     let _guard = request_span.enter();

//     let reencrypt_request = state
//         .data_store
//         .get_reencrypt_request(request.job_id)
//         .await
//         .map_err(|e| {
//             tracing::error!(error = %e, "Failed to get reencrypt request");
//             AppError::Database(e.to_string())
//         })?;

//     if reencrypt_request.is_none() {
//         return Err(AppError::RequestNotFound(
//             "Reencrypt request not found".into(),
//         ));
//     }

//     let reencrypt_request = reencrypt_request.unwrap();

//     Ok(Json(GetReencryptRequestStatusResponse {
//         request: reencrypt_request,
//     }))
// }
