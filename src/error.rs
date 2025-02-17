use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Key not found for app_id: {0}")]
    KeyNotFound(u32),
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    #[error("Key generation error: {0}")]
    KeyGenerationError(String),
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AppError::KeyNotFound(_) => (StatusCode::NOT_FOUND, self.to_string()),
            AppError::InvalidKey(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            AppError::EncryptionError(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AppError::KeyGenerationError(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };

        (status, Json(ErrorResponse { error: message })).into_response()
    }
}