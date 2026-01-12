use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use std::io;
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    #[error("Decryption error: {0}")]
    DecryptionError(String),
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    #[error("Key generation error: {0}")]
    KeyGenerationError(String),
    #[error("Key not found for app_id: {0}")]
    KeyNotFound(Uuid),
    #[error("Decrypt request not found: {0}")]
    RequestNotFound(String),
    #[error("request not found: {0}")]
    Database(String),
    #[error("Quote retrieval failed: {0}")]
    QuoteGenerationFailed(String),
    #[error("Decryption failed invalid input: {0}")]
    InvalidInput(String),
    #[error("Unexpected error: {0}")]
    Other(String),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("Internal error: {0}")]
    Internal(String),
    #[error("Network error: {0}")]
    Network(String),
    #[error("Worker error: {0}")]
    Worker(String),
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AppError::EncryptionError(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AppError::DecryptionError(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AppError::InvalidKey(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            AppError::KeyGenerationError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string())
            }
            AppError::KeyNotFound(_) => (StatusCode::NOT_FOUND, self.to_string()),
            AppError::RequestNotFound(_) => (StatusCode::NOT_FOUND, self.to_string()),
            AppError::Database(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AppError::QuoteGenerationFailed(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string())
            }
            AppError::InvalidInput(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            AppError::Other(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AppError::Io(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AppError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AppError::Network(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AppError::Worker(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };

        (status, Json(ErrorResponse { error: message })).into_response()
    }
}
