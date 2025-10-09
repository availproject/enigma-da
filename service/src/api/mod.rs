pub mod decrypt;
pub mod encrypt;
pub mod quote;
pub mod reencrypt;

use crate::AppState;
use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;

pub use decrypt::decrypt;
pub use encrypt::encrypt;
pub use quote::quote;

use serde_json::json;

pub async fn health(State(_state): State<AppState>) -> impl IntoResponse {
    Json(json!({ "status": "healthy" }))
}
