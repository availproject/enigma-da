pub mod decrypt;
pub mod encrypt;
pub mod participant;

use axum::response::IntoResponse;
use axum::Json;
pub use decrypt::{create_decrypt_request, get_decrypt_request, list_decrypt_requests, submit_signature};
pub use encrypt::encrypt;
pub use participant::{add_participant, delete_participant, register};
use serde_json::json;

pub async fn health() -> impl IntoResponse {
    Json(json!({ "status": "healthy" }))
}
