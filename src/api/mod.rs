pub mod decrypt;
pub mod encrypt;
pub mod participant;

use axum::Json;
use axum::response::IntoResponse;
pub use decrypt::{create_decrypt_request, get_decrypt_request, submit_signature};
pub use encrypt::encrypt;
pub use participant::{add_participant, delete_participant, register};
use serde_json::json;

pub async fn health() -> impl IntoResponse {
    Json(json!({ "status": "healthy" }))
}
