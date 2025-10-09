pub mod decrypt;
pub mod encrypt;
pub mod quote;

use axum::Json;
use axum::response::IntoResponse;

pub use decrypt::decrypt;
pub use encrypt::encrypt;
pub use quote::quote;

use serde_json::json;

pub async fn health() -> impl IntoResponse {
    Json(json!({ "status": "healthy" }))
}
