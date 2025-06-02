use crate::types::QuoteResponse;
use dstack_sdk::dstack_client::DstackClient;
use crate::error::AppError;
use axum::{
    response::IntoResponse,
    Json, 
};

pub async fn quote() -> Result<impl IntoResponse, AppError> {
    let client = DstackClient::new(None);

    let quote_resp = client
        .get_quote(b"test-data".to_vec())
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, "Failed to generate quote");
            AppError::QuoteGenerationFailed(e.to_string())
        })?;

    tracing::info!(
        quote_length = quote_resp.quote.len(),
        "Successfully generated quote"
    );

    Ok(Json(QuoteResponse {
        quote: quote_resp,
    }))
}