use crate::error::AppError;

use crate::types::QuoteResponse;
use axum::{Json, response::IntoResponse};
use dstack_sdk::tappd_client::TappdClient;

pub async fn quote() -> Result<impl IntoResponse, AppError> {
    let client = TappdClient::new(None);

    let quote_resp = client.get_quote(b"test-data".to_vec()).await.map_err(|e| {
        tracing::error!(error = ?e, "Failed to generate quote");
        AppError::QuoteGenerationFailed(e.to_string())
    })?;

    tracing::info!(
        quote_length = quote_resp.quote.len(),
        "Successfully generated quote"
    );

    Ok(Json(QuoteResponse { quote: quote_resp }))
}
