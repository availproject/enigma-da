use crate::types::QuoteResponse;
use axum::{response::IntoResponse, Json};
use dstack_sdk::dstack_client::DstackClient;

pub async fn quote() -> impl IntoResponse {
    let client = DstackClient::new(None);

    let quote_resp = client
        .get_quote(b"test-data".to_vec())
        .await
        .expect("Failed to get quote");
    println!("Quote: {}", quote_resp.quote);

    tracing::info!(
        quote_length = quote_resp.quote.len(),
        "Successfully generated quote"
    );

    Json(QuoteResponse { quote: quote_resp })
}
