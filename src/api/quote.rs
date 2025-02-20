use axum::{
    response::IntoResponse,
    Json, 
};

pub async fn quote() -> impl IntoResponse {
    let span = tracing::info_span!("generate_quote");
    let _guard = span.enter();

    tracing::debug!("Generating random quote bytes");
    let random_bytes: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
    
    tracing::info!(
        quote_length = random_bytes.len(),
        "Successfully generated quote"
    );
    
    Json(random_bytes)
}