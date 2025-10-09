use crate::AppState;
use crate::api::encrypt::encrypt;
use crate::config::ServiceConfig;
use crate::tests::cleanup_test_files;
use crate::types::{EncryptRequest, EncryptResponse, RegisterAppRequest};
use axum::{Json, extract::State, response::IntoResponse};
use http_body_util::BodyExt;
use std::sync::Arc;
use uuid::Uuid;

// Use a unique database path for this test to avoid conflicts
fn get_test_db_path() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("test_keystore_encrypt_request_db_{}", timestamp)
}

#[tokio::test]
async fn test_encrypt_request_endpoint() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    println!("Starting P2P nodes");

    // Wait a bit for registration to complete
    tokio::time::sleep(tokio::time::Duration::from_secs(20)).await;

    // Encrypt the plaintext
    let request = EncryptRequest {
        plaintext: vec![0; 32],
        turbo_da_app_id: Uuid::new_v4(),
    };

    let response = encrypt(Json(request.clone())).await.unwrap();

    let response_body = response.into_response().into_body();
    let response: EncryptResponse =
        serde_json::from_slice(&response_body.collect().await.unwrap().to_bytes()).unwrap();

    println!("Encrypt response: {:?}", response);

    assert!(!response.ciphertext.is_empty());
    assert!(response.signature_ciphertext_hash.r() != alloy_primitives::U256::ZERO);
    assert!(response.signature_plaintext_hash.r() != alloy_primitives::U256::ZERO);
    assert!(!response.address.is_empty());
    assert!(!response.ephemeral_pub_key.is_empty());

    cleanup_test_files().await;
}
