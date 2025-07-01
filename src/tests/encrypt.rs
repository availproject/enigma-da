use crate::api::register;
use crate::types::{EncryptRequest, EncryptResponse, RegisterRequest};
use crate::{api::encrypt, key_store::KeyStore};
use axum::{extract::State, response::IntoResponse, Json};
use http_body_util::BodyExt;
use std::sync::Arc;

const TEST_KEYSTORE_DB_ENCRYPT_REQUEST: &str = "test_keystore_encrypt_request_db";

#[tokio::test]
async fn test_encrypt_request_endpoint() {
    let key_store = Arc::new(KeyStore::new(TEST_KEYSTORE_DB_ENCRYPT_REQUEST).unwrap());

    // Register the app
    let register_request = RegisterRequest {
        app_id: 234,
        k: 3,
        n: 4,
    };
    let _register_response = register(State(key_store.clone()), Json(register_request.clone()))
        .await
        .unwrap();

    // Encrypt the plaintext
    let request = EncryptRequest {
        app_id: 234,
        plaintext: vec![0; 32],
    };

    let response = encrypt(State(key_store), Json(request.clone()))
        .await
        .unwrap();

    let response_body = response.into_response().into_body();

    let response: EncryptResponse =
        serde_json::from_slice(&response_body.collect().await.unwrap().to_bytes()).unwrap();

    assert!(!response.ciphertext.is_empty());
    assert!(response.signature.v());
    assert!(!response.address.is_empty());
    assert!(!response.ephemeral_pub_key.is_empty());
}
