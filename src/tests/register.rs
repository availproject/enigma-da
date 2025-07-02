use crate::api::register;
use crate::types::RegisterRequest;
use crate::{key_store::KeyStore, types::RegisterResponse};
use axum::{extract::State, response::IntoResponse, Json};
use http_body_util::BodyExt;
use std::sync::Arc;

const TEST_KEYSTORE_DB_REGISTER_REQUEST: &str = "test_keystore_register_request_db";

#[tokio::test]
async fn test_register_request_endpoint() {

    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();

    let key_store = Arc::new(KeyStore::new(TEST_KEYSTORE_DB_REGISTER_REQUEST).unwrap());

    let request = RegisterRequest {
        app_id: 233,
        k: 3,
        n: 4,
    };


    let response = register(State(key_store), Json(request.clone()))
        .await
        .unwrap();

    let response_body = response.into_response().into_body();
    let response: RegisterResponse =
        serde_json::from_slice(&response_body.collect().await.unwrap().to_bytes()).unwrap();

    assert_eq!(response.app_id, request.app_id);
    assert!(!response.public_key.is_empty());
}
