use crate::api::register;
use crate::types::{EncryptRequest, EncryptResponse, RegisterRequest};
use crate::{api::encrypt, key_store::KeyStore, network_manager::NetworkManager, AppState};
use axum::{extract::State, response::IntoResponse, Json};
use http_body_util::BodyExt;
use std::sync::Arc;
use uuid::Uuid;

const TEST_KEYSTORE_DB_ENCRYPT_REQUEST: &str = "test_keystore_encrypt_request_db";

#[tokio::test]
async fn test_encrypt_request_endpoint() {
    let key_store = Arc::new(KeyStore::new(TEST_KEYSTORE_DB_ENCRYPT_REQUEST).unwrap());

    let network_manager = NetworkManager::new(3001, "encryption-service-node".to_string())
        .await
        .unwrap();
    let network_manager_clone = network_manager.clone();
    let app_state = AppState {
        key_store,
        network_manager,
    };

    // Register the app
    let register_request = RegisterRequest { app_id: 123 };
    let _register_response = register(State(app_state.clone()), Json(register_request.clone()))
        .await
        .unwrap();

    // Encrypt the plaintext
    let request = EncryptRequest {
        app_id: 123,
        plaintext: vec![0; 32],
        turbo_da_app_id: Uuid::new_v4(),
    };

    let response = encrypt(State(app_state), Json(request.clone()))
        .await
        .unwrap();

    let response_body = response.into_response().into_body();
    let response: EncryptResponse =
        serde_json::from_slice(&response_body.collect().await.unwrap().to_bytes()).unwrap();

    println!("response: {:?}", response);

    assert!(!response.ciphertext.is_empty());
    assert!(response.signature.r() != alloy_primitives::U256::ZERO);
    assert!(!response.address.is_empty());
    assert!(!response.ephemeral_pub_key.is_empty());

    network_manager_clone.lock().await.shutdown().await.unwrap();
}
