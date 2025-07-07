use crate::api::{encrypt, register};
use crate::types::{
    DecryptRequest, DecryptResponse, EncryptRequest, EncryptResponse, RegisterRequest,
    RegisterResponse,
};
use crate::{api::decrypt, key_store::KeyStore, network_manager::NetworkManager, AppState};
use axum::response::IntoResponse;
use axum::{extract::State, Json};
use http_body_util::BodyExt;
use std::sync::Arc;

const TEST_KEYSTORE_DB_DECRYPT_REQUEST: &str = "test_keystore_decrypt_request_db";

#[tokio::test]
async fn test_decrypt_request_endpoint() {
    let key_store = Arc::new(KeyStore::new(TEST_KEYSTORE_DB_DECRYPT_REQUEST).unwrap());

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
    let register_response = register(State(app_state.clone()), Json(register_request.clone()))
        .await
        .unwrap();
    let register_response_body = register_response.into_response().into_body();
    let _register_response: RegisterResponse =
        serde_json::from_slice(&register_response_body.collect().await.unwrap().to_bytes())
            .unwrap();

    // Encrypt the plaintext
    let encrypt_request = EncryptRequest {
        app_id: 123,
        plaintext: vec![0; 32],
    };
    let encrypt_response = encrypt(State(app_state.clone()), Json(encrypt_request.clone()))
        .await
        .unwrap();
    let encrypt_response_body = encrypt_response.into_response().into_body();
    let encrypt_response: EncryptResponse =
        serde_json::from_slice(&encrypt_response_body.collect().await.unwrap().to_bytes()).unwrap();

    // Decrypt the ciphertext
    let request = DecryptRequest {
        app_id: 123,
        ciphertext: encrypt_response.ciphertext,
        ephemeral_pub_key: encrypt_response.ephemeral_pub_key,
    };

    let response = decrypt(State(app_state), Json(request.clone()))
        .await
        .unwrap();

    let response_body = response.into_response().into_body();
    let response: DecryptResponse =
        serde_json::from_slice(&response_body.collect().await.unwrap().to_bytes()).unwrap();

    assert_eq!(response.plaintext, encrypt_request.plaintext);

    network_manager_clone.lock().await.shutdown().await.unwrap();
}
