use crate::api::register::{register, run_node};

use crate::types::{EncryptRequest, EncryptResponse, NodeInfo, RegisterRequest};
use crate::{AppState, api::encrypt, key_store::KeyStore, network_manager::NetworkManager};
use axum::{Json, extract::State, response::IntoResponse};
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
    let _pid1 = run_node("node1", 9000).unwrap();
    let _pid2 = run_node("node2", 9001).unwrap();
    let _pid3 = run_node("node3", 9002).unwrap();
    let _pid4 = run_node("node4", 9003).unwrap();

    let register_request = RegisterRequest {
        app_id: 234,
        k: 3,
        n: 4,
        nodes: vec![
            NodeInfo {
                name: "node1".to_string(),
                address: "127.0.0.1:9000".to_string(),
            },
            NodeInfo {
                name: "node2".to_string(),
                address: "127.0.0.1:9001".to_string(),
            },
            NodeInfo {
                name: "node3".to_string(),
                address: "127.0.0.1:9002".to_string(),
            },
            NodeInfo {
                name: "node4".to_string(),
                address: "127.0.0.1:9003".to_string(),
            },
        ],
    };

    let _register_response = register(State(app_state.clone()), Json(register_request.clone()))
        .await
        .unwrap();

    // Encrypt the plaintext
    let request = EncryptRequest {
        app_id: 234,
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
