use super::p2p::run_node;
use crate::api::register::register;
use crate::types::{NodeInfo, RegisterRequest};
use crate::{
    AppState, key_store::KeyStore, network_manager::NetworkManager, types::RegisterResponse,
};
use axum::{Json, extract::State, response::IntoResponse};
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
    let network_manager = NetworkManager::new(3001, "encryption-service-node".to_string())
        .await
        .unwrap();
    let network_manager_clone = network_manager.clone();
    let app_state = AppState {
        key_store,
        network_manager,
    };
    let _pid1 = run_node("node1", 9000).unwrap();
    let _pid2 = run_node("node2", 9001).unwrap();
    let _pid3 = run_node("node3", 9002).unwrap();
    let _pid4 = run_node("node4", 9003).unwrap();
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

    let request = RegisterRequest {
        app_id: 56,
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

    let response = register(State(app_state), Json(request.clone()))
        .await
        .unwrap();

    let response_body = response.into_response().into_body();
    let response: RegisterResponse =
        serde_json::from_slice(&response_body.collect().await.unwrap().to_bytes()).unwrap();

    assert_eq!(response.app_id, request.app_id);
    assert!(!response.public_key.is_empty());

    network_manager_clone.lock().await.shutdown().await.unwrap();
}
