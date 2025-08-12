use super::p2p::{kill_process, run_node};
use crate::api::encrypt::encrypt;
use crate::api::register::register;
use crate::config::ServiceConfig;
use crate::db::async_store::AsyncDataStore;
use crate::network::async_manager::AsyncNetworkManager;
use crate::tests::cleanup_test_files;
use crate::traits::{DataStore, NetworkManager, WorkerManager};
use crate::types::{EncryptRequest, EncryptResponse, RegisterAppRequest};
use crate::worker::async_manager::AsyncWorkerManager;

use crate::AppState;
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

    // Create configuration
    let config = ServiceConfig::default();

    // Initialize async components with trait objects
    let test_db_path = get_test_db_path();
    let data_store: Arc<dyn DataStore + Send + Sync> = Arc::new(
        AsyncDataStore::from_path(&test_db_path, config.clone())
            .expect("Failed to create async data store"),
    );
    let mut network_manager: Arc<dyn NetworkManager + Send + Sync> = Arc::new(
        AsyncNetworkManager::from_config(
            3001,
            "encryption-service-node".to_string(),
            config.clone(),
        )
        .await
        .expect("Failed to create async network manager"),
    );
    let mut worker_manager: Arc<dyn WorkerManager + Send + Sync> = Arc::new(
        AsyncWorkerManager::new(data_store.clone(), network_manager.clone(), &config.clone())
            .expect("Failed to create async worker manager"),
    );

    let app_state = AppState {
        config: Arc::new(config),
        data_store: data_store.clone(),
        network_manager: network_manager.clone(),
        worker_manager: worker_manager.clone(),
    };
    println!("Starting P2P nodes");
    // Start P2P nodes
    let pid1 = run_node("node1", 9000).unwrap();
    let pid2 = run_node("node2", 9001).unwrap();
    let pid3 = run_node("node3", 9002).unwrap();
    let pid4 = run_node("node4", 9003).unwrap();

    println!("Registering app");

    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

    // Register the app first
    let register_request = RegisterAppRequest { app_id: 234 };

    let register_response = register(State(app_state.clone()), Json(register_request.clone()))
        .await
        .unwrap();

    let register_response_body = register_response.into_response().into_body();
    let register_response: crate::types::RegisterResponse =
        serde_json::from_slice(&register_response_body.collect().await.unwrap().to_bytes())
            .unwrap();

    println!("Register response: {:?}", register_response);

    // Wait a bit for registration to complete
    tokio::time::sleep(tokio::time::Duration::from_secs(20)).await;

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

    println!("Encrypt response: {:?}", response);

    assert!(!response.ciphertext.is_empty());
    assert!(response.signature_ciphertext_hash.r() != alloy_primitives::U256::ZERO);
    assert!(response.signature_plaintext_hash.r() != alloy_primitives::U256::ZERO);
    assert!(!response.address.is_empty());
    assert!(!response.ephemeral_pub_key.is_empty());

    // Gracefully shutdown worker and network manager to avoid warnings
    if let Some(worker) = Arc::get_mut(&mut worker_manager) {
        let _ = worker.shutdown().await;
    }
    if let Some(network) = Arc::get_mut(&mut network_manager) {
        let _ = network.shutdown().await;
    }

    // Clean up P2P processes
    let _ = kill_process(pid1);
    let _ = kill_process(pid2);
    let _ = kill_process(pid3);
    let _ = kill_process(pid4);

    cleanup_test_files().await;
}
