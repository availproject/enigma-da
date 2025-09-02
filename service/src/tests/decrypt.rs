use crate::AppState;
use crate::api::decrypt;
use crate::api::{encrypt, register};
use crate::config::ServiceConfig;
use crate::db::async_store::AsyncDataStore;
use crate::db::types::RequestStatus;
use crate::network::async_manager::AsyncNetworkManager;
use crate::tests::cleanup_test_files;
use crate::tests::p2p::{kill_process, run_node};
use crate::traits::{DataStore, NetworkManager, WorkerManager};
use crate::types::{
    DecryptRequest, DecryptResponse, EncryptRequest, EncryptResponse, RegisterAppRequest,
    RegisterResponse,
};
use crate::worker::async_manager::AsyncWorkerManager;
use axum::response::IntoResponse;
use axum::{Json, extract::State};
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
    format!("test_keystore_decrypt_request_db_{}", timestamp)
}

#[tokio::test]
async fn test_decrypt_request_endpoint() {
    //@TODO this test will run when we give shares from the nodes to the decryption service
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
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

    // Start P2P nodes
    let pid1 = run_node("node1", 9001).unwrap();
    let pid2 = run_node("node2", 9002).unwrap();
    let pid3 = run_node("node3", 9003).unwrap();
    let pid4 = run_node("node4", 9004).unwrap();
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

    // Register the app
    let register_request = RegisterAppRequest {
        turbo_da_app_id: Uuid::new_v4(),
    };
    let register_response = register(State(app_state.clone()), Json(register_request.clone()))
        .await
        .unwrap();
    let register_response_body = register_response.into_response().into_body();
    let register_response: RegisterResponse =
        serde_json::from_slice(&register_response_body.collect().await.unwrap().to_bytes())
            .unwrap();
    // Wait for the job to be processed
    tokio::time::sleep(tokio::time::Duration::from_secs(20)).await;
    let stored_job = data_store
        .get_register_app_request(register_response.job_id)
        .await
        .expect("Failed to retrieve job from database");

    let job_data = stored_job.unwrap();
    assert_eq!(
        job_data.status,
        RequestStatus::Completed,
        "Job should be completed"
    );

    // Encrypt the plaintext
    let encrypt_request = EncryptRequest {
        plaintext: vec![0; 32],
        turbo_da_app_id: register_request.turbo_da_app_id,
    };
    let encrypt_response = encrypt(State(app_state.clone()), Json(encrypt_request.clone()))
        .await
        .unwrap();
    let encrypt_response_body = encrypt_response.into_response().into_body();
    let encrypt_response: EncryptResponse =
        serde_json::from_slice(&encrypt_response_body.collect().await.unwrap().to_bytes()).unwrap();

    // Decrypt the ciphertext - convert single values to arrays as expected by DecryptRequest
    let request = DecryptRequest {
        ciphertext: vec![encrypt_response.ciphertext],
        ephemeral_pub_key: vec![encrypt_response.ephemeral_pub_key],
        turbo_da_app_id: register_request.turbo_da_app_id,
    };

    let response = decrypt(State(app_state.clone()), Json(request.clone()))
        .await
        .unwrap();

    let response_body = response.into_response().into_body();
    let response: DecryptResponse =
        serde_json::from_slice(&response_body.collect().await.unwrap().to_bytes()).unwrap();

    // Wait for the job to be processed
    tokio::time::sleep(tokio::time::Duration::from_secs(20)).await;

    let stored_job = data_store
        .get_decrypt_request(response.job_id)
        .await
        .expect("Failed to retrieve job from database");
    let job_data = stored_job.unwrap();
    assert_eq!(
        job_data.status,
        RequestStatus::Completed,
        "Job should be completed"
    );

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
