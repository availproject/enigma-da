use super::p2p::{kill_process, run_node};
use crate::api::register::register;
use crate::config::ServiceConfig;
use crate::db::async_store::AsyncDataStore;
use crate::db::types::RequestStatus;
use crate::network::async_manager::AsyncNetworkManager;
use crate::traits::{DataStore, NetworkManager, WorkerManager};
use crate::types::RegisterAppRequest;
use crate::worker::async_manager::AsyncWorkerManager;

use crate::AppState;
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

    // Create configuration
    let config = ServiceConfig::default();

    // Initialize async components with trait objects
    let data_store: Arc<dyn DataStore + Send + Sync> = Arc::new(
        AsyncDataStore::from_path(TEST_KEYSTORE_DB_REGISTER_REQUEST)
            .expect("Failed to create async data store"),
    );
    let mut network_manager: Arc<dyn NetworkManager + Send + Sync> = Arc::new(
        AsyncNetworkManager::from_config(3001, "encryption-service-node".to_string())
            .await
            .expect("Failed to create async network manager"),
    );
    let mut worker_manager: Arc<dyn WorkerManager + Send + Sync> = Arc::new(
        AsyncWorkerManager::new(data_store.clone(), network_manager.clone(), &config)
            .expect("Failed to create async worker manager"),
    );

    let app_state = AppState {
        config: Arc::new(config),
        data_store: data_store.clone(),
        network_manager: network_manager.clone(),
        worker_manager: worker_manager.clone(),
    };

    let pid1 = run_node("node1", 9000).unwrap();
    let pid2 = run_node("node2", 9001).unwrap();
    let pid3 = run_node("node3", 9002).unwrap();
    let pid4 = run_node("node4", 9003).unwrap();
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

    let request = RegisterAppRequest { app_id: 56 };

    let response = register(State(app_state), Json(request.clone()))
        .await
        .unwrap();

    let response_body = response.into_response().into_body();
    let response: crate::types::RegisterResponse =
        serde_json::from_slice(&response_body.collect().await.unwrap().to_bytes()).unwrap();

    assert_eq!(response.app_id, request.app_id);
    assert!(!response.job_id.is_nil());

    // Verify that the job was actually created and stored in the database
    println!(
        "🔍 Checking if job {} was created in database...",
        response.job_id
    );

    let stored_job = data_store
        .get_register_app_request(response.job_id)
        .await
        .expect("Failed to retrieve job from database");

    assert!(stored_job.is_some(), "Job should exist in database");

    let job_data = stored_job.unwrap();
    println!("📋 Job data: {:?}", job_data);

    // Verify job details
    assert_eq!(job_data.app_id, request.app_id.to_string());
    assert_eq!(job_data.job_id, response.job_id);
    assert_eq!(job_data.status, RequestStatus::Pending);
    assert!(
        job_data.public_key.is_none(),
        "Public key should not be set initially"
    );

    // Wait for the job to be processed
    tokio::time::sleep(tokio::time::Duration::from_secs(20)).await;

    let stored_job = data_store
        .get_register_app_request(response.job_id)
        .await
        .expect("Failed to retrieve job from database");

    let job_data = stored_job.unwrap();
    assert_eq!(job_data.status, RequestStatus::Completed);

    println!("✅ Job verification completed successfully!");
    println!("   - Job ID: {}", job_data.job_id);
    println!("   - App ID: {}", job_data.app_id);
    println!("   - Status: {:?}", job_data.status);

    // Gracefully shutdown worker and network manager to avoid warnings
    if let Some(worker) = Arc::get_mut(&mut worker_manager) {
        let _ = worker.shutdown().await;
    }
    if let Some(network) = Arc::get_mut(&mut network_manager) {
        let _ = network.shutdown().await;
    }

    let _ = kill_process(pid1);
    let _ = kill_process(pid2);
    let _ = kill_process(pid3);
    let _ = kill_process(pid4);
}
