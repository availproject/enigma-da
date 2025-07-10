use crate::api::register;
use crate::handler::worker::JobWorker;
use crate::types::RegisterRequest;
use crate::{
    AppState, db::store::DataStore, network_manager::NetworkManager, types::RegisterResponse,
};
use axum::{Json, extract::State, response::IntoResponse};
use http_body_util::BodyExt;
use std::sync::Arc;
use tokio::sync::Mutex;

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

    let data_store = Arc::new(DataStore::new(TEST_KEYSTORE_DB_REGISTER_REQUEST).unwrap());
    let network_manager = NetworkManager::new(3001, "encryption-service-node".to_string())
        .await
        .unwrap();
    let network_manager_clone = network_manager.clone();
    let worker_manager = Arc::new(Mutex::new(JobWorker::new(
        data_store.clone(),
        network_manager.clone(),
    )));
    let app_state = AppState {
        data_store,
        network_manager,
        worker_manager,
    };

    let request = RegisterRequest {
        app_id: 233,
        k: 3,
        n: 4,
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
