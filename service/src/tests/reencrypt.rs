use crate::AppState;
use crate::api::reencrypt::{encrypt_private_key, reencrypt};
use crate::db::store::DataStore;
use crate::handler::worker::JobWorker;
use crate::network_manager::NetworkManager;
use crate::types::{PrivateKeyRequest, PrivateKeyResponse};
use axum::{Json, extract::State, response::IntoResponse};
use ecies::utils::generate_keypair;
use http_body_util::BodyExt;
use rstest::rstest;
use std::sync::Arc;
use tokio::sync::Mutex;

const TEST_KEYSTORE_DB_REQUEST_PRIVATE_KEY: &str = "test_keystore_reencrypt_db";

#[rstest]
fn test_encrypt_private_key() {
    let (private_key, public_key) = generate_keypair();
    // Dummy private key to test encryption and decryption
    let temp_private_key = vec![0; 32];
    let (ephemeral_pub_key, ciphertext) =
        encrypt_private_key(&temp_private_key, &public_key.serialize()).unwrap();

    let mut full_ciphertext = ephemeral_pub_key.clone();
    full_ciphertext.extend_from_slice(&ciphertext);

    let decrypted_private_key = ecies::decrypt(&private_key.serialize(), &full_ciphertext).unwrap();
    assert_eq!(decrypted_private_key, temp_private_key);
}

#[tokio::test]
async fn test_private_key_request_endpoint() {
    let data_store = Arc::new(DataStore::new(TEST_KEYSTORE_DB_REQUEST_PRIVATE_KEY).unwrap());
    let network_manager = NetworkManager::new(3001, "encryption-service-node".to_string())
        .await
        .unwrap();
    let network_manager_clone = network_manager.clone();
    let worker_manager = Arc::new(Mutex::new(JobWorker::new(
        data_store.clone(),
        network_manager.clone(),
    )));

    let app_state = AppState {
        data_store: data_store.clone(),
        network_manager,
        worker_manager,
    };

    let (private_key, public_key) = generate_keypair();
    let app_id = 123;

    data_store
        .clone()
        .store_public_key(app_id, &public_key.serialize())
        .unwrap();

    let (client_private_key, client_public_key) = generate_keypair();

    let request = PrivateKeyRequest {
        app_id,
        public_key: client_public_key.serialize().to_vec(),
    };

    let response = reencrypt(State(app_state), Json(request)).await.unwrap();

    // Extract the response data
    let response_body = response.into_response().into_body();
    let response: PrivateKeyResponse =
        serde_json::from_slice(&response_body.collect().await.unwrap().to_bytes()).unwrap();

    // Verify response structure
    assert!(!response.ephemeral_pub_key.is_empty());
    assert!(!response.ciphertext.is_empty());

    // Verify we can decrypt the response
    let mut full_ciphertext = response.ephemeral_pub_key.clone();
    full_ciphertext.extend_from_slice(&response.ciphertext);

    let decrypted_private_key =
        ecies::decrypt(&client_private_key.serialize(), &full_ciphertext).unwrap();

    // Verify the decrypted private key matches the original
    assert_eq!(decrypted_private_key, private_key.serialize());

    network_manager_clone.lock().await.shutdown().await.unwrap();
}
