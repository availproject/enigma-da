// use crate::AppState;
// use crate::api::reencrypt::{encrypt_private_key, reencrypt};
// use crate::config::ServiceConfig;
// use crate::db::async_store::AsyncDataStore;
// use crate::network::async_manager::AsyncNetworkManager;
// use crate::traits::{DataStore, NetworkManager, WorkerManager};
// use crate::types::{PrivateKeyRequest, PrivateKeyResponse};
// use crate::worker::async_manager::AsyncWorkerManager;
// use axum::{Json, extract::State, response::IntoResponse};
// use ecies::utils::generate_keypair;
// use http_body_util::BodyExt;
// use rstest::rstest;
// use std::sync::Arc;

// const TEST_KEYSTORE_DB_REQUEST_PRIVATE_KEY: &str = "test_keystore_reencrypt_db";

// #[rstest]
// fn test_encrypt_private_key() {
//     let (private_key, public_key) = generate_keypair();
//     // Dummy private key to test encryption and decryption
//     let temp_private_key = vec![0; 32];
//     let (ephemeral_pub_key, ciphertext) =
//         encrypt_private_key(&temp_private_key, &public_key.serialize()).unwrap();

//     let mut full_ciphertext = ephemeral_pub_key.clone();
//     full_ciphertext.extend_from_slice(&ciphertext);

//     let decrypted_private_key = ecies::decrypt(&private_key.serialize(), &full_ciphertext).unwrap();
//     assert_eq!(decrypted_private_key, temp_private_key);
// }

// #[tokio::test]
// async fn test_private_key_request_endpoint() {
//     let config = ServiceConfig::default();
//     let data_store: Arc<dyn DataStore + Send + Sync> =
//         Arc::new(AsyncDataStore::from_path(TEST_KEYSTORE_DB_REQUEST_PRIVATE_KEY).unwrap());
//     let network_manager: Arc<dyn NetworkManager + Send + Sync> = Arc::new(
//         AsyncNetworkManager::from_config(3001, "encryption-service-node".to_string())
//             .await
//             .unwrap(),
//     );
//     let worker_manager: Arc<dyn WorkerManager + Send + Sync> = Arc::new(
//         AsyncWorkerManager::new(data_store.clone(), network_manager.clone(), &config).unwrap(),
//     );

//     let app_state = AppState {
//         config: Arc::new(config),
//         data_store: data_store.clone(),
//         network_manager: network_manager.clone(),
//         worker_manager: worker_manager.clone(),
//     };

//     let (private_key, public_key) = generate_keypair();
//     let app_id = 123;

//     data_store
//         .clone()
//         .store_public_key(app_id, &public_key.serialize())
//         .await
//         .unwrap();

//     let (client_private_key, client_public_key) = generate_keypair();

//     let request = PrivateKeyRequest {
//         app_id,
//         public_key: client_public_key.serialize().to_vec(),
//     };

//     let response = reencrypt(State(app_state), Json(request)).await.unwrap();

//     // Extract the response data
//     let response_body = response.into_response().into_body();
//     let response: PrivateKeyResponse =
//         serde_json::from_slice(&response_body.collect().await.unwrap().to_bytes()).unwrap();

//     // Verify response structure
//     assert!(!response.ephemeral_pub_key.is_empty());
//     assert!(!response.ciphertext.is_empty());

//     // Verify we can decrypt the response
//     let mut full_ciphertext = response.ephemeral_pub_key.clone();
//     full_ciphertext.extend_from_slice(&response.ciphertext);

//     let decrypted_private_key =
//         ecies::decrypt(&client_private_key.serialize(), &full_ciphertext).unwrap();

//     // Verify the decrypted private key matches the original
//     assert_eq!(decrypted_private_key, private_key.serialize());

//     // Note: Network manager cleanup is handled automatically when the Arc is dropped
// }
