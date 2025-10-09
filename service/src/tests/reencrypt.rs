// use super::p2p::{kill_process, run_node};
// use crate::AppState;
// use crate::api::reencrypt::reencrypt;
// use crate::api::register;
// use crate::config::ServiceConfig;
// use crate::db::async_store::AsyncDataStore;
// use crate::db::types::RequestStatus;
// use crate::network::async_manager::AsyncNetworkManager;
// use crate::tests::cleanup_test_files;
// use crate::traits::{DataStore, NetworkManager, WorkerManager};
// use crate::types::{PrivateKeyRequest, RegisterAppRequest};
// use crate::worker::async_manager::AsyncWorkerManager;
// use axum::{Json, extract::State, response::IntoResponse};
// use ecies::utils::generate_keypair;
// use http_body_util::BodyExt;
// use rstest::rstest;
// use std::sync::Arc;
// use uuid::Uuid;

// // Use a unique database path for this test to avoid conflicts
// fn get_test_db_path() -> String {
//     use std::time::{SystemTime, UNIX_EPOCH};
//     let timestamp = SystemTime::now()
//         .duration_since(UNIX_EPOCH)
//         .unwrap()
//         .as_nanos();
//     format!("test_keystore_reencrypt_request_db_{}", timestamp)
// }

// #[rstest]
// fn test_encrypt_private_key() {
//     let (private_key, public_key) = generate_keypair();
//     // Dummy private key to test encryption and decryption
//     let temp_private_key = vec![0; 32];
//     let (ephemeral_pub_key, ciphertext) =
//         crate::handler::worker::encrypt_private_key(&temp_private_key, &public_key.serialize())
//             .unwrap();

//     let mut full_ciphertext = ephemeral_pub_key.clone();
//     full_ciphertext.extend_from_slice(&ciphertext);

//     let decrypted_private_key = ecies::decrypt(&private_key.serialize(), &full_ciphertext).unwrap();
//     assert_eq!(decrypted_private_key, temp_private_key);
// }

// #[tokio::test]
// async fn test_reencrypt_request_endpoint() {
//     let _ = tracing_subscriber::fmt()
//         .with_env_filter("info")
//         .with_test_writer()
//         .try_init();
//     let _ = tracing_subscriber::fmt()
//         .with_env_filter("debug")
//         .with_test_writer()
//         .try_init();

//     // Create configuration
//     let config = ServiceConfig::default();

//     // Initialize async components with trait objects
//     let test_db_path = get_test_db_path();
//     let data_store: Arc<dyn DataStore + Send + Sync> = Arc::new(
//         AsyncDataStore::from_path(&test_db_path, config.clone())
//             .expect("Failed to create async data store"),
//     );
//     let mut network_manager: Arc<dyn NetworkManager + Send + Sync> = Arc::new(
//         AsyncNetworkManager::from_config(
//             3001,
//             "encryption-service-node".to_string(),
//             config.clone(),
//         )
//         .await
//         .expect("Failed to create async network manager"),
//     );
//     let mut worker_manager: Arc<dyn WorkerManager + Send + Sync> = Arc::new(
//         AsyncWorkerManager::new(data_store.clone(), network_manager.clone(), &config.clone())
//             .expect("Failed to create async worker manager"),
//     );

//     let app_state = AppState {
//         config: Arc::new(config),
//         data_store: data_store.clone(),
//         network_manager: network_manager.clone(),
//         worker_manager: worker_manager.clone(),
//     };

//     // Start P2P nodes
//     let pid1 = run_node("node_0", 9000).unwrap();
//     let pid2 = run_node("node_1", 9001).unwrap();
//     // let pid3 = run_node("node3", 9002).unwrap();
//     // let pid4 = run_node("node4", 9003).unwrap();
//     tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

//     let app_id = Uuid::new_v4();
//     let request = RegisterAppRequest {
//         turbo_da_app_id: app_id,
//     };

//     let response = register(State(app_state.clone()), Json(request.clone()))
//         .await
//         .unwrap();

//     let response_body = response.into_response().into_body();
//     let response: crate::types::RegisterResponse =
//         serde_json::from_slice(&response_body.collect().await.unwrap().to_bytes()).unwrap();

//     assert_eq!(response.turbo_da_app_id, request.turbo_da_app_id);
//     assert!(!response.job_id.is_nil());

//     // Verify that the job was actually created and stored in the database
//     println!(
//         "🔍 Checking if job {} was created in database...",
//         response.job_id
//     );

//     let stored_job = data_store
//         .get_register_app_request(response.job_id)
//         .await
//         .expect("Failed to retrieve job from database");

//     assert!(stored_job.is_some(), "Job should exist in database");

//     let job_data = stored_job.unwrap();
//     println!("📋 Job data: {:?}", job_data);

//     // Verify job details
//     assert_eq!(job_data.app_id, request.turbo_da_app_id.to_string());
//     assert_eq!(job_data.job_id, response.job_id);
//     assert_eq!(job_data.status, RequestStatus::Pending);
//     assert!(
//         job_data.public_key.is_none(),
//         "Public key should not be set initially"
//     );

//     // Wait for the job to be processed
//     tokio::time::sleep(tokio::time::Duration::from_secs(20)).await;

//     let stored_job = data_store
//         .get_register_app_request(response.job_id)
//         .await
//         .expect("Failed to retrieve job from database");

//     let job_data = stored_job.unwrap();
//     assert_eq!(job_data.status, RequestStatus::Completed);

//     println!("✅ Job verification completed successfully!");
//     println!("   - Job ID: {}", job_data.job_id);
//     println!("   - App ID: {}", job_data.app_id);
//     println!("   - Status: {:?}", job_data.status);

//     let keypair = generate_keypair();

//     let private_key_request = PrivateKeyRequest {
//         turbo_da_app_id: job_data.app_id.parse().unwrap(),
//         public_key: keypair.1.serialize().to_vec(),
//     };

//     let response = reencrypt(State(app_state.clone()), Json(private_key_request.clone()))
//         .await
//         .unwrap();

//     let response_body = response.into_response().into_body();
//     let response: crate::types::PrivateKeyResponse =
//         serde_json::from_slice(&response_body.collect().await.unwrap().to_bytes()).unwrap();
//     assert!(!response.job_id.is_nil());

//     // Verify that the job was actually created and stored in the database
//     println!(
//         "🔍 Checking if job {} was created in database...",
//         response.job_id
//     );

//     let stored_job = data_store
//         .get_reencrypt_request(response.job_id)
//         .await
//         .expect("Failed to retrieve job from database");

//     assert!(stored_job.is_some(), "Job should exist in database");

//     let job_data = stored_job.unwrap();
//     println!("📋 Job data: {:?}", job_data);

//     // Verify job details
//     assert_eq!(
//         job_data.app_id,
//         private_key_request.turbo_da_app_id.to_string()
//     );
//     assert_eq!(job_data.job_id, response.job_id);
//     assert_eq!(job_data.status, RequestStatus::Pending);
//     assert!(
//         job_data.ephemeral_pub_key.is_none(),
//         "Ephemeral public key should not be set initially"
//     );
//     assert!(
//         job_data.private_key_ciphertext.is_none(),
//         "Private key ciphertext should not be set initially"
//     );

//     // Wait for the job to be processed
//     tokio::time::sleep(tokio::time::Duration::from_secs(20)).await;

//     let stored_job = data_store
//         .get_reencrypt_request(response.job_id)
//         .await
//         .expect("Failed to retrieve job from database");

//     let job_data = stored_job.unwrap();
//     assert_eq!(job_data.status, RequestStatus::Completed);

//     println!("✅ Job verification completed successfully!");
//     println!("   - Job ID: {}", job_data.job_id);
//     println!("   - App ID: {}", job_data.app_id);
//     println!("   - Status: {:?}", job_data.status);

//     // decrypt the private key received from the job
//     let mut full_ciphertext = job_data.ephemeral_pub_key.unwrap();
//     full_ciphertext.extend_from_slice(&job_data.private_key_ciphertext.unwrap());
//     let decrypted_private_key = ecies::decrypt(&keypair.0.serialize(), &full_ciphertext).unwrap();
//     println!(
//         "🔍 Decrypted private key: {:?}",
//         decrypted_private_key.to_vec()
//     );

//     // Gracefully shutdown worker and network manager to avoid warnings
//     if let Some(worker) = Arc::get_mut(&mut worker_manager) {
//         let _ = worker.shutdown().await;
//     }
//     if let Some(network) = Arc::get_mut(&mut network_manager) {
//         let _ = network.shutdown().await;
//     }
//     cleanup_test_files().await;
//     let _ = kill_process(pid1);
//     let _ = kill_process(pid2);
//     // let _ = kill_process(pid3);
//     // let _ = kill_process(pid4);
// }
