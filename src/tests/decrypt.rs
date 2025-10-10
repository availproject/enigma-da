use crate::api::{decrypt, encrypt};
use crate::tests::cleanup_test_files;
use crate::types::{DecryptRequest, DecryptRequestData, EncryptRequest, EncryptResponse};
use axum::Json;
use axum::response::IntoResponse;
use http_body_util::BodyExt;
use uuid::Uuid;

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

    let turbo_da_app_id = Uuid::new_v4();
    // Encrypt the plaintext
    let encrypt_request = EncryptRequest {
        plaintext: vec![0; 32],
        turbo_da_app_id: turbo_da_app_id,
    };
    let encrypt_response = encrypt(Json(encrypt_request.clone())).await.unwrap();
    let encrypt_response_body = encrypt_response.into_response().into_body();
    let encrypt_response: EncryptResponse =
        serde_json::from_slice(&encrypt_response_body.collect().await.unwrap().to_bytes()).unwrap();

    // Decrypt the ciphertext - convert single values to arrays as expected by DecryptRequest
    let request = DecryptRequest {
        ciphertext: encrypt_response.ciphertext,
        ephemeral_pub_key: encrypt_response.ephemeral_pub_key,
        turbo_da_app_id: turbo_da_app_id,
    };

    let response = decrypt(Json(request.clone())).await.unwrap();

    let response_body = response.into_response().into_body();
    let response: DecryptRequestData =
        serde_json::from_slice(&response_body.collect().await.unwrap().to_bytes()).unwrap();

    tokio::time::sleep(tokio::time::Duration::from_secs(20)).await;

    assert_eq!(
        response.decrypted_array.is_some(),
        true,
        "Decrypted array should be some"
    );

    cleanup_test_files().await;
}
