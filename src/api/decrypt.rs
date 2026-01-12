use crate::{
    db,
    error::AppError,
    types::{
        DecryptRequest, DecryptRequestResponse, SubmitSignatureRequest, SubmitSignatureResponse,
    },
    utils,
};
use alloy_primitives::keccak256;
use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Json,
};
use sqlx::SqlitePool;
use uuid::Uuid;

pub async fn create_decrypt_request(
    State(pool): State<SqlitePool>,
    Json(request): Json<DecryptRequest>,
) -> Result<impl IntoResponse, AppError> {
    let request_span = tracing::info_span!(
        "create_decrypt_request",
        ciphertext_length = request.ciphertext.len(),
        turbo_da_app_id = request.turbo_da_app_id.to_string()
    );
    let _guard = request_span.enter();

    if request.ciphertext.is_empty() {
        return Err(AppError::InvalidInput(
            "Ciphertext must not be empty".into(),
        ));
    }

    tracing::debug!(
        "Creating decryption request for app_id {}",
        request.turbo_da_app_id
    );

    let turbo_da_app_id_str = request.turbo_da_app_id.to_string();

    let threshold = db::get_app_threshold(&pool, &turbo_da_app_id_str)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get app threshold");
            AppError::Database(format!("Failed to get app threshold: {}", e))
        })?
        .ok_or_else(|| {
            AppError::InvalidInput("App not registered. Please register the app first.".into())
        })?;

    let signers = db::get_participants(&pool, &turbo_da_app_id_str)
        .await
        .map_err(|e| AppError::Database(format!("Failed to get participants: {}", e)))?;

    if signers.is_empty() {
        return Err(AppError::InvalidInput(
            "No registered participants found. Cannot create decryption request.".into(),
        ));
    }

    let request_id = Uuid::new_v4().to_string();

    db::create_decryption_request(
        &pool,
        &request_id,
        &turbo_da_app_id_str,
        &request.ciphertext,
    )
    .await
    .map_err(|e| AppError::Database(format!("Failed to create decryption request: {}", e)))?;

    tracing::info!(
        request_id = %request_id,
        app_id = %turbo_da_app_id_str,
        signer_count = signers.len(),
        threshold = threshold,
        "Decryption request created successfully"
    );

    Ok(Json(DecryptRequestResponse {
        request_id,
        turbo_da_app_id: turbo_da_app_id_str,
        status: "pending".to_string(),
        signers,
        created_at: chrono::Utc::now().timestamp(),
    }))
}

pub async fn get_decrypt_request(
    State(pool): State<SqlitePool>,
    Path(request_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    tracing::info!(request_id = %request_id, "Fetching decryption request status");

    let record = db::get_decryption_request(&pool, &request_id)
        .await
        .map_err(|e| AppError::Database(format!("Failed to fetch decryption request: {}", e)))?
        .ok_or_else(|| AppError::RequestNotFound(request_id.clone()))?;

    let signers = db::get_participants(&pool, &record.turbo_da_app_id)
        .await
        .map_err(|e| AppError::Database(format!("Failed to get participants: {}", e)))?;

    tracing::info!(
        request_id = %request_id,
        status = %record.status,
        "Decryption request retrieved successfully"
    );

    Ok(Json(DecryptRequestResponse {
        request_id: record.id,
        turbo_da_app_id: record.turbo_da_app_id,
        status: record.status,
        signers,
        created_at: record.created_at,
    }))
}

pub async fn submit_signature(
    State(pool): State<SqlitePool>,
    Path(request_id): Path<String>,
    Json(request): Json<SubmitSignatureRequest>,
) -> Result<impl IntoResponse, AppError> {
    tracing::info!(
        request_id = %request_id,
        participant = %request.participant_address,
        "Submitting signature for decryption request"
    );

    let record = db::get_decryption_request(&pool, &request_id)
        .await
        .map_err(|e| AppError::Database(format!("Failed to fetch decryption request: {}", e)))?
        .ok_or_else(|| AppError::RequestNotFound(request_id.clone()))?;

    if record.status != "pending" {
        return Err(AppError::InvalidInput(format!(
            "Decryption request is in '{}' state, cannot accept signatures",
            record.status
        )));
    }

    let signers = db::get_participants(&pool, &record.turbo_da_app_id)
        .await
        .map_err(|e| AppError::Database(format!("Failed to get participants: {}", e)))?;

    if !signers.contains(&request.participant_address) {
        tracing::warn!(
            request_id = %request_id,
            participant = %request.participant_address,
            "Participant not authorized for this decryption request"
        );
        return Err(AppError::InvalidInput(
            "Participant not authorized for this decryption request".into(),
        ));
    }

    let submitted = db::submit_signature(
        &pool,
        &request_id,
        &request.participant_address,
        &request.signature,
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to submit signature");
        AppError::Database(format!("Failed to submit signature: {}", e))
    })?;

    if !submitted {
        return Err(AppError::InvalidInput(
            "Signature already submitted by this participant".into(),
        ));
    }

    let updated_record = db::get_decryption_request(&pool, &request_id)
        .await
        .map_err(|e| {
            AppError::Database(format!("Failed to fetch updated decryption request: {}", e))
        })?
        .ok_or_else(|| AppError::RequestNotFound(request_id.clone()))?;

    let submitted_signatures: Vec<serde_json::Value> =
        serde_json::from_str(&updated_record.submitted_signatures).map_err(|e| {
            AppError::Internal(format!("Failed to parse submitted signatures: {}", e))
        })?;

    let signatures_count = submitted_signatures.len();

    let threshold = db::get_app_threshold(&pool, &updated_record.turbo_da_app_id)
        .await
        .map_err(|e| AppError::Database(format!("Failed to get app threshold: {}", e)))?
        .ok_or_else(|| AppError::Internal("App not found".into()))?;
    let mut verified_signatures_count = 0;
    for sig in &submitted_signatures {
        let participant = sig["participant"].as_str().ok_or_else(|| {
            AppError::Internal("Invalid signature format: missing participant".into())
        })?;
        let signature = sig["signature"].as_str().ok_or_else(|| {
            AppError::Internal("Invalid signature format: missing signature".into())
        })?;

        let ciphertext_hash = keccak256(&record.ciphertext);
        let message = format!("{:?}{}", ciphertext_hash, record.turbo_da_app_id);
        // Verify the signature against the request_id
        match utils::verify_ecdsa_signature(&message, signature, participant) {
            Ok(true) => {
                verified_signatures_count += 1;
                tracing::debug!(
                    participant = participant,
                    request_id = %request_id,
                    "Signature verified successfully"
                );
            }
            Ok(false) => {
                tracing::warn!(
                    participant = participant,
                    request_id = %request_id,
                    "Signature verification failed"
                );
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    participant = participant,
                    request_id = %request_id,
                    "Error verifying signature"
                );
            }
        }
    }

    let ready_to_decrypt = verified_signatures_count >= threshold as usize;

    tracing::info!(
        request_id = %request_id,
        signatures_count = signatures_count,
        verified_signatures_count = verified_signatures_count,
        threshold = threshold,
        ready_to_decrypt = ready_to_decrypt,
        "Signature submitted successfully"
    );


    if ready_to_decrypt {
        tracing::info!(
            request_id = %request_id,
            "Threshold met, performing decryption"
        );

        let turbo_da_app_id = Uuid::parse_str(&updated_record.turbo_da_app_id)
            .map_err(|e| AppError::Internal(format!("Invalid UUID format: {}", e)))?;

        let plaintext = utils::decrypt(turbo_da_app_id, &updated_record.ciphertext)
            .await
            .map_err(|e| AppError::DecryptionError(format!("Decryption failed: {}", e)))?;

        db::complete_decryption_request(&pool, &request_id, &plaintext)
            .await
            .map_err(|e| {
                AppError::Database(format!("Failed to complete decryption request: {}", e))
            })?;

        let quote_data = format!("{}:{}", request_id, hex::encode(&plaintext));
        let quote_data_hash = keccak256(quote_data.as_bytes());

        let tee_quote = utils::quote(quote_data_hash.to_vec()).await.map_err(|e| {
            tracing::error!(error = %e, "Failed to generate TEE quote");
            e
        })?;

        tracing::info!(
            request_id = %request_id,
            "Decryption completed successfully with TEE attestation"
        );

        Ok(Json(SubmitSignatureResponse {
            request_id,
            status: "completed".to_string(),
            signatures_submitted: signatures_count,
            threshold,
            ready_to_decrypt: true,
            tee_attestion: Some(tee_quote.quote), // Extract inner GetQuoteResponse
        }))
    } else {
        Ok(Json(SubmitSignatureResponse {
            request_id,
            status: if ready_to_decrypt {
                "completed".to_string()
            } else {
                "pending".to_string()
            },
            signatures_submitted: signatures_count,
            threshold,
            ready_to_decrypt,
            tee_attestion: None,
        }))
    }
}
