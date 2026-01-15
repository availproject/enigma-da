use crate::{
    db,
    error::AppError,
    types::{
        DecryptRequest, DecryptRequestResponse, ListDecryptRequestsQuery,
        ListDecryptRequestsResponse, SubmitSignatureRequest, SubmitSignatureResponse,
    },
    utils,
};
use alloy_primitives::keccak256;
use axum::{
    extract::{Path, Query, State},
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
        tracing::debug!(
            app_id = %request.turbo_da_app_id,
            "Rejecting decrypt request: empty ciphertext provided"
        );
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
            tracing::debug!(
                app_id = %turbo_da_app_id_str,
                "App not found in database - registration required"
            );
            AppError::InvalidInput("App not registered. Please register the app first.".into())
        })?;

    let signers = db::get_participants(&pool, &turbo_da_app_id_str)
        .await
        .map_err(|e| {
            tracing::error!(
                error = %e,
                app_id = %turbo_da_app_id_str,
                "Database error while fetching participants"
            );
            AppError::Database(format!("Failed to get participants: {}", e))
        })?;

    if signers.is_empty() {
        tracing::debug!(
            app_id = %turbo_da_app_id_str,
            "No participants registered for app - cannot create decrypt request"
        );
        return Err(AppError::InvalidInput(
            "No registered participants found. Cannot create decryption request.".into(),
        ));
    }

    db::create_decryption_request(
        &pool,
        &request.id.to_string().as_str(),
        &turbo_da_app_id_str,
        &request.ciphertext,
    )
    .await
    .map_err(|e| {
        tracing::error!(
            error = %e,
            request_id = %request.id,
            app_id = %turbo_da_app_id_str,
            "Database error while creating decryption request"
        );
        AppError::Database(format!("Failed to create decryption request: {}", e))
    })?;

    tracing::info!(
        request_id = %request.id,
        app_id = %turbo_da_app_id_str,
        signer_count = signers.len(),
        threshold = threshold,
        "Decryption request created successfully"
    );

    Ok(Json(DecryptRequestResponse {
        id: request.id.to_string(),
        turbo_da_app_id: turbo_da_app_id_str,
        status: "pending".to_string(),
        signers,
        created_at: chrono::Utc::now().timestamp(),
    }))
}

pub async fn get_decrypt_request(
    State(pool): State<SqlitePool>,
    Path(request_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    tracing::info!(request_id = %request_id, "Fetching decryption request status");
    let record = db::get_decryption_request(&pool, &request_id.to_string())
        .await
        .map_err(|e| {
            tracing::error!(
                error = %e,
                request_id = %request_id,
                "Database error while fetching decryption request"
            );
            AppError::Database(format!("Failed to fetch decryption request: {}", e))
        })?
        .ok_or_else(|| {
            tracing::debug!(
                request_id = %request_id,
                "Decryption request not found in database"
            );
            AppError::RequestNotFound(request_id.to_string())
        })?;

    tracing::debug!(
        request_id = %request_id,
        status = %record.status,
        app_id = %record.turbo_da_app_id,
        "Decryption request retrieved successfully"
    );

    Ok(Json(record))
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

    let check = db::check_signature_submission(&pool, &request_id, &request.participant_address)
        .await
        .map_err(|e| {
            tracing::error!(
                error = %e,
                request_id = %request_id,
                participant = %request.participant_address,
                "Database error while checking signature submission eligibility"
            );
            AppError::Database(format!("Failed to check signature submission: {}", e))
        })?
        .ok_or_else(|| {
            tracing::debug!(
                request_id = %request_id,
                participant = %request.participant_address,
                "Cannot submit signature: decryption request not found"
            );
            AppError::RequestNotFound(request_id.clone())
        })?;

    if check.status != "pending" {
        tracing::debug!(
            request_id = %request_id,
            participant = %request.participant_address,
            current_status = %check.status,
            "Cannot submit signature: request not in pending state"
        );
        return Err(AppError::InvalidInput(format!(
            "Decryption request is in '{}' state, cannot accept signatures",
            check.status
        )));
    }

    if !check.is_participant_authorized {
        tracing::warn!(
            request_id = %request_id,
            participant = %request.participant_address,
            "Participant not authorized for this decryption request"
        );
        return Err(AppError::InvalidInput(
            "Participant not authorized for this decryption request".into(),
        ));
    }

    let message = format!("{}:{}", request_id, check.turbo_da_app_id);
    match utils::verify_ecdsa_signature(&message, &request.signature, &request.participant_address)
    {
        Ok(true) => {
            tracing::debug!(
                participant = request.participant_address,
                request_id = %request_id,
                "Signature verified successfully"
            );
        }
        Ok(false) => {
            tracing::warn!(
                participant = request.participant_address,
                request_id = %request_id,
                "Signature verification failed"
            );
            return Err(AppError::InvalidInput(
                "Invalid signature: verification failed".into(),
            ));
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                participant = request.participant_address,
                request_id = %request_id,
                "Error verifying signature"
            );
            return Err(AppError::InvalidInput(format!(
                "Invalid signature: {}",
                e
            )));
        }
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
        tracing::debug!(
            request_id = %request_id,
            participant = %request.participant_address,
            "Duplicate signature submission rejected"
        );
        return Err(AppError::InvalidInput(
            "Signature already submitted by this participant".into(),
        ));
    }

    let status = db::get_signature_status(&pool, &request_id)
        .await
        .map_err(|e| {
            tracing::error!(
                error = %e,
                request_id = %request_id,
                "Database error while fetching signature status"
            );
            AppError::Database(format!("Failed to fetch signature status: {}", e))
        })?
        .ok_or_else(|| {
            tracing::error!(
                request_id = %request_id,
                "Decryption request not found after signature submission"
            );
            AppError::RequestNotFound(request_id.clone())
        })?;

    let signatures_count = status.signatures_count as usize;
    let threshold = status.threshold;

    let ready_to_decrypt = signatures_count >= threshold as usize;

    tracing::info!(
        request_id = %request_id,
        signatures_count = signatures_count,
        verified_signatures_count = signatures_count,
        threshold = threshold,
        ready_to_decrypt = ready_to_decrypt,
        "Signature submitted successfully"
    );

    if ready_to_decrypt {
        tracing::info!(
            request_id = %request_id,
            "Threshold met, performing decryption"
        );

        let record = db::get_decryption_request(&pool, &request_id)
            .await
            .map_err(|e| {
                tracing::error!(
                    error = %e,
                    request_id = %request_id,
                    "Database error while fetching decryption request for decryption"
                );
                AppError::Database(format!("Failed to fetch decryption request: {}", e))
            })?
            .ok_or_else(|| {
                tracing::error!(
                    request_id = %request_id,
                    "Decryption request not found"
                );
                AppError::RequestNotFound(request_id.clone())
            })?;

        let turbo_da_app_id = Uuid::parse_str(&record.turbo_da_app_id).map_err(|e| {
            tracing::error!(
                error = %e,
                request_id = %request_id,
                app_id_str = %record.turbo_da_app_id,
                "Failed to parse turbo_da_app_id as UUID"
            );
            AppError::Internal(format!("Invalid UUID format: {}", e))
        })?;

        tracing::debug!(
            request_id = %request_id,
            app_id = %turbo_da_app_id,
            ciphertext_len = record.ciphertext.len(),
            "Starting decryption process"
        );

        let plaintext = utils::decrypt(turbo_da_app_id, &record.ciphertext)
            .await
            .map_err(|e| {
                tracing::error!(
                    error = %e,
                    request_id = %request_id,
                    app_id = %turbo_da_app_id,
                    ciphertext_len = record.ciphertext.len(),
                    "Decryption operation failed"
                );
                AppError::DecryptionError(format!("Decryption failed: {}", e))
            })?;


        db::complete_decryption_request(&pool, &request_id, &plaintext)
            .await
            .map_err(|e| {
                tracing::error!(
                    error = %e,
                    request_id = %request_id,
                    "Database error while completing decryption request"
                );
                AppError::Database(format!("Failed to complete decryption request: {}", e))
            })?;

        let quote_data = format!("{}:{}", request_id, hex::encode(&plaintext));
        let quote_data_hash = keccak256(quote_data.as_bytes());

        tracing::debug!(
            request_id = %request_id,
            quote_data_hash = %hex::encode(quote_data_hash),
            "Generating TEE attestation quote"
        );

        let tee_quote = utils::quote(quote_data_hash.to_vec()).await.map_err(|e| {
            tracing::error!(
                error = %e,
                request_id = %request_id,
                quote_data_hash = %hex::encode(quote_data_hash),
                "Failed to generate TEE attestation quote"
            );
            e
        })?;

        tracing::info!(
            request_id = %request_id,
            "Decryption completed successfully with TEE attestation"
        );

        Ok(Json(SubmitSignatureResponse {
            id: request_id,
            status: "completed".to_string(),
            signatures_submitted: signatures_count,
            threshold,
            ready_to_decrypt: true,
            tee_attestion: Some(tee_quote.quote), // Extract inner GetQuoteResponse
        }))
    } else {
        Ok(Json(SubmitSignatureResponse {
            id:request_id,
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

pub async fn list_decrypt_requests(
    State(pool): State<SqlitePool>,
    Query(query): Query<ListDecryptRequestsQuery>,
) -> Result<impl IntoResponse, AppError> {
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(50).min(100);

    tracing::info!(
        turbo_da_app_id = %query.turbo_da_app_id,
        offset = offset,
        limit = limit,
        "Listing decryption requests"
    );

    let (records, total) =
        db::list_decryption_requests(&pool, &query.turbo_da_app_id, offset, limit)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Database error while listing decryption requests");
                AppError::Database(format!("Failed to list decryption requests: {}", e))
            })?;
    tracing::debug!(
        total = total,
        returned = records.len(),
        "Decryption requests listed successfully"
    );

    Ok(Json(ListDecryptRequestsResponse {
        items: records,
        total,
        offset,
        limit,
    }))
}
