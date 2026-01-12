use crate::{
    db,
    error::AppError,
    types::{
        AddParticipantRequest, AddParticipantResponse, DeleteParticipantRequest,
        DeleteParticipantResponse, RegisterRequest, RegisterResponse,
    },
};
use axum::{extract::State, response::IntoResponse, Json};
use sqlx::SqlitePool;

pub async fn register(
    State(pool): State<SqlitePool>,
    Json(request): Json<RegisterRequest>,
) -> Result<impl IntoResponse, AppError> {
    if request.turbo_da_app_id.is_empty() {
        tracing::warn!("Empty turbo_da_app_id provided");
        return Err(AppError::InvalidInput(
            "turbo_da_app_id cannot be empty".into(),
        ));
    }

    if request.participants.is_empty() {
        tracing::warn!(turbo_da_app_id = %request.turbo_da_app_id, "Empty participants list");
        return Err(AppError::InvalidInput(
            "participants list cannot be empty".into(),
        ));
    }

    if request.threshold <= 0 {
        tracing::warn!(turbo_da_app_id = %request.turbo_da_app_id, "Invalid threshold");
        return Err(AppError::InvalidInput(
            "threshold must be greater than 0".into(),
        ));
    }

    if request.threshold as usize > request.participants.len() {
        tracing::warn!(
            turbo_da_app_id = %request.turbo_da_app_id,
            threshold = request.threshold,
            participant_count = request.participants.len(),
            "Threshold exceeds participant count"
        );
        return Err(AppError::InvalidInput(
            "threshold cannot exceed participant count".into(),
        ));
    }

    let request_span = tracing::info_span!(
        "register_participants",
        turbo_da_app_id = %request.turbo_da_app_id,
        participant_count = request.participants.len(),
        threshold = request.threshold
    );

    let _guard = request_span.enter();

    tracing::debug!("Registering app and participants");

    db::register_app(&pool, &request.turbo_da_app_id, request.threshold)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to register app");
            AppError::Database(format!("Failed to register app: {}", e))
        })?;

    let mut added_count = 0;
    for address in &request.participants {
        if address.is_empty() {
            tracing::warn!("Skipping empty address");
            continue;
        }

        db::add_participant(&pool, &request.turbo_da_app_id, address)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, address = %address, "Failed to add participant");
                AppError::Database(format!("Failed to add participant: {}", e))
            })?;

        added_count += 1;
    }

    tracing::info!(
        turbo_da_app_id = %request.turbo_da_app_id,
        added = added_count,
        threshold = request.threshold,
        "Successfully registered app and participants"
    );

    Ok(Json(RegisterResponse {
        turbo_da_app_id: request.turbo_da_app_id,
        participants_added: added_count,
    }))
}

pub async fn add_participant(
    State(pool): State<SqlitePool>,
    Json(request): Json<AddParticipantRequest>,
) -> Result<impl IntoResponse, AppError> {
    if request.turbo_da_app_id.is_empty() {
        tracing::warn!("Empty turbo_da_app_id provided");
        return Err(AppError::InvalidInput(
            "turbo_da_app_id cannot be empty".into(),
        ));
    }

    if request.participants.is_empty() {
        tracing::warn!(turbo_da_app_id = %request.turbo_da_app_id, "Empty participants list");
        return Err(AppError::InvalidInput(
            "participants list cannot be empty".into(),
        ));
    }

    let request_span = tracing::info_span!(
        "add_participants",
        turbo_da_app_id = %request.turbo_da_app_id,
        participant_count = request.participants.len()
    );
    let _guard = request_span.enter();

    tracing::debug!("Adding participants to account");

    let mut added_count = 0;
    for address in &request.participants {
        if address.is_empty() {
            tracing::warn!("Skipping empty address");
            continue;
        }

        db::add_participant(&pool, &request.turbo_da_app_id, address)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, address = %address, "Failed to add participant");
                AppError::Database(format!("Failed to add participant: {}", e))
            })?;

        added_count += 1;
    }

    tracing::info!(
        turbo_da_app_id = %request.turbo_da_app_id,
        added = added_count,
        "Successfully added participants"
    );

    Ok(Json(AddParticipantResponse {
        turbo_da_app_id: request.turbo_da_app_id,
        participants_added: added_count,
    }))
}

pub async fn delete_participant(
    State(pool): State<SqlitePool>,
    Json(request): Json<DeleteParticipantRequest>,
) -> Result<impl IntoResponse, AppError> {
    if request.turbo_da_app_id.is_empty() {
        tracing::warn!("Empty turbo_da_app_id provided");
        return Err(AppError::InvalidInput(
            "turbo_da_app_id cannot be empty".into(),
        ));
    }

    if request.participants.is_empty() {
        tracing::warn!(turbo_da_app_id = %request.turbo_da_app_id, "Empty participants list");
        return Err(AppError::InvalidInput(
            "participants list cannot be empty".into(),
        ));
    }

    let request_span = tracing::info_span!(
        "delete_participants",
        turbo_da_app_id = %request.turbo_da_app_id,
        participant_count = request.participants.len()
    );
    let _guard = request_span.enter();

    tracing::debug!("Deleting participants from account");

    let mut deleted_count = 0;
    for address in &request.participants {
        if address.is_empty() {
            tracing::warn!("Skipping empty address");
            continue;
        }

        let removed = db::remove_participant(&pool, &request.turbo_da_app_id, address)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, address = %address, "Failed to delete participant");
                AppError::Database(format!("Failed to delete participant: {}", e))
            })?;

        if removed {
            deleted_count += 1;
        }
    }

    tracing::info!(
        turbo_da_app_id = %request.turbo_da_app_id,
        deleted = deleted_count,
        "Successfully deleted participants"
    );

    Ok(Json(DeleteParticipantResponse {
        turbo_da_app_id: request.turbo_da_app_id,
        participants_deleted: deleted_count,
    }))
}
