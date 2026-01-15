use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use std::path::Path;
use std::time::Duration;

pub async fn init_db() -> Result<SqlitePool, sqlx::Error> {
    let data_dir = Path::new("/app/data");
    if !data_dir.exists() {
        std::fs::create_dir_all(data_dir).map_err(|e| {
            sqlx::Error::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to create data directory: {}", e),
            ))
        })?;
    }

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite:///app/data/enigma.db?mode=rwc".to_string());

    tracing::info!("Connecting to SQLite database at {}", database_url);

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(3))
        .connect(&database_url)
        .await?;

    tracing::info!("SQLite connection pool created successfully");

    // Check if migration is needed for apps table
    let apps_table_exists: bool = sqlx::query_scalar(
        "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='apps'",
    )
    .fetch_one(&pool)
    .await?;

    if !apps_table_exists {
        tracing::info!("Running apps table migration...");

        sqlx::query(
            r#"
            CREATE TABLE apps (
                turbo_da_app_id TEXT PRIMARY KEY NOT NULL,
                threshold INTEGER NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
            )
            "#,
        )
        .execute(&pool)
        .await?;

        tracing::info!("apps table migration completed successfully");
    } else {
        tracing::info!("apps table already exists, skipping migration");
    }

    // Check if migration is needed for mpc_participants table
    let participants_table_exists: bool = sqlx::query_scalar(
        "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='mpc_participants'",
    )
    .fetch_one(&pool)
    .await?;

    if !participants_table_exists {
        tracing::info!("Running mpc_participants table migration...");

        sqlx::query(
            r#"
            CREATE TABLE mpc_participants (
                turbo_da_app_id TEXT NOT NULL,
                address TEXT NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                PRIMARY KEY (turbo_da_app_id, address),
                FOREIGN KEY (turbo_da_app_id) REFERENCES apps(turbo_da_app_id)
            )
            "#,
        )
        .execute(&pool)
        .await?;

        sqlx::query(
            r#"
            CREATE INDEX idx_turbo_da_app_id 
            ON mpc_participants(turbo_da_app_id)
            "#,
        )
        .execute(&pool)
        .await?;

        tracing::info!("mpc_participants table migration completed successfully");
    } else {
        tracing::info!("mpc_participants table already exists, skipping migration");
    }

    // Check if migration is needed for decryption_requests table
    let decryption_requests_table_exists: bool = sqlx::query_scalar(
        "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='decryption_requests'",
    )
    .fetch_one(&pool)
    .await?;

    if !decryption_requests_table_exists {
        tracing::info!("Running decryption_requests table migration...");

        sqlx::query(
            r#"
            CREATE TABLE decryption_requests (
                id TEXT PRIMARY KEY NOT NULL,
                turbo_da_app_id TEXT NOT NULL,
                ciphertext BLOB NOT NULL,
                submitted_signatures TEXT NOT NULL DEFAULT '[]',
                decrypted_data BLOB,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                completed_at INTEGER,
                FOREIGN KEY (turbo_da_app_id) REFERENCES apps(turbo_da_app_id)
            )
            "#,
        )
        .execute(&pool)
        .await?;

        sqlx::query(
            r#"
            CREATE INDEX idx_decryption_turbo_da_app_id 
            ON decryption_requests(turbo_da_app_id)
            "#,
        )
        .execute(&pool)
        .await?;

        sqlx::query(
            r#"
            CREATE INDEX idx_decryption_status 
            ON decryption_requests(status)
            "#,
        )
        .execute(&pool)
        .await?;

        tracing::info!("decryption_requests table migration completed successfully");
    } else {
        tracing::info!("decryption_requests table already exists, skipping migration");
    }

    Ok(pool)
}

pub async fn register_app(
    pool: &SqlitePool,
    turbo_da_app_id: &str,
    threshold: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT OR REPLACE INTO apps (turbo_da_app_id, threshold) VALUES (?, ?)")
        .bind(turbo_da_app_id)
        .bind(threshold)
        .execute(pool)
        .await?;

    Ok(())
}

pub async fn get_app_threshold(
    pool: &SqlitePool,
    turbo_da_app_id: &str,
) -> Result<Option<i64>, sqlx::Error> {
    let threshold =
        sqlx::query_scalar::<_, i64>("SELECT threshold FROM apps WHERE turbo_da_app_id = ?")
            .bind(turbo_da_app_id)
            .fetch_optional(pool)
            .await?;

    Ok(threshold)
}

pub async fn get_participants(
    pool: &SqlitePool,
    turbo_da_app_id: &str,
) -> Result<Vec<String>, sqlx::Error> {
    let addresses = sqlx::query_scalar::<_, String>(
        "SELECT address FROM mpc_participants WHERE turbo_da_app_id = ? ORDER BY created_at",
    )
    .bind(turbo_da_app_id)
    .fetch_all(pool)
    .await?;

    Ok(addresses)
}

pub async fn add_participant(
    pool: &SqlitePool,
    turbo_da_app_id: &str,
    address: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO mpc_participants (turbo_da_app_id, address) VALUES (?, ?)")
        .bind(turbo_da_app_id)
        .bind(address)
        .execute(pool)
        .await?;

    Ok(())
}

pub async fn remove_participant(
    pool: &SqlitePool,
    turbo_da_app_id: &str,
    address: &str,
) -> Result<bool, sqlx::Error> {
    let result =
        sqlx::query("DELETE FROM mpc_participants WHERE turbo_da_app_id = ? AND address = ?")
            .bind(turbo_da_app_id)
            .bind(address)
            .execute(pool)
            .await?;

    Ok(result.rows_affected() > 0)
}

pub async fn remove_all_participants(
    pool: &SqlitePool,
    turbo_da_app_id: &str,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("DELETE FROM mpc_participants WHERE turbo_da_app_id = ?")
        .bind(turbo_da_app_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected())
}

pub async fn has_participants(
    pool: &SqlitePool,
    turbo_da_app_id: &str,
) -> Result<bool, sqlx::Error> {
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM mpc_participants WHERE turbo_da_app_id = ?")
            .bind(turbo_da_app_id)
            .fetch_one(pool)
            .await?;

    Ok(count > 0)
}

pub async fn create_decryption_request(
    pool: &SqlitePool,
    id: &str,
    turbo_da_app_id: &str,
    ciphertext: &[u8],
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO decryption_requests 
        (id, turbo_da_app_id, ciphertext, status) 
        VALUES (?, ?, ?, 'pending')
        "#,
    )
    .bind(id)
    .bind(turbo_da_app_id)
    .bind(ciphertext)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn get_decryption_request(
    pool: &SqlitePool,
    id: &str,
) -> Result<Option<DecryptionRequestRecord>, sqlx::Error> {
    let record = sqlx::query_as::<_, DecryptionRequestRecord>(
        r#"
        SELECT id, turbo_da_app_id, ciphertext, 
               submitted_signatures, decrypted_data, status, created_at, completed_at
        FROM decryption_requests
        WHERE id = ?
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(record)
}

pub async fn submit_signature(
    pool: &SqlitePool,
    id: &str,
    participant_address: &str,
    signature: &str,
) -> Result<bool, sqlx::Error> {
    // Get current submitted signatures
    let record = get_decryption_request(pool, id)
        .await?
        .ok_or_else(|| sqlx::Error::RowNotFound)?;

    let mut signatures: Vec<serde_json::Value> = serde_json::from_str(&record.submitted_signatures)
        .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

    // Check if participant already submitted
    if signatures
        .iter()
        .any(|s| s["participant"] == participant_address)
    {
        return Ok(false); // Already submitted
    }

    // Add new signature
    signatures.push(serde_json::json!({
        "participant": participant_address,
        "signature": signature,
        "submitted_at": chrono::Utc::now().timestamp()
    }));

    let signatures_json =
        serde_json::to_string(&signatures).map_err(|e| sqlx::Error::Encode(Box::new(e)))?;

    let result =
        sqlx::query("UPDATE decryption_requests SET submitted_signatures = ? WHERE id = ?")
            .bind(signatures_json)
            .bind(id)
            .execute(pool)
            .await?;

    Ok(result.rows_affected() > 0)
}

pub async fn complete_decryption_request(
    pool: &SqlitePool,
    id: &str,
    decrypted_data: &[u8],
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        r#"
        UPDATE decryption_requests 
        SET status = 'completed', 
            decrypted_data = ?,
            completed_at = strftime('%s', 'now')
        WHERE id = ?
        "#,
    )
    .bind(decrypted_data)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct DecryptionRequestRecord {
    pub id: String,
    pub turbo_da_app_id: String,
    pub ciphertext: Vec<u8>,
    pub submitted_signatures: String,
    pub decrypted_data: Option<Vec<u8>>,
    pub status: String,
    pub created_at: i64,
    pub completed_at: Option<i64>,
}

#[derive(Debug, Clone, sqlx::FromRow, Deserialize, Serialize)]
pub struct DecryptionRequestListWithThreshold {
    pub id: String,
    pub turbo_da_app_id: String,
    pub submitted_signatures: String,
    pub status: String,
    pub created_at: i64,
    pub completed_at: Option<i64>,
    pub threshold: i64,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SignatureCheckResult {
    pub threshold: i64,
    pub signatures_count: i64,
}

pub async fn get_signature_status(
    pool: &SqlitePool,
    request_id: &str,
) -> Result<Option<SignatureCheckResult>, sqlx::Error> {
    let result = sqlx::query_as::<_, SignatureCheckResult>(
        r#"
        SELECT a.threshold,
               json_array_length(dr.submitted_signatures) as signatures_count
        FROM decryption_requests dr
        JOIN apps a ON dr.turbo_da_app_id = a.turbo_da_app_id
        WHERE dr.id = ?
        "#,
    )
    .bind(request_id)
    .fetch_optional(pool)
    .await?;

    Ok(result)
}

pub async fn list_decryption_requests(
    pool: &SqlitePool,
    turbo_da_app_id: &str,
    offset: u32,
    limit: u32,
) -> Result<(Vec<DecryptionRequestListWithThreshold>, u32), sqlx::Error> {
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM decryption_requests WHERE turbo_da_app_id = ?",
    )
    .bind(turbo_da_app_id)
    .fetch_one(pool)
    .await?;

    let records = sqlx::query_as::<_, DecryptionRequestListWithThreshold>(
        r#"
        SELECT dr.id, dr.turbo_da_app_id, 
               dr.submitted_signatures, dr.status,
               dr.created_at, dr.completed_at, a.threshold
        FROM decryption_requests dr
        JOIN apps a ON dr.turbo_da_app_id = a.turbo_da_app_id
        WHERE dr.turbo_da_app_id = ?
        ORDER BY dr.created_at DESC
        LIMIT ? OFFSET ?
        "#,
    )
    .bind(turbo_da_app_id)
    .bind(limit as i64)
    .bind(offset as i64)
    .fetch_all(pool)
    .await?;

    Ok((records, total as u32))
}
