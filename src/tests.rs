mod decrypt;
mod encrypt;

use glob::glob;
use sqlx::SqlitePool;
use std::fs;
use tracing::debug;

/// Helper function to create a test database with all required tables
pub async fn setup_test_db() -> SqlitePool {
    let pool = SqlitePool::connect("sqlite::memory:")
        .await
        .expect("Failed to create test database");

    // Create apps table
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
    .await
    .expect("Failed to create apps table");

    // Create mpc_participants table
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
    .await
    .expect("Failed to create mpc_participants table");

    // Create decryption_requests table
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
    .await
    .expect("Failed to create decryption_requests table");

    pool
}

pub async fn cleanup_test_files() {
    println!("🧹 Cleaning up test files...");

    let key_patterns = [
        "peer_id_*",
        "p2p_store_*",
        "test_keystore_*",
        "shard_store_*",
        "./service/peer_id_*",
        "./service/p2p_store_*",
        "./service/test_keystore_*",
        "./service/shard_store_*",
    ];
    for pattern in &key_patterns {
        if let Ok(entries) = glob(pattern) {
            for entry in entries {
                if let Ok(path) = entry {
                    if path.is_dir() {
                        if let Err(e) = fs::remove_dir_all(&path) {
                            debug!("⚠️ Failed to remove dir {}: {}", path.display(), e);
                        } else {
                            debug!("🗑️ Removed dir: {}", path.display());
                        }
                    } else {
                        if let Err(e) = fs::remove_file(&path) {
                            debug!("⚠️ Failed to remove file {}: {}", path.display(), e);
                        } else {
                            debug!("🗑️ Removed file: {}", path.display());
                        }
                    }
                }
            }
        }
    }
    println!("✅ Test file cleanup complete.");
}
