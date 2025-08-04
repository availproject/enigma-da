mod decrypt;
mod encrypt;
mod p2p;
mod p2p_store;
mod reencrypt;
mod register;

use glob::glob;
use std::fs;
use tracing::debug;

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
