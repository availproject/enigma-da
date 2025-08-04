mod p2p;
mod sled;
mod tee;

use glob::glob;
use std::fs;

pub async fn cleanup_test_files() {
    println!("🧹 Cleaning up test files...");

    let key_patterns = ["node_key_*.bin", "node_key_*.pem", "peer_id_*.txt"];

    for pattern in &key_patterns {
        if let Ok(entries) = glob(pattern) {
            for entry in entries {
                if let Ok(path) = entry {
                    if let Err(e) = fs::remove_file(&path) {
                        println!("⚠️ Failed to remove file {}: {}", path.display(), e);
                    } else {
                        println!("🗑️ Removed file: {}", path.display());
                    }
                }
            }
        }
    }

    let db_patterns = ["shard_store_node_*_db"];
    for pattern in &db_patterns {
        if let Ok(entries) = glob(pattern) {
            for entry in entries {
                if let Ok(path) = entry {
                    if path.is_dir() {
                        if let Err(e) = fs::remove_dir_all(&path) {
                            println!("⚠️ Failed to remove dir {}: {}", path.display(), e);
                        } else {
                            println!("🗑️ Removed dir: {}", path.display());
                        }
                    }
                }
            }
        }
    }
    println!("✅ Test file cleanup complete.");
}
