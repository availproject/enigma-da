mod p2p;
mod sled;
mod tee;

use glob::glob;
use std::fs;

pub async fn cleanup_test_files() {
    println!("🧹 Cleaning up test files...");

    let current_dir = std::env::current_dir().unwrap();
    println!("Current dir: {}", current_dir.display());

    let key_patterns = [
        "node_key_*.bin",
        "node_key_*.pem",
        "peer_id_*.txt",
        "shard_store_*",
        "./kms-node/node_key_*.bin",
        "./kms-node/node_key_*.pem",
        "./kms-node/peer_id_*.txt",
        "./kms-node/shard_store_*",
    ];

    for pattern in &key_patterns {
        if let Ok(entries) = glob(pattern) {
            for entry in entries {
                if let Ok(path) = entry {
                    if let Err(e) = fs::remove_dir_all(&path) {
                        println!("⚠️ Failed to remove file {}: {}", path.display(), e);
                    } else {
                        println!("🗑️ Removed file: {}", path.display());
                    }
                }
            }
        }
    }

    println!("✅ Test file cleanup complete.");
}
