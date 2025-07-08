use anyhow::Result;
use serde::{Deserialize, Serialize};
use sled::Db;
use std::collections::HashMap;

// Key prefixes for different data types
const SHARD_PREFIX: &str = "shard:";
const PEER_ID_PREFIX: &str = "peer:";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardData {
    pub app_id: String,
    pub shard_index: u32,
    pub shard: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerIdData {
    pub app_id: String,
    pub peer_ids: Vec<String>,
}

pub struct P2PStore {
    db: Db,
}

impl P2PStore {
    pub fn new(db_path: &str) -> Result<Self> {
        let db = sled::open(db_path)?;
        Ok(Self { db })
    }

    /// Get a specific shard for an app
    pub fn get_shard(&self, app_id: &str, shard_index: u32) -> Result<Option<String>> {
        let key = format!("{}:{}:{}", SHARD_PREFIX, app_id, shard_index);
        match self.db.get(key.as_bytes())? {
            Some(value) => {
                let shard_data: ShardData = bincode::deserialize(&value)?;
                Ok(Some(shard_data.shard))
            }
            None => Ok(None),
        }
    }

    /// Get all shards for an app
    pub fn get_all_shards(&self, app_id: &str) -> Result<HashMap<u32, String>> {
        let mut shards = HashMap::new();
        let prefix = format!("{}:{}:", SHARD_PREFIX, app_id);

        for result in self.db.scan_prefix(prefix.as_bytes()) {
            let (_, value) = result?;
            let shard_data: ShardData = bincode::deserialize(&value)?;
            shards.insert(shard_data.shard_index, shard_data.shard);
        }

        Ok(shards)
    }

    /// Get peer IDs for an app
    pub fn get_app_peer_ids(&self, app_id: &str) -> Result<Option<Vec<String>>> {
        let key = format!("{}:{}", PEER_ID_PREFIX, app_id);
        match self.db.get(key.as_bytes())? {
            Some(value) => {
                let peer_data: PeerIdData = bincode::deserialize(&value)?;
                Ok(Some(peer_data.peer_ids))
            }
            None => Ok(None),
        }
    }

    /// Add a shard for an app
    pub fn add_shard(&self, app_id: &str, shard_index: u32, shard: String) -> Result<()> {
        let key = format!("{}:{}:{}", SHARD_PREFIX, app_id, shard_index);
        let shard_data = ShardData {
            app_id: app_id.to_string(),
            shard_index,
            shard,
        };
        let value = bincode::serialize(&shard_data)?;
        self.db.insert(key.as_bytes(), value)?;
        self.db.flush()?;
        Ok(())
    }

    /// Add peer IDs for an app
    pub fn add_app_peer_ids(&self, app_id: &str, peer_ids: Vec<String>) -> Result<()> {
        let key = format!("{}:{}", PEER_ID_PREFIX, app_id);
        let peer_data = PeerIdData {
            app_id: app_id.to_string(),
            peer_ids,
        };
        let value = bincode::serialize(&peer_data)?;
        self.db.insert(key.as_bytes(), value)?;
        self.db.flush()?;
        Ok(())
    }

    /// Remove peer IDs for an app
    pub fn remove_app_peer_ids(&self, app_id: &str) -> Result<()> {
        let key = format!("{}:{}", PEER_ID_PREFIX, app_id);
        self.db.remove(key.as_bytes())?;
        self.db.flush()?;
        Ok(())
    }

    /// Remove a specific shard
    pub fn remove_shard(&self, app_id: &str, shard_index: u32) -> Result<()> {
        let key = format!("{}:{}:{}", SHARD_PREFIX, app_id, shard_index);
        self.db.remove(key.as_bytes())?;
        self.db.flush()?;
        Ok(())
    }

    /// Remove all data for an app (both shards and peer IDs)
    pub fn remove_app(&self, app_id: &str) -> Result<()> {
        // Remove all shards for this app
        let shard_prefix = format!("{}:{}:", SHARD_PREFIX, app_id);
        for result in self.db.scan_prefix(shard_prefix.as_bytes()) {
            let (key, _) = result?;
            self.db.remove(&key)?;
        }

        // Remove peer IDs for this app
        let peer_key = format!("{}:{}", PEER_ID_PREFIX, app_id);
        self.db.remove(peer_key.as_bytes())?;

        self.db.flush()?;
        Ok(())
    }

    /// List all app IDs that have stored data
    pub fn list_apps(&self) -> Result<Vec<String>> {
        let mut apps = std::collections::HashSet::new();

        // Get apps from shard data
        for result in self.db.scan_prefix(SHARD_PREFIX.as_bytes()) {
            let (_, value) = result?;
            if let Ok(shard_data) = bincode::deserialize::<ShardData>(&value) {
                apps.insert(shard_data.app_id);
            }
        }

        // Get apps from peer ID data
        for result in self.db.scan_prefix(PEER_ID_PREFIX.as_bytes()) {
            let (_, value) = result?;
            if let Ok(peer_data) = bincode::deserialize::<PeerIdData>(&value) {
                apps.insert(peer_data.app_id);
            }
        }

        Ok(apps.into_iter().collect())
    }

    /// Get database statistics (basic info)
    pub fn get_stats(&self) -> Result<String> {
        let tree_count = self.db.tree_names().len();
        let size_on_disk = self.db.size_on_disk()?;
        Ok(format!(
            "Trees: {}, Size on disk: {} bytes",
            tree_count, size_on_disk
        ))
    }

    /// Compact the database to reclaim space
    pub fn compact(&self) -> Result<()> {
        // Sled doesn't have a direct compact method, but we can flush to ensure data is written
        self.db.flush()?;
        Ok(())
    }

    /// Close the database
    pub fn close(self) -> Result<()> {
        self.db.flush()?;
        Ok(())
    }
}

impl Drop for P2PStore {
    fn drop(&mut self) {
        if let Err(e) = self.db.flush() {
            eprintln!("Failed to flush database on drop: {}", e);
        }
    }
}
