use crate::config::ServiceConfig;
use crate::db::types::{
    DECRYPT_REQUEST_PREFIX, DecryptRequestData, PEER_ID_PREFIX, PUBLIC_KEY_PREFIX, PeerIdData,
    REENCRYPT_REQUEST_PREFIX, REGISTER_APP_REQUEST_PREFIX, ReencryptRequestData,
    RegisterAppRequestData, SHARD_PREFIX, ShardData,
};
use anyhow::Result;
use sled::Db;
use std::collections::HashMap;
use uuid::Uuid;

pub struct DataStore {
    db: Db,
    config: ServiceConfig,
    db_path: String,
    write_count: std::sync::atomic::AtomicU64,
}

impl DataStore {
    pub fn new(db_path: &str, config: ServiceConfig) -> Result<Self> {
        let db = sled::open(db_path)?;
        Ok(Self {
            db,
            config,
            db_path: db_path.to_string(),
            write_count: std::sync::atomic::AtomicU64::new(0),
        })
    }

    pub fn get_db_path(&self) -> &str {
        &self.db_path
    }

    pub fn get_config(&self) -> &ServiceConfig {
        &self.config
    }

    fn maybe_flush(&self) -> Result<()> {
        let write_count = self
            .write_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // Flush every 100 writes to reduce I/O overhead
        if write_count % 100 == 0 {
            self.db.flush()?;
        }
        Ok(())
    }

    pub fn store_public_key(&self, app_id: Uuid, public_key: &[u8]) -> Result<()> {
        if public_key.is_empty() {
            return Err(anyhow::anyhow!("Keys cannot be empty"));
        }

        let pub_key_key = format!("{}:{app_id}", PUBLIC_KEY_PREFIX);

        self.db
            .insert(pub_key_key.as_bytes(), public_key)
            .map_err(|e| anyhow::anyhow!("Failed to store public key: {}", e))?;

        // Only flush periodically, not on every write
        self.maybe_flush()?;

        Ok(())
    }

    pub fn get_public_key(&self, app_id: Uuid) -> Result<Vec<u8>> {
        let pub_key_key = format!("{}:{app_id}", PUBLIC_KEY_PREFIX);
        match self.db.get(pub_key_key.as_bytes()) {
            Ok(Some(ivec)) => Ok(ivec.to_vec()),
            Ok(None) => Err(anyhow::anyhow!("Public key not found")),
            Err(e) => Err(anyhow::anyhow!("Failed to get public key: {}", e)),
        }
    }

    /// Get a specific shard for an app
    pub fn get_shard(&self, app_id: Uuid, shard_index: u32) -> Result<Option<String>> {
        let key = format!("{}:{}:{}", SHARD_PREFIX, app_id, shard_index);
        match self.db.get(key.as_bytes())? {
            Some(value) => {
                let shard_data: ShardData = bincode::deserialize(&value)?;
                Ok(Some(shard_data.shard))
            }
            None => Ok(None),
        }
    }

    /// Get a specific shard data (including timestamp) for an app
    pub fn get_shard_data(&self, app_id: Uuid, shard_index: u32) -> Result<Option<ShardData>> {
        let key = format!("{}:{}:{}", SHARD_PREFIX, app_id, shard_index);
        match self.db.get(key.as_bytes())? {
            Some(value) => {
                let shard_data: ShardData = bincode::deserialize(&value)?;
                Ok(Some(shard_data))
            }
            None => Ok(None),
        }
    }

    /// Get all shards for an app
    pub fn get_all_shards(&self, app_id: Uuid) -> Result<HashMap<u32, ShardData>> {
        let mut shards = HashMap::new();

        for i in 0..self.config.p2p.number_of_p2p_network_nodes {
            let shard = self.get_shard_data(app_id, i as u32)?;
            if shard.is_some() {
                shards.insert(i as u32, shard.unwrap());
            }
        }

        Ok(shards)
    }

    /// Get peer IDs for an app
    pub fn get_app_peer_ids(&self, app_id: Uuid) -> Result<Option<Vec<String>>> {
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
    pub fn add_shard(&self, app_id: Uuid, shard_index: u32, shard: String) -> Result<()> {
        let key = format!("{}:{}:{}", SHARD_PREFIX, app_id, shard_index);
        let shard_data = ShardData {
            app_id: app_id.to_string(),
            shard_index,
            shard,
            time_stamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        let value = bincode::serialize(&shard_data)?;
        self.db.insert(key.as_bytes(), value)?;
        self.maybe_flush()?;
        Ok(())
    }

    /// Add peer IDs for an app
    pub fn add_app_peer_ids(&self, app_id: Uuid, peer_ids: Vec<String>) -> Result<()> {
        let key = format!("{}:{}", PEER_ID_PREFIX, app_id);
        let peer_data = PeerIdData {
            app_id: app_id.to_string(),
            peer_ids,
        };
        let value = bincode::serialize(&peer_data)?;
        self.db.insert(key.as_bytes(), value)?;
        self.maybe_flush()?;
        Ok(())
    }

    /// Remove peer IDs for an app
    pub fn remove_app_peer_ids(&self, app_id: u32) -> Result<()> {
        let key = format!("{}:{}", PEER_ID_PREFIX, app_id);
        self.db.remove(key.as_bytes())?;
        self.maybe_flush()?;
        Ok(())
    }

    /// Remove a specific shard
    pub fn remove_shard(&self, app_id: Uuid, shard_index: u32) -> Result<()> {
        let key = format!("{}:{}:{}", SHARD_PREFIX, app_id, shard_index);
        self.db.remove(key.as_bytes())?;
        self.maybe_flush()?;
        Ok(())
    }

    /// Remove all data for an app (both shards and peer IDs)
    pub fn remove_app(&self, app_id: Uuid) -> Result<()> {
        // Remove all shards for this app
        let shard_prefix = format!("{}:{}:", SHARD_PREFIX, app_id);
        for result in self.db.scan_prefix(shard_prefix.as_bytes()) {
            let (key, _) = result?;
            self.db.remove(&key)?;
        }

        // Remove peer IDs for this app
        let peer_key = format!("{}:{}", PEER_ID_PREFIX, app_id);
        self.db.remove(peer_key.as_bytes())?;

        self.maybe_flush()?;
        Ok(())
    }

    pub fn store_decrypt_request(&self, request: DecryptRequestData) -> Result<()> {
        let key = format!("{}:{}", DECRYPT_REQUEST_PREFIX, request.job_id);
        let value = bincode::serialize(&request)?;
        self.db.insert(key.as_bytes(), value)?;
        self.maybe_flush()?;
        Ok(())
    }

    pub fn update_decrypt_request(
        &self,
        job_id: uuid::Uuid,
        request: DecryptRequestData,
    ) -> Result<()> {
        let key = format!("{}:{}", DECRYPT_REQUEST_PREFIX, job_id);
        let value = bincode::serialize(&request)?;
        self.db.insert(key.as_bytes(), value)?;
        self.maybe_flush()?;
        Ok(())
    }

    pub fn get_decrypt_request(&self, job_id: uuid::Uuid) -> Result<Option<DecryptRequestData>> {
        let key = format!("{}:{}", DECRYPT_REQUEST_PREFIX, job_id);
        match self.db.get(key.as_bytes())? {
            Some(value) => Ok(Some(bincode::deserialize(&value)?)),
            None => Ok(None),
        }
    }

    pub fn store_register_app_request(&self, request: RegisterAppRequestData) -> Result<()> {
        let key = format!("{}:{}", REGISTER_APP_REQUEST_PREFIX, request.job_id);
        let value = bincode::serialize(&request)?;
        self.db.insert(key.as_bytes(), value)?;
        self.maybe_flush()?;
        Ok(())
    }

    pub fn update_register_app_request(
        &self,
        job_id: uuid::Uuid,
        request: RegisterAppRequestData,
    ) -> Result<()> {
        let key = format!("{}:{}", REGISTER_APP_REQUEST_PREFIX, job_id);
        let value = bincode::serialize(&request)?;
        self.db.insert(key.as_bytes(), value)?;
        self.maybe_flush()?;
        Ok(())
    }

    pub fn get_register_app_request(
        &self,
        job_id: uuid::Uuid,
    ) -> Result<Option<RegisterAppRequestData>> {
        let key = format!("{}:{}", REGISTER_APP_REQUEST_PREFIX, job_id);
        match self.db.get(key.as_bytes())? {
            Some(value) => Ok(Some(bincode::deserialize(&value)?)),
            None => Ok(None),
        }
    }

    pub fn store_reencrypt_request(&self, request: ReencryptRequestData) -> Result<()> {
        let key = format!("{}:{}", REENCRYPT_REQUEST_PREFIX, request.job_id);
        let value = bincode::serialize(&request)?;
        self.db.insert(key.as_bytes(), value)?;
        self.maybe_flush()?;
        Ok(())
    }

    pub fn update_reencrypt_request(
        &self,
        job_id: uuid::Uuid,
        request: ReencryptRequestData,
    ) -> Result<()> {
        let key = format!("{}:{}", REENCRYPT_REQUEST_PREFIX, job_id);
        let value = bincode::serialize(&request)?;
        self.db.insert(key.as_bytes(), value)?;
        self.maybe_flush()?;
        Ok(())
    }

    pub fn get_reencrypt_request(
        &self,
        job_id: uuid::Uuid,
    ) -> Result<Option<ReencryptRequestData>> {
        let key = format!("{}:{}", REENCRYPT_REQUEST_PREFIX, job_id);
        match self.db.get(key.as_bytes())? {
            Some(value) => Ok(Some(bincode::deserialize(&value)?)),
            None => Ok(None),
        }
    }

    /// List all app IDs that have stored data
    pub fn list_apps(&self) -> Result<Vec<Uuid>> {
        let mut apps = std::collections::HashSet::new();

        // Get apps from shard data
        for result in self.db.scan_prefix(SHARD_PREFIX.as_bytes()) {
            let (_, value) = result?;
            if let Ok(shard_data) = bincode::deserialize::<ShardData>(&value) {
                apps.insert(shard_data.app_id.parse::<Uuid>()?);
            }
        }

        // Get apps from peer ID data
        for result in self.db.scan_prefix(PEER_ID_PREFIX.as_bytes()) {
            let (_, value) = result?;
            if let Ok(peer_data) = bincode::deserialize::<PeerIdData>(&value) {
                apps.insert(peer_data.app_id.parse::<Uuid>()?);
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

impl Drop for DataStore {
    fn drop(&mut self) {
        if let Err(e) = self.db.flush() {
            eprintln!("Failed to flush database on drop: {}", e);
        }
    }
}
