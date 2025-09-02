use std::collections::HashMap;

use log::info;
use uuid::Uuid;

pub struct ShardStore {
    db: sled::Db,
}

impl ShardStore {
    pub fn new(node_name: &str) -> anyhow::Result<Self> {
        let db_path = format!("shard_store_{}_db", node_name);
        let db = sled::open(&db_path)?;
        info!(
            "[{}] 💾 ShardStore initialized with database at: {}",
            node_name, db_path
        );
        Ok(ShardStore { db })
    }

    #[cfg(test)]
    pub fn new_with_suffix(node_name: &str, suffix: &str) -> anyhow::Result<Self> {
        let db_path = format!("shard_store_{}_{}_db", node_name, suffix);
        let db = sled::open(&db_path)?;
        info!(
            "[{}] 💾 ShardStore initialized with database at: {}",
            node_name, db_path
        );
        Ok(ShardStore { db })
    }

    pub fn add_shard(&self, app_id: Uuid, shard_index: u32, shard: String) -> anyhow::Result<()> {
        let key = format!("{}:{}", app_id, shard_index);
        self.db.insert(key.as_bytes(), shard.as_bytes())?;
        info!(
            "💾 Stored shard for app_id: {}, shard_index: {}",
            app_id, shard_index
        );
        Ok(())
    }

    pub fn get_shard(&self, app_id: Uuid, shard_index: u32) -> anyhow::Result<Option<String>> {
        let key = format!("{}:{}", app_id, shard_index);
        if let Some(value) = self.db.get(key.as_bytes())? {
            let shard = String::from_utf8(value.to_vec())?;
            Ok(Some(shard))
        } else {
            Ok(None)
        }
    }

    pub fn get_all_shards_for_app(&self, app_id: Uuid) -> anyhow::Result<HashMap<u32, String>> {
        let mut shards = HashMap::new();
        let prefix = format!("{}:", app_id);

        for result in self.db.scan_prefix(prefix.as_bytes()) {
            let (key, value) = result?;
            let key_str = String::from_utf8(key.to_vec())?;
            let parts: Vec<&str> = key_str.split(':').collect();
            if parts.len() == 2 {
                if let Ok(shard_index) = parts[1].parse::<u32>() {
                    let shard = String::from_utf8(value.to_vec())?;
                    shards.insert(shard_index, shard);
                }
            }
        }
        Ok(shards)
    }

    pub fn remove_shard(&self, app_id: Uuid, shard_index: u32) -> anyhow::Result<()> {
        let key = format!("{}:{}", app_id, shard_index);
        self.db.remove(key.as_bytes())?;
        Ok(())
    }

    pub fn clear_app_shards(&self, app_id: u32) -> anyhow::Result<()> {
        let prefix = format!("{}:", app_id);
        let keys_to_remove: Vec<Vec<u8>> = self
            .db
            .scan_prefix(prefix.as_bytes())
            .map(|result| result.map(|(key, _)| key.to_vec()))
            .collect::<Result<Vec<_>, _>>()?;

        for key in keys_to_remove {
            self.db.remove(key)?;
        }
        Ok(())
    }
}
