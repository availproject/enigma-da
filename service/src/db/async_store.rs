use crate::db::store::DataStore as SyncDataStore;
use crate::db::types::{DecryptRequestData, RegisterAppRequestData, ShardData};
use crate::error::AppError;
use crate::traits::DataStore as DataStoreTrait;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

pub struct AsyncDataStore {
    store: Arc<Mutex<SyncDataStore>>,
}

impl AsyncDataStore {
    pub fn new(store: SyncDataStore) -> Self {
        Self {
            store: Arc::new(Mutex::new(store)),
        }
    }

    pub fn from_path(db_path: &str) -> Result<Self, AppError> {
        let store = SyncDataStore::new(db_path)
            .map_err(|e| AppError::Database(format!("Failed to create data store: {}", e)))?;
        Ok(Self::new(store))
    }
}

#[async_trait]
impl DataStoreTrait for AsyncDataStore {
    async fn get_public_key(&self, app_id: u32) -> Result<Vec<u8>, AppError> {
        let store = self.store.lock().await;
        store
            .get_public_key(app_id)
            .map_err(|e| AppError::Database(format!("Failed to get public key: {}", e)))
    }
    async fn store_public_key(&self, app_id: u32, public_key: &[u8]) -> Result<(), AppError> {
        let store = self.store.lock().await;
        store
            .store_public_key(app_id, public_key)
            .map_err(|e| AppError::Database(format!("Failed to store public key: {}", e)))
    }
    async fn store_decrypt_request(&self, request: DecryptRequestData) -> Result<(), AppError> {
        let store = self.store.lock().await;
        store
            .store_decrypt_request(request)
            .map_err(|e| AppError::Database(format!("Failed to store decrypt request: {}", e)))
    }
    async fn update_decrypt_request(
        &self,
        job_id: Uuid,
        request: DecryptRequestData,
    ) -> Result<(), AppError> {
        let store = self.store.lock().await;
        store
            .update_decrypt_request(job_id, request)
            .map_err(|e| AppError::Database(format!("Failed to update decrypt request: {}", e)))
    }
    async fn get_decrypt_request(
        &self,
        job_id: Uuid,
    ) -> Result<Option<DecryptRequestData>, AppError> {
        let store = self.store.lock().await;
        store
            .get_decrypt_request(job_id)
            .map_err(|e| AppError::Database(format!("Failed to get decrypt request: {}", e)))
    }
    async fn store_register_app_request(
        &self,
        request: RegisterAppRequestData,
    ) -> Result<(), AppError> {
        let store = self.store.lock().await;
        store
            .store_register_app_request(request)
            .map_err(|e| AppError::Database(format!("Failed to store register app request: {}", e)))
    }
    async fn update_register_app_request(
        &self,
        job_id: Uuid,
        request: RegisterAppRequestData,
    ) -> Result<(), AppError> {
        let store = self.store.lock().await;
        store
            .update_register_app_request(job_id, request)
            .map_err(|e| {
                AppError::Database(format!("Failed to update register app request: {}", e))
            })
    }
    async fn get_register_app_request(
        &self,
        job_id: Uuid,
    ) -> Result<Option<RegisterAppRequestData>, AppError> {
        let store = self.store.lock().await;
        store
            .get_register_app_request(job_id)
            .map_err(|e| AppError::Database(format!("Failed to get register app request: {}", e)))
    }
    async fn get_app_peer_ids(&self, app_id: u32) -> Result<Option<Vec<String>>, AppError> {
        let store = self.store.lock().await;
        store
            .get_app_peer_ids(app_id)
            .map_err(|e| AppError::Database(format!("Failed to get app peer IDs: {}", e)))
    }
    async fn add_app_peer_ids(&self, app_id: u32, peer_ids: Vec<String>) -> Result<(), AppError> {
        let store = self.store.lock().await;
        store
            .add_app_peer_ids(app_id, peer_ids)
            .map_err(|e| AppError::Database(format!("Failed to add app peer IDs: {}", e)))
    }
    async fn add_shard(
        &self,
        app_id: u32,
        shard_index: u32,
        shard: String,
    ) -> Result<(), AppError> {
        let store = self.store.lock().await;
        store
            .add_shard(app_id, shard_index, shard)
            .map_err(|e| AppError::Database(format!("Failed to add shard: {}", e)))
    }
    async fn get_shard(&self, app_id: u32, shard_index: u32) -> Result<Option<String>, AppError> {
        let store = self.store.lock().await;
        store
            .get_shard(app_id, shard_index)
            .map_err(|e| AppError::Database(format!("Failed to get shard: {}", e)))
    }
    async fn get_all_shards(
        &self,
        app_id: u32,
    ) -> Result<std::collections::HashMap<u32, String>, AppError> {
        let store = self.store.lock().await;
        store
            .get_all_shards(app_id)
            .map_err(|e| AppError::Database(format!("Failed to get all shards: {}", e)))
    }
    async fn remove_shard(&self, app_id: u32, shard_index: u32) -> Result<(), AppError> {
        let store = self.store.lock().await;
        store
            .remove_shard(app_id, shard_index)
            .map_err(|e| AppError::Database(format!("Failed to remove shard: {}", e)))
    }
    async fn list_apps(&self) -> Result<Vec<u32>, AppError> {
        let store = self.store.lock().await;
        store
            .list_apps()
            .map_err(|e| AppError::Database(format!("Failed to list apps: {}", e)))
    }
    async fn get_shard_data(
        &self,
        app_id: u32,
        shard_index: u32,
    ) -> Result<Option<ShardData>, AppError> {
        let store = self.store.lock().await;
        store
            .get_shard_data(app_id, shard_index)
            .map_err(|e| AppError::Database(format!("Failed to get shard data: {}", e)))
    }
}
