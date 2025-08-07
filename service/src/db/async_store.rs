use crate::config::ServiceConfig;
use crate::db::store::DataStore as SyncDataStore;
use crate::db::types::{
    DecryptRequestData, ReencryptRequestData, RegisterAppRequestData, ShardData,
};
use crate::error::AppError;
use crate::traits::DataStore as DataStoreTrait;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};
use uuid::Uuid;

pub struct AsyncDataStore {
    store: Arc<Mutex<SyncDataStore>>,
    semaphore: Arc<Semaphore>,
}

impl AsyncDataStore {
    pub fn new(store: SyncDataStore) -> Self {
        Self {
            store: Arc::new(Mutex::new(store)),
            semaphore: Arc::new(Semaphore::new(16)), // Allow up to 16 concurrent operations
        }
    }

    pub fn from_path(db_path: &str, config: ServiceConfig) -> Result<Self, AppError> {
        let store = SyncDataStore::new(db_path, config)
            .map_err(|e| AppError::Database(format!("Failed to create data store: {}", e)))?;

        Ok(Self::new(store))
    }

    async fn with_store<F, T>(&self, f: F) -> Result<T, AppError>
    where
        F: FnOnce(&mut SyncDataStore) -> Result<T, anyhow::Error>,
    {
        let _permit =
            self.semaphore.acquire().await.map_err(|e| {
                AppError::Database(format!("Failed to acquire database permit: {}", e))
            })?;

        let mut store = self.store.lock().await;
        f(&mut *store).map_err(|e| AppError::Database(format!("Database operation failed: {}", e)))
    }
}

#[async_trait]
impl DataStoreTrait for AsyncDataStore {
    async fn get_public_key(&self, app_id: u32) -> Result<Vec<u8>, AppError> {
        self.with_store(|store| store.get_public_key(app_id)).await
    }

    async fn store_public_key(&self, app_id: u32, public_key: &[u8]) -> Result<(), AppError> {
        self.with_store(|store| store.store_public_key(app_id, public_key))
            .await
    }

    async fn store_decrypt_request(&self, request: DecryptRequestData) -> Result<(), AppError> {
        self.with_store(|store| store.store_decrypt_request(request))
            .await
    }

    async fn update_decrypt_request(
        &self,
        job_id: Uuid,
        request: DecryptRequestData,
    ) -> Result<(), AppError> {
        self.with_store(|store| store.update_decrypt_request(job_id, request))
            .await
    }

    async fn get_decrypt_request(
        &self,
        job_id: Uuid,
    ) -> Result<Option<DecryptRequestData>, AppError> {
        self.with_store(|store| store.get_decrypt_request(job_id))
            .await
    }

    async fn store_register_app_request(
        &self,
        request: RegisterAppRequestData,
    ) -> Result<(), AppError> {
        self.with_store(|store| store.store_register_app_request(request))
            .await
    }

    async fn update_register_app_request(
        &self,
        job_id: Uuid,
        request: RegisterAppRequestData,
    ) -> Result<(), AppError> {
        self.with_store(|store| store.update_register_app_request(job_id, request))
            .await
    }

    async fn get_register_app_request(
        &self,
        job_id: Uuid,
    ) -> Result<Option<RegisterAppRequestData>, AppError> {
        self.with_store(|store| store.get_register_app_request(job_id))
            .await
    }

    async fn store_reencrypt_request(&self, request: ReencryptRequestData) -> Result<(), AppError> {
        self.with_store(|store| store.store_reencrypt_request(request))
            .await
    }

    async fn update_reencrypt_request(
        &self,
        job_id: Uuid,
        request: ReencryptRequestData,
    ) -> Result<(), AppError> {
        self.with_store(|store| store.update_reencrypt_request(job_id, request))
            .await
    }

    async fn get_reencrypt_request(
        &self,
        job_id: Uuid,
    ) -> Result<Option<ReencryptRequestData>, AppError> {
        self.with_store(|store| store.get_reencrypt_request(job_id))
            .await
    }

    async fn get_app_peer_ids(&self, app_id: u32) -> Result<Option<Vec<String>>, AppError> {
        self.with_store(|store| store.get_app_peer_ids(app_id))
            .await
    }

    async fn add_app_peer_ids(&self, app_id: u32, peer_ids: Vec<String>) -> Result<(), AppError> {
        self.with_store(|store| store.add_app_peer_ids(app_id, peer_ids))
            .await
    }

    async fn add_shard(
        &self,
        app_id: u32,
        shard_index: u32,
        shard: String,
    ) -> Result<(), AppError> {
        self.with_store(|store| store.add_shard(app_id, shard_index, shard))
            .await
    }

    async fn get_shard(&self, app_id: u32, shard_index: u32) -> Result<Option<String>, AppError> {
        self.with_store(|store| store.get_shard(app_id, shard_index))
            .await
    }

    async fn get_all_shards(
        &self,
        app_id: u32,
    ) -> Result<std::collections::HashMap<u32, ShardData>, AppError> {
        self.with_store(|store| store.get_all_shards(app_id)).await
    }

    async fn remove_shard(&self, app_id: u32, shard_index: u32) -> Result<(), AppError> {
        self.with_store(|store| store.remove_shard(app_id, shard_index))
            .await
    }

    async fn list_apps(&self) -> Result<Vec<u32>, AppError> {
        self.with_store(|store| store.list_apps()).await
    }

    async fn get_shard_data(
        &self,
        app_id: u32,
        shard_index: u32,
    ) -> Result<Option<ShardData>, AppError> {
        self.with_store(|store| store.get_shard_data(app_id, shard_index))
            .await
    }
}
