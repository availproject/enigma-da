use crate::db::types::{
    DecryptRequestData, ReencryptRequestData, RegisterAppRequestData, ShardData,
};
use crate::error::AppError;
use async_trait::async_trait;
use uuid::Uuid;

#[async_trait]
pub trait DataStore: Send + Sync {
    async fn get_public_key(&self, app_id: u32) -> Result<Vec<u8>, AppError>;
    async fn store_public_key(&self, app_id: u32, public_key: &[u8]) -> Result<(), AppError>;
    async fn store_decrypt_request(&self, request: DecryptRequestData) -> Result<(), AppError>;
    async fn update_decrypt_request(
        &self,
        job_id: Uuid,
        request: DecryptRequestData,
    ) -> Result<(), AppError>;
    async fn get_decrypt_request(
        &self,
        job_id: Uuid,
    ) -> Result<Option<DecryptRequestData>, AppError>;
    async fn store_register_app_request(
        &self,
        request: RegisterAppRequestData,
    ) -> Result<(), AppError>;
    async fn update_register_app_request(
        &self,
        job_id: Uuid,
        request: RegisterAppRequestData,
    ) -> Result<(), AppError>;
    async fn get_register_app_request(
        &self,
        job_id: Uuid,
    ) -> Result<Option<RegisterAppRequestData>, AppError>;
    async fn store_reencrypt_request(&self, request: ReencryptRequestData) -> Result<(), AppError>;
    async fn update_reencrypt_request(
        &self,
        job_id: Uuid,
        request: ReencryptRequestData,
    ) -> Result<(), AppError>;
    async fn get_reencrypt_request(
        &self,
        job_id: Uuid,
    ) -> Result<Option<ReencryptRequestData>, AppError>;
    async fn get_app_peer_ids(&self, app_id: u32) -> Result<Option<Vec<String>>, AppError>;
    async fn add_app_peer_ids(&self, app_id: u32, peer_ids: Vec<String>) -> Result<(), AppError>;
    async fn add_shard(&self, app_id: u32, shard_index: u32, shard: String)
    -> Result<(), AppError>;
    async fn get_shard(&self, app_id: u32, shard_index: u32) -> Result<Option<String>, AppError>;
    async fn get_all_shards(
        &self,
        app_id: u32,
    ) -> Result<std::collections::HashMap<u32, ShardData>, AppError>;
    async fn remove_shard(&self, app_id: u32, shard_index: u32) -> Result<(), AppError>;
    async fn list_apps(&self) -> Result<Vec<u32>, AppError>;
    async fn get_shard_data(
        &self,
        app_id: u32,
        shard_index: u32,
    ) -> Result<Option<ShardData>, AppError>;
}

#[async_trait]
pub trait NetworkManager: Send + Sync {
    async fn send_command(&self, command: crate::p2p::node::NodeCommand) -> Result<(), AppError>;
    async fn get_request_status(&self, job_id: Uuid) -> Option<(usize, usize)>;
    async fn shutdown(&mut self) -> Result<(), AppError>;
}

#[async_trait]
pub trait WorkerManager: Send + Sync {
    async fn send_job(&self, job: crate::handler::worker::JobType) -> Result<(), AppError>;
    async fn shutdown(&mut self) -> Result<(), AppError>;
}
