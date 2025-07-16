use crate::config::ServiceConfig;
use crate::error::AppError;
use crate::network_manager::NetworkManager as SyncNetworkManager;
use crate::p2p::node::NodeCommand;
use crate::traits::NetworkManager as NetworkManagerTrait;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

pub struct AsyncNetworkManager {
    manager: Arc<Mutex<SyncNetworkManager>>,
}

impl AsyncNetworkManager {
    pub fn new(manager: SyncNetworkManager) -> Self {
        Self {
            manager: Arc::new(Mutex::new(manager)),
        }
    }

    pub async fn from_config(
        port: u16,
        node_name: String,
        config: ServiceConfig,
    ) -> Result<Self, AppError> {
        let manager = SyncNetworkManager::new(port, node_name, config)
            .await
            .map_err(|e| AppError::Network(format!("Failed to create network manager: {}", e)))?;
        Ok(Self { manager })
    }
}

#[async_trait]
impl NetworkManagerTrait for AsyncNetworkManager {
    async fn send_command(&self, command: NodeCommand) -> Result<(), AppError> {
        let manager = self.manager.lock().await;
        manager
            .send_command(command)
            .await
            .map_err(|e| AppError::Network(format!("Failed to send command: {}", e)))
    }

    async fn get_request_status(&self, job_id: Uuid) -> Option<(usize, usize)> {
        let manager = self.manager.lock().await;
        manager.get_request_status(job_id).await
    }

    async fn shutdown(&mut self) -> Result<(), AppError> {
        let mut manager = self.manager.lock().await;
        manager
            .shutdown()
            .await
            .map_err(|e| AppError::Network(format!("Failed to shutdown network manager: {}", e)))
    }
}
