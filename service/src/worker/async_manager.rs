use crate::config::ServiceConfig;
use crate::error::AppError;
use crate::handler::worker::JobType;
use crate::traits::{DataStore, NetworkManager, WorkerManager as WorkerManagerTrait};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

pub struct AsyncWorkerManager {
    tx: mpsc::Sender<JobType>,
    worker_handle: Option<JoinHandle<Result<(), anyhow::Error>>>,
}

impl AsyncWorkerManager {
    pub fn new(
        data_store: Arc<dyn DataStore + Send + Sync>,
        network_manager: Arc<dyn NetworkManager + Send + Sync>,
        config: &ServiceConfig,
    ) -> Result<Self, AppError> {
        let (tx, rx) = mpsc::channel(config.worker.job_queue_size);

        let config_clone = config.clone();
        let worker_handle = tokio::spawn(async move {
            // Create and run the worker
            let worker = crate::handler::worker::JobWorker::new_with_receiver(
                rx,
                data_store,
                network_manager,
                config_clone,
            )
            .await?;
            worker.run_job_worker().await
        });

        Ok(Self {
            tx,
            worker_handle: Some(worker_handle),
        })
    }
}

#[async_trait]
impl WorkerManagerTrait for AsyncWorkerManager {
    async fn send_job(&self, job: JobType) -> Result<(), AppError> {
        self.tx
            .send(job)
            .await
            .map_err(|e| AppError::Worker(format!("Failed to send job: {}", e)))
    }

    async fn shutdown(&mut self) -> Result<(), AppError> {
        // Drop the sender to close the channel
        let _ = self
            .tx
            .try_send(crate::handler::worker::JobType::CleanupShards);

        // Wait for the worker to finish
        if let Some(handle) = self.worker_handle.take() {
            match handle.await {
                Ok(result) => {
                    result.map_err(|e| AppError::Worker(format!("Worker failed: {}", e)))?;
                }
                Err(e) => {
                    return Err(AppError::Worker(format!("Failed to join worker: {}", e)));
                }
            }
        }

        Ok(())
    }
}

impl Drop for AsyncWorkerManager {
    fn drop(&mut self) {
        if self.worker_handle.is_some() {
            tracing::warn!("AsyncWorkerManager dropped without proper shutdown");
        }
    }
}
