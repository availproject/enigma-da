use crate::db::store::DataStore;
use crate::network_manager::NetworkManager;
use crate::p2p::node::NodeCommand;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub enum JobType {
    RegisterApp(String, uuid::Uuid), // app_id, job_id
    DecryptJob(String, uuid::Uuid, Vec<Vec<u8>>, Vec<Vec<u8>>), // app_id, job_id, encrypted_data, ephemeral_pub_key
    CleanupShards,                                              // Cleanup job for old shards
}

const SHARD_REQUEST_INTERVAL: u64 = 5;
const SHARD_REQUEST_RETRY_COUNT: u32 = 5;
const SHARD_CLEANUP_INTERVAL_HOURS: u64 = 6; // 6 hours

pub struct JobWorker {
    tx: mpsc::UnboundedSender<JobType>,
    rx: mpsc::UnboundedReceiver<JobType>,
    data_store: Arc<DataStore>,
    network_manager: Arc<Mutex<NetworkManager>>,
    retry_count: u32,
}

impl JobWorker {
    pub fn new(data_store: Arc<DataStore>, network_manager: Arc<Mutex<NetworkManager>>) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self {
            tx,
            rx,
            data_store,
            network_manager,
            retry_count: 0,
        }
    }

    pub fn get_tx(&self) -> mpsc::UnboundedSender<JobType> {
        self.tx.clone()
    }

    pub async fn run_job_worker(mut self) -> Result<(), anyhow::Error> {
        // Start the cleanup job as a background task that runs continuously
        let data_store_clone = self.data_store.clone();
        let cleanup_task = tokio::spawn(async move {
            loop {
                tracing::info!("Starting periodic shard cleanup job");
                if let Err(e) = Self::handle_cleanup_shards_static(&data_store_clone).await {
                    tracing::error!("Cleanup job failed: {}", e);
                }

                // Wait for 6 hours before next cleanup
                tokio::time::sleep(std::time::Duration::from_secs(
                    SHARD_CLEANUP_INTERVAL_HOURS * 3600,
                ))
                .await;
            }
        });

        let job_worker: tokio::task::JoinHandle<Result<(), anyhow::Error>> =
            tokio::spawn(async move {
                while let Some(job) = self.rx.recv().await {
                    match job {
                        JobType::RegisterApp(_app_id, _job_id) => {
                            tracing::info!("Received register app job");
                        }
                        JobType::DecryptJob(app_id, job_id, encrypted_data, ephemeral_pub_key) => {
                            self.handle_decrypt_job(
                                app_id,
                                job_id,
                                encrypted_data,
                                ephemeral_pub_key,
                            )
                            .await?;
                        }
                        JobType::CleanupShards => {
                            self.handle_cleanup_shards().await?;
                        }
                    }
                }
                Ok(())
            });

        // Wait for either task to complete (though cleanup task runs indefinitely)
        tokio::select! {
            _ = cleanup_task => {
                tracing::error!("Cleanup task unexpectedly terminated");
            }
            result = job_worker => {
                let _ = result?;
            }
        }

        Ok(())
    }

    pub async fn handle_decrypt_job(
        &mut self,
        app_id: String,
        job_id: uuid::Uuid,
        _encrypted_data: Vec<Vec<u8>>,
        _ephemeral_pub_key: Vec<Vec<u8>>,
    ) -> Result<(), anyhow::Error> {
        tracing::info!(
            "Handling decrypt job for app_id: {}, job_id: {}",
            app_id,
            job_id
        );
        let app_peer_ids = self.data_store.get_app_peer_ids(&app_id)?;
        if app_peer_ids.is_none() {
            tracing::error!("No peer ids found for app_id: {}. Skipping job.", app_id);
            return Ok(());
        }
        let peer_ids = app_peer_ids.unwrap();
        // Sending request to the peers to get the shard
        for peer_id in peer_ids {
            self.network_manager
                .lock()
                .await
                .send_command(NodeCommand::RequestShard {
                    peer_id: peer_id.clone(),
                    app_id: app_id.clone(),
                    job_id,
                })
                .await?;
        }
        // Wait for request to be completed
        while let Some((pending, _)) = self
            .network_manager
            .lock()
            .await
            .get_request_status(job_id)
            .await
        {
            if pending == 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_secs(SHARD_REQUEST_INTERVAL)).await;
            self.retry_count += 1;
            if self.retry_count > SHARD_REQUEST_RETRY_COUNT {
                tracing::error!(
                    "Failed to get shard for app_id: {}, job_id: {}",
                    app_id,
                    job_id
                );
                return Err(anyhow::anyhow!(
                    "Failed to get shard for app_id: {}, job_id: {}",
                    app_id,
                    job_id
                ));
            }
        }

        // Get the shard from the data store
        let shards = self.data_store.get_all_shards(&app_id)?;
        if shards.is_empty() {
            tracing::error!("No shard found for app_id: {}, job_id: {}", app_id, job_id);
            return Err(anyhow::anyhow!(
                "No shard found for app_id: {}, job_id: {}",
                app_id,
                job_id
            ));
        }

        // TODO : Add the shard indexes check
        // TODO : construct the key from shards
        // TODO : decrypt the data
        // TODO : store the decrypted data in the data store
        // TODO : update the decrypt request status to completed

        Ok(())
    }

    // Static method for the background cleanup task
    async fn handle_cleanup_shards_static(
        data_store: &Arc<DataStore>,
    ) -> Result<(), anyhow::Error> {
        tracing::info!("Starting cleanup of old shards");

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let cutoff_time = current_time - (SHARD_CLEANUP_INTERVAL_HOURS * 3600); // 6 hours ago

        // Get all apps that have stored data
        let apps = data_store.list_apps()?;
        let mut total_cleaned = 0;

        for app_id in apps {
            let shards = data_store.get_all_shards(&app_id)?;
            let mut shards_to_remove = Vec::new();

            // Check each shard's timestamp
            for (shard_index, _) in &shards {
                if let Ok(Some(shard_data)) = data_store.get_shard_data(&app_id, *shard_index) {
                    if shard_data.time_stamp < cutoff_time {
                        shards_to_remove.push(*shard_index);
                    }
                }
            }

            // Remove old shards
            for shard_index in shards_to_remove {
                if let Err(e) = data_store.remove_shard(&app_id, shard_index) {
                    tracing::error!(
                        "Failed to remove old shard for app_id: {}, shard_index: {}: {}",
                        app_id,
                        shard_index,
                        e
                    );
                } else {
                    tracing::info!(
                        "Removed old shard for app_id: {}, shard_index: {}",
                        app_id,
                        shard_index
                    );
                    total_cleaned += 1;
                }
            }
        }

        tracing::info!("Cleanup completed. Removed {} old shards", total_cleaned);
        Ok(())
    }

    pub async fn handle_cleanup_shards(&self) -> Result<(), anyhow::Error> {
        Self::handle_cleanup_shards_static(&self.data_store).await
    }
}
