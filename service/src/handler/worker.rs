use crate::db::types::RegisterAppRequestData;
use crate::db::types::RequestStatus;
use crate::db::types::{DecryptRequestData, ReencryptRequestData};
use crate::error::AppError;
use crate::p2p::node::NodeCommand;
use crate::traits::{DataStore as DataStoreTrait, NetworkManager as NetworkManagerTrait};
use ecies::SecretKey;
use k256::Scalar;
use keygen::keygen;
use keys::keys::PrivateKeyShare;
use keys::keys::Verifier;
use keys::keystore::KeyStore;
use lazy_static::lazy_static;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;

lazy_static! {
    static ref PEERS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(load_json_array());
    static ref N: u32 = PEERS.lock().unwrap().len() as u32;
    static ref K: u32 = *N / 2 + 1;
}

const PEERS_FILE: &str = "peers.json";

#[derive(Debug, Clone)]
pub enum JobType {
    RegisterApp(u32, uuid::Uuid), // app_id, job_id
    DecryptJob(u32, uuid::Uuid, Vec<Vec<u8>>, Vec<Vec<u8>>), // app_id, job_id, encrypted_data, ephemeral_pub_key
    ReencryptJob(u32, uuid::Uuid, Vec<u8>),                  // app_id, job_id, public_key
    CleanupShards,                                           // Cleanup job for old shards
}

const SHARD_REQUEST_INTERVAL: u64 = 5;
const SHARD_REQUEST_RETRY_COUNT: u32 = 5;
const SHARD_CLEANUP_INTERVAL_HOURS: u64 = 6; // 6 hours

pub struct JobWorker {
    tx: mpsc::UnboundedSender<JobType>,
    rx: mpsc::UnboundedReceiver<JobType>,
    data_store: Arc<dyn DataStoreTrait + Send + Sync>,
    network_manager: Arc<dyn NetworkManagerTrait + Send + Sync>,
    retry_count: u32,
}

impl JobWorker {
    pub fn new(
        data_store: Arc<dyn DataStoreTrait + Send + Sync>,
        network_manager: Arc<dyn NetworkManagerTrait + Send + Sync>,
    ) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self {
            tx,
            rx,
            data_store,
            network_manager,
            retry_count: 0,
        }
    }

    pub async fn new_with_receiver(
        mut rx: mpsc::Receiver<JobType>,
        data_store: Arc<dyn DataStoreTrait + Send + Sync>,
        network_manager: Arc<dyn NetworkManagerTrait + Send + Sync>,
        _config: crate::config::ServiceConfig,
    ) -> Result<Self, anyhow::Error> {
        let (tx, unbounded_rx) = mpsc::unbounded_channel();
        let tx_clone = tx.clone();

        // Convert bounded receiver to unbounded receiver by spawning a task
        tokio::spawn(async move {
            while let Some(job) = rx.recv().await {
                if tx_clone.send(job).is_err() {
                    break;
                }
            }
        });

        Ok(Self {
            tx,
            rx: unbounded_rx,
            data_store,
            network_manager,
            retry_count: 0,
        })
    }

    pub fn get_tx(&self) -> mpsc::UnboundedSender<JobType> {
        self.tx.clone()
    }

    pub async fn run_job_worker(mut self) -> Result<(), anyhow::Error> {
        // Clone the peers data to avoid holding mutex guard across async boundaries
        let peers = PEERS.lock().unwrap().clone();
        let n = *N;
        let k = *K;

        // Start the cleanup job as a background task that runs once
        let data_store_clone = self.data_store.clone();
        let cleanup_task = tokio::spawn(async move {
            tracing::info!("Starting one-time shard cleanup job");
            if let Err(e) = Self::handle_cleanup_shards_static(&data_store_clone).await {
                tracing::error!("Cleanup job failed: {}", e);
            }
            tracing::info!("Cleanup job completed");
        });

        let job_worker: tokio::task::JoinHandle<Result<(), anyhow::Error>> =
            tokio::spawn(async move {
                while let Some(job) = self.rx.recv().await {
                    match job {
                        JobType::RegisterApp(app_id, job_id) => {
                            let result = self
                                .handle_register_app_job(app_id, job_id, &peers, n, k)
                                .await;
                            if let Err(e) = result {
                                self.data_store
                                    .update_register_app_request(
                                        job_id,
                                        RegisterAppRequestData {
                                            app_id: app_id.to_string(),
                                            job_id,
                                            status: RequestStatus::Failed,
                                            public_key: None,
                                        },
                                    )
                                    .await?;
                                tracing::error!("Failed to handle register app job: {}", e);
                            }
                        }
                        JobType::DecryptJob(app_id, job_id, encrypted_data, ephemeral_pub_key) => {
                            let result = self
                                .handle_decrypt_job(
                                    app_id,
                                    job_id,
                                    k,
                                    encrypted_data.clone(),
                                    ephemeral_pub_key.clone(),
                                )
                                .await;
                            if let Err(e) = result {
                                self.data_store
                                    .update_decrypt_request(
                                        job_id,
                                        DecryptRequestData {
                                            app_id: app_id.to_string(),
                                            job_id,
                                            status: RequestStatus::Failed,
                                            ciphertext_array: encrypted_data,
                                            ephemeral_pub_key_array: ephemeral_pub_key,
                                            decrypted_array: None,
                                        },
                                    )
                                    .await?;
                                tracing::error!("Failed to handle decrypt job: {}", e);
                            }
                        }
                        JobType::ReencryptJob(app_id, job_id, public_key) => {
                            let result = self
                                .handle_reencrypt_job(app_id, job_id, k, public_key)
                                .await;
                            if let Err(e) = result {
                                self.data_store
                                    .update_reencrypt_request(
                                        job_id,
                                        ReencryptRequestData {
                                            app_id: app_id.to_string(),
                                            job_id,
                                            status: RequestStatus::Failed,
                                            ephemeral_pub_key: None,
                                            private_key_ciphertext: None,
                                        },
                                    )
                                    .await?;
                                tracing::error!("Failed to handle reencrypt job: {}", e);
                            }
                        }
                        JobType::CleanupShards => {
                            self.handle_cleanup_shards().await?;
                        }
                    }
                }
                Ok(())
            });

        // Wait for both tasks to complete
        tokio::select! {
            _ = cleanup_task => {
                tracing::info!("Cleanup task completed");
            }
            result = job_worker => {
                let _ = result?;
            }
        }

        Ok(())
    }

    pub async fn handle_reencrypt_job(
        &mut self,
        app_id: u32,
        job_id: uuid::Uuid,
        k: u32,
        public_key: Vec<u8>,
    ) -> Result<(), anyhow::Error> {
        tracing::info!(
            "Handling reencrypt job for app_id: {}, job_id: {}",
            app_id,
            job_id
        );
        let app_peer_ids = self.data_store.get_app_peer_ids(app_id).await?;
        if app_peer_ids.is_none() {
            tracing::error!("No peer ids found for app_id: {}. Skipping job.", app_id);
            return Ok(());
        }
        let peer_ids = app_peer_ids.unwrap();
        // Sending request to the peers to get the shard
        for peer_id in peer_ids {
            self.network_manager
                .send_command(NodeCommand::RequestShard {
                    peer_id: peer_id.clone(),
                    app_id: app_id.to_string(),
                    job_id,
                })
                .await?;
        }
        // Wait for request to be completed
        while let Some((pending, _)) = self.network_manager.get_request_status(job_id).await {
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

        let (response_sender, response_receiver) = tokio::sync::oneshot::channel();
        self.network_manager
            .send_command(NodeCommand::GetShard {
                app_id: app_id.to_string(),
                response_sender,
            })
            .await?;
        let shards = response_receiver.await?;

        let secret_key = convert_shards_to_key(
            shards.values().map(|shard| shard.shard.clone()).collect(),
            k,
        )?;

        let (ephemeral_pub_key, ciphertext) =
            encrypt_private_key(&secret_key.serialize(), &public_key)?;

        self.data_store
            .update_reencrypt_request(
                job_id,
                ReencryptRequestData {
                    app_id: app_id.to_string(),
                    job_id,
                    status: RequestStatus::Completed,
                    ephemeral_pub_key: Some(ephemeral_pub_key),
                    private_key_ciphertext: Some(ciphertext),
                },
            )
            .await?;

        Ok(())
    }

    pub async fn handle_decrypt_job(
        &mut self,
        app_id: u32,
        job_id: uuid::Uuid,
        k: u32,
        encrypted_data: Vec<Vec<u8>>,
        ephemeral_pub_key: Vec<Vec<u8>>,
    ) -> Result<(), anyhow::Error> {
        tracing::info!(
            "Handling decrypt job for app_id: {}, job_id: {}",
            app_id,
            job_id
        );
        let app_peer_ids = self.data_store.get_app_peer_ids(app_id).await?;
        if app_peer_ids.is_none() {
            tracing::error!("No peer ids found for app_id: {}. Skipping job.", app_id);
            return Ok(());
        }
        let peer_ids = app_peer_ids.unwrap();
        // Sending request to the peers to get the shard
        for peer_id in peer_ids {
            self.network_manager
                .send_command(NodeCommand::RequestShard {
                    peer_id: peer_id.clone(),
                    app_id: app_id.to_string(),
                    job_id,
                })
                .await?;
        }
        // Wait for request to be completed
        while let Some((pending, _)) = self.network_manager.get_request_status(job_id).await {
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

        let (response_sender, response_receiver) = tokio::sync::oneshot::channel();
        self.network_manager
            .send_command(NodeCommand::GetShard {
                app_id: app_id.to_string(),
                response_sender,
            })
            .await?;
        let shards = response_receiver.await?;

        let secret_key = convert_shards_to_key(
            shards.values().map(|shard| shard.shard.clone()).collect(),
            k,
        )?;

        let mut decrypted_data_vec: Vec<Vec<u8>> = Vec::new();
        for (i, data) in encrypted_data.iter().enumerate() {
            let ephemeral_pub_key_bytes: [u8; 65] = ephemeral_pub_key[i]
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("Failed to convert ephemeral pub key to [u8; 65]"))?;

            let ephemeral_pub_key = ecies::PublicKey::parse(&ephemeral_pub_key_bytes)
                .map_err(|_| anyhow::anyhow!("Failed to parse ephemeral pub key"))?;

            let mut full_ciphertext = ephemeral_pub_key.serialize().to_vec();
            full_ciphertext.extend_from_slice(data.as_slice());

            let decrypted_data = ecies::decrypt(&secret_key.serialize(), &full_ciphertext)
                .map_err(|_| anyhow::anyhow!("Failed to decrypt data"))?;

            decrypted_data_vec.push(decrypted_data);
        }

        self.data_store
            .update_decrypt_request(
                job_id,
                DecryptRequestData {
                    app_id: app_id.to_string(),
                    job_id,
                    status: RequestStatus::Completed,
                    ciphertext_array: encrypted_data,
                    ephemeral_pub_key_array: ephemeral_pub_key,
                    decrypted_array: Some(decrypted_data_vec),
                },
            )
            .await?;

        Ok(())
    }

    async fn handle_register_app_job(
        &mut self,
        app_id: u32,
        job_id: uuid::Uuid,
        peers: &Vec<String>,
        n: u32,
        k: u32,
    ) -> Result<(), anyhow::Error> {
        tracing::info!(
            "Handling register app job for app_id: {}, job_id: {}",
            app_id,
            job_id
        );
        let public_key = keygen(
            k as u16,
            n as u16,
            "ECIESThreshold",
            format!("./conf/{}", app_id).as_str(),
            true,
            app_id,
        )?;
        self.data_store
            .store_public_key(app_id, &public_key)
            .await?;
        self.data_store
            .add_app_peer_ids(app_id, peers.clone())
            .await?;

        // read the shards
        let shards = read_shards(app_id)?;
        for (i, peer_id) in peers.iter().enumerate() {
            self.network_manager
                .send_command(NodeCommand::SendShard {
                    peer_id: peer_id.clone(),
                    app_id: app_id.to_string(),
                    shard_index: i as u32,
                    shard: shards[i].clone(),
                    job_id,
                })
                .await?;
        }

        // Wait for request to be completed
        while let Some((pending, _)) = self.network_manager.get_request_status(job_id).await {
            if pending == 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_secs(SHARD_REQUEST_INTERVAL)).await;
            self.retry_count += 1;
            if self.retry_count > SHARD_REQUEST_RETRY_COUNT {
                tracing::error!(
                    "Failed to send shard for app_id: {}, job_id: {}",
                    app_id,
                    job_id
                );
                return Err(anyhow::anyhow!(
                    "Failed to send shard for app_id: {}, job_id: {}",
                    app_id,
                    job_id
                ));
            }
        }

        self.data_store
            .update_register_app_request(
                job_id,
                RegisterAppRequestData {
                    app_id: app_id.to_string(),
                    job_id,
                    status: RequestStatus::Completed,
                    public_key: Some(public_key),
                },
            )
            .await?;

        delete_shards(app_id)?;

        Ok(())
    }

    // Static method for the background cleanup task
    async fn handle_cleanup_shards_static(
        data_store: &Arc<dyn DataStoreTrait + Send + Sync>,
    ) -> Result<(), anyhow::Error> {
        tracing::info!("Starting cleanup of old shards");

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let cutoff_time = current_time - (SHARD_CLEANUP_INTERVAL_HOURS * 3600); // 6 hours ago

        // Get all apps that have stored data
        let apps = data_store.list_apps().await?;
        let mut total_cleaned = 0;

        for app_id in apps {
            let shards = data_store.get_all_shards(app_id).await?;
            let mut shards_to_remove = Vec::new();

            // Check each shard's timestamp
            for (shard_index, _) in &shards {
                if let Ok(Some(shard_data)) = data_store.get_shard_data(app_id, *shard_index).await
                {
                    if shard_data.time_stamp < cutoff_time {
                        shards_to_remove.push(*shard_index);
                    }
                }
            }

            // Remove old shards
            for shard_index in shards_to_remove {
                if let Err(e) = data_store.remove_shard(app_id, shard_index).await {
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

fn load_json_array() -> Vec<String> {
    let data = fs::read_to_string(PEERS_FILE).expect("Failed to read peers.json file");

    serde_json::from_str(&data).expect("Failed to parse peers.json as JSON array")
}

fn read_shards(app_id: u32) -> Result<Vec<String>, anyhow::Error> {
    let mut shards = Vec::new();
    for i in 0..*N {
        let path = format!("./conf/{}/node{}.keystore", app_id, i + 1);
        let keystore = KeyStore::from_file(&PathBuf::from(path))?;
        let entry = keystore
            .get_key_by_id(&app_id)
            .map_err(|e| anyhow::anyhow!("Failed to read keyentry: {}", e))?;
        let sk = entry.sk.ok_or(anyhow::anyhow!("Key not found"))?;
        let verifier = entry.verifier.ok_or(anyhow::anyhow!("Key not found"))?;
        shards.push(serde_json::to_string(&(sk, verifier))?);
    }
    Ok(shards)
}

fn convert_shards_to_key(shards: Vec<String>, k: u32) -> Result<SecretKey, anyhow::Error> {
    let mut shares = Vec::new();
    for shard in shards.iter().take(k as usize) {
        let parsed: Result<(PrivateKeyShare, Verifier), _> = serde_json::from_str(shard);
        shares.push(parsed?.0.get_share().clone());
    }

    let reconstructed = vsss_rs_std::combine_shares::<Scalar>(&shares)
        .map_err(|_| anyhow::anyhow!("combine_shares failed"))?;

    let scalar_bytes: [u8; 32] = reconstructed
        .to_bytes()
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Failed to convert scalar bytes to [u8; 32]"))?;

    Ok(ecies::SecretKey::parse(&scalar_bytes)
        .map_err(|_| anyhow::anyhow!("Failed to reconstruct ECIES SecretKey from scalar"))?)
}

fn delete_shards(app_id: u32) -> Result<(), anyhow::Error> {
    for i in 0..*N {
        let path = format!("./conf/{}/node{}.keystore", app_id, i + 1);
        let _ = fs::remove_file(path);
    }
    Ok(())
}

pub fn encrypt_private_key(
    private_key: &[u8],
    public_key: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), AppError> {
    let encrypted_private_key = ecies::encrypt(public_key, private_key).map_err(|e| {
        tracing::error!(error = %e, "Failed to encrypt private key");
        AppError::EncryptionError(e.to_string())
    })?;

    let key_size = ecies::config::get_ephemeral_key_size();
    let (ephemeral_pub_key, ciphertext) = encrypted_private_key.split_at(key_size);

    Ok((ephemeral_pub_key.to_vec(), ciphertext.to_vec()))
}
