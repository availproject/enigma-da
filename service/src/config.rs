use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    pub server: ServerConfig,
    pub p2p: P2PConfig,
    pub worker: WorkerConfig,
    pub database: DatabaseConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2PConfig {
    pub port: u16,
    pub node_name: String,
    pub protocol_name: String,
    pub identify_protocol_version: String,
    pub number_of_p2p_network_nodes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerConfig {
    pub shard_request_interval_secs: u64,
    pub shard_request_retry_count: u32,
    pub shard_cleanup_interval_hours: u64,
    pub job_queue_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub path: String,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: env::var("SERVER_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
                port: env::var("SERVER_PORT")
                    .unwrap_or_else(|_| "3000".to_string())
                    .parse()
                    .unwrap_or_else(|_| {
                        tracing::warn!("Invalid SERVER_PORT, using default 3000");
                        3000
                    }),
            },
            p2p: P2PConfig {
                port: env::var("P2P_PORT")
                    .unwrap_or_else(|_| "3001".to_string())
                    .parse()
                    .unwrap_or_else(|_| {
                        tracing::warn!("Invalid P2P_PORT, using default 3001");
                        3001
                    }),
                node_name: env::var("P2P_NODE_NAME")
                    .unwrap_or_else(|_| "encryption-service-node".to_string()),
                protocol_name: env::var("P2P_PROTOCOL_NAME")
                    .unwrap_or_else(|_| "/enigma-kms-p2p/message/1.0.0".to_string()),
                identify_protocol_version: env::var("P2P_IDENTIFY_PROTOCOL_VERSION")
                    .unwrap_or_else(|_| "/enigma-encrypted-network/1.0.0".to_string()),
                number_of_p2p_network_nodes: env::var("NUMBER_OF_P2P_NETWORK_NODES")
                    .unwrap_or_else(|_| "3".to_string())
                    .parse()
                    .unwrap_or_else(|_| {
                        tracing::warn!("Invalid NUMBER_OF_P2P_NETWORK_NODES, using default 3");
                        3
                    }),
            },
            worker: WorkerConfig {
                shard_request_interval_secs: env::var("SHARD_REQUEST_INTERVAL_SECS")
                    .unwrap_or_else(|_| "5".to_string())
                    .parse()
                    .unwrap_or_else(|_| {
                        tracing::warn!("Invalid SHARD_REQUEST_INTERVAL_SECS, using default 5");
                        5
                    }),
                shard_request_retry_count: env::var("SHARD_REQUEST_RETRY_COUNT")
                    .unwrap_or_else(|_| "5".to_string())
                    .parse()
                    .unwrap_or_else(|_| {
                        tracing::warn!("Invalid SHARD_REQUEST_RETRY_COUNT, using default 5");
                        5
                    }),
                shard_cleanup_interval_hours: env::var("SHARD_CLEANUP_INTERVAL_HOURS")
                    .unwrap_or_else(|_| "6".to_string())
                    .parse()
                    .unwrap_or_else(|_| {
                        tracing::warn!("Invalid SHARD_CLEANUP_INTERVAL_HOURS, using default 6");
                        6
                    }),
                job_queue_size: env::var("JOB_QUEUE_SIZE")
                    .unwrap_or_else(|_| "1000".to_string())
                    .parse()
                    .unwrap_or_else(|_| {
                        tracing::warn!("Invalid JOB_QUEUE_SIZE, using default 1000");
                        1000
                    }),
            },
            database: DatabaseConfig {
                path: env::var("DATABASE_PATH").unwrap_or_else(|_| "keystore_db".to_string()),
            },
        }
    }
}

impl ServiceConfig {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let config: ServiceConfig = serde_json::from_str(&content)?;
        Ok(config)
    }

    pub fn from_env() -> Self {
        Self::default()
    }

    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        // Try to load from config file first, fallback to environment variables
        if let Ok(config) = Self::from_file("config.json") {
            Ok(config)
        } else {
            Ok(Self::from_env())
        }
    }
}
