use serde::{Deserialize, Serialize};

// Key prefixes for different data types
pub const SHARD_PREFIX: &str = "shard:";
pub const PEER_ID_PREFIX: &str = "peer:";
pub const PUBLIC_KEY_PREFIX: &str = "pub:";
pub const DECRYPT_REQUEST_PREFIX: &str = "decrypt_request:";
pub const REGISTER_APP_REQUEST_PREFIX: &str = "register_app_request:";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardData {
    pub app_id: String,
    pub shard_index: u32,
    pub shard: String,
    pub time_stamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerIdData {
    pub app_id: String,
    pub peer_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RequestStatus {
    Pending,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptRequestData {
    pub app_id: String,
    pub ciphertext_array: Vec<Vec<u8>>,
    pub ephemeral_pub_key_array: Vec<Vec<u8>>,
    pub decrypted_array: Option<Vec<Vec<u8>>>,
    pub job_id: uuid::Uuid,
    pub status: RequestStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterAppRequestData {
    pub app_id: String,
    pub job_id: uuid::Uuid,
    pub status: RequestStatus,
    pub public_key: Option<Vec<u8>>,
}
