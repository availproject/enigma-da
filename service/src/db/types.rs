use serde::{Deserialize, Serialize};

// Key prefixes for different data types
pub const SHARD_PREFIX: &str = "shard:";
pub const PEER_ID_PREFIX: &str = "peer:";
pub const PUBLIC_KEY_PREFIX: &str = "pub:";
pub const DECRYPT_REQUEST_PREFIX: &str = "decrypt_request:";

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
pub enum DecryptRequestStatus {
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
    pub status: DecryptRequestStatus,
}
