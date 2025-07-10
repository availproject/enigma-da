use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

lazy_static! {
    static ref P2P_PROTOCOL_NAME: String = {
        std::env::var("P2P_PROTOCOL_NAME")
            .unwrap_or_else(|_| "/enigma-kms-p2p/message/1.0.0".to_string())
    };
    static ref P2P_IDENTIFY_PROTOCOL_VERSION: String = {
        std::env::var("P2P_IDENTIFY_PROTOCOL_VERSION")
            .unwrap_or_else(|_| "/enigma-encrypted-network/1.0.0".to_string())
    };
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendShards {
    pub app_id: String,
    pub shard: String,
    pub shard_index: u32,
    pub job_id: uuid::Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestShard {
    pub app_id: String,
    pub job_id: uuid::Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageRequest {
    SendShard(SendShards),
    RequestShard(RequestShard),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageResponse {
    pub shard: Option<Vec<u8>>,
    pub app_id: String,
    pub job_id: uuid::Uuid,
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Clone, Default)]
pub struct MessageProtocol;

pub fn get_p2p_identifier() -> &'static str {
    &P2P_IDENTIFY_PROTOCOL_VERSION
}

impl AsRef<str> for MessageProtocol {
    fn as_ref(&self) -> &str {
        &P2P_PROTOCOL_NAME
    }
}
