use alloy_primitives::{Address, Signature};
use dstack_sdk::dstack_client::GetQuoteResponse;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Deserialize, Clone)]
pub struct EncryptRequest {
    pub app_id: u32,
    #[serde(with = "serde_bytes")]
    pub plaintext: Vec<u8>,
    pub turbo_da_app_id: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptResponse {
    pub ciphertext: Vec<u8>,
    pub signature: Signature,
    pub address: Address,
    pub ephemeral_pub_key: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub struct PrivateKeyRequest {
    pub app_id: u32,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PrivateKeyResponse {
    pub ephemeral_pub_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[derive(Serialize)]
pub struct QuoteResponse {
    pub quote: GetQuoteResponse,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RegisterRequest {
    pub app_id: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub app_id: u32,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DecryptRequest {
    pub app_id: u32,
    pub ciphertext: Vec<u8>,
    pub ephemeral_pub_key: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DecryptResponse {
    pub plaintext: Vec<u8>,
}
