use serde::{Deserialize, Serialize};
use dstack_sdk::dstack_client::GetQuoteResponse;
use alloy_primitives::{Address, Signature};

#[derive(Debug, Deserialize)]
pub struct EncryptRequest {
    pub app_id: u32,
    #[serde(with = "serde_bytes")]
    pub plaintext: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct EncryptResponse {
    pub ciphertext: Vec<u8>,
    pub signature: Signature,
    pub address: Address,
    pub ephemeral_pub_key: Vec<u8>,
}

#[derive(Serialize)]
pub struct QuoteResponse {
    pub quote: GetQuoteResponse,
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub app_id: u32,
}

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub app_id: u32,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub struct DecryptRequest {
    pub app_id: u32,
    pub ciphertext: Vec<u8>,
    pub ephemeral_pub_key: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct DecryptResponse {
    pub plaintext: Vec<u8>,
}