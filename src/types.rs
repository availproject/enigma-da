use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct EncryptRequest {
    pub app_id: u32,
    pub plaintext: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct EncryptResponse {
    pub ciphertext: Vec<u8>,
    pub signature: String,
    pub ephemeral_pub_key: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct QuoteResponse {
    pub signed_quote: Vec<u8>,
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