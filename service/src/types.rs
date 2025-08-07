use alloy_primitives::{Address, Signature};
use dstack_sdk::tappd_client::TdxQuoteResponse;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::types::{DecryptRequestData, ReencryptRequestData, RegisterAppRequestData};

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

#[derive(Debug, Deserialize, Clone)]
pub struct PrivateKeyRequest {
    pub app_id: u32,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PrivateKeyResponse {
    pub job_id: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct GetReencryptRequestStatusRequest {
    pub job_id: Uuid,
}

#[derive(Debug, Serialize)]
pub struct GetReencryptRequestStatusResponse {
    pub request: ReencryptRequestData,
}

#[derive(Serialize)]
pub struct QuoteResponse {
    pub quote: TdxQuoteResponse,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RegisterAppRequest {
    pub app_id: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub app_id: u32,
    pub job_id: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct GetRegisterAppRequestStatusRequest {
    pub job_id: Uuid,
}

#[derive(Debug, Serialize)]
pub struct GetRegisterAppRequestStatusResponse {
    pub request: RegisterAppRequestData,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DecryptRequest {
    pub app_id: u32,
    pub turbo_da_app_id: Uuid,
    pub ciphertext: Vec<Vec<u8>>,
    pub ephemeral_pub_key: Vec<Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DecryptResponse {
    pub job_id: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct GetDecryptRequestStatusRequest {
    pub job_id: Uuid,
}

#[derive(Debug, Serialize)]
pub struct GetDecryptRequestStatusResponse {
    pub request: DecryptRequestData,
}
