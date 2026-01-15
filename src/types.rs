use alloy_primitives::{Address, Signature};
use dstack_sdk::dstack_client::GetQuoteResponse;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::DecryptionRequestListWithThreshold;

#[derive(Debug, Deserialize, Clone)]
pub struct EncryptRequest {
    #[serde(with = "serde_bytes")]
    pub plaintext: Vec<u8>,
    pub turbo_da_app_id: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptResponse {
    pub ciphertext: Vec<u8>,
    pub ciphertext_hash: Vec<u8>,
    pub plaintext_hash: Vec<u8>,
    pub signature_ciphertext_hash: Signature,
    pub signature_plaintext_hash: Signature,
    pub address: Address,
    pub ephemeral_pub_key: Vec<u8>,
}

#[derive(Serialize)]
pub struct QuoteResponse {
    pub quote: GetQuoteResponse,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DecryptRequest {
    pub turbo_da_app_id: Uuid,
    pub submission_id:Uuid,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DecryptRequestResponse {
    pub request_id: String,
    pub turbo_da_app_id: String,
    pub status: String,
    pub signers: Vec<String>,
    pub created_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct SubmitSignatureRequest {
    pub participant_address: String,
    pub signature: String,
}

#[derive(Serialize, Deserialize)]
pub struct SubmitSignatureResponse {
    pub request_id: String,
    pub status: String,
    pub signatures_submitted: usize,
    pub threshold: i64,
    pub ready_to_decrypt: bool,
    pub tee_attestion: Option<GetQuoteResponse>,
}

#[derive(Debug, Serialize)]
pub struct DecryptResponse {
    pub request_id: String,
    pub plaintext: Vec<u8>,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub turbo_da_app_id: String,
    pub participants: Vec<String>,
    pub threshold: i64,
}

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub turbo_da_app_id: String,
    pub participants_added: usize,
}

#[derive(Debug, Deserialize)]
pub struct AddParticipantRequest {
    pub turbo_da_app_id: String,
    pub participants: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct AddParticipantResponse {
    pub turbo_da_app_id: String,
    pub participants_added: usize,
}

#[derive(Debug, Deserialize)]
pub struct DeleteParticipantRequest {
    pub turbo_da_app_id: String,
    pub participants: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DeleteParticipantResponse {
    pub turbo_da_app_id: String,
    pub participants_deleted: usize,
}

#[derive(Debug, Deserialize)]
pub struct ListDecryptRequestsQuery {
    pub turbo_da_app_id: String,
    pub offset: Option<u32>,
    pub limit: Option<u32>,
}

#[derive(Serialize, Deserialize)]
pub struct ListDecryptRequestsResponse {
    pub items: Vec<DecryptionRequestListWithThreshold>,
    pub total: u32,
    pub offset: u32,
    pub limit: u32,
}

#[derive(Serialize, Deserialize)]
pub struct DecryptRequestItem {
    pub request_id: String,
    pub turbo_da_app_id: String,
    pub status: String,
    pub signatures_submitted: usize,
    pub threshold: i64,
    pub ready_to_decrypt: bool,
    pub created_at: i64,
}
