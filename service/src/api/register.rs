use crate::AppState;
use crate::error::AppError;
use crate::p2p::node::NodeCommand;
use crate::types::{RegisterRequest, RegisterResponse};
use axum::{Json, extract::State, response::IntoResponse};
use keygen::keygen;
use keys::keystore::KeyStore;
use libp2p::PeerId;
use std::{
    fs::File,
    io::{BufRead, BufReader},
    process::{Command, Stdio},
    time::Duration,
};
use tokio::time::sleep;

pub async fn register(
    State(state): State<AppState>,
    Json(request): Json<RegisterRequest>,
) -> Result<impl IntoResponse, AppError> {
    let request_span = tracing::info_span!("register_request", app_id = request.app_id);
    let _guard = request_span.enter();

    // Check if app_id is already registered
    match state.key_store.get_public_key(request.app_id) {
        Ok(existing_key) => {
            tracing::warn!(app_id = request.app_id, "App ID already registered");
            return Ok(Json(RegisterResponse {
                app_id: request.app_id,
                public_key: existing_key,
            }));
        }
        Err(AppError::KeyNotFound(_)) => {
            tracing::info!(
                app_id = request.app_id,
                "App ID not found, proceeding with registration"
            );
        }
        Err(e) => {
            tracing::error!(error = ?e, "Database error during public key lookup");
            return Err(e);
        }
    }

    println!("app id not found");

    tracing::debug!("Generating new keypair");
    let public_key = (keygen(
        request.k,
        request.n,
        "ECIESThreshold",
        "./conf",
        true,
        request.app_id,
    ))
    .map_err(|e| AppError::KeyGenerationError(e.to_string()))?;
    tracing::debug!("Generated keypair successfully");

    for (i, node) in request.nodes.iter().enumerate() {
        let filename = format!("./conf/node{}.keystore", i + 1);
        let path = std::path::PathBuf::from(&filename);
        let keystore = KeyStore::from_file(&path)?;

        let entry = keystore
            .get_key_by_id(&request.app_id)
            .map_err(|e| AppError::Other(format!("Failed to read keyentry: {}", e)))?;
        let sk = entry.sk.ok_or(AppError::KeyNotFound(request.app_id))?;
        let verifier = entry
            .verifier
            .ok_or(AppError::KeyNotFound(request.app_id))?;

        let peer_id = read_peer_id(&node.name)
            .map_err(|e| AppError::Other(format!("Failed to read peer_id: {}", e)))?;
        let command_sender = state.network_manager.lock().await.get_command_sender();

        command_sender
            .send(NodeCommand::SendShard {
                peer_id: peer_id.to_string(),
                app_id: request.app_id.to_string(),
                shard_index: (i + 1) as u32,
                shard: serde_json::to_string(&(sk, verifier))
                    .map_err(|e| AppError::Other(format!("Failed to send command: {}", e)))?, // send both as a tuple
            })
            .map_err(|e| AppError::Other(format!("Failed to send command: {}", e)))?;
    }
    sleep(Duration::from_secs(10)).await;

    // Try to store the keys in the TEE
    let mock_private_key = vec![0; 32];

    if let Err(e) = state
        .key_store
        .store_keys(request.app_id, &public_key, &mock_private_key)
    {
        tracing::error!(error = ?e, "Failed to store keys");
        return Err(e);
    }
    tracing::info!(app_id = request.app_id, "Successfully registered new app");

    Ok(Json(RegisterResponse {
        app_id: request.app_id,
        public_key: public_key,
    }))
}
fn read_peer_id(name: &str) -> anyhow::Result<PeerId> {
    let file = File::open(format!("peer_id_{}.txt", name))?;
    let reader = BufReader::new(file);
    let peer_id: String =
        String::from_utf8(reader.lines().next().unwrap().unwrap().as_bytes().to_vec())?;
    Ok(peer_id.parse()?)
}
