use crate::p2p::node::{NetworkNode, NodeCommand};
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};
use tracing::{error, info, warn};
use uuid::Uuid;

pub struct NetworkManager {
    node_handle: Option<tokio::task::JoinHandle<anyhow::Result<()>>>,
    command_sender: mpsc::UnboundedSender<NodeCommand>,
    shutdown_sender: Option<tokio::sync::oneshot::Sender<()>>,
}

impl NetworkManager {
    pub async fn new(port: u16, node_name: String) -> anyhow::Result<Arc<Mutex<Self>>> {
        info!("Initializing network manager for node: {}", node_name);

        // Create the network node
        let mut network_node = NetworkNode::new(port, node_name.clone()).await?;
        let command_sender = network_node.get_command_sender();

        // Create shutdown channel
        let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();

        // Spawn the network node in a separate thread
        let node_handle = tokio::spawn(async move {
            info!("Starting network node: {}", node_name);

            // Run the node with shutdown signal
            let result = tokio::select! {
                result = network_node.run() => result,
                _ = shutdown_receiver => {
                    info!("Network node shutdown signal received");
                    network_node.shutdown();
                    Ok(())
                }
            };

            info!("Network node stopped: {}", node_name);
            result
        });

        Ok(Arc::new(Mutex::new(NetworkManager {
            node_handle: Some(node_handle),
            command_sender,
            shutdown_sender: Some(shutdown_sender),
        })))
    }

    pub fn get_command_sender(&self) -> mpsc::UnboundedSender<NodeCommand> {
        self.command_sender.clone()
    }

    pub async fn shutdown(&mut self) -> anyhow::Result<()> {
        info!("Shutting down network manager...");

        // Send shutdown signal to the node
        if let Some(sender) = self.shutdown_sender.take() {
            if let Err(e) = sender.send(()) {
                warn!("Failed to send shutdown signal: {:?}", e);
            }
        }

        // Wait for the node to finish
        if let Some(handle) = self.node_handle.take() {
            match handle.await {
                Ok(result) => match result {
                    Ok(_) => info!("Network node shutdown successfully"),
                    Err(e) => {
                        error!("Network node shutdown with error: {:?}", e);
                        return Err(e);
                    }
                },
                Err(e) => {
                    error!("Failed to join network node thread: {:?}", e);
                    return Err(anyhow::anyhow!(
                        "Failed to join network node thread: {:?}",
                        e
                    ));
                }
            }
        }

        info!("Network manager shutdown complete");
        Ok(())
    }

    pub async fn send_command(&self, command: NodeCommand) -> anyhow::Result<()> {
        self.command_sender
            .send(command)
            .map_err(|e| anyhow::anyhow!("Failed to send command to network node: {}", e))
    }

    pub async fn get_request_status(&self, job_id: Uuid) -> Option<(usize, usize)> {
        let (response_sender, response_receiver) = tokio::sync::oneshot::channel();

        let command = NodeCommand::GetRequestStatus {
            job_id,
            response_sender,
        };

        // Send the command
        if let Err(e) = self.command_sender.send(command) {
            error!("Failed to send GetRequestStatus command: {:?}", e);
            return None;
        }

        // Wait for the response
        match response_receiver.await {
            Ok(status) => status,
            Err(e) => {
                error!("Failed to receive status response: {:?}", e);
                None
            }
        }
    }

    pub async fn get_shard(&self, app_id: u32) -> Result<std::collections::HashMap<u32, crate::db::types::ShardData>, anyhow::Error> {
        let (response_sender, response_receiver) = tokio::sync::oneshot::channel();

        let command = NodeCommand::GetShard {
            app_id: app_id.to_string(),
            response_sender,
        };

        // Send the command
        if let Err(e) = self.command_sender.send(command) {
            return Err(anyhow::anyhow!("Failed to send GetShard command: {}", e));
        }

        // Wait for the response
        match response_receiver.await {
            Ok(shards) => Ok(shards),
            Err(e) => {
                error!("Failed to receive shard response: {:?}", e);
                Err(anyhow::anyhow!("Failed to receive shard response: {:?}", e))
            }
        }
    }
}

impl Drop for NetworkManager {
    fn drop(&mut self) {
        if self.shutdown_sender.is_some() || self.node_handle.is_some() {
            warn!("NetworkManager dropped without proper shutdown");
        }
    }
}
