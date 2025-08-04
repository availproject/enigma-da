use std::{collections::HashMap, time::Duration};

use crate::{
    p2p::{
        store::ShardStore,
        types::{MessageProtocol, MessageRequest, MessageResponse},
    },
    tee::verify_attestation_from_quote,
};
use dstack_sdk::dstack_client::GetQuoteResponse;
#[allow(unused_imports)]
use keys::keys::{PrivateKeyShare, Verifier};
use libp2p::futures::StreamExt;
use libp2p::swarm::Config;
use libp2p::{Multiaddr, Transport};
use libp2p::{
    PeerId, Swarm, mdns, noise,
    request_response::{self, OutboundRequestId, ProtocolSupport},
    swarm::NetworkBehaviour,
    swarm::SwarmEvent,
    tcp, yamux,
};
use log::{info, warn};
use std::fs;
use std::path::Path;

/// Load existing keypair from file or generate new one and save it
fn load_or_generate_keypair(node_key_path: &str) -> anyhow::Result<libp2p::identity::Keypair> {
    let key_file = node_key_path;

    if Path::new(&key_file).exists() {
        // Load existing keypair
        let key_bytes = fs::read(key_file)?;
        let keypair = libp2p::identity::Keypair::from_protobuf_encoding(&key_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to decode keypair: {}", e))?;
        info!("Loaded existing keypair for node: {}", node_key_path);
        Ok(keypair)
    } else {
        // Generate new keypair and save it
        let keypair = libp2p::identity::Keypair::generate_ed25519();
        let key_bytes = keypair
            .to_protobuf_encoding()
            .map_err(|e| anyhow::anyhow!("Failed to encode keypair: {}", e))?;
        fs::write(key_file, key_bytes)?;
        info!(
            "Generated and saved new keypair for node: {}",
            node_key_path
        );
        Ok(keypair)
    }
}

#[derive(NetworkBehaviour)]
pub struct P2PBehaviour {
    pub mdns: mdns::tokio::Behaviour,
    pub request_response: request_response::Behaviour<MessageProtocol>,
}

pub struct NetworkNode {
    swarm: Swarm<P2PBehaviour>,
    pending_requests: HashMap<OutboundRequestId, MessageRequest>,
    shard_store: ShardStore,
    pub node_name: String,
    pub local_peer_id: String,
    shutdown_signal: Option<tokio::sync::oneshot::Sender<()>>,
}

impl NetworkNode {
    pub async fn new(port: u16, node_name: String) -> anyhow::Result<Self> {
        Self::new_with_shard_store(port, node_name, None).await
    }

    #[cfg(test)]
    pub async fn new_with_suffix(
        port: u16,
        node_name: String,
        suffix: String,
    ) -> anyhow::Result<Self> {
        Self::new_with_shard_store(port, node_name, Some(suffix)).await
    }

    async fn new_with_shard_store(
        port: u16,
        node_name: String,
        suffix: Option<String>,
    ) -> anyhow::Result<Self> {
        // Generate identity
        let node_key_path = std::env::var("P2P_NODE_KEY_PATH")
            .unwrap_or_else(|_| format!("node_key_{}.bin", node_name));
        let local_key = load_or_generate_keypair(&node_key_path)?;
        let local_peer_id = PeerId::from(local_key.public());
        info!("Local peer id: {local_peer_id}");

        // Create transport with encryption
        let transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
            .upgrade(libp2p::core::upgrade::Version::V1)
            .authenticate(noise::Config::new(&local_key)?)
            .multiplex(yamux::Config::default())
            .boxed();

        // Create request-response behaviour
        let request_response = request_response::Behaviour::new(
            std::iter::once((MessageProtocol, ProtocolSupport::Full)),
            request_response::Config::default().with_request_timeout(Duration::from_secs(60)),
        );

        // Create mDNS behaviour
        let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)?;

        // Create network behaviour
        let behaviour = P2PBehaviour {
            mdns,
            request_response,
        };

        // Create swarm
        let mut swarm = Swarm::new(
            transport,
            behaviour,
            local_peer_id,
            Config::with_tokio_executor()
                .with_idle_connection_timeout(Duration::from_secs(60 * 60 * 24 * 30)), // 30 days
        );

        // Listen on all interfaces
        let listen_addr = format!("/ip4/0.0.0.0/tcp/{}", port);
        swarm.listen_on(listen_addr.parse()?)?;

        let shard_store = match suffix {
            #[cfg(test)]
            Some(suffix) => ShardStore::new_with_suffix(&node_name, &suffix)?,
            #[cfg(not(test))]
            Some(_) => ShardStore::new(&node_name)?,
            None => ShardStore::new(&node_name)?,
        };

        Ok(NetworkNode {
            swarm,
            pending_requests: HashMap::new(),
            shard_store,
            node_name,
            local_peer_id: local_peer_id.to_string(),
            shutdown_signal: None,
        })
    }

    pub async fn connect_to_peer(&mut self, addr: &str) -> anyhow::Result<()> {
        info!("[{}] 🔗 Attempting to connect to: {}", self.node_name, addr);
        let addr: Multiaddr = addr.parse()?;

        // Just initiate the dial - the connection will be established asynchronously
        self.swarm.dial(addr)?;
        info!("[{}] ✅ Dial request initiated", self.node_name);

        Ok(())
    }

    fn store_shard(&mut self, app_id: String, shard_index: u32, shard: String) {
        if !self.verify_shard(&app_id, shard_index, &shard) {
            warn!(
                "[{}] ❌ Shard verification failed — not storing. app_id: {}, shard_index: {}",
                self.node_name, app_id, shard_index
            );
        } else {
            match app_id.parse::<u32>() {
                Ok(app_id_u32) => {
                    if let Err(e) = self.shard_store.add_shard(app_id_u32, shard_index, shard) {
                        warn!(
                            "[{}] ❌ Failed to store shard for app_id: {}, shard_index: {}: {}",
                            self.node_name, app_id, shard_index, e
                        );
                    } else {
                        info!(
                            "[{}] 💾 Stored verified shard for app_id: {}, shard_index: {}",
                            self.node_name, app_id, shard_index
                        );
                    }
                }
                Err(_) => {
                    warn!("[{}] ❌ Invalid app_id format: {}", self.node_name, app_id);
                }
            }
        }
    }

    #[cfg(not(test))]
    pub fn verify_shard(&mut self, app_id: &str, shard_index: u32, shard: &str) -> bool {
        info!(
            "[{}] 🔍 Called verify_shard for app_id={}, index={}",
            self.node_name, app_id, shard_index
        );

        let parsed: Result<(PrivateKeyShare, Verifier), _> = serde_json::from_str(shard);

        if let Ok((sk, verifier)) = parsed {
            let share = sk.get_share();
            let blind_share = verifier.get_blind_shares();
            let vset = verifier.get_verifier_set();
            vset.verify(share, blind_share).is_ok()
        } else {
            false
        }
    }

    #[cfg(test)]
    pub fn verify_shard(&mut self, _app_id: &str, _shard_index: u32, _shard: &str) -> bool {
        true
    }

    fn get_shard(&self, app_id: &str) -> Option<HashMap<u32, String>> {
        match app_id.parse::<u32>() {
            Ok(app_id_u32) => match self.shard_store.get_all_shards_for_app(app_id_u32) {
                Ok(shards) => Some(shards),
                Err(e) => {
                    warn!(
                        "[{}] ❌ Failed to get shards for app_id {}: {}",
                        self.node_name, app_id, e
                    );
                    None
                }
            },
            Err(_) => {
                warn!("[{}] ❌ Invalid app_id format: {}", self.node_name, app_id);
                None
            }
        }
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
        self.shutdown_signal = Some(shutdown_tx);

        let mut ctrl_c = Box::pin(tokio::signal::ctrl_c());

        info!("Node running");

        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => {
                    match event {
                        SwarmEvent::Behaviour(event) => {
                            self.handle_behaviour_event(event).await?;
                        }
                        SwarmEvent::NewListenAddr { address, .. } => {
                            info!("Listening on {}", address);
                        }
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            info!("Connected to {}", peer_id);
                        }
                        SwarmEvent::ConnectionClosed { peer_id, .. } => {
                            info!("Disconnected from {}", peer_id);
                        }
                        _ => {}
                    }
                }
                _ = &mut shutdown_rx => {
                    info!("Shutdown signal received, stopping node");
                    break;
                }
                _ = &mut ctrl_c => {
                    info!("Ctrl+C received, shutting down node gracefully");
                    break;
                }
            }
        }
        Ok(())
    }

    pub fn shutdown(&mut self) {
        if let Some(signal) = self.shutdown_signal.take() {
            let _ = signal.send(());
        }
    }

    async fn handle_behaviour_event(&mut self, event: P2PBehaviourEvent) -> anyhow::Result<()> {
        match event {
            P2PBehaviourEvent::RequestResponse(request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
            }) => {
                warn!(
                    "[{}] ❌ Outbound request failed: peer: {}, request_id: {:?}, error: {:?}",
                    self.node_name, peer, request_id, error
                );
                // Remove the failed request from pending_requests
                if let Some(original_request) = self.pending_requests.remove(&request_id) {
                    warn!(
                        "[{}] ❌ Failed request was: {:?}",
                        self.node_name, original_request
                    );
                }
            }
            P2PBehaviourEvent::RequestResponse(request_response::Event::ResponseSent {
                peer,
                request_id,
            }) => {
                info!(
                    "[{}] ✅ Response sent successfully to peer: {}, request_id: {:?}",
                    self.node_name, peer, request_id
                );
            }
            P2PBehaviourEvent::RequestResponse(request_response::Event::Message {
                message,
                ..
            }) => {
                match message {
                    request_response::Message::Request {
                        request, channel, ..
                    } => {
                        match request {
                            MessageRequest::SendShard(send_shard) => {
                                info!(
                                    "[{}] 📨 Received shard for app_id: {}, shard_index: {}, shard: {}",
                                    self.node_name,
                                    send_shard.app_id,
                                    send_shard.shard_index,
                                    send_shard.shard
                                );
                                let quote =
                                    bincode::deserialize::<GetQuoteResponse>(&send_shard.quote)?;
                                verify_attestation_from_quote(quote).await?;

                                // Store the received shard
                                self.store_shard(
                                    send_shard.app_id.clone(),
                                    send_shard.shard_index,
                                    send_shard.shard.clone(),
                                );

                                let response = MessageResponse {
                                    shard: None,
                                    app_id: send_shard.app_id,
                                    job_id: send_shard.job_id,
                                    success: true,
                                    message: "Shard received and stored successfully".to_string(),
                                };

                                if let Err(e) = self
                                    .swarm
                                    .behaviour_mut()
                                    .request_response
                                    .send_response(channel, response)
                                {
                                    warn!("Failed to send response: {:?}", e);
                                }
                            }
                            MessageRequest::RequestShard(request_shard) => {
                                info!(
                                    "[{}] 📥 Shard requested for app_id: {}",
                                    self.node_name, request_shard.app_id
                                );

                                let shard = self.get_shard(&request_shard.app_id);
                                let response = if let Some(shard_data) = shard {
                                    match bincode::serialize(&shard_data) {
                                        Ok(serialized_shard) => MessageResponse {
                                            shard: Some(serialized_shard),
                                            app_id: request_shard.app_id,
                                            job_id: request_shard.job_id,
                                            success: true,
                                            message: "Shard found and returned".to_string(),
                                        },
                                        Err(e) => {
                                            warn!(
                                                "[{}] ❌ Failed to serialize shard: {:?}",
                                                self.node_name, e
                                            );
                                            MessageResponse {
                                                shard: None,
                                                app_id: request_shard.app_id,
                                                job_id: request_shard.job_id,
                                                success: false,
                                                message: format!(
                                                    "Failed to serialize shard: {}",
                                                    e
                                                ),
                                            }
                                        }
                                    }
                                } else {
                                    MessageResponse {
                                        shard: None,
                                        app_id: request_shard.app_id,
                                        job_id: request_shard.job_id,
                                        success: false,
                                        message: "Shard not found".to_string(),
                                    }
                                };

                                if let Err(e) = self
                                    .swarm
                                    .behaviour_mut()
                                    .request_response
                                    .send_response(channel, response)
                                {
                                    warn!("Failed to send response: {:?}", e);
                                }
                            }
                        }
                    }
                    request_response::Message::Response {
                        response,
                        request_id,
                        ..
                    } => {
                        info!(
                            "[{}] 🔍 Received response for request_id: {:?}",
                            self.node_name, request_id
                        );
                        if let Some(original_request) = self.pending_requests.remove(&request_id) {
                            if response.success {
                                if let Some(shard) = &response.shard {
                                    info!(
                                        "[{}] ✅ Shard received: {:?} (Request: {:?})",
                                        self.node_name,
                                        String::from_utf8_lossy(shard),
                                        original_request
                                    );
                                    // Try to deserialize and store the received shard
                                    match bincode::deserialize::<HashMap<u32, String>>(shard) {
                                        Ok(shard_data) => {
                                            // Store each shard in the received data
                                            for (shard_index, shard_content) in shard_data {
                                                self.store_shard(
                                                    response.app_id.clone(),
                                                    shard_index,
                                                    shard_content,
                                                );
                                            }
                                        }
                                        Err(e) => {
                                            warn!(
                                                "[{}] ❌ Failed to deserialize shard: {:?}",
                                                self.node_name, e
                                            );
                                        }
                                    }
                                } else {
                                    info!(
                                        "[{}] ✅ Response: {} (Request: {:?})",
                                        self.node_name, response.message, original_request
                                    );
                                }
                            } else {
                                info!(
                                    "[{}] ❌ Request failed: {} (Request: {:?})",
                                    self.node_name, response.message, original_request
                                );
                            }
                        } else {
                            warn!(
                                "[{}] ❌ No pending request found for request_id: {:?}",
                                self.node_name, request_id
                            );
                        }
                    }
                }
            }
            _ => {
                info!("Received unknown event: {:?}", event);
            }
        }
        Ok(())
    }

    pub fn local_peer_id(&self) -> &str {
        &self.local_peer_id
    }
}

// Test-specific extensions
// Incudes a NodeCommand enum for sending commands to the node.
// This is used to test the node in a multi-threaded environment.
// The commands are sent to the node via a channel.
// The node processes the commands in its event loop alongside libp2p events.
#[cfg(test)]
pub mod test_ext {
    use super::*;
    use tokio::sync::mpsc;

    #[derive(Debug)]
    pub enum NodeCommand {
        SendShard {
            peer_id: String,
            app_id: String,
            shard_index: u32,
            shard: String,
        },
        RequestShard {
            peer_id: String,
            app_id: String,
        },
        StoreShard {
            app_id: String,
            shard_index: u32,
            shard: String,
        },
        GetShard {
            app_id: String,
        },
        Shutdown,
    }

    pub struct TestableNetworkNode {
        inner: NetworkNode,
        command_receiver: mpsc::UnboundedReceiver<NodeCommand>,
        command_sender: mpsc::UnboundedSender<NodeCommand>,
    }

    impl TestableNetworkNode {
        pub async fn new(port: u16, node_name: String) -> anyhow::Result<Self> {
            // Generate a unique suffix for test isolation
            let suffix = format!(
                "test_{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|e| anyhow::anyhow!("Failed to get system time: {}", e))?
                    .as_nanos()
            );
            let inner = NetworkNode::new_with_suffix(port, node_name, suffix).await?;
            let (command_sender, command_receiver) = mpsc::unbounded_channel();

            Ok(TestableNetworkNode {
                inner,
                command_receiver,
                command_sender,
            })
        }

        pub fn get_command_sender(&self) -> mpsc::UnboundedSender<NodeCommand> {
            self.command_sender.clone()
        }

        async fn process_send_shard(
            &mut self,
            peer_id: &str,
            app_id: String,
            shard_index: u32,
            shard: String,
        ) -> anyhow::Result<()> {
            println!(
                "[{}] 🔧 send_shard method called with peer_id: {}, app_id: {}, shard_index: {}",
                self.inner.node_name, peer_id, app_id, shard_index
            );
            let peer_id: PeerId = peer_id.parse()?;
            let send_shard = MessageRequest::SendShard(crate::p2p::types::SendShards {
                app_id,
                shard_index,
                shard,
                job_id: uuid::Uuid::new_v4(),
                quote: bincode::serialize(&GetQuoteResponse {
                    quote: "".to_string(),
                    event_log: "".to_string(),
                })?, // This function is available only in the test environment. So here we just pass an empty vector.
            });

            let request_id = self
                .inner
                .swarm
                .behaviour_mut()
                .request_response
                .send_request(&peer_id, send_shard.clone());
            println!(
                "[{}] >>> request_id >>>: {:?}",
                self.inner.node_name, request_id
            );
            self.inner.pending_requests.insert(request_id, send_shard);
            println!(
                "[{}] ✅ send_shard method completed successfully",
                self.inner.node_name
            );
            Ok(())
        }

        async fn process_request_shard(
            &mut self,
            peer_id: &str,
            app_id: String,
        ) -> anyhow::Result<()> {
            println!(
                "[{}] 🔧 request_shard method called with peer_id: {}, app_id: {}",
                self.inner.node_name, peer_id, app_id
            );
            let peer_id: PeerId = peer_id.parse()?;
            let request_shard = MessageRequest::RequestShard(crate::p2p::types::RequestShard {
                app_id,
                job_id: uuid::Uuid::new_v4(),
            });

            let request_id = self
                .inner
                .swarm
                .behaviour_mut()
                .request_response
                .send_request(&peer_id, request_shard.clone());

            println!(
                "[{}] 🔧 Request sent with request_id: {:?}",
                self.inner.node_name, request_id
            );
            self.inner
                .pending_requests
                .insert(request_id, request_shard);
            println!(
                "[{}] ✅ request_shard method completed successfully",
                self.inner.node_name
            );
            Ok(())
        }

        async fn process_get_shard(
            &mut self,
            app_id: &str,
        ) -> anyhow::Result<Option<HashMap<u32, String>>> {
            println!(
                "[{}] 🔧 get_shard method called with app_id: {}",
                self.inner.node_name, app_id
            );
            let shard = self.inner.get_shard(app_id);
            println!(
                "[{}] ✅ get_shard method completed successfully, shard: {:?}",
                self.inner.node_name, shard
            );
            Ok(shard)
        }

        pub async fn run(&mut self) -> anyhow::Result<()> {
            let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
            self.inner.shutdown_signal = Some(shutdown_tx);

            let mut ctrl_c = Box::pin(tokio::signal::ctrl_c());

            loop {
                tokio::select! {
                    event = self.inner.swarm.select_next_some() => {
                        match event {
                            SwarmEvent::Behaviour(event) => {
                                self.inner.handle_behaviour_event(event).await?;
                            }
                            SwarmEvent::NewListenAddr { address, .. } => {
                                info!("Listening on {}", address);
                            }
                            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                                info!("Connected to {}", peer_id);
                            }
                            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                                info!("Disconnected from {}", peer_id);
                            }
                            _ => {}
                        }
                    }
                    command = self.command_receiver.recv() => {
                        match command {
                            Some(NodeCommand::SendShard { peer_id, app_id, shard_index, shard }) => {
                                info!("[{}] 🔧 Processing SendShard command", self.inner.node_name);
                                self.process_send_shard(&peer_id, app_id, shard_index, shard).await?;
                            }
                            Some(NodeCommand::RequestShard { peer_id, app_id }) => {
                                info!("[{}] 🔧 Processing RequestShard command", self.inner.node_name);
                                self.process_request_shard(&peer_id, app_id).await?;
                            }
                            Some(NodeCommand::StoreShard { app_id, shard_index, shard }) => {
                                info!("[{}] 🔧 Processing StoreShard command", self.inner.node_name);
                                self.inner.store_shard(app_id, shard_index, shard);
                            }
                            Some(NodeCommand::GetShard { app_id }) => {
                                info!("[{}] 🔧 Processing GetShard command", self.inner.node_name);
                                self.process_get_shard(&app_id).await?;
                            }
                            Some(NodeCommand::Shutdown) => {
                                info!("[{}] 🛑 Shutdown command received", self.inner.node_name);
                                break;
                            }
                            None => {
                                warn!("[{}] ❌ Command channel closed", self.inner.node_name);
                                break;
                            }
                        }
                    }
                    _ = &mut shutdown_rx => {
                        info!("Shutdown signal received, stopping node");
                        break;
                    }
                    _ = &mut ctrl_c => {
                        info!("Ctrl+C received, shutting down node gracefully");
                        break;
                    }
                }
            }
            Ok(())
        }

        pub fn shutdown(&mut self) {
            self.inner.shutdown();
        }

        pub async fn connect_to_peer(&mut self, addr: &str) -> anyhow::Result<()> {
            self.inner.connect_to_peer(addr).await
        }

        pub fn local_peer_id(&self) -> &str {
            &self.inner.local_peer_id
        }
    }
}
