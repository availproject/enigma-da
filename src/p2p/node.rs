use std::{collections::HashMap, time::Duration};

use crate::p2p::types::{get_p2p_identifier, MessageProtocol, MessageRequest, MessageResponse};
use libp2p::futures::StreamExt;
use libp2p::swarm::Config;
use libp2p::{
    gossipsub, identify, kad, mdns, noise,
    request_response::{self, OutboundRequestId, ProtocolSupport},
    swarm::NetworkBehaviour,
    swarm::SwarmEvent,
    tcp, yamux, PeerId, Swarm,
};
use libp2p::{ping, Multiaddr, Transport};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

#[derive(NetworkBehaviour)]
pub struct P2PBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
    pub request_response: request_response::Behaviour<MessageProtocol>,
    pub identify: identify::Behaviour,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub ping: ping::Behaviour,
}

pub struct NetworkNode {
    swarm: Swarm<P2PBehaviour>,
    pending_requests: HashMap<OutboundRequestId, MessageRequest>,
    shard_storage: HashMap<String, HashMap<u32, String>>, // app_id -> shard_index -> shard
    pub node_name: String,
    pub local_peer_id: String,
    shutdown_signal: Option<tokio::sync::oneshot::Sender<()>>,
    pub command_receiver: mpsc::UnboundedReceiver<NodeCommand>,
    pub command_sender: mpsc::UnboundedSender<NodeCommand>,
}

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

impl NetworkNode {
    pub async fn new(port: u16, node_name: String) -> anyhow::Result<Self> {
        // Generate identity
        let local_key = libp2p::identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());
        info!("Local peer id: {local_peer_id}");

        // Create transport with encryption
        let transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
            .upgrade(libp2p::core::upgrade::Version::V1)
            .authenticate(noise::Config::new(&local_key)?)
            .multiplex(yamux::Config::default())
            .boxed();

        // Create Kademlia behaviour
        let store = kad::store::MemoryStore::new(local_peer_id);
        let kademlia = kad::Behaviour::new(local_peer_id, store);

        // Create request-response behaviour
        let request_response = request_response::Behaviour::new(
            std::iter::once((MessageProtocol, ProtocolSupport::Full)),
            request_response::Config::default().with_request_timeout(Duration::from_secs(60)),
        );

        // Create Gossipsub behaviour
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_secs(10))
            .validation_mode(gossipsub::ValidationMode::Strict)
            .build()
            .map_err(|msg| anyhow::anyhow!("Gossipsub config error: {}", msg))?;

        #[allow(unused_mut)]
        let mut gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(local_key.clone()),
            gossipsub_config,
        )
        .map_err(|msg| anyhow::anyhow!("Gossipsub error: {}", msg))?;

        // Create mDNS behaviour
        let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)?;

        // Create identify behaviour
        let identify = identify::Behaviour::new(identify::Config::new(
            get_p2p_identifier().to_string(),
            local_key.public(),
        ));

        // This is only for testing purposes. To keep the connection alive.
        #[cfg(test)]
        {
            let topic = gossipsub::IdentTopic::new("test-keep-alive");
            gossipsub.subscribe(&topic)?;
        }

        let (command_sender, command_receiver) = mpsc::unbounded_channel();

        // Create network behaviour
        let behaviour = P2PBehaviour {
            gossipsub,
            mdns,
            request_response,
            identify,
            kademlia,
            ping: ping::Behaviour::new(
                ping::Config::default().with_timeout(Duration::from_secs(60)),
            ),
        };

        // Create swarm
        let mut swarm = Swarm::new(
            transport,
            behaviour,
            local_peer_id,
            Config::with_tokio_executor(),
        );

        // Listen on all interfaces
        let listen_addr = format!("/ip4/0.0.0.0/tcp/{}", port);
        swarm.listen_on(listen_addr.parse()?)?;

        Ok(NetworkNode {
            swarm,
            pending_requests: HashMap::new(),
            shard_storage: HashMap::new(),
            node_name,
            local_peer_id: local_peer_id.to_string(),
            shutdown_signal: None,
            command_receiver,
            command_sender,
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
        self.shard_storage
            .entry(app_id.clone())
            .or_default()
            .insert(shard_index, shard);

        info!(
            "💾 Stored shard for app_id: {}, shard_index: {}",
            app_id, shard_index
        );
    }

    fn get_shard(&self, app_id: &str) -> Option<HashMap<u32, String>> {
        self.shard_storage.get(app_id).cloned()
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
        info!(
            "[{}] 🔧 send_shard method called with peer_id: {}, app_id: {}, shard_index: {}",
            self.node_name, peer_id, app_id, shard_index
        );
        let peer_id: PeerId = peer_id.parse()?;
        let send_shard = MessageRequest::SendShard(crate::p2p::types::SendShards {
            app_id,
            shard_index,
            shard,
        });

        let request_id = self
            .swarm
            .behaviour_mut()
            .request_response
            .send_request(&peer_id, send_shard.clone());
        debug!("[{}] >>> request_id >>>: {:?}", self.node_name, request_id);
        self.pending_requests.insert(request_id, send_shard);
        debug!(
            "[{}] ✅ send_shard method completed successfully",
            self.node_name
        );
        Ok(())
    }

    async fn process_request_shard(&mut self, peer_id: &str, app_id: String) -> anyhow::Result<()> {
        info!(
            "[{}] 🔧 request_shard method called with peer_id: {}, app_id: {}",
            self.node_name, peer_id, app_id
        );
        let peer_id: PeerId = peer_id.parse()?;
        let request_shard =
            MessageRequest::RequestShard(crate::p2p::types::RequestShard { app_id });

        let request_id = self
            .swarm
            .behaviour_mut()
            .request_response
            .send_request(&peer_id, request_shard.clone());

        debug!(
            "[{}] 🔧 Request sent with request_id: {:?}",
            self.node_name, request_id
        );
        self.pending_requests.insert(request_id, request_shard);
        debug!(
            "[{}] ✅ request_shard method completed successfully",
            self.node_name
        );
        Ok(())
    }

    async fn process_get_shard(
        &mut self,
        app_id: &str,
    ) -> anyhow::Result<Option<HashMap<u32, String>>> {
        info!(
            "[{}] 🔧 get_shard method called with app_id: {}",
            self.node_name, app_id
        );
        let shard = self.get_shard(app_id);
        debug!(
            "[{}] ✅ get_shard method completed successfully, shard: {:?}",
            self.node_name, shard
        );
        Ok(shard)
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
        self.shutdown_signal = Some(shutdown_tx);

        let mut ctrl_c = Box::pin(tokio::signal::ctrl_c());

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
                command = self.command_receiver.recv() => {
                    match command {
                        Some(NodeCommand::SendShard { peer_id, app_id, shard_index, shard }) => {
                            info!("[{}] 🔧 Processing SendShard command", self.node_name);
                            self.process_send_shard(&peer_id, app_id, shard_index, shard).await?;
                        }
                        Some(NodeCommand::RequestShard { peer_id, app_id }) => {
                            info!("[{}] 🔧 Processing RequestShard command", self.node_name);
                            self.process_request_shard(&peer_id, app_id).await?;
                        }
                        Some(NodeCommand::StoreShard { app_id, shard_index, shard }) => {
                            info!("[{}] 🔧 Processing StoreShard command", self.node_name);
                            self.store_shard(app_id, shard_index, shard);
                        }
                        Some(NodeCommand::GetShard { app_id }) => {
                            info!("[{}] 🔧 Processing GetShard command", self.node_name);
                            self.process_get_shard(&app_id).await?;
                        }
                        Some(NodeCommand::Shutdown) => {
                            info!("[{}] 🛑 Shutdown command received", self.node_name);
                            break;
                        }
                        None => {
                            warn!("[{}] ❌ Command channel closed", self.node_name);
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
        if let Some(signal) = self.shutdown_signal.take() {
            let _ = signal.send(());
        }
    }

    async fn handle_behaviour_event(&mut self, event: P2PBehaviourEvent) -> anyhow::Result<()> {
        match event {
            P2PBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                propagation_source: _,
                message_id: _,
                message,
            }) => {
                // Handle gossipsub messages if needed
                info!(
                    "[{}] 📢 Broadcast message received: {:?}",
                    self.node_name,
                    String::from_utf8_lossy(&message.data)
                );
            }

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

                                // Store the received shard
                                self.store_shard(
                                    send_shard.app_id.clone(),
                                    send_shard.shard_index,
                                    send_shard.shard.clone(),
                                );

                                let response = MessageResponse {
                                    shard: None,
                                    app_id: send_shard.app_id.clone(),
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
                                    MessageResponse {
                                        shard: Some(bincode::serialize(&shard_data).unwrap()),
                                        app_id: request_shard.app_id.clone(),
                                        success: true,
                                        message: "Shard found and returned".to_string(),
                                    }
                                } else {
                                    MessageResponse {
                                        shard: None,
                                        app_id: request_shard.app_id.clone(),
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

            P2PBehaviourEvent::Mdns(mdns::Event::Discovered(list)) => {
                for (peer_id, multiaddr) in list {
                    info!("Discovered peer {} at {}", peer_id, multiaddr);
                    self.swarm
                        .behaviour_mut()
                        .gossipsub
                        .add_explicit_peer(&peer_id);
                }
            }

            P2PBehaviourEvent::Mdns(mdns::Event::Expired(list)) => {
                for (peer_id, _) in list {
                    self.swarm
                        .behaviour_mut()
                        .gossipsub
                        .remove_explicit_peer(&peer_id);
                }
            }

            P2PBehaviourEvent::Identify(identify::Event::Received { peer_id, info }) => {
                info!("Identified peer {}: {}", peer_id, info.protocol_version);
            }

            _ => {}
        }
        Ok(())
    }
}
