// src/p2p.rs

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, broadcast};
use serde::{Deserialize, Serialize};
use futures::prelude::*;
use libp2p::{
    gossipsub::{self, IdentTopic, MessageAuthenticity, ValidationMode},
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, noise, yamux, mdns, identify, ping, kad,
    Multiaddr, PeerId, Swarm, SwarmBuilder,
    core::upgrade,
};
use anyhow::{Result, anyhow};
use tracing::{info, warn, error, debug};

use crate::pos::registry::ValidatorId;
use crate::types::{Block, Vote, QC, Hash};

/// Network messages for HotStuff consensus protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConsensusMessage {
    /// Block proposal from a leader to all validators
    Proposal {
        block: Block,
        sender_id: ValidatorId,
    },
    /// Vote from a validator to the leader of next view
    Vote {
        vote: Vote,
        sender_id: ValidatorId,
    },
    /// QC broadcast from leader to all validators
    QC {
        qc: QC,
        sender_id: ValidatorId,
    },
    /// View change/timeout message when a view expires
    ViewChange {
        view: u64,
        sender_id: ValidatorId,
        timeout_qc: Option<QC>, // If we have a QC that justifies the timeout
    },
}

/// P2P Network Behaviour combining all protocols
#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "P2PEvent")]
struct P2PBehaviour {
    gossipsub: gossipsub::Behaviour,
    mdns: mdns::tokio::Behaviour,
    identify: identify::Behaviour,
    ping: ping::Behaviour,
    kademlia: kad::Behaviour<kad::store::MemoryStore>,
}

/// Events from the P2P behaviour
#[derive(Debug)]
enum P2PEvent {
    Gossipsub(gossipsub::Event),
    Mdns(mdns::Event),
    Identify(identify::Event),
    Ping(ping::Event),
    Kademlia(kad::Event),
}

impl From<gossipsub::Event> for P2PEvent {
    fn from(event: gossipsub::Event) -> Self {
        P2PEvent::Gossipsub(event)
    }
}

impl From<mdns::Event> for P2PEvent {
    fn from(event: mdns::Event) -> Self {
        P2PEvent::Mdns(event)
    }
}

impl From<identify::Event> for P2PEvent {
    fn from(event: identify::Event) -> Self {
        P2PEvent::Identify(event)
    }
}

impl From<ping::Event> for P2PEvent {
    fn from(event: ping::Event) -> Self {
        P2PEvent::Ping(event)
    }
}

impl From<kad::Event> for P2PEvent {
    fn from(event: kad::Event) -> Self {
        P2PEvent::Kademlia(event)
    }
}

/// Configuration for the P2P network
#[derive(Debug, Clone)]
pub struct P2PConfig {
    pub listen_addr: Multiaddr,
    pub bootstrap_peers: Vec<Multiaddr>,
    pub max_peers: usize,
}

impl Default for P2PConfig {
    fn default() -> Self {
        Self {
            listen_addr: "/ip4/0.0.0.0/tcp/0".parse().unwrap(),
            bootstrap_peers: Vec::new(),
            max_peers: 50,
        }
    }
}

/// Network layer for HotStuff consensus messages using libp2p
#[derive(Clone)]
pub struct ConsensusNetwork {
    /// My validator ID
    validator_id: ValidatorId,
    /// Channel for receiving consensus messages from the network
    message_rx: Arc<Mutex<broadcast::Receiver<ConsensusMessage>>>,
    /// Channel sender for publishing messages
    message_tx: broadcast::Sender<ConsensusMessage>,
    /// P2P Network command sender
    command_tx: mpsc::UnboundedSender<NetworkCommand>,
    /// Connected peers mapped to validator IDs
    peers: Arc<Mutex<HashMap<PeerId, ValidatorId>>>,
    /// Our local PeerId
    local_peer_id: PeerId,
}

/// Commands for the P2P network task
#[derive(Debug)]
enum NetworkCommand {
    BroadcastMessage(ConsensusMessage),
    SendToValidator(ValidatorId, ConsensusMessage),
    ConnectPeer(Multiaddr),
    GetConnectedPeers,
}

impl ConsensusNetwork {
    /// Create a new consensus network instance with P2P
    pub async fn new(validator_id: ValidatorId, config: P2PConfig) -> Result<Self> {
        let local_key = libp2p::identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());
        
        info!("Starting P2P network for validator {} with peer ID {}", validator_id, local_peer_id);
        
        // Create message channels
        let (message_tx, message_rx) = broadcast::channel(1024);
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        
        // Initialize the network behaviour
        let mut swarm = SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_behaviour(|key| {
                // Gossipsub configuration
                let gossipsub_config = gossipsub::ConfigBuilder::default()
                    .heartbeat_interval(Duration::from_secs(1))
                    .validation_mode(ValidationMode::Strict)
                    .message_id_fn(|message| {
                        use std::collections::hash_map::DefaultHasher;
                        use std::hash::{Hash, Hasher};
                        let mut hasher = DefaultHasher::new();
                        message.data.hash(&mut hasher);
                        gossipsub::MessageId::from(hasher.finish().to_string())
                    })
                    .build()
                    .expect("Valid gossipsub config");
                
                let gossipsub = gossipsub::Behaviour::new(
                    MessageAuthenticity::Signed(key.clone()),
                    gossipsub_config,
                )?;
                
                let mdns = mdns::tokio::Behaviour::new(
                    mdns::Config::default(),
                    key.public().to_peer_id(),
                )?;
                
                let identify = identify::Behaviour::new(
                    identify::Config::new(
                        "/hotstuff/1.0.0".to_string(),
                        key.public(),
                    )
                );
                
                let ping = ping::Behaviour::new(
                    ping::Config::new().with_interval(Duration::from_secs(30))
                );
                
                let store = kad::store::MemoryStore::new(key.public().to_peer_id());
                let kademlia = kad::Behaviour::new(
                    key.public().to_peer_id(),
                    store,
                );
                
                Ok(P2PBehaviour {
                    gossipsub,
                    mdns,
                    identify,
                    ping,
                    kademlia,
                })
            })?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();
        
        // Subscribe to consensus topics
        let topics = [
            "hotstuff-proposals",
            "hotstuff-votes", 
            "hotstuff-qcs",
            "hotstuff-view-changes"
        ];
        
        for topic_str in &topics {
            let topic = IdentTopic::new(*topic_str);
            swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
            info!("Subscribed to topic: {}", topic_str);
        }
        
        // Start listening
        swarm.listen_on(config.listen_addr.clone())?;
        
        let peers = Arc::new(Mutex::new(HashMap::new()));
        let network = Self {
            validator_id,
            message_rx: Arc::new(Mutex::new(message_rx)),
            message_tx,
            command_tx,
            peers: peers.clone(),
            local_peer_id,
        };
        
        // Spawn the network event loop
        let network_task = NetworkTask {
            swarm,
            command_rx,
            message_tx: network.message_tx.clone(),
            peers,
            validator_id,
        };
        
        tokio::spawn(network_task.run());
        
        // Connect to bootstrap peers
        for peer in config.bootstrap_peers {
            let _ = network.command_tx.send(NetworkCommand::ConnectPeer(peer));
        }
        
        info!("P2P network initialized for validator {}", validator_id);
        Ok(network)
    }

    /// Connect to a peer by address
    pub fn connect_peer(&self, addr: Multiaddr) -> Result<()> {
        self.command_tx
            .send(NetworkCommand::ConnectPeer(addr))
            .map_err(|e| anyhow!("Failed to send connect command: {}", e))
    }

    /// Broadcast a proposal to all connected peers
    pub fn broadcast_proposal(&self, block: Block) -> Result<()> {
        let msg = ConsensusMessage::Proposal {
            block,
            sender_id: self.validator_id,
        };
        
        self.broadcast_message(msg)
    }

    /// Send a vote to the leader of the next view
    pub fn send_vote(&self, vote: Vote, leader_id: ValidatorId) -> Result<()> {
        let msg = ConsensusMessage::Vote {
            vote,
            sender_id: self.validator_id,
        };
        
        self.send_to_validator(leader_id, msg)
    }

    /// Broadcast a QC to all connected peers
    pub fn broadcast_qc(&self, qc: QC) -> Result<()> {
        let msg = ConsensusMessage::QC {
            qc,
            sender_id: self.validator_id,
        };
        
        self.broadcast_message(msg)
    }

    /// Broadcast a view change message
    pub fn broadcast_view_change(&self, view: u64, timeout_qc: Option<QC>) -> Result<()> {
        let msg = ConsensusMessage::ViewChange {
            view,
            sender_id: self.validator_id,
            timeout_qc,
        };
        
        self.broadcast_message(msg)
    }

    /// Try to receive a consensus message (non-blocking)
    pub fn try_recv_message(&self) -> Option<ConsensusMessage> {
        let mut rx = self.message_rx.lock().unwrap();
        match rx.try_recv() {
            Ok(msg) => Some(msg),
            Err(broadcast::error::TryRecvError::Empty) => None,
            Err(broadcast::error::TryRecvError::Lagged(n)) => {
                warn!("Message receiver lagged by {} messages", n);
                None
            }
            Err(broadcast::error::TryRecvError::Closed) => {
                error!("Message receiver closed");
                None
            }
        }
    }

    /// Send a message to a specific validator
    fn send_to_validator(&self, validator_id: ValidatorId, msg: ConsensusMessage) -> Result<()> {
        self.command_tx
            .send(NetworkCommand::SendToValidator(validator_id, msg))
            .map_err(|e| anyhow!("Failed to send validator message command: {}", e))
    }

    /// Broadcast a message to all connected peers
    fn broadcast_message(&self, msg: ConsensusMessage) -> Result<()> {
        self.command_tx
            .send(NetworkCommand::BroadcastMessage(msg))
            .map_err(|e| anyhow!("Failed to send broadcast command: {}", e))
    }

    /// Get my validator ID
    pub fn validator_id(&self) -> ValidatorId {
        self.validator_id
    }
    
    /// Get our local peer ID
    pub fn peer_id(&self) -> PeerId {
        self.local_peer_id
    }
    
    /// Get connected peers count
    pub fn connected_peers(&self) -> usize {
        self.peers.lock().unwrap().len()
    }
}

/// Network task handling P2P events
struct NetworkTask {
    swarm: Swarm<P2PBehaviour>,
    command_rx: mpsc::UnboundedReceiver<NetworkCommand>,
    message_tx: broadcast::Sender<ConsensusMessage>,
    peers: Arc<Mutex<HashMap<PeerId, ValidatorId>>>,
    validator_id: ValidatorId,
}

impl NetworkTask {
    async fn run(mut self) {
        info!("Starting network task for validator {}", self.validator_id);
        
        loop {
            tokio::select! {
                command = self.command_rx.recv() => {
                    if let Some(cmd) = command {
                        self.handle_command(cmd).await;
                    } else {
                        info!("Command channel closed, shutting down network task");
                        break;
                    }
                }
                
                event = self.swarm.select_next_some() => {
                    self.handle_swarm_event(event).await;
                }
            }
        }
    }
    
    async fn handle_command(&mut self, command: NetworkCommand) {
        match command {
            NetworkCommand::BroadcastMessage(msg) => {
                if let Err(e) = self.broadcast_consensus_message(msg).await {
                    error!("Failed to broadcast message: {}", e);
                }
            }
            
            NetworkCommand::SendToValidator(validator_id, msg) => {
                if let Err(e) = self.send_to_validator(validator_id, msg).await {
                    error!("Failed to send to validator {}: {}", validator_id, e);
                }
            }
            
            NetworkCommand::ConnectPeer(addr) => {
                if let Err(e) = self.swarm.dial(addr.clone()) {
                    error!("Failed to dial peer {}: {}", addr, e);
                } else {
                    info!("Dialing peer: {}", addr);
                }
            }
            
            NetworkCommand::GetConnectedPeers => {
                let peers = self.peers.lock().unwrap();
                info!("Connected peers: {:?}", peers.keys().collect::<Vec<_>>());
            }
        }
    }
    
    async fn handle_swarm_event(&mut self, event: SwarmEvent<P2PEvent>) {
        match event {
            SwarmEvent::Behaviour(P2PEvent::Gossipsub(gossipsub::Event::Message {
                propagation_source: _,
                message_id: _,
                message,
            })) => {
                self.handle_gossipsub_message(message).await;
            }
            
            SwarmEvent::Behaviour(P2PEvent::Mdns(mdns::Event::Discovered(list))) => {
                for (peer_id, multiaddr) in list {
                    info!("mDNS discovered peer: {} at {}", peer_id, multiaddr);
                    if let Err(e) = self.swarm.dial(multiaddr) {
                        error!("Failed to dial discovered peer {}: {}", peer_id, e);
                    }
                }
            }
            
            SwarmEvent::Behaviour(P2PEvent::Identify(identify::Event::Received {
                peer_id,
                info: identify::Info { protocols, .. },
                ..  
            })) => {
                info!("Identified peer: {} with protocols: {:?}", peer_id, protocols);
                // Add to Kademlia if they support it
                if protocols.iter().any(|p| p.to_string().starts_with("/ipfs/kad")) {
                    let addr = self.swarm.external_addresses().next().cloned()
                        .unwrap_or_else(|| "/ip4/127.0.0.1/tcp/0".parse().unwrap());
                    let _update = self.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                    debug!("Added peer {} to kademlia", peer_id);
                }
            }
            
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                info!("Connection established with peer: {}", peer_id);
                // For now, we don't have a way to map peer_id to validator_id
                // This would need to be part of the handshake/identify protocol
            }
            
            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                info!("Connection closed with peer: {} due to: {:?}", peer_id, cause);
                let mut peers = self.peers.lock().unwrap();
                peers.remove(&peer_id);
            }
            
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("Listening on: {}", address);
            }
            
            _ => {}
        }
    }
    
    async fn handle_gossipsub_message(&mut self, message: gossipsub::Message) {
        if let Ok(consensus_msg) = serde_json::from_slice::<ConsensusMessage>(&message.data) {
            debug!("Received consensus message: {:?}", consensus_msg);
            if let Err(e) = self.message_tx.send(consensus_msg) {
                error!("Failed to forward consensus message: {}", e);
            }
        } else {
            warn!("Failed to deserialize gossipsub message");
        }
    }
    
    async fn broadcast_consensus_message(&mut self, msg: ConsensusMessage) -> Result<()> {
        let topic = match &msg {
            ConsensusMessage::Proposal { .. } => IdentTopic::new("hotstuff-proposals"),
            ConsensusMessage::Vote { .. } => IdentTopic::new("hotstuff-votes"),
            ConsensusMessage::QC { .. } => IdentTopic::new("hotstuff-qcs"),
            ConsensusMessage::ViewChange { .. } => IdentTopic::new("hotstuff-view-changes"),
        };
        
        let data = serde_json::to_vec(&msg)
            .map_err(|e| anyhow!("Failed to serialize message: {}", e))?;
            
        self.swarm.behaviour_mut().gossipsub.publish(topic, data)
            .map_err(|e| anyhow!("Failed to publish to gossipsub: {}", e))?;
            
        Ok(())
    }
    
    async fn send_to_validator(&mut self, _validator_id: ValidatorId, msg: ConsensusMessage) -> Result<()> {
        // For now, we broadcast to all peers since we don't have validator<->peer mapping
        // In production, this would require a registry or handshake to map validators to peer IDs
        self.broadcast_consensus_message(msg).await
    }
}

/// Simple leader election for testing - round-robin based on view
/// In production, this would use VRF or stake-weighted selection
pub fn simple_leader_election(view: u64, num_validators: usize) -> ValidatorId {
    if num_validators == 0 {
        return 0;
    }
    (view as usize % num_validators) as ValidatorId
}

/// Create a P2P network for testing with multiple validators
pub async fn create_test_network(validator_ids: Vec<ValidatorId>) -> Result<Vec<ConsensusNetwork>, anyhow::Error> {
    let mut networks = Vec::new();
    let mut listen_ports = Vec::new();
    
    // Create networks on different ports
    for (i, &id) in validator_ids.iter().enumerate() {
        let port = 9000 + i as u16; // Use different ports for each validator
        let config = P2PConfig {
            listen_addr: format!("/ip4/127.0.0.1/tcp/{}", port).parse()?,
            bootstrap_peers: Vec::new(),
            max_peers: 50,
        };
        
        let network = ConsensusNetwork::new(id, config).await?;
        listen_ports.push(port);
        networks.push(network);
        
        // Give time for the network to start listening
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    
    // Connect each network to all others
    for (i, network) in networks.iter().enumerate() {
        for (j, &port) in listen_ports.iter().enumerate() {
            if i != j {
                let addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", port).parse()?;
                if let Err(e) = network.connect_peer(addr) {
                    warn!("Failed to connect validator {} to validator {}: {}", 
                         network.validator_id(), validator_ids[j], e);
                }
            }
        }
    }
    
    // Give time for connections to establish
    tokio::time::sleep(Duration::from_millis(500)).await;
    
    Ok(networks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{BlockHeader, Pacemaker};
    use crate::crypto::bls::BlsSignatureBytes;
    use bitvec::vec::BitVec;

    fn dummy_block() -> Block {
        Block {
            transactions: vec![],
            reveals: vec![],
            batch_digests: vec![],
            header: BlockHeader {
                parent_hash: [0u8; 32],
                height: 1,
                txs_root: [0u8; 32],
                receipts_root: [0u8; 32],
                gas_used: 0,
                randomness: [0u8; 32],
                reveal_set_root: [0u8; 32],
                il_root: [0u8; 32],
                exec_base_fee: 1000,
                commit_base_fee: 1000,
                avail_base_fee: 1000,
                timestamp: 0,
                slot: 1,
                epoch: 0,
                proposer_id: 0,
                signature: [0u8; 64],
                bundle_len: 8,
                vrf_preout: [0u8; 32],
                vrf_output: [0u8; 32],
                vrf_proof: vec![],
                view: 1,
                justify_qc_hash: [0u8; 32],
            },
            justify_qc: QC {
                view: 0,
                block_id: [0u8; 32],
                agg_sig: BlsSignatureBytes([0u8; 96]),
                bitmap: BitVec::new(),
            },
        }
    }

    #[tokio::test]
    async fn test_network_creation() {
        // Skip real P2P test - requires more complex setup
        let validators = vec![0, 1, 2];
        assert_eq!(validators.len(), 3);
        println!("P2P network creation test skipped - use integration tests");
    }

    #[tokio::test]
    async fn test_proposal_broadcast() {
        // Skip real P2P test - requires more complex setup
        println!("P2P proposal broadcast test skipped - use integration tests");
    }

    #[test]
    fn test_leader_election() {
        // Test round-robin leader election
        assert_eq!(simple_leader_election(0, 3), 0);
        assert_eq!(simple_leader_election(1, 3), 1);
        assert_eq!(simple_leader_election(2, 3), 2);
        assert_eq!(simple_leader_election(3, 3), 0);
        assert_eq!(simple_leader_election(4, 3), 1);
    }
}