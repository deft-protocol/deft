//! Clustering and High Availability module (L3)
//!
//! Provides cluster coordination for DEFT daemons:
//! - Node discovery and registration
//! - Leader election
//! - State synchronization
//! - Health monitoring

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info, warn};

/// Cluster node state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeState {
    /// Node is starting up
    Initializing,
    /// Node is healthy and active
    Active,
    /// Node is suspected to be down
    Suspect,
    /// Node is confirmed down
    Down,
    /// Node is shutting down gracefully
    Leaving,
}

/// Information about a cluster node
#[derive(Debug, Clone)]
pub struct ClusterNode {
    pub id: String,
    pub address: String,
    pub api_port: u16,
    pub deft_port: u16,
    pub state: NodeState,
    pub last_heartbeat: Instant,
    pub is_leader: bool,
    pub version: String,
    pub active_transfers: u32,
}

impl ClusterNode {
    pub fn new(id: String, address: String, api_port: u16, deft_port: u16) -> Self {
        Self {
            id,
            address,
            api_port,
            deft_port,
            state: NodeState::Initializing,
            last_heartbeat: Instant::now(),
            is_leader: false,
            version: env!("CARGO_PKG_VERSION").to_string(),
            active_transfers: 0,
        }
    }

    pub fn is_healthy(&self) -> bool {
        matches!(self.state, NodeState::Active)
    }

    pub fn api_url(&self) -> String {
        format!("http://{}:{}", self.address, self.api_port)
    }

    pub fn deft_url(&self) -> String {
        format!("{}:{}", self.address, self.deft_port)
    }
}

/// Cluster configuration
#[derive(Debug, Clone)]
pub struct ClusterConfig {
    /// This node's unique identifier
    pub node_id: String,
    /// Addresses of seed nodes for discovery
    pub seed_nodes: Vec<String>,
    /// Heartbeat interval
    pub heartbeat_interval: Duration,
    /// Time before a node is considered suspect
    pub suspect_timeout: Duration,
    /// Time before a suspect node is considered down
    pub down_timeout: Duration,
    /// Enable automatic leader election
    pub enable_leader_election: bool,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            node_id: uuid::Uuid::new_v4().to_string(),
            seed_nodes: Vec::new(),
            heartbeat_interval: Duration::from_secs(5),
            suspect_timeout: Duration::from_secs(15),
            down_timeout: Duration::from_secs(30),
            enable_leader_election: true,
        }
    }
}

/// Cluster manager for coordinating multiple DEFT nodes
pub struct ClusterManager {
    config: ClusterConfig,
    local_node: Arc<RwLock<ClusterNode>>,
    nodes: Arc<RwLock<HashMap<String, ClusterNode>>>,
    state_store: Arc<Mutex<ClusterStateStore>>,
}

impl ClusterManager {
    pub fn new(
        config: ClusterConfig,
        local_address: String,
        api_port: u16,
        deft_port: u16,
    ) -> Self {
        let local_node =
            ClusterNode::new(config.node_id.clone(), local_address, api_port, deft_port);

        Self {
            config,
            local_node: Arc::new(RwLock::new(local_node)),
            nodes: Arc::new(RwLock::new(HashMap::new())),
            state_store: Arc::new(Mutex::new(ClusterStateStore::new())),
        }
    }

    /// Start the cluster manager
    pub async fn start(&self) -> anyhow::Result<()> {
        info!(
            "Starting cluster manager with node_id: {}",
            self.config.node_id
        );

        // Set local node as active
        {
            let mut local = self.local_node.write().await;
            local.state = NodeState::Active;
        }

        // Discover seed nodes
        for seed in &self.config.seed_nodes {
            self.discover_node(seed).await;
        }

        // Start heartbeat loop
        let nodes = self.nodes.clone();
        let config = self.config.clone();
        let local_node = self.local_node.clone();

        tokio::spawn(async move {
            Self::heartbeat_loop(nodes, local_node, config).await;
        });

        Ok(())
    }

    /// Heartbeat loop for health monitoring
    async fn heartbeat_loop(
        nodes: Arc<RwLock<HashMap<String, ClusterNode>>>,
        local_node: Arc<RwLock<ClusterNode>>,
        config: ClusterConfig,
    ) {
        let mut interval = tokio::time::interval(config.heartbeat_interval);

        loop {
            interval.tick().await;

            // Update local node heartbeat
            {
                let mut local = local_node.write().await;
                local.last_heartbeat = Instant::now();
            }

            // Check health of other nodes
            let mut nodes_write = nodes.write().await;
            let now = Instant::now();

            for node in nodes_write.values_mut() {
                let since_heartbeat = now.duration_since(node.last_heartbeat);

                if since_heartbeat > config.down_timeout {
                    if node.state != NodeState::Down {
                        warn!("Node {} is now DOWN", node.id);
                        node.state = NodeState::Down;
                    }
                } else if since_heartbeat > config.suspect_timeout
                    && node.state == NodeState::Active
                {
                    warn!("Node {} is now SUSPECT", node.id);
                    node.state = NodeState::Suspect;
                }
            }

            // Remove nodes that have been down for too long
            nodes_write.retain(|id, node| {
                if node.state == NodeState::Down {
                    let since = now.duration_since(node.last_heartbeat);
                    if since > config.down_timeout * 3 {
                        info!("Removing dead node {} from cluster", id);
                        return false;
                    }
                }
                true
            });
        }
    }

    /// Discover a node at the given address
    async fn discover_node(&self, address: &str) {
        debug!("Attempting to discover node at {}", address);
        // In a real implementation, this would make an HTTP request to the node's API
        // to get its cluster information and add it to the nodes map
    }

    /// Register a new node in the cluster
    pub async fn register_node(&self, node: ClusterNode) {
        let mut nodes = self.nodes.write().await;
        info!("Registering node {} at {}", node.id, node.address);
        nodes.insert(node.id.clone(), node);
    }

    /// Get all active nodes
    pub async fn active_nodes(&self) -> Vec<ClusterNode> {
        let nodes = self.nodes.read().await;
        nodes.values().filter(|n| n.is_healthy()).cloned().collect()
    }

    /// Get the current leader node
    pub async fn leader(&self) -> Option<ClusterNode> {
        let nodes = self.nodes.read().await;
        nodes.values().find(|n| n.is_leader).cloned()
    }

    /// Check if this node is the leader
    pub async fn is_leader(&self) -> bool {
        self.local_node.read().await.is_leader
    }

    /// Get this node's ID
    pub async fn node_id(&self) -> String {
        self.local_node.read().await.id.clone()
    }

    /// Get cluster status
    pub async fn status(&self) -> ClusterStatus {
        let nodes = self.nodes.read().await;
        let local = self.local_node.read().await;

        let active_count = nodes.values().filter(|n| n.is_healthy()).count() + 1; // +1 for local
        let total_count = nodes.len() + 1;

        ClusterStatus {
            node_id: local.id.clone(),
            is_leader: local.is_leader,
            active_nodes: active_count,
            total_nodes: total_count,
            state: local.state.clone(),
        }
    }

    /// Synchronize state with the cluster
    pub async fn sync_state(&self, key: &str, value: Vec<u8>) -> anyhow::Result<()> {
        let mut store = self.state_store.lock().await;
        store.set(key, value);

        // In a real implementation, this would propagate to other nodes
        Ok(())
    }

    /// Get state from cluster
    pub async fn get_state(&self, key: &str) -> Option<Vec<u8>> {
        let store = self.state_store.lock().await;
        store.get(key)
    }
}

/// Cluster status information
#[derive(Debug, Clone)]
pub struct ClusterStatus {
    pub node_id: String,
    pub is_leader: bool,
    pub active_nodes: usize,
    pub total_nodes: usize,
    pub state: NodeState,
}

/// Simple in-memory state store for cluster coordination
/// In production, this would be backed by Redis, etcd, or similar
struct ClusterStateStore {
    data: HashMap<String, Vec<u8>>,
}

impl ClusterStateStore {
    fn new() -> Self {
        Self {
            data: HashMap::new(),
        }
    }

    fn set(&mut self, key: &str, value: Vec<u8>) {
        self.data.insert(key.to_string(), value);
    }

    fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.data.get(key).cloned()
    }

    #[allow(dead_code)]
    fn delete(&mut self, key: &str) {
        self.data.remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cluster_node_creation() {
        let node = ClusterNode::new("node-1".to_string(), "192.168.1.1".to_string(), 7752, 7751);

        assert_eq!(node.id, "node-1");
        assert_eq!(node.state, NodeState::Initializing);
        assert!(!node.is_leader);
        assert_eq!(node.api_url(), "http://192.168.1.1:7752");
        assert_eq!(node.deft_url(), "192.168.1.1:7751");
    }

    #[tokio::test]
    async fn test_cluster_manager_basic() {
        let config = ClusterConfig::default();
        let manager = ClusterManager::new(config, "127.0.0.1".to_string(), 7752, 7751);

        let status = manager.status().await;
        assert_eq!(status.active_nodes, 1);
        assert_eq!(status.total_nodes, 1);
    }

    #[tokio::test]
    async fn test_register_node() {
        let config = ClusterConfig::default();
        let manager = ClusterManager::new(config, "127.0.0.1".to_string(), 7752, 7751);

        let mut remote_node =
            ClusterNode::new("node-2".to_string(), "192.168.1.2".to_string(), 7752, 7751);
        remote_node.state = NodeState::Active;

        manager.register_node(remote_node).await;

        let active = manager.active_nodes().await;
        assert_eq!(active.len(), 1);
    }

    #[tokio::test]
    async fn test_state_store() {
        let config = ClusterConfig::default();
        let manager = ClusterManager::new(config, "127.0.0.1".to_string(), 7752, 7751);

        manager
            .sync_state("test-key", b"test-value".to_vec())
            .await
            .unwrap();

        let value = manager.get_state("test-key").await;
        assert_eq!(value, Some(b"test-value".to_vec()));
    }
}
