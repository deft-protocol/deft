//! Configuration management.
//!
//! Some methods reserved for config introspection.
#![allow(dead_code)]

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::hooks::HookConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub client: ClientConfig,
    pub storage: StorageConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    /// Partners that can connect TO us (incoming connections)
    #[serde(default)]
    pub partners: Vec<PartnerConfig>,
    /// Servers we can connect TO (outgoing connections - truststore)
    #[serde(default)]
    pub trusted_servers: Vec<TrustedServerConfig>,
    #[serde(default)]
    pub hooks: Vec<HookConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_format")]
    pub format: LogFormat,
    #[serde(default = "default_log_level")]
    pub level: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Text,
    Json,
}

fn default_log_format() -> LogFormat {
    LogFormat::Text
}

fn default_log_level() -> String {
    "info".to_string()
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            format: default_log_format(),
            level: default_log_level(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitsConfig {
    #[serde(default = "default_max_connections_per_ip")]
    pub max_connections_per_ip: u32,
    #[serde(default = "default_max_requests_per_partner")]
    pub max_requests_per_partner: u32,
    #[serde(default = "default_max_bytes_per_partner")]
    pub max_bytes_per_partner: u64,
    #[serde(default = "default_window_seconds")]
    pub window_seconds: u64,
    #[serde(default = "default_ban_seconds")]
    pub ban_seconds: u64,
    #[serde(default = "default_connection_timeout")]
    pub connection_timeout_seconds: u64,
    #[serde(default = "default_transfer_timeout")]
    pub transfer_timeout_seconds: u64,
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_seconds: u64,
    #[serde(default = "default_parallel_chunks")]
    pub parallel_chunks: usize,
    #[serde(default)]
    pub metrics_enabled: bool,
    #[serde(default = "default_metrics_port")]
    pub metrics_port: u16,
    #[serde(default)]
    pub api_enabled: bool,
    #[serde(default = "default_api_listen")]
    pub api_listen: String,
    #[serde(default)]
    pub api_key: Option<String>,
}

fn default_api_listen() -> String {
    "127.0.0.1:7742".to_string()
}

fn default_parallel_chunks() -> usize {
    4
}

fn default_metrics_port() -> u16 {
    9090
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_listen")]
    pub listen: String,
    pub cert: String,
    pub key: String,
    pub ca: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    pub cert: String,
    pub key: String,
    pub ca: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    #[serde(default = "default_chunk_size")]
    pub chunk_size: u32,
    #[serde(default = "default_temp_dir")]
    pub temp_dir: String,
}

/// Partners that can connect TO us (incoming connections)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartnerConfig {
    /// Partner ID - must match the CN of their client certificate
    pub id: String,
    /// Allowed client certificate fingerprints (SHA-256) for this partner
    #[serde(default)]
    pub allowed_certs: Vec<String>,
    /// Virtual files this partner can access
    #[serde(default)]
    pub virtual_files: Vec<VirtualFileConfig>,
}

/// Servers we can connect TO (outgoing connections - truststore)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedServerConfig {
    /// Friendly name for this server
    pub name: String,
    /// Server address (host:port)
    pub address: String,
    /// Expected server certificate fingerprint (SHA-256) - optional extra validation
    #[serde(default)]
    pub cert_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualFileConfig {
    pub name: String,
    pub path: String,
    pub direction: Direction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Send,
    Receive,
}

fn default_enabled() -> bool {
    true
}

fn default_listen() -> String {
    "0.0.0.0:7741".to_string()
}

fn default_chunk_size() -> u32 {
    262144 // 256 KB
}

fn default_temp_dir() -> String {
    "/var/deft/tmp".to_string()
}

fn default_max_connections_per_ip() -> u32 {
    10
}

fn default_max_requests_per_partner() -> u32 {
    1000
}

fn default_max_bytes_per_partner() -> u64 {
    1024 * 1024 * 1024 // 1 GB
}

fn default_window_seconds() -> u64 {
    60
}

fn default_ban_seconds() -> u64 {
    300
}

fn default_connection_timeout() -> u64 {
    30
}

fn default_transfer_timeout() -> u64 {
    3600 // 1 hour
}

fn default_idle_timeout() -> u64 {
    300 // 5 minutes
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_connections_per_ip: default_max_connections_per_ip(),
            max_requests_per_partner: default_max_requests_per_partner(),
            max_bytes_per_partner: default_max_bytes_per_partner(),
            window_seconds: default_window_seconds(),
            ban_seconds: default_ban_seconds(),
            connection_timeout_seconds: default_connection_timeout(),
            transfer_timeout_seconds: default_transfer_timeout(),
            idle_timeout_seconds: default_idle_timeout(),
            parallel_chunks: default_parallel_chunks(),
            metrics_enabled: false,
            metrics_port: default_metrics_port(),
            api_enabled: false,
            api_listen: default_api_listen(),
            api_key: None,
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            chunk_size: default_chunk_size(),
            temp_dir: default_temp_dir(),
        }
    }
}

impl Config {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())
            .with_context(|| format!("Failed to read config file: {:?}", path.as_ref()))?;

        let config: Config =
            toml::from_str(&content).with_context(|| "Failed to parse config file")?;

        Ok(config)
    }

    pub fn find_partner(&self, partner_id: &str) -> Option<&PartnerConfig> {
        self.partners.iter().find(|p| p.id == partner_id)
    }

    pub fn find_trusted_server(&self, name: &str) -> Option<&TrustedServerConfig> {
        self.trusted_servers.iter().find(|s| s.name == name)
    }

    pub fn get_virtual_files_for_partner(&self, partner_id: &str) -> Vec<&VirtualFileConfig> {
        self.partners
            .iter()
            .find(|p| p.id == partner_id)
            .map(|p| p.virtual_files.iter().collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_config() -> Config {
        Config {
            server: ServerConfig {
                enabled: true,
                listen: "127.0.0.1:7741".to_string(),
                cert: "server.crt".to_string(),
                key: "server.key".to_string(),
                ca: "ca.crt".to_string(),
            },
            client: ClientConfig {
                enabled: true,
                cert: "client.crt".to_string(),
                key: "client.key".to_string(),
                ca: "ca.crt".to_string(),
            },
            storage: StorageConfig::default(),
            limits: LimitsConfig::default(),
            logging: LoggingConfig::default(),
            partners: vec![],
            trusted_servers: vec![],
            hooks: vec![],
        }
    }

    #[test]
    fn test_defaults() {
        let limits = LimitsConfig::default();
        assert_eq!(limits.max_connections_per_ip, 10);
        assert_eq!(limits.max_requests_per_partner, 1000);
        assert_eq!(limits.window_seconds, 60);
        assert_eq!(limits.ban_seconds, 300);

        let storage = StorageConfig::default();
        assert_eq!(storage.chunk_size, 262144);
    }

    #[test]
    fn test_find_partner() {
        let mut config = minimal_config();
        config.partners.push(PartnerConfig {
            id: "partner-a".to_string(),
            allowed_certs: vec!["abc123".to_string()],
            virtual_files: vec![],
        });

        assert!(config.find_partner("partner-a").is_some());
        assert!(config.find_partner("unknown").is_none());
    }

    #[test]
    fn test_find_trusted_server() {
        let mut config = minimal_config();
        config.trusted_servers.push(TrustedServerConfig {
            name: "server-b".to_string(),
            address: "192.168.1.100:7741".to_string(),
            cert_fingerprint: Some("def456".to_string()),
        });

        let server = config.find_trusted_server("server-b");
        assert!(server.is_some());
        assert_eq!(server.unwrap().address, "192.168.1.100:7741");
        assert!(config.find_trusted_server("unknown").is_none());
    }

    #[test]
    fn test_get_virtual_files_for_partner() {
        let mut config = minimal_config();
        config.partners.push(PartnerConfig {
            id: "partner-a".to_string(),
            allowed_certs: vec![],
            virtual_files: vec![
                VirtualFileConfig {
                    name: "invoices".to_string(),
                    path: "/data/invoices".to_string(),
                    direction: Direction::Send,
                },
                VirtualFileConfig {
                    name: "reports".to_string(),
                    path: "/data/reports".to_string(),
                    direction: Direction::Receive,
                },
            ],
        });

        let vfs = config.get_virtual_files_for_partner("partner-a");
        assert_eq!(vfs.len(), 2);
        assert_eq!(vfs[0].name, "invoices");

        let empty = config.get_virtual_files_for_partner("unknown");
        assert!(empty.is_empty());
    }

    #[test]
    fn test_direction_enum() {
        assert_eq!(Direction::Send, Direction::Send);
        assert_ne!(Direction::Send, Direction::Receive);
    }

    #[test]
    fn test_config_toml_parsing() {
        let toml_content = r#"
[server]
enabled = true
listen = "0.0.0.0:7741"
cert = "server.crt"
key = "server.key"
ca = "ca.crt"

[client]
enabled = false
cert = "client.crt"
key = "client.key"
ca = "ca.crt"

[storage]
chunk_size = 524288
temp_dir = "/tmp/deft"

[[partners]]
id = "test-partner"
allowed_certs = ["fingerprint123"]

[[partners.virtual_files]]
name = "data"
path = "/data/files"
direction = "send"

[[trusted_servers]]
name = "remote-server"
address = "10.0.0.1:7741"
cert_fingerprint = "abc123"
"#;

        let config: Config = toml::from_str(toml_content).expect("Failed to parse TOML");
        assert!(config.server.enabled);
        assert!(!config.client.enabled);
        assert_eq!(config.storage.chunk_size, 524288);
        assert_eq!(config.partners.len(), 1);
        assert_eq!(config.partners[0].id, "test-partner");
        assert_eq!(config.partners[0].virtual_files.len(), 1);
        assert_eq!(config.trusted_servers.len(), 1);
        assert_eq!(config.trusted_servers[0].name, "remote-server");
    }
}
