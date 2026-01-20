use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub client: ClientConfig,
    pub storage: StorageConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub partners: Vec<PartnerConfig>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartnerConfig {
    pub id: String,
    #[serde(default)]
    pub allowed_certs: Vec<String>,
    #[serde(default)]
    pub endpoints: Vec<String>,
    #[serde(default)]
    pub virtual_files: Vec<VirtualFileConfig>,
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
    "/var/rift/tmp".to_string()
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
        
        let config: Config = toml::from_str(&content)
            .with_context(|| "Failed to parse config file")?;
        
        Ok(config)
    }

    pub fn find_partner(&self, partner_id: &str) -> Option<&PartnerConfig> {
        self.partners.iter().find(|p| p.id == partner_id)
    }

    pub fn get_virtual_files_for_partner(&self, partner_id: &str) -> Vec<&VirtualFileConfig> {
        self.partners
            .iter()
            .find(|p| p.id == partner_id)
            .map(|p| p.virtual_files.iter().collect())
            .unwrap_or_default()
    }
}
