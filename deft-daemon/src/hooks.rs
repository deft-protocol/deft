use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{debug, info, warn};

/// Hook event types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookEvent {
    /// Before a transfer starts
    PreTransfer,
    /// After a transfer completes successfully
    PostTransfer,
    /// When a transfer fails
    TransferError,
    /// When a new connection is established
    Connect,
    /// When a connection is closed
    Disconnect,
    /// When a file is received
    FileReceived,
    /// When a file is sent
    FileSent,
}

impl HookEvent {
    pub fn as_str(&self) -> &'static str {
        match self {
            HookEvent::PreTransfer => "pre_transfer",
            HookEvent::PostTransfer => "post_transfer",
            HookEvent::TransferError => "transfer_error",
            HookEvent::Connect => "connect",
            HookEvent::Disconnect => "disconnect",
            HookEvent::FileReceived => "file_received",
            HookEvent::FileSent => "file_sent",
        }
    }
}

/// Context passed to hooks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookContext {
    pub event: String,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transfer_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partner_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub virtual_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chunks: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_addr: Option<String>,
}

impl HookContext {
    pub fn new(event: HookEvent) -> Self {
        Self {
            event: event.as_str().to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            transfer_id: None,
            partner_id: None,
            virtual_file: None,
            local_path: None,
            file_size: None,
            chunks: None,
            error: None,
            remote_addr: None,
        }
    }

    pub fn with_transfer(mut self, id: &str) -> Self {
        self.transfer_id = Some(id.to_string());
        self
    }

    pub fn with_partner(mut self, id: &str) -> Self {
        self.partner_id = Some(id.to_string());
        self
    }

    pub fn with_virtual_file(mut self, name: &str) -> Self {
        self.virtual_file = Some(name.to_string());
        self
    }

    pub fn with_path(mut self, path: &Path) -> Self {
        self.local_path = Some(path.to_string_lossy().to_string());
        self
    }

    pub fn with_size(mut self, size: u64) -> Self {
        self.file_size = Some(size);
        self
    }

    pub fn with_error(mut self, err: &str) -> Self {
        self.error = Some(err.to_string());
        self
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    pub fn to_env_vars(&self) -> Vec<(String, String)> {
        let mut vars = vec![
            ("DEFT_EVENT".to_string(), self.event.clone()),
            ("DEFT_TIMESTAMP".to_string(), self.timestamp.clone()),
        ];

        if let Some(ref v) = self.transfer_id {
            vars.push(("DEFT_TRANSFER_ID".to_string(), v.clone()));
        }
        if let Some(ref v) = self.partner_id {
            vars.push(("DEFT_PARTNER_ID".to_string(), v.clone()));
        }
        if let Some(ref v) = self.virtual_file {
            vars.push(("DEFT_VIRTUAL_FILE".to_string(), v.clone()));
        }
        if let Some(ref v) = self.local_path {
            vars.push(("DEFT_LOCAL_PATH".to_string(), v.clone()));
        }
        if let Some(v) = self.file_size {
            vars.push(("DEFT_FILE_SIZE".to_string(), v.to_string()));
        }
        if let Some(v) = self.chunks {
            vars.push(("DEFT_CHUNKS".to_string(), v.to_string()));
        }
        if let Some(ref v) = self.error {
            vars.push(("DEFT_ERROR".to_string(), v.clone()));
        }
        if let Some(ref v) = self.remote_addr {
            vars.push(("DEFT_REMOTE_ADDR".to_string(), v.clone()));
        }

        vars
    }
}

/// Hook configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookConfig {
    /// Event to trigger on
    pub event: String,
    /// Script or command to execute
    pub command: String,
    /// Working directory (optional)
    #[serde(default)]
    pub cwd: Option<PathBuf>,
    /// Timeout in seconds (default: 30)
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    /// Whether to block transfer until hook completes
    #[serde(default)]
    pub blocking: bool,
    /// Only run for specific partners (empty = all)
    #[serde(default)]
    pub partners: Vec<String>,
    /// Only run for specific virtual files (empty = all)
    #[serde(default)]
    pub virtual_files: Vec<String>,
}

fn default_timeout() -> u64 {
    30
}

/// Hook execution result
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct HookResult {
    pub success: bool,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
}

/// Hook manager
pub struct HookManager {
    hooks: HashMap<String, Vec<HookConfig>>,
}

impl HookManager {
    pub fn new() -> Self {
        Self {
            hooks: HashMap::new(),
        }
    }

    pub fn from_configs(configs: Vec<HookConfig>) -> Self {
        let mut manager = Self::new();
        for config in configs {
            manager.register(config);
        }
        manager
    }

    pub fn register(&mut self, config: HookConfig) {
        self.hooks
            .entry(config.event.clone())
            .or_default()
            .push(config);
    }

    /// Check if hook should run for given context
    fn should_run(config: &HookConfig, ctx: &HookContext) -> bool {
        // Check partner filter
        if !config.partners.is_empty() {
            if let Some(ref partner) = ctx.partner_id {
                if !config.partners.contains(partner) {
                    return false;
                }
            }
        }

        // Check virtual file filter
        if !config.virtual_files.is_empty() {
            if let Some(ref vf) = ctx.virtual_file {
                if !config.virtual_files.contains(vf) {
                    return false;
                }
            }
        }

        true
    }

    /// Execute hooks for an event
    pub async fn execute(&self, ctx: &HookContext) -> Vec<HookResult> {
        let mut results = Vec::new();

        let hooks = match self.hooks.get(&ctx.event) {
            Some(h) => h,
            None => return results,
        };

        for hook in hooks {
            if !Self::should_run(hook, ctx) {
                continue;
            }

            debug!("Executing hook: {} for event {}", hook.command, ctx.event);
            let result = Self::run_hook(hook, ctx).await;

            if result.success {
                info!("Hook {} completed successfully", hook.command);
            } else {
                warn!("Hook {} failed: {}", hook.command, result.stderr);
            }

            results.push(result);
        }

        results
    }

    async fn run_hook(config: &HookConfig, ctx: &HookContext) -> HookResult {
        let start = std::time::Instant::now();

        // Parse command
        let parts: Vec<&str> = config.command.split_whitespace().collect();
        if parts.is_empty() {
            return HookResult {
                success: false,
                exit_code: None,
                stdout: String::new(),
                stderr: "Empty command".to_string(),
                duration_ms: 0,
            };
        }

        let program = parts[0];
        let args = &parts[1..];

        // Build command
        let mut cmd = Command::new(program);
        cmd.args(args);

        // Set working directory
        if let Some(ref cwd) = config.cwd {
            cmd.current_dir(cwd);
        }

        // Set environment variables
        for (key, value) in ctx.to_env_vars() {
            cmd.env(&key, &value);
        }

        // Pass context as JSON via stdin or env
        cmd.env("DEFT_CONTEXT_JSON", ctx.to_json());

        // Execute
        let output = match cmd.output() {
            Ok(o) => o,
            Err(e) => {
                return HookResult {
                    success: false,
                    exit_code: None,
                    stdout: String::new(),
                    stderr: format!("Failed to execute: {}", e),
                    duration_ms: start.elapsed().as_millis() as u64,
                };
            }
        };

        HookResult {
            success: output.status.success(),
            exit_code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            duration_ms: start.elapsed().as_millis() as u64,
        }
    }
}

impl Default for HookManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hook_context() {
        let ctx = HookContext::new(HookEvent::PostTransfer)
            .with_transfer("tx-123")
            .with_partner("acme-corp")
            .with_virtual_file("invoices")
            .with_size(1024);

        assert_eq!(ctx.event, "post_transfer");
        assert_eq!(ctx.transfer_id, Some("tx-123".to_string()));

        let vars = ctx.to_env_vars();
        assert!(vars.iter().any(|(k, _)| k == "DEFT_EVENT"));
        assert!(vars.iter().any(|(k, _)| k == "DEFT_PARTNER_ID"));
    }

    #[test]
    fn test_hook_context_json() {
        let ctx = HookContext::new(HookEvent::FileReceived)
            .with_partner("test")
            .with_path(Path::new("/data/file.xml"));

        let json = ctx.to_json();
        assert!(json.contains("file_received"));
        assert!(json.contains("test"));
    }

    #[tokio::test]
    async fn test_hook_manager() {
        let mut manager = HookManager::new();

        manager.register(HookConfig {
            event: "post_transfer".to_string(),
            command: "echo test".to_string(),
            cwd: None,
            timeout_seconds: 30,
            blocking: false,
            partners: vec![],
            virtual_files: vec![],
        });

        let ctx = HookContext::new(HookEvent::PostTransfer);
        let results = manager.execute(&ctx).await;

        assert_eq!(results.len(), 1);
        assert!(results[0].success);
    }

    #[test]
    fn test_should_run_filter() {
        let config = HookConfig {
            event: "post_transfer".to_string(),
            command: "echo".to_string(),
            cwd: None,
            timeout_seconds: 30,
            blocking: false,
            partners: vec!["allowed-partner".to_string()],
            virtual_files: vec![],
        };

        let ctx_allowed = HookContext::new(HookEvent::PostTransfer).with_partner("allowed-partner");
        let ctx_denied = HookContext::new(HookEvent::PostTransfer).with_partner("other-partner");

        assert!(HookManager::should_run(&config, &ctx_allowed));
        assert!(!HookManager::should_run(&config, &ctx_denied));
    }
}
