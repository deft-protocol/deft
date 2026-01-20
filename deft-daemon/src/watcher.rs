//! Directory watcher module for automatic file detection.
//!
//! This module is reserved for future use (v2 feature).
#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc;
use tokio::time::interval;
use tracing::{debug, error, info, warn};

/// File event types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileEvent {
    Created(PathBuf),
    Modified(PathBuf),
    Deleted(PathBuf),
}

/// Watch configuration for a directory
#[derive(Debug, Clone)]
pub struct WatchConfig {
    /// Directory to watch
    pub path: PathBuf,
    /// File pattern (glob)
    pub pattern: Option<String>,
    /// Partner to send to
    pub partner_id: String,
    /// Virtual file name
    pub virtual_file: String,
    /// Poll interval in seconds
    pub poll_interval_secs: u64,
    /// Delete after successful transfer
    pub delete_after_send: bool,
    /// Move to directory after transfer (alternative to delete)
    pub move_to: Option<PathBuf>,
}

impl Default for WatchConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("."),
            pattern: None,
            partner_id: String::new(),
            virtual_file: String::new(),
            poll_interval_secs: 30,
            delete_after_send: false,
            move_to: None,
        }
    }
}

/// File state for change detection
#[derive(Debug, Clone)]
struct FileState {
    path: PathBuf,
    size: u64,
    modified: SystemTime,
    sent: bool,
}

/// Directory watcher using polling
pub struct DirectoryWatcher {
    config: WatchConfig,
    known_files: HashMap<PathBuf, FileState>,
    event_tx: mpsc::Sender<FileEvent>,
}

impl DirectoryWatcher {
    pub fn new(config: WatchConfig, event_tx: mpsc::Sender<FileEvent>) -> Self {
        Self {
            config,
            known_files: HashMap::new(),
            event_tx,
        }
    }

    /// Start watching the directory
    pub async fn watch(&mut self) {
        let mut poll_interval = interval(Duration::from_secs(self.config.poll_interval_secs));

        info!(
            "Starting directory watch: {:?} (interval: {}s)",
            self.config.path, self.config.poll_interval_secs
        );

        loop {
            poll_interval.tick().await;

            if let Err(e) = self.poll().await {
                error!("Poll error for {:?}: {}", self.config.path, e);
            }
        }
    }

    /// Poll the directory for changes
    async fn poll(&mut self) -> std::io::Result<()> {
        let current_files = self.scan_directory()?;

        // Detect new and modified files
        for (path, state) in &current_files {
            match self.known_files.get(path) {
                None => {
                    // New file
                    debug!("New file detected: {:?}", path);
                    let _ = self.event_tx.send(FileEvent::Created(path.clone())).await;
                }
                Some(old_state) => {
                    // Check if modified
                    if state.modified > old_state.modified || state.size != old_state.size {
                        debug!("Modified file detected: {:?}", path);
                        let _ = self.event_tx.send(FileEvent::Modified(path.clone())).await;
                    }
                }
            }
        }

        // Detect deleted files
        let current_paths: HashSet<_> = current_files.keys().collect();
        let deleted: Vec<_> = self
            .known_files
            .keys()
            .filter(|p| !current_paths.contains(p))
            .cloned()
            .collect();

        for path in deleted {
            debug!("Deleted file detected: {:?}", path);
            let _ = self.event_tx.send(FileEvent::Deleted(path.clone())).await;
            self.known_files.remove(&path);
        }

        // Update known files
        self.known_files = current_files;

        Ok(())
    }

    /// Scan directory for files
    fn scan_directory(&self) -> std::io::Result<HashMap<PathBuf, FileState>> {
        let mut files = HashMap::new();

        if !self.config.path.exists() {
            warn!("Watch directory does not exist: {:?}", self.config.path);
            return Ok(files);
        }

        for entry in std::fs::read_dir(&self.config.path)? {
            let entry = entry?;
            let path = entry.path();

            if !path.is_file() {
                continue;
            }

            // Check pattern match
            if let Some(pattern) = &self.config.pattern {
                if !self.matches_pattern(&path, pattern) {
                    continue;
                }
            }

            let metadata = entry.metadata()?;
            let state = FileState {
                path: path.clone(),
                size: metadata.len(),
                modified: metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                sent: false,
            };

            files.insert(path, state);
        }

        Ok(files)
    }

    /// Check if path matches glob pattern
    fn matches_pattern(&self, path: &Path, pattern: &str) -> bool {
        let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

        // Simple glob matching (supports * and ?)
        glob_match(pattern, filename)
    }

    /// Mark a file as sent
    pub fn mark_sent(&mut self, path: &Path) {
        if let Some(state) = self.known_files.get_mut(path) {
            state.sent = true;
        }
    }

    /// Handle post-transfer action (delete or move)
    pub async fn post_transfer(&self, path: &Path) -> std::io::Result<()> {
        if self.config.delete_after_send {
            info!("Deleting sent file: {:?}", path);
            std::fs::remove_file(path)?;
        } else if let Some(move_to) = &self.config.move_to {
            let filename = path.file_name().unwrap();
            let dest = move_to.join(filename);
            info!("Moving sent file: {:?} -> {:?}", path, dest);
            std::fs::rename(path, dest)?;
        }
        Ok(())
    }
}

/// Simple glob pattern matching
fn glob_match(pattern: &str, text: &str) -> bool {
    let mut pi = pattern.chars().peekable();
    let mut ti = text.chars().peekable();

    while let Some(pc) = pi.next() {
        match pc {
            '*' => {
                // Skip consecutive stars
                while pi.peek() == Some(&'*') {
                    pi.next();
                }

                // If star is at end, match rest
                if pi.peek().is_none() {
                    return true;
                }

                // Try matching remaining pattern at each position
                let remaining: String = pi.collect();
                while ti.peek().is_some() {
                    let rest: String = ti.clone().collect();
                    if glob_match(&remaining, &rest) {
                        return true;
                    }
                    ti.next();
                }
                return glob_match(&remaining, "");
            }
            '?' => {
                if ti.next().is_none() {
                    return false;
                }
            }
            c => {
                if ti.next() != Some(c) {
                    return false;
                }
            }
        }
    }

    ti.peek().is_none()
}

/// Watch manager for multiple directories
pub struct WatchManager {
    configs: Vec<WatchConfig>,
    event_rx: mpsc::Receiver<FileEvent>,
    event_tx: mpsc::Sender<FileEvent>,
}

impl WatchManager {
    pub fn new(configs: Vec<WatchConfig>) -> Self {
        let (event_tx, event_rx) = mpsc::channel(100);
        Self {
            configs,
            event_rx,
            event_tx,
        }
    }

    /// Start all watchers
    pub async fn start(&mut self) {
        for config in self.configs.clone() {
            let tx = self.event_tx.clone();
            tokio::spawn(async move {
                let mut watcher = DirectoryWatcher::new(config, tx);
                watcher.watch().await;
            });
        }
    }

    /// Get next file event
    pub async fn next_event(&mut self) -> Option<FileEvent> {
        self.event_rx.recv().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glob_match() {
        // Exact match
        assert!(glob_match("file.txt", "file.txt"));
        assert!(!glob_match("file.txt", "file.xml"));

        // Star wildcard
        assert!(glob_match("*.txt", "file.txt"));
        assert!(glob_match("*.txt", "document.txt"));
        assert!(!glob_match("*.txt", "file.xml"));

        // Star in middle
        assert!(glob_match("file*.txt", "file123.txt"));
        assert!(glob_match("file*.txt", "file.txt"));

        // Question mark
        assert!(glob_match("file?.txt", "file1.txt"));
        assert!(!glob_match("file?.txt", "file12.txt"));

        // Complex patterns
        assert!(glob_match("*.xml", "orders.xml"));
        assert!(glob_match("order_*.xml", "order_2026.xml"));
        assert!(glob_match("*_*.*", "order_2026.xml"));
    }

    #[test]
    fn test_watch_config_default() {
        let config = WatchConfig::default();
        assert_eq!(config.poll_interval_secs, 30);
        assert!(!config.delete_after_send);
        assert!(config.move_to.is_none());
    }

    #[tokio::test]
    async fn test_file_event() {
        let (tx, mut rx) = mpsc::channel(10);

        tx.send(FileEvent::Created(PathBuf::from("/test/file.txt")))
            .await
            .unwrap();

        let event = rx.recv().await.unwrap();
        assert!(matches!(event, FileEvent::Created(_)));
    }
}
