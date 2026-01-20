//! Transfer state persistence for resumable transfers.
//! 
//! Reserved for transfer resume functionality.
#![allow(dead_code)]

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::{debug, info};

/// Persistent state for a transfer that can be resumed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferState {
    pub transfer_id: String,
    pub virtual_file: String,
    pub sender_partner: String,
    pub receiver_partner: String,
    pub total_chunks: u64,
    pub total_bytes: u64,
    pub chunk_size: u32,
    pub file_hash: String,
    pub received_chunks: HashSet<u64>,
    pub chunk_hashes: Vec<(u64, String)>,
    pub started_at: String,
    pub last_updated: String,
}

impl TransferState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        transfer_id: String,
        virtual_file: String,
        sender_partner: String,
        receiver_partner: String,
        total_chunks: u64,
        total_bytes: u64,
        chunk_size: u32,
        file_hash: String,
        chunk_hashes: Vec<(u64, String)>,
    ) -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        Self {
            transfer_id,
            virtual_file,
            sender_partner,
            receiver_partner,
            total_chunks,
            total_bytes,
            chunk_size,
            file_hash,
            received_chunks: HashSet::new(),
            chunk_hashes,
            started_at: now.clone(),
            last_updated: now,
        }
    }

    pub fn mark_chunk_received(&mut self, chunk_index: u64) {
        self.received_chunks.insert(chunk_index);
        self.last_updated = chrono::Utc::now().to_rfc3339();
    }

    pub fn is_chunk_received(&self, chunk_index: u64) -> bool {
        self.received_chunks.contains(&chunk_index)
    }

    pub fn received_count(&self) -> u64 {
        self.received_chunks.len() as u64
    }

    pub fn pending_chunks(&self) -> Vec<u64> {
        (0..self.total_chunks)
            .filter(|i| !self.received_chunks.contains(i))
            .collect()
    }

    pub fn is_complete(&self) -> bool {
        self.received_chunks.len() as u64 == self.total_chunks
    }

    pub fn progress_percent(&self) -> f64 {
        if self.total_chunks == 0 {
            return 100.0;
        }
        (self.received_chunks.len() as f64 / self.total_chunks as f64) * 100.0
    }
}

/// Store for persisting transfer states
pub struct TransferStateStore {
    base_dir: PathBuf,
}

impl TransferStateStore {
    pub fn new<P: AsRef<Path>>(base_dir: P) -> io::Result<Self> {
        let base_dir = base_dir.as_ref().to_path_buf();
        fs::create_dir_all(&base_dir)?;
        Ok(Self { base_dir })
    }

    fn state_path(&self, transfer_id: &str) -> PathBuf {
        self.base_dir.join(format!("{}.json", transfer_id))
    }

    pub fn save(&self, state: &TransferState) -> io::Result<()> {
        let path = self.state_path(&state.transfer_id);
        let file = File::create(&path)?;
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, state)
            .map_err(io::Error::other)?;
        debug!(
            "Saved transfer state: {} ({} chunks received)",
            state.transfer_id,
            state.received_count()
        );
        Ok(())
    }

    pub fn load(&self, transfer_id: &str) -> io::Result<TransferState> {
        let path = self.state_path(transfer_id);
        let file = File::open(&path)?;
        let reader = BufReader::new(file);
        serde_json::from_reader(reader).map_err(io::Error::other)
    }

    pub fn exists(&self, transfer_id: &str) -> bool {
        self.state_path(transfer_id).exists()
    }

    pub fn delete(&self, transfer_id: &str) -> io::Result<()> {
        let path = self.state_path(transfer_id);
        if path.exists() {
            fs::remove_file(&path)?;
            debug!("Deleted transfer state: {}", transfer_id);
        }
        Ok(())
    }

    pub fn find_by_virtual_file(&self, virtual_file: &str) -> io::Result<Option<TransferState>> {
        for entry in fs::read_dir(&self.base_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map(|e| e == "json").unwrap_or(false) {
                if let Ok(state) = self.load_from_path(&path) {
                    if state.virtual_file == virtual_file && !state.is_complete() {
                        return Ok(Some(state));
                    }
                }
            }
        }
        Ok(None)
    }

    fn load_from_path(&self, path: &Path) -> io::Result<TransferState> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        serde_json::from_reader(reader).map_err(io::Error::other)
    }

    pub fn list_incomplete(&self) -> io::Result<Vec<TransferState>> {
        let mut states = Vec::new();
        if !self.base_dir.exists() {
            return Ok(states);
        }

        for entry in fs::read_dir(&self.base_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map(|e| e == "json").unwrap_or(false) {
                if let Ok(state) = self.load_from_path(&path) {
                    if !state.is_complete() {
                        states.push(state);
                    }
                }
            }
        }
        Ok(states)
    }

    pub fn cleanup_completed(&self) -> io::Result<usize> {
        let mut count = 0;
        if !self.base_dir.exists() {
            return Ok(0);
        }

        for entry in fs::read_dir(&self.base_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map(|e| e == "json").unwrap_or(false) {
                if let Ok(state) = self.load_from_path(&path) {
                    if state.is_complete() {
                        fs::remove_file(&path)?;
                        count += 1;
                    }
                }
            }
        }
        info!("Cleaned up {} completed transfer states", count);
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_transfer_state() {
        let mut state = TransferState::new(
            "transfer-1".into(),
            "invoices".into(),
            "sender".into(),
            "receiver".into(),
            10,
            10000,
            1024,
            "hash123".into(),
            vec![],
        );

        assert_eq!(state.received_count(), 0);
        assert_eq!(state.pending_chunks().len(), 10);
        assert!(!state.is_complete());

        state.mark_chunk_received(0);
        state.mark_chunk_received(5);
        assert_eq!(state.received_count(), 2);
        assert!(state.is_chunk_received(0));
        assert!(state.is_chunk_received(5));
        assert!(!state.is_chunk_received(1));

        // Mark all chunks received
        for i in 0..10 {
            state.mark_chunk_received(i);
        }
        assert!(state.is_complete());
        assert_eq!(state.pending_chunks().len(), 0);
    }

    #[test]
    fn test_transfer_state_store() {
        let temp = TempDir::new().unwrap();
        let store = TransferStateStore::new(temp.path()).unwrap();

        let mut state = TransferState::new(
            "transfer-1".into(),
            "invoices".into(),
            "sender".into(),
            "receiver".into(),
            5,
            5000,
            1024,
            "hash123".into(),
            vec![],
        );

        state.mark_chunk_received(0);
        state.mark_chunk_received(2);

        // Save
        store.save(&state).unwrap();
        assert!(store.exists("transfer-1"));

        // Load
        let loaded = store.load("transfer-1").unwrap();
        assert_eq!(loaded.transfer_id, "transfer-1");
        assert_eq!(loaded.received_count(), 2);
        assert!(loaded.is_chunk_received(0));
        assert!(loaded.is_chunk_received(2));

        // Find by virtual file
        let found = store.find_by_virtual_file("invoices").unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().transfer_id, "transfer-1");

        // Delete
        store.delete("transfer-1").unwrap();
        assert!(!store.exists("transfer-1"));
    }
}
