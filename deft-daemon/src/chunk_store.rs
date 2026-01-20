//! Chunk storage and file assembly.
//!
//! Some methods reserved for advanced transfer scenarios.
#![allow(dead_code)]

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use tracing::{debug, info};

/// Stores chunks on disk and reassembles them into the final file
pub struct ChunkStore {
    base_dir: PathBuf,
}

impl ChunkStore {
    pub fn new<P: AsRef<Path>>(base_dir: P) -> io::Result<Self> {
        let base_dir = base_dir.as_ref().to_path_buf();
        fs::create_dir_all(&base_dir)?;
        Ok(Self { base_dir })
    }

    /// Get the directory for a specific transfer
    fn transfer_dir(&self, transfer_id: &str) -> PathBuf {
        self.base_dir.join("transfers").join(transfer_id)
    }

    /// Get the path for a specific chunk file
    fn chunk_path(&self, transfer_id: &str, chunk_index: u64) -> PathBuf {
        self.transfer_dir(transfer_id)
            .join(format!("chunk_{:08}", chunk_index))
    }

    /// Initialize storage for a new transfer
    pub fn init_transfer(&self, transfer_id: &str) -> io::Result<()> {
        let dir = self.transfer_dir(transfer_id);
        fs::create_dir_all(&dir)?;
        debug!("Initialized transfer storage: {:?}", dir);
        Ok(())
    }

    /// Store a chunk to disk
    pub fn store_chunk(&self, transfer_id: &str, chunk_index: u64, data: &[u8]) -> io::Result<()> {
        let dir = self.transfer_dir(transfer_id);
        fs::create_dir_all(&dir)?;

        let path = self.chunk_path(transfer_id, chunk_index);
        let mut file = File::create(&path)?;
        file.write_all(data)?;
        file.sync_all()?;

        debug!(
            "Stored chunk {} ({} bytes) at {:?}",
            chunk_index,
            data.len(),
            path
        );
        Ok(())
    }

    /// Read a chunk from disk
    pub fn read_chunk(&self, transfer_id: &str, chunk_index: u64) -> io::Result<Vec<u8>> {
        let path = self.chunk_path(transfer_id, chunk_index);
        fs::read(&path)
    }

    /// Check if a chunk exists
    pub fn has_chunk(&self, transfer_id: &str, chunk_index: u64) -> bool {
        self.chunk_path(transfer_id, chunk_index).exists()
    }

    /// Get list of stored chunk indices for a transfer
    pub fn list_chunks(&self, transfer_id: &str) -> io::Result<Vec<u64>> {
        let dir = self.transfer_dir(transfer_id);
        if !dir.exists() {
            return Ok(vec![]);
        }

        let mut chunks = Vec::new();
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if let Some(index_str) = name_str.strip_prefix("chunk_") {
                if let Ok(index) = index_str.parse::<u64>() {
                    chunks.push(index);
                }
            }
        }
        chunks.sort();
        Ok(chunks)
    }

    /// Assemble all chunks into the final file
    pub fn assemble_file(
        &self,
        transfer_id: &str,
        output_path: &Path,
        total_chunks: u64,
        chunk_size: u32,
        total_bytes: u64,
    ) -> io::Result<()> {
        // Ensure parent directory exists
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut output = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(output_path)?;

        let mut bytes_written: u64 = 0;

        for chunk_index in 0..total_chunks {
            let chunk_data = self.read_chunk(transfer_id, chunk_index)?;

            // For the last chunk, we might need to truncate
            let expected_size = if chunk_index == total_chunks - 1 {
                (total_bytes - (chunk_index * chunk_size as u64)) as usize
            } else {
                chunk_size as usize
            };

            let data_to_write = if chunk_data.len() > expected_size {
                &chunk_data[..expected_size]
            } else {
                &chunk_data
            };

            output.write_all(data_to_write)?;
            bytes_written += data_to_write.len() as u64;
        }

        output.sync_all()?;
        info!(
            "Assembled file {:?} ({} bytes from {} chunks)",
            output_path, bytes_written, total_chunks
        );

        Ok(())
    }

    /// Clean up chunks after successful transfer
    pub fn cleanup_transfer(&self, transfer_id: &str) -> io::Result<()> {
        let dir = self.transfer_dir(transfer_id);
        if dir.exists() {
            fs::remove_dir_all(&dir)?;
            debug!("Cleaned up transfer storage: {:?}", dir);
        }
        Ok(())
    }

    /// Get total bytes stored for a transfer
    pub fn stored_bytes(&self, transfer_id: &str) -> io::Result<u64> {
        let chunks = self.list_chunks(transfer_id)?;
        let mut total = 0u64;
        for chunk_index in chunks {
            let path = self.chunk_path(transfer_id, chunk_index);
            total += fs::metadata(&path)?.len();
        }
        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_store_and_read_chunk() {
        let temp = TempDir::new().unwrap();
        let store = ChunkStore::new(temp.path()).unwrap();

        let data = b"Hello, chunk!";
        store.store_chunk("transfer1", 0, data).unwrap();

        let read_data = store.read_chunk("transfer1", 0).unwrap();
        assert_eq!(read_data, data);
    }

    #[test]
    fn test_list_chunks() {
        let temp = TempDir::new().unwrap();
        let store = ChunkStore::new(temp.path()).unwrap();

        store.store_chunk("transfer1", 0, b"chunk0").unwrap();
        store.store_chunk("transfer1", 2, b"chunk2").unwrap();
        store.store_chunk("transfer1", 1, b"chunk1").unwrap();

        let chunks = store.list_chunks("transfer1").unwrap();
        assert_eq!(chunks, vec![0, 1, 2]);
    }

    #[test]
    fn test_assemble_file() {
        let temp = TempDir::new().unwrap();
        let store = ChunkStore::new(temp.path()).unwrap();

        // Store 3 chunks of 10 bytes each, but total file is 25 bytes
        store.store_chunk("transfer1", 0, b"0123456789").unwrap();
        store.store_chunk("transfer1", 1, b"ABCDEFGHIJ").unwrap();
        store.store_chunk("transfer1", 2, b"XYZ__").unwrap(); // Last chunk partial

        let output_path = temp.path().join("output.bin");
        store
            .assemble_file("transfer1", &output_path, 3, 10, 25)
            .unwrap();

        let content = fs::read_to_string(&output_path).unwrap();
        assert_eq!(content, "0123456789ABCDEFGHIJXYZ__");
    }

    #[test]
    fn test_cleanup_transfer() {
        let temp = TempDir::new().unwrap();
        let store = ChunkStore::new(temp.path()).unwrap();

        store.store_chunk("transfer1", 0, b"data").unwrap();
        assert!(store.has_chunk("transfer1", 0));

        store.cleanup_transfer("transfer1").unwrap();
        assert!(!store.has_chunk("transfer1", 0));
    }
}
