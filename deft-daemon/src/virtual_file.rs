use std::collections::HashMap;
use std::fs::File;
use std::path::PathBuf;
use std::sync::RwLock;

use deft_common::{Chunker, FileChunks};
use deft_protocol::{ChunkInfo, FileDirection, VirtualFileInfo};

use crate::config::{Direction, VirtualFileConfig};

pub struct VirtualFileManager {
    files: RwLock<HashMap<String, VirtualFile>>,
    chunk_size: u32,
}

pub struct VirtualFile {
    pub name: String,
    pub physical_path: PathBuf,
    pub direction: Direction,
    pub chunks: Option<FileChunks>,
}

impl VirtualFileManager {
    pub fn new(chunk_size: u32) -> Self {
        Self {
            files: RwLock::new(HashMap::new()),
            chunk_size,
        }
    }

    pub fn register(&self, config: &VirtualFileConfig) -> std::io::Result<()> {
        let path = PathBuf::from(&config.path);
        
        let vf = VirtualFile {
            name: config.name.clone(),
            physical_path: path,
            direction: config.direction,
            chunks: None,
        };

        self.files.write().unwrap().insert(config.name.clone(), vf);
        Ok(())
    }

    pub fn get_info(&self, name: &str) -> Option<VirtualFileInfo> {
        let files = self.files.read().unwrap();
        let vf = files.get(name)?;

        let metadata = std::fs::metadata(&vf.physical_path).ok()?;
        let size = metadata.len();
        let chunk_count = (size + self.chunk_size as u64 - 1) / self.chunk_size as u64;

        let modified = metadata.modified().ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs().to_string())
            .unwrap_or_default();

        Some(VirtualFileInfo {
            name: vf.name.clone(),
            size,
            chunk_count,
            chunk_size: self.chunk_size,
            hash: String::new(), // Computed on demand
            modified,
            direction: match vf.direction {
                Direction::Send => FileDirection::Send,
                Direction::Receive => FileDirection::Receive,
            },
        })
    }

    pub fn compute_chunks(&self, name: &str) -> std::io::Result<(VirtualFileInfo, Vec<ChunkInfo>)> {
        let files = self.files.read().unwrap();
        let vf = files.get(name)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "Virtual file not found"))?;

        let mut file = File::open(&vf.physical_path)?;
        let chunker = Chunker::new(self.chunk_size);
        let file_chunks = chunker.compute_chunks(&mut file)?;

        let metadata = std::fs::metadata(&vf.physical_path)?;
        let modified = metadata.modified().ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs().to_string())
            .unwrap_or_default();

        let info = VirtualFileInfo {
            name: vf.name.clone(),
            size: file_chunks.total_size,
            chunk_count: file_chunks.chunk_count(),
            chunk_size: file_chunks.chunk_size,
            hash: file_chunks.file_hash.clone(),
            modified,
            direction: match vf.direction {
                Direction::Send => FileDirection::Send,
                Direction::Receive => FileDirection::Receive,
            },
        };

        let chunks: Vec<ChunkInfo> = file_chunks.chunks.iter().map(|c| ChunkInfo {
            index: c.index,
            size: c.size,
            hash: c.hash.clone(),
        }).collect();

        Ok((info, chunks))
    }

    pub fn read_chunk(&self, name: &str, chunk_index: u64) -> std::io::Result<Vec<u8>> {
        let files = self.files.read().unwrap();
        let vf = files.get(name)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "Virtual file not found"))?;

        let mut file = File::open(&vf.physical_path)?;
        let chunker = Chunker::new(self.chunk_size);
        chunker.read_chunk(&mut file, chunk_index)
    }

    pub fn list_for_partner(&self, allowed_files: &[String]) -> Vec<VirtualFileInfo> {
        allowed_files.iter()
            .filter_map(|name| self.get_info(name))
            .collect()
    }
}
