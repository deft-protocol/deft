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

#[allow(dead_code)]
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
        let chunk_count = size.div_ceil(self.chunk_size as u64);

        let modified = metadata
            .modified()
            .ok()
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
        let vf = files.get(name).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "Virtual file not found")
        })?;

        let mut file = File::open(&vf.physical_path)?;
        let chunker = Chunker::new(self.chunk_size);
        let file_chunks = chunker.compute_chunks(&mut file)?;

        let metadata = std::fs::metadata(&vf.physical_path)?;
        let modified = metadata
            .modified()
            .ok()
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

        let chunks: Vec<ChunkInfo> = file_chunks
            .chunks
            .iter()
            .map(|c| ChunkInfo {
                index: c.index,
                size: c.size,
                hash: c.hash.clone(),
            })
            .collect();

        Ok((info, chunks))
    }

    pub fn read_chunk(&self, name: &str, chunk_index: u64) -> std::io::Result<Vec<u8>> {
        let files = self.files.read().unwrap();
        let vf = files.get(name).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "Virtual file not found")
        })?;

        let mut file = File::open(&vf.physical_path)?;
        let chunker = Chunker::new(self.chunk_size);
        chunker.read_chunk(&mut file, chunk_index)
    }

    pub fn list_for_partner(&self, allowed_files: &[String]) -> Vec<VirtualFileInfo> {
        allowed_files
            .iter()
            .filter_map(|name| self.get_info(name))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn create_test_file(dir: &TempDir, name: &str, content: &[u8]) -> PathBuf {
        let path = dir.path().join(name);
        let mut file = File::create(&path).unwrap();
        file.write_all(content).unwrap();
        path
    }

    #[test]
    fn test_virtual_file_manager_new() {
        let manager = VirtualFileManager::new(4096);
        assert_eq!(manager.chunk_size, 4096);
    }

    #[test]
    fn test_register_and_get_info() {
        let temp = TempDir::new().unwrap();
        let path = create_test_file(&temp, "test.txt", b"hello world");

        let manager = VirtualFileManager::new(1024);
        let config = VirtualFileConfig {
            name: "test-file".to_string(),
            path: path.to_string_lossy().to_string(),
            direction: Direction::Send,
        };

        manager.register(&config).unwrap();

        let info = manager.get_info("test-file").unwrap();
        assert_eq!(info.name, "test-file");
        assert_eq!(info.size, 11);
        assert_eq!(info.chunk_size, 1024);
    }

    #[test]
    fn test_get_info_not_found() {
        let manager = VirtualFileManager::new(1024);
        assert!(manager.get_info("nonexistent").is_none());
    }

    #[test]
    fn test_list_for_partner() {
        let temp = TempDir::new().unwrap();
        let path1 = create_test_file(&temp, "file1.txt", b"content1");
        let path2 = create_test_file(&temp, "file2.txt", b"content2");

        let manager = VirtualFileManager::new(1024);

        manager
            .register(&VirtualFileConfig {
                name: "vf1".to_string(),
                path: path1.to_string_lossy().to_string(),
                direction: Direction::Send,
            })
            .unwrap();

        manager
            .register(&VirtualFileConfig {
                name: "vf2".to_string(),
                path: path2.to_string_lossy().to_string(),
                direction: Direction::Receive,
            })
            .unwrap();

        let list = manager.list_for_partner(&["vf1".to_string(), "vf2".to_string()]);
        assert_eq!(list.len(), 2);

        let partial = manager.list_for_partner(&["vf1".to_string()]);
        assert_eq!(partial.len(), 1);
        assert_eq!(partial[0].name, "vf1");
    }

    #[test]
    fn test_list_for_partner_empty() {
        let manager = VirtualFileManager::new(1024);
        let list = manager.list_for_partner(&[]);
        assert!(list.is_empty());
    }

    #[test]
    fn test_list_for_partner_nonexistent() {
        let manager = VirtualFileManager::new(1024);
        let list = manager.list_for_partner(&["nonexistent".to_string()]);
        assert!(list.is_empty());
    }

    #[test]
    fn test_virtual_file_struct() {
        let vf = VirtualFile {
            name: "test-vf".to_string(),
            physical_path: PathBuf::from("/data/test.txt"),
            direction: Direction::Send,
            chunks: None,
        };

        assert_eq!(vf.name, "test-vf");
        assert_eq!(vf.physical_path, PathBuf::from("/data/test.txt"));
        assert!(matches!(vf.direction, Direction::Send));
        assert!(vf.chunks.is_none());
    }

    #[test]
    fn test_compute_chunks_file_not_found() {
        let manager = VirtualFileManager::new(1024);
        let result = manager.compute_chunks("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_direction_conversion() {
        let send_dir = Direction::Send;
        let recv_dir = Direction::Receive;

        let send_proto = match send_dir {
            Direction::Send => FileDirection::Send,
            Direction::Receive => FileDirection::Receive,
        };
        assert!(matches!(send_proto, FileDirection::Send));

        let recv_proto = match recv_dir {
            Direction::Send => FileDirection::Send,
            Direction::Receive => FileDirection::Receive,
        };
        assert!(matches!(recv_proto, FileDirection::Receive));
    }

    #[test]
    fn test_register_multiple_files() {
        let temp = TempDir::new().unwrap();
        let manager = VirtualFileManager::new(2048);

        for i in 0..5 {
            let path = create_test_file(&temp, &format!("file{}.txt", i), b"test content");
            manager
                .register(&VirtualFileConfig {
                    name: format!("vf_{}", i),
                    path: path.to_string_lossy().to_string(),
                    direction: if i % 2 == 0 {
                        Direction::Send
                    } else {
                        Direction::Receive
                    },
                })
                .unwrap();
        }

        // Verify all registered
        for i in 0..5 {
            let info = manager.get_info(&format!("vf_{}", i));
            assert!(info.is_some());
        }
    }
}
