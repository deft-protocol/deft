use serde::{Deserialize, Serialize};
use std::fmt;

use crate::{Capabilities, DeftError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkRange {
    pub start: u64,
    pub end: u64,
}

impl ChunkRange {
    pub fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }

    pub fn single(index: u64) -> Self {
        Self {
            start: index,
            end: index,
        }
    }

    pub fn count(&self) -> u64 {
        self.end - self.start + 1
    }
}

impl fmt::Display for ChunkRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.start == self.end {
            write!(f, "{}", self.start)
        } else {
            write!(f, "{}-{}", self.start, self.end)
        }
    }
}

impl std::str::FromStr for ChunkRange {
    type Err = DeftError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((start, end)) = s.split_once('-') {
            let start: u64 = start
                .parse()
                .map_err(|_| DeftError::InvalidChunkRange(s.to_string()))?;
            let end: u64 = end
                .parse()
                .map_err(|_| DeftError::InvalidChunkRange(s.to_string()))?;
            if start > end {
                return Err(DeftError::InvalidChunkRange(s.to_string()));
            }
            Ok(ChunkRange::new(start, end))
        } else {
            let index: u64 = s
                .parse()
                .map_err(|_| DeftError::InvalidChunkRange(s.to_string()))?;
            Ok(ChunkRange::single(index))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Command {
    Hello {
        version: String,
        capabilities: Capabilities,
    },
    Auth {
        partner_id: String,
    },
    Discover,
    Describe {
        virtual_file: String,
    },
    Get {
        virtual_file: String,
        chunks: ChunkRange,
    },
    BeginTransfer {
        virtual_file: String,
        total_chunks: u64,
        total_bytes: u64,
        file_hash: String,
        /// Sender's transfer_id for correlation (v2.1)
        #[serde(default)]
        transfer_id: Option<String>,
    },
    ResumeTransfer {
        virtual_file: String,
        transfer_id: String,
    },
    GetStatus {
        virtual_file: String,
    },
    Put {
        virtual_file: String,
        chunk_index: u64,
        size: u64,
        hash: String,
        #[serde(default)]
        nonce: Option<u64>,
        #[serde(default)]
        compressed: bool,
    },
    /// Request file signature for delta sync (v2.0)
    DeltaSigReq {
        virtual_file: String,
        block_size: usize,
        /// Optional filename for directory-based virtual files
        filename: Option<String>,
    },
    /// Send delta data to update existing file (v2.0)
    DeltaPut {
        virtual_file: String,
        /// Base64-encoded delta operations
        delta_data: String,
        /// Expected final file hash after applying delta
        final_hash: String,
    },
    /// Pause an active transfer (v2.0)
    PauseTransfer {
        transfer_id: String,
    },
    /// Resume a paused transfer (v2.0)
    ResumeTransferCmd {
        transfer_id: String,
    },
    /// Abort a transfer permanently (v2.0)
    AbortTransfer {
        transfer_id: String,
        reason: Option<String>,
    },
    Bye,
}

impl Command {
    pub fn hello(version: impl Into<String>, capabilities: Capabilities) -> Self {
        Command::Hello {
            version: version.into(),
            capabilities,
        }
    }

    pub fn auth(partner_id: impl Into<String>) -> Self {
        Command::Auth {
            partner_id: partner_id.into(),
        }
    }

    pub fn discover() -> Self {
        Command::Discover
    }

    pub fn describe(virtual_file: impl Into<String>) -> Self {
        Command::Describe {
            virtual_file: virtual_file.into(),
        }
    }

    pub fn get(virtual_file: impl Into<String>, chunks: ChunkRange) -> Self {
        Command::Get {
            virtual_file: virtual_file.into(),
            chunks,
        }
    }

    pub fn begin_transfer(
        virtual_file: impl Into<String>,
        total_chunks: u64,
        total_bytes: u64,
        file_hash: impl Into<String>,
    ) -> Self {
        Command::BeginTransfer {
            virtual_file: virtual_file.into(),
            total_chunks,
            total_bytes,
            file_hash: file_hash.into(),
            transfer_id: None,
        }
    }

    pub fn begin_transfer_with_id(
        virtual_file: impl Into<String>,
        total_chunks: u64,
        total_bytes: u64,
        file_hash: impl Into<String>,
        transfer_id: impl Into<String>,
    ) -> Self {
        Command::BeginTransfer {
            virtual_file: virtual_file.into(),
            total_chunks,
            total_bytes,
            file_hash: file_hash.into(),
            transfer_id: Some(transfer_id.into()),
        }
    }

    pub fn resume_transfer(
        virtual_file: impl Into<String>,
        transfer_id: impl Into<String>,
    ) -> Self {
        Command::ResumeTransfer {
            virtual_file: virtual_file.into(),
            transfer_id: transfer_id.into(),
        }
    }

    pub fn get_status(virtual_file: impl Into<String>) -> Self {
        Command::GetStatus {
            virtual_file: virtual_file.into(),
        }
    }

    pub fn put(
        virtual_file: impl Into<String>,
        chunk_index: u64,
        size: u64,
        hash: impl Into<String>,
    ) -> Self {
        Command::Put {
            virtual_file: virtual_file.into(),
            chunk_index,
            size,
            hash: hash.into(),
            nonce: None,
            compressed: false,
        }
    }

    pub fn put_with_nonce(
        virtual_file: impl Into<String>,
        chunk_index: u64,
        size: u64,
        hash: impl Into<String>,
        nonce: Option<u64>,
    ) -> Self {
        Command::Put {
            virtual_file: virtual_file.into(),
            chunk_index,
            size,
            hash: hash.into(),
            nonce,
            compressed: false,
        }
    }

    pub fn put_compressed(
        virtual_file: impl Into<String>,
        chunk_index: u64,
        size: u64,
        hash: impl Into<String>,
        nonce: Option<u64>,
    ) -> Self {
        Command::Put {
            virtual_file: virtual_file.into(),
            chunk_index,
            size,
            hash: hash.into(),
            nonce,
            compressed: true,
        }
    }

    pub fn bye() -> Self {
        Command::Bye
    }

    /// Request file signature for delta sync (v2.0)
    pub fn delta_sig_req(
        virtual_file: impl Into<String>,
        block_size: usize,
        filename: Option<String>,
    ) -> Self {
        Command::DeltaSigReq {
            virtual_file: virtual_file.into(),
            block_size,
            filename,
        }
    }

    /// Send delta data to update file (v2.0)
    pub fn delta_put(
        virtual_file: impl Into<String>,
        delta_data: impl Into<String>,
        final_hash: impl Into<String>,
    ) -> Self {
        Command::DeltaPut {
            virtual_file: virtual_file.into(),
            delta_data: delta_data.into(),
            final_hash: final_hash.into(),
        }
    }
}

impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Command::Hello {
                version,
                capabilities,
            } => {
                if capabilities.caps.is_empty() && capabilities.window_size.is_none() {
                    write!(f, "DEFT HELLO {}", version)
                } else {
                    write!(f, "DEFT HELLO {} {}", version, capabilities)
                }
            }
            Command::Auth { partner_id } => {
                write!(f, "DEFT AUTH {}", partner_id)
            }
            Command::Discover => {
                write!(f, "DEFT DISCOVER")
            }
            Command::Describe { virtual_file } => {
                write!(f, "DEFT DESCRIBE {}", virtual_file)
            }
            Command::Get {
                virtual_file,
                chunks,
            } => {
                write!(f, "DEFT GET {} CHUNKS {}", virtual_file, chunks)
            }
            Command::BeginTransfer {
                virtual_file,
                total_chunks,
                total_bytes,
                file_hash,
                transfer_id,
            } => {
                if let Some(tid) = transfer_id {
                    write!(
                        f,
                        "DEFT BEGIN_TRANSFER {} {} {} {} TX_ID:{}",
                        virtual_file, total_chunks, total_bytes, file_hash, tid
                    )
                } else {
                    write!(
                        f,
                        "DEFT BEGIN_TRANSFER {} {} {} {}",
                        virtual_file, total_chunks, total_bytes, file_hash
                    )
                }
            }
            Command::ResumeTransfer {
                virtual_file,
                transfer_id,
            } => {
                write!(f, "DEFT RESUME_TRANSFER {} {}", virtual_file, transfer_id)
            }
            Command::GetStatus { virtual_file } => {
                write!(f, "DEFT GET_STATUS {}", virtual_file)
            }
            Command::Put {
                virtual_file,
                chunk_index,
                size,
                hash,
                nonce,
                compressed,
            } => {
                write!(
                    f,
                    "DEFT PUT {} CHUNK {} SIZE:{} HASH:{}",
                    virtual_file, chunk_index, size, hash
                )?;
                if let Some(n) = nonce {
                    write!(f, " NONCE:{}", n)?;
                }
                if *compressed {
                    write!(f, " COMPRESSED")?;
                }
                Ok(())
            }
            Command::Bye => {
                write!(f, "DEFT BYE")
            }
            Command::DeltaSigReq {
                virtual_file,
                block_size,
                filename,
            } => {
                write!(f, "DEFT DELTA_SIG_REQ {} {}", virtual_file, block_size)?;
                if let Some(fname) = filename {
                    write!(f, " FILE:{}", fname)?;
                }
                Ok(())
            }
            Command::DeltaPut {
                virtual_file,
                delta_data,
                final_hash,
            } => {
                write!(
                    f,
                    "DEFT DELTA_PUT {} HASH:{} DATA:{}",
                    virtual_file, final_hash, delta_data
                )
            }
            Command::PauseTransfer { transfer_id } => {
                write!(f, "DEFT PAUSE_TRANSFER {}", transfer_id)
            }
            Command::ResumeTransferCmd { transfer_id } => {
                write!(f, "DEFT RESUME_TRANSFER_CMD {}", transfer_id)
            }
            Command::AbortTransfer {
                transfer_id,
                reason,
            } => {
                if let Some(r) = reason {
                    write!(f, "DEFT ABORT_TRANSFER {} REASON:{}", transfer_id, r)
                } else {
                    write!(f, "DEFT ABORT_TRANSFER {}", transfer_id)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_range_new() {
        let range = ChunkRange::new(5, 10);
        assert_eq!(range.start, 5);
        assert_eq!(range.end, 10);
        assert_eq!(range.count(), 6);
    }

    #[test]
    fn test_chunk_range_single() {
        let range = ChunkRange::single(42);
        assert_eq!(range.start, 42);
        assert_eq!(range.end, 42);
        assert_eq!(range.count(), 1);
    }

    #[test]
    fn test_chunk_range_display() {
        let range = ChunkRange::new(1, 10);
        assert_eq!(format!("{}", range), "1-10");

        let single = ChunkRange::single(5);
        assert_eq!(format!("{}", single), "5");
    }

    #[test]
    fn test_chunk_range_from_str() {
        let range: ChunkRange = "1-10".parse().unwrap();
        assert_eq!(range.start, 1);
        assert_eq!(range.end, 10);

        let single: ChunkRange = "42".parse().unwrap();
        assert_eq!(single.start, 42);
        assert_eq!(single.end, 42);
    }

    #[test]
    fn test_chunk_range_invalid() {
        let result: Result<ChunkRange, _> = "abc".parse();
        assert!(result.is_err());

        let result: Result<ChunkRange, _> = "10-5".parse(); // Invalid: start > end
        assert!(result.is_err());

        let result: Result<ChunkRange, _> = "1-abc".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_command_hello_display() {
        let cmd = Command::Hello {
            version: "2.0".to_string(),
            capabilities: Capabilities::new(),
        };
        let s = format!("{}", cmd);
        assert!(s.contains("DEFT HELLO"));
        assert!(s.contains("2.0"));
    }

    #[test]
    fn test_command_auth_display() {
        let cmd = Command::Auth {
            partner_id: "partner-a".to_string(),
        };
        assert_eq!(format!("{}", cmd), "DEFT AUTH partner-a");
    }

    #[test]
    fn test_command_discover_display() {
        let cmd = Command::Discover;
        assert_eq!(format!("{}", cmd), "DEFT DISCOVER");
    }

    #[test]
    fn test_command_describe_display() {
        let cmd = Command::Describe {
            virtual_file: "invoices".to_string(),
        };
        assert_eq!(format!("{}", cmd), "DEFT DESCRIBE invoices");
    }

    #[test]
    fn test_command_bye_display() {
        let cmd = Command::Bye;
        assert_eq!(format!("{}", cmd), "DEFT BYE");
    }

    #[test]
    fn test_command_pause_transfer_display() {
        let cmd = Command::PauseTransfer {
            transfer_id: "tx-123".to_string(),
        };
        assert_eq!(format!("{}", cmd), "DEFT PAUSE_TRANSFER tx-123");
    }

    #[test]
    fn test_command_resume_transfer_cmd_display() {
        let cmd = Command::ResumeTransferCmd {
            transfer_id: "tx-456".to_string(),
        };
        assert_eq!(format!("{}", cmd), "DEFT RESUME_TRANSFER_CMD tx-456");
    }

    #[test]
    fn test_command_abort_transfer_with_reason() {
        let cmd = Command::AbortTransfer {
            transfer_id: "tx-789".to_string(),
            reason: Some("user cancelled".to_string()),
        };
        let s = format!("{}", cmd);
        assert!(s.contains("DEFT ABORT_TRANSFER tx-789"));
        assert!(s.contains("REASON:user cancelled"));
    }

    #[test]
    fn test_command_abort_transfer_without_reason() {
        let cmd = Command::AbortTransfer {
            transfer_id: "tx-abc".to_string(),
            reason: None,
        };
        assert_eq!(format!("{}", cmd), "DEFT ABORT_TRANSFER tx-abc");
    }

    #[test]
    fn test_command_put_display() {
        let cmd = Command::Put {
            virtual_file: "data".to_string(),
            chunk_index: 5,
            size: 1024,
            hash: "sha256:abc".to_string(),
            nonce: None,
            compressed: false,
        };
        let s = format!("{}", cmd);
        assert!(s.contains("DEFT PUT data CHUNK 5"));
        assert!(s.contains("SIZE:1024"));
        assert!(s.contains("HASH:sha256:abc"));
    }

    #[test]
    fn test_command_put_with_nonce_and_compressed() {
        let cmd = Command::Put {
            virtual_file: "data".to_string(),
            chunk_index: 3,
            size: 512,
            hash: "hash".to_string(),
            nonce: Some(12345),
            compressed: true,
        };
        let s = format!("{}", cmd);
        assert!(s.contains("NONCE:12345"));
        assert!(s.contains("COMPRESSED"));
    }

    #[test]
    fn test_command_delta_sig_req_display() {
        let cmd = Command::DeltaSigReq {
            virtual_file: "file".to_string(),
            block_size: 4096,
            filename: None,
        };
        assert_eq!(format!("{}", cmd), "DEFT DELTA_SIG_REQ file 4096");

        let cmd_with_file = Command::DeltaSigReq {
            virtual_file: "vf".to_string(),
            block_size: 4096,
            filename: Some("test.bin".to_string()),
        };
        assert_eq!(
            format!("{}", cmd_with_file),
            "DEFT DELTA_SIG_REQ vf 4096 FILE:test.bin"
        );
    }

    #[test]
    fn test_command_delta_put_display() {
        let cmd = Command::DeltaPut {
            virtual_file: "file".to_string(),
            delta_data: "base64data".to_string(),
            final_hash: "finalhash".to_string(),
        };
        let s = format!("{}", cmd);
        assert!(s.contains("DEFT DELTA_PUT file"));
        assert!(s.contains("HASH:finalhash"));
        assert!(s.contains("DATA:base64data"));
    }

    #[test]
    fn test_command_serialization() {
        let cmd = Command::Auth {
            partner_id: "test".to_string(),
        };
        let json = serde_json::to_string(&cmd).unwrap();
        let parsed: Command = serde_json::from_str(&json).unwrap();
        assert_eq!(cmd, parsed);
    }

    #[test]
    fn test_chunk_range_serialization() {
        let range = ChunkRange::new(10, 20);
        let json = serde_json::to_string(&range).unwrap();
        let parsed: ChunkRange = serde_json::from_str(&json).unwrap();
        assert_eq!(range, parsed);
    }
}
