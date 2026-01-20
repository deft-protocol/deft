use serde::{Deserialize, Serialize};
use std::fmt;

use crate::{Capabilities, RiftError};

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
        Self { start: index, end: index }
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
    type Err = RiftError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((start, end)) = s.split_once('-') {
            let start: u64 = start.parse()
                .map_err(|_| RiftError::InvalidChunkRange(s.to_string()))?;
            let end: u64 = end.parse()
                .map_err(|_| RiftError::InvalidChunkRange(s.to_string()))?;
            if start > end {
                return Err(RiftError::InvalidChunkRange(s.to_string()));
            }
            Ok(ChunkRange::new(start, end))
        } else {
            let index: u64 = s.parse()
                .map_err(|_| RiftError::InvalidChunkRange(s.to_string()))?;
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
        }
    }

    pub fn resume_transfer(virtual_file: impl Into<String>, transfer_id: impl Into<String>) -> Self {
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

    pub fn put(virtual_file: impl Into<String>, chunk_index: u64, size: u64, hash: impl Into<String>) -> Self {
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
}

impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Command::Hello { version, capabilities } => {
                if capabilities.caps.is_empty() && capabilities.window_size.is_none() {
                    write!(f, "RIFT HELLO {}", version)
                } else {
                    write!(f, "RIFT HELLO {} {}", version, capabilities)
                }
            }
            Command::Auth { partner_id } => {
                write!(f, "RIFT AUTH {}", partner_id)
            }
            Command::Discover => {
                write!(f, "RIFT DISCOVER")
            }
            Command::Describe { virtual_file } => {
                write!(f, "RIFT DESCRIBE {}", virtual_file)
            }
            Command::Get { virtual_file, chunks } => {
                write!(f, "RIFT GET {} CHUNKS {}", virtual_file, chunks)
            }
            Command::BeginTransfer { virtual_file, total_chunks, total_bytes, file_hash } => {
                write!(f, "RIFT BEGIN_TRANSFER {} {} {} {}", virtual_file, total_chunks, total_bytes, file_hash)
            }
            Command::ResumeTransfer { virtual_file, transfer_id } => {
                write!(f, "RIFT RESUME_TRANSFER {} {}", virtual_file, transfer_id)
            }
            Command::GetStatus { virtual_file } => {
                write!(f, "RIFT GET_STATUS {}", virtual_file)
            }
            Command::Put { virtual_file, chunk_index, size, hash, nonce, compressed } => {
                write!(f, "RIFT PUT {} CHUNK {} SIZE:{} HASH:{}", virtual_file, chunk_index, size, hash)?;
                if let Some(n) = nonce {
                    write!(f, " NONCE:{}", n)?;
                }
                if *compressed {
                    write!(f, " COMPRESSED")?;
                }
                Ok(())
            }
            Command::Bye => {
                write!(f, "RIFT BYE")
            }
        }
    }
}
