use serde::{Deserialize, Serialize};
use std::fmt;

use crate::{Capabilities, DeftErrorCode};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VirtualFileInfo {
    pub name: String,
    pub size: u64,
    pub chunk_count: u64,
    pub chunk_size: u32,
    pub hash: String,
    pub modified: String,
    pub direction: FileDirection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileDirection {
    Send,
    Receive,
}

impl fmt::Display for FileDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileDirection::Send => write!(f, "SEND"),
            FileDirection::Receive => write!(f, "RECV"),
        }
    }
}

impl std::str::FromStr for FileDirection {
    type Err = crate::DeftError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "SEND" => Ok(FileDirection::Send),
            "RECV" | "RECEIVE" => Ok(FileDirection::Receive),
            _ => Err(crate::DeftError::ParseError(format!(
                "Invalid direction: {}",
                s
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkInfo {
    pub index: u64,
    pub size: u32,
    pub hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AckStatus {
    Ok,
    Error(AckErrorReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AckErrorReason {
    HashMismatch,
    Timeout,
    OutOfOrder,
    StorageFull,
    IoError,
    Unknown,
}

impl std::fmt::Display for AckStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AckStatus::Ok => write!(f, "OK"),
            AckStatus::Error(reason) => write!(f, "ERROR {}", reason),
        }
    }
}

impl std::fmt::Display for AckErrorReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AckErrorReason::HashMismatch => write!(f, "HASH_MISMATCH"),
            AckErrorReason::Timeout => write!(f, "TIMEOUT"),
            AckErrorReason::OutOfOrder => write!(f, "OUT_OF_ORDER"),
            AckErrorReason::StorageFull => write!(f, "STORAGE_FULL"),
            AckErrorReason::IoError => write!(f, "IO_ERROR"),
            AckErrorReason::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

impl std::str::FromStr for AckErrorReason {
    type Err = crate::DeftError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "HASH_MISMATCH" => Ok(AckErrorReason::HashMismatch),
            "TIMEOUT" => Ok(AckErrorReason::Timeout),
            "OUT_OF_ORDER" => Ok(AckErrorReason::OutOfOrder),
            "STORAGE_FULL" => Ok(AckErrorReason::StorageFull),
            "IO_ERROR" => Ok(AckErrorReason::IoError),
            _ => Ok(AckErrorReason::Unknown),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferReceipt {
    pub transfer_id: String,
    pub virtual_file: String,
    pub sender_partner: String,
    pub receiver_partner: String,
    pub timestamp_start: String,
    pub timestamp_complete: String,
    pub chunks_total: u64,
    pub total_bytes: u64,
    pub file_hash: String,
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    Welcome {
        version: String,
        capabilities: Capabilities,
        session_id: String,
    },
    AuthOk {
        partner_name: String,
        virtual_files: Vec<String>,
    },
    Files {
        files: Vec<VirtualFileInfo>,
    },
    FileInfo {
        info: VirtualFileInfo,
        chunks: Vec<ChunkInfo>,
    },
    ChunkData {
        virtual_file: String,
        chunk_index: u64,
        data: Vec<u8>,
    },
    ChunkOk {
        virtual_file: String,
        chunk_index: u64,
    },
    TransferAccepted {
        transfer_id: String,
        virtual_file: String,
        window_size: u32,
    },
    ChunkReady {
        virtual_file: String,
        chunk_index: u64,
        size: u64,
    },
    ChunkAck {
        virtual_file: String,
        chunk_index: u64,
        status: AckStatus,
    },
    ChunkAckBatch {
        virtual_file: String,
        ranges: Vec<crate::ChunkRange>,
    },
    TransferComplete {
        virtual_file: String,
        file_hash: String,
        total_size: u64,
        chunk_count: u64,
        signature: Option<String>,
    },
    TransferStatus {
        transfer_id: String,
        virtual_file: String,
        total_chunks: u64,
        received_chunks: u64,
        pending_chunks: Vec<u64>,
    },
    Error {
        code: DeftErrorCode,
        message: Option<String>,
    },
    Goodbye,
    /// Delta signature response (v2.0) - base64-encoded signature
    DeltaSig {
        virtual_file: String,
        signature_data: String,
        file_exists: bool,
    },
    /// Delta applied successfully (v2.0)
    DeltaAck {
        virtual_file: String,
        bytes_written: u64,
        final_hash: String,
    },
    /// Transfer paused acknowledgment (v2.0)
    TransferPaused {
        transfer_id: String,
    },
    /// Transfer resumed acknowledgment (v2.0)
    TransferResumed {
        transfer_id: String,
    },
    /// Transfer aborted acknowledgment (v2.0)
    TransferAborted {
        transfer_id: String,
        reason: Option<String>,
    },
}

impl Response {
    pub fn welcome(
        version: impl Into<String>,
        capabilities: Capabilities,
        session_id: impl Into<String>,
    ) -> Self {
        Response::Welcome {
            version: version.into(),
            capabilities,
            session_id: session_id.into(),
        }
    }

    pub fn auth_ok(partner_name: impl Into<String>, virtual_files: Vec<String>) -> Self {
        Response::AuthOk {
            partner_name: partner_name.into(),
            virtual_files,
        }
    }

    pub fn error(code: DeftErrorCode, message: Option<String>) -> Self {
        Response::Error { code, message }
    }

    pub fn goodbye() -> Self {
        Response::Goodbye
    }
}

impl fmt::Display for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Response::Welcome {
                version,
                capabilities,
                session_id,
            } => {
                if capabilities.caps.is_empty() && capabilities.window_size.is_none() {
                    write!(f, "DEFT WELCOME {} {}", version, session_id)
                } else {
                    write!(
                        f,
                        "DEFT WELCOME {} {} {}",
                        version, capabilities, session_id
                    )
                }
            }
            Response::AuthOk {
                partner_name,
                virtual_files,
            } => {
                let vf_list = virtual_files.join(",");
                write!(f, "DEFT AUTH_OK \"{}\" VF:{}", partner_name, vf_list)
            }
            Response::Files { files } => {
                writeln!(f, "DEFT FILES {}", files.len())?;
                for file in files {
                    writeln!(
                        f,
                        "  {} {} {} {}",
                        file.name, file.size, file.direction, file.modified
                    )?;
                }
                Ok(())
            }
            Response::FileInfo { info, chunks } => {
                writeln!(
                    f,
                    "DEFT FILE_INFO {} SIZE:{} CHUNKS:{} CHUNK_SIZE:{} HASH:{}",
                    info.name, info.size, info.chunk_count, info.chunk_size, info.hash
                )?;
                for chunk in chunks {
                    writeln!(
                        f,
                        "  CHUNK {} SIZE:{} HASH:{}",
                        chunk.index, chunk.size, chunk.hash
                    )?;
                }
                Ok(())
            }
            Response::ChunkData {
                virtual_file,
                chunk_index,
                data,
            } => {
                write!(
                    f,
                    "DEFT CHUNK_DATA {} {} SIZE:{}",
                    virtual_file,
                    chunk_index,
                    data.len()
                )
            }
            Response::ChunkOk {
                virtual_file,
                chunk_index,
            } => {
                write!(f, "DEFT CHUNK_OK {} {}", virtual_file, chunk_index)
            }
            Response::TransferAccepted {
                transfer_id,
                virtual_file,
                window_size,
            } => {
                write!(
                    f,
                    "DEFT TRANSFER_ACCEPTED {} {} WINDOW_SIZE:{}",
                    transfer_id, virtual_file, window_size
                )
            }
            Response::ChunkReady {
                virtual_file,
                chunk_index,
                size,
            } => {
                write!(
                    f,
                    "DEFT CHUNK_READY {} {} SIZE:{}",
                    virtual_file, chunk_index, size
                )
            }
            Response::ChunkAck {
                virtual_file,
                chunk_index,
                status,
            } => {
                write!(
                    f,
                    "DEFT CHUNK_ACK {} {} {}",
                    virtual_file, chunk_index, status
                )
            }
            Response::ChunkAckBatch {
                virtual_file,
                ranges,
            } => {
                let ranges_str: Vec<String> = ranges.iter().map(|r| r.to_string()).collect();
                write!(
                    f,
                    "DEFT CHUNK_ACK_BATCH {} {}",
                    virtual_file,
                    ranges_str.join(",")
                )
            }
            Response::TransferComplete {
                virtual_file,
                file_hash,
                total_size,
                chunk_count,
                signature,
            } => {
                if let Some(sig) = signature {
                    write!(
                        f,
                        "DEFT TRANSFER_COMPLETE {} {} {} {} sig:{}",
                        virtual_file, file_hash, total_size, chunk_count, sig
                    )
                } else {
                    write!(
                        f,
                        "DEFT TRANSFER_COMPLETE {} {} {} {}",
                        virtual_file, file_hash, total_size, chunk_count
                    )
                }
            }
            Response::TransferStatus {
                transfer_id,
                virtual_file,
                total_chunks,
                received_chunks,
                pending_chunks,
            } => {
                let pending_str = pending_chunks
                    .iter()
                    .map(|c| c.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                write!(
                    f,
                    "DEFT TRANSFER_STATUS {} {} {}/{} PENDING:{}",
                    transfer_id, virtual_file, received_chunks, total_chunks, pending_str
                )
            }
            Response::Error { code, message } => match message {
                Some(msg) => write!(f, "DEFT ERROR {} {}", code.code(), msg),
                None => write!(f, "DEFT ERROR {} {}", code.code(), code.message()),
            },
            Response::Goodbye => {
                write!(f, "DEFT GOODBYE")
            }
            Response::DeltaSig {
                virtual_file,
                signature_data,
                file_exists,
            } => {
                write!(
                    f,
                    "DEFT DELTA_SIG {} EXISTS:{} DATA:{}",
                    virtual_file, file_exists, signature_data
                )
            }
            Response::DeltaAck {
                virtual_file,
                bytes_written,
                final_hash,
            } => {
                write!(
                    f,
                    "DEFT DELTA_ACK {} {} HASH:{}",
                    virtual_file, bytes_written, final_hash
                )
            }
            Response::TransferPaused { transfer_id } => {
                write!(f, "DEFT TRANSFER_PAUSED {}", transfer_id)
            }
            Response::TransferResumed { transfer_id } => {
                write!(f, "DEFT TRANSFER_RESUMED {}", transfer_id)
            }
            Response::TransferAborted { transfer_id, reason } => {
                if let Some(r) = reason {
                    write!(f, "DEFT TRANSFER_ABORTED {} REASON:{}", transfer_id, r)
                } else {
                    write!(f, "DEFT TRANSFER_ABORTED {}", transfer_id)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Capability;

    #[test]
    fn test_ack_status_display() {
        assert_eq!(AckStatus::Ok.to_string(), "OK");
        assert_eq!(
            AckStatus::Error(AckErrorReason::HashMismatch).to_string(),
            "ERROR HASH_MISMATCH"
        );
        assert_eq!(
            AckStatus::Error(AckErrorReason::Timeout).to_string(),
            "ERROR TIMEOUT"
        );
        assert_eq!(
            AckStatus::Error(AckErrorReason::OutOfOrder).to_string(),
            "ERROR OUT_OF_ORDER"
        );
        assert_eq!(
            AckStatus::Error(AckErrorReason::StorageFull).to_string(),
            "ERROR STORAGE_FULL"
        );
        assert_eq!(
            AckStatus::Error(AckErrorReason::Unknown).to_string(),
            "ERROR UNKNOWN"
        );
    }

    #[test]
    fn test_chunk_ack_response_display() {
        let resp = Response::ChunkAck {
            virtual_file: "invoices".to_string(),
            chunk_index: 42,
            status: AckStatus::Ok,
        };
        assert_eq!(resp.to_string(), "DEFT CHUNK_ACK invoices 42 OK");
    }

    #[test]
    fn test_chunk_ack_error_response_display() {
        let resp = Response::ChunkAck {
            virtual_file: "invoices".to_string(),
            chunk_index: 5,
            status: AckStatus::Error(AckErrorReason::HashMismatch),
        };
        assert_eq!(
            resp.to_string(),
            "DEFT CHUNK_ACK invoices 5 ERROR HASH_MISMATCH"
        );
    }

    #[test]
    fn test_chunk_ack_batch_response_display() {
        let resp = Response::ChunkAckBatch {
            virtual_file: "data".to_string(),
            ranges: vec![
                crate::ChunkRange::new(1, 50),
                crate::ChunkRange::new(52, 100),
            ],
        };
        assert_eq!(resp.to_string(), "DEFT CHUNK_ACK_BATCH data 1-50,52-100");
    }

    #[test]
    fn test_transfer_complete_response_display() {
        let resp = Response::TransferComplete {
            virtual_file: "invoices".to_string(),
            file_hash: "sha256:abc123".to_string(),
            total_size: 1048576,
            chunk_count: 100,
            signature: None,
        };
        assert_eq!(
            resp.to_string(),
            "DEFT TRANSFER_COMPLETE invoices sha256:abc123 1048576 100"
        );
    }

    #[test]
    fn test_transfer_complete_with_signature_display() {
        let resp = Response::TransferComplete {
            virtual_file: "invoices".to_string(),
            file_hash: "sha256:abc123".to_string(),
            total_size: 1048576,
            chunk_count: 100,
            signature: Some("ed25519:xyz789".to_string()),
        };
        assert_eq!(
            resp.to_string(),
            "DEFT TRANSFER_COMPLETE invoices sha256:abc123 1048576 100 sig:ed25519:xyz789"
        );
    }

    #[test]
    fn test_welcome_response_with_window_size() {
        let caps = Capabilities::new()
            .with(Capability::Chunked)
            .with_window_size(64);
        let resp = Response::welcome("1.0", caps, "sess_123");
        let s = resp.to_string();
        assert!(s.contains("WELCOME"));
        assert!(s.contains("1.0"));
        assert!(s.contains("CHUNKED"));
        assert!(s.contains("WINDOW_SIZE:64"));
        assert!(s.contains("sess_123"));
    }

    #[test]
    fn test_transfer_accepted_display() {
        let resp = Response::TransferAccepted {
            transfer_id: "tr-abc123".to_string(),
            virtual_file: "invoices-jan".to_string(),
            window_size: 64,
        };
        assert_eq!(
            resp.to_string(),
            "DEFT TRANSFER_ACCEPTED tr-abc123 invoices-jan WINDOW_SIZE:64"
        );
    }

    #[test]
    fn test_transfer_receipt_serialization() {
        let receipt = TransferReceipt {
            transfer_id: "tr-123".to_string(),
            virtual_file: "invoices".to_string(),
            sender_partner: "acme".to_string(),
            receiver_partner: "supplier".to_string(),
            timestamp_start: "2026-01-19T10:00:00Z".to_string(),
            timestamp_complete: "2026-01-19T10:05:00Z".to_string(),
            chunks_total: 100,
            total_bytes: 1048576,
            file_hash: "sha256:abc123".to_string(),
            signature: Some("sig123".to_string()),
        };

        let json = serde_json::to_string(&receipt).unwrap();
        assert!(json.contains("tr-123"));
        assert!(json.contains("invoices"));
        assert!(json.contains("1048576"));

        let deserialized: TransferReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.transfer_id, receipt.transfer_id);
        assert_eq!(deserialized.total_bytes, receipt.total_bytes);
    }
}
