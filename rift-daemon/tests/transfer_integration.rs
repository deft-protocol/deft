use std::collections::HashMap;
use std::io::Cursor;
use tempfile::TempDir;

use rift_common::{sha256_hex, Chunker};
use rift_protocol::{
    AckStatus, Capabilities, Command, Parser, Response, RiftErrorCode, RIFT_VERSION,
};

/// Simulates a RIFT session for testing
struct MockSession {
    state: SessionState,
    partner_id: Option<String>,
    virtual_files: Vec<String>,
    transfers: HashMap<String, MockTransfer>,
    window_size: u32,
}

#[derive(Debug, Clone, PartialEq)]
enum SessionState {
    Connected,
    Welcomed,
    Authenticated,
}

struct MockTransfer {
    virtual_file: String,
    total_chunks: u64,
    total_bytes: u64,
    file_hash: String,
    received_chunks: HashMap<u64, Vec<u8>>,
}

impl MockSession {
    fn new() -> Self {
        Self {
            state: SessionState::Connected,
            partner_id: None,
            virtual_files: vec!["invoices".into(), "reports".into()],
            transfers: HashMap::new(),
            window_size: 64,
        }
    }

    fn handle_command(&mut self, cmd: &Command) -> Response {
        match cmd {
            Command::Hello { version, capabilities } => {
                if self.state != SessionState::Connected {
                    return Response::error(RiftErrorCode::BadRequest, Some("Already welcomed".into()));
                }
                self.state = SessionState::Welcomed;
                self.window_size = capabilities.window_size.unwrap_or(64);
                Response::welcome(
                    version,
                    Capabilities::all().with_window_size(self.window_size),
                    "test_session_123",
                )
            }
            Command::Auth { partner_id } => {
                if self.state != SessionState::Welcomed {
                    return Response::error(RiftErrorCode::BadRequest, Some("Not welcomed".into()));
                }
                self.state = SessionState::Authenticated;
                self.partner_id = Some(partner_id.clone());
                Response::auth_ok(partner_id, self.virtual_files.clone())
            }
            Command::BeginTransfer { virtual_file, total_chunks, total_bytes, file_hash } => {
                if self.state != SessionState::Authenticated {
                    return Response::error(RiftErrorCode::Unauthorized, None);
                }
                if !self.virtual_files.contains(virtual_file) {
                    return Response::error(RiftErrorCode::Forbidden, None);
                }
                let transfer_id = format!("txn_{}", self.transfers.len());
                self.transfers.insert(transfer_id.clone(), MockTransfer {
                    virtual_file: virtual_file.clone(),
                    total_chunks: *total_chunks,
                    total_bytes: *total_bytes,
                    file_hash: file_hash.clone(),
                    received_chunks: HashMap::new(),
                });
                Response::TransferAccepted {
                    transfer_id,
                    virtual_file: virtual_file.clone(),
                    window_size: self.window_size,
                }
            }
            Command::Put { virtual_file, chunk_index, size, hash, .. } => {
                if self.state != SessionState::Authenticated {
                    return Response::error(RiftErrorCode::Unauthorized, None);
                }
                Response::ChunkReady {
                    virtual_file: virtual_file.clone(),
                    chunk_index: *chunk_index,
                    size: *size,
                }
            }
            Command::Bye => Response::Goodbye,
            _ => Response::error(RiftErrorCode::BadRequest, Some("Unsupported command".into())),
        }
    }

    fn receive_chunk(&mut self, transfer_id: &str, chunk_index: u64, data: Vec<u8>, expected_hash: &str) -> Response {
        let transfer = match self.transfers.get_mut(transfer_id) {
            Some(t) => t,
            None => return Response::error(RiftErrorCode::NotFound, None),
        };

        let computed_hash = sha256_hex(&data);
        if computed_hash != expected_hash {
            return Response::ChunkAck {
                virtual_file: transfer.virtual_file.clone(),
                chunk_index,
                status: AckStatus::Error(rift_protocol::AckErrorReason::HashMismatch),
            };
        }

        transfer.received_chunks.insert(chunk_index, data);

        // Check if transfer is complete
        if transfer.received_chunks.len() as u64 == transfer.total_chunks {
            Response::TransferComplete {
                virtual_file: transfer.virtual_file.clone(),
                file_hash: transfer.file_hash.clone(),
                total_size: transfer.total_bytes,
                chunk_count: transfer.total_chunks,
                signature: Some("test_sig".into()),
            }
        } else {
            Response::ChunkAck {
                virtual_file: transfer.virtual_file.clone(),
                chunk_index,
                status: AckStatus::Ok,
            }
        }
    }

    fn get_transfer(&self, transfer_id: &str) -> Option<&MockTransfer> {
        self.transfers.get(transfer_id)
    }
}

#[test]
fn test_full_handshake_and_auth() {
    let mut session = MockSession::new();

    // HELLO
    let hello = Command::hello(RIFT_VERSION, Capabilities::all());
    let resp = session.handle_command(&hello);
    
    if let Response::Welcome { version, session_id, .. } = resp {
        assert_eq!(version, RIFT_VERSION);
        assert!(!session_id.is_empty());
    } else {
        panic!("Expected Welcome response, got: {:?}", resp);
    }
    assert_eq!(session.state, SessionState::Welcomed);

    // AUTH
    let auth = Command::auth("partner-acme");
    let resp = session.handle_command(&auth);
    
    if let Response::AuthOk { partner_name, virtual_files } = resp {
        assert_eq!(partner_name, "partner-acme");
        assert!(virtual_files.contains(&"invoices".to_string()));
    } else {
        panic!("Expected AuthOk response");
    }
    assert_eq!(session.state, SessionState::Authenticated);
}

#[test]
fn test_small_file_transfer() {
    let mut session = MockSession::new();

    // Handshake
    session.handle_command(&Command::hello(RIFT_VERSION, Capabilities::all()));
    session.handle_command(&Command::auth("partner-acme"));

    // Create test file data (5KB)
    let file_data: Vec<u8> = (0..5000).map(|i| (i % 256) as u8).collect();
    let file_hash = sha256_hex(&file_data);

    // Chunk the file
    let chunker = Chunker::new(1024);
    let mut cursor = Cursor::new(&file_data);
    let file_chunks = chunker.compute_chunks(&mut cursor).unwrap();

    // BEGIN_TRANSFER
    let begin = Command::begin_transfer(
        "invoices",
        file_chunks.chunks.len() as u64,
        file_data.len() as u64,
        &file_hash,
    );
    let resp = session.handle_command(&begin);

    let transfer_id = if let Response::TransferAccepted { transfer_id, .. } = resp {
        transfer_id
    } else {
        panic!("Expected TransferAccepted");
    };

    // Send each chunk
    for (i, chunk_meta) in file_chunks.chunks.iter().enumerate() {
        let chunk_data = chunker.read_chunk(&mut cursor, i as u64).unwrap();
        
        // PUT command
        let put = Command::put("invoices", i as u64, chunk_data.len() as u64, &chunk_meta.hash);
        let resp = session.handle_command(&put);
        
        if let Response::ChunkReady { chunk_index, size, .. } = resp {
            assert_eq!(chunk_index, i as u64);
            assert_eq!(size, chunk_data.len() as u64);
        } else {
            panic!("Expected ChunkReady");
        }

        // Send binary data and receive ACK
        let resp = session.receive_chunk(&transfer_id, i as u64, chunk_data, &chunk_meta.hash);
        
        if i == file_chunks.chunks.len() - 1 {
            // Last chunk should complete the transfer
            if let Response::TransferComplete { file_hash: resp_hash, chunk_count, .. } = resp {
                assert_eq!(resp_hash, file_hash);
                assert_eq!(chunk_count, file_chunks.chunks.len() as u64);
            } else {
                panic!("Expected TransferComplete on last chunk");
            }
        } else {
            if let Response::ChunkAck { status, .. } = resp {
                assert_eq!(status, AckStatus::Ok);
            } else {
                panic!("Expected ChunkAck");
            }
        }
    }

    // Verify all chunks received
    let transfer = session.get_transfer(&transfer_id).unwrap();
    assert_eq!(transfer.received_chunks.len(), file_chunks.chunks.len());
}

#[test]
fn test_large_file_transfer() {
    let mut session = MockSession::new();

    // Handshake
    session.handle_command(&Command::hello(RIFT_VERSION, Capabilities::all()));
    session.handle_command(&Command::auth("partner-acme"));

    // Create large test file (1MB)
    let file_data: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();
    let file_hash = sha256_hex(&file_data);

    // Chunk with 64KB chunks
    let chunker = Chunker::new(65536);
    let mut cursor = Cursor::new(&file_data);
    let file_chunks = chunker.compute_chunks(&mut cursor).unwrap();

    assert_eq!(file_chunks.chunks.len(), 16); // 1MB / 64KB = ~16 chunks

    // BEGIN_TRANSFER
    let begin = Command::begin_transfer(
        "invoices",
        file_chunks.chunks.len() as u64,
        file_data.len() as u64,
        &file_hash,
    );
    let resp = session.handle_command(&begin);

    let transfer_id = if let Response::TransferAccepted { transfer_id, .. } = resp {
        transfer_id
    } else {
        panic!("Expected TransferAccepted");
    };

    // Send all chunks
    for (i, chunk_meta) in file_chunks.chunks.iter().enumerate() {
        let chunk_data = chunker.read_chunk(&mut cursor, i as u64).unwrap();
        
        let put = Command::put("invoices", i as u64, chunk_data.len() as u64, &chunk_meta.hash);
        session.handle_command(&put);
        session.receive_chunk(&transfer_id, i as u64, chunk_data, &chunk_meta.hash);
    }

    // Verify transfer complete
    let transfer = session.get_transfer(&transfer_id).unwrap();
    assert_eq!(transfer.received_chunks.len(), 16);

    // Reassemble and verify integrity
    let mut reassembled = Vec::new();
    for i in 0..transfer.total_chunks {
        reassembled.extend(transfer.received_chunks.get(&i).unwrap());
    }
    assert_eq!(reassembled.len(), file_data.len());
    assert_eq!(sha256_hex(&reassembled), file_hash);
}

#[test]
fn test_hash_mismatch_rejection() {
    let mut session = MockSession::new();

    session.handle_command(&Command::hello(RIFT_VERSION, Capabilities::all()));
    session.handle_command(&Command::auth("partner-acme"));

    let file_data = vec![1u8; 1000];
    let file_hash = sha256_hex(&file_data);

    let begin = Command::begin_transfer("invoices", 1, 1000, &file_hash);
    let resp = session.handle_command(&begin);

    let transfer_id = if let Response::TransferAccepted { transfer_id, .. } = resp {
        transfer_id
    } else {
        panic!("Expected TransferAccepted");
    };

    // Send PUT with correct hash
    let correct_hash = sha256_hex(&file_data);
    let put = Command::put("invoices", 0, 1000, &correct_hash);
    session.handle_command(&put);

    // Send corrupted data
    let corrupted_data = vec![2u8; 1000];
    let resp = session.receive_chunk(&transfer_id, 0, corrupted_data, &correct_hash);

    // Should get hash mismatch error
    if let Response::ChunkAck { status, .. } = resp {
        assert!(matches!(status, AckStatus::Error(rift_protocol::AckErrorReason::HashMismatch)));
    } else {
        panic!("Expected ChunkAck with error");
    }
}

#[test]
fn test_unauthorized_transfer() {
    let mut session = MockSession::new();

    // Try to begin transfer without auth
    session.handle_command(&Command::hello(RIFT_VERSION, Capabilities::all()));
    
    let begin = Command::begin_transfer("invoices", 1, 1000, "hash");
    let resp = session.handle_command(&begin);

    if let Response::Error { code, .. } = resp {
        assert_eq!(code, RiftErrorCode::Unauthorized);
    } else {
        panic!("Expected Unauthorized error");
    }
}

#[test]
fn test_forbidden_virtual_file() {
    let mut session = MockSession::new();

    session.handle_command(&Command::hello(RIFT_VERSION, Capabilities::all()));
    session.handle_command(&Command::auth("partner-acme"));

    // Try to access non-existent virtual file
    let begin = Command::begin_transfer("secret_files", 1, 1000, "hash");
    let resp = session.handle_command(&begin);

    if let Response::Error { code, .. } = resp {
        assert_eq!(code, RiftErrorCode::Forbidden);
    } else {
        panic!("Expected Forbidden error");
    }
}

#[test]
fn test_protocol_parsing_roundtrip() {
    // Test that commands can be serialized and parsed back
    let commands = vec![
        Command::hello(RIFT_VERSION, Capabilities::all().with_window_size(128)),
        Command::auth("test-partner"),
        Command::begin_transfer("invoices", 10, 10240, "abc123"),
        Command::resume_transfer("invoices", "txn_456"),
        Command::get_status("invoices"),
        Command::put("invoices", 5, 1024, "chunk_hash"),
        Command::bye(),
    ];

    for cmd in commands {
        let serialized = format!("{}", cmd);
        let parsed = Parser::parse_command(&serialized).expect(&format!("Failed to parse: {}", serialized));
        let reserialized = format!("{}", parsed);
        assert_eq!(serialized, reserialized, "Roundtrip failed for command");
    }
}

#[test]
fn test_chunk_ordering() {
    let mut session = MockSession::new();

    session.handle_command(&Command::hello(RIFT_VERSION, Capabilities::all()));
    session.handle_command(&Command::auth("partner-acme"));

    // Create file with distinct chunk contents
    let chunk_size = 100;
    let num_chunks = 10;
    let file_data: Vec<u8> = (0..num_chunks)
        .flat_map(|chunk_num| vec![chunk_num as u8; chunk_size])
        .collect();
    let file_hash = sha256_hex(&file_data);

    let chunker = Chunker::new(chunk_size as u32);
    let mut cursor = Cursor::new(&file_data);
    let file_chunks = chunker.compute_chunks(&mut cursor).unwrap();

    let begin = Command::begin_transfer("invoices", num_chunks as u64, file_data.len() as u64, &file_hash);
    let resp = session.handle_command(&begin);
    let transfer_id = if let Response::TransferAccepted { transfer_id, .. } = resp {
        transfer_id
    } else {
        panic!("Expected TransferAccepted");
    };

    // Send chunks out of order: 5, 2, 8, 0, 3, 7, 1, 6, 4, 9
    let order = [5, 2, 8, 0, 3, 7, 1, 6, 4, 9];
    for &i in &order {
        let chunk_data = chunker.read_chunk(&mut cursor, i as u64).unwrap();
        let put = Command::put("invoices", i as u64, chunk_data.len() as u64, &file_chunks.chunks[i].hash);
        session.handle_command(&put);
        session.receive_chunk(&transfer_id, i as u64, chunk_data, &file_chunks.chunks[i].hash);
    }

    // Reassemble in correct order and verify
    let transfer = session.get_transfer(&transfer_id).unwrap();
    let mut reassembled: Vec<u8> = Vec::new();
    for i in 0..num_chunks {
        reassembled.extend(transfer.received_chunks.get(&(i as u64)).unwrap());
    }
    assert_eq!(reassembled, file_data);
}
