use deft_protocol::{
    Capabilities, Capability, Command, Parser, Response, 
    Endpoint, EndpointList, ChunkRange, AckStatus,
    DEFT_VERSION,
};

#[test]
fn test_full_handshake_flow() {
    // Client sends HELLO
    let hello = Command::hello(DEFT_VERSION, Capabilities::all());
    let hello_str = format!("{}", hello);
    assert!(hello_str.contains("HELLO"));
    assert!(hello_str.contains(DEFT_VERSION));

    // Server responds with WELCOME
    let welcome = Response::welcome(DEFT_VERSION, Capabilities::all(), "sess_123");
    let welcome_str = format!("{}", welcome);
    assert!(welcome_str.contains("WELCOME"));
    assert!(welcome_str.contains("sess_123"));

    // Parse welcome response
    let parsed = Parser::parse_response(&welcome_str).unwrap();
    if let Response::Welcome { version, session_id, .. } = parsed {
        assert_eq!(version, DEFT_VERSION);
        assert_eq!(session_id, "sess_123");
    } else {
        panic!("Expected Welcome response");
    }

    // Client sends AUTH
    let auth = Command::auth("partner-acme");
    let auth_str = format!("{}", auth);
    assert!(auth_str.contains("AUTH partner-acme"));

    // Server responds with AUTH_OK
    let auth_ok = Response::auth_ok("ACME Corp", vec!["invoices".into(), "reports".into()]);
    let auth_ok_str = format!("{}", auth_ok);
    assert!(auth_ok_str.contains("AUTH_OK"));
    assert!(auth_ok_str.contains("ACME Corp"));
}

#[test]
fn test_transfer_flow() {
    // BEGIN_TRANSFER
    let begin = Command::begin_transfer("invoices", 10, 10240, "abc123");
    let begin_str = format!("{}", begin);
    assert!(begin_str.contains("BEGIN_TRANSFER"));
    assert!(begin_str.contains("invoices"));
    assert!(begin_str.contains("10"));
    assert!(begin_str.contains("10240"));

    // Parse BEGIN_TRANSFER
    let parsed = Parser::parse_command(&begin_str).unwrap();
    if let Command::BeginTransfer { virtual_file, total_chunks, total_bytes, file_hash } = parsed {
        assert_eq!(virtual_file, "invoices");
        assert_eq!(total_chunks, 10);
        assert_eq!(total_bytes, 10240);
        assert_eq!(file_hash, "abc123");
    } else {
        panic!("Expected BeginTransfer command");
    }

    // TRANSFER_ACCEPTED response
    let accepted = Response::TransferAccepted {
        transfer_id: "txn_456".into(),
        virtual_file: "invoices".into(),
        window_size: 64,
    };
    let accepted_str = format!("{}", accepted);
    assert!(accepted_str.contains("TRANSFER_ACCEPTED"));
    assert!(accepted_str.contains("txn_456"));

    // PUT command
    let put = Command::put("invoices", 0, 1024, "chunk_hash_0");
    let put_str = format!("{}", put);
    assert!(put_str.contains("PUT invoices CHUNK 0"));
    assert!(put_str.contains("SIZE:1024"));
    assert!(put_str.contains("HASH:chunk_hash_0"));

    // Parse PUT
    let parsed = Parser::parse_command(&put_str).unwrap();
    if let Command::Put { virtual_file, chunk_index, size, hash, .. } = parsed {
        assert_eq!(virtual_file, "invoices");
        assert_eq!(chunk_index, 0);
        assert_eq!(size, 1024);
        assert_eq!(hash, "chunk_hash_0");
    } else {
        panic!("Expected Put command");
    }

    // CHUNK_ACK response
    let ack = Response::ChunkAck {
        virtual_file: "invoices".into(),
        chunk_index: 0,
        status: AckStatus::Ok,
    };
    let ack_str = format!("{}", ack);
    assert!(ack_str.contains("CHUNK_ACK invoices 0 OK"));

    // TRANSFER_COMPLETE
    let complete = Response::TransferComplete {
        virtual_file: "invoices".into(),
        file_hash: "abc123".into(),
        total_size: 10240,
        chunk_count: 10,
        signature: Some("sig_xyz".into()),
    };
    let complete_str = format!("{}", complete);
    assert!(complete_str.contains("TRANSFER_COMPLETE"));
    assert!(complete_str.contains("sig:sig_xyz"));
}


#[test]
fn test_resume_transfer_flow() {
    // RESUME_TRANSFER command
    let resume = Command::resume_transfer("invoices", "txn_456");
    let resume_str = format!("{}", resume);
    assert!(resume_str.contains("RESUME_TRANSFER"));
    assert!(resume_str.contains("invoices"));
    assert!(resume_str.contains("txn_456"));

    // Parse RESUME_TRANSFER
    let parsed = Parser::parse_command(&resume_str).unwrap();
    if let Command::ResumeTransfer { virtual_file, transfer_id } = parsed {
        assert_eq!(virtual_file, "invoices");
        assert_eq!(transfer_id, "txn_456");
    } else {
        panic!("Expected ResumeTransfer command");
    }

    // GET_STATUS command
    let status = Command::get_status("invoices");
    let status_str = format!("{}", status);
    assert!(status_str.contains("GET_STATUS"));

    // Parse GET_STATUS
    let parsed = Parser::parse_command(&status_str).unwrap();
    if let Command::GetStatus { virtual_file } = parsed {
        assert_eq!(virtual_file, "invoices");
    } else {
        panic!("Expected GetStatus command");
    }

    // TRANSFER_STATUS response
    let transfer_status = Response::TransferStatus {
        transfer_id: "txn_456".into(),
        virtual_file: "invoices".into(),
        total_chunks: 10,
        received_chunks: 5,
        pending_chunks: vec![5, 6, 7, 8, 9],
    };
    let status_str = format!("{}", transfer_status);
    assert!(status_str.contains("TRANSFER_STATUS"));
    assert!(status_str.contains("5/10"));
    assert!(status_str.contains("PENDING:5,6,7,8,9"));
}

#[test]
fn test_capabilities_negotiation() {
    // Client capabilities - use all() which includes CHUNKED, PARALLEL, RESUME
    let client_caps = Capabilities::all().with_window_size(128);

    // Server capabilities - parse from string
    let server_caps: Capabilities = "CHUNKED,RESUME WINDOW_SIZE:64".parse().unwrap();

    // Intersection (negotiated)
    let negotiated = client_caps.intersect(&server_caps);
    assert!(negotiated.has(Capability::Chunked));
    assert!(negotiated.has(Capability::Resume));
    assert!(!negotiated.has(Capability::Parallel));

    // Effective window size is minimum
    let effective = client_caps.effective_window_size(&server_caps);
    assert_eq!(effective, 64);
}

#[test]
fn test_endpoint_management() {
    let mut endpoints = EndpointList::new();
    
    // Add multiple endpoints with priorities
    endpoints.add(Endpoint::new("primary.example.com", 7741).with_priority(10));
    endpoints.add(Endpoint::new("backup1.example.com", 7741).with_priority(5));
    endpoints.add(Endpoint::new("backup2.example.com", 7741).with_priority(1));

    assert_eq!(endpoints.len(), 3);
    
    // Primary should be highest priority
    let primary = endpoints.primary().unwrap();
    assert_eq!(primary.host, "primary.example.com");

    // By priority order
    let by_prio = endpoints.by_priority();
    assert_eq!(by_prio[0].host, "primary.example.com");
    assert_eq!(by_prio[1].host, "backup1.example.com");
    assert_eq!(by_prio[2].host, "backup2.example.com");
}

#[test]
fn test_chunk_range_parsing() {
    // Single chunk
    let range: ChunkRange = "5".parse().unwrap();
    assert_eq!(range.start, 5);
    assert_eq!(range.end, 5);
    assert_eq!(range.count(), 1);

    // Range
    let range: ChunkRange = "10-20".parse().unwrap();
    assert_eq!(range.start, 10);
    assert_eq!(range.end, 20);
    assert_eq!(range.count(), 11);

    // Display
    assert_eq!(ChunkRange::single(5).to_string(), "5");
    assert_eq!(ChunkRange::new(10, 20).to_string(), "10-20");
}

#[test]
fn test_error_handling() {
    // Invalid command
    let result = Parser::parse_command("INVALID COMMAND");
    assert!(result.is_err());

    // Missing RIFT prefix
    let result = Parser::parse_command("HELLO 1.0");
    assert!(result.is_err());

    // Invalid chunk range
    let result: Result<ChunkRange, _> = "invalid".parse();
    assert!(result.is_err());

    // Reversed range
    let result: Result<ChunkRange, _> = "20-10".parse();
    assert!(result.is_err());
}
