use crate::{Capabilities, Command, ChunkRange, RiftError, RiftErrorCode, Response, AckStatus, AckErrorReason};

pub struct Parser;

impl Parser {
    pub fn parse_command(line: &str) -> Result<Command, RiftError> {
        let line = line.trim();
        if !line.starts_with("RIFT ") {
            return Err(RiftError::ParseError("Command must start with 'RIFT '".into()));
        }

        let rest = &line[5..];
        let parts: Vec<&str> = rest.split_whitespace().collect();

        if parts.is_empty() {
            return Err(RiftError::ParseError("Empty command".into()));
        }

        match parts[0].to_uppercase().as_str() {
            "HELLO" => Self::parse_hello(&parts[1..]),
            "AUTH" => Self::parse_auth(&parts[1..]),
            "DISCOVER" => Ok(Command::Discover),
            "DESCRIBE" => Self::parse_describe(&parts[1..]),
            "GET" => Self::parse_get(&parts[1..]),
            "BEGIN_TRANSFER" => Self::parse_begin_transfer(&parts[1..]),
            "RESUME_TRANSFER" => Self::parse_resume_transfer(&parts[1..]),
            "GET_STATUS" => Self::parse_get_status(&parts[1..]),
            "PUT" => Self::parse_put(&parts[1..]),
            "BYE" => Ok(Command::Bye),
            cmd => Err(RiftError::UnknownCommand(cmd.to_string())),
        }
    }

    fn parse_hello(parts: &[&str]) -> Result<Command, RiftError> {
        if parts.is_empty() {
            return Err(RiftError::MissingField("version".into()));
        }

        let version = parts[0].to_string();
        let capabilities = if parts.len() > 1 {
            // Join remaining parts to handle "CHUNKED,PARALLEL WINDOW_SIZE:64" format
            parts[1..].join(" ").parse()?
        } else {
            Capabilities::new()
        };

        Ok(Command::Hello { version, capabilities })
    }

    fn parse_auth(parts: &[&str]) -> Result<Command, RiftError> {
        if parts.is_empty() {
            return Err(RiftError::MissingField("partner_id".into()));
        }

        Ok(Command::Auth {
            partner_id: parts[0].to_string(),
        })
    }

    fn parse_describe(parts: &[&str]) -> Result<Command, RiftError> {
        if parts.is_empty() {
            return Err(RiftError::MissingField("virtual_file".into()));
        }

        Ok(Command::Describe {
            virtual_file: parts[0].to_string(),
        })
    }

    fn parse_get(parts: &[&str]) -> Result<Command, RiftError> {
        if parts.is_empty() {
            return Err(RiftError::MissingField("virtual_file".into()));
        }

        let virtual_file = parts[0].to_string();

        if parts.len() < 3 || parts[1].to_uppercase() != "CHUNKS" {
            return Err(RiftError::ParseError("GET requires CHUNKS <range>".into()));
        }

        let chunks: ChunkRange = parts[2].parse()?;

        Ok(Command::Get { virtual_file, chunks })
    }

    fn parse_begin_transfer(parts: &[&str]) -> Result<Command, RiftError> {
        // BEGIN_TRANSFER <virtual_file> <total_chunks> <total_bytes> <file_hash>
        if parts.len() < 4 {
            return Err(RiftError::ParseError(
                "BEGIN_TRANSFER requires <virtual_file> <total_chunks> <total_bytes> <file_hash>".into()
            ));
        }

        let virtual_file = parts[0].to_string();
        let total_chunks: u64 = parts[1].parse()
            .map_err(|_| RiftError::ParseError("Invalid total_chunks".into()))?;
        let total_bytes: u64 = parts[2].parse()
            .map_err(|_| RiftError::ParseError("Invalid total_bytes".into()))?;
        let file_hash = parts[3].to_string();

        Ok(Command::BeginTransfer {
            virtual_file,
            total_chunks,
            total_bytes,
            file_hash,
        })
    }

    fn parse_resume_transfer(parts: &[&str]) -> Result<Command, RiftError> {
        // RESUME_TRANSFER <virtual_file> <transfer_id>
        if parts.len() < 2 {
            return Err(RiftError::ParseError(
                "RESUME_TRANSFER requires <virtual_file> <transfer_id>".into()
            ));
        }

        Ok(Command::ResumeTransfer {
            virtual_file: parts[0].to_string(),
            transfer_id: parts[1].to_string(),
        })
    }

    fn parse_get_status(parts: &[&str]) -> Result<Command, RiftError> {
        // GET_STATUS <virtual_file>
        if parts.is_empty() {
            return Err(RiftError::MissingField("virtual_file".into()));
        }

        Ok(Command::GetStatus {
            virtual_file: parts[0].to_string(),
        })
    }

    fn parse_put(parts: &[&str]) -> Result<Command, RiftError> {
        // PUT <virtual_file> CHUNK <index> SIZE:<bytes> HASH:<hash>
        if parts.is_empty() {
            return Err(RiftError::MissingField("virtual_file".into()));
        }

        let virtual_file = parts[0].to_string();

        if parts.len() < 5 || parts[1].to_uppercase() != "CHUNK" {
            return Err(RiftError::ParseError("PUT requires CHUNK <index> SIZE:<bytes> HASH:<hash>".into()));
        }

        let chunk_index: u64 = parts[2].parse()
            .map_err(|_| RiftError::ParseError("Invalid chunk index".into()))?;

        // Parse SIZE:<bytes>
        let size_part = parts[3].to_uppercase();
        let size: u64 = if size_part.starts_with("SIZE:") {
            size_part[5..].parse()
                .map_err(|_| RiftError::ParseError("Invalid SIZE value".into()))?
        } else {
            return Err(RiftError::ParseError("Expected SIZE:<bytes>".into()));
        };

        // Parse HASH:<hash>
        let hash_part = parts[4];
        let hash = if hash_part.to_uppercase().starts_with("HASH:") {
            hash_part[5..].to_string()
        } else {
            return Err(RiftError::ParseError("Expected HASH:<hash>".into()));
        };

        // Parse optional NONCE:<nonce> and COMPRESSED flag
        let mut nonce = None;
        let mut compressed = false;
        
        for part in parts.iter().skip(5) {
            let upper = part.to_uppercase();
            if let Some(n) = upper.strip_prefix("NONCE:") {
                nonce = n.parse().ok();
            } else if upper == "COMPRESSED" {
                compressed = true;
            }
        }

        Ok(Command::Put {
            virtual_file,
            chunk_index,
            size,
            hash,
            nonce,
            compressed,
        })
    }

    pub fn parse_response(line: &str) -> Result<Response, RiftError> {
        let line = line.trim();
        if !line.starts_with("RIFT ") {
            return Err(RiftError::ParseError("Response must start with 'RIFT '".into()));
        }

        let rest = &line[5..];
        let parts: Vec<&str> = rest.split_whitespace().collect();

        if parts.is_empty() {
            return Err(RiftError::ParseError("Empty response".into()));
        }

        match parts[0].to_uppercase().as_str() {
            "WELCOME" => Self::parse_welcome(&parts[1..]),
            "AUTH_OK" => Self::parse_auth_ok(rest),
            "ERROR" => Self::parse_error(&parts[1..]),
            "GOODBYE" => Ok(Response::Goodbye),
            "CHUNK_OK" => Self::parse_chunk_ok(&parts[1..]),
            "CHUNK_ACK" => Self::parse_chunk_ack(&parts[1..]),
            "CHUNK_ACK_BATCH" => Self::parse_chunk_ack_batch(&parts[1..]),
            "TRANSFER_ACCEPTED" => Self::parse_transfer_accepted(&parts[1..]),
            "TRANSFER_COMPLETE" => Self::parse_transfer_complete(&parts[1..]),
            "CHUNK_READY" => Self::parse_chunk_ready(&parts[1..]),
            resp => Err(RiftError::ParseError(format!("Unknown response: {}", resp))),
        }
    }

    fn parse_welcome(parts: &[&str]) -> Result<Response, RiftError> {
        if parts.is_empty() {
            return Err(RiftError::MissingField("version".into()));
        }

        let version = parts[0].to_string();

        // Session ID is always the last element
        // Capabilities (if any) are in between version and session_id
        let (capabilities, session_id) = if parts.len() == 2 {
            // No capabilities: version session_id
            (Capabilities::new(), parts[1].to_string())
        } else if parts.len() >= 3 {
            // With capabilities: version caps [WINDOW_SIZE:n] session_id
            // Join all middle parts as capabilities, session_id is last
            let session_id = parts[parts.len() - 1].to_string();
            let caps_str = parts[1..parts.len() - 1].join(" ");
            (caps_str.parse()?, session_id)
        } else {
            return Err(RiftError::MissingField("session_id".into()));
        };

        Ok(Response::Welcome {
            version,
            capabilities,
            session_id,
        })
    }

    fn parse_auth_ok(rest: &str) -> Result<Response, RiftError> {
        let after_auth_ok = rest.strip_prefix("AUTH_OK ")
            .ok_or_else(|| RiftError::ParseError("Invalid AUTH_OK format".into()))?;

        let (partner_name, vf_part) = if after_auth_ok.starts_with('"') {
            let end_quote = after_auth_ok[1..].find('"')
                .ok_or_else(|| RiftError::ParseError("Unclosed quote in partner name".into()))?;
            let name = &after_auth_ok[1..=end_quote];
            let rest = after_auth_ok[end_quote + 2..].trim();
            (name.to_string(), rest)
        } else {
            let parts: Vec<&str> = after_auth_ok.split_whitespace().collect();
            if parts.is_empty() {
                return Err(RiftError::MissingField("partner_name".into()));
            }
            (parts[0].to_string(), parts.get(1).copied().unwrap_or(""))
        };

        let virtual_files = if let Some(vf_list) = vf_part.strip_prefix("VF:") {
            vf_list.split(',').map(|s| s.to_string()).collect()
        } else {
            Vec::new()
        };

        Ok(Response::AuthOk {
            partner_name,
            virtual_files,
        })
    }

    fn parse_error(parts: &[&str]) -> Result<Response, RiftError> {
        if parts.is_empty() {
            return Err(RiftError::MissingField("error_code".into()));
        }

        let code_num: u16 = parts[0].parse()
            .map_err(|_| RiftError::ParseError("Invalid error code".into()))?;

        let code = RiftErrorCode::from_code(code_num)
            .ok_or_else(|| RiftError::ParseError(format!("Unknown error code: {}", code_num)))?;

        let message = if parts.len() > 1 {
            Some(parts[1..].join(" "))
        } else {
            None
        };

        Ok(Response::Error { code, message })
    }

    fn parse_chunk_ok(parts: &[&str]) -> Result<Response, RiftError> {
        if parts.len() < 2 {
            return Err(RiftError::MissingField("virtual_file or chunk_index".into()));
        }

        let virtual_file = parts[0].to_string();
        let chunk_index: u64 = parts[1].parse()
            .map_err(|_| RiftError::ParseError("Invalid chunk index".into()))?;

        Ok(Response::ChunkOk {
            virtual_file,
            chunk_index,
        })
    }

    fn parse_chunk_ack(parts: &[&str]) -> Result<Response, RiftError> {
        if parts.len() < 3 {
            return Err(RiftError::MissingField("virtual_file, chunk_index or status".into()));
        }

        let virtual_file = parts[0].to_string();
        let chunk_index: u64 = parts[1].parse()
            .map_err(|_| RiftError::ParseError("Invalid chunk index".into()))?;

        let status = match parts[2].to_uppercase().as_str() {
            "OK" => AckStatus::Ok,
            "ERROR" => {
                let reason = if parts.len() > 3 {
                    parts[3].parse().unwrap_or(AckErrorReason::Unknown)
                } else {
                    AckErrorReason::Unknown
                };
                AckStatus::Error(reason)
            }
            _ => return Err(RiftError::ParseError(format!("Invalid ACK status: {}", parts[2]))),
        };

        Ok(Response::ChunkAck {
            virtual_file,
            chunk_index,
            status,
        })
    }

    fn parse_chunk_ack_batch(parts: &[&str]) -> Result<Response, RiftError> {
        if parts.len() < 2 {
            return Err(RiftError::MissingField("virtual_file or ranges".into()));
        }

        let virtual_file = parts[0].to_string();
        let ranges: Result<Vec<ChunkRange>, _> = parts[1]
            .split(',')
            .map(|r| r.parse())
            .collect();

        Ok(Response::ChunkAckBatch {
            virtual_file,
            ranges: ranges?,
        })
    }

    fn parse_transfer_complete(parts: &[&str]) -> Result<Response, RiftError> {
        if parts.len() < 4 {
            return Err(RiftError::MissingField("virtual_file, file_hash, total_size or chunk_count".into()));
        }

        let virtual_file = parts[0].to_string();
        let file_hash = parts[1].to_string();
        let total_size: u64 = parts[2].parse()
            .map_err(|_| RiftError::ParseError("Invalid total_size".into()))?;
        let chunk_count: u64 = parts[3].parse()
            .map_err(|_| RiftError::ParseError("Invalid chunk_count".into()))?;

        let signature = parts.get(4)
            .and_then(|s| s.strip_prefix("sig:"))
            .map(|s| s.to_string());

        Ok(Response::TransferComplete {
            virtual_file,
            file_hash,
            total_size,
            chunk_count,
            signature,
        })
    }

    fn parse_transfer_accepted(parts: &[&str]) -> Result<Response, RiftError> {
        // TRANSFER_ACCEPTED <transfer_id> <virtual_file> WINDOW_SIZE:<n>
        if parts.len() < 2 {
            return Err(RiftError::MissingField("transfer_id or virtual_file".into()));
        }

        let transfer_id = parts[0].to_string();
        let virtual_file = parts[1].to_string();

        let window_size = parts.get(2)
            .and_then(|s| s.strip_prefix("WINDOW_SIZE:"))
            .and_then(|s| s.parse().ok())
            .unwrap_or(64);

        Ok(Response::TransferAccepted {
            transfer_id,
            virtual_file,
            window_size,
        })
    }

    fn parse_chunk_ready(parts: &[&str]) -> Result<Response, RiftError> {
        // CHUNK_READY <virtual_file> <chunk_index> SIZE:<n>
        if parts.len() < 2 {
            return Err(RiftError::MissingField("virtual_file or chunk_index".into()));
        }

        let virtual_file = parts[0].to_string();
        let chunk_index: u64 = parts[1].parse()
            .map_err(|_| RiftError::ParseError("Invalid chunk index".into()))?;

        let size = parts.get(2)
            .and_then(|s| s.strip_prefix("SIZE:"))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        Ok(Response::ChunkReady {
            virtual_file,
            chunk_index,
            size,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hello() {
        let cmd = Parser::parse_command("RIFT HELLO 1.0 CHUNKED,PARALLEL,RESUME").unwrap();
        match cmd {
            Command::Hello { version, capabilities } => {
                assert_eq!(version, "1.0");
                assert!(capabilities.has(crate::Capability::Chunked));
                assert!(capabilities.has(crate::Capability::Parallel));
                assert!(capabilities.has(crate::Capability::Resume));
            }
            _ => panic!("Expected Hello command"),
        }
    }

    #[test]
    fn test_parse_auth() {
        let cmd = Parser::parse_command("RIFT AUTH partner-acme-corp").unwrap();
        match cmd {
            Command::Auth { partner_id } => {
                assert_eq!(partner_id, "partner-acme-corp");
            }
            _ => panic!("Expected Auth command"),
        }
    }

    #[test]
    fn test_parse_get() {
        let cmd = Parser::parse_command("RIFT GET monthly-invoices CHUNKS 0-10").unwrap();
        match cmd {
            Command::Get { virtual_file, chunks } => {
                assert_eq!(virtual_file, "monthly-invoices");
                assert_eq!(chunks.start, 0);
                assert_eq!(chunks.end, 10);
            }
            _ => panic!("Expected Get command"),
        }
    }

    #[test]
    fn test_parse_put() {
        let cmd = Parser::parse_command("RIFT PUT invoices CHUNK 5 SIZE:1024 HASH:abc123def456").unwrap();
        match cmd {
            Command::Put { virtual_file, chunk_index, size, hash, nonce, compressed } => {
                assert_eq!(virtual_file, "invoices");
                assert_eq!(chunk_index, 5);
                assert_eq!(size, 1024);
                assert!(nonce.is_none());
                assert!(!compressed);
                assert_eq!(hash, "abc123def456");
            }
            _ => panic!("Expected Put command"),
        }
    }

    #[test]
    fn test_parse_put_compressed() {
        let cmd = Parser::parse_command("RIFT PUT invoices CHUNK 5 SIZE:1024 HASH:abc123 NONCE:12345 COMPRESSED").unwrap();
        match cmd {
            Command::Put { virtual_file, chunk_index, size, hash, nonce, compressed } => {
                assert_eq!(virtual_file, "invoices");
                assert_eq!(chunk_index, 5);
                assert_eq!(size, 1024);
                assert_eq!(nonce, Some(12345));
                assert!(compressed);
                assert_eq!(hash, "abc123");
            }
            _ => panic!("Expected Put command"),
        }
    }

    #[test]
    fn test_parse_welcome() {
        let resp = Parser::parse_response("RIFT WELCOME 1.0 CHUNKED,PARALLEL,RESUME sess_20260119_001").unwrap();
        match resp {
            Response::Welcome { version, capabilities, session_id } => {
                assert_eq!(version, "1.0");
                assert!(capabilities.has(crate::Capability::Chunked));
                assert_eq!(session_id, "sess_20260119_001");
            }
            _ => panic!("Expected Welcome response"),
        }
    }

    #[test]
    fn test_parse_auth_ok() {
        let resp = Parser::parse_response("RIFT AUTH_OK \"ACME Corporation\" VF:monthly-invoices,product-catalog").unwrap();
        match resp {
            Response::AuthOk { partner_name, virtual_files } => {
                assert_eq!(partner_name, "ACME Corporation");
                assert_eq!(virtual_files, vec!["monthly-invoices", "product-catalog"]);
            }
            _ => panic!("Expected AuthOk response"),
        }
    }

    #[test]
    fn test_parse_error() {
        let resp = Parser::parse_response("RIFT ERROR 401 Unauthorized - Invalid partner").unwrap();
        match resp {
            Response::Error { code, message } => {
                assert_eq!(code, RiftErrorCode::Unauthorized);
                assert!(message.is_some());
            }
            _ => panic!("Expected Error response"),
        }
    }

    #[test]
    fn test_parse_hello_with_window_size() {
        let cmd = Parser::parse_command("RIFT HELLO 1.0 CHUNKED,PARALLEL WINDOW_SIZE:128").unwrap();
        match cmd {
            Command::Hello { version, capabilities } => {
                assert_eq!(version, "1.0");
                assert!(capabilities.has(crate::Capability::Chunked));
                assert!(capabilities.has(crate::Capability::Parallel));
                assert_eq!(capabilities.window_size, Some(128));
            }
            _ => panic!("Expected Hello command"),
        }
    }

    #[test]
    fn test_parse_welcome_with_window_size() {
        let resp = Parser::parse_response("RIFT WELCOME 1.0 CHUNKED,RESUME WINDOW_SIZE:64 sess_123").unwrap();
        match resp {
            Response::Welcome { version, capabilities, session_id } => {
                assert_eq!(version, "1.0");
                assert!(capabilities.has(crate::Capability::Chunked));
                assert!(capabilities.has(crate::Capability::Resume));
                assert_eq!(capabilities.window_size, Some(64));
                assert_eq!(session_id, "sess_123");
            }
            _ => panic!("Expected Welcome response"),
        }
    }

    #[test]
    fn test_parse_chunk_ack_ok() {
        let resp = Parser::parse_response("RIFT CHUNK_ACK invoices 42 OK").unwrap();
        match resp {
            Response::ChunkAck { virtual_file, chunk_index, status } => {
                assert_eq!(virtual_file, "invoices");
                assert_eq!(chunk_index, 42);
                assert_eq!(status, crate::AckStatus::Ok);
            }
            _ => panic!("Expected ChunkAck response"),
        }
    }

    #[test]
    fn test_parse_chunk_ack_error() {
        let resp = Parser::parse_response("RIFT CHUNK_ACK invoices 5 ERROR HASH_MISMATCH").unwrap();
        match resp {
            Response::ChunkAck { virtual_file, chunk_index, status } => {
                assert_eq!(virtual_file, "invoices");
                assert_eq!(chunk_index, 5);
                assert_eq!(status, crate::AckStatus::Error(crate::AckErrorReason::HashMismatch));
            }
            _ => panic!("Expected ChunkAck response"),
        }
    }

    #[test]
    fn test_parse_chunk_ack_batch() {
        let resp = Parser::parse_response("RIFT CHUNK_ACK_BATCH monthly-data 1-50,52-100").unwrap();
        match resp {
            Response::ChunkAckBatch { virtual_file, ranges } => {
                assert_eq!(virtual_file, "monthly-data");
                assert_eq!(ranges.len(), 2);
                assert_eq!(ranges[0].start, 1);
                assert_eq!(ranges[0].end, 50);
                assert_eq!(ranges[1].start, 52);
                assert_eq!(ranges[1].end, 100);
            }
            _ => panic!("Expected ChunkAckBatch response"),
        }
    }

    #[test]
    fn test_parse_transfer_complete() {
        let resp = Parser::parse_response(
            "RIFT TRANSFER_COMPLETE invoices sha256:abc123 1048576 100"
        ).unwrap();
        match resp {
            Response::TransferComplete { virtual_file, file_hash, total_size, chunk_count, signature } => {
                assert_eq!(virtual_file, "invoices");
                assert_eq!(file_hash, "sha256:abc123");
                assert_eq!(total_size, 1048576);
                assert_eq!(chunk_count, 100);
                assert!(signature.is_none());
            }
            _ => panic!("Expected TransferComplete response"),
        }
    }

    #[test]
    fn test_parse_transfer_complete_with_signature() {
        let resp = Parser::parse_response(
            "RIFT TRANSFER_COMPLETE invoices sha256:abc123 1048576 100 sig:ed25519:xyz789"
        ).unwrap();
        match resp {
            Response::TransferComplete { virtual_file, file_hash, total_size, chunk_count, signature } => {
                assert_eq!(virtual_file, "invoices");
                assert_eq!(file_hash, "sha256:abc123");
                assert_eq!(total_size, 1048576);
                assert_eq!(chunk_count, 100);
                assert_eq!(signature, Some("ed25519:xyz789".to_string()));
            }
            _ => panic!("Expected TransferComplete response"),
        }
    }

    #[test]
    fn test_parse_begin_transfer() {
        let cmd = Parser::parse_command(
            "RIFT BEGIN_TRANSFER invoices-jan 100 10485760 sha256:abcdef123456"
        ).unwrap();
        match cmd {
            Command::BeginTransfer { virtual_file, total_chunks, total_bytes, file_hash } => {
                assert_eq!(virtual_file, "invoices-jan");
                assert_eq!(total_chunks, 100);
                assert_eq!(total_bytes, 10485760);
                assert_eq!(file_hash, "sha256:abcdef123456");
            }
            _ => panic!("Expected BeginTransfer command"),
        }
    }

    #[test]
    fn test_begin_transfer_display() {
        let cmd = Command::BeginTransfer {
            virtual_file: "data-file".to_string(),
            total_chunks: 50,
            total_bytes: 5242880,
            file_hash: "sha256:xyz789".to_string(),
        };
        assert_eq!(
            cmd.to_string(),
            "RIFT BEGIN_TRANSFER data-file 50 5242880 sha256:xyz789"
        );
    }
}
