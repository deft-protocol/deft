use crate::{
    AckErrorReason, AckStatus, Capabilities, ChunkRange, Command, DeftError, DeftErrorCode,
    Response,
};

pub struct Parser;

impl Parser {
    pub fn parse_command(line: &str) -> Result<Command, DeftError> {
        let line = line.trim();
        if !line.starts_with("DEFT ") {
            return Err(DeftError::ParseError(
                "Command must start with 'DEFT '".into(),
            ));
        }

        let rest = &line[5..];
        let parts: Vec<&str> = rest.split_whitespace().collect();

        if parts.is_empty() {
            return Err(DeftError::ParseError("Empty command".into()));
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
            "DELTA_SIG_REQ" => Self::parse_delta_sig_req(&parts[1..]),
            "DELTA_PUT" => Self::parse_delta_put(&parts[1..]),
            "PAUSE_TRANSFER" => Self::parse_pause_transfer(&parts[1..]),
            "RESUME_TRANSFER_CMD" => Self::parse_resume_transfer_cmd(&parts[1..]),
            "ABORT_TRANSFER" => Self::parse_abort_transfer(&parts[1..]),
            "BYE" => Ok(Command::Bye),
            cmd => Err(DeftError::UnknownCommand(cmd.to_string())),
        }
    }

    fn parse_hello(parts: &[&str]) -> Result<Command, DeftError> {
        if parts.is_empty() {
            return Err(DeftError::MissingField("version".into()));
        }

        let version = parts[0].to_string();
        let capabilities = if parts.len() > 1 {
            // Join remaining parts to handle "CHUNKED,PARALLEL WINDOW_SIZE:64" format
            parts[1..].join(" ").parse()?
        } else {
            Capabilities::new()
        };

        Ok(Command::Hello {
            version,
            capabilities,
        })
    }

    fn parse_auth(parts: &[&str]) -> Result<Command, DeftError> {
        if parts.is_empty() {
            return Err(DeftError::MissingField("partner_id".into()));
        }

        Ok(Command::Auth {
            partner_id: parts[0].to_string(),
        })
    }

    fn parse_describe(parts: &[&str]) -> Result<Command, DeftError> {
        if parts.is_empty() {
            return Err(DeftError::MissingField("virtual_file".into()));
        }

        Ok(Command::Describe {
            virtual_file: parts[0].to_string(),
        })
    }

    fn parse_get(parts: &[&str]) -> Result<Command, DeftError> {
        if parts.is_empty() {
            return Err(DeftError::MissingField("virtual_file".into()));
        }

        let virtual_file = parts[0].to_string();

        if parts.len() < 3 || parts[1].to_uppercase() != "CHUNKS" {
            return Err(DeftError::ParseError("GET requires CHUNKS <range>".into()));
        }

        let chunks: ChunkRange = parts[2].parse()?;

        Ok(Command::Get {
            virtual_file,
            chunks,
        })
    }

    fn parse_begin_transfer(parts: &[&str]) -> Result<Command, DeftError> {
        // BEGIN_TRANSFER <virtual_file> <total_chunks> <total_bytes> <file_hash> [TX_ID:<id>]
        if parts.len() < 4 {
            return Err(DeftError::ParseError(
                "BEGIN_TRANSFER requires <virtual_file> <total_chunks> <total_bytes> <file_hash>"
                    .into(),
            ));
        }

        let virtual_file = parts[0].to_string();
        let total_chunks: u64 = parts[1]
            .parse()
            .map_err(|_| DeftError::ParseError("Invalid total_chunks".into()))?;
        let total_bytes: u64 = parts[2]
            .parse()
            .map_err(|_| DeftError::ParseError("Invalid total_bytes".into()))?;
        let file_hash = parts[3].to_string();

        // Parse optional TX_ID:<id> parameter
        let mut transfer_id = None;
        for part in &parts[4..] {
            let upper = part.to_uppercase();
            if upper.starts_with("TX_ID:") {
                transfer_id = Some(part[6..].to_string());
            }
        }

        Ok(Command::BeginTransfer {
            virtual_file,
            total_chunks,
            total_bytes,
            file_hash,
            transfer_id,
        })
    }

    fn parse_resume_transfer(parts: &[&str]) -> Result<Command, DeftError> {
        // RESUME_TRANSFER <virtual_file> <transfer_id>
        if parts.len() < 2 {
            return Err(DeftError::ParseError(
                "RESUME_TRANSFER requires <virtual_file> <transfer_id>".into(),
            ));
        }

        Ok(Command::ResumeTransfer {
            virtual_file: parts[0].to_string(),
            transfer_id: parts[1].to_string(),
        })
    }

    fn parse_get_status(parts: &[&str]) -> Result<Command, DeftError> {
        // GET_STATUS <virtual_file>
        if parts.is_empty() {
            return Err(DeftError::MissingField("virtual_file".into()));
        }

        Ok(Command::GetStatus {
            virtual_file: parts[0].to_string(),
        })
    }

    fn parse_put(parts: &[&str]) -> Result<Command, DeftError> {
        // PUT <virtual_file> CHUNK <index> SIZE:<bytes> HASH:<hash>
        if parts.is_empty() {
            return Err(DeftError::MissingField("virtual_file".into()));
        }

        let virtual_file = parts[0].to_string();

        if parts.len() < 5 || parts[1].to_uppercase() != "CHUNK" {
            return Err(DeftError::ParseError(
                "PUT requires CHUNK <index> SIZE:<bytes> HASH:<hash>".into(),
            ));
        }

        let chunk_index: u64 = parts[2]
            .parse()
            .map_err(|_| DeftError::ParseError("Invalid chunk index".into()))?;

        // Parse SIZE:<bytes>
        let size_part = parts[3].to_uppercase();
        let size: u64 = if let Some(size_str) = size_part.strip_prefix("SIZE:") {
            size_str
                .parse()
                .map_err(|_| DeftError::ParseError("Invalid SIZE value".into()))?
        } else {
            return Err(DeftError::ParseError("Expected SIZE:<bytes>".into()));
        };

        // Parse HASH:<hash>
        let hash_part = parts[4];
        let hash = if let Some(hash_str) = hash_part
            .strip_prefix("HASH:")
            .or_else(|| hash_part.strip_prefix("hash:"))
        {
            hash_str.to_string()
        } else {
            return Err(DeftError::ParseError("Expected HASH:<hash>".into()));
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

    /// Parse DELTA_SIG_REQ <virtual_file> <block_size> [FILE:<filename>]
    fn parse_delta_sig_req(parts: &[&str]) -> Result<Command, DeftError> {
        if parts.len() < 2 {
            return Err(DeftError::ParseError(
                "DELTA_SIG_REQ requires <virtual_file> <block_size>".into(),
            ));
        }

        let virtual_file = parts[0].to_string();
        let block_size: usize = parts[1]
            .parse()
            .map_err(|_| DeftError::ParseError("Invalid block_size".into()))?;

        // Parse optional FILE:<filename> parameter
        let filename = parts.iter().skip(2).find_map(|p| {
            p.strip_prefix("FILE:").map(|f| f.to_string())
        });

        Ok(Command::DeltaSigReq {
            virtual_file,
            block_size,
            filename,
        })
    }

    /// Parse DELTA_PUT <virtual_file> HASH:<hash> DATA:<base64_delta>
    fn parse_delta_put(parts: &[&str]) -> Result<Command, DeftError> {
        if parts.len() < 3 {
            return Err(DeftError::ParseError(
                "DELTA_PUT requires <virtual_file> HASH:<hash> DATA:<delta>".into(),
            ));
        }

        let virtual_file = parts[0].to_string();

        let mut final_hash = String::new();
        let mut delta_data = String::new();

        for part in &parts[1..] {
            let upper = part.to_uppercase();
            if upper.starts_with("HASH:") {
                final_hash = part[5..].to_string();
            } else if upper.starts_with("DATA:") {
                delta_data = part[5..].to_string();
            }
        }

        if final_hash.is_empty() || delta_data.is_empty() {
            return Err(DeftError::ParseError(
                "DELTA_PUT requires HASH:<hash> and DATA:<delta>".into(),
            ));
        }

        Ok(Command::DeltaPut {
            virtual_file,
            delta_data,
            final_hash,
        })
    }

    /// Parse PAUSE_TRANSFER <transfer_id>
    fn parse_pause_transfer(parts: &[&str]) -> Result<Command, DeftError> {
        if parts.is_empty() {
            return Err(DeftError::ParseError(
                "PAUSE_TRANSFER requires <transfer_id>".into(),
            ));
        }
        Ok(Command::PauseTransfer {
            transfer_id: parts[0].to_string(),
        })
    }

    /// Parse RESUME_TRANSFER_CMD <transfer_id>
    fn parse_resume_transfer_cmd(parts: &[&str]) -> Result<Command, DeftError> {
        if parts.is_empty() {
            return Err(DeftError::ParseError(
                "RESUME_TRANSFER_CMD requires <transfer_id>".into(),
            ));
        }
        Ok(Command::ResumeTransferCmd {
            transfer_id: parts[0].to_string(),
        })
    }

    /// Parse ABORT_TRANSFER <transfer_id> [REASON:<reason>]
    fn parse_abort_transfer(parts: &[&str]) -> Result<Command, DeftError> {
        if parts.is_empty() {
            return Err(DeftError::ParseError(
                "ABORT_TRANSFER requires <transfer_id>".into(),
            ));
        }

        let transfer_id = parts[0].to_string();
        let mut reason = None;

        for part in &parts[1..] {
            let upper = part.to_uppercase();
            if upper.starts_with("REASON:") {
                reason = Some(part[7..].to_string());
            }
        }

        Ok(Command::AbortTransfer {
            transfer_id,
            reason,
        })
    }

    pub fn parse_response(line: &str) -> Result<Response, DeftError> {
        let line = line.trim();
        if !line.starts_with("DEFT ") {
            return Err(DeftError::ParseError(
                "Response must start with 'DEFT '".into(),
            ));
        }

        let rest = &line[5..];
        let parts: Vec<&str> = rest.split_whitespace().collect();

        if parts.is_empty() {
            return Err(DeftError::ParseError("Empty response".into()));
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
            "TRANSFER_PAUSED" => Self::parse_transfer_paused(&parts[1..]),
            "TRANSFER_RESUMED" => Self::parse_transfer_resumed(&parts[1..]),
            "TRANSFER_ABORTED" => Self::parse_transfer_aborted(&parts[1..]),
            resp => Err(DeftError::ParseError(format!("Unknown response: {}", resp))),
        }
    }

    fn parse_welcome(parts: &[&str]) -> Result<Response, DeftError> {
        if parts.is_empty() {
            return Err(DeftError::MissingField("version".into()));
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
            return Err(DeftError::MissingField("session_id".into()));
        };

        Ok(Response::Welcome {
            version,
            capabilities,
            session_id,
        })
    }

    fn parse_auth_ok(rest: &str) -> Result<Response, DeftError> {
        let after_auth_ok = rest
            .strip_prefix("AUTH_OK ")
            .ok_or_else(|| DeftError::ParseError("Invalid AUTH_OK format".into()))?;

        let (partner_name, vf_part) = if let Some(after_quote) = after_auth_ok.strip_prefix('"') {
            let end_quote = after_quote
                .find('"')
                .ok_or_else(|| DeftError::ParseError("Unclosed quote in partner name".into()))?;
            let name = &after_quote[..end_quote];
            let rest = after_quote[end_quote + 1..].trim();
            (name.to_string(), rest)
        } else {
            let parts: Vec<&str> = after_auth_ok.split_whitespace().collect();
            if parts.is_empty() {
                return Err(DeftError::MissingField("partner_name".into()));
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

    fn parse_error(parts: &[&str]) -> Result<Response, DeftError> {
        if parts.is_empty() {
            return Err(DeftError::MissingField("error_code".into()));
        }

        let code_num: u16 = parts[0]
            .parse()
            .map_err(|_| DeftError::ParseError("Invalid error code".into()))?;

        let code = DeftErrorCode::from_code(code_num)
            .ok_or_else(|| DeftError::ParseError(format!("Unknown error code: {}", code_num)))?;

        let message = if parts.len() > 1 {
            Some(parts[1..].join(" "))
        } else {
            None
        };

        Ok(Response::Error { code, message })
    }

    fn parse_chunk_ok(parts: &[&str]) -> Result<Response, DeftError> {
        if parts.len() < 2 {
            return Err(DeftError::MissingField(
                "virtual_file or chunk_index".into(),
            ));
        }

        let virtual_file = parts[0].to_string();
        let chunk_index: u64 = parts[1]
            .parse()
            .map_err(|_| DeftError::ParseError("Invalid chunk index".into()))?;

        Ok(Response::ChunkOk {
            virtual_file,
            chunk_index,
        })
    }

    fn parse_chunk_ack(parts: &[&str]) -> Result<Response, DeftError> {
        if parts.len() < 3 {
            return Err(DeftError::MissingField(
                "virtual_file, chunk_index or status".into(),
            ));
        }

        let virtual_file = parts[0].to_string();
        let chunk_index: u64 = parts[1]
            .parse()
            .map_err(|_| DeftError::ParseError("Invalid chunk index".into()))?;

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
            _ => {
                return Err(DeftError::ParseError(format!(
                    "Invalid ACK status: {}",
                    parts[2]
                )))
            }
        };

        Ok(Response::ChunkAck {
            virtual_file,
            chunk_index,
            status,
        })
    }

    fn parse_chunk_ack_batch(parts: &[&str]) -> Result<Response, DeftError> {
        if parts.len() < 2 {
            return Err(DeftError::MissingField("virtual_file or ranges".into()));
        }

        let virtual_file = parts[0].to_string();
        let ranges: Result<Vec<ChunkRange>, _> = parts[1].split(',').map(|r| r.parse()).collect();

        Ok(Response::ChunkAckBatch {
            virtual_file,
            ranges: ranges?,
        })
    }

    fn parse_transfer_complete(parts: &[&str]) -> Result<Response, DeftError> {
        if parts.len() < 4 {
            return Err(DeftError::MissingField(
                "virtual_file, file_hash, total_size or chunk_count".into(),
            ));
        }

        let virtual_file = parts[0].to_string();
        let file_hash = parts[1].to_string();
        let total_size: u64 = parts[2]
            .parse()
            .map_err(|_| DeftError::ParseError("Invalid total_size".into()))?;
        let chunk_count: u64 = parts[3]
            .parse()
            .map_err(|_| DeftError::ParseError("Invalid chunk_count".into()))?;

        let signature = parts
            .get(4)
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

    fn parse_transfer_accepted(parts: &[&str]) -> Result<Response, DeftError> {
        // TRANSFER_ACCEPTED <transfer_id> <virtual_file> WINDOW_SIZE:<n>
        if parts.len() < 2 {
            return Err(DeftError::MissingField(
                "transfer_id or virtual_file".into(),
            ));
        }

        let transfer_id = parts[0].to_string();
        let virtual_file = parts[1].to_string();

        let window_size = parts
            .get(2)
            .and_then(|s| s.strip_prefix("WINDOW_SIZE:"))
            .and_then(|s| s.parse().ok())
            .unwrap_or(64);

        Ok(Response::TransferAccepted {
            transfer_id,
            virtual_file,
            window_size,
        })
    }

    fn parse_chunk_ready(parts: &[&str]) -> Result<Response, DeftError> {
        // CHUNK_READY <virtual_file> <chunk_index> SIZE:<n>
        if parts.len() < 2 {
            return Err(DeftError::MissingField(
                "virtual_file or chunk_index".into(),
            ));
        }

        let virtual_file = parts[0].to_string();
        let chunk_index: u64 = parts[1]
            .parse()
            .map_err(|_| DeftError::ParseError("Invalid chunk index".into()))?;

        let size = parts
            .get(2)
            .and_then(|s| s.strip_prefix("SIZE:"))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        Ok(Response::ChunkReady {
            virtual_file,
            chunk_index,
            size,
        })
    }

    fn parse_transfer_paused(parts: &[&str]) -> Result<Response, DeftError> {
        if parts.is_empty() {
            return Err(DeftError::MissingField("transfer_id".into()));
        }
        Ok(Response::TransferPaused {
            transfer_id: parts[0].to_string(),
        })
    }

    fn parse_transfer_resumed(parts: &[&str]) -> Result<Response, DeftError> {
        if parts.is_empty() {
            return Err(DeftError::MissingField("transfer_id".into()));
        }
        Ok(Response::TransferResumed {
            transfer_id: parts[0].to_string(),
        })
    }

    fn parse_transfer_aborted(parts: &[&str]) -> Result<Response, DeftError> {
        if parts.is_empty() {
            return Err(DeftError::MissingField("transfer_id".into()));
        }

        let transfer_id = parts[0].to_string();
        let mut reason = None;

        for part in &parts[1..] {
            let upper = part.to_uppercase();
            if upper.starts_with("REASON:") {
                reason = Some(part[7..].to_string());
            }
        }

        Ok(Response::TransferAborted {
            transfer_id,
            reason,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hello() {
        let cmd = Parser::parse_command("DEFT HELLO 1.0 CHUNKED,PARALLEL,RESUME").unwrap();
        match cmd {
            Command::Hello {
                version,
                capabilities,
            } => {
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
        let cmd = Parser::parse_command("DEFT AUTH partner-acme-corp").unwrap();
        match cmd {
            Command::Auth { partner_id } => {
                assert_eq!(partner_id, "partner-acme-corp");
            }
            _ => panic!("Expected Auth command"),
        }
    }

    #[test]
    fn test_parse_get() {
        let cmd = Parser::parse_command("DEFT GET monthly-invoices CHUNKS 0-10").unwrap();
        match cmd {
            Command::Get {
                virtual_file,
                chunks,
            } => {
                assert_eq!(virtual_file, "monthly-invoices");
                assert_eq!(chunks.start, 0);
                assert_eq!(chunks.end, 10);
            }
            _ => panic!("Expected Get command"),
        }
    }

    #[test]
    fn test_parse_put() {
        let cmd =
            Parser::parse_command("DEFT PUT invoices CHUNK 5 SIZE:1024 HASH:abc123def456").unwrap();
        match cmd {
            Command::Put {
                virtual_file,
                chunk_index,
                size,
                hash,
                nonce,
                compressed,
            } => {
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
        let cmd = Parser::parse_command(
            "DEFT PUT invoices CHUNK 5 SIZE:1024 HASH:abc123 NONCE:12345 COMPRESSED",
        )
        .unwrap();
        match cmd {
            Command::Put {
                virtual_file,
                chunk_index,
                size,
                hash,
                nonce,
                compressed,
            } => {
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
        let resp =
            Parser::parse_response("DEFT WELCOME 1.0 CHUNKED,PARALLEL,RESUME sess_20260119_001")
                .unwrap();
        match resp {
            Response::Welcome {
                version,
                capabilities,
                session_id,
            } => {
                assert_eq!(version, "1.0");
                assert!(capabilities.has(crate::Capability::Chunked));
                assert_eq!(session_id, "sess_20260119_001");
            }
            _ => panic!("Expected Welcome response"),
        }
    }

    #[test]
    fn test_parse_auth_ok() {
        let resp = Parser::parse_response(
            "DEFT AUTH_OK \"ACME Corporation\" VF:monthly-invoices,product-catalog",
        )
        .unwrap();
        match resp {
            Response::AuthOk {
                partner_name,
                virtual_files,
            } => {
                assert_eq!(partner_name, "ACME Corporation");
                assert_eq!(virtual_files, vec!["monthly-invoices", "product-catalog"]);
            }
            _ => panic!("Expected AuthOk response"),
        }
    }

    #[test]
    fn test_parse_error() {
        let resp = Parser::parse_response("DEFT ERROR 401 Unauthorized - Invalid partner").unwrap();
        match resp {
            Response::Error { code, message } => {
                assert_eq!(code, DeftErrorCode::Unauthorized);
                assert!(message.is_some());
            }
            _ => panic!("Expected Error response"),
        }
    }

    #[test]
    fn test_parse_hello_with_window_size() {
        let cmd = Parser::parse_command("DEFT HELLO 1.0 CHUNKED,PARALLEL WINDOW_SIZE:128").unwrap();
        match cmd {
            Command::Hello {
                version,
                capabilities,
            } => {
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
        let resp =
            Parser::parse_response("DEFT WELCOME 1.0 CHUNKED,RESUME WINDOW_SIZE:64 sess_123")
                .unwrap();
        match resp {
            Response::Welcome {
                version,
                capabilities,
                session_id,
            } => {
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
        let resp = Parser::parse_response("DEFT CHUNK_ACK invoices 42 OK").unwrap();
        match resp {
            Response::ChunkAck {
                virtual_file,
                chunk_index,
                status,
            } => {
                assert_eq!(virtual_file, "invoices");
                assert_eq!(chunk_index, 42);
                assert_eq!(status, crate::AckStatus::Ok);
            }
            _ => panic!("Expected ChunkAck response"),
        }
    }

    #[test]
    fn test_parse_chunk_ack_error() {
        let resp = Parser::parse_response("DEFT CHUNK_ACK invoices 5 ERROR HASH_MISMATCH").unwrap();
        match resp {
            Response::ChunkAck {
                virtual_file,
                chunk_index,
                status,
            } => {
                assert_eq!(virtual_file, "invoices");
                assert_eq!(chunk_index, 5);
                assert_eq!(
                    status,
                    crate::AckStatus::Error(crate::AckErrorReason::HashMismatch)
                );
            }
            _ => panic!("Expected ChunkAck response"),
        }
    }

    #[test]
    fn test_parse_chunk_ack_batch() {
        let resp = Parser::parse_response("DEFT CHUNK_ACK_BATCH monthly-data 1-50,52-100").unwrap();
        match resp {
            Response::ChunkAckBatch {
                virtual_file,
                ranges,
            } => {
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
        let resp =
            Parser::parse_response("DEFT TRANSFER_COMPLETE invoices sha256:abc123 1048576 100")
                .unwrap();
        match resp {
            Response::TransferComplete {
                virtual_file,
                file_hash,
                total_size,
                chunk_count,
                signature,
            } => {
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
            "DEFT TRANSFER_COMPLETE invoices sha256:abc123 1048576 100 sig:ed25519:xyz789",
        )
        .unwrap();
        match resp {
            Response::TransferComplete {
                virtual_file,
                file_hash,
                total_size,
                chunk_count,
                signature,
            } => {
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
            "DEFT BEGIN_TRANSFER invoices-jan 100 10485760 sha256:abcdef123456",
        )
        .unwrap();
        match cmd {
            Command::BeginTransfer {
                virtual_file,
                total_chunks,
                total_bytes,
                file_hash,
                transfer_id,
            } => {
                assert_eq!(virtual_file, "invoices-jan");
                assert_eq!(total_chunks, 100);
                assert_eq!(total_bytes, 10485760);
                assert_eq!(file_hash, "sha256:abcdef123456");
                assert!(transfer_id.is_none());
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
            transfer_id: None,
        };
        assert_eq!(
            cmd.to_string(),
            "DEFT BEGIN_TRANSFER data-file 50 5242880 sha256:xyz789"
        );
    }

    #[test]
    fn test_begin_transfer_with_transfer_id() {
        let cmd = Parser::parse_command(
            "DEFT BEGIN_TRANSFER invoices 50 1048576 sha256:abc TX_ID:push_12345",
        )
        .unwrap();
        match cmd {
            Command::BeginTransfer {
                virtual_file,
                transfer_id,
                ..
            } => {
                assert_eq!(virtual_file, "invoices");
                assert_eq!(transfer_id, Some("push_12345".to_string()));
            }
            _ => panic!("Expected BeginTransfer command"),
        }
    }

    #[test]
    fn test_begin_transfer_display_with_transfer_id() {
        let cmd = Command::BeginTransfer {
            virtual_file: "data-file".to_string(),
            total_chunks: 50,
            total_bytes: 5242880,
            file_hash: "sha256:xyz789".to_string(),
            transfer_id: Some("tx_sender_123".to_string()),
        };
        assert_eq!(
            cmd.to_string(),
            "DEFT BEGIN_TRANSFER data-file 50 5242880 sha256:xyz789 TX_ID:tx_sender_123"
        );
    }

    // ==================== Transfer Control Commands Tests ====================

    #[test]
    fn test_parse_pause_transfer() {
        let cmd = Parser::parse_command("DEFT PAUSE_TRANSFER tx_12345").unwrap();
        match cmd {
            Command::PauseTransfer { transfer_id } => {
                assert_eq!(transfer_id, "tx_12345");
            }
            _ => panic!("Expected PauseTransfer command"),
        }
    }

    #[test]
    fn test_parse_pause_transfer_missing_id() {
        let result = Parser::parse_command("DEFT PAUSE_TRANSFER");
        assert!(result.is_err());
    }

    #[test]
    fn test_pause_transfer_display() {
        let cmd = Command::PauseTransfer {
            transfer_id: "tx_abc123".to_string(),
        };
        assert_eq!(cmd.to_string(), "DEFT PAUSE_TRANSFER tx_abc123");
    }

    #[test]
    fn test_parse_resume_transfer_cmd() {
        let cmd = Parser::parse_command("DEFT RESUME_TRANSFER_CMD tx_67890").unwrap();
        match cmd {
            Command::ResumeTransferCmd { transfer_id } => {
                assert_eq!(transfer_id, "tx_67890");
            }
            _ => panic!("Expected ResumeTransferCmd command"),
        }
    }

    #[test]
    fn test_parse_resume_transfer_cmd_missing_id() {
        let result = Parser::parse_command("DEFT RESUME_TRANSFER_CMD");
        assert!(result.is_err());
    }

    #[test]
    fn test_resume_transfer_cmd_display() {
        let cmd = Command::ResumeTransferCmd {
            transfer_id: "tx_resume_test".to_string(),
        };
        assert_eq!(cmd.to_string(), "DEFT RESUME_TRANSFER_CMD tx_resume_test");
    }

    #[test]
    fn test_parse_abort_transfer_without_reason() {
        let cmd = Parser::parse_command("DEFT ABORT_TRANSFER tx_cancel123").unwrap();
        match cmd {
            Command::AbortTransfer {
                transfer_id,
                reason,
            } => {
                assert_eq!(transfer_id, "tx_cancel123");
                assert!(reason.is_none());
            }
            _ => panic!("Expected AbortTransfer command"),
        }
    }

    #[test]
    fn test_parse_abort_transfer_with_reason() {
        let cmd = Parser::parse_command("DEFT ABORT_TRANSFER tx_cancel456 REASON:user_requested")
            .unwrap();
        match cmd {
            Command::AbortTransfer {
                transfer_id,
                reason,
            } => {
                assert_eq!(transfer_id, "tx_cancel456");
                assert_eq!(reason, Some("user_requested".to_string()));
            }
            _ => panic!("Expected AbortTransfer command"),
        }
    }

    #[test]
    fn test_parse_abort_transfer_missing_id() {
        let result = Parser::parse_command("DEFT ABORT_TRANSFER");
        assert!(result.is_err());
    }

    #[test]
    fn test_abort_transfer_display_without_reason() {
        let cmd = Command::AbortTransfer {
            transfer_id: "tx_abort_test".to_string(),
            reason: None,
        };
        assert_eq!(cmd.to_string(), "DEFT ABORT_TRANSFER tx_abort_test");
    }

    #[test]
    fn test_abort_transfer_display_with_reason() {
        let cmd = Command::AbortTransfer {
            transfer_id: "tx_abort_test".to_string(),
            reason: Some("timeout".to_string()),
        };
        assert_eq!(
            cmd.to_string(),
            "DEFT ABORT_TRANSFER tx_abort_test REASON:timeout"
        );
    }

    #[test]
    fn test_parse_transfer_paused_response() {
        let resp = Parser::parse_response("DEFT TRANSFER_PAUSED tx_paused123").unwrap();
        match resp {
            Response::TransferPaused { transfer_id } => {
                assert_eq!(transfer_id, "tx_paused123");
            }
            _ => panic!("Expected TransferPaused response"),
        }
    }

    #[test]
    fn test_parse_transfer_resumed_response() {
        let resp = Parser::parse_response("DEFT TRANSFER_RESUMED tx_resumed456").unwrap();
        match resp {
            Response::TransferResumed { transfer_id } => {
                assert_eq!(transfer_id, "tx_resumed456");
            }
            _ => panic!("Expected TransferResumed response"),
        }
    }

    #[test]
    fn test_parse_transfer_aborted_response_without_reason() {
        let resp = Parser::parse_response("DEFT TRANSFER_ABORTED tx_aborted789").unwrap();
        match resp {
            Response::TransferAborted {
                transfer_id,
                reason,
            } => {
                assert_eq!(transfer_id, "tx_aborted789");
                assert!(reason.is_none());
            }
            _ => panic!("Expected TransferAborted response"),
        }
    }

    #[test]
    fn test_parse_transfer_aborted_response_with_reason() {
        let resp =
            Parser::parse_response("DEFT TRANSFER_ABORTED tx_aborted789 REASON:network_error")
                .unwrap();
        match resp {
            Response::TransferAborted {
                transfer_id,
                reason,
            } => {
                assert_eq!(transfer_id, "tx_aborted789");
                assert_eq!(reason, Some("network_error".to_string()));
            }
            _ => panic!("Expected TransferAborted response"),
        }
    }

    #[test]
    fn test_transfer_control_roundtrip_pause() {
        let original = Command::PauseTransfer {
            transfer_id: "roundtrip_test".to_string(),
        };
        let serialized = original.to_string();
        let parsed = Parser::parse_command(&serialized).unwrap();
        assert_eq!(format!("{:?}", original), format!("{:?}", parsed));
    }

    #[test]
    fn test_transfer_control_roundtrip_resume() {
        let original = Command::ResumeTransferCmd {
            transfer_id: "roundtrip_resume".to_string(),
        };
        let serialized = original.to_string();
        let parsed = Parser::parse_command(&serialized).unwrap();
        assert_eq!(format!("{:?}", original), format!("{:?}", parsed));
    }

    #[test]
    fn test_transfer_control_roundtrip_abort_with_reason() {
        let original = Command::AbortTransfer {
            transfer_id: "roundtrip_abort".to_string(),
            reason: Some("test_reason".to_string()),
        };
        let serialized = original.to_string();
        let parsed = Parser::parse_command(&serialized).unwrap();
        assert_eq!(format!("{:?}", original), format!("{:?}", parsed));
    }
}
