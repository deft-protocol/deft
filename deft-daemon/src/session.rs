//! Session management.
//!
//! Some methods reserved for session introspection.
#![allow(dead_code)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use deft_protocol::{Capabilities, Capability, DEFAULT_WINDOW_SIZE};

static SESSION_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    Connected,
    Welcomed,
    Authenticated,
    Closed,
}

/// Client certificate information extracted during mTLS handshake
#[derive(Debug, Clone, Default)]
pub struct ClientCertInfo {
    /// Common Name (CN) from the certificate subject
    pub cn: Option<String>,
    /// SHA-256 fingerprint of the certificate (hex encoded)
    pub fingerprint: Option<String>,
    /// Certificate serial number
    pub serial: Option<String>,
}

#[derive(Debug)]
pub struct Session {
    pub id: String,
    pub state: SessionState,
    pub protocol_version: Option<String>,
    pub capabilities: Capabilities,
    pub window_size: u32,
    pub partner_id: Option<String>,
    pub partner_name: Option<String>,
    pub allowed_virtual_files: Vec<String>,
    pub active_transfer_ids: Vec<String>,
    pub cert_cn: Option<String>,
    /// mTLS client certificate information
    pub cert_info: ClientCertInfo,
    // Pull transfer tracking
    pub active_pull_transfer: Option<String>,
    pub active_pull_vf: Option<String>,
    pub pull_total_chunks: u64,
    pub pull_chunks_sent: u64,
    // Push transfer tracking
    pub last_chunk_compressed: bool,
    // Transfer control state
    pub active_transfer: Option<ActiveTransfer>,
}

/// Active transfer state for pause/resume/abort
#[derive(Debug, Clone)]
pub struct ActiveTransfer {
    pub id: String,
    pub virtual_file: String,
    pub paused: bool,
}

impl Session {
    pub fn new() -> Self {
        let session_id = generate_session_id();
        Self {
            id: session_id,
            state: SessionState::Connected,
            protocol_version: None,
            capabilities: Capabilities::new(),
            window_size: DEFAULT_WINDOW_SIZE,
            partner_id: None,
            partner_name: None,
            allowed_virtual_files: Vec::new(),
            active_transfer_ids: Vec::new(),
            cert_cn: None,
            cert_info: ClientCertInfo::default(),
            active_pull_transfer: None,
            active_pull_vf: None,
            pull_total_chunks: 0,
            pull_chunks_sent: 0,
            last_chunk_compressed: false,
            active_transfer: None,
        }
    }

    pub fn set_cert_cn(&mut self, cn: String) {
        self.cert_cn = Some(cn.clone());
        self.cert_info.cn = Some(cn);
    }

    pub fn set_cert_info(&mut self, info: ClientCertInfo) {
        self.cert_cn = info.cn.clone();
        self.cert_info = info;
    }

    pub fn get_cert_cn(&self) -> Option<&str> {
        self.cert_info.cn.as_deref()
    }

    pub fn get_cert_fingerprint(&self) -> Option<&str> {
        self.cert_info.fingerprint.as_deref()
    }

    pub fn partner_id(&self) -> Option<&str> {
        self.partner_id.as_deref()
    }

    pub fn set_welcomed(&mut self, version: String, capabilities: Capabilities) {
        self.protocol_version = Some(version);
        self.window_size = capabilities.window_size.unwrap_or(DEFAULT_WINDOW_SIZE);
        self.capabilities = capabilities;
        self.state = SessionState::Welcomed;
    }

    pub fn set_authenticated(
        &mut self,
        partner_id: String,
        partner_name: String,
        virtual_files: Vec<String>,
    ) {
        self.partner_id = Some(partner_id);
        self.partner_name = Some(partner_name);
        self.allowed_virtual_files = virtual_files;
        self.state = SessionState::Authenticated;
    }

    pub fn close(&mut self) {
        self.state = SessionState::Closed;
    }

    pub fn is_authenticated(&self) -> bool {
        self.state == SessionState::Authenticated
    }

    pub fn can_access_virtual_file(&self, vf_name: &str) -> bool {
        self.allowed_virtual_files.iter().any(|vf| vf == vf_name)
    }

    pub fn has_capability(&self, cap: Capability) -> bool {
        self.capabilities.has(cap)
    }

    pub fn add_transfer(&mut self, transfer_id: String) {
        self.active_transfer_ids.push(transfer_id);
    }

    pub fn remove_transfer(&mut self, transfer_id: &str) {
        self.active_transfer_ids.retain(|id| id != transfer_id);
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

fn generate_session_id() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let counter = SESSION_COUNTER.fetch_add(1, Ordering::SeqCst);

    format!("sess_{}_{:03}", timestamp, counter % 1000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_lifecycle() {
        let mut session = Session::new();
        assert_eq!(session.state, SessionState::Connected);
        assert!(session.id.starts_with("sess_"));

        session.set_welcomed("1.0".into(), Capabilities::all());
        assert_eq!(session.state, SessionState::Welcomed);
        assert!(session.has_capability(Capability::Chunked));

        session.set_authenticated(
            "partner-1".into(),
            "Partner One".into(),
            vec!["file1".into(), "file2".into()],
        );
        assert_eq!(session.state, SessionState::Authenticated);
        assert!(session.is_authenticated());
        assert!(session.can_access_virtual_file("file1"));
        assert!(!session.can_access_virtual_file("file3"));

        session.close();
        assert_eq!(session.state, SessionState::Closed);
    }

    #[test]
    fn test_session_window_size() {
        let mut session = Session::new();
        assert_eq!(session.window_size, DEFAULT_WINDOW_SIZE);

        let caps = Capabilities::new().with_window_size(128);
        session.set_welcomed("1.0".into(), caps);
        assert_eq!(session.window_size, 128);
    }

    #[test]
    fn test_session_window_size_default_when_not_specified() {
        let mut session = Session::new();
        let caps = Capabilities::new(); // No window_size
        session.set_welcomed("1.0".into(), caps);
        assert_eq!(session.window_size, DEFAULT_WINDOW_SIZE);
    }

    #[test]
    fn test_session_transfer_tracking() {
        let mut session = Session::new();
        assert!(session.active_transfer_ids.is_empty());

        session.add_transfer("transfer-1".into());
        session.add_transfer("transfer-2".into());
        assert_eq!(session.active_transfer_ids.len(), 2);

        session.remove_transfer("transfer-1");
        assert_eq!(session.active_transfer_ids.len(), 1);
        assert_eq!(session.active_transfer_ids[0], "transfer-2");
    }

    #[test]
    fn test_session_cert_info() {
        let mut session = Session::new();
        assert!(session.get_cert_cn().is_none());
        assert!(session.get_cert_fingerprint().is_none());

        let cert_info = ClientCertInfo {
            cn: Some("partner-1".to_string()),
            fingerprint: Some("abc123def456".to_string()),
            serial: Some("12345678".to_string()),
        };
        session.set_cert_info(cert_info);

        assert_eq!(session.get_cert_cn(), Some("partner-1"));
        assert_eq!(session.get_cert_fingerprint(), Some("abc123def456"));
    }

    #[test]
    fn test_session_cert_cn_only() {
        let mut session = Session::new();
        session.set_cert_cn("test-cn".to_string());

        assert_eq!(session.get_cert_cn(), Some("test-cn"));
        assert!(session.get_cert_fingerprint().is_none());
    }

    #[test]
    fn test_session_default() {
        let session = Session::default();
        assert_eq!(session.state, SessionState::Connected);
        assert!(session.id.starts_with("sess_"));
    }

    #[test]
    fn test_session_state_transitions() {
        let mut session = Session::new();

        assert_eq!(session.state, SessionState::Connected);
        assert!(!session.is_authenticated());

        session.state = SessionState::Welcomed;
        assert_eq!(session.state, SessionState::Welcomed);
        assert!(!session.is_authenticated());

        session.state = SessionState::Authenticated;
        assert!(session.is_authenticated());

        session.state = SessionState::Closed;
        assert!(!session.is_authenticated());
    }

    #[test]
    fn test_session_active_transfer() {
        let mut session = Session::new();
        assert!(session.active_transfer.is_none());

        session.active_transfer = Some(ActiveTransfer {
            id: "tx-001".to_string(),
            virtual_file: "file.dat".to_string(),
            paused: false,
        });

        let transfer = session.active_transfer.as_ref().unwrap();
        assert_eq!(transfer.id, "tx-001");
        assert!(!transfer.paused);

        // Pause the transfer
        session.active_transfer.as_mut().unwrap().paused = true;
        assert!(session.active_transfer.as_ref().unwrap().paused);
    }

    #[test]
    fn test_session_pull_tracking() {
        let mut session = Session::new();

        session.active_pull_transfer = Some("pull-tx-001".to_string());
        session.active_pull_vf = Some("data.bin".to_string());
        session.pull_total_chunks = 100;
        session.pull_chunks_sent = 50;

        assert_eq!(
            session.active_pull_transfer,
            Some("pull-tx-001".to_string())
        );
        assert_eq!(session.pull_chunks_sent, 50);
    }

    #[test]
    fn test_client_cert_info_default() {
        let info = ClientCertInfo::default();
        assert!(info.cn.is_none());
        assert!(info.fingerprint.is_none());
        assert!(info.serial.is_none());
    }

    #[test]
    fn test_session_multiple_virtual_files() {
        let mut session = Session::new();
        session.set_authenticated(
            "partner".to_string(),
            "Partner Name".to_string(),
            vec!["vf1".to_string(), "vf2".to_string(), "vf3".to_string()],
        );

        assert!(session.can_access_virtual_file("vf1"));
        assert!(session.can_access_virtual_file("vf2"));
        assert!(session.can_access_virtual_file("vf3"));
        assert!(!session.can_access_virtual_file("vf4"));
    }

    #[test]
    fn test_generate_unique_session_ids() {
        let session1 = Session::new();
        let session2 = Session::new();
        let session3 = Session::new();

        assert_ne!(session1.id, session2.id);
        assert_ne!(session2.id, session3.id);
        assert_ne!(session1.id, session3.id);
    }

    #[test]
    fn test_session_capabilities() {
        let mut session = Session::new();

        let caps = Capabilities::new()
            .with(Capability::Chunked)
            .with(Capability::Parallel);

        session.set_welcomed("2.0".to_string(), caps);

        assert!(session.has_capability(Capability::Chunked));
        assert!(session.has_capability(Capability::Parallel));
    }
}
