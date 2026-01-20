use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rift_protocol::{Capabilities, Capability, DEFAULT_WINDOW_SIZE};

static SESSION_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    Connected,
    Welcomed,
    Authenticated,
    Closed,
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
        }
    }

    pub fn set_cert_cn(&mut self, cn: String) {
        self.cert_cn = Some(cn);
    }

    pub fn get_cert_cn(&self) -> Option<&str> {
        self.cert_cn.as_deref()
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

        session.remove_transfer("transfer-2");
        assert!(session.active_transfer_ids.is_empty());
    }

    #[test]
    fn test_session_default() {
        let session = Session::default();
        assert_eq!(session.state, SessionState::Connected);
        assert!(session.id.starts_with("sess_"));
    }
}
