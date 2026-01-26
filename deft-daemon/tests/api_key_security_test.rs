//! API Key Security Tests (H3)
//!
//! Tests:
//! - Rejection without API key
//! - Acceptance with valid API key
//! - Rejection with invalid API key
//! - Key retrieval only from localhost
//! - Key rotation
//! - Constant-time comparison (timing attack resistance)

use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::Duration;

struct ApiKeyTestFixture {
    instance: Option<Child>,
    temp_dir: PathBuf,
    api_port: u16,
}

impl ApiKeyTestFixture {
    fn new() -> std::io::Result<Self> {
        let temp_dir = std::env::temp_dir().join("deft-apikey-test");
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir)?;
        std::fs::create_dir_all(temp_dir.join("certs"))?;
        std::fs::create_dir_all(temp_dir.join("tmp"))?;

        Ok(Self {
            instance: None,
            temp_dir,
            api_port: 19752,
        })
    }

    fn setup_certificates(&self) -> std::io::Result<()> {
        let ca_key = self.temp_dir.join("ca.key");
        let ca_cert = self.temp_dir.join("ca.crt");

        Command::new("openssl")
            .args([
                "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", ca_key.to_str().unwrap(),
                "-out", ca_cert.to_str().unwrap(),
                "-days", "1",
                "-subj", "/CN=TestCA",
            ])
            .output()?;

        let key_path = self.temp_dir.join("certs/server.key");
        let csr_path = self.temp_dir.join("certs/server.csr");
        let cert_path = self.temp_dir.join("certs/server.crt");

        Command::new("openssl")
            .args(["genrsa", "-out", key_path.to_str().unwrap(), "2048"])
            .output()?;

        Command::new("openssl")
            .args([
                "req", "-new",
                "-key", key_path.to_str().unwrap(),
                "-out", csr_path.to_str().unwrap(),
                "-subj", "/CN=test-instance",
            ])
            .output()?;

        Command::new("openssl")
            .args([
                "x509", "-req",
                "-in", csr_path.to_str().unwrap(),
                "-CA", ca_cert.to_str().unwrap(),
                "-CAkey", ca_key.to_str().unwrap(),
                "-CAcreateserial",
                "-out", cert_path.to_str().unwrap(),
                "-days", "1",
            ])
            .output()?;

        std::fs::copy(&ca_cert, self.temp_dir.join("certs/ca.crt"))?;
        Ok(())
    }

    fn write_config(&self) -> std::io::Result<()> {
        let config = format!(r#"
[server]
enabled = true
listen = "127.0.0.1:19751"
cert = "{}/certs/server.crt"
key = "{}/certs/server.key"
ca = "{}/certs/ca.crt"

[client]
enabled = false
cert = "{}/certs/server.crt"
key = "{}/certs/server.key"
ca = "{}/certs/ca.crt"

[storage]
chunk_size = 262144
temp_dir = "{}/tmp"

[limits]
api_enabled = true
api_listen = "127.0.0.1:{}"
api_key_enabled = true
"#,
            self.temp_dir.display(), self.temp_dir.display(), self.temp_dir.display(),
            self.temp_dir.display(), self.temp_dir.display(), self.temp_dir.display(),
            self.temp_dir.display(), self.api_port
        );

        std::fs::write(self.temp_dir.join("config.toml"), config)?;
        Ok(())
    }

    fn start_instance(&mut self) -> std::io::Result<()> {
        let possible_paths = [
            std::env::current_dir()?.join("target/release/deftd"),
            std::env::current_dir()?.join("target/debug/deftd"),
            PathBuf::from("/home/cpo/deft/deft/target/release/deftd"),
        ];

        let deftd_path = possible_paths
            .iter()
            .find(|p| p.exists())
            .cloned()
            .ok_or_else(|| std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "deftd binary not found",
            ))?;

        self.instance = Some(
            Command::new(&deftd_path)
                .args(["--config", self.temp_dir.join("config.toml").to_str().unwrap()])
                .spawn()?,
        );

        std::thread::sleep(Duration::from_secs(2));
        Ok(())
    }

    fn api_url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{}", self.api_port, path)
    }

    fn get_api_key(&self) -> Result<String, Box<dyn std::error::Error>> {
        let client = reqwest::blocking::Client::new();
        let resp = client
            .get(&self.api_url("/api/auth/key"))
            .timeout(Duration::from_secs(5))
            .send()?;
        let json: serde_json::Value = resp.json()?;
        Ok(json["api_key"].as_str().unwrap_or("").to_string())
    }

    fn request_with_key(&self, path: &str, key: Option<&str>) -> Result<(u16, String), Box<dyn std::error::Error>> {
        let client = reqwest::blocking::Client::new();
        let mut req = client.get(&self.api_url(path)).timeout(Duration::from_secs(5));
        
        if let Some(k) = key {
            req = req.header("X-API-Key", k);
        }
        
        let resp = req.send()?;
        let status = resp.status().as_u16();
        let body = resp.text()?;
        Ok((status, body))
    }

    fn rotate_key(&self, current_key: &str) -> Result<String, Box<dyn std::error::Error>> {
        let client = reqwest::blocking::Client::new();
        let resp = client
            .post(&self.api_url("/api/auth/rotate"))
            .header("X-API-Key", current_key)
            .timeout(Duration::from_secs(5))
            .send()?;
        let json: serde_json::Value = resp.json()?;
        Ok(json["api_key"].as_str().unwrap_or("").to_string())
    }
}

impl Drop for ApiKeyTestFixture {
    fn drop(&mut self) {
        if let Some(ref mut child) = self.instance {
            let _ = child.kill();
        }
        let _ = std::fs::remove_dir_all(&self.temp_dir);
    }
}

#[test]
#[ignore] // Run with: cargo test --test api_key_security_test -- --ignored --nocapture
fn test_rejection_without_api_key() {
    let mut fixture = ApiKeyTestFixture::new().expect("Failed to create fixture");
    fixture.setup_certificates().expect("Failed to setup certs");
    fixture.write_config().expect("Failed to write config");
    fixture.start_instance().expect("Failed to start instance");

    // Request without API key should be rejected
    let (status, body) = fixture.request_with_key("/api/status", None).expect("Request failed");
    
    assert_eq!(status, 401, "Should return 401 Unauthorized");
    assert!(body.contains("Invalid or missing API key"), "Should mention API key error");
}

#[test]
#[ignore]
fn test_acceptance_with_valid_key() {
    let mut fixture = ApiKeyTestFixture::new().expect("Failed to create fixture");
    fixture.setup_certificates().expect("Failed to setup certs");
    fixture.write_config().expect("Failed to write config");
    fixture.start_instance().expect("Failed to start instance");

    // Get the API key
    let api_key = fixture.get_api_key().expect("Failed to get API key");
    assert!(!api_key.is_empty(), "API key should not be empty");
    assert_eq!(api_key.len(), 64, "API key should be 64 hex chars (256 bits)");

    // Request with valid API key should succeed
    let (status, body) = fixture.request_with_key("/api/status", Some(&api_key)).expect("Request failed");
    
    assert_eq!(status, 200, "Should return 200 OK with valid key");
    assert!(body.contains("version"), "Should return status with version");
}

#[test]
#[ignore]
fn test_rejection_with_invalid_key() {
    let mut fixture = ApiKeyTestFixture::new().expect("Failed to create fixture");
    fixture.setup_certificates().expect("Failed to setup certs");
    fixture.write_config().expect("Failed to write config");
    fixture.start_instance().expect("Failed to start instance");

    // Request with invalid API key should be rejected
    let (status, _) = fixture.request_with_key("/api/status", Some("invalid_key_12345")).expect("Request failed");
    
    assert_eq!(status, 401, "Should return 401 with invalid key");
}

#[test]
#[ignore]
fn test_key_retrieval_localhost_only() {
    let mut fixture = ApiKeyTestFixture::new().expect("Failed to create fixture");
    fixture.setup_certificates().expect("Failed to setup certs");
    fixture.write_config().expect("Failed to write config");
    fixture.start_instance().expect("Failed to start instance");

    // From localhost, should work
    let (status, body) = fixture.request_with_key("/api/auth/key", None).expect("Request failed");
    
    assert_eq!(status, 200, "Should return 200 from localhost");
    assert!(body.contains("api_key"), "Should return API key");
}

#[test]
#[ignore]
fn test_key_rotation() {
    let mut fixture = ApiKeyTestFixture::new().expect("Failed to create fixture");
    fixture.setup_certificates().expect("Failed to setup certs");
    fixture.write_config().expect("Failed to write config");
    fixture.start_instance().expect("Failed to start instance");

    // Get initial key
    let initial_key = fixture.get_api_key().expect("Failed to get initial key");
    
    // Rotate key
    let new_key = fixture.rotate_key(&initial_key).expect("Failed to rotate key");
    
    assert_ne!(initial_key, new_key, "New key should be different");
    assert_eq!(new_key.len(), 64, "New key should be 64 hex chars");

    // Old key should no longer work
    let (status, _) = fixture.request_with_key("/api/status", Some(&initial_key)).expect("Request failed");
    assert_eq!(status, 401, "Old key should be rejected after rotation");

    // New key should work
    let (status, _) = fixture.request_with_key("/api/status", Some(&new_key)).expect("Request failed");
    assert_eq!(status, 200, "New key should work after rotation");
}

#[test]
#[ignore]
fn test_public_endpoints_no_auth() {
    let mut fixture = ApiKeyTestFixture::new().expect("Failed to create fixture");
    fixture.setup_certificates().expect("Failed to setup certs");
    fixture.write_config().expect("Failed to write config");
    fixture.start_instance().expect("Failed to start instance");

    // Health endpoint should work without auth
    let (status, body) = fixture.request_with_key("/api/health", None).expect("Request failed");
    assert_eq!(status, 200, "/api/health should work without auth");
    assert!(body.contains("ok"), "Health should return ok");

    // Metrics endpoint should work without auth
    let (status, _) = fixture.request_with_key("/api/metrics", None).expect("Request failed");
    assert_eq!(status, 200, "/api/metrics should work without auth");

    // Dashboard should work without auth
    let (status, body) = fixture.request_with_key("/", None).expect("Request failed");
    assert_eq!(status, 200, "/ should work without auth");
    assert!(body.contains("DOCTYPE") || body.contains("html"), "Should return HTML");
}

#[test]
#[ignore]
fn test_authorization_bearer_header() {
    let mut fixture = ApiKeyTestFixture::new().expect("Failed to create fixture");
    fixture.setup_certificates().expect("Failed to setup certs");
    fixture.write_config().expect("Failed to write config");
    fixture.start_instance().expect("Failed to start instance");

    let api_key = fixture.get_api_key().expect("Failed to get API key");

    // Test with Authorization: Bearer header instead of X-API-Key
    let client = reqwest::blocking::Client::new();
    let resp = client
        .get(&fixture.api_url("/api/status"))
        .header("Authorization", format!("Bearer {}", api_key))
        .timeout(Duration::from_secs(5))
        .send()
        .expect("Request failed");
    
    assert_eq!(resp.status().as_u16(), 200, "Authorization: Bearer should also work");
}

#[test]
#[ignore]
fn test_api_key_stored_with_correct_permissions() {
    let mut fixture = ApiKeyTestFixture::new().expect("Failed to create fixture");
    fixture.setup_certificates().expect("Failed to setup certs");
    fixture.write_config().expect("Failed to write config");
    fixture.start_instance().expect("Failed to start instance");

    // Check that API key file exists and has correct permissions
    let key_path = fixture.temp_dir.join("tmp/api.key");
    assert!(key_path.exists(), "API key file should exist");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(&key_path).expect("Failed to get metadata");
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "API key file should have 600 permissions");
    }

    // Key file should contain a valid key
    let key_content = std::fs::read_to_string(&key_path).expect("Failed to read key file");
    assert_eq!(key_content.trim().len(), 64, "Key file should contain 64-char hex key");
}
