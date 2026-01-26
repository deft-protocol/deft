//! Delta-sync integration tests (C1)
//!
//! Tests:
//! - New file transfer (no existing file on receiver)
//! - Small modification (delta sync should transfer only changed blocks)
//! - Large modification (delta sync with significant changes)
//! - File hash verification after delta sync

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::Duration;

/// Test fixture for delta-sync integration tests
struct DeltaSyncTestFixture {
    instance_a: Option<Child>,
    instance_b: Option<Child>,
    temp_dir: PathBuf,
    instance_a_received: PathBuf,
    instance_b_shares: PathBuf,
}

impl DeltaSyncTestFixture {
    const API_A: &'static str = "http://127.0.0.1:17752";
    const API_B: &'static str = "http://127.0.0.1:17762";
    const DEFT_A: &'static str = "127.0.0.1:17751";

    fn new() -> std::io::Result<Self> {
        let temp_dir = std::env::temp_dir().join("deft-delta-test");
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir)?;

        let instance_a_dir = temp_dir.join("instance-a");
        let instance_b_dir = temp_dir.join("instance-b");
        let instance_a_received = instance_a_dir.join("received");
        let instance_b_shares = instance_b_dir.join("shares");

        std::fs::create_dir_all(&instance_a_dir.join("certs"))?;
        std::fs::create_dir_all(&instance_a_received)?;
        std::fs::create_dir_all(&instance_a_dir.join("tmp"))?;
        std::fs::create_dir_all(&instance_b_dir.join("certs"))?;
        std::fs::create_dir_all(&instance_b_shares)?;
        std::fs::create_dir_all(&instance_b_dir.join("tmp"))?;

        Ok(Self {
            instance_a: None,
            instance_b: None,
            temp_dir,
            instance_a_received,
            instance_b_shares,
        })
    }

    fn setup_certificates(&self) -> std::io::Result<()> {
        // Generate test certificates using openssl
        let ca_key = self.temp_dir.join("ca.key");
        let ca_cert = self.temp_dir.join("ca.crt");

        // Generate CA key and cert
        Command::new("openssl")
            .args([
                "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", ca_key.to_str().unwrap(),
                "-out", ca_cert.to_str().unwrap(),
                "-days", "1",
                "-subj", "/CN=TestCA",
            ])
            .output()?;

        // Generate instance-a cert
        self.generate_cert("instance-a", &ca_key, &ca_cert)?;
        // Generate instance-b cert
        self.generate_cert("instance-b", &ca_key, &ca_cert)?;

        // Copy CA to both instances
        std::fs::copy(&ca_cert, self.temp_dir.join("instance-a/certs/ca.crt"))?;
        std::fs::copy(&ca_cert, self.temp_dir.join("instance-b/certs/ca.crt"))?;

        Ok(())
    }

    fn generate_cert(&self, name: &str, ca_key: &PathBuf, ca_cert: &PathBuf) -> std::io::Result<()> {
        let key_path = self.temp_dir.join(format!("{}/certs/server.key", name));
        let csr_path = self.temp_dir.join(format!("{}/certs/server.csr", name));
        let cert_path = self.temp_dir.join(format!("{}/certs/server.crt", name));

        // Generate key
        Command::new("openssl")
            .args([
                "genrsa", "-out", key_path.to_str().unwrap(), "2048",
            ])
            .output()?;

        // Generate CSR
        Command::new("openssl")
            .args([
                "req", "-new",
                "-key", key_path.to_str().unwrap(),
                "-out", csr_path.to_str().unwrap(),
                "-subj", &format!("/CN={}", name),
            ])
            .output()?;

        // Sign with CA
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

        Ok(())
    }

    fn write_configs(&self) -> std::io::Result<()> {
        // Instance A config (receiver)
        let config_a = format!(r#"
[server]
enabled = true
listen = "127.0.0.1:17751"
cert = "{}/instance-a/certs/server.crt"
key = "{}/instance-a/certs/server.key"
ca = "{}/instance-a/certs/ca.crt"

[client]
enabled = true
cert = "{}/instance-a/certs/server.crt"
key = "{}/instance-a/certs/server.key"
ca = "{}/instance-a/certs/ca.crt"

[storage]
chunk_size = 262144
temp_dir = "{}/instance-a/tmp"

[limits]
api_enabled = true
api_listen = "127.0.0.1:17752"
api_key_enabled = false

[[partners]]
id = "instance-b"

[[partners.virtual_files]]
name = "delta-test-files"
path = "{}/instance-a/received/"
direction = "receive"
"#,
            self.temp_dir.display(), self.temp_dir.display(), self.temp_dir.display(),
            self.temp_dir.display(), self.temp_dir.display(), self.temp_dir.display(),
            self.temp_dir.display(), self.temp_dir.display()
        );

        std::fs::write(self.temp_dir.join("instance-a/config.toml"), config_a)?;

        // Instance B config (sender)
        let config_b = format!(r#"
[server]
enabled = true
listen = "127.0.0.1:17761"
cert = "{}/instance-b/certs/server.crt"
key = "{}/instance-b/certs/server.key"
ca = "{}/instance-b/certs/ca.crt"

[client]
enabled = true
cert = "{}/instance-b/certs/server.crt"
key = "{}/instance-b/certs/server.key"
ca = "{}/instance-b/certs/ca.crt"

[storage]
chunk_size = 262144
temp_dir = "{}/instance-b/tmp"

[limits]
api_enabled = true
api_listen = "127.0.0.1:17762"
api_key_enabled = false

[[partners]]
id = "instance-a"

[[partners.virtual_files]]
name = "delta-test-files"
path = "{}/instance-b/shares/"
direction = "send"

[[trusted_servers]]
name = "A"
address = "127.0.0.1:17751"
skip_verify = true
"#,
            self.temp_dir.display(), self.temp_dir.display(), self.temp_dir.display(),
            self.temp_dir.display(), self.temp_dir.display(), self.temp_dir.display(),
            self.temp_dir.display(), self.temp_dir.display()
        );

        std::fs::write(self.temp_dir.join("instance-b/config.toml"), config_b)?;

        Ok(())
    }

    fn start_instances(&mut self) -> std::io::Result<()> {
        // Find deftd binary - check multiple locations
        let possible_paths = [
            std::env::current_dir()?.join("target/release/deftd"),
            std::env::current_dir()?.join("target/debug/deftd"),
            std::env::current_dir()?.join("../target/release/deftd"),
            std::env::current_dir()?.join("../target/debug/deftd"),
            PathBuf::from("/home/cpo/deft/deft/target/release/deftd"),
        ];
        
        let deftd_path = possible_paths
            .iter()
            .find(|p| p.exists())
            .cloned()
            .ok_or_else(|| std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("deftd binary not found. Checked: {:?}", possible_paths),
            ))?;

        // Start instance A
        self.instance_a = Some(
            Command::new(&deftd_path)
                .args(["--config", self.temp_dir.join("instance-a/config.toml").to_str().unwrap()])
                .spawn()?,
        );

        // Start instance B
        self.instance_b = Some(
            Command::new(&deftd_path)
                .args(["--config", self.temp_dir.join("instance-b/config.toml").to_str().unwrap()])
                .spawn()?,
        );

        // Wait for instances to start
        std::thread::sleep(Duration::from_secs(2));

        Ok(())
    }

    fn create_test_file(&self, name: &str, size_bytes: usize) -> std::io::Result<PathBuf> {
        let path = self.instance_b_shares.join(name);
        let mut file = std::fs::File::create(&path)?;
        
        // Create deterministic content
        let mut data = vec![0u8; size_bytes];
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = (i % 256) as u8;
        }
        file.write_all(&data)?;
        
        Ok(path)
    }

    fn modify_file_small(&self, name: &str, offset: usize, change_size: usize) -> std::io::Result<()> {
        let path = self.instance_b_shares.join(name);
        let mut data = std::fs::read(&path)?;
        
        // Modify a small section
        for i in 0..change_size.min(data.len() - offset) {
            data[offset + i] = data[offset + i].wrapping_add(1);
        }
        
        std::fs::write(&path, &data)?;
        Ok(())
    }

    fn modify_file_large(&self, name: &str, change_percent: usize) -> std::io::Result<()> {
        let path = self.instance_b_shares.join(name);
        let mut data = std::fs::read(&path)?;
        
        // Modify a percentage of the file
        let change_bytes = (data.len() * change_percent) / 100;
        let step = data.len() / change_bytes.max(1);
        
        for i in (0..data.len()).step_by(step.max(1)) {
            data[i] = data[i].wrapping_add(1);
        }
        
        std::fs::write(&path, &data)?;
        Ok(())
    }

    fn compute_file_hash(path: &PathBuf) -> std::io::Result<String> {
        use sha2::{Digest, Sha256};
        let mut file = std::fs::File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];
        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }
        Ok(format!("{:x}", hasher.finalize()))
    }

    fn connect_b_to_a(&self) -> Result<bool, Box<dyn std::error::Error>> {
        let client = reqwest::blocking::Client::new();
        let resp = client
            .post(&format!("{}/api/client/connect", Self::API_B))
            .json(&serde_json::json!({
                "server_name": "A",
                "our_identity": "instance-b"
            }))
            .timeout(Duration::from_secs(10))
            .send()?;
        
        let json: serde_json::Value = resp.json()?;
        Ok(json["success"].as_bool().unwrap_or(false))
    }

    fn push_file(&self, file_path: &PathBuf) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let client = reqwest::blocking::Client::new();
        let resp = client
            .post(&format!("{}/api/client/push", Self::API_B))
            .json(&serde_json::json!({
                "file_path": file_path.to_str().unwrap(),
                "partner_id": "instance-a",
                "virtual_file": "delta-test-files"
            }))
            .timeout(Duration::from_secs(60))
            .send()?;
        
        Ok(resp.json()?)
    }

    fn get_received_files(&self) -> std::io::Result<Vec<PathBuf>> {
        let mut files = Vec::new();
        for entry in std::fs::read_dir(&self.instance_a_received)? {
            let entry = entry?;
            if entry.path().is_file() {
                files.push(entry.path());
            }
        }
        files.sort();
        Ok(files)
    }

    fn get_most_recent_received(&self) -> std::io::Result<Option<PathBuf>> {
        let mut files = self.get_received_files()?;
        files.sort_by_key(|f| {
            f.metadata()
                .and_then(|m| m.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
        });
        Ok(files.last().cloned())
    }
}

impl Drop for DeltaSyncTestFixture {
    fn drop(&mut self) {
        // Kill instances
        if let Some(ref mut child) = self.instance_a {
            let _ = child.kill();
        }
        if let Some(ref mut child) = self.instance_b {
            let _ = child.kill();
        }
        // Cleanup temp dir
        let _ = std::fs::remove_dir_all(&self.temp_dir);
    }
}

#[test]
#[ignore] // Run with: cargo test --test delta_sync_integration -- --ignored --nocapture
fn test_delta_sync_new_file() {
    let mut fixture = DeltaSyncTestFixture::new().expect("Failed to create fixture");
    fixture.setup_certificates().expect("Failed to setup certs");
    fixture.write_configs().expect("Failed to write configs");
    fixture.start_instances().expect("Failed to start instances");

    // Create a 1MB test file
    let test_file = fixture
        .create_test_file("delta-new.bin", 1024 * 1024)
        .expect("Failed to create test file");
    let source_hash = DeltaSyncTestFixture::compute_file_hash(&test_file).expect("Failed to hash");

    // Connect and push
    assert!(fixture.connect_b_to_a().expect("Connect failed"), "Connection should succeed");
    
    let result = fixture.push_file(&test_file).expect("Push failed");
    assert!(result["success"].as_bool().unwrap_or(false), "Push should succeed");

    // Wait for transfer
    std::thread::sleep(Duration::from_secs(2));

    // Verify file received
    let received = fixture.get_most_recent_received().expect("Failed to get received");
    assert!(received.is_some(), "Should have received file");
    
    let received_hash = DeltaSyncTestFixture::compute_file_hash(&received.unwrap()).expect("Hash failed");
    assert_eq!(source_hash, received_hash, "File hashes should match");
}

#[test]
#[ignore]
fn test_delta_sync_small_modification() {
    let mut fixture = DeltaSyncTestFixture::new().expect("Failed to create fixture");
    fixture.setup_certificates().expect("Failed to setup certs");
    fixture.write_configs().expect("Failed to write configs");
    fixture.start_instances().expect("Failed to start instances");

    // Create initial 5MB file
    let test_file = fixture
        .create_test_file("delta-small.bin", 5 * 1024 * 1024)
        .expect("Failed to create test file");

    // Connect and push initial file
    assert!(fixture.connect_b_to_a().expect("Connect failed"));
    let result = fixture.push_file(&test_file).expect("Push failed");
    assert!(result["success"].as_bool().unwrap_or(false));
    std::thread::sleep(Duration::from_secs(3));

    let files_before = fixture.get_received_files().expect("Failed to list").len();

    // Modify 4KB in the middle of the file
    fixture.modify_file_small("delta-small.bin", 2 * 1024 * 1024, 4096).expect("Modify failed");
    let modified_hash = DeltaSyncTestFixture::compute_file_hash(&test_file).expect("Hash failed");

    // Push modified file (should use delta sync)
    let result = fixture.push_file(&test_file).expect("Push failed");
    assert!(result["success"].as_bool().unwrap_or(false), "Delta push should succeed");
    std::thread::sleep(Duration::from_secs(3));

    // Verify new file received
    let files_after = fixture.get_received_files().expect("Failed to list").len();
    assert!(files_after > files_before, "Should have new received file");

    let received = fixture.get_most_recent_received().expect("Failed to get").unwrap();
    let received_hash = DeltaSyncTestFixture::compute_file_hash(&received).expect("Hash failed");
    assert_eq!(modified_hash, received_hash, "Modified file hash should match");
}

#[test]
#[ignore]
fn test_delta_sync_large_modification() {
    let mut fixture = DeltaSyncTestFixture::new().expect("Failed to create fixture");
    fixture.setup_certificates().expect("Failed to setup certs");
    fixture.write_configs().expect("Failed to write configs");
    fixture.start_instances().expect("Failed to start instances");

    // Create initial 5MB file
    let test_file = fixture
        .create_test_file("delta-large.bin", 5 * 1024 * 1024)
        .expect("Failed to create test file");

    // Connect and push initial file
    assert!(fixture.connect_b_to_a().expect("Connect failed"));
    let result = fixture.push_file(&test_file).expect("Push failed");
    assert!(result["success"].as_bool().unwrap_or(false));
    std::thread::sleep(Duration::from_secs(3));

    // Modify 50% of the file
    fixture.modify_file_large("delta-large.bin", 50).expect("Modify failed");
    let modified_hash = DeltaSyncTestFixture::compute_file_hash(&test_file).expect("Hash failed");

    // Push modified file
    let result = fixture.push_file(&test_file).expect("Push failed");
    assert!(result["success"].as_bool().unwrap_or(false), "Large delta push should succeed");
    std::thread::sleep(Duration::from_secs(5));

    // Verify received
    let received = fixture.get_most_recent_received().expect("Failed to get").unwrap();
    let received_hash = DeltaSyncTestFixture::compute_file_hash(&received).expect("Hash failed");
    assert_eq!(modified_hash, received_hash, "Large modified file hash should match");
}

#[test]
#[ignore]
fn test_delta_sync_preserves_integrity() {
    let mut fixture = DeltaSyncTestFixture::new().expect("Failed to create fixture");
    fixture.setup_certificates().expect("Failed to setup certs");
    fixture.write_configs().expect("Failed to write configs");
    fixture.start_instances().expect("Failed to start instances");

    // Create 2MB file with specific pattern
    let test_file = fixture
        .create_test_file("delta-integrity.bin", 2 * 1024 * 1024)
        .expect("Failed to create test file");

    assert!(fixture.connect_b_to_a().expect("Connect failed"));

    // Transfer 3 times with modifications
    for i in 0..3 {
        if i > 0 {
            // Modify 1KB at different offsets
            fixture.modify_file_small("delta-integrity.bin", i * 100_000, 1024).expect("Modify failed");
        }
        
        let source_hash = DeltaSyncTestFixture::compute_file_hash(&test_file).expect("Hash failed");
        let result = fixture.push_file(&test_file).expect("Push failed");
        assert!(result["success"].as_bool().unwrap_or(false), "Transfer {} should succeed", i);
        std::thread::sleep(Duration::from_secs(2));

        let received = fixture.get_most_recent_received().expect("Failed to get").unwrap();
        let received_hash = DeltaSyncTestFixture::compute_file_hash(&received).expect("Hash failed");
        assert_eq!(source_hash, received_hash, "Transfer {} hash mismatch", i);
    }
}
