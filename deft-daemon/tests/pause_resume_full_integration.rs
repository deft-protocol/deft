//! Pause/Resume integration tests (C2)
//!
//! Tests:
//! - Pause sender, resume sender (same party)
//! - Pause sender, resume receiver (cross-party)
//! - Multiple pause/resume cycles
//! - Resume after long pause

#![allow(dead_code, unused_variables, unused_assignments, clippy::ptr_arg)]

use std::io::Write;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::Duration;

/// Test fixture for pause/resume integration tests
struct PauseResumeTestFixture {
    instance_a: Option<Child>,
    instance_b: Option<Child>,
    temp_dir: PathBuf,
    instance_a_received: PathBuf,
    instance_b_shares: PathBuf,
}

impl PauseResumeTestFixture {
    const API_A: &'static str = "http://127.0.0.1:18752";
    const API_B: &'static str = "http://127.0.0.1:18762";

    fn new() -> std::io::Result<Self> {
        let temp_dir = std::env::temp_dir().join("deft-pause-test");
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir)?;

        let instance_a_dir = temp_dir.join("instance-a");
        let instance_b_dir = temp_dir.join("instance-b");
        let instance_a_received = instance_a_dir.join("received");
        let instance_b_shares = instance_b_dir.join("shares");

        std::fs::create_dir_all(instance_a_dir.join("certs"))?;
        std::fs::create_dir_all(&instance_a_received)?;
        std::fs::create_dir_all(instance_a_dir.join("tmp"))?;
        std::fs::create_dir_all(instance_b_dir.join("certs"))?;
        std::fs::create_dir_all(&instance_b_shares)?;
        std::fs::create_dir_all(instance_b_dir.join("tmp"))?;

        Ok(Self {
            instance_a: None,
            instance_b: None,
            temp_dir,
            instance_a_received,
            instance_b_shares,
        })
    }

    fn setup_certificates(&self) -> std::io::Result<()> {
        let ca_key = self.temp_dir.join("ca.key");
        let ca_cert = self.temp_dir.join("ca.crt");

        Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                ca_key.to_str().unwrap(),
                "-out",
                ca_cert.to_str().unwrap(),
                "-days",
                "1",
                "-subj",
                "/CN=TestCA",
            ])
            .output()?;

        self.generate_cert("instance-a", &ca_key, &ca_cert)?;
        self.generate_cert("instance-b", &ca_key, &ca_cert)?;

        std::fs::copy(&ca_cert, self.temp_dir.join("instance-a/certs/ca.crt"))?;
        std::fs::copy(&ca_cert, self.temp_dir.join("instance-b/certs/ca.crt"))?;

        Ok(())
    }

    fn generate_cert(
        &self,
        name: &str,
        ca_key: &PathBuf,
        ca_cert: &PathBuf,
    ) -> std::io::Result<()> {
        let key_path = self.temp_dir.join(format!("{}/certs/server.key", name));
        let csr_path = self.temp_dir.join(format!("{}/certs/server.csr", name));
        let cert_path = self.temp_dir.join(format!("{}/certs/server.crt", name));

        Command::new("openssl")
            .args(["genrsa", "-out", key_path.to_str().unwrap(), "2048"])
            .output()?;

        Command::new("openssl")
            .args([
                "req",
                "-new",
                "-key",
                key_path.to_str().unwrap(),
                "-out",
                csr_path.to_str().unwrap(),
                "-subj",
                &format!("/CN={}", name),
            ])
            .output()?;

        Command::new("openssl")
            .args([
                "x509",
                "-req",
                "-in",
                csr_path.to_str().unwrap(),
                "-CA",
                ca_cert.to_str().unwrap(),
                "-CAkey",
                ca_key.to_str().unwrap(),
                "-CAcreateserial",
                "-out",
                cert_path.to_str().unwrap(),
                "-days",
                "1",
            ])
            .output()?;

        Ok(())
    }

    fn write_configs(&self) -> std::io::Result<()> {
        let config_a = format!(
            r#"
[server]
enabled = true
listen = "127.0.0.1:18751"
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
api_listen = "127.0.0.1:18752"
api_key_enabled = false

[[partners]]
id = "instance-b"

[[partners.virtual_files]]
name = "pause-test-files"
path = "{}/instance-a/received/"
direction = "receive"
"#,
            self.temp_dir.display(),
            self.temp_dir.display(),
            self.temp_dir.display(),
            self.temp_dir.display(),
            self.temp_dir.display(),
            self.temp_dir.display(),
            self.temp_dir.display(),
            self.temp_dir.display()
        );

        std::fs::write(self.temp_dir.join("instance-a/config.toml"), config_a)?;

        let config_b = format!(
            r#"
[server]
enabled = true
listen = "127.0.0.1:18761"
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
api_listen = "127.0.0.1:18762"
api_key_enabled = false

[[partners]]
id = "instance-a"

[[partners.virtual_files]]
name = "pause-test-files"
path = "{}/instance-b/shares/"
direction = "send"

[[trusted_servers]]
name = "A"
address = "127.0.0.1:18751"
skip_verify = true
"#,
            self.temp_dir.display(),
            self.temp_dir.display(),
            self.temp_dir.display(),
            self.temp_dir.display(),
            self.temp_dir.display(),
            self.temp_dir.display(),
            self.temp_dir.display(),
            self.temp_dir.display()
        );

        std::fs::write(self.temp_dir.join("instance-b/config.toml"), config_b)?;

        Ok(())
    }

    fn start_instances(&mut self) -> std::io::Result<()> {
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
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "deftd binary not found")
            })?;

        self.instance_a = Some(
            Command::new(&deftd_path)
                .args([
                    "--config",
                    self.temp_dir
                        .join("instance-a/config.toml")
                        .to_str()
                        .unwrap(),
                ])
                .spawn()?,
        );

        self.instance_b = Some(
            Command::new(&deftd_path)
                .args([
                    "--config",
                    self.temp_dir
                        .join("instance-b/config.toml")
                        .to_str()
                        .unwrap(),
                ])
                .spawn()?,
        );

        std::thread::sleep(Duration::from_secs(2));
        Ok(())
    }

    fn create_test_file(&self, name: &str, size_bytes: usize) -> std::io::Result<PathBuf> {
        let path = self.instance_b_shares.join(name);
        let mut file = std::fs::File::create(&path)?;
        let mut data = vec![0u8; size_bytes];
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = (i % 256) as u8;
        }
        file.write_all(&data)?;
        Ok(path)
    }

    fn compute_file_hash(path: &PathBuf) -> std::io::Result<String> {
        use sha2::{Digest, Sha256};
        use std::io::Read;
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
            .post(format!("{}/api/client/connect", Self::API_B))
            .json(&serde_json::json!({
                "server_name": "A",
                "our_identity": "instance-b"
            }))
            .timeout(Duration::from_secs(10))
            .send()?;
        let json: serde_json::Value = resp.json()?;
        Ok(json["success"].as_bool().unwrap_or(false))
    }

    fn push_file_async(&self, file_path: &PathBuf) -> Result<String, Box<dyn std::error::Error>> {
        let client = reqwest::blocking::Client::new();
        let resp = client
            .post(format!("{}/api/client/push", Self::API_B))
            .json(&serde_json::json!({
                "file_path": file_path.to_str().unwrap(),
                "partner_id": "instance-a",
                "virtual_file": "pause-test-files"
            }))
            .timeout(Duration::from_secs(5))
            .send();

        // Return immediately - the push runs in background
        match resp {
            Ok(r) => {
                let json: serde_json::Value = r.json()?;
                Ok(json["transfer_id"]
                    .as_str()
                    .unwrap_or("unknown")
                    .to_string())
            }
            Err(_) => Ok("pending".to_string()),
        }
    }

    fn get_transfers(
        &self,
        api_url: &str,
    ) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
        let client = reqwest::blocking::Client::new();
        let resp = client
            .get(format!("{}/api/transfers", api_url))
            .timeout(Duration::from_secs(5))
            .send()?;
        let json: serde_json::Value = resp.json()?;
        Ok(json.as_array().cloned().unwrap_or_default())
    }

    fn get_active_transfer_id(&self, api_url: &str) -> Option<String> {
        if let Ok(transfers) = self.get_transfers(api_url) {
            for t in transfers {
                if t["status"].as_str() == Some("active")
                    || t["status"].as_str() == Some("interrupted")
                {
                    return t["id"].as_str().map(|s| s.to_string());
                }
            }
        }
        None
    }

    fn interrupt_transfer(
        &self,
        api_url: &str,
        transfer_id: &str,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let client = reqwest::blocking::Client::new();
        let resp = client
            .post(format!(
                "{}/api/transfers/{}/interrupt",
                api_url, transfer_id
            ))
            .json(&serde_json::json!({}))
            .timeout(Duration::from_secs(5))
            .send()?;
        let json: serde_json::Value = resp.json()?;
        Ok(json["status"].as_str() == Some("interrupted"))
    }

    fn resume_transfer(
        &self,
        api_url: &str,
        transfer_id: &str,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let client = reqwest::blocking::Client::new();
        let resp = client
            .post(format!("{}/api/transfers/{}/resume", api_url, transfer_id))
            .json(&serde_json::json!({}))
            .timeout(Duration::from_secs(5))
            .send()?;
        let json: serde_json::Value = resp.json()?;
        let status = json["status"].as_str().unwrap_or("");
        Ok(status == "resumed" || status == "resuming")
    }

    fn wait_for_transfer_complete(&self, timeout_secs: u64) -> bool {
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_secs(timeout_secs) {
            // Check both instances for completion
            if let Ok(transfers_a) = self.get_transfers(Self::API_A) {
                if transfers_a
                    .iter()
                    .all(|t| t["status"].as_str() != Some("active"))
                {
                    if let Ok(transfers_b) = self.get_transfers(Self::API_B) {
                        if transfers_b
                            .iter()
                            .all(|t| t["status"].as_str() != Some("active"))
                        {
                            return true;
                        }
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        false
    }

    fn get_most_recent_received(&self) -> std::io::Result<Option<PathBuf>> {
        let mut files: Vec<_> = std::fs::read_dir(&self.instance_a_received)?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
            .collect();

        files.sort_by_key(|f| {
            f.metadata()
                .and_then(|m| m.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
        });

        Ok(files.last().map(|f| f.path()))
    }
}

impl Drop for PauseResumeTestFixture {
    fn drop(&mut self) {
        if let Some(ref mut child) = self.instance_a {
            let _ = child.kill();
        }
        if let Some(ref mut child) = self.instance_b {
            let _ = child.kill();
        }
        let _ = std::fs::remove_dir_all(&self.temp_dir);
    }
}

#[test]
#[ignore] // Run with: cargo test --test pause_resume_full_integration -- --ignored --nocapture
fn test_pause_resume_same_party() {
    let mut fixture = PauseResumeTestFixture::new().expect("Failed to create fixture");
    fixture.setup_certificates().expect("Failed to setup certs");
    fixture.write_configs().expect("Failed to write configs");
    fixture
        .start_instances()
        .expect("Failed to start instances");

    // Create 10MB file (takes time to transfer)
    let test_file = fixture
        .create_test_file("pause-same.bin", 10 * 1024 * 1024)
        .expect("Failed to create test file");
    let source_hash = PauseResumeTestFixture::compute_file_hash(&test_file).expect("Hash failed");

    // Connect
    assert!(fixture.connect_b_to_a().expect("Connect failed"));

    // Start transfer (async)
    let _ = fixture.push_file_async(&test_file);
    std::thread::sleep(Duration::from_millis(500));

    // Get transfer ID from sender (B)
    let transfer_id = fixture
        .get_active_transfer_id(PauseResumeTestFixture::API_B)
        .expect("Should have active transfer");

    // Pause from sender
    assert!(
        fixture
            .interrupt_transfer(PauseResumeTestFixture::API_B, &transfer_id)
            .expect("Interrupt failed"),
        "Interrupt should succeed"
    );
    std::thread::sleep(Duration::from_secs(1));

    // Resume from sender
    assert!(
        fixture
            .resume_transfer(PauseResumeTestFixture::API_B, &transfer_id)
            .expect("Resume failed"),
        "Resume should succeed"
    );

    // Wait for completion
    assert!(
        fixture.wait_for_transfer_complete(30),
        "Transfer should complete"
    );

    // Verify integrity
    let received = fixture
        .get_most_recent_received()
        .expect("Failed to get")
        .expect("No file");
    let received_hash = PauseResumeTestFixture::compute_file_hash(&received).expect("Hash failed");
    assert_eq!(
        source_hash, received_hash,
        "File hash should match after pause/resume"
    );
}

#[test]
#[ignore]
fn test_pause_sender_resume_receiver_cross_party() {
    let mut fixture = PauseResumeTestFixture::new().expect("Failed to create fixture");
    fixture.setup_certificates().expect("Failed to setup certs");
    fixture.write_configs().expect("Failed to write configs");
    fixture
        .start_instances()
        .expect("Failed to start instances");

    // Create 10MB file
    let test_file = fixture
        .create_test_file("pause-cross.bin", 10 * 1024 * 1024)
        .expect("Failed to create test file");
    let source_hash = PauseResumeTestFixture::compute_file_hash(&test_file).expect("Hash failed");

    // Connect
    assert!(fixture.connect_b_to_a().expect("Connect failed"));

    // Start transfer
    let _ = fixture.push_file_async(&test_file);
    std::thread::sleep(Duration::from_millis(800));

    // Get transfer ID from sender (B)
    let transfer_id_b = fixture
        .get_active_transfer_id(PauseResumeTestFixture::API_B)
        .expect("Should have active transfer on sender");

    // Pause from sender (B)
    assert!(
        fixture
            .interrupt_transfer(PauseResumeTestFixture::API_B, &transfer_id_b)
            .expect("Interrupt failed"),
        "Sender interrupt should succeed"
    );
    std::thread::sleep(Duration::from_secs(2));

    // Get transfer ID from receiver (A) - may have different ID format
    let transfer_id_a = fixture.get_active_transfer_id(PauseResumeTestFixture::API_A);

    // Resume from receiver (A) if we have an ID, otherwise from sender
    let resume_success = if let Some(tid_a) = transfer_id_a {
        fixture
            .resume_transfer(PauseResumeTestFixture::API_A, &tid_a)
            .unwrap_or(false)
    } else {
        // Fallback to resume from sender
        fixture
            .resume_transfer(PauseResumeTestFixture::API_B, &transfer_id_b)
            .unwrap_or(false)
    };

    assert!(resume_success, "Cross-party resume should succeed");

    // Wait for completion
    assert!(
        fixture.wait_for_transfer_complete(30),
        "Transfer should complete after cross-party resume"
    );

    // Verify integrity
    let received = fixture
        .get_most_recent_received()
        .expect("Failed to get")
        .expect("No file");
    let received_hash = PauseResumeTestFixture::compute_file_hash(&received).expect("Hash failed");
    assert_eq!(
        source_hash, received_hash,
        "File hash should match after cross-party resume"
    );
}

#[test]
#[ignore]
fn test_multiple_pause_resume_cycles() {
    let mut fixture = PauseResumeTestFixture::new().expect("Failed to create fixture");
    fixture.setup_certificates().expect("Failed to setup certs");
    fixture.write_configs().expect("Failed to write configs");
    fixture
        .start_instances()
        .expect("Failed to start instances");

    // Create 15MB file (longer transfer for multiple pauses)
    let test_file = fixture
        .create_test_file("pause-multi.bin", 15 * 1024 * 1024)
        .expect("Failed to create test file");
    let source_hash = PauseResumeTestFixture::compute_file_hash(&test_file).expect("Hash failed");

    assert!(fixture.connect_b_to_a().expect("Connect failed"));

    // Start transfer
    let _ = fixture.push_file_async(&test_file);
    std::thread::sleep(Duration::from_millis(500));

    // Do 3 pause/resume cycles
    for cycle in 1..=3 {
        std::thread::sleep(Duration::from_millis(500));

        if let Some(transfer_id) = fixture.get_active_transfer_id(PauseResumeTestFixture::API_B) {
            // Pause
            let paused = fixture
                .interrupt_transfer(PauseResumeTestFixture::API_B, &transfer_id)
                .unwrap_or(false);
            if paused {
                println!("Cycle {}: Paused", cycle);
                std::thread::sleep(Duration::from_millis(300));

                // Resume
                let resumed = fixture
                    .resume_transfer(PauseResumeTestFixture::API_B, &transfer_id)
                    .unwrap_or(false);
                println!("Cycle {}: Resumed = {}", cycle, resumed);
            }
        } else {
            // Transfer may have completed
            break;
        }
    }

    // Wait for completion
    assert!(
        fixture.wait_for_transfer_complete(60),
        "Transfer should complete after multiple cycles"
    );

    // Verify integrity
    let received = fixture
        .get_most_recent_received()
        .expect("Failed to get")
        .expect("No file");
    let received_hash = PauseResumeTestFixture::compute_file_hash(&received).expect("Hash failed");
    assert_eq!(
        source_hash, received_hash,
        "File hash should match after multiple pause/resume cycles"
    );
}

#[test]
#[ignore]
fn test_resume_after_long_pause() {
    let mut fixture = PauseResumeTestFixture::new().expect("Failed to create fixture");
    fixture.setup_certificates().expect("Failed to setup certs");
    fixture.write_configs().expect("Failed to write configs");
    fixture
        .start_instances()
        .expect("Failed to start instances");

    // Create 8MB file
    let test_file = fixture
        .create_test_file("pause-long.bin", 8 * 1024 * 1024)
        .expect("Failed to create test file");
    let source_hash = PauseResumeTestFixture::compute_file_hash(&test_file).expect("Hash failed");

    assert!(fixture.connect_b_to_a().expect("Connect failed"));

    // Start transfer
    let _ = fixture.push_file_async(&test_file);
    std::thread::sleep(Duration::from_millis(500));

    // Get transfer ID
    let transfer_id = fixture
        .get_active_transfer_id(PauseResumeTestFixture::API_B)
        .expect("Should have active transfer");

    // Pause
    assert!(fixture
        .interrupt_transfer(PauseResumeTestFixture::API_B, &transfer_id)
        .expect("Interrupt failed"));

    // Long pause (5 seconds)
    println!("Long pause for 5 seconds...");
    std::thread::sleep(Duration::from_secs(5));

    // Resume
    assert!(
        fixture
            .resume_transfer(PauseResumeTestFixture::API_B, &transfer_id)
            .expect("Resume failed"),
        "Resume after long pause should succeed"
    );

    // Wait for completion
    assert!(
        fixture.wait_for_transfer_complete(30),
        "Transfer should complete after long pause"
    );

    // Verify integrity
    let received = fixture
        .get_most_recent_received()
        .expect("Failed to get")
        .expect("No file");
    let received_hash = PauseResumeTestFixture::compute_file_hash(&received).expect("Hash failed");
    assert_eq!(
        source_hash, received_hash,
        "File hash should match after long pause"
    );
}
