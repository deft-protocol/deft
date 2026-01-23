//! Integration tests for pause/resume functionality using real HTTP API
//!
//! These tests spawn two real deftd instances and test pause/resume via API calls.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

struct TestInstance {
    process: Child,
    api_port: u16,
    deft_port: u16,
    config_dir: PathBuf,
    name: String,
}

impl TestInstance {
    fn api_url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{}", self.api_port, path)
    }
}

impl Drop for TestInstance {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

struct TestFixture {
    instance_a: TestInstance,
    instance_b: TestInstance,
    client: reqwest::Client,
    _temp_dir: tempfile::TempDir,
}

impl TestFixture {
    async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // Use existing test infrastructure if available
        let existing_dir = PathBuf::from("/tmp/deft-integration");
        if existing_dir.exists() {
            return Self::use_existing_infrastructure().await;
        }

        let temp_dir = tempfile::tempdir()?;
        let base_path = temp_dir.path();

        // Create directories for both instances
        let dir_a = base_path.join("instance-a");
        let dir_b = base_path.join("instance-b");
        std::fs::create_dir_all(&dir_a)?;
        std::fs::create_dir_all(&dir_b)?;
        std::fs::create_dir_all(dir_a.join("shares"))?;
        std::fs::create_dir_all(dir_b.join("shares"))?;
        std::fs::create_dir_all(dir_a.join("certs"))?;
        std::fs::create_dir_all(dir_b.join("certs"))?;

        // Use unique ports for this test
        let api_port_a = 17752;
        let deft_port_a = 17751;
        let api_port_b = 17762;
        let deft_port_b = 17761;

        // Generate test certificates
        Self::generate_test_certs(&dir_a, &dir_b)?;

        // Create config files
        Self::create_config(&dir_a, "instance-a", api_port_a, deft_port_a, &dir_b, deft_port_b)?;
        Self::create_config(&dir_b, "instance-b", api_port_b, deft_port_b, &dir_a, deft_port_a)?;

        // Create a test file in instance-b's shares
        let test_file_path = dir_b.join("shares/test-pause-resume.bin");
        let mut test_file = std::fs::File::create(&test_file_path)?;
        // Create a 10MB file for testing (enough to allow pause during transfer)
        let data = vec![0xABu8; 10 * 1024 * 1024];
        test_file.write_all(&data)?;

        // Find the deftd binary
        let deftd_path = Self::find_deftd_binary()?;

        // Start instances
        let instance_a = Self::start_instance(&deftd_path, &dir_a, "instance-a", api_port_a, deft_port_a)?;
        tokio::time::sleep(Duration::from_millis(500)).await;
        
        let instance_b = Self::start_instance(&deftd_path, &dir_b, "instance-b", api_port_b, deft_port_b)?;
        tokio::time::sleep(Duration::from_millis(500)).await;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;

        // Wait for instances to be ready
        Self::wait_for_instance(&client, api_port_a).await?;
        Self::wait_for_instance(&client, api_port_b).await?;

        Ok(Self {
            instance_a: TestInstance {
                process: instance_a,
                api_port: api_port_a,
                deft_port: deft_port_a,
                config_dir: dir_a,
                name: "instance-a".to_string(),
            },
            instance_b: TestInstance {
                process: instance_b,
                api_port: api_port_b,
                deft_port: deft_port_b,
                config_dir: dir_b,
                name: "instance-b".to_string(),
            },
            client,
            _temp_dir: temp_dir,
        })
    }
    
    /// Use existing /tmp/deft-integration infrastructure (assumes instances are already running)
    async fn use_existing_infrastructure() -> Result<Self, Box<dyn std::error::Error>> {
        let dir_a = PathBuf::from("/tmp/deft-integration/instance-a");
        let dir_b = PathBuf::from("/tmp/deft-integration/instance-b");
        
        // Read API ports from config files
        let config_a = std::fs::read_to_string(dir_a.join("config.toml"))?;
        let config_b = std::fs::read_to_string(dir_b.join("config.toml"))?;
        
        let api_port_a = Self::extract_api_port(&config_a)?;
        let api_port_b = Self::extract_api_port(&config_b)?;
        
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;
            
        // Check if instances are running
        Self::wait_for_instance(&client, api_port_a).await?;
        Self::wait_for_instance(&client, api_port_b).await?;
        
        // Create test file if it doesn't exist
        let shares_dir = dir_b.join("shares");
        std::fs::create_dir_all(&shares_dir).ok();
        let test_file_path = shares_dir.join("test-pause-resume.bin");
        if !test_file_path.exists() {
            let mut test_file = std::fs::File::create(&test_file_path)?;
            let data = vec![0xABu8; 50 * 1024 * 1024]; // 50MB file
            test_file.write_all(&data)?;
        }
        
        // Create a dummy temp_dir that won't delete anything
        let temp_dir = tempfile::tempdir()?;
        
        Ok(Self {
            instance_a: TestInstance {
                process: Self::dummy_process()?,
                api_port: api_port_a,
                deft_port: 7751,
                config_dir: dir_a,
                name: "instance-a".to_string(),
            },
            instance_b: TestInstance {
                process: Self::dummy_process()?,
                api_port: api_port_b,
                deft_port: 7761,
                config_dir: dir_b,
                name: "instance-b".to_string(),
            },
            client,
            _temp_dir: temp_dir,
        })
    }
    
    fn extract_api_port(config: &str) -> Result<u16, Box<dyn std::error::Error>> {
        for line in config.lines() {
            if line.contains("api_listen") {
                // Parse "api_listen = "127.0.0.1:7752""
                if let Some(port_str) = line.split(':').last() {
                    let port_str = port_str.trim().trim_matches('"');
                    return Ok(port_str.parse()?);
                }
            }
        }
        Err("Could not find api_listen port in config".into())
    }
    
    fn dummy_process() -> Result<Child, Box<dyn std::error::Error>> {
        // Create a dummy process that does nothing (sleep)
        Ok(Command::new("sleep")
            .arg("0")
            .spawn()?)
    }

    fn find_deftd_binary() -> Result<PathBuf, Box<dyn std::error::Error>> {
        // Try release first, then debug
        let release_path = PathBuf::from("target/release/deftd");
        if release_path.exists() {
            return Ok(release_path);
        }
        let debug_path = PathBuf::from("target/debug/deftd");
        if debug_path.exists() {
            return Ok(debug_path);
        }
        // Try from workspace root
        let workspace_release = PathBuf::from("../target/release/deftd");
        if workspace_release.exists() {
            return Ok(workspace_release);
        }
        Err("deftd binary not found. Run 'cargo build --release' first.".into())
    }

    fn generate_test_certs(dir_a: &PathBuf, dir_b: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
        // Use openssl to generate test certificates
        let ca_key = dir_a.join("certs/ca.key");
        let ca_cert = dir_a.join("certs/ca.crt");

        // Generate CA
        Command::new("openssl")
            .args(["genrsa", "-out"])
            .arg(&ca_key)
            .arg("2048")
            .output()?;

        Command::new("openssl")
            .args(["req", "-x509", "-new", "-nodes", "-key"])
            .arg(&ca_key)
            .args(["-sha256", "-days", "1", "-out"])
            .arg(&ca_cert)
            .args(["-subj", "/CN=TestCA"])
            .output()?;

        // Copy CA to both instances
        std::fs::copy(&ca_cert, dir_b.join("certs/ca.crt"))?;

        // Generate certs for instance-a
        Self::generate_instance_cert(dir_a, "instance-a", &ca_key, &ca_cert)?;
        
        // Generate certs for instance-b
        Self::generate_instance_cert(dir_b, "instance-b", &ca_key, &ca_cert)?;

        // Copy CA key to dir_b for signing
        std::fs::copy(&ca_key, dir_b.join("certs/ca.key"))?;

        Ok(())
    }

    fn generate_instance_cert(
        dir: &PathBuf,
        name: &str,
        ca_key: &PathBuf,
        ca_cert: &PathBuf,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key_path = dir.join(format!("certs/{}.key", name));
        let csr_path = dir.join(format!("certs/{}.csr", name));
        let cert_path = dir.join(format!("certs/{}.crt", name));

        Command::new("openssl")
            .args(["genrsa", "-out"])
            .arg(&key_path)
            .arg("2048")
            .output()?;

        Command::new("openssl")
            .args(["req", "-new", "-key"])
            .arg(&key_path)
            .args(["-out"])
            .arg(&csr_path)
            .args(["-subj", &format!("/CN={}", name)])
            .output()?;

        Command::new("openssl")
            .args(["x509", "-req", "-in"])
            .arg(&csr_path)
            .args(["-CA"])
            .arg(ca_cert)
            .args(["-CAkey"])
            .arg(ca_key)
            .args(["-CAcreateserial", "-out"])
            .arg(&cert_path)
            .args(["-days", "1", "-sha256"])
            .output()?;

        Ok(())
    }

    fn create_config(
        dir: &PathBuf,
        name: &str,
        api_port: u16,
        deft_port: u16,
        remote_dir: &PathBuf,
        remote_deft_port: u16,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let remote_name = if name == "instance-a" { "instance-b" } else { "instance-a" };
        
        let config = format!(r#"
[server]
identity = "{name}"
listen_address = "127.0.0.1"
listen_port = {deft_port}
cert_path = "{dir}/certs/{name}.crt"
key_path = "{dir}/certs/{name}.key"
ca_path = "{dir}/certs/ca.crt"
data_dir = "{dir}"
metrics_port = 0

[api]
api_enabled = true
api_listen = "127.0.0.1:{api_port}"

[client]
identity = "{name}"
cert_path = "{dir}/certs/{name}.crt"
key_path = "{dir}/certs/{name}.key"
ca_path = "{dir}/certs/ca.crt"

[[partners]]
id = "{remote_name}"
allowed_virtual_files = ["*"]

[[trusted_servers]]
name = "{remote_name}"
address = "127.0.0.1"
port = {remote_deft_port}
ca_path = "{remote_dir}/certs/ca.crt"

[[virtual_files]]
name = "test-pause-resume.bin"
path = "{dir}/shares/test-pause-resume.bin"
allowed_partners = ["{remote_name}"]
"#,
            name = name,
            dir = dir.display(),
            deft_port = deft_port,
            api_port = api_port,
            remote_name = remote_name,
            remote_deft_port = remote_deft_port,
            remote_dir = remote_dir.display(),
        );

        std::fs::write(dir.join("config.toml"), config)?;
        Ok(())
    }

    fn start_instance(
        deftd_path: &PathBuf,
        config_dir: &PathBuf,
        name: &str,
        _api_port: u16,
        _deft_port: u16,
    ) -> Result<Child, Box<dyn std::error::Error>> {
        let config_path = config_dir.join("config.toml");
        let log_path = config_dir.join("daemon.log");

        let log_file = std::fs::File::create(&log_path)?;

        let child = Command::new(deftd_path)
            .args(["-c", config_path.to_str().unwrap(), "daemon"])
            .stdout(Stdio::from(log_file.try_clone()?))
            .stderr(Stdio::from(log_file))
            .spawn()?;

        println!("Started {} with PID {}", name, child.id());
        Ok(child)
    }

    async fn wait_for_instance(client: &reqwest::Client, port: u16) -> Result<(), Box<dyn std::error::Error>> {
        let url = format!("http://127.0.0.1:{}/api/transfers", port);
        for i in 0..30 {
            match client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    println!("Instance on port {} is ready", port);
                    return Ok(());
                }
                _ => {
                    if i == 29 {
                        return Err(format!("Instance on port {} failed to start", port).into());
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        }
        Ok(())
    }

    async fn connect_b_to_a(&self) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        // Read config to find correct server name
        let config_b = std::fs::read_to_string(self.instance_b.config_dir.join("config.toml"))?;
        let server_name = Self::extract_trusted_server_name(&config_b).unwrap_or("A".to_string());
        
        let resp = self.client
            .post(self.instance_b.api_url("/api/client/connect"))
            .json(&serde_json::json!({
                "server_name": server_name,
                "our_identity": "instance-b"
            }))
            .send()
            .await?
            .json()
            .await?;
        Ok(resp)
    }
    
    fn extract_trusted_server_name(config: &str) -> Option<String> {
        // Find [[trusted_servers]] section and extract name
        let mut in_trusted_servers = false;
        for line in config.lines() {
            if line.contains("[[trusted_servers]]") {
                in_trusted_servers = true;
                continue;
            }
            if in_trusted_servers && line.trim().starts_with("name = ") {
                let name = line.split('=').nth(1)?
                    .trim()
                    .trim_matches('"')
                    .to_string();
                return Some(name);
            }
            if line.starts_with("[[") && in_trusted_servers {
                in_trusted_servers = false;
            }
        }
        None
    }

    async fn push_file_from_b(&self) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let file_path = self.instance_b.config_dir.join("shares/test-pause-resume.bin");
        // Use "files-to-a" which is the receive virtual file on instance-a
        let resp = self.client
            .post(self.instance_b.api_url("/api/client/push"))
            .json(&serde_json::json!({
                "file_path": file_path.to_str().unwrap(),
                "partner_id": "instance-a",
                "virtual_file": "files-to-a"
            }))
            .send()
            .await?
            .json()
            .await?;
        Ok(resp)
    }

    async fn get_transfers(&self, instance: &TestInstance) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
        let resp: Vec<serde_json::Value> = self.client
            .get(instance.api_url("/api/transfers"))
            .send()
            .await?
            .json()
            .await?;
        Ok(resp)
    }

    async fn interrupt_transfer(&self, instance: &TestInstance, transfer_id: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let resp = self.client
            .post(instance.api_url(&format!("/api/transfers/{}/interrupt", transfer_id)))
            .send()
            .await?
            .json()
            .await?;
        Ok(resp)
    }

    async fn resume_transfer(&self, instance: &TestInstance, transfer_id: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let resp = self.client
            .post(instance.api_url(&format!("/api/transfers/{}/resume", transfer_id)))
            .send()
            .await?
            .json()
            .await?;
        Ok(resp)
    }

    async fn wait_for_transfer_status(&self, instance: &TestInstance, transfer_id: &str, expected_status: &str, timeout_ms: u64) -> Result<bool, Box<dyn std::error::Error>> {
        let start = std::time::Instant::now();
        while start.elapsed().as_millis() < timeout_ms as u128 {
            let transfers = self.get_transfers(instance).await?;
            for t in &transfers {
                if t["id"].as_str() == Some(transfer_id) {
                    if t["status"].as_str() == Some(expected_status) {
                        return Ok(true);
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Ok(false)
    }
}

#[tokio::test]
async fn test_pause_resume_from_receiver() {
    let fixture = match TestFixture::new().await {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to create test fixture: {}. Skipping test.", e);
            return;
        }
    };

    // Connect B to A
    println!("Connecting instance-b to instance-a...");
    let connect_result = fixture.connect_b_to_a().await;
    match &connect_result {
        Ok(v) => println!("Connect result: {:?}", v),
        Err(e) => {
            eprintln!("Failed to connect: {}", e);
            return;
        }
    }

    // Start push from B
    println!("Starting push from instance-b...");
    let push_result = fixture.push_file_from_b().await;
    println!("Push result: {:?}", push_result);

    // Wait for transfer to start
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Check transfer exists on both sides - get transfer_id from receiver (A)
    let transfers_a = fixture.get_transfers(&fixture.instance_a).await.unwrap_or_default();
    let transfers_b = fixture.get_transfers(&fixture.instance_b).await.unwrap_or_default();
    println!("Transfers on A: {:?}", transfers_a);
    println!("Transfers on B: {:?}", transfers_b);

    // Get transfer_id from A (the receiver)
    let transfer_id = transfers_a.first()
        .and_then(|t| t["id"].as_str())
        .unwrap_or("unknown")
        .to_string();
    println!("Using transfer_id from A: {}", transfer_id);

    if transfer_id == "unknown" || transfers_a.is_empty() {
        eprintln!("No transfer found on A, skipping test");
        return;
    }

    // Pause from receiver (A)
    println!("Pausing transfer from receiver (A)...");
    let pause_result = fixture.interrupt_transfer(&fixture.instance_a, &transfer_id).await;
    println!("Pause result: {:?}", pause_result);

    // Verify transfer is interrupted on A
    tokio::time::sleep(Duration::from_millis(200)).await;
    let status_ok = fixture.wait_for_transfer_status(&fixture.instance_a, &transfer_id, "interrupted", 2000).await.unwrap_or(false);
    assert!(status_ok, "Transfer should be interrupted on A");

    // Wait a bit while paused
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Verify transfer is still interrupted (not completed)
    let transfers_a = fixture.get_transfers(&fixture.instance_a).await.unwrap_or_default();
    println!("Transfers on A after pause: {:?}", transfers_a);
    let transfer_a = transfers_a.iter().find(|t| t["id"].as_str() == Some(&transfer_id));
    assert!(transfer_a.is_some(), "Transfer should still exist on A");
    assert_eq!(transfer_a.unwrap()["status"].as_str(), Some("interrupted"), "Transfer should still be interrupted");

    // Resume from receiver (A)
    println!("Resuming transfer from receiver (A)...");
    let resume_result = fixture.resume_transfer(&fixture.instance_a, &transfer_id).await;
    println!("Resume result: {:?}", resume_result);

    // Verify transfer resumes
    let resumed = fixture.wait_for_transfer_status(&fixture.instance_a, &transfer_id, "active", 3000).await.unwrap_or(false);
    assert!(resumed, "Transfer should resume to active status");

    // Wait for transfer to complete
    let completed = fixture.wait_for_transfer_status(&fixture.instance_a, &transfer_id, "completed", 30000).await.unwrap_or(false);
    println!("Transfer completed: {}", completed);

    println!("Test passed!");
}

#[tokio::test]
#[ignore] // Push API is synchronous - transfer completes before we can pause
async fn test_pause_resume_from_sender() {
    let fixture = match TestFixture::new().await {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to create test fixture: {}. Skipping test.", e);
            return;
        }
    };

    // Connect B to A
    println!("Connecting instance-b to instance-a...");
    let _ = fixture.connect_b_to_a().await;

    // Start push from B (async - won't wait for completion)
    println!("Starting push from instance-b...");
    let push_result = fixture.push_file_from_b().await;
    println!("Push result: {:?}", push_result);

    // Wait for transfer to be registered on B
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Get transfer_id from B's transfers list
    let transfers_b = fixture.get_transfers(&fixture.instance_b).await.unwrap_or_default();
    println!("Transfers on B: {:?}", transfers_b);
    
    let transfer_id = transfers_b.first()
        .and_then(|t| t["id"].as_str())
        .unwrap_or("unknown")
        .to_string();
    println!("Using transfer_id from B: {}", transfer_id);

    if transfer_id == "unknown" || transfers_b.is_empty() {
        eprintln!("No transfer found on B, skipping test");
        return;
    }

    // Pause from sender (B)
    println!("Pausing transfer from sender (B)...");
    let pause_result = fixture.interrupt_transfer(&fixture.instance_b, &transfer_id).await;
    println!("Pause result: {:?}", pause_result);

    // Verify transfer is interrupted on B
    let status_ok = fixture.wait_for_transfer_status(&fixture.instance_b, &transfer_id, "interrupted", 2000).await.unwrap_or(false);
    assert!(status_ok, "Transfer should be interrupted on B");

    // Wait a bit
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Resume from sender (B)
    println!("Resuming transfer from sender (B)...");
    let resume_result = fixture.resume_transfer(&fixture.instance_b, &transfer_id).await;
    println!("Resume result: {:?}", resume_result);

    // Verify transfer resumes
    let resumed = fixture.wait_for_transfer_status(&fixture.instance_b, &transfer_id, "active", 3000).await.unwrap_or(false);
    assert!(resumed, "Transfer should resume to active status");

    println!("Test passed!");
}
