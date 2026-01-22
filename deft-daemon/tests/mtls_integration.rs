//! mTLS Integration Tests
//!
//! Tests verify mutual TLS authentication between two DEFT daemon instances.
//! TDD approach: tests define expected behavior, then implementation is fixed.

use std::fs;
use std::io::{BufReader, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, ServerName};
use rustls::RootCertStore;

const BASE_DIR: &str = "/tmp/deft-mtls-test";

/// Test fixture managing certificates and deftd instances
struct MtlsTestFixture {
    base_dir: String,
    instance_a: Option<Child>,
    instance_b: Option<Child>,
    port_a: u16,
    port_b: u16,
}

impl MtlsTestFixture {
    fn new(test_name: &str, port_a: u16, port_b: u16) -> Self {
        Self {
            base_dir: format!("{}/{}", BASE_DIR, test_name),
            instance_a: None,
            instance_b: None,
            port_a,
            port_b,
        }
    }

    fn setup_certs(&self) -> std::io::Result<()> {
        let _ = fs::remove_dir_all(&self.base_dir);
        fs::create_dir_all(format!("{}/instance-a/tmp", self.base_dir))?;
        fs::create_dir_all(format!("{}/instance-a/outbox", self.base_dir))?;
        fs::create_dir_all(format!("{}/instance-a/received", self.base_dir))?;
        fs::create_dir_all(format!("{}/instance-b/tmp", self.base_dir))?;
        fs::create_dir_all(format!("{}/instance-b/outbox", self.base_dir))?;
        fs::create_dir_all(format!("{}/instance-b/received", self.base_dir))?;

        // Generate CA
        self.run_openssl(&[
            "genrsa",
            "-out",
            &format!("{}/ca.key", self.base_dir),
            "2048",
        ])?;
        self.run_openssl(&[
            "req",
            "-x509",
            "-new",
            "-nodes",
            "-key",
            &format!("{}/ca.key", self.base_dir),
            "-sha256",
            "-days",
            "1",
            "-out",
            &format!("{}/ca.crt", self.base_dir),
            "-subj",
            "/CN=Test CA/O=DEFT",
        ])?;

        // Copy CA to instances
        fs::copy(
            format!("{}/ca.crt", self.base_dir),
            format!("{}/instance-a/ca.crt", self.base_dir),
        )?;
        fs::copy(
            format!("{}/ca.crt", self.base_dir),
            format!("{}/instance-b/ca.crt", self.base_dir),
        )?;

        // Generate server certs for both instances
        self.generate_server_cert("instance-a")?;
        self.generate_server_cert("instance-b")?;

        // Generate client certs (CN = instance name)
        self.generate_client_cert("instance-a", "instance-a")?;
        self.generate_client_cert("instance-b", "instance-b")?;

        Ok(())
    }

    fn generate_server_cert(&self, instance: &str) -> std::io::Result<()> {
        let dir = format!("{}/{}", self.base_dir, instance);

        // Config file for SAN
        let config = format!(
            "[req]\ndistinguished_name=dn\nreq_extensions=v3\nprompt=no\n\
             [dn]\nCN={}-server\n\
             [v3]\nbasicConstraints=CA:FALSE\n\
             keyUsage=digitalSignature,keyEncipherment\n\
             extendedKeyUsage=serverAuth,clientAuth\n\
             subjectAltName=DNS:localhost,IP:127.0.0.1",
            instance
        );
        fs::write(format!("{}/server.cnf", dir), &config)?;

        self.run_openssl(&["genrsa", "-out", &format!("{}/server.key", dir), "2048"])?;
        self.run_openssl(&[
            "req",
            "-new",
            "-key",
            &format!("{}/server.key", dir),
            "-out",
            &format!("{}/server.csr", dir),
            "-config",
            &format!("{}/server.cnf", dir),
        ])?;
        self.run_openssl(&[
            "x509",
            "-req",
            "-in",
            &format!("{}/server.csr", dir),
            "-CA",
            &format!("{}/ca.crt", self.base_dir),
            "-CAkey",
            &format!("{}/ca.key", self.base_dir),
            "-CAcreateserial",
            "-out",
            &format!("{}/server.crt", dir),
            "-days",
            "1",
            "-sha256",
            "-extensions",
            "v3",
            "-extfile",
            &format!("{}/server.cnf", dir),
        ])?;

        Ok(())
    }

    fn generate_client_cert(&self, instance: &str, cn: &str) -> std::io::Result<()> {
        let dir = format!("{}/{}", self.base_dir, instance);

        let ext =
            "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth";
        fs::write(format!("{}/client.ext", dir), ext)?;

        self.run_openssl(&["genrsa", "-out", &format!("{}/client.key", dir), "2048"])?;
        self.run_openssl(&[
            "req",
            "-new",
            "-key",
            &format!("{}/client.key", dir),
            "-out",
            &format!("{}/client.csr", dir),
            "-subj",
            &format!("/CN={}/O=DEFT/OU=Client", cn),
        ])?;
        self.run_openssl(&[
            "x509",
            "-req",
            "-in",
            &format!("{}/client.csr", dir),
            "-CA",
            &format!("{}/ca.crt", self.base_dir),
            "-CAkey",
            &format!("{}/ca.key", self.base_dir),
            "-CAcreateserial",
            "-out",
            &format!("{}/client.crt", dir),
            "-days",
            "1",
            "-sha256",
            "-extfile",
            &format!("{}/client.ext", dir),
        ])?;

        Ok(())
    }

    fn run_openssl(&self, args: &[&str]) -> std::io::Result<()> {
        let output = Command::new("openssl").args(args).output()?;
        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "openssl failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        Ok(())
    }

    fn write_config(
        &self,
        instance: &str,
        port: u16,
        partner: &str,
        partner_port: u16,
        allowed_certs_empty: bool,
    ) -> std::io::Result<()> {
        let allowed_certs = if allowed_certs_empty {
            "[]".to_string()
        } else {
            format!("[\"{}/{}/client.crt\"]", self.base_dir, partner)
        };

        let config = format!(
            r#"[server]
enabled = true
listen = "127.0.0.1:{port}"
cert = "{base}/{instance}/server.crt"
key = "{base}/{instance}/server.key"
ca = "{base}/{instance}/ca.crt"

[client]
enabled = true
cert = "{base}/{instance}/client.crt"
key = "{base}/{instance}/client.key"
ca = "{base}/{instance}/ca.crt"

[storage]
chunk_size = 262144
temp_dir = "{base}/{instance}/tmp"

[limits]
max_connections_per_ip = 100
max_requests_per_partner = 10000
metrics_enabled = false
api_enabled = false

[logging]
format = "text"
level = "debug"

[[partners]]
id = "{partner}"
allowed_certs = {allowed_certs}
endpoints = ["127.0.0.1:{partner_port}"]

[[partners.virtual_files]]
name = "test-files"
path = "{base}/{instance}/outbox/"
direction = "send"
"#,
            port = port,
            base = self.base_dir,
            instance = instance,
            partner = partner,
            partner_port = partner_port,
            allowed_certs = allowed_certs,
        );

        fs::write(
            format!("{}/{}/config.toml", self.base_dir, instance),
            config,
        )
    }

    fn start_instance(&mut self, instance: &str) -> std::io::Result<Child> {
        let config_path = format!("{}/{}/config.toml", self.base_dir, instance);

        // Find the deftd binary using absolute paths
        let workspace_root = "/home/cpo/deft/deft";
        let release_path = format!("{}/target/release/deftd", workspace_root);
        let debug_path = format!("{}/target/debug/deftd", workspace_root);

        let deftd_path = if Path::new(&release_path).exists() {
            release_path
        } else if Path::new(&debug_path).exists() {
            debug_path
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!(
                    "deftd binary not found at {} or {}",
                    release_path, debug_path
                ),
            ));
        };

        Command::new(deftd_path)
            .args(["--config", &config_path])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
    }

    fn wait_for_port(&self, port: u16, timeout_secs: u64) -> bool {
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_secs(timeout_secs) {
            if TcpStream::connect(format!("127.0.0.1:{}", port)).is_ok() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        false
    }

    fn setup_and_start(
        &mut self,
        allowed_certs_empty_a: bool,
        allowed_certs_empty_b: bool,
    ) -> std::io::Result<()> {
        self.setup_certs()?;
        self.write_config(
            "instance-a",
            self.port_a,
            "instance-b",
            self.port_b,
            allowed_certs_empty_a,
        )?;
        self.write_config(
            "instance-b",
            self.port_b,
            "instance-a",
            self.port_a,
            allowed_certs_empty_b,
        )?;

        self.instance_a = Some(self.start_instance("instance-a")?);
        self.instance_b = Some(self.start_instance("instance-b")?);

        if !self.wait_for_port(self.port_a, 5) || !self.wait_for_port(self.port_b, 5) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Instances did not start in time",
            ));
        }

        Ok(())
    }
}

impl Drop for MtlsTestFixture {
    fn drop(&mut self) {
        if let Some(mut child) = self.instance_a.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some(mut child) = self.instance_b.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Connect and authenticate via mTLS, returns the AUTH response
fn mtls_connect_and_auth(
    server_port: u16,
    client_cert: &str,
    client_key: &str,
    ca_cert: &str,
    partner_id: &str,
) -> Result<String, String> {
    // Load certificates
    let cert_file = std::fs::File::open(client_cert)
        .map_err(|e| format!("Failed to open client cert: {}", e))?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Failed to parse client cert: {}", e))?;

    let key_file =
        std::fs::File::open(client_key).map_err(|e| format!("Failed to open client key: {}", e))?;
    let mut key_reader = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| format!("Failed to read client key: {}", e))?
        .ok_or("No private key found")?;

    let ca_file =
        std::fs::File::open(ca_cert).map_err(|e| format!("Failed to open CA cert: {}", e))?;
    let mut ca_reader = BufReader::new(ca_file);
    let ca_certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut ca_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Failed to parse CA cert: {}", e))?;

    let mut root_store = RootCertStore::empty();
    for cert in ca_certs {
        root_store
            .add(cert)
            .map_err(|e| format!("Failed to add CA: {}", e))?;
    }

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(certs, key)
        .map_err(|e| format!("Failed to build TLS config: {}", e))?;

    let server_name = ServerName::try_from("localhost".to_string())
        .map_err(|e| format!("Invalid server name: {}", e))?;

    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name)
        .map_err(|e| format!("Failed to create TLS connection: {}", e))?;

    let mut sock = TcpStream::connect(format!("127.0.0.1:{}", server_port))
        .map_err(|e| format!("Failed to connect: {}", e))?;
    sock.set_read_timeout(Some(Duration::from_secs(5))).ok();
    sock.set_write_timeout(Some(Duration::from_secs(5))).ok();

    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    // HELLO
    tls.write_all(b"DEFT HELLO 1.0 CHUNKED,RESUME\n")
        .map_err(|e| format!("Failed to send HELLO: {}", e))?;

    // Read WELCOME
    let mut buf = vec![0u8; 1024];
    let n = std::io::Read::read(&mut tls, &mut buf)
        .map_err(|e| format!("Failed to read WELCOME: {}", e))?;
    let welcome = String::from_utf8_lossy(&buf[..n]).to_string();
    if !welcome.contains("WELCOME") {
        return Err(format!("Expected WELCOME, got: {}", welcome));
    }

    // AUTH
    tls.write_all(format!("DEFT AUTH {}\n", partner_id).as_bytes())
        .map_err(|e| format!("Failed to send AUTH: {}", e))?;

    // Read AUTH response
    let mut buf = vec![0u8; 1024];
    let n = std::io::Read::read(&mut tls, &mut buf)
        .map_err(|e| format!("Failed to read AUTH response: {}", e))?;
    let response = String::from_utf8_lossy(&buf[..n]).to_string();

    // BYE
    let _ = tls.write_all(b"DEFT BYE\n");

    Ok(response)
}

// ============================================================================
// TDD TESTS - These define expected mTLS behavior
// ============================================================================

/// TEST 1: Valid mTLS - CN matches partner_id, fingerprint in allowed_certs
/// EXPECTED: AUTH_OK
#[test]
fn test_mtls_valid_cn_and_fingerprint() {
    let mut fixture = MtlsTestFixture::new("valid", 18751, 18761);
    if fixture.setup_and_start(false, false).is_err() {
        eprintln!("Skipping test - could not setup");
        return;
    }

    // instance-a (CN=instance-a) connects to instance-b and auths as instance-a
    let result = mtls_connect_and_auth(
        fixture.port_b,
        &format!("{}/instance-a/client.crt", fixture.base_dir),
        &format!("{}/instance-a/client.key", fixture.base_dir),
        &format!("{}/instance-a/ca.crt", fixture.base_dir),
        "instance-a",
    );

    assert!(result.is_ok(), "Connection failed: {:?}", result.err());
    let response = result.unwrap();
    assert!(
        response.contains("AUTH_OK"),
        "Expected AUTH_OK, got: {}",
        response
    );
}

/// TEST 2: CN mismatch - client cert CN doesn't match partner_id
/// EXPECTED: ERROR 401 with CN mismatch message
#[test]
fn test_mtls_cn_mismatch_rejected() {
    let mut fixture = MtlsTestFixture::new("cn-mismatch", 18851, 18861);
    if fixture.setup_and_start(false, false).is_err() {
        eprintln!("Skipping test - could not setup");
        return;
    }

    // Create a rogue cert with different CN
    fixture
        .generate_client_cert("instance-a", "rogue-attacker")
        .unwrap();

    // rogue-attacker (CN=rogue-attacker) tries to auth as instance-a
    let result = mtls_connect_and_auth(
        fixture.port_b,
        &format!("{}/instance-a/client.crt", fixture.base_dir),
        &format!("{}/instance-a/client.key", fixture.base_dir),
        &format!("{}/instance-a/ca.crt", fixture.base_dir),
        "instance-a",
    );

    assert!(result.is_ok(), "Connection should succeed at TLS level");
    let response = result.unwrap();
    assert!(
        response.contains("ERROR") && response.contains("401"),
        "Expected ERROR 401, got: {}",
        response
    );
}

/// TEST 3: BUG - When allowed_certs is empty, CN validation should still be enforced
/// Currently this might pass when it shouldn't
/// EXPECTED: ERROR 401 if no CN or CN doesn't match
#[test]
fn test_mtls_empty_allowed_certs_still_validates_cn() {
    let mut fixture = MtlsTestFixture::new("empty-allowed", 18951, 18961);
    // allowed_certs is empty for instance-b
    if fixture.setup_and_start(false, true).is_err() {
        eprintln!("Skipping test - could not setup");
        return;
    }

    // Create a rogue cert with wrong CN
    fixture
        .generate_client_cert("instance-a", "wrong-cn")
        .unwrap();

    // wrong-cn tries to auth as instance-a with empty allowed_certs
    let result = mtls_connect_and_auth(
        fixture.port_b,
        &format!("{}/instance-a/client.crt", fixture.base_dir),
        &format!("{}/instance-a/client.key", fixture.base_dir),
        &format!("{}/instance-a/ca.crt", fixture.base_dir),
        "instance-a",
    );

    assert!(result.is_ok(), "Connection should succeed at TLS level");
    let response = result.unwrap();
    // THIS IS THE BUG: With empty allowed_certs, CN mismatch should still be rejected
    assert!(
        response.contains("ERROR") && response.contains("401"),
        "BUG: CN mismatch should be rejected even with empty allowed_certs. Got: {}",
        response
    );
}

/// TEST 4: Fingerprint not in allowed_certs
/// EXPECTED: ERROR 401
#[test]
fn test_mtls_fingerprint_not_allowed() {
    let mut fixture = MtlsTestFixture::new("fp-not-allowed", 19051, 19061);
    if fixture.setup_and_start(false, false).is_err() {
        eprintln!("Skipping test - could not setup");
        return;
    }

    // Generate a new client cert with correct CN but different fingerprint
    fs::create_dir_all(format!("{}/rogue", fixture.base_dir)).unwrap();
    fixture.generate_client_cert("rogue", "instance-a").unwrap();

    // Use rogue cert (correct CN but wrong fingerprint)
    let result = mtls_connect_and_auth(
        fixture.port_b,
        &format!("{}/rogue/client.crt", fixture.base_dir),
        &format!("{}/rogue/client.key", fixture.base_dir),
        &format!("{}/instance-a/ca.crt", fixture.base_dir),
        "instance-a",
    );

    assert!(result.is_ok(), "Connection should succeed at TLS level");
    let response = result.unwrap();
    assert!(
        response.contains("ERROR") && response.contains("401"),
        "Fingerprint not in allowed_certs should be rejected. Got: {}",
        response
    );
}

/// TEST 5: BUG - Certificate with NO CN should be rejected
/// Currently this might pass when it shouldn't
/// EXPECTED: ERROR 401
#[test]
fn test_mtls_no_cn_rejected() {
    let mut fixture = MtlsTestFixture::new("no-cn", 19251, 19261);
    // allowed_certs is empty for instance-b to isolate CN validation
    if fixture.setup_and_start(false, true).is_err() {
        eprintln!("Skipping test - could not setup");
        return;
    }

    // Generate a certificate WITHOUT a CN (only O and OU)
    let dir = format!("{}/instance-a", fixture.base_dir);
    let ext = "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth";
    fs::write(format!("{}/nocn.ext", dir), ext).unwrap();

    fixture
        .run_openssl(&["genrsa", "-out", &format!("{}/nocn.key", dir), "2048"])
        .unwrap();
    fixture
        .run_openssl(&[
            "req",
            "-new",
            "-key",
            &format!("{}/nocn.key", dir),
            "-out",
            &format!("{}/nocn.csr", dir),
            "-subj",
            "/O=DEFT/OU=Client", // NO CN!
        ])
        .unwrap();
    fixture
        .run_openssl(&[
            "x509",
            "-req",
            "-in",
            &format!("{}/nocn.csr", dir),
            "-CA",
            &format!("{}/ca.crt", fixture.base_dir),
            "-CAkey",
            &format!("{}/ca.key", fixture.base_dir),
            "-CAcreateserial",
            "-out",
            &format!("{}/nocn.crt", dir),
            "-days",
            "1",
            "-sha256",
            "-extfile",
            &format!("{}/nocn.ext", dir),
        ])
        .unwrap();

    // Try to auth with cert that has no CN
    let result = mtls_connect_and_auth(
        fixture.port_b,
        &format!("{}/nocn.crt", dir),
        &format!("{}/nocn.key", dir),
        &format!("{}/instance-a/ca.crt", fixture.base_dir),
        "instance-a",
    );

    assert!(result.is_ok(), "Connection should succeed at TLS level");
    let response = result.unwrap();
    // THIS IS THE BUG: A cert with no CN should be rejected
    assert!(
        response.contains("ERROR") && response.contains("401"),
        "BUG: Certificate with no CN should be rejected. Got: {}",
        response
    );
}

/// TEST 6: Bidirectional authentication
/// EXPECTED: Both directions AUTH_OK
#[test]
fn test_mtls_bidirectional() {
    let mut fixture = MtlsTestFixture::new("bidir", 19151, 19161);
    if fixture.setup_and_start(false, false).is_err() {
        eprintln!("Skipping test - could not setup");
        return;
    }

    // A -> B
    let result_a_to_b = mtls_connect_and_auth(
        fixture.port_b,
        &format!("{}/instance-a/client.crt", fixture.base_dir),
        &format!("{}/instance-a/client.key", fixture.base_dir),
        &format!("{}/instance-a/ca.crt", fixture.base_dir),
        "instance-a",
    );

    // B -> A
    let result_b_to_a = mtls_connect_and_auth(
        fixture.port_a,
        &format!("{}/instance-b/client.crt", fixture.base_dir),
        &format!("{}/instance-b/client.key", fixture.base_dir),
        &format!("{}/instance-b/ca.crt", fixture.base_dir),
        "instance-b",
    );

    assert!(result_a_to_b.is_ok() && result_a_to_b.unwrap().contains("AUTH_OK"));
    assert!(result_b_to_a.is_ok() && result_b_to_a.unwrap().contains("AUTH_OK"));
}
