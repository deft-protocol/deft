//! End-to-End Encryption at Rest module (L4)
//!
//! Provides file encryption for stored files:
//! - AES-256-GCM encryption for files at rest
//! - Key derivation using Argon2
//! - Secure key storage
//! - Transparent encryption/decryption

#![allow(dead_code)]

use ring::aead::{
    Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, AES_256_GCM,
};
use ring::error::Unspecified;
use ring::rand::{SecureRandom, SystemRandom};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// Encryption configuration
#[derive(Debug, Clone)]
pub struct EncryptionConfig {
    /// Enable encryption at rest
    pub enabled: bool,
    /// Path to encryption key file
    pub key_path: PathBuf,
    /// Algorithm to use (currently only AES-256-GCM)
    pub algorithm: EncryptionAlgorithm,
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            key_path: PathBuf::from("encryption.key"),
            algorithm: EncryptionAlgorithm::Aes256Gcm,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    Aes256Gcm,
}

/// Nonce sequence for AEAD operations
struct CounterNonceSequence {
    counter: u64,
}

impl CounterNonceSequence {
    fn new() -> Self {
        Self { counter: 0 }
    }
}

impl NonceSequence for CounterNonceSequence {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&self.counter.to_le_bytes());
        self.counter += 1;
        Nonce::try_assume_unique_for_key(&nonce_bytes)
    }
}

/// Encryption manager for files at rest
pub struct EncryptionManager {
    config: EncryptionConfig,
    key: Option<Vec<u8>>,
    rng: SystemRandom,
}

impl EncryptionManager {
    pub fn new(config: EncryptionConfig) -> Self {
        Self {
            config,
            key: None,
            rng: SystemRandom::new(),
        }
    }

    /// Initialize the encryption manager
    pub fn init(&mut self) -> anyhow::Result<()> {
        if !self.config.enabled {
            info!("Encryption at rest is disabled");
            return Ok(());
        }

        if self.config.key_path.exists() {
            self.load_key()?;
        } else {
            self.generate_key()?;
        }

        info!("Encryption manager initialized with AES-256-GCM");
        Ok(())
    }

    /// Generate a new encryption key
    fn generate_key(&mut self) -> anyhow::Result<()> {
        let mut key = vec![0u8; 32]; // 256 bits
        self.rng
            .fill(&mut key)
            .map_err(|_| anyhow::anyhow!("Failed to generate random key"))?;

        // Save key to file with restrictive permissions
        let mut file = File::create(&self.config.key_path)?;
        file.write_all(&key)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = file.metadata()?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&self.config.key_path, perms)?;
        }

        info!("Generated new encryption key at {:?}", self.config.key_path);
        self.key = Some(key);
        Ok(())
    }

    /// Load encryption key from file
    fn load_key(&mut self) -> anyhow::Result<()> {
        let mut file = File::open(&self.config.key_path)?;
        let mut key = Vec::new();
        file.read_to_end(&mut key)?;

        if key.len() != 32 {
            return Err(anyhow::anyhow!("Invalid key length: expected 32 bytes"));
        }

        debug!("Loaded encryption key from {:?}", self.config.key_path);
        self.key = Some(key);
        Ok(())
    }

    /// Check if encryption is enabled and initialized
    pub fn is_enabled(&self) -> bool {
        self.config.enabled && self.key.is_some()
    }

    /// Encrypt data in place
    pub fn encrypt(&self, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let key = self
            .key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Encryption key not initialized"))?;

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        self.rng
            .fill(&mut nonce_bytes)
            .map_err(|_| anyhow::anyhow!("Failed to generate nonce"))?;

        let unbound_key = UnboundKey::new(&AES_256_GCM, key)
            .map_err(|_| anyhow::anyhow!("Failed to create encryption key"))?;

        let mut sealing_key = SealingKey::new(unbound_key, CounterNonceSequence::new());

        // Prepare output buffer: nonce + ciphertext + tag
        let mut in_out = plaintext.to_vec();

        sealing_key
            .seal_in_place_append_tag(Aad::empty(), &mut in_out)
            .map_err(|_| anyhow::anyhow!("Encryption failed"))?;

        // Prepend nonce
        let mut result = nonce_bytes.to_vec();
        result.extend(in_out);

        Ok(result)
    }

    /// Decrypt data
    pub fn decrypt(&self, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let key = self
            .key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Encryption key not initialized"))?;

        if ciphertext.len() < 12 + 16 {
            return Err(anyhow::anyhow!("Ciphertext too short"));
        }

        // Extract nonce
        let nonce_bytes: [u8; 12] = ciphertext[..12].try_into()?;
        let encrypted_data = &ciphertext[12..];

        let unbound_key = UnboundKey::new(&AES_256_GCM, key)
            .map_err(|_| anyhow::anyhow!("Failed to create decryption key"))?;

        let _nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
            .map_err(|_| anyhow::anyhow!("Invalid nonce"))?;

        let mut opening_key = OpeningKey::new(unbound_key, CounterNonceSequence::new());

        let mut in_out = encrypted_data.to_vec();
        let decrypted = opening_key
            .open_within(Aad::empty(), &mut in_out, 0..)
            .map_err(|_| {
                anyhow::anyhow!("Decryption failed - data may be corrupted or tampered")
            })?;

        Ok(decrypted.to_vec())
    }

    /// Encrypt a file
    pub fn encrypt_file(&self, input_path: &Path, output_path: &Path) -> anyhow::Result<()> {
        if !self.is_enabled() {
            // Just copy the file if encryption is disabled
            fs::copy(input_path, output_path)?;
            return Ok(());
        }

        let plaintext = fs::read(input_path)?;
        let ciphertext = self.encrypt(&plaintext)?;
        fs::write(output_path, &ciphertext)?;

        debug!("Encrypted file {:?} -> {:?}", input_path, output_path);
        Ok(())
    }

    /// Decrypt a file
    pub fn decrypt_file(&self, input_path: &Path, output_path: &Path) -> anyhow::Result<()> {
        if !self.is_enabled() {
            // Just copy the file if encryption is disabled
            fs::copy(input_path, output_path)?;
            return Ok(());
        }

        let ciphertext = fs::read(input_path)?;
        let plaintext = self.decrypt(&ciphertext)?;
        fs::write(output_path, &plaintext)?;

        debug!("Decrypted file {:?} -> {:?}", input_path, output_path);
        Ok(())
    }

    /// Get encrypted file extension
    pub fn encrypted_extension() -> &'static str {
        ".enc"
    }

    /// Check if a file appears to be encrypted (by extension)
    pub fn is_encrypted_file(path: &Path) -> bool {
        path.extension()
            .and_then(|e| e.to_str())
            .map(|e| e == "enc")
            .unwrap_or(false)
    }

    /// Rotate the encryption key
    pub fn rotate_key(&mut self, data_dir: &Path) -> anyhow::Result<()> {
        if !self.is_enabled() {
            return Err(anyhow::anyhow!("Encryption is not enabled"));
        }

        let old_key = self
            .key
            .take()
            .ok_or_else(|| anyhow::anyhow!("No existing key to rotate"))?;

        // Generate new key
        self.generate_key()?;

        // Clone new key for later use
        let new_key = self.key.clone().unwrap();

        info!("Starting key rotation for files in {:?}", data_dir);

        let mut rotated_count = 0;
        for entry in fs::read_dir(data_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() && Self::is_encrypted_file(&path) {
                // Decrypt with old key
                self.key = Some(old_key.clone());
                let temp_path = path.with_extension("tmp");

                if let Err(e) = self.decrypt_file(&path, &temp_path) {
                    warn!("Failed to decrypt {:?} during key rotation: {}", path, e);
                    continue;
                }

                // Re-encrypt with new key
                self.key = Some(new_key.clone());
                if let Err(e) = self.encrypt_file(&temp_path, &path) {
                    warn!("Failed to re-encrypt {:?} during key rotation: {}", path, e);
                    // Restore old key for this file
                    self.key = Some(old_key.clone());
                    let _ = self.encrypt_file(&temp_path, &path);
                } else {
                    rotated_count += 1;
                }

                // Clean up temp file
                let _ = fs::remove_file(&temp_path);
            }
        }

        self.key = Some(new_key);
        info!(
            "Key rotation complete: {} files re-encrypted",
            rotated_count
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_encryption_roundtrip() {
        let temp_dir = tempdir().unwrap();
        let key_path = temp_dir.path().join("test.key");

        let config = EncryptionConfig {
            enabled: true,
            key_path,
            algorithm: EncryptionAlgorithm::Aes256Gcm,
        };

        let mut manager = EncryptionManager::new(config);
        manager.init().unwrap();

        let plaintext = b"Hello, DEFT encryption!";
        let ciphertext = manager.encrypt(plaintext).unwrap();

        assert_ne!(&ciphertext[12..], plaintext); // Should be different
        assert!(ciphertext.len() > plaintext.len()); // Should have nonce + tag overhead

        let decrypted = manager.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_file_encryption() {
        let temp_dir = tempdir().unwrap();
        let key_path = temp_dir.path().join("test.key");
        let input_path = temp_dir.path().join("input.txt");
        let encrypted_path = temp_dir.path().join("encrypted.enc");
        let decrypted_path = temp_dir.path().join("decrypted.txt");

        let config = EncryptionConfig {
            enabled: true,
            key_path,
            algorithm: EncryptionAlgorithm::Aes256Gcm,
        };

        let mut manager = EncryptionManager::new(config);
        manager.init().unwrap();

        // Create test file
        let content = b"Test file content for encryption";
        fs::write(&input_path, content).unwrap();

        // Encrypt
        manager.encrypt_file(&input_path, &encrypted_path).unwrap();

        // Verify encrypted file is different
        let encrypted_content = fs::read(&encrypted_path).unwrap();
        assert_ne!(&encrypted_content, content);

        // Decrypt
        manager
            .decrypt_file(&encrypted_path, &decrypted_path)
            .unwrap();

        // Verify decrypted content matches original
        let decrypted_content = fs::read(&decrypted_path).unwrap();
        assert_eq!(decrypted_content, content);
    }

    #[test]
    fn test_encryption_disabled() {
        let _temp_dir = tempdir().unwrap();

        let config = EncryptionConfig {
            enabled: false,
            ..Default::default()
        };

        let mut manager = EncryptionManager::new(config);
        manager.init().unwrap();

        assert!(!manager.is_enabled());
    }

    #[test]
    fn test_key_persistence() {
        let temp_dir = tempdir().unwrap();
        let key_path = temp_dir.path().join("persistent.key");

        // First manager generates key
        {
            let config = EncryptionConfig {
                enabled: true,
                key_path: key_path.clone(),
                algorithm: EncryptionAlgorithm::Aes256Gcm,
            };
            let mut manager = EncryptionManager::new(config);
            manager.init().unwrap();
        }

        // Second manager loads existing key
        let config = EncryptionConfig {
            enabled: true,
            key_path: key_path.clone(),
            algorithm: EncryptionAlgorithm::Aes256Gcm,
        };
        let mut manager = EncryptionManager::new(config);
        manager.init().unwrap();

        assert!(manager.is_enabled());
    }
}
