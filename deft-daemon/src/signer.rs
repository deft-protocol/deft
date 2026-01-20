//! Receipt signing and verification.
//! 
//! Some methods reserved for signature verification scenarios.
#![allow(dead_code)]

use std::fs::File;
use std::io::Read;
use std::path::Path;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

/// Signature algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SignatureAlgorithm {
    /// SHA-256 hash only (not cryptographically secure for non-repudiation)
    Sha256,
    /// Ed25519 signature (recommended)
    #[default]
    Ed25519,
}

/// Signs data using the server's private key
pub struct ReceiptSigner {
    algorithm: SignatureAlgorithm,
    ed25519_key: Option<Ed25519KeyPair>,
    public_key_bytes: Option<Vec<u8>>,
}

impl ReceiptSigner {
    pub fn new() -> Self {
        Self {
            algorithm: SignatureAlgorithm::Sha256,
            ed25519_key: None,
            public_key_bytes: None,
        }
    }

    /// Create a signer with a new Ed25519 key pair
    pub fn with_new_ed25519_key() -> Result<Self, ring::error::Unspecified> {
        let rng = SystemRandom::new();
        let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng)?;
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())?;
        let public_key = key_pair.public_key().as_ref().to_vec();

        info!("Generated new Ed25519 signing key");

        Ok(Self {
            algorithm: SignatureAlgorithm::Ed25519,
            ed25519_key: Some(key_pair),
            public_key_bytes: Some(public_key),
        })
    }

    /// Load Ed25519 key from PKCS#8 DER file
    pub fn with_ed25519_key_file<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let mut file = File::open(path)?;
        let mut key_data = Vec::new();
        file.read_to_end(&mut key_data)?;

        let key_pair = Ed25519KeyPair::from_pkcs8(&key_data).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{:?}", e))
        })?;
        let public_key = key_pair.public_key().as_ref().to_vec();

        Ok(Self {
            algorithm: SignatureAlgorithm::Ed25519,
            ed25519_key: Some(key_pair),
            public_key_bytes: Some(public_key),
        })
    }

    /// Get the public key as base64
    pub fn public_key_base64(&self) -> Option<String> {
        self.public_key_bytes.as_ref().map(|k| BASE64.encode(k))
    }

    /// Sign a transfer receipt and return base64-encoded signature
    pub fn sign_receipt(&self, receipt_json: &str) -> Option<String> {
        match self.algorithm {
            SignatureAlgorithm::Sha256 => {
                // Fallback: SHA-256 hash only
                let mut hasher = Sha256::new();
                hasher.update(receipt_json.as_bytes());
                let hash = hasher.finalize();
                let sig = format!("sha256:{}", hex_encode(&hash));
                debug!("Generated SHA-256 receipt hash");
                Some(sig)
            }
            SignatureAlgorithm::Ed25519 => {
                if let Some(key) = &self.ed25519_key {
                    let signature = key.sign(receipt_json.as_bytes());
                    let sig = format!("ed25519:{}", BASE64.encode(signature.as_ref()));
                    debug!("Generated Ed25519 receipt signature");
                    Some(sig)
                } else {
                    warn!("No Ed25519 key configured");
                    None
                }
            }
        }
    }

    /// Verify a signature against receipt data
    pub fn verify_signature(&self, receipt_json: &str, signature: &str) -> bool {
        if let Some(hash_hex) = signature.strip_prefix("sha256:") {
            // Verify SHA-256 hash
            let mut hasher = Sha256::new();
            hasher.update(receipt_json.as_bytes());
            let computed = hex_encode(&hasher.finalize());
            computed == hash_hex
        } else if let Some(sig_b64) = signature.strip_prefix("ed25519:") {
            // Verify Ed25519 signature
            if let (Some(public_key), Ok(sig_bytes)) =
                (&self.public_key_bytes, BASE64.decode(sig_b64))
            {
                let public_key = UnparsedPublicKey::new(&ED25519, public_key);
                public_key
                    .verify(receipt_json.as_bytes(), &sig_bytes)
                    .is_ok()
            } else {
                false
            }
        } else {
            false
        }
    }

    /// Verify with external public key
    pub fn verify_with_public_key(
        receipt_json: &str,
        signature: &str,
        public_key_b64: &str,
    ) -> bool {
        if let Some(sig_b64) = signature.strip_prefix("ed25519:") {
            if let (Ok(public_key_bytes), Ok(sig_bytes)) =
                (BASE64.decode(public_key_b64), BASE64.decode(sig_b64))
            {
                let public_key = UnparsedPublicKey::new(&ED25519, &public_key_bytes);
                return public_key
                    .verify(receipt_json.as_bytes(), &sig_bytes)
                    .is_ok();
            }
        }
        false
    }

    pub fn has_key(&self) -> bool {
        self.ed25519_key.is_some()
    }

    pub fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }
}

impl Default for ReceiptSigner {
    fn default() -> Self {
        Self::new()
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_sign_and_verify() {
        let signer = ReceiptSigner::new();
        let receipt_json = r#"{"transfer_id":"test-123","virtual_file":"invoices"}"#;

        let signature = signer.sign_receipt(receipt_json);
        assert!(signature.is_some());

        let sig = signature.unwrap();
        assert!(sig.starts_with("sha256:"));

        // Verify the signature
        assert!(signer.verify_signature(receipt_json, &sig));

        // Different data should not verify
        assert!(!signer.verify_signature("different data", &sig));
    }

    #[test]
    fn test_ed25519_sign_and_verify() {
        let signer = ReceiptSigner::with_new_ed25519_key().unwrap();
        assert!(signer.has_key());
        assert_eq!(signer.algorithm(), SignatureAlgorithm::Ed25519);

        let receipt_json = r#"{"transfer_id":"test-456","virtual_file":"orders"}"#;

        let signature = signer.sign_receipt(receipt_json);
        assert!(signature.is_some());

        let sig = signature.unwrap();
        assert!(sig.starts_with("ed25519:"));

        // Verify the signature
        assert!(signer.verify_signature(receipt_json, &sig));

        // Different data should not verify
        assert!(!signer.verify_signature("different data", &sig));
    }

    #[test]
    fn test_ed25519_public_key() {
        let signer = ReceiptSigner::with_new_ed25519_key().unwrap();

        let public_key = signer.public_key_base64();
        assert!(public_key.is_some());

        let pk = public_key.unwrap();
        assert!(!pk.is_empty());
    }

    #[test]
    fn test_verify_with_external_public_key() {
        let signer = ReceiptSigner::with_new_ed25519_key().unwrap();
        let public_key = signer.public_key_base64().unwrap();

        let receipt_json = r#"{"transfer_id":"test-789"}"#;
        let signature = signer.sign_receipt(receipt_json).unwrap();

        // Verify with extracted public key
        assert!(ReceiptSigner::verify_with_public_key(
            receipt_json,
            &signature,
            &public_key
        ));

        // Wrong data fails
        assert!(!ReceiptSigner::verify_with_public_key(
            "wrong",
            &signature,
            &public_key
        ));
    }

    #[test]
    fn test_no_key() {
        let signer = ReceiptSigner::new();
        assert!(!signer.has_key());

        // SHA-256 still works without Ed25519 key
        let receipt_json = r#"{"test":"data"}"#;
        let sig = signer.sign_receipt(receipt_json);
        assert!(sig.is_some());
        assert!(sig.unwrap().starts_with("sha256:"));
    }
}
