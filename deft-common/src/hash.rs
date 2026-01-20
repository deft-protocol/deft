use sha2::{Digest, Sha256};

pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex_encode(&result)
}

pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    result.into()
}

pub fn verify_hash(data: &[u8], expected_hex: &str) -> bool {
    let computed = sha256_hex(data);
    computed.eq_ignore_ascii_case(expected_hex)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>, HexDecodeError> {
    if !s.len().is_multiple_of(2) {
        return Err(HexDecodeError::OddLength);
    }

    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| HexDecodeError::InvalidChar))
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HexDecodeError {
    OddLength,
    InvalidChar,
}

impl std::fmt::Display for HexDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HexDecodeError::OddLength => write!(f, "Odd length hex string"),
            HexDecodeError::InvalidChar => write!(f, "Invalid hex character"),
        }
    }
}

impl std::error::Error for HexDecodeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let data = b"hello world";
        let hash = sha256_hex(data);
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_verify_hash() {
        let data = b"hello world";
        assert!(verify_hash(
            data,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        ));
        assert!(!verify_hash(
            data,
            "0000000000000000000000000000000000000000000000000000000000000000"
        ));
    }

    #[test]
    fn test_hex_roundtrip() {
        let bytes = vec![0xde, 0xad, 0xbe, 0xef];
        let hex = hex_encode(&bytes);
        assert_eq!(hex, "deadbeef");
        let decoded = hex_decode(&hex).unwrap();
        assert_eq!(decoded, bytes);
    }
}
