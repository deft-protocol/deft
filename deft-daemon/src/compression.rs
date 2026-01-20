use std::io::Read;

use flate2::read::{GzDecoder, GzEncoder};
use flate2::Compression;

/// Compression level for data transfer
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CompressionLevel {
    None,
    Fast,
    #[default]
    Default,
    Best,
}

impl From<CompressionLevel> for Compression {
    fn from(level: CompressionLevel) -> Compression {
        match level {
            CompressionLevel::None => Compression::none(),
            CompressionLevel::Fast => Compression::fast(),
            CompressionLevel::Default => Compression::default(),
            CompressionLevel::Best => Compression::best(),
        }
    }
}

/// Compress data using gzip
pub fn compress(data: &[u8], level: CompressionLevel) -> std::io::Result<Vec<u8>> {
    if level == CompressionLevel::None {
        return Ok(data.to_vec());
    }

    let mut encoder = GzEncoder::new(data, level.into());
    let mut compressed = Vec::new();
    encoder.read_to_end(&mut compressed)?;
    Ok(compressed)
}

/// Decompress gzip data
pub fn decompress(data: &[u8]) -> std::io::Result<Vec<u8>> {
    // Check if data is gzip compressed (magic bytes 1f 8b)
    if data.len() < 2 || data[0] != 0x1f || data[1] != 0x8b {
        return Ok(data.to_vec());
    }

    let mut decoder = GzDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;
    Ok(decompressed)
}

/// Calculate compression ratio
pub fn compression_ratio(original: usize, compressed: usize) -> f64 {
    if original == 0 {
        return 0.0;
    }
    1.0 - (compressed as f64 / original as f64)
}

/// Check if compression is beneficial (at least 10% reduction)
pub fn is_compression_beneficial(original: usize, compressed: usize) -> bool {
    compression_ratio(original, compressed) > 0.10
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_decompress() {
        let original = b"Hello, World! This is a test of compression. ".repeat(100);

        let compressed = compress(&original, CompressionLevel::Default).unwrap();
        assert!(compressed.len() < original.len());

        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn test_no_compression() {
        let original = b"Hello, World!";
        let result = compress(original, CompressionLevel::None).unwrap();
        assert_eq!(result, original);
    }

    #[test]
    fn test_decompress_uncompressed() {
        let original = b"Not compressed data";
        let result = decompress(original).unwrap();
        assert_eq!(result, original);
    }

    #[test]
    fn test_compression_ratio() {
        assert_eq!(compression_ratio(100, 50), 0.5);
        assert_eq!(compression_ratio(100, 100), 0.0);
        assert_eq!(compression_ratio(0, 0), 0.0);
    }

    #[test]
    fn test_compression_beneficial() {
        assert!(is_compression_beneficial(100, 80));
        assert!(!is_compression_beneficial(100, 95));
    }

    #[test]
    fn test_compression_levels() {
        let data = b"Test data for compression levels".repeat(50);

        let fast = compress(&data, CompressionLevel::Fast).unwrap();
        let default = compress(&data, CompressionLevel::Default).unwrap();
        let best = compress(&data, CompressionLevel::Best).unwrap();

        // Best should be smallest (or equal)
        assert!(best.len() <= default.len());
        // Fast should be largest compressed (or equal)
        assert!(fast.len() >= default.len());
    }
}
