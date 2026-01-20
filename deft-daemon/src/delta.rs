//! Delta transfer module for incremental file synchronization.
//! 
//! This module is reserved for future use (v2 feature).
#![allow(dead_code)]

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};

/// Block size for delta computation (4KB default)
pub const DELTA_BLOCK_SIZE: usize = 4096;

/// Rolling checksum for fast block matching (Adler-32 like)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RollingChecksum {
    a: u32,
    b: u32,
    count: usize,
}

impl RollingChecksum {
    pub fn new() -> Self {
        Self {
            a: 0,
            b: 0,
            count: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        for &byte in data {
            self.a = self.a.wrapping_add(byte as u32);
            self.b = self.b.wrapping_add(self.a);
            self.count += 1;
        }
    }

    pub fn roll(&mut self, old_byte: u8, new_byte: u8) {
        self.a = self
            .a
            .wrapping_sub(old_byte as u32)
            .wrapping_add(new_byte as u32);
        self.b = self
            .b
            .wrapping_sub((self.count as u32).wrapping_mul(old_byte as u32))
            .wrapping_add(self.a);
    }

    pub fn value(&self) -> u32 {
        (self.b << 16) | (self.a & 0xffff)
    }

    pub fn reset(&mut self) {
        self.a = 0;
        self.b = 0;
        self.count = 0;
    }
}

impl Default for RollingChecksum {
    fn default() -> Self {
        Self::new()
    }
}

/// Block signature for delta matching
#[derive(Debug, Clone)]
pub struct BlockSignature {
    pub index: u64,
    pub weak_checksum: u32,
    pub strong_hash: [u8; 32],
}

/// File signature containing all block signatures
#[derive(Debug, Clone)]
pub struct FileSignature {
    pub block_size: usize,
    pub file_size: u64,
    pub blocks: Vec<BlockSignature>,
}

impl FileSignature {
    /// Compute signature for a file
    pub fn compute<R: Read>(reader: &mut R, block_size: usize) -> std::io::Result<Self> {
        let mut blocks = Vec::new();
        let mut buffer = vec![0u8; block_size];
        let mut index = 0u64;
        let mut total_size = 0u64;

        loop {
            let bytes_read = reader.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }

            total_size += bytes_read as u64;
            let data = &buffer[..bytes_read];

            // Compute weak checksum
            let mut rolling = RollingChecksum::new();
            rolling.update(data);
            let weak_checksum = rolling.value();

            // Compute strong hash
            let mut hasher = Sha256::new();
            hasher.update(data);
            let hash_result = hasher.finalize();
            let mut strong_hash = [0u8; 32];
            strong_hash.copy_from_slice(&hash_result);

            blocks.push(BlockSignature {
                index,
                weak_checksum,
                strong_hash,
            });

            index += 1;
        }

        Ok(FileSignature {
            block_size,
            file_size: total_size,
            blocks,
        })
    }

    /// Build lookup table for fast matching
    pub fn build_lookup(&self) -> HashMap<u32, Vec<usize>> {
        let mut lookup: HashMap<u32, Vec<usize>> = HashMap::new();
        for (i, block) in self.blocks.iter().enumerate() {
            lookup.entry(block.weak_checksum).or_default().push(i);
        }
        lookup
    }
}

/// Delta operation
#[derive(Debug, Clone)]
pub enum DeltaOp {
    /// Copy block from source at given index
    Copy { block_index: u64 },
    /// Insert new data
    Insert { data: Vec<u8> },
}

/// Delta between two files
#[derive(Debug, Clone)]
pub struct Delta {
    pub block_size: usize,
    pub target_size: u64,
    pub operations: Vec<DeltaOp>,
}

impl Delta {
    /// Compute delta from signature and new file
    pub fn compute<R: Read + Seek>(
        signature: &FileSignature,
        new_file: &mut R,
    ) -> std::io::Result<Self> {
        let lookup = signature.build_lookup();
        let block_size = signature.block_size;
        let mut operations = Vec::new();
        let mut pending_data = Vec::new();
        // Read entire new file
        let mut new_data = Vec::new();
        new_file.read_to_end(&mut new_data)?;
        let target_size = new_data.len() as u64;

        if new_data.is_empty() {
            return Ok(Delta {
                block_size,
                target_size: 0,
                operations,
            });
        }

        let mut pos = 0usize;
        let mut rolling = RollingChecksum::new();

        // Initialize rolling checksum with first block
        let init_len = block_size.min(new_data.len());
        rolling.update(&new_data[..init_len]);

        while pos + block_size <= new_data.len() {
            let weak = rolling.value();

            // Check if weak checksum matches any block
            let mut matched = false;
            if let Some(candidates) = lookup.get(&weak) {
                // Verify with strong hash
                let block_data = &new_data[pos..pos + block_size];
                let mut hasher = Sha256::new();
                hasher.update(block_data);
                let hash_result = hasher.finalize();
                let mut strong_hash = [0u8; 32];
                strong_hash.copy_from_slice(&hash_result);

                for &candidate_idx in candidates {
                    if signature.blocks[candidate_idx].strong_hash == strong_hash {
                        // Match found!
                        if !pending_data.is_empty() {
                            operations.push(DeltaOp::Insert {
                                data: std::mem::take(&mut pending_data),
                            });
                        }
                        operations.push(DeltaOp::Copy {
                            block_index: signature.blocks[candidate_idx].index,
                        });
                        matched = true;
                        pos += block_size;

                        // Reset rolling checksum for next block
                        rolling.reset();
                        if pos + block_size <= new_data.len() {
                            rolling.update(&new_data[pos..pos + block_size]);
                        }
                        break;
                    }
                }
            }

            if !matched {
                // No match, add byte to pending data
                pending_data.push(new_data[pos]);

                if pos + block_size < new_data.len() {
                    // Roll the checksum
                    rolling.roll(new_data[pos], new_data[pos + block_size]);
                }
                pos += 1;
            }
        }

        // Handle remaining bytes
        if pos < new_data.len() {
            pending_data.extend_from_slice(&new_data[pos..]);
        }

        if !pending_data.is_empty() {
            operations.push(DeltaOp::Insert { data: pending_data });
        }

        Ok(Delta {
            block_size,
            target_size,
            operations,
        })
    }

    /// Apply delta to reconstruct target file
    pub fn apply<R: Read + Seek, W: std::io::Write>(
        &self,
        source: &mut R,
        target: &mut W,
    ) -> std::io::Result<u64> {
        let mut written = 0u64;
        let mut block_buffer = vec![0u8; self.block_size];

        for op in &self.operations {
            match op {
                DeltaOp::Copy { block_index } => {
                    let offset = (*block_index as usize) * self.block_size;
                    source.seek(SeekFrom::Start(offset as u64))?;
                    let bytes_read = source.read(&mut block_buffer)?;
                    target.write_all(&block_buffer[..bytes_read])?;
                    written += bytes_read as u64;
                }
                DeltaOp::Insert { data } => {
                    target.write_all(data)?;
                    written += data.len() as u64;
                }
            }
        }

        Ok(written)
    }

    /// Calculate compression ratio (bytes saved / original size)
    pub fn savings(&self, original_size: u64) -> f64 {
        let delta_size: usize = self
            .operations
            .iter()
            .map(|op| {
                match op {
                    DeltaOp::Copy { .. } => 8,                  // Just the block index
                    DeltaOp::Insert { data } => data.len() + 4, // Data + length prefix
                }
            })
            .sum();

        if original_size == 0 {
            return 0.0;
        }

        1.0 - (delta_size as f64 / original_size as f64)
    }

    /// Count statistics
    pub fn stats(&self) -> DeltaStats {
        let mut copy_blocks = 0u64;
        let mut insert_bytes = 0u64;

        for op in &self.operations {
            match op {
                DeltaOp::Copy { .. } => copy_blocks += 1,
                DeltaOp::Insert { data } => insert_bytes += data.len() as u64,
            }
        }

        DeltaStats {
            copy_blocks,
            insert_bytes,
            total_ops: self.operations.len(),
        }
    }
}

/// Delta statistics
#[derive(Debug, Clone)]
pub struct DeltaStats {
    pub copy_blocks: u64,
    pub insert_bytes: u64,
    pub total_ops: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_rolling_checksum() {
        let mut rolling = RollingChecksum::new();
        rolling.update(b"hello");
        let v1 = rolling.value();

        let mut rolling2 = RollingChecksum::new();
        rolling2.update(b"hello");
        assert_eq!(v1, rolling2.value());
    }

    #[test]
    fn test_file_signature() {
        let data = b"hello world this is a test file with some content";
        let mut cursor = Cursor::new(data);

        let sig = FileSignature::compute(&mut cursor, 16).unwrap();
        assert_eq!(sig.file_size, data.len() as u64);
        assert!(!sig.blocks.is_empty());
    }

    #[test]
    fn test_delta_identical() {
        let data = b"hello world this is a test";
        let mut source = Cursor::new(data);
        let mut new_file = Cursor::new(data);

        let sig = FileSignature::compute(&mut source, 8).unwrap();
        source.seek(SeekFrom::Start(0)).unwrap();

        let delta = Delta::compute(&sig, &mut new_file).unwrap();

        // All blocks should be Copy operations
        let stats = delta.stats();
        assert!(stats.insert_bytes < data.len() as u64);
    }

    #[test]
    fn test_delta_modified() {
        let original = b"AAAAAAAAAAAAAAAA"; // 16 bytes
        let modified = b"AAAABBBBAAAAAAAA"; // Changed middle

        let mut source = Cursor::new(original);
        let mut new_file = Cursor::new(modified);

        let sig = FileSignature::compute(&mut source, 4).unwrap();
        source.seek(SeekFrom::Start(0)).unwrap();

        let delta = Delta::compute(&sig, &mut new_file).unwrap();

        // Apply delta
        source.seek(SeekFrom::Start(0)).unwrap();
        let mut output = Vec::new();
        delta.apply(&mut source, &mut output).unwrap();

        assert_eq!(output, modified);
    }

    #[test]
    fn test_delta_apply() {
        let original = b"the quick brown fox jumps over the lazy dog";
        let modified = b"the quick brown cat jumps over the lazy dog";

        let mut source = Cursor::new(original);
        let mut new_file = Cursor::new(modified);

        let sig = FileSignature::compute(&mut source, 8).unwrap();
        source.seek(SeekFrom::Start(0)).unwrap();

        let delta = Delta::compute(&sig, &mut new_file).unwrap();

        source.seek(SeekFrom::Start(0)).unwrap();
        let mut output = Vec::new();
        delta.apply(&mut source, &mut output).unwrap();

        assert_eq!(output, modified);
    }
}
