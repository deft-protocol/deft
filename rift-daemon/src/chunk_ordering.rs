use std::collections::HashMap;
use rand::seq::SliceRandom;
use rand::Rng;

/// Generates a random ordering for chunks with nonces for verification
#[derive(Debug, Clone)]
pub struct ChunkOrderer {
    /// Original chunk count
    chunk_count: u64,
    /// Randomized order: position -> original chunk index
    order: Vec<u64>,
    /// Nonces for each chunk: chunk_index -> nonce
    nonces: HashMap<u64, u64>,
    /// Current position in the randomized order
    current_position: usize,
}

impl ChunkOrderer {
    /// Create a new chunk orderer with randomized order
    pub fn new_random(chunk_count: u64) -> Self {
        let mut rng = rand::thread_rng();
        
        // Create ordered list and shuffle
        let mut order: Vec<u64> = (0..chunk_count).collect();
        order.shuffle(&mut rng);
        
        // Generate unique nonces for each chunk
        let mut nonces = HashMap::new();
        for i in 0..chunk_count {
            nonces.insert(i, rng.gen::<u64>());
        }
        
        Self {
            chunk_count,
            order,
            nonces,
            current_position: 0,
        }
    }

    /// Create a sequential orderer (no randomization)
    pub fn new_sequential(chunk_count: u64) -> Self {
        let mut rng = rand::thread_rng();
        let order: Vec<u64> = (0..chunk_count).collect();
        
        let mut nonces = HashMap::new();
        for i in 0..chunk_count {
            nonces.insert(i, rng.gen::<u64>());
        }
        
        Self {
            chunk_count,
            order,
            nonces,
            current_position: 0,
        }
    }

    /// Get the next chunk index to send
    pub fn next_chunk(&mut self) -> Option<u64> {
        if self.current_position >= self.order.len() {
            return None;
        }
        let chunk_index = self.order[self.current_position];
        self.current_position += 1;
        Some(chunk_index)
    }

    /// Get the nonce for a specific chunk
    pub fn get_nonce(&self, chunk_index: u64) -> Option<u64> {
        self.nonces.get(&chunk_index).copied()
    }

    /// Get all chunk indices in sending order
    pub fn sending_order(&self) -> &[u64] {
        &self.order
    }

    /// Get the total chunk count
    pub fn chunk_count(&self) -> u64 {
        self.chunk_count
    }

    /// Check if all chunks have been sent
    pub fn is_complete(&self) -> bool {
        self.current_position >= self.order.len()
    }

    /// Reset to start
    pub fn reset(&mut self) {
        self.current_position = 0;
    }

    /// Reshuffle the remaining chunks
    pub fn reshuffle_remaining(&mut self) {
        if self.current_position < self.order.len() {
            let mut rng = rand::thread_rng();
            self.order[self.current_position..].shuffle(&mut rng);
        }
    }
}

/// Receiver-side chunk reorderer
#[derive(Debug)]
pub struct ChunkReorderer {
    /// Expected total chunks
    total_chunks: u64,
    /// Received chunks with their nonces: chunk_index -> (data, nonce)
    received: HashMap<u64, (Vec<u8>, Option<u64>)>,
    /// Expected nonces (if provided by sender)
    expected_nonces: HashMap<u64, u64>,
}

impl ChunkReorderer {
    pub fn new(total_chunks: u64) -> Self {
        Self {
            total_chunks,
            received: HashMap::new(),
            expected_nonces: HashMap::new(),
        }
    }

    /// Set expected nonce for a chunk (from transfer metadata)
    pub fn set_expected_nonce(&mut self, chunk_index: u64, nonce: u64) {
        self.expected_nonces.insert(chunk_index, nonce);
    }

    /// Receive a chunk with optional nonce verification
    pub fn receive_chunk(&mut self, chunk_index: u64, data: Vec<u8>, nonce: Option<u64>) -> ChunkReceiveResult {
        if chunk_index >= self.total_chunks {
            return ChunkReceiveResult::InvalidIndex;
        }

        if self.received.contains_key(&chunk_index) {
            return ChunkReceiveResult::Duplicate;
        }

        // Verify nonce if expected
        if let Some(expected) = self.expected_nonces.get(&chunk_index) {
            match nonce {
                Some(received_nonce) if received_nonce == *expected => {
                    // Nonce matches
                }
                Some(received_nonce) => {
                    return ChunkReceiveResult::NonceMismatch {
                        expected: *expected,
                        received: received_nonce,
                    };
                }
                None => {
                    return ChunkReceiveResult::MissingNonce;
                }
            }
        }

        self.received.insert(chunk_index, (data, nonce));
        
        if self.is_complete() {
            ChunkReceiveResult::Complete
        } else {
            ChunkReceiveResult::Ok
        }
    }

    /// Check if all chunks have been received
    pub fn is_complete(&self) -> bool {
        self.received.len() as u64 == self.total_chunks
    }

    /// Get received chunk count
    pub fn received_count(&self) -> u64 {
        self.received.len() as u64
    }

    /// Get missing chunk indices
    pub fn missing_chunks(&self) -> Vec<u64> {
        (0..self.total_chunks)
            .filter(|i| !self.received.contains_key(i))
            .collect()
    }

    /// Reassemble chunks in correct order
    pub fn reassemble(&self) -> Option<Vec<u8>> {
        if !self.is_complete() {
            return None;
        }

        let mut result = Vec::new();
        for i in 0..self.total_chunks {
            if let Some((data, _)) = self.received.get(&i) {
                result.extend_from_slice(data);
            } else {
                return None;
            }
        }
        Some(result)
    }

    /// Get chunks in order for writing
    pub fn chunks_in_order(&self) -> Vec<Option<&[u8]>> {
        (0..self.total_chunks)
            .map(|i| self.received.get(&i).map(|(data, _)| data.as_slice()))
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkReceiveResult {
    Ok,
    Complete,
    Duplicate,
    InvalidIndex,
    NonceMismatch { expected: u64, received: u64 },
    MissingNonce,
}

impl ChunkReceiveResult {
    pub fn is_ok(&self) -> bool {
        matches!(self, ChunkReceiveResult::Ok | ChunkReceiveResult::Complete)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_ordering() {
        let orderer = ChunkOrderer::new_random(10);
        
        // Should have all indices 0-9
        let mut indices: Vec<u64> = orderer.sending_order().to_vec();
        indices.sort();
        assert_eq!(indices, (0..10).collect::<Vec<_>>());
        
        // Each chunk should have a nonce
        for i in 0..10 {
            assert!(orderer.get_nonce(i).is_some());
        }
    }

    #[test]
    fn test_sequential_ordering() {
        let orderer = ChunkOrderer::new_sequential(5);
        assert_eq!(orderer.sending_order(), &[0, 1, 2, 3, 4]);
    }

    #[test]
    fn test_chunk_iteration() {
        let mut orderer = ChunkOrderer::new_sequential(3);
        
        assert_eq!(orderer.next_chunk(), Some(0));
        assert_eq!(orderer.next_chunk(), Some(1));
        assert_eq!(orderer.next_chunk(), Some(2));
        assert_eq!(orderer.next_chunk(), None);
        assert!(orderer.is_complete());
    }

    #[test]
    fn test_reorderer_basic() {
        let mut reorderer = ChunkReorderer::new(3);
        
        // Receive out of order
        assert!(reorderer.receive_chunk(2, vec![3, 4], None).is_ok());
        assert!(reorderer.receive_chunk(0, vec![1, 2], None).is_ok());
        assert_eq!(reorderer.receive_chunk(1, vec![2, 3], None), ChunkReceiveResult::Complete);
        
        assert!(reorderer.is_complete());
        
        // Reassemble in order
        let data = reorderer.reassemble().unwrap();
        assert_eq!(data, vec![1, 2, 2, 3, 3, 4]);
    }

    #[test]
    fn test_reorderer_nonce_verification() {
        let mut reorderer = ChunkReorderer::new(2);
        reorderer.set_expected_nonce(0, 12345);
        reorderer.set_expected_nonce(1, 67890);
        
        // Correct nonce
        assert!(reorderer.receive_chunk(0, vec![1], Some(12345)).is_ok());
        
        // Wrong nonce
        let result = reorderer.receive_chunk(1, vec![2], Some(99999));
        assert_eq!(result, ChunkReceiveResult::NonceMismatch {
            expected: 67890,
            received: 99999,
        });
    }

    #[test]
    fn test_reorderer_duplicate() {
        let mut reorderer = ChunkReorderer::new(2);
        
        assert!(reorderer.receive_chunk(0, vec![1], None).is_ok());
        assert_eq!(reorderer.receive_chunk(0, vec![1], None), ChunkReceiveResult::Duplicate);
    }

    #[test]
    fn test_missing_chunks() {
        let mut reorderer = ChunkReorderer::new(5);
        
        reorderer.receive_chunk(0, vec![], None);
        reorderer.receive_chunk(2, vec![], None);
        reorderer.receive_chunk(4, vec![], None);
        
        assert_eq!(reorderer.missing_chunks(), vec![1, 3]);
    }
}
