use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Tracks chunk transmission state for timeout and retransmission
#[derive(Debug)]
pub struct ChunkTracker {
    chunks: HashMap<u64, ChunkState>,
    timeout: Duration,
    max_retries: u32,
}

#[derive(Debug, Clone)]
struct ChunkState {
    sent_at: Option<Instant>,
    acked: bool,
    retry_count: u32,
}

impl ChunkTracker {
    pub fn new(total_chunks: u64, timeout_secs: u64, max_retries: u32) -> Self {
        let mut chunks = HashMap::new();
        for i in 0..total_chunks {
            chunks.insert(i, ChunkState {
                sent_at: None,
                acked: false,
                retry_count: 0,
            });
        }
        Self {
            chunks,
            timeout: Duration::from_secs(timeout_secs),
            max_retries,
        }
    }

    /// Mark a chunk as sent
    pub fn mark_sent(&mut self, chunk_index: u64) {
        if let Some(state) = self.chunks.get_mut(&chunk_index) {
            state.sent_at = Some(Instant::now());
        }
    }

    /// Mark a chunk as acknowledged
    pub fn mark_acked(&mut self, chunk_index: u64) {
        if let Some(state) = self.chunks.get_mut(&chunk_index) {
            state.acked = true;
        }
    }

    /// Check if a chunk has been acknowledged
    pub fn is_acked(&self, chunk_index: u64) -> bool {
        self.chunks.get(&chunk_index)
            .map(|s| s.acked)
            .unwrap_or(false)
    }

    /// Get chunks that have timed out and need retransmission
    pub fn get_timed_out(&self) -> Vec<u64> {
        let now = Instant::now();
        self.chunks.iter()
            .filter(|(_, state)| {
                !state.acked 
                    && state.sent_at.is_some()
                    && now.duration_since(state.sent_at.unwrap()) > self.timeout
                    && state.retry_count < self.max_retries
            })
            .map(|(idx, _)| *idx)
            .collect()
    }

    /// Increment retry count for a chunk
    pub fn increment_retry(&mut self, chunk_index: u64) {
        if let Some(state) = self.chunks.get_mut(&chunk_index) {
            state.retry_count += 1;
            state.sent_at = Some(Instant::now());
        }
    }

    /// Check if a chunk has exceeded max retries
    pub fn exceeded_max_retries(&self, chunk_index: u64) -> bool {
        self.chunks.get(&chunk_index)
            .map(|s| s.retry_count >= self.max_retries)
            .unwrap_or(false)
    }

    /// Get chunks that have failed (exceeded max retries)
    pub fn get_failed(&self) -> Vec<u64> {
        self.chunks.iter()
            .filter(|(_, state)| !state.acked && state.retry_count >= self.max_retries)
            .map(|(idx, _)| *idx)
            .collect()
    }

    /// Get pending chunks (not yet sent or need retransmission)
    pub fn get_pending(&self) -> Vec<u64> {
        self.chunks.iter()
            .filter(|(_, state)| !state.acked && state.sent_at.is_none())
            .map(|(idx, _)| *idx)
            .collect()
    }

    /// Get count of acknowledged chunks
    pub fn acked_count(&self) -> u64 {
        self.chunks.values().filter(|s| s.acked).count() as u64
    }

    /// Check if all chunks are acknowledged
    pub fn all_acked(&self) -> bool {
        self.chunks.values().all(|s| s.acked)
    }

    /// Get total chunk count
    pub fn total_count(&self) -> u64 {
        self.chunks.len() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_chunk_tracker() {
        let mut tracker = ChunkTracker::new(5, 1, 3);
        
        assert_eq!(tracker.total_count(), 5);
        assert_eq!(tracker.acked_count(), 0);
        assert!(!tracker.all_acked());

        tracker.mark_sent(0);
        tracker.mark_sent(1);
        
        tracker.mark_acked(0);
        assert!(tracker.is_acked(0));
        assert!(!tracker.is_acked(1));
        assert_eq!(tracker.acked_count(), 1);
    }

    #[test]
    fn test_timeout_detection() {
        let mut tracker = ChunkTracker::new(3, 0, 3); // 0 second timeout for testing
        
        tracker.mark_sent(0);
        tracker.mark_sent(1);
        
        // Small delay to ensure timeout
        sleep(Duration::from_millis(10));
        
        let timed_out = tracker.get_timed_out();
        assert_eq!(timed_out.len(), 2);
        
        tracker.mark_acked(0);
        let timed_out = tracker.get_timed_out();
        assert_eq!(timed_out.len(), 1);
        assert!(timed_out.contains(&1));
    }

    #[test]
    fn test_retry_limit() {
        let mut tracker = ChunkTracker::new(1, 0, 2);
        
        tracker.mark_sent(0);
        assert!(!tracker.exceeded_max_retries(0));
        
        tracker.increment_retry(0);
        assert!(!tracker.exceeded_max_retries(0));
        
        tracker.increment_retry(0);
        assert!(tracker.exceeded_max_retries(0));
        
        let failed = tracker.get_failed();
        assert_eq!(failed.len(), 1);
    }
}
