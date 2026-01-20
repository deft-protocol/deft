use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};
use tracing::{debug, warn};

/// Configuration for parallel transfers
#[derive(Debug, Clone)]
pub struct ParallelConfig {
    /// Maximum concurrent chunk transfers
    pub max_concurrent: usize,
    /// Channel buffer size
    pub buffer_size: usize,
}

impl Default for ParallelConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 4,
            buffer_size: 16,
        }
    }
}

/// Result of a chunk transfer
#[derive(Debug, Clone)]
pub struct ChunkResult {
    pub chunk_index: u64,
    pub success: bool,
    pub bytes_sent: u64,
    pub error: Option<String>,
}

/// Manages parallel chunk sending
pub struct ParallelSender {
    config: ParallelConfig,
    semaphore: Arc<Semaphore>,
    results: Arc<Mutex<HashMap<u64, ChunkResult>>>,
}

impl ParallelSender {
    pub fn new(config: ParallelConfig) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent));
        Self {
            config,
            semaphore,
            results: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Get the number of concurrent transfers allowed
    pub fn max_concurrent(&self) -> usize {
        self.config.max_concurrent
    }

    /// Acquire a permit to send a chunk
    pub async fn acquire(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        self.semaphore.clone().acquire_owned().await.ok()
    }

    /// Record a chunk result
    pub async fn record_result(&self, result: ChunkResult) {
        let mut results = self.results.lock().await;
        results.insert(result.chunk_index, result);
    }

    /// Get all results
    pub async fn get_results(&self) -> HashMap<u64, ChunkResult> {
        self.results.lock().await.clone()
    }

    /// Get failed chunk indices
    pub async fn failed_chunks(&self) -> Vec<u64> {
        self.results
            .lock()
            .await
            .iter()
            .filter(|(_, r)| !r.success)
            .map(|(i, _)| *i)
            .collect()
    }

    /// Get success count
    pub async fn success_count(&self) -> usize {
        self.results
            .lock()
            .await
            .values()
            .filter(|r| r.success)
            .count()
    }

    /// Clear results
    pub async fn clear(&self) {
        self.results.lock().await.clear();
    }
}

/// Manages parallel chunk receiving
pub struct ParallelReceiver {
    config: ParallelConfig,
    /// Received chunks: index -> (data, hash)
    chunks: Arc<Mutex<HashMap<u64, (Vec<u8>, String)>>>,
    /// Expected total chunks
    total_chunks: u64,
}

impl ParallelReceiver {
    pub fn new(config: ParallelConfig, total_chunks: u64) -> Self {
        Self {
            config,
            chunks: Arc::new(Mutex::new(HashMap::new())),
            total_chunks,
        }
    }

    /// Store a received chunk
    pub async fn store_chunk(&self, index: u64, data: Vec<u8>, hash: String) -> bool {
        if index >= self.total_chunks {
            warn!(
                "Received chunk {} but total is {}",
                index, self.total_chunks
            );
            return false;
        }

        let mut chunks = self.chunks.lock().await;
        if chunks.contains_key(&index) {
            debug!("Duplicate chunk {} ignored", index);
            return false;
        }

        chunks.insert(index, (data, hash));
        true
    }

    /// Check if all chunks received
    pub async fn is_complete(&self) -> bool {
        self.chunks.lock().await.len() as u64 == self.total_chunks
    }

    /// Get received count
    pub async fn received_count(&self) -> u64 {
        self.chunks.lock().await.len() as u64
    }

    /// Get missing chunk indices
    pub async fn missing_chunks(&self) -> Vec<u64> {
        let chunks = self.chunks.lock().await;
        (0..self.total_chunks)
            .filter(|i| !chunks.contains_key(i))
            .collect()
    }

    /// Reassemble all chunks in order
    pub async fn reassemble(&self) -> Option<Vec<u8>> {
        let chunks = self.chunks.lock().await;
        if chunks.len() as u64 != self.total_chunks {
            return None;
        }

        let mut result = Vec::new();
        for i in 0..self.total_chunks {
            if let Some((data, _)) = chunks.get(&i) {
                result.extend_from_slice(data);
            } else {
                return None;
            }
        }
        Some(result)
    }

    /// Get chunk data by index
    pub async fn get_chunk(&self, index: u64) -> Option<(Vec<u8>, String)> {
        self.chunks.lock().await.get(&index).cloned()
    }
}

/// Batch sender for sending chunks in parallel batches
pub struct BatchSender {
    batch_size: usize,
    current_batch: Vec<u64>,
}

impl BatchSender {
    pub fn new(batch_size: usize) -> Self {
        Self {
            batch_size,
            current_batch: Vec::with_capacity(batch_size),
        }
    }

    /// Add a chunk index to the current batch
    pub fn add(&mut self, chunk_index: u64) -> bool {
        if self.current_batch.len() >= self.batch_size {
            return false;
        }
        self.current_batch.push(chunk_index);
        true
    }

    /// Check if batch is full
    pub fn is_full(&self) -> bool {
        self.current_batch.len() >= self.batch_size
    }

    /// Take the current batch
    pub fn take_batch(&mut self) -> Vec<u64> {
        std::mem::take(&mut self.current_batch)
    }

    /// Get batch size
    pub fn batch_size(&self) -> usize {
        self.batch_size
    }
}

/// Coordinator for parallel transfer operations
pub struct TransferCoordinator {
    sender: ParallelSender,
    /// Chunks pending acknowledgment
    pending_acks: Arc<Mutex<HashMap<u64, tokio::time::Instant>>>,
    /// Timeout for individual chunk ACKs
    ack_timeout: std::time::Duration,
}

impl TransferCoordinator {
    pub fn new(config: ParallelConfig) -> Self {
        Self {
            sender: ParallelSender::new(config),
            pending_acks: Arc::new(Mutex::new(HashMap::new())),
            ack_timeout: std::time::Duration::from_secs(30),
        }
    }

    /// Mark a chunk as sent, waiting for ACK
    pub async fn chunk_sent(&self, chunk_index: u64) {
        self.pending_acks
            .lock()
            .await
            .insert(chunk_index, tokio::time::Instant::now());
    }

    /// Mark a chunk as acknowledged
    pub async fn chunk_acked(&self, chunk_index: u64, success: bool) {
        self.pending_acks.lock().await.remove(&chunk_index);
        self.sender
            .record_result(ChunkResult {
                chunk_index,
                success,
                bytes_sent: 0,
                error: if success {
                    None
                } else {
                    Some("ACK failed".into())
                },
            })
            .await;
    }

    /// Get chunks that have timed out
    pub async fn timed_out_chunks(&self) -> Vec<u64> {
        let pending = self.pending_acks.lock().await;
        let now = tokio::time::Instant::now();
        pending
            .iter()
            .filter(|(_, sent_at)| now.duration_since(**sent_at) > self.ack_timeout)
            .map(|(idx, _)| *idx)
            .collect()
    }

    /// Get count of pending ACKs
    pub async fn pending_count(&self) -> usize {
        self.pending_acks.lock().await.len()
    }

    /// Get the underlying sender
    pub fn sender(&self) -> &ParallelSender {
        &self.sender
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_parallel_sender() {
        let sender = ParallelSender::new(ParallelConfig::default());

        // Acquire permits
        let _permit1 = sender.acquire().await.unwrap();
        let _permit2 = sender.acquire().await.unwrap();

        // Record results
        sender
            .record_result(ChunkResult {
                chunk_index: 0,
                success: true,
                bytes_sent: 1024,
                error: None,
            })
            .await;

        sender
            .record_result(ChunkResult {
                chunk_index: 1,
                success: false,
                bytes_sent: 0,
                error: Some("Network error".into()),
            })
            .await;

        assert_eq!(sender.success_count().await, 1);
        assert_eq!(sender.failed_chunks().await, vec![1]);
    }

    #[tokio::test]
    async fn test_parallel_receiver() {
        let receiver = ParallelReceiver::new(ParallelConfig::default(), 3);

        // Receive out of order
        assert!(receiver.store_chunk(2, vec![3], "hash2".into()).await);
        assert!(receiver.store_chunk(0, vec![1], "hash0".into()).await);
        assert!(!receiver.is_complete().await);

        assert!(receiver.store_chunk(1, vec![2], "hash1".into()).await);
        assert!(receiver.is_complete().await);

        // Reassemble
        let data = receiver.reassemble().await.unwrap();
        assert_eq!(data, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn test_parallel_receiver_missing() {
        let receiver = ParallelReceiver::new(ParallelConfig::default(), 5);

        receiver.store_chunk(0, vec![], "".into()).await;
        receiver.store_chunk(2, vec![], "".into()).await;
        receiver.store_chunk(4, vec![], "".into()).await;

        let missing = receiver.missing_chunks().await;
        assert_eq!(missing, vec![1, 3]);
    }

    #[tokio::test]
    async fn test_batch_sender() {
        let mut batch = BatchSender::new(3);

        assert!(batch.add(0));
        assert!(batch.add(1));
        assert!(!batch.is_full());
        assert!(batch.add(2));
        assert!(batch.is_full());
        assert!(!batch.add(3)); // Full

        let chunks = batch.take_batch();
        assert_eq!(chunks, vec![0, 1, 2]);
        assert!(!batch.is_full());
    }

    #[tokio::test]
    async fn test_transfer_coordinator() {
        let coord = TransferCoordinator::new(ParallelConfig::default());

        coord.chunk_sent(0).await;
        coord.chunk_sent(1).await;
        assert_eq!(coord.pending_count().await, 2);

        coord.chunk_acked(0, true).await;
        assert_eq!(coord.pending_count().await, 1);

        coord.chunk_acked(1, false).await;
        assert_eq!(coord.pending_count().await, 0);

        assert_eq!(coord.sender().success_count().await, 1);
    }
}
