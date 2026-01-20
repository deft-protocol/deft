use std::collections::{HashMap, HashSet};
use std::sync::RwLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use deft_common::sha256_hex;
use deft_protocol::{AckErrorReason, AckStatus, ChunkRange, TransferReceipt};

pub const DEFAULT_CHUNK_TIMEOUT: Duration = Duration::from_secs(10);
pub const DEFAULT_MAX_RETRIES: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkState {
    Pending,
    Received,
    Validated,
    Error(AckErrorReason),
}

#[derive(Debug)]
pub struct ChunkTracker {
    pub index: u64,
    pub expected_hash: String,
    pub state: ChunkState,
    pub received_at: Option<Instant>,
    pub retry_count: u32,
}

#[derive(Debug)]
pub struct ActiveTransfer {
    pub transfer_id: String,
    pub virtual_file: String,
    pub sender_partner: String,
    pub receiver_partner: String,
    pub direction: TransferDirection,
    pub total_chunks: u64,
    pub total_bytes: u64,
    pub chunk_size: u32,
    pub file_hash: String,
    pub chunks: HashMap<u64, ChunkTracker>,
    pub window_size: u32,
    pub in_flight: HashSet<u64>,
    pub started_at: Instant,
    pub start_timestamp: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDirection {
    Sending,
    Receiving,
}

impl ActiveTransfer {
    pub fn new_receive(
        virtual_file: String,
        sender_partner: String,
        receiver_partner: String,
        total_chunks: u64,
        total_bytes: u64,
        chunk_size: u32,
        file_hash: String,
        chunk_hashes: Vec<(u64, String)>,
        window_size: u32,
    ) -> Self {
        let transfer_id = generate_transfer_id();
        let mut chunks = HashMap::new();

        for (index, hash) in chunk_hashes {
            chunks.insert(index, ChunkTracker {
                index,
                expected_hash: hash,
                state: ChunkState::Pending,
                received_at: None,
                retry_count: 0,
            });
        }

        let start_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| format!("{}Z", d.as_secs()))
            .unwrap_or_default();

        Self {
            transfer_id,
            virtual_file,
            sender_partner,
            receiver_partner,
            direction: TransferDirection::Receiving,
            total_chunks,
            total_bytes,
            chunk_size,
            file_hash,
            chunks,
            window_size,
            in_flight: HashSet::new(),
            started_at: Instant::now(),
            start_timestamp,
        }
    }

    pub fn can_send_chunk(&self) -> bool {
        (self.in_flight.len() as u32) < self.window_size
    }

    pub fn mark_in_flight(&mut self, chunk_index: u64) {
        self.in_flight.insert(chunk_index);
    }

    pub fn mark_acked(&mut self, chunk_index: u64) {
        self.in_flight.remove(&chunk_index);
    }

    pub fn in_flight_count(&self) -> usize {
        self.in_flight.len()
    }

    pub fn available_window(&self) -> u32 {
        self.window_size.saturating_sub(self.in_flight.len() as u32)
    }

    pub fn validate_chunk(&mut self, index: u64, data: &[u8]) -> AckStatus {
        // Remove from in-flight when validated
        self.in_flight.remove(&index);

        let chunk = match self.chunks.get_mut(&index) {
            Some(c) => c,
            None => return AckStatus::Error(AckErrorReason::Unknown),
        };

        let computed_hash = sha256_hex(data);
        
        if computed_hash.eq_ignore_ascii_case(&chunk.expected_hash) {
            chunk.state = ChunkState::Validated;
            chunk.received_at = Some(Instant::now());
            AckStatus::Ok
        } else {
            chunk.state = ChunkState::Error(AckErrorReason::HashMismatch);
            chunk.retry_count += 1;
            AckStatus::Error(AckErrorReason::HashMismatch)
        }
    }

    pub fn validated_ranges(&self) -> Vec<ChunkRange> {
        let mut validated: Vec<u64> = self.chunks
            .iter()
            .filter(|(_, c)| c.state == ChunkState::Validated)
            .map(|(idx, _)| *idx)
            .collect();
        
        validated.sort();
        
        if validated.is_empty() {
            return Vec::new();
        }

        let mut ranges = Vec::new();
        let mut start = validated[0];
        let mut end = validated[0];

        for &idx in &validated[1..] {
            if idx == end + 1 {
                end = idx;
            } else {
                ranges.push(ChunkRange::new(start, end));
                start = idx;
                end = idx;
            }
        }
        ranges.push(ChunkRange::new(start, end));

        ranges
    }

    pub fn is_complete(&self) -> bool {
        self.chunks.values().all(|c| c.state == ChunkState::Validated)
    }

    pub fn pending_count(&self) -> usize {
        self.chunks.values().filter(|c| c.state == ChunkState::Pending).count()
    }

    pub fn validated_count(&self) -> usize {
        self.chunks.values().filter(|c| c.state == ChunkState::Validated).count()
    }

    pub fn generate_receipt(&self, signature: Option<String>) -> TransferReceipt {
        let complete_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| format!("{}Z", d.as_secs()))
            .unwrap_or_default();

        TransferReceipt {
            transfer_id: self.transfer_id.clone(),
            virtual_file: self.virtual_file.clone(),
            sender_partner: self.sender_partner.clone(),
            receiver_partner: self.receiver_partner.clone(),
            timestamp_start: self.start_timestamp.clone(),
            timestamp_complete: complete_timestamp,
            chunks_total: self.total_chunks,
            total_bytes: self.total_bytes,
            file_hash: self.file_hash.clone(),
            signature,
        }
    }
}

pub struct TransferManager {
    active_transfers: RwLock<HashMap<String, ActiveTransfer>>,
}

impl TransferManager {
    pub fn new() -> Self {
        Self {
            active_transfers: RwLock::new(HashMap::new()),
        }
    }

    pub fn start_transfer(&self, transfer: ActiveTransfer) -> String {
        let id = transfer.transfer_id.clone();
        self.active_transfers.write().unwrap().insert(id.clone(), transfer);
        id
    }

    pub fn get_transfer(&self, transfer_id: &str) -> Option<ActiveTransfer> {
        self.active_transfers.read().unwrap().get(transfer_id).cloned()
    }

    pub fn validate_chunk(&self, transfer_id: &str, chunk_index: u64, data: &[u8]) -> Option<AckStatus> {
        let mut transfers = self.active_transfers.write().unwrap();
        transfers.get_mut(transfer_id).map(|t| t.validate_chunk(chunk_index, data))
    }

    pub fn update_chunk_hash(&self, transfer_id: &str, chunk_index: u64, hash: &str) {
        let mut transfers = self.active_transfers.write().unwrap();
        if let Some(transfer) = transfers.get_mut(transfer_id) {
            if let Some(chunk) = transfer.chunks.get_mut(&chunk_index) {
                chunk.expected_hash = hash.to_string();
            }
        }
    }

    pub fn is_complete(&self, transfer_id: &str) -> bool {
        self.active_transfers.read().unwrap()
            .get(transfer_id)
            .map(|t| t.is_complete())
            .unwrap_or(false)
    }

    pub fn complete_transfer(&self, transfer_id: &str) -> Option<TransferReceipt> {
        let mut transfers = self.active_transfers.write().unwrap();
        transfers.remove(transfer_id).map(|t| t.generate_receipt(None))
    }
}

impl Default for TransferManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for ActiveTransfer {
    fn clone(&self) -> Self {
        Self {
            transfer_id: self.transfer_id.clone(),
            virtual_file: self.virtual_file.clone(),
            sender_partner: self.sender_partner.clone(),
            receiver_partner: self.receiver_partner.clone(),
            direction: self.direction,
            total_chunks: self.total_chunks,
            total_bytes: self.total_bytes,
            chunk_size: self.chunk_size,
            file_hash: self.file_hash.clone(),
            chunks: self.chunks.iter().map(|(k, v)| (*k, ChunkTracker {
                index: v.index,
                expected_hash: v.expected_hash.clone(),
                state: v.state,
                received_at: v.received_at,
                retry_count: v.retry_count,
            })).collect(),
            window_size: self.window_size,
            in_flight: self.in_flight.clone(),
            started_at: self.started_at,
            start_timestamp: self.start_timestamp.clone(),
        }
    }
}

fn generate_transfer_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let counter = COUNTER.fetch_add(1, Ordering::SeqCst);
    
    format!("{:x}-{:04x}", timestamp, counter % 0xFFFF)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transfer_validation() {
        let data = b"test chunk data";
        let hash = sha256_hex(data);

        let mut transfer = ActiveTransfer::new_receive(
            "test-file".into(),
            "sender".into(),
            "receiver".into(),
            1,
            data.len() as u64,
            1024,
            hash.clone(),
            vec![(0, hash.clone())],
            64,
        );

        assert!(!transfer.is_complete());
        assert_eq!(transfer.pending_count(), 1);

        let status = transfer.validate_chunk(0, data);
        assert_eq!(status, AckStatus::Ok);
        assert!(transfer.is_complete());
    }

    #[test]
    fn test_hash_mismatch() {
        let mut transfer = ActiveTransfer::new_receive(
            "test-file".into(),
            "sender".into(),
            "receiver".into(),
            1,
            10,
            1024,
            "filehash".into(),
            vec![(0, "expectedhash".into())],
            64,
        );

        let status = transfer.validate_chunk(0, b"wrong data");
        assert!(matches!(status, AckStatus::Error(AckErrorReason::HashMismatch)));
    }

    #[test]
    fn test_validated_ranges() {
        let mut transfer = ActiveTransfer::new_receive(
            "test-file".into(),
            "sender".into(),
            "receiver".into(),
            5,
            5000,
            1024,
            "hash".into(),
            vec![
                (0, sha256_hex(b"0")),
                (1, sha256_hex(b"1")),
                (2, sha256_hex(b"2")),
                (3, sha256_hex(b"3")),
                (4, sha256_hex(b"4")),
            ],
            64,
        );

        transfer.validate_chunk(0, b"0");
        transfer.validate_chunk(1, b"1");
        transfer.validate_chunk(3, b"3");

        let ranges = transfer.validated_ranges();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].start, 0);
        assert_eq!(ranges[0].end, 1);
        assert_eq!(ranges[1].start, 3);
        assert_eq!(ranges[1].end, 3);
    }

    #[test]
    fn test_transfer_manager() {
        let manager = TransferManager::new();
        let data = b"chunk data";
        let hash = sha256_hex(data);

        let transfer = ActiveTransfer::new_receive(
            "test-file".into(),
            "sender".into(),
            "receiver".into(),
            1,
            data.len() as u64,
            1024,
            hash.clone(),
            vec![(0, hash.clone())],
            64,
        );

        let id = manager.start_transfer(transfer);
        assert!(!manager.is_complete(&id));

        let status = manager.validate_chunk(&id, 0, data);
        assert_eq!(status, Some(AckStatus::Ok));
        assert!(manager.is_complete(&id));

        let receipt = manager.complete_transfer(&id);
        assert!(receipt.is_some());
        assert_eq!(receipt.unwrap().virtual_file, "test-file");
    }

    #[test]
    fn test_generate_receipt() {
        let data = b"test data";
        let hash = sha256_hex(data);

        let transfer = ActiveTransfer::new_receive(
            "invoices".into(),
            "acme".into(),
            "supplier".into(),
            1,
            data.len() as u64,
            1024,
            hash.clone(),
            vec![(0, hash)],
            64,
        );

        let receipt = transfer.generate_receipt(Some("sig123".into()));
        assert_eq!(receipt.virtual_file, "invoices");
        assert_eq!(receipt.sender_partner, "acme");
        assert_eq!(receipt.receiver_partner, "supplier");
        assert_eq!(receipt.chunks_total, 1);
        assert_eq!(receipt.signature, Some("sig123".into()));
    }

    #[test]
    fn test_chunk_state_tracking() {
        let mut transfer = ActiveTransfer::new_receive(
            "file".into(),
            "s".into(),
            "r".into(),
            3,
            3000,
            1024,
            "fh".into(),
            vec![
                (0, sha256_hex(b"a")),
                (1, sha256_hex(b"b")),
                (2, sha256_hex(b"c")),
            ],
            64,
        );

        assert_eq!(transfer.pending_count(), 3);
        assert_eq!(transfer.validated_count(), 0);

        transfer.validate_chunk(0, b"a");
        assert_eq!(transfer.pending_count(), 2);
        assert_eq!(transfer.validated_count(), 1);

        transfer.validate_chunk(1, b"wrong");
        // Chunk 1 is now in Error state, not Pending anymore
        assert_eq!(transfer.pending_count(), 1);
        assert_eq!(transfer.validated_count(), 1);

        transfer.validate_chunk(2, b"c");
        assert_eq!(transfer.validated_count(), 2);
        assert_eq!(transfer.pending_count(), 0);
        assert!(!transfer.is_complete()); // Chunk 1 failed (Error state)
    }

    #[test]
    fn test_sliding_window() {
        let mut transfer = ActiveTransfer::new_receive(
            "file".into(),
            "s".into(),
            "r".into(),
            10,
            10000,
            1024,
            "fh".into(),
            (0..10).map(|i| (i, sha256_hex(&[i as u8]))).collect(),
            4, // Window size of 4
        );

        // Initially, window is fully available
        assert_eq!(transfer.available_window(), 4);
        assert!(transfer.can_send_chunk());
        assert_eq!(transfer.in_flight_count(), 0);

        // Mark chunks 0-3 as in-flight
        transfer.mark_in_flight(0);
        transfer.mark_in_flight(1);
        transfer.mark_in_flight(2);
        transfer.mark_in_flight(3);

        assert_eq!(transfer.in_flight_count(), 4);
        assert_eq!(transfer.available_window(), 0);
        assert!(!transfer.can_send_chunk()); // Window is full

        // Validate chunk 0 (removes from in-flight)
        transfer.validate_chunk(0, &[0u8]);
        assert_eq!(transfer.in_flight_count(), 3);
        assert_eq!(transfer.available_window(), 1);
        assert!(transfer.can_send_chunk()); // Window has room

        // Mark chunk 4 as in-flight
        transfer.mark_in_flight(4);
        assert_eq!(transfer.in_flight_count(), 4);
        assert!(!transfer.can_send_chunk()); // Window is full again

        // Acknowledge chunks 1 and 2
        transfer.mark_acked(1);
        transfer.mark_acked(2);
        assert_eq!(transfer.in_flight_count(), 2);
        assert_eq!(transfer.available_window(), 2);
    }
}
