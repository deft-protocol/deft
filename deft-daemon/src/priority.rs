//! Transfer priority queue (M2)
//!
//! Provides priority-based transfer scheduling with three levels:
//! - Urgent: Processed immediately
//! - Normal: Standard FIFO order
//! - Batch: Processed when no higher priority transfers are pending

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

/// Transfer priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransferPriority {
    /// Highest priority - processed immediately
    Urgent = 0,
    /// Normal priority - standard FIFO
    Normal = 1,
    /// Lowest priority - processed when idle
    Batch = 2,
}

impl Default for TransferPriority {
    fn default() -> Self {
        Self::Normal
    }
}

impl std::str::FromStr for TransferPriority {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "urgent" | "high" | "0" => Ok(Self::Urgent),
            "normal" | "medium" | "1" => Ok(Self::Normal),
            "batch" | "low" | "2" => Ok(Self::Batch),
            _ => Err(format!("Unknown priority: {}", s)),
        }
    }
}

impl std::fmt::Display for TransferPriority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Urgent => write!(f, "urgent"),
            Self::Normal => write!(f, "normal"),
            Self::Batch => write!(f, "batch"),
        }
    }
}

/// A queued transfer request
#[derive(Debug, Clone)]
pub struct QueuedTransfer {
    pub id: String,
    pub virtual_file: String,
    pub partner_id: String,
    pub file_path: Option<String>,
    pub priority: TransferPriority,
    pub queued_at: Instant,
    pub direction: TransferDirection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDirection {
    Push,
    Pull,
}

impl Eq for QueuedTransfer {}

impl PartialEq for QueuedTransfer {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Ord for QueuedTransfer {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher priority (lower number) comes first
        // If same priority, earlier queued time comes first
        match (self.priority as u8).cmp(&(other.priority as u8)) {
            Ordering::Equal => other.queued_at.cmp(&self.queued_at), // Reverse for min-heap behavior
            ord => ord.reverse(), // Reverse because BinaryHeap is max-heap
        }
    }
}

impl PartialOrd for QueuedTransfer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Priority queue for transfers
pub struct TransferQueue {
    queue: Arc<Mutex<BinaryHeap<QueuedTransfer>>>,
    max_size: usize,
    next_id: Arc<Mutex<u64>>,
}

impl TransferQueue {
    pub fn new(max_size: usize) -> Self {
        Self {
            queue: Arc::new(Mutex::new(BinaryHeap::new())),
            max_size,
            next_id: Arc::new(Mutex::new(0)),
        }
    }

    /// Generate a unique transfer ID
    async fn generate_id(&self) -> String {
        let mut id = self.next_id.lock().await;
        *id += 1;
        format!("txn_queue_{}", *id)
    }

    /// Enqueue a new transfer request
    pub async fn enqueue(
        &self,
        virtual_file: String,
        partner_id: String,
        file_path: Option<String>,
        priority: TransferPriority,
        direction: TransferDirection,
    ) -> Result<String, String> {
        let mut queue = self.queue.lock().await;
        
        if queue.len() >= self.max_size {
            return Err("Transfer queue is full".to_string());
        }

        let id = self.generate_id().await;
        let transfer = QueuedTransfer {
            id: id.clone(),
            virtual_file,
            partner_id,
            file_path,
            priority,
            queued_at: Instant::now(),
            direction,
        };

        queue.push(transfer);
        Ok(id)
    }

    /// Dequeue the highest priority transfer
    pub async fn dequeue(&self) -> Option<QueuedTransfer> {
        self.queue.lock().await.pop()
    }

    /// Peek at the highest priority transfer without removing it
    pub async fn peek(&self) -> Option<QueuedTransfer> {
        self.queue.lock().await.peek().cloned()
    }

    /// Get queue length
    pub async fn len(&self) -> usize {
        self.queue.lock().await.len()
    }

    /// Check if queue is empty
    pub async fn is_empty(&self) -> bool {
        self.queue.lock().await.is_empty()
    }

    /// Get all queued transfers (sorted by priority)
    pub async fn list(&self) -> Vec<QueuedTransfer> {
        let queue = self.queue.lock().await;
        let mut items: Vec<_> = queue.iter().cloned().collect();
        items.sort_by(|a, b| a.cmp(b).reverse());
        items
    }

    /// Remove a specific transfer by ID
    pub async fn remove(&self, id: &str) -> Option<QueuedTransfer> {
        let mut queue = self.queue.lock().await;
        let items: Vec<_> = queue.drain().collect();
        let mut removed = None;
        
        for item in items {
            if item.id == id {
                removed = Some(item);
            } else {
                queue.push(item);
            }
        }
        
        removed
    }

    /// Update priority of a queued transfer
    pub async fn update_priority(&self, id: &str, new_priority: TransferPriority) -> bool {
        let mut queue = self.queue.lock().await;
        let items: Vec<_> = queue.drain().collect();
        let mut found = false;
        
        for mut item in items {
            if item.id == id {
                item.priority = new_priority;
                found = true;
            }
            queue.push(item);
        }
        
        found
    }

    /// Get counts by priority
    pub async fn counts_by_priority(&self) -> (usize, usize, usize) {
        let queue = self.queue.lock().await;
        let mut urgent = 0;
        let mut normal = 0;
        let mut batch = 0;
        
        for item in queue.iter() {
            match item.priority {
                TransferPriority::Urgent => urgent += 1,
                TransferPriority::Normal => normal += 1,
                TransferPriority::Batch => batch += 1,
            }
        }
        
        (urgent, normal, batch)
    }
}

impl Default for TransferQueue {
    fn default() -> Self {
        Self::new(1000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_priority_ordering() {
        let queue = TransferQueue::new(100);

        // Add transfers in random order
        queue.enqueue("file1".into(), "p1".into(), None, TransferPriority::Batch, TransferDirection::Push).await.unwrap();
        queue.enqueue("file2".into(), "p2".into(), None, TransferPriority::Urgent, TransferDirection::Push).await.unwrap();
        queue.enqueue("file3".into(), "p3".into(), None, TransferPriority::Normal, TransferDirection::Push).await.unwrap();

        // Should dequeue in priority order: Urgent, Normal, Batch
        let t1 = queue.dequeue().await.unwrap();
        assert_eq!(t1.priority, TransferPriority::Urgent);
        
        let t2 = queue.dequeue().await.unwrap();
        assert_eq!(t2.priority, TransferPriority::Normal);
        
        let t3 = queue.dequeue().await.unwrap();
        assert_eq!(t3.priority, TransferPriority::Batch);
    }

    #[tokio::test]
    async fn test_fifo_same_priority() {
        let queue = TransferQueue::new(100);

        queue.enqueue("first".into(), "p1".into(), None, TransferPriority::Normal, TransferDirection::Push).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        queue.enqueue("second".into(), "p2".into(), None, TransferPriority::Normal, TransferDirection::Push).await.unwrap();

        let t1 = queue.dequeue().await.unwrap();
        let t2 = queue.dequeue().await.unwrap();
        
        assert_eq!(t1.virtual_file, "first");
        assert_eq!(t2.virtual_file, "second");
    }

    #[tokio::test]
    async fn test_remove_transfer() {
        let queue = TransferQueue::new(100);

        let id1 = queue.enqueue("file1".into(), "p1".into(), None, TransferPriority::Normal, TransferDirection::Push).await.unwrap();
        let _id2 = queue.enqueue("file2".into(), "p2".into(), None, TransferPriority::Normal, TransferDirection::Push).await.unwrap();

        assert_eq!(queue.len().await, 2);
        
        let removed = queue.remove(&id1).await;
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().virtual_file, "file1");
        assert_eq!(queue.len().await, 1);
    }

    #[tokio::test]
    async fn test_update_priority() {
        let queue = TransferQueue::new(100);

        let id = queue.enqueue("file1".into(), "p1".into(), None, TransferPriority::Batch, TransferDirection::Push).await.unwrap();
        queue.enqueue("file2".into(), "p2".into(), None, TransferPriority::Normal, TransferDirection::Push).await.unwrap();

        // file2 should come first (Normal > Batch)
        let peek = queue.peek().await.unwrap();
        assert_eq!(peek.virtual_file, "file2");

        // Upgrade file1 to Urgent
        queue.update_priority(&id, TransferPriority::Urgent).await;

        // Now file1 should come first
        let peek = queue.peek().await.unwrap();
        assert_eq!(peek.virtual_file, "file1");
    }

    #[tokio::test]
    async fn test_queue_full() {
        let queue = TransferQueue::new(2);

        queue.enqueue("f1".into(), "p".into(), None, TransferPriority::Normal, TransferDirection::Push).await.unwrap();
        queue.enqueue("f2".into(), "p".into(), None, TransferPriority::Normal, TransferDirection::Push).await.unwrap();
        
        let result = queue.enqueue("f3".into(), "p".into(), None, TransferPriority::Normal, TransferDirection::Push).await;
        assert!(result.is_err());
    }
}
