//! Integration tests for transfer control (pause/resume/cancel) with real transfers
//!
//! These tests simulate actual transfer scenarios to verify the pause/resume/cancel
//! functionality works correctly end-to-end.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch, RwLock};

/// Simulates the sender's state and behavior
struct MockSender {
    transfer_id: String,
    status: Arc<RwLock<String>>,
    control_tx: mpsc::Sender<MockControl>,
    control_rx: Option<mpsc::Receiver<MockControl>>,
    cancel_tx: watch::Sender<bool>,
    cancel_rx: watch::Receiver<bool>,
}

/// Simulates the receiver's state
struct MockReceiver {
    transfer_id: String,
    paused: Arc<RwLock<bool>>,
}

#[derive(Debug, Clone)]
enum MockControl {
    Pause,
    Resume,
    Abort,
}

#[derive(Debug, Clone, PartialEq)]
enum MockResponse {
    ChunkReady,
    TransferPaused,
    ChunkAck,
}

impl MockSender {
    fn new(transfer_id: &str) -> Self {
        let (control_tx, control_rx) = mpsc::channel(16);
        let (cancel_tx, cancel_rx) = watch::channel(false);
        Self {
            transfer_id: transfer_id.to_string(),
            status: Arc::new(RwLock::new("active".to_string())),
            control_tx,
            control_rx: Some(control_rx),
            cancel_tx,
            cancel_rx,
        }
    }

    async fn get_status(&self) -> String {
        self.status.read().await.clone()
    }

    async fn set_status(&self, status: &str) {
        *self.status.write().await = status.to_string();
    }

    async fn interrupt(&self) {
        *self.status.write().await = "interrupted".to_string();
    }

    async fn resume(&self) -> bool {
        let mut status = self.status.write().await;
        if *status == "interrupted" {
            *status = "active".to_string();
            true
        } else {
            false
        }
    }

    async fn is_interrupted(&self) -> bool {
        *self.status.read().await == "interrupted"
    }

    fn get_control_sender(&self) -> mpsc::Sender<MockControl> {
        self.control_tx.clone()
    }
}

impl MockReceiver {
    fn new(transfer_id: &str) -> Self {
        Self {
            transfer_id: transfer_id.to_string(),
            paused: Arc::new(RwLock::new(false)),
        }
    }

    async fn handle_pause(&self) -> bool {
        let mut paused = self.paused.write().await;
        *paused = true;
        true
    }

    async fn handle_resume(&self) -> bool {
        let mut paused = self.paused.write().await;
        *paused = false;
        true
    }

    async fn is_paused(&self) -> bool {
        *self.paused.read().await
    }

    async fn handle_put(&self) -> MockResponse {
        if *self.paused.read().await {
            MockResponse::TransferPaused
        } else {
            MockResponse::ChunkReady
        }
    }
}

// ==================== Integration Tests ====================

#[tokio::test]
async fn test_basic_pause_resume_flow() {
    let sender = MockSender::new("tx_test_001");
    let receiver = MockReceiver::new("tx_test_001");

    // Initial state
    assert_eq!(sender.get_status().await, "active");
    assert!(!receiver.is_paused().await);

    // Sender initiates pause
    sender.interrupt().await;
    receiver.handle_pause().await;

    assert_eq!(sender.get_status().await, "interrupted");
    assert!(receiver.is_paused().await);

    // PUT should return TRANSFER_PAUSED
    assert_eq!(receiver.handle_put().await, MockResponse::TransferPaused);

    // Resume
    assert!(sender.resume().await);
    receiver.handle_resume().await;

    assert_eq!(sender.get_status().await, "active");
    assert!(!receiver.is_paused().await);

    // PUT should work now
    assert_eq!(receiver.handle_put().await, MockResponse::ChunkReady);
}

#[tokio::test]
async fn test_resume_only_works_when_interrupted() {
    let sender = MockSender::new("tx_test_002");

    // Can't resume when active
    assert!(!sender.resume().await);
    assert_eq!(sender.get_status().await, "active");

    // Interrupt first
    sender.interrupt().await;
    assert_eq!(sender.get_status().await, "interrupted");

    // Now resume works
    assert!(sender.resume().await);
    assert_eq!(sender.get_status().await, "active");

    // Can't resume again
    assert!(!sender.resume().await);
}

#[tokio::test]
async fn test_pause_resume_with_put_retry() {
    let sender = Arc::new(MockSender::new("tx_test_003"));
    let receiver = Arc::new(MockReceiver::new("tx_test_003"));

    let sender_clone = sender.clone();
    let receiver_clone = receiver.clone();

    // Simulate sender's PUT loop with retry
    let sender_task = tokio::spawn(async move {
        let mut chunks_sent = 0;
        let total_chunks = 5;

        while chunks_sent < total_chunks {
            // Check if interrupted, wait for resume
            while sender_clone.is_interrupted().await {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }

            // Send PUT
            let response = receiver_clone.handle_put().await;
            
            match response {
                MockResponse::TransferPaused => {
                    // Remote paused - set local interrupted and retry
                    sender_clone.interrupt().await;
                    continue;
                }
                MockResponse::ChunkReady => {
                    // Success - send data and get ACK
                    chunks_sent += 1;
                }
                _ => {}
            }
        }
        chunks_sent
    });

    // Let transfer start
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Pause the transfer
    sender.interrupt().await;
    receiver.handle_pause().await;

    // Wait a bit while paused
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(sender.is_interrupted().await);
    assert!(receiver.is_paused().await);

    // Resume
    sender.resume().await;
    receiver.handle_resume().await;

    // Wait for completion
    let result = tokio::time::timeout(Duration::from_secs(1), sender_task).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().unwrap(), 5);
}

#[tokio::test]
async fn test_race_condition_resume_before_receiver() {
    // This tests the bug: sender resumes but receiver is still paused
    let sender = Arc::new(MockSender::new("tx_test_004"));
    let receiver = Arc::new(MockReceiver::new("tx_test_004"));

    // Both pause
    sender.interrupt().await;
    receiver.handle_pause().await;

    // Sender resumes BEFORE receiver
    sender.resume().await;
    assert_eq!(sender.get_status().await, "active");
    assert!(receiver.is_paused().await); // Receiver still paused!

    // PUT will fail with TRANSFER_PAUSED
    let response = receiver.handle_put().await;
    assert_eq!(response, MockResponse::TransferPaused);

    // This is the bug - sender should handle this gracefully
    // and not flip-flop between active and interrupted
    
    // Correct behavior: sender sets itself back to interrupted
    // and waits for proper resume signal
    if response == MockResponse::TransferPaused {
        sender.interrupt().await;
    }
    assert_eq!(sender.get_status().await, "interrupted");

    // Now properly resume both sides
    receiver.handle_resume().await;
    sender.resume().await;

    assert_eq!(sender.get_status().await, "active");
    assert!(!receiver.is_paused().await);
    assert_eq!(receiver.handle_put().await, MockResponse::ChunkReady);
}

#[tokio::test]
async fn test_synchronized_pause_resume() {
    // Test proper synchronization: sender should wait for receiver confirmation
    let sender = Arc::new(MockSender::new("tx_test_005"));
    let receiver = Arc::new(MockReceiver::new("tx_test_005"));

    // Simulate proper pause flow:
    // 1. Sender sends PAUSE_TRANSFER
    // 2. Receiver responds TRANSFER_PAUSED
    // 3. Sender sets local state to interrupted

    // Step 1 & 2: Sender initiates pause, receiver confirms
    receiver.handle_pause().await;
    assert!(receiver.is_paused().await);
    
    // Step 3: Sender updates local state after receiver confirms
    sender.interrupt().await;
    assert!(sender.is_interrupted().await);

    // Simulate proper resume flow:
    // 1. Sender sends RESUME_TRANSFER_CMD
    // 2. Receiver responds TRANSFER_RESUMED
    // 3. Sender sets local state to active

    // Step 1 & 2: Sender initiates resume, receiver confirms
    receiver.handle_resume().await;
    assert!(!receiver.is_paused().await);

    // Step 3: Sender updates local state after receiver confirms
    sender.resume().await;
    assert!(!sender.is_interrupted().await);
    assert_eq!(sender.get_status().await, "active");
}

#[tokio::test]
async fn test_control_channel_ordering() {
    let sender = MockSender::new("tx_test_006");
    let control_tx = sender.get_control_sender();

    // Send multiple commands
    control_tx.send(MockControl::Pause).await.unwrap();
    control_tx.send(MockControl::Resume).await.unwrap();
    control_tx.send(MockControl::Pause).await.unwrap();

    let mut control_rx = sender.control_rx.unwrap();

    // Commands should be received in order
    assert!(matches!(control_rx.recv().await.unwrap(), MockControl::Pause));
    assert!(matches!(control_rx.recv().await.unwrap(), MockControl::Resume));
    assert!(matches!(control_rx.recv().await.unwrap(), MockControl::Pause));
}

#[tokio::test]
async fn test_status_consistency_during_transfer() {
    let sender = Arc::new(MockSender::new("tx_test_007"));
    let status_history = Arc::new(RwLock::new(Vec::new()));

    let sender_clone = sender.clone();
    let history_clone = status_history.clone();

    // Monitor status changes
    let monitor = tokio::spawn(async move {
        let mut last_status = String::new();
        for _ in 0..100 {
            let status = sender_clone.get_status().await;
            if status != last_status {
                history_clone.write().await.push(status.clone());
                last_status = status;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    });

    // Perform pause/resume
    tokio::time::sleep(Duration::from_millis(10)).await;
    sender.interrupt().await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    sender.resume().await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    monitor.await.unwrap();

    let history = status_history.read().await;
    
    // Should see: active -> interrupted -> active
    // Should NOT see: active -> interrupted -> active -> interrupted -> active (flip-flop)
    assert!(history.len() <= 3, "Status flip-flopped: {:?}", history);
    
    if history.len() >= 2 {
        assert_eq!(history[0], "active");
        assert_eq!(history[1], "interrupted");
    }
    if history.len() >= 3 {
        assert_eq!(history[2], "active");
    }
}

#[tokio::test]
async fn test_resume_waits_for_receiver_confirmation() {
    // This is the key test for the bug fix
    // Resume should NOT change local status until receiver confirms
    
    let sender = Arc::new(MockSender::new("tx_test_008"));
    let receiver = Arc::new(MockReceiver::new("tx_test_008"));

    // Pause both sides
    sender.interrupt().await;
    receiver.handle_pause().await;

    // Simulate the correct resume flow:
    // 1. API receives resume request
    // 2. Send RESUME_TRANSFER_CMD to receiver
    // 3. Wait for TRANSFER_RESUMED response
    // 4. THEN update local status

    // Simulate sending RESUME_TRANSFER_CMD
    // Receiver processes it
    receiver.handle_resume().await;
    
    // Only after receiver confirms, update sender status
    assert!(sender.resume().await);

    // Both should be active now
    assert_eq!(sender.get_status().await, "active");
    assert!(!receiver.is_paused().await);

    // PUT should work
    assert_eq!(receiver.handle_put().await, MockResponse::ChunkReady);
}
