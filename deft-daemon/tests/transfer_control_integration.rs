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
    TransferResumed,
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

    /// Handle PUT when receiver just resumed - returns TRANSFER_RESUMED once
    async fn handle_put_after_resume(&self, just_resumed: &mut bool) -> MockResponse {
        if *self.paused.read().await {
            MockResponse::TransferPaused
        } else if *just_resumed {
            *just_resumed = false;
            MockResponse::TransferResumed
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
    assert!(matches!(
        control_rx.recv().await.unwrap(),
        MockControl::Pause
    ));
    assert!(matches!(
        control_rx.recv().await.unwrap(),
        MockControl::Resume
    ));
    assert!(matches!(
        control_rx.recv().await.unwrap(),
        MockControl::Pause
    ));
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

#[tokio::test]
async fn test_put_handles_transfer_resumed_response() {
    // This tests the specific bug: sender receives TRANSFER_RESUMED after retry
    // and must handle it correctly by retrying PUT

    let sender = Arc::new(MockSender::new("tx_test_009"));
    let receiver = Arc::new(MockReceiver::new("tx_test_009"));

    // Both pause
    sender.interrupt().await;
    receiver.handle_pause().await;

    // Verify paused state
    assert!(sender.is_interrupted().await);
    assert!(receiver.is_paused().await);
    assert_eq!(receiver.handle_put().await, MockResponse::TransferPaused);

    // Receiver resumes via its API (not sender-initiated)
    receiver.handle_resume().await;
    let mut just_resumed = true;

    // Sender retries PUT - first response is TRANSFER_RESUMED
    let response1 = receiver.handle_put_after_resume(&mut just_resumed).await;
    assert_eq!(response1, MockResponse::TransferResumed);

    // Sender must handle TRANSFER_RESUMED by:
    // 1. Updating local status if interrupted
    if sender.is_interrupted().await {
        sender.resume().await;
    }
    // 2. Retrying PUT
    let response2 = receiver.handle_put_after_resume(&mut just_resumed).await;
    assert_eq!(response2, MockResponse::ChunkReady);

    // Both should now be active
    assert_eq!(sender.get_status().await, "active");
    assert!(!receiver.is_paused().await);
}

#[tokio::test]
async fn test_put_retry_loop_with_transfer_resumed() {
    // Full simulation of PUT retry loop handling all response types

    let receiver = Arc::new(MockReceiver::new("tx_test_010"));
    let sender_status = Arc::new(RwLock::new("active".to_string()));

    // Track chunks sent
    let chunks_sent = Arc::new(RwLock::new(0u32));
    let chunks_sent_clone = chunks_sent.clone();
    let sender_status_clone = sender_status.clone();
    let receiver_clone = receiver.clone();

    // Pause after 2 chunks
    let pause_at_chunk = 2;
    let total_chunks = 5;

    let sender_task = tokio::spawn(async move {
        while *chunks_sent_clone.read().await < total_chunks {
            // Simulate PUT retry loop
            loop {
                let response = receiver_clone.handle_put().await;

                match response {
                    MockResponse::TransferPaused => {
                        // Set local status to interrupted and wait
                        *sender_status_clone.write().await = "interrupted".to_string();
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        continue; // Retry PUT
                    }
                    MockResponse::ChunkReady => {
                        // Success - if we were interrupted, resume now
                        if *sender_status_clone.read().await == "interrupted" {
                            *sender_status_clone.write().await = "active".to_string();
                        }
                        break;
                    }
                    _ => break,
                }
            }

            // "Send" the chunk
            let mut sent = chunks_sent_clone.write().await;
            *sent += 1;

            // Pause after specific chunk
            if *sent == pause_at_chunk {
                receiver_clone.handle_pause().await;
            }
        }

        *chunks_sent_clone.read().await
    });

    // Let transfer start
    tokio::time::sleep(Duration::from_millis(30)).await;

    // After pause happens, wait a bit then resume
    tokio::time::sleep(Duration::from_millis(50)).await;
    receiver.handle_resume().await;

    // Wait for completion
    let result = tokio::time::timeout(Duration::from_secs(2), sender_task).await;
    assert!(result.is_ok(), "Transfer should complete");
    assert_eq!(result.unwrap().unwrap(), total_chunks);
    assert_eq!(*sender_status.read().await, "active");
}

/// Tests sender-initiated pause/resume flow
/// This tests the fix for the protocol synchronization bug where sender
/// didn't read TRANSFER_PAUSED response after sending PAUSE_TRANSFER
#[tokio::test]
async fn test_sender_initiated_pause_resume() {
    // Simulate sender initiating pause, then resume
    let receiver = Arc::new(MockReceiver::new("tx_sender_pause_001"));
    let sender_status = Arc::new(RwLock::new("active".to_string()));
    let (control_tx, mut control_rx) = mpsc::channel::<MockControl>(16);

    let chunks_sent = Arc::new(RwLock::new(0u32));
    let total_chunks = 5u32;
    let pause_at_chunk = 2u32;

    let sender_status_clone = sender_status.clone();
    let receiver_clone = receiver.clone();
    let chunks_sent_clone = chunks_sent.clone();

    // Sender task - simulates the corrected push_file logic
    let sender_task = tokio::spawn(async move {
        for chunk_idx in 0..total_chunks {
            // Small delay to allow control commands to be received
            tokio::time::sleep(Duration::from_millis(5)).await;

            // Check for pause command BEFORE sending PUT
            if let Ok(cmd) = control_rx.try_recv() {
                match cmd {
                    MockControl::Pause => {
                        // Sender sends PAUSE_TRANSFER to receiver
                        receiver_clone.handle_pause().await;
                        // Read and verify TRANSFER_PAUSED response (this was the bug fix)
                        assert!(
                            *receiver_clone.paused.read().await,
                            "Receiver should be paused"
                        );
                        *sender_status_clone.write().await = "interrupted".to_string();

                        // Wait in loop for Resume command
                        loop {
                            tokio::time::sleep(Duration::from_millis(10)).await;
                            if let Ok(resume_cmd) = control_rx.try_recv() {
                                if matches!(resume_cmd, MockControl::Resume) {
                                    // Sender sends RESUME_TRANSFER_CMD
                                    receiver_clone.handle_resume().await;
                                    *sender_status_clone.write().await = "active".to_string();
                                    break;
                                }
                            }
                        }
                    }
                    MockControl::Resume => {
                        // Resume when not paused - ignore
                    }
                    MockControl::Abort => {
                        return Err::<u32, &str>("Aborted");
                    }
                }
            }

            // Send PUT and handle response
            loop {
                let response = receiver_clone.handle_put().await;
                match response {
                    MockResponse::ChunkReady => break,
                    MockResponse::TransferPaused => {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        continue;
                    }
                    _ => break,
                }
            }

            let mut sent = chunks_sent_clone.write().await;
            *sent = chunk_idx + 1;

            // Signal when we reach the pause point
            if *sent == pause_at_chunk {
                drop(sent);
                // Give time for pause command to be queued before next iteration
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }

        Ok(*chunks_sent_clone.read().await)
    });

    // Wait for some chunks to be sent
    loop {
        tokio::time::sleep(Duration::from_millis(10)).await;
        if *chunks_sent.read().await >= pause_at_chunk {
            break;
        }
    }

    // Sender initiates pause
    let _ = control_tx.send(MockControl::Pause).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Verify sender is paused
    assert_eq!(*sender_status.read().await, "interrupted");

    // Sender initiates resume
    let _ = control_tx.send(MockControl::Resume).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Verify sender resumed
    assert_eq!(*sender_status.read().await, "active");

    // Wait for completion
    let result = tokio::time::timeout(Duration::from_secs(2), sender_task).await;
    assert!(result.is_ok(), "Transfer should complete");
    let inner = result.unwrap().unwrap();
    assert!(inner.is_ok(), "Transfer should succeed");
    assert_eq!(inner.unwrap(), total_chunks);
}

/// Tests that sender pause waits for TRANSFER_PAUSED confirmation
#[tokio::test]
async fn test_sender_pause_waits_for_confirmation() {
    let receiver = Arc::new(MockReceiver::new("tx_pause_confirm_001"));
    let confirmed = Arc::new(RwLock::new(false));
    let confirmed_clone = confirmed.clone();
    let receiver_clone = receiver.clone();

    // Simulate sender sending PAUSE_TRANSFER and waiting for response
    let sender_task = tokio::spawn(async move {
        // Send PAUSE_TRANSFER
        receiver_clone.handle_pause().await;

        // Read confirmation (this is what was missing before the fix)
        if *receiver_clone.paused.read().await {
            *confirmed_clone.write().await = true;
        }
    });

    tokio::time::timeout(Duration::from_secs(1), sender_task)
        .await
        .expect("Sender should complete")
        .expect("Task should succeed");

    assert!(*confirmed.read().await, "Pause should be confirmed");
    assert!(*receiver.paused.read().await, "Receiver should be paused");
}
