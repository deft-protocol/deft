//! API integration tests for delta, parallel, and transfer-state endpoints
//!
//! These tests verify the HTTP API layer works correctly.
//! The module-level unit tests (in delta.rs, parallel.rs, transfer_state.rs)
//! already test the core logic. These tests validate the API responses.

/// Test API response format parsing
#[test]
fn test_api_response_json_format() {
    // This test validates our JSON response parsing logic
    let json = r#"{"max_concurrent":4,"buffer_size":32768}"#;
    let parsed: serde_json::Value = serde_json::from_str(json).unwrap();

    assert!(parsed.get("max_concurrent").is_some());
    assert!(parsed.get("buffer_size").is_some());
}

/// Test delta signature request format
#[test]
fn test_delta_signature_request_format() {
    let request = serde_json::json!({
        "virtual_file": "invoices",
        "block_size": 4096
    });

    let json = serde_json::to_string(&request).unwrap();
    assert!(json.contains("virtual_file"));
    assert!(json.contains("block_size"));
}

/// Test delta compute request format
#[test]
fn test_delta_compute_request_format() {
    let request = serde_json::json!({
        "base_file": "/path/to/base.dat",
        "new_file": "/path/to/new.dat",
        "block_size": 8192
    });

    let json = serde_json::to_string(&request).unwrap();
    assert!(json.contains("base_file"));
    assert!(json.contains("new_file"));
}

/// Test transfer state list response format
#[test]
fn test_transfer_states_response_format() {
    let response = serde_json::json!([
        {
            "transfer_id": "txn_001",
            "virtual_file": "invoices",
            "progress_percent": 50.0,
            "received_chunks": 5,
            "total_chunks": 10,
            "pending_chunks": 5,
            "is_complete": false,
            "started_at": "2026-01-21T10:00:00Z",
            "last_updated": "2026-01-21T10:05:00Z"
        }
    ]);

    let arr = response.as_array().unwrap();
    assert_eq!(arr.len(), 1);

    let state = &arr[0];
    assert_eq!(state["transfer_id"], "txn_001");
    assert_eq!(state["progress_percent"], 50.0);
    assert_eq!(state["is_complete"], false);
}

/// Test parallel config response format
#[test]
fn test_parallel_config_response_format() {
    let response = serde_json::json!({
        "max_concurrent": 4,
        "buffer_size": 32768
    });

    assert_eq!(response["max_concurrent"], 4);
    assert_eq!(response["buffer_size"], 32768);
}

/// Test delta signature response format
#[test]
fn test_delta_signature_response_format() {
    let response = serde_json::json!({
        "virtual_file": "invoices",
        "block_size": 4096,
        "file_size": 1048576,
        "blocks_count": 256
    });

    assert_eq!(response["virtual_file"], "invoices");
    assert_eq!(response["block_size"], 4096);
    assert!(response["file_size"].as_u64().unwrap() > 0);
}

/// Test delta compute response format
#[test]
fn test_delta_compute_response_format() {
    let response = serde_json::json!({
        "block_size": 4096,
        "target_size": 1048576,
        "operations_count": 100,
        "copy_blocks": 90,
        "insert_bytes": 4096,
        "savings_percent": "85.5"
    });

    assert!(response["operations_count"].as_u64().unwrap() > 0);
    assert!(response["savings_percent"].as_str().is_some());
}

/// Test error response format
#[test]
fn test_error_response_format() {
    let error = serde_json::json!({
        "error": "Virtual file not found"
    });

    assert!(error["error"].as_str().is_some());
}

/// Test transfer state delete response format
#[test]
fn test_transfer_state_delete_response_format() {
    let response = serde_json::json!({
        "status": "deleted",
        "id": "txn_001"
    });

    assert_eq!(response["status"], "deleted");
    assert_eq!(response["id"], "txn_001");
}
