# 🔌 Hooks & Plugins

Execute custom scripts on transfer events for automation and integration.

## Overview

RIFT hooks allow you to:
- Send notifications on transfer completion
- Trigger downstream processing
- Log to external systems
- Validate files before/after transfer
- Integrate with existing workflows

---

## Configuration

Add hooks to your `config.toml`:

```toml
[[hooks]]
event = "post_transfer"
command = "/scripts/notify.sh"
timeout_seconds = 30
blocking = false
partners = []           # Empty = all partners
virtual_files = []      # Empty = all files
```

### Hook Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `event` | string | required | Event to trigger on |
| `command` | string | required | Command or script to execute |
| `cwd` | string | none | Working directory |
| `timeout_seconds` | integer | `30` | Execution timeout |
| `blocking` | bool | `false` | Wait for completion before continuing |
| `partners` | array | `[]` | Filter by partner IDs (empty = all) |
| `virtual_files` | array | `[]` | Filter by virtual file names (empty = all) |

---

## Events

| Event | When | Use Case |
|-------|------|----------|
| `pre_transfer` | Before transfer starts | Validation, preparation |
| `post_transfer` | After successful transfer | Notification, processing |
| `transfer_error` | When transfer fails | Alerting, retry logic |
| `file_received` | After file fully received | Processing incoming files |
| `file_sent` | After file fully sent | Cleanup, confirmation |
| `connect` | New connection established | Logging, monitoring |
| `disconnect` | Connection closed | Cleanup |

---

## Environment Variables

Your script receives context via environment variables:

| Variable | Description | Example |
|----------|-------------|---------|
| `RIFT_EVENT` | Event type | `post_transfer` |
| `RIFT_TIMESTAMP` | ISO 8601 timestamp | `2026-01-20T12:00:00Z` |
| `RIFT_TRANSFER_ID` | Transfer identifier | `tx-abc123` |
| `RIFT_PARTNER_ID` | Partner identifier | `acme-corp` |
| `RIFT_VIRTUAL_FILE` | Virtual file name | `daily-orders` |
| `RIFT_LOCAL_PATH` | Local file path | `/data/orders/order.xml` |
| `RIFT_FILE_SIZE` | File size in bytes | `1048576` |
| `RIFT_CHUNKS` | Number of chunks | `4` |
| `RIFT_ERROR` | Error message (if failed) | `Connection timeout` |
| `RIFT_REMOTE_ADDR` | Remote address | `192.168.1.100:54321` |
| `RIFT_CONTEXT_JSON` | Full context as JSON | `{"event":"post_transfer",...}` |

---

## Examples

### 1. Email Notification

```bash
#!/bin/bash
# /scripts/notify-email.sh

if [ "$RIFT_EVENT" = "post_transfer" ]; then
    mail -s "RIFT: Transfer completed" admin@company.com <<EOF
Transfer completed successfully!

Partner: $RIFT_PARTNER_ID
File: $RIFT_VIRTUAL_FILE
Size: $RIFT_FILE_SIZE bytes
Time: $RIFT_TIMESTAMP
EOF
fi
```

```toml
[[hooks]]
event = "post_transfer"
command = "/scripts/notify-email.sh"
```

### 2. Slack Notification

```bash
#!/bin/bash
# /scripts/notify-slack.sh

WEBHOOK_URL="https://hooks.slack.com/services/XXX/YYY/ZZZ"

if [ "$RIFT_EVENT" = "post_transfer" ]; then
    curl -X POST -H 'Content-type: application/json' \
        --data "{\"text\":\"✅ Transfer completed: $RIFT_VIRTUAL_FILE from $RIFT_PARTNER_ID ($RIFT_FILE_SIZE bytes)\"}" \
        "$WEBHOOK_URL"
elif [ "$RIFT_EVENT" = "transfer_error" ]; then
    curl -X POST -H 'Content-type: application/json' \
        --data "{\"text\":\"❌ Transfer failed: $RIFT_VIRTUAL_FILE - $RIFT_ERROR\"}" \
        "$WEBHOOK_URL"
fi
```

```toml
[[hooks]]
event = "post_transfer"
command = "/scripts/notify-slack.sh"

[[hooks]]
event = "transfer_error"
command = "/scripts/notify-slack.sh"
```

### 3. File Processing

```bash
#!/bin/bash
# /scripts/process-invoice.sh

if [ "$RIFT_EVENT" = "file_received" ]; then
    # Parse XML invoice
    INVOICE_NUM=$(xmllint --xpath "//InvoiceNumber/text()" "$RIFT_LOCAL_PATH")
    
    # Insert into database
    psql -c "INSERT INTO invoices (number, partner, received_at, file_path) 
             VALUES ('$INVOICE_NUM', '$RIFT_PARTNER_ID', NOW(), '$RIFT_LOCAL_PATH')"
    
    # Move to processed folder
    mv "$RIFT_LOCAL_PATH" /data/invoices/processed/
fi
```

```toml
[[hooks]]
event = "file_received"
command = "/scripts/process-invoice.sh"
partners = ["acme-corp"]
virtual_files = ["invoices"]
```

### 4. Validation Hook (Blocking)

```bash
#!/bin/bash
# /scripts/validate-order.sh

# Blocking hook - exit code determines if transfer proceeds

if [ "$RIFT_EVENT" = "pre_transfer" ]; then
    # Check file exists
    if [ ! -f "$RIFT_LOCAL_PATH" ]; then
        echo "File not found: $RIFT_LOCAL_PATH" >&2
        exit 1
    fi
    
    # Validate XML
    if ! xmllint --noout "$RIFT_LOCAL_PATH" 2>/dev/null; then
        echo "Invalid XML: $RIFT_LOCAL_PATH" >&2
        exit 1
    fi
    
    # Check file size
    SIZE=$(stat -f%z "$RIFT_LOCAL_PATH" 2>/dev/null || stat -c%s "$RIFT_LOCAL_PATH")
    if [ "$SIZE" -gt 104857600 ]; then  # 100MB limit
        echo "File too large: $SIZE bytes" >&2
        exit 1
    fi
    
    echo "Validation passed"
    exit 0
fi
```

```toml
[[hooks]]
event = "pre_transfer"
command = "/scripts/validate-order.sh"
blocking = true
timeout_seconds = 10
```

### 5. Cleanup Hook

```bash
#!/bin/bash
# /scripts/cleanup.sh

if [ "$RIFT_EVENT" = "file_sent" ]; then
    # Archive the sent file
    ARCHIVE_DIR="/data/archive/$(date +%Y/%m/%d)"
    mkdir -p "$ARCHIVE_DIR"
    
    # Move with timestamp
    BASENAME=$(basename "$RIFT_LOCAL_PATH")
    mv "$RIFT_LOCAL_PATH" "$ARCHIVE_DIR/${RIFT_TIMESTAMP}_${BASENAME}"
    
    echo "Archived to $ARCHIVE_DIR"
fi
```

```toml
[[hooks]]
event = "file_sent"
command = "/scripts/cleanup.sh"
```

### 6. Logging to External System

```python
#!/usr/bin/env python3
# /scripts/log-to-elk.py

import os
import json
import requests

context = json.loads(os.environ.get('RIFT_CONTEXT_JSON', '{}'))

log_entry = {
    '@timestamp': context.get('timestamp'),
    'event': context.get('event'),
    'partner': context.get('partner_id'),
    'virtual_file': context.get('virtual_file'),
    'file_size': context.get('file_size'),
    'transfer_id': context.get('transfer_id'),
}

# Send to Elasticsearch
requests.post(
    'http://elasticsearch:9200/rift-logs/_doc',
    json=log_entry,
    headers={'Content-Type': 'application/json'}
)
```

```toml
[[hooks]]
event = "post_transfer"
command = "python3 /scripts/log-to-elk.py"
```

---

## JSON Context

The `RIFT_CONTEXT_JSON` variable contains all context:

```json
{
  "event": "post_transfer",
  "timestamp": "2026-01-20T12:00:00Z",
  "transfer_id": "tx-abc123",
  "partner_id": "acme-corp",
  "virtual_file": "daily-orders",
  "local_path": "/data/orders/order-001.xml",
  "file_size": 1048576,
  "chunks": 4
}
```

Parse in your script:

```bash
# Bash with jq
PARTNER=$(echo "$RIFT_CONTEXT_JSON" | jq -r '.partner_id')

# Python
import os, json
ctx = json.loads(os.environ['RIFT_CONTEXT_JSON'])
```

---

## Best Practices

### 1. Keep Hooks Fast

```bash
# Bad - blocks transfer
sleep 60
send_email

# Good - run in background
send_email &
```

### 2. Handle Errors Gracefully

```bash
#!/bin/bash
set -e  # Exit on error

# Wrap in try-catch equivalent
{
    process_file "$RIFT_LOCAL_PATH"
} || {
    echo "Processing failed, but continuing" >&2
    exit 0  # Don't fail the transfer
}
```

### 3. Use Filters

```toml
# Only for specific partners
[[hooks]]
event = "post_transfer"
command = "/scripts/acme-notify.sh"
partners = ["acme-corp"]

# Only for specific files
[[hooks]]
event = "file_received"
command = "/scripts/process-invoices.sh"
virtual_files = ["invoices", "credit-notes"]
```

### 4. Log Hook Output

```bash
#!/bin/bash
exec >> /var/log/rift/hooks.log 2>&1
echo "$(date) - $RIFT_EVENT for $RIFT_VIRTUAL_FILE"
# ... rest of script
```

### 5. Test Hooks Manually

```bash
# Simulate hook execution
export RIFT_EVENT="post_transfer"
export RIFT_PARTNER_ID="test-partner"
export RIFT_VIRTUAL_FILE="test-file"
export RIFT_LOCAL_PATH="/tmp/test.txt"
export RIFT_FILE_SIZE="1024"

/scripts/my-hook.sh
echo "Exit code: $?"
```

---

## Troubleshooting

### Hook Not Executing

1. Check script is executable: `chmod +x /scripts/hook.sh`
2. Verify path is absolute
3. Check logs: `journalctl -u rift | grep hook`

### Hook Timing Out

```toml
# Increase timeout
[[hooks]]
event = "post_transfer"
command = "/scripts/slow-script.sh"
timeout_seconds = 120
```

### Hook Failing Silently

Add logging to your script:

```bash
#!/bin/bash
exec 2>&1 | tee -a /var/log/rift/hook-debug.log
set -x  # Debug mode
```

---

## See Also

- [Configuration](CONFIGURATION.md) - Full config reference
- [API Reference](API.md) - REST API for monitoring
- [Getting Started](GETTING_STARTED.md) - Initial setup
