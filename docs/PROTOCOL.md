# 📡 RIFT Protocol Specification

Technical specification of the RIFT wire protocol.

## Overview

RIFT (Reliable Interoperable File Transfer) is a text-based protocol over TLS for secure B2B file transfers.

- **Transport**: TCP + TLS 1.3 (mTLS required)
- **Default Port**: 7741
- **Encoding**: UTF-8 for commands, binary for data
- **Line Ending**: `\r\n`

---

## Connection Flow

```
┌─────────┐                      ┌─────────┐
│  Client │                      │  Server │
└────┬────┘                      └────┬────┘
     │                                │
     │──── TCP Connect ──────────────>│
     │<─── TCP Accept ────────────────│
     │                                │
     │──── TLS Handshake (mTLS) ─────>│
     │<─── TLS Established ───────────│
     │                                │
     │──── RIFT HELLO 1.0 ... ───────>│
     │<─── RIFT WELCOME 1.0 ... ──────│
     │                                │
     │──── RIFT AUTH partner-id ─────>│
     │<─── RIFT AUTH_OK ... ──────────│
     │                                │
     │     [Session Established]      │
     │                                │
     │──── Commands... ──────────────>│
     │<─── Responses... ──────────────│
     │                                │
     │──── RIFT BYE ─────────────────>│
     │<─── RIFT GOODBYE ──────────────│
     │                                │
     └────────────────────────────────┘
```

---

## Commands

All commands start with `RIFT ` prefix.

### HELLO

Initiates session with capability negotiation.

```
RIFT HELLO <version> [capabilities] [WINDOW_SIZE:<n>]
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `version` | yes | Protocol version (e.g., `1.0`) |
| `capabilities` | no | Comma-separated list |
| `WINDOW_SIZE:<n>` | no | Requested window size |

**Example:**
```
RIFT HELLO 1.0 CHUNKED,PARALLEL,RESUME,COMPRESS WINDOW_SIZE:128
```

### AUTH

Authenticates partner identity.

```
RIFT AUTH <partner-id>
```

**Example:**
```
RIFT AUTH acme-corp
```

### DISCOVER

Lists available virtual files.

```
RIFT DISCOVER
```

### DESCRIBE

Gets metadata for a virtual file.

```
RIFT DESCRIBE <virtual-file>
```

**Example:**
```
RIFT DESCRIBE daily-orders
```

### GET

Downloads chunks from a virtual file.

```
RIFT GET <virtual-file> CHUNKS <range>
```

| Range Format | Description |
|--------------|-------------|
| `0-9` | Chunks 0 through 9 |
| `5` | Only chunk 5 |
| `0-4,10-14` | Multiple ranges |

**Example:**
```
RIFT GET daily-orders CHUNKS 0-99
```

### PUT

Uploads a chunk to a virtual file.

```
RIFT PUT <virtual-file> CHUNK <index> SIZE:<size> HASH:<hash> [NONCE:<nonce>] [COMPRESSED]
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `virtual-file` | yes | Target virtual file |
| `index` | yes | Chunk index (0-based) |
| `SIZE:<size>` | yes | Chunk size in bytes |
| `HASH:<hash>` | yes | SHA-256 hash (hex) |
| `NONCE:<nonce>` | no | Anti-replay nonce |
| `COMPRESSED` | no | Flag if data is gzip compressed |

**Example:**
```
RIFT PUT invoices CHUNK 0 SIZE:262144 HASH:abc123... NONCE:1705756800 COMPRESSED
[binary data follows]
```

### BYE

Closes the session gracefully.

```
RIFT BYE
```

---

## Responses

All responses start with `RIFT ` prefix.

### WELCOME

Session established response.

```
RIFT WELCOME <version> [capabilities] [WINDOW_SIZE:<n>] <session-id>
```

**Example:**
```
RIFT WELCOME 1.0 CHUNKED,PARALLEL,RESUME WINDOW_SIZE:64 sess_20260120_001
```

### AUTH_OK

Authentication successful.

```
RIFT AUTH_OK "<partner-name>" VF:<virtual-files>
```

**Example:**
```
RIFT AUTH_OK "ACME Corporation" VF:daily-orders,invoices
```

### FILES

List of available files (follows DISCOVER).

```
RIFT FILES <count>
<name> <size> <direction> <timestamp>
...
```

**Example:**
```
RIFT FILES 2
daily-orders 1048576 SEND 1705756800
product-catalog 524288 SEND 1705753200
```

### FILE_INFO

File metadata (follows DESCRIBE).

```
RIFT FILE_INFO <name> SIZE:<size> CHUNKS:<count> CHUNK_SIZE:<size> HASH:<hash>
CHUNK <index> SIZE:<size> HASH:<hash>
...
```

**Example:**
```
RIFT FILE_INFO daily-orders SIZE:1048576 CHUNKS:4 CHUNK_SIZE:262144 HASH:abc123...
CHUNK 0 SIZE:262144 HASH:def456...
CHUNK 1 SIZE:262144 HASH:789012...
CHUNK 2 SIZE:262144 HASH:345678...
CHUNK 3 SIZE:262144 HASH:901234...
```

### CHUNK_DATA

Chunk data (follows GET).

```
RIFT CHUNK_DATA <virtual-file> <index> SIZE:<size>
[binary data]
```

### CHUNK_ACK

Acknowledgment for PUT.

```
RIFT CHUNK_ACK <virtual-file> <index> OK|ERROR [reason]
```

**Examples:**
```
RIFT CHUNK_ACK invoices 0 OK
RIFT CHUNK_ACK invoices 1 ERROR Hash mismatch
```

### CHUNK_ACK_BATCH

Batch acknowledgment (optimization).

```
RIFT CHUNK_ACK_BATCH <virtual-file> <ranges>
```

**Example:**
```
RIFT CHUNK_ACK_BATCH invoices 0-4,6-9
```

### TRANSFER_COMPLETE

Transfer finished with receipt.

```
RIFT TRANSFER_COMPLETE <virtual-file> HASH:<hash> SIZE:<size> CHUNKS:<count> [SIG:<signature>]
```

**Example:**
```
RIFT TRANSFER_COMPLETE invoices HASH:abc123... SIZE:1048576 CHUNKS:4 SIG:ed25519:base64...
```

### ERROR

Error response.

```
RIFT ERROR <code> <message>
```

### GOODBYE

Session closed response.

```
RIFT GOODBYE
```

---

## Error Codes

| Code | Name | Description |
|------|------|-------------|
| 400 | Bad Request | Malformed command |
| 401 | Unauthorized | Invalid or missing authentication |
| 403 | Forbidden | Partner not allowed for operation |
| 404 | Not Found | Virtual file not found |
| 409 | Conflict | Transfer already in progress |
| 413 | Payload Too Large | File/chunk exceeds limits |
| 426 | Upgrade Required | Protocol version not supported |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Error | Server error |

---

## Capabilities

Negotiated during HELLO/WELCOME handshake.

| Capability | Description |
|------------|-------------|
| `CHUNKED` | Support for chunked transfers |
| `PARALLEL` | Parallel chunk transfers |
| `RESUME` | Transfer resumption |
| `COMPRESS` | Gzip compression |

### Window Size

The `WINDOW_SIZE` parameter controls flow control:

- Client requests a size in HELLO
- Server responds with negotiated size (may be lower)
- Represents max chunks in flight without ACK

```
Client: WINDOW_SIZE:128
Server: WINDOW_SIZE:64  (limited by server)
```

---

## Security

### TLS Requirements

- **Version**: TLS 1.3 minimum
- **Authentication**: mTLS (both sides present certificates)
- **Cipher Suites**: TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256

### Integrity

- Each chunk has SHA-256 hash
- File has overall SHA-256 hash
- Optional Ed25519 signature on receipt

### Anti-Replay

- Optional nonces per chunk
- Server tracks seen nonces per session
- Rejects duplicate nonces

---

## Transfer Flow

### Sending (PUT)

```
Client                              Server
  │                                    │
  │── PUT file CHUNK 0 SIZE HASH ────>│
  │   [262144 bytes binary data]       │
  │<── CHUNK_ACK file 0 OK ───────────│
  │                                    │
  │── PUT file CHUNK 1 SIZE HASH ────>│
  │   [262144 bytes binary data]       │
  │<── CHUNK_ACK file 1 OK ───────────│
  │                                    │
  │   ... more chunks ...              │
  │                                    │
  │<── TRANSFER_COMPLETE file ... ────│
  │                                    │
```

### Receiving (GET)

```
Client                              Server
  │                                    │
  │── DESCRIBE file ─────────────────>│
  │<── FILE_INFO file ... ────────────│
  │    CHUNK 0 SIZE HASH              │
  │    CHUNK 1 SIZE HASH              │
  │    ...                            │
  │                                    │
  │── GET file CHUNKS 0-99 ──────────>│
  │<── CHUNK_DATA file 0 SIZE ────────│
  │    [binary data]                   │
  │<── CHUNK_DATA file 1 SIZE ────────│
  │    [binary data]                   │
  │    ...                            │
  │                                    │
```

### Parallel Transfer

With `PARALLEL` capability, multiple chunks can be in flight:

```
Client                              Server
  │                                    │
  │── PUT CHUNK 0 ───────────────────>│
  │── PUT CHUNK 1 ───────────────────>│
  │── PUT CHUNK 2 ───────────────────>│
  │── PUT CHUNK 3 ───────────────────>│
  │<── CHUNK_ACK 0 OK ────────────────│
  │── PUT CHUNK 4 ───────────────────>│
  │<── CHUNK_ACK_BATCH 1-3 ───────────│
  │── PUT CHUNK 5 ───────────────────>│
  │── PUT CHUNK 6 ───────────────────>│
  │── PUT CHUNK 7 ───────────────────>│
  │   ...                             │
```

---

## Compression

When `COMPRESS` capability is negotiated:

1. Sender compresses chunk data with gzip
2. Includes `COMPRESSED` flag in PUT
3. `SIZE` is compressed size
4. `HASH` is of compressed data
5. Receiver decompresses after verification

```
RIFT PUT invoices CHUNK 0 SIZE:180000 HASH:... COMPRESSED
[180000 bytes of gzip compressed data]
```

---

## Delta Sync

For incremental updates (similar to rsync):

1. Receiver sends file signature (block hashes)
2. Sender computes delta (changed blocks only)
3. Only changed blocks are transferred

This is handled at application level, not protocol level.

---

## Example Session

```
[TLS Handshake Complete]

C: RIFT HELLO 1.0 CHUNKED,PARALLEL,COMPRESS WINDOW_SIZE:64
S: RIFT WELCOME 1.0 CHUNKED,PARALLEL,COMPRESS WINDOW_SIZE:32 sess_001

C: RIFT AUTH acme-corp
S: RIFT AUTH_OK "ACME Corporation" VF:orders,invoices

C: RIFT DISCOVER
S: RIFT FILES 2
   orders 1048576 SEND 1705756800
   invoices 524288 RECEIVE 1705753200

C: RIFT DESCRIBE orders
S: RIFT FILE_INFO orders SIZE:1048576 CHUNKS:4 CHUNK_SIZE:262144 HASH:abc...
   CHUNK 0 SIZE:262144 HASH:def...
   CHUNK 1 SIZE:262144 HASH:123...
   CHUNK 2 SIZE:262144 HASH:456...
   CHUNK 3 SIZE:262144 HASH:789...

C: RIFT GET orders CHUNKS 0-3
S: RIFT CHUNK_DATA orders 0 SIZE:262144
   [binary data...]
S: RIFT CHUNK_DATA orders 1 SIZE:262144
   [binary data...]
S: RIFT CHUNK_DATA orders 2 SIZE:262144
   [binary data...]
S: RIFT CHUNK_DATA orders 3 SIZE:262144
   [binary data...]

C: RIFT PUT invoices CHUNK 0 SIZE:200000 HASH:aaa... NONCE:12345 COMPRESSED
   [compressed binary data...]
S: RIFT CHUNK_ACK invoices 0 OK

C: RIFT PUT invoices CHUNK 1 SIZE:180000 HASH:bbb... NONCE:12346 COMPRESSED
   [compressed binary data...]
S: RIFT CHUNK_ACK invoices 1 OK
S: RIFT TRANSFER_COMPLETE invoices HASH:xyz... SIZE:524288 CHUNKS:2 SIG:ed25519:...

C: RIFT BYE
S: RIFT GOODBYE

[Connection Closed]
```

---

## See Also

- [Configuration](CONFIGURATION.md) - Server/client setup
- [Getting Started](GETTING_STARTED.md) - Deployment guide
- [API Reference](API.md) - REST API
