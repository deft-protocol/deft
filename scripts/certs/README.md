# DEFT Certificate Management Scripts

Scripts for generating TLS certificates for DEFT daemon instances.

## Scripts

### `generate-ca.sh`
Generate a Certificate Authority (CA).

```bash
./generate-ca.sh <output_dir> [ca_name]
```

### `generate-server-cert.sh`
Generate a server certificate signed by the CA.

```bash
./generate-server-cert.sh <ca_dir> <output_dir> <server_name> [hostnames...]
```

### `generate-client-cert.sh`
Generate a client certificate signed by the CA for mTLS authentication.

```bash
./generate-client-cert.sh <ca_dir> <output_dir> <client_name>
```

### `setup-integration-test.sh`
Setup a complete integration test environment with 2 DEFT instances.

```bash
./setup-integration-test.sh [base_dir]
# Default: /tmp/deft-integration
```

## Certificate Architecture

```
CA (shared)
├── Instance A
│   ├── server.crt/key  (for accepting connections)
│   └── client.crt/key  (for connecting to other instances)
└── Instance B
    ├── server.crt/key  (for accepting connections)
    └── client.crt/key  (for connecting to other instances)
```

## Partner Configuration

When Instance A connects to Instance B:
- Instance A uses `instance-a/client.crt` to authenticate
- Instance B must have `instance-a/client.crt` in partner's `allowed_certs`

When Instance B connects to Instance A:
- Instance B uses `instance-b/client.crt` to authenticate
- Instance A must have `instance-b/client.crt` in partner's `allowed_certs`
