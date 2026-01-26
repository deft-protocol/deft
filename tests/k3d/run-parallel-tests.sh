#!/bin/bash
# DEFT Parallel Transfer Tests using k3d
# Tests multi-node parallel transfers across multiple network interfaces

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CLUSTER_NAME="deft-test"
NAMESPACE="deft-test"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

cleanup() {
    log_info "Cleaning up..."
    k3d cluster delete $CLUSTER_NAME 2>/dev/null || true
}

trap cleanup EXIT

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    command -v k3d >/dev/null 2>&1 || { log_error "k3d is required but not installed"; exit 1; }
    command -v kubectl >/dev/null 2>&1 || { log_error "kubectl is required but not installed"; exit 1; }
    command -v docker >/dev/null 2>&1 || { log_error "docker is required but not installed"; exit 1; }
    
    log_info "All prerequisites met"
}

# Build DEFT Docker image
build_image() {
    log_info "Building DEFT Docker image..."
    
    docker build -t deft-daemon:test -f "$SCRIPT_DIR/Dockerfile" "$PROJECT_ROOT"
    
    log_info "Docker image built successfully"
}

# Create k3d cluster
create_cluster() {
    log_info "Creating k3d cluster '$CLUSTER_NAME'..."
    
    # Delete existing cluster if present
    k3d cluster delete $CLUSTER_NAME 2>/dev/null || true
    
    # Create cluster with 3 agent nodes (simulating multiple network interfaces)
    k3d cluster create $CLUSTER_NAME \
        --servers 1 \
        --agents 3 \
        --port "7741:7741@loadbalancer" \
        --port "7742:7742@loadbalancer" \
        --k3s-arg "--disable=traefik@server:*" \
        --wait
    
    # Import DEFT image into cluster
    k3d image import deft-daemon:test -c $CLUSTER_NAME
    
    log_info "Cluster created successfully"
}

# Generate test certificates
generate_certs() {
    log_info "Generating test certificates..."
    
    CERT_DIR=$(mktemp -d)
    
    # Generate CA
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$CERT_DIR/ca.key" \
        -out "$CERT_DIR/ca.crt" \
        -days 1 -subj "/CN=DEFT-Test-CA"
    
    # Generate server cert
    openssl genrsa -out "$CERT_DIR/server.key" 2048
    openssl req -new -key "$CERT_DIR/server.key" \
        -out "$CERT_DIR/server.csr" \
        -subj "/CN=deft-node"
    openssl x509 -req -in "$CERT_DIR/server.csr" \
        -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" \
        -CAcreateserial -out "$CERT_DIR/server.crt" -days 1
    
    # Generate client cert
    openssl genrsa -out "$CERT_DIR/client.key" 2048
    openssl req -new -key "$CERT_DIR/client.key" \
        -out "$CERT_DIR/client.csr" \
        -subj "/CN=deft-client"
    openssl x509 -req -in "$CERT_DIR/client.csr" \
        -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" \
        -CAcreateserial -out "$CERT_DIR/client.crt" -days 1
    
    # Create Kubernetes secret
    kubectl create namespace $NAMESPACE --dry-run=client -o yaml | kubectl apply -f -
    kubectl create secret generic deft-certs -n $NAMESPACE \
        --from-file=ca.crt="$CERT_DIR/ca.crt" \
        --from-file=server.crt="$CERT_DIR/server.crt" \
        --from-file=server.key="$CERT_DIR/server.key" \
        --from-file=client.crt="$CERT_DIR/client.crt" \
        --from-file=client.key="$CERT_DIR/client.key" \
        --dry-run=client -o yaml | kubectl apply -f -
    
    rm -rf "$CERT_DIR"
    
    log_info "Certificates generated and stored in Kubernetes secret"
}

# Deploy DEFT nodes
deploy_nodes() {
    log_info "Deploying DEFT nodes..."
    
    kubectl apply -f "$SCRIPT_DIR/manifests/namespace.yaml"
    kubectl apply -f "$SCRIPT_DIR/manifests/deft-node.yaml"
    
    # Wait for pods to be ready
    log_info "Waiting for DEFT nodes to be ready..."
    kubectl wait --for=condition=ready pod -l app=deft-node -n $NAMESPACE --timeout=120s
    
    log_info "DEFT nodes deployed successfully"
}

# Run parallel transfer tests
run_parallel_tests() {
    log_info "Running parallel transfer tests..."
    
    # Get pod names
    PODS=$(kubectl get pods -n $NAMESPACE -l app=deft-node -o jsonpath='{.items[*].metadata.name}')
    POD_ARRAY=($PODS)
    
    if [ ${#POD_ARRAY[@]} -lt 2 ]; then
        log_error "Need at least 2 pods for parallel tests"
        exit 1
    fi
    
    SENDER_POD="${POD_ARRAY[0]}"
    RECEIVER_POD="${POD_ARRAY[1]}"
    
    log_info "Sender: $SENDER_POD, Receiver: $RECEIVER_POD"
    
    # Create test file on sender
    log_info "Creating test file (100MB)..."
    kubectl exec -n $NAMESPACE $SENDER_POD -- \
        dd if=/dev/urandom of=/var/lib/deft/test-file.dat bs=1M count=100 2>/dev/null
    
    # Get receiver IP
    RECEIVER_IP=$(kubectl get pod -n $NAMESPACE $RECEIVER_POD -o jsonpath='{.status.podIP}')
    log_info "Receiver IP: $RECEIVER_IP"
    
    # Test 1: Single stream transfer
    log_info "Test 1: Single stream transfer..."
    START_TIME=$(date +%s.%N)
    
    kubectl exec -n $NAMESPACE $SENDER_POD -- \
        curl -s -X POST "http://localhost:7742/api/client/push" \
        -H "Content-Type: application/json" \
        -d "{\"file_path\":\"/var/lib/deft/test-file.dat\",\"virtual_file\":\"test-single\"}" || true
    
    END_TIME=$(date +%s.%N)
    SINGLE_DURATION=$(echo "$END_TIME - $START_TIME" | bc)
    log_info "Single stream duration: ${SINGLE_DURATION}s"
    
    # Test 2: Parallel streams transfer (4 streams)
    log_info "Test 2: Parallel streams transfer (4 streams)..."
    START_TIME=$(date +%s.%N)
    
    # Simulate parallel streams by running multiple transfers
    for i in 1 2 3 4; do
        kubectl exec -n $NAMESPACE $SENDER_POD -- \
            curl -s -X POST "http://localhost:7742/api/client/push" \
            -H "Content-Type: application/json" \
            -d "{\"file_path\":\"/var/lib/deft/test-file.dat\",\"virtual_file\":\"test-parallel-$i\",\"priority\":\"urgent\"}" &
    done
    wait
    
    END_TIME=$(date +%s.%N)
    PARALLEL_DURATION=$(echo "$END_TIME - $START_TIME" | bc)
    log_info "Parallel streams duration: ${PARALLEL_DURATION}s"
    
    # Test 3: Multi-node parallel transfers
    log_info "Test 3: Multi-node parallel transfers..."
    START_TIME=$(date +%s.%N)
    
    for pod in "${POD_ARRAY[@]}"; do
        kubectl exec -n $NAMESPACE $pod -- \
            curl -s -X POST "http://localhost:7742/api/client/push" \
            -H "Content-Type: application/json" \
            -d "{\"file_path\":\"/var/lib/deft/test-file.dat\",\"virtual_file\":\"test-multinode\"}" &
    done
    wait
    
    END_TIME=$(date +%s.%N)
    MULTINODE_DURATION=$(echo "$END_TIME - $START_TIME" | bc)
    log_info "Multi-node parallel duration: ${MULTINODE_DURATION}s"
    
    # Summary
    echo ""
    log_info "========== TEST RESULTS =========="
    echo "Single stream:     ${SINGLE_DURATION}s"
    echo "Parallel (4x):     ${PARALLEL_DURATION}s"
    echo "Multi-node (${#POD_ARRAY[@]}x): ${MULTINODE_DURATION}s"
    log_info "=================================="
}

# Test cluster connectivity
test_connectivity() {
    log_info "Testing cluster connectivity..."
    
    PODS=$(kubectl get pods -n $NAMESPACE -l app=deft-node -o jsonpath='{.items[*].metadata.name}')
    
    for pod in $PODS; do
        log_info "Testing $pod..."
        kubectl exec -n $NAMESPACE $pod -- curl -s http://localhost:7742/api/health || {
            log_error "Health check failed for $pod"
            return 1
        }
    done
    
    log_info "All nodes are healthy"
}

# Main
main() {
    log_info "Starting DEFT Parallel Transfer Tests"
    
    check_prerequisites
    build_image
    create_cluster
    generate_certs
    deploy_nodes
    
    sleep 5  # Allow nodes to stabilize
    
    test_connectivity
    run_parallel_tests
    
    log_info "Tests completed successfully!"
}

# Run
main "$@"
