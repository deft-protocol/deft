#!/bin/bash
# DEFT Protocol Load Test Script
# Usage: ./load_test.sh [num_files] [file_size_kb] [partner_id]

set -e

NUM_FILES=${1:-10}
FILE_SIZE_KB=${2:-1024}
PARTNER_ID=${3:-"test-partner"}
CONFIG=${CONFIG:-"test-env/config.toml"}

DEFTD="./target/release/deftd"
TEST_DIR="/tmp/deft-load-test"
RESULTS_FILE="$TEST_DIR/results.csv"

echo "=========================================="
echo "DEFT Protocol Load Test"
echo "=========================================="
echo "Files:       $NUM_FILES"
echo "Size:        ${FILE_SIZE_KB}KB each"
echo "Partner:     $PARTNER_ID"
echo "Config:      $CONFIG"
echo "=========================================="

# Check if deftd exists
if [ ! -f "$DEFTD" ]; then
    echo "Error: $DEFTD not found. Run 'cargo build --release' first."
    exit 1
fi

# Create test directory
rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR/input"
mkdir -p "$TEST_DIR/output"

# Generate test files
echo "Generating $NUM_FILES test files..."
for i in $(seq 1 $NUM_FILES); do
    dd if=/dev/urandom of="$TEST_DIR/input/file_$i.dat" bs=1024 count=$FILE_SIZE_KB 2>/dev/null
done
echo "Done."

# Initialize results CSV
echo "file,size_bytes,chunks,duration_ms,throughput_mbps,status" > "$RESULTS_FILE"

# Function to send a file and measure time
send_file() {
    local file=$1
    local vf_name=$2
    local size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file")
    
    local start=$(date +%s%3N)
    
    if $DEFTD -c "$CONFIG" send "$PARTNER_ID" "$vf_name" "$file" 2>/dev/null; then
        local end=$(date +%s%3N)
        local duration=$((end - start))
        local throughput=$(echo "scale=2; ($size / 1048576) / ($duration / 1000)" | bc)
        local chunks=$(( (size + 262143) / 262144 ))
        echo "$vf_name,$size,$chunks,$duration,$throughput,success" >> "$RESULTS_FILE"
        echo "  ✓ $vf_name: ${duration}ms (${throughput} MB/s)"
        return 0
    else
        echo "$vf_name,$size,0,0,0,failed" >> "$RESULTS_FILE"
        echo "  ✗ $vf_name: FAILED"
        return 1
    fi
}

echo ""
echo "Starting transfers..."
echo ""

TOTAL_START=$(date +%s%3N)
SUCCESS=0
FAILED=0

for i in $(seq 1 $NUM_FILES); do
    file="$TEST_DIR/input/file_$i.dat"
    vf_name="load-test-$i"
    
    if send_file "$file" "$vf_name"; then
        SUCCESS=$((SUCCESS + 1))
    else
        FAILED=$((FAILED + 1))
    fi
done

TOTAL_END=$(date +%s%3N)
TOTAL_DURATION=$((TOTAL_END - TOTAL_START))

echo ""
echo "=========================================="
echo "Results Summary"
echo "=========================================="
echo "Total files:     $NUM_FILES"
echo "Successful:      $SUCCESS"
echo "Failed:          $FAILED"
echo "Total time:      ${TOTAL_DURATION}ms"

TOTAL_BYTES=$((NUM_FILES * FILE_SIZE_KB * 1024))
TOTAL_MB=$(echo "scale=2; $TOTAL_BYTES / 1048576" | bc)
AVG_THROUGHPUT=$(echo "scale=2; $TOTAL_MB / ($TOTAL_DURATION / 1000)" | bc)

echo "Total data:      ${TOTAL_MB}MB"
echo "Avg throughput:  ${AVG_THROUGHPUT} MB/s"
echo ""
echo "Results saved to: $RESULTS_FILE"
echo "=========================================="

# Show CSV summary
echo ""
echo "Detailed results:"
cat "$RESULTS_FILE"
