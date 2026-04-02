#!/usr/bin/env bash
# Copyright (c) 2025-2026, The Shekyl Foundation
# BSD-3-Clause
#
# RPC Comparison Harness
# ---------------------
# Sends identical requests to the legacy epee RPC and the new Axum RPC,
# diffs the responses, and reports mismatches.
#
# Usage:
#   ./compare_rpc.sh [EPEE_PORT] [AXUM_PORT] [OUTPUT_DIR]
#
# Defaults: epee on 12029, Axum on 22029 (testnet ports).
# Requires: curl, jq, diff
#
# Start the daemon in dual-server mode (Rust RPC enabled by default):
#   shekyld --testnet   (epee on 12029, Axum on 22029)
#   shekyld             (epee on 11029, Axum on 21029)
# Disable with: shekyld --no-rust-rpc

set -uo pipefail

EPEE_PORT="${1:-12029}"
AXUM_PORT="${2:-22029}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DEV_DATA="${REPO_ROOT}/../shekyl-dev/data/rpc_comparison"
OUTPUT_DIR="${3:-$DEV_DATA}"

EPEE="http://127.0.0.1:${EPEE_PORT}"
AXUM="http://127.0.0.1:${AXUM_PORT}"

PASS=0
FAIL=0
SKIP=0
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RUN_DIR="$OUTPUT_DIR/$TIMESTAMP"
mkdir -p "$RUN_DIR"

log_pass() { PASS=$((PASS + 1)); echo "  [PASS] $1"; }
log_fail() { FAIL=$((FAIL + 1)); echo "  [FAIL] $1"; }
log_skip() { SKIP=$((SKIP + 1)); echo "  [SKIP] $1"; }

compare_json() {
    local label="$1" uri="$2" body="${3:-"{}"}"
    local safe_name
    safe_name=$(echo "$label" | tr ' /' '_')

    local e_file="$RUN_DIR/${safe_name}_epee.json"
    local a_file="$RUN_DIR/${safe_name}_axum.json"

    local e_code a_code
    e_code=$(curl -s -o "$e_file" -w "%{http_code}" -X POST -H 'Content-Type: application/json' -d "$body" "${EPEE}${uri}" 2>/dev/null) || true
    a_code=$(curl -s -o "$a_file" -w "%{http_code}" -X POST -H 'Content-Type: application/json' -d "$body" "${AXUM}${uri}" 2>/dev/null) || true

    if [ "$e_code" != "200" ] && [ "$a_code" != "200" ]; then
        log_skip "$label (both returned non-200: epee=$e_code axum=$a_code)"
        return
    fi

    local e_norm="$RUN_DIR/${safe_name}_epee_norm.json"
    local a_norm="$RUN_DIR/${safe_name}_axum_norm.json"
    jq -S '.' "$e_file" > "$e_norm" 2>/dev/null || cp "$e_file" "$e_norm"
    jq -S '.' "$a_file" > "$a_norm" 2>/dev/null || cp "$a_file" "$a_norm"

    if diff -q "$e_norm" "$a_norm" > /dev/null 2>&1; then
        log_pass "$label"
    else
        log_fail "$label"
        echo "    --- epee ($e_code) vs axum ($a_code) ---"
        diff --unified=3 "$e_norm" "$a_norm" | head -30 || true
        diff --unified=3 "$e_norm" "$a_norm" > "$RUN_DIR/${safe_name}_diff.txt" 2>&1 || true
    fi
}

compare_jsonrpc() {
    local label="$1" method="$2" params="${3:-"{}"}"
    local body="{\"jsonrpc\":\"2.0\",\"id\":\"test\",\"method\":\"${method}\",\"params\":${params}}"
    compare_json "$label" "/json_rpc" "$body"
}

compare_binary() {
    local label="$1" uri="$2"
    local safe_name
    safe_name=$(echo "$label" | tr ' /' '_')

    local e_file="$RUN_DIR/${safe_name}_epee.bin"
    local a_file="$RUN_DIR/${safe_name}_axum.bin"

    local e_code a_code
    e_code=$(curl -s -o "$e_file" -w "%{http_code}" -X POST "${EPEE}${uri}" 2>/dev/null) || true
    a_code=$(curl -s -o "$a_file" -w "%{http_code}" -X POST "${AXUM}${uri}" 2>/dev/null) || true

    if [ "$e_code" != "200" ] && [ "$a_code" != "200" ]; then
        log_skip "$label (both non-200: epee=$e_code axum=$a_code)"
        return
    fi

    if cmp -s "$e_file" "$a_file"; then
        log_pass "$label"
    else
        log_fail "$label (binary content differs, epee=$(wc -c < "$e_file")B vs axum=$(wc -c < "$a_file")B)"
    fi
}

echo "═══════════════════════════════════════════════════════"
echo " Shekyl RPC Comparison: epee ($EPEE) vs Axum ($AXUM)"
echo " Output: $RUN_DIR"
echo "═══════════════════════════════════════════════════════"

echo ""
echo "── JSON REST Endpoints ──"
compare_json "GET /get_height"              "/get_height"
compare_json "GET /get_info"                "/get_info"
compare_json "GET /get_limit"               "/get_limit"
compare_json "GET /get_transaction_pool"    "/get_transaction_pool"
compare_json "GET /get_transaction_pool_hashes"     "/get_transaction_pool_hashes"
compare_json "GET /get_transaction_pool_stats"      "/get_transaction_pool_stats"
compare_json "GET /get_public_nodes"        "/get_public_nodes"
compare_json "GET /get_alt_blocks_hashes"   "/get_alt_blocks_hashes"
compare_json "GET /get_outs"                "/get_outs" '{"outputs":[{"amount":0,"index":0}]}'

echo ""
echo "── JSON REST (Restricted) ──"
compare_json "GET /get_peer_list"           "/get_peer_list"
compare_json "GET /mining_status"           "/mining_status"
compare_json "GET /get_net_stats"           "/get_net_stats"

echo ""
echo "── Binary Endpoints ──"
compare_binary "BIN /get_hashes.bin"              "/get_hashes.bin"
compare_binary "BIN /get_o_indexes.bin"           "/get_o_indexes.bin"

echo ""
echo "── JSON-RPC Methods ──"
compare_jsonrpc "RPC get_block_count"        "get_block_count"
compare_jsonrpc "RPC get_version"            "get_version"
compare_jsonrpc "RPC get_fee_estimate"       "get_fee_estimate"
compare_jsonrpc "RPC hard_fork_info"         "hard_fork_info"
compare_jsonrpc "RPC get_info"               "get_info"
compare_jsonrpc "RPC get_last_block_header"  "get_last_block_header"
compare_jsonrpc "RPC get_output_histogram"   "get_output_histogram" '{"amounts":[0]}'
compare_jsonrpc "RPC get_staking_info"       "get_staking_info"
compare_jsonrpc "RPC get_txpool_backlog"     "get_txpool_backlog"

echo ""
echo "── JSON-RPC (Restricted) ──"
compare_jsonrpc "RPC get_connections"        "get_connections"
compare_jsonrpc "RPC get_bans"               "get_bans"
compare_jsonrpc "RPC sync_info"              "sync_info"
compare_jsonrpc "RPC get_alternate_chains"   "get_alternate_chains"

SUMMARY="Results: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped"

echo ""
echo "═══════════════════════════════════════════════════════"
echo " $SUMMARY"
echo "═══════════════════════════════════════════════════════"

echo "$SUMMARY" > "$RUN_DIR/SUMMARY.txt"
echo "epee: $EPEE" >> "$RUN_DIR/SUMMARY.txt"
echo "axum: $AXUM" >> "$RUN_DIR/SUMMARY.txt"
echo "timestamp: $TIMESTAMP" >> "$RUN_DIR/SUMMARY.txt"

exit $FAIL
