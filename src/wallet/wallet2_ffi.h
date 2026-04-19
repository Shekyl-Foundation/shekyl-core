// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// C FFI facade over tools::wallet2 for consumption by Rust.
// All complex return values are serialized as JSON strings.
// The caller must free any non-NULL char* with wallet2_ffi_free_string().

#pragma once

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct wallet2_handle wallet2_handle;

// ── Lifecycle ────────────────────────────────────────────────────────────────

// Create a new wallet2 handle. `nettype`: 0=mainnet, 1=testnet, 2=stagenet.
wallet2_handle* wallet2_ffi_create(uint8_t nettype);

// Destroy the handle and free the underlying wallet2 (stores if open).
void wallet2_ffi_destroy(wallet2_handle* w);

// Connect to daemon. Returns 0 on success, negative error code on failure.
int wallet2_ffi_init(wallet2_handle* w,
                     const char* daemon_address,
                     const char* daemon_username,
                     const char* daemon_password,
                     bool trusted_daemon);

// Trigger a wallet refresh/sync. Returns 0 on success.
int wallet2_ffi_refresh(wallet2_handle* w);

// Save the wallet to disk. Returns 0 on success.
int wallet2_ffi_store(wallet2_handle* w);

// ── Error state ──────────────────────────────────────────────────────────────

// After any function returns an error (negative code or NULL), these provide
// the error details. Values are valid until the next call on the same handle.
int wallet2_ffi_last_error_code(const wallet2_handle* w);
const char* wallet2_ffi_last_error_msg(const wallet2_handle* w);

// Free a string returned by any wallet2_ffi_* function.
void wallet2_ffi_free_string(char* str);

// ── Wallet file operations ───────────────────────────────────────────────────
//
// The FFI does not carry filesystem state. Callers construct the full
// wallet path (directory + filename) in their preferred language — Rust's
// PathBuf::join on the Tauri/wallet-rpc side is platform-correct on every
// target — and pass it in here. See docs/CHANGELOG.md §"wallet2_ffi
// no longer carries wallet-directory state".

// Create a new wallet at the given absolute or relative path. Returns 0 on success.
int wallet2_ffi_create_wallet(wallet2_handle* w,
                              const char* wallet_path,
                              const char* password,
                              const char* language);

// Open an existing wallet at the given path. Returns 0 on success.
int wallet2_ffi_open_wallet(wallet2_handle* w,
                            const char* wallet_path,
                            const char* password);

// Close the current wallet (stores first if autosave is true). Returns 0 on success.
int wallet2_ffi_close_wallet(wallet2_handle* w, bool autosave);

// Restore from mnemonic seed. Returns JSON: {"address":"...","seed":"...","info":"..."} or NULL.
char* wallet2_ffi_restore_deterministic_wallet(wallet2_handle* w,
                                               const char* wallet_path,
                                               const char* seed,
                                               const char* password,
                                               const char* language,
                                               uint64_t restore_height,
                                               const char* seed_offset);

// Restore from keys. Returns JSON: {"address":"...","info":"..."} or NULL.
char* wallet2_ffi_generate_from_keys(wallet2_handle* w,
                                     const char* wallet_path,
                                     const char* address,
                                     const char* spendkey,
                                     const char* viewkey,
                                     const char* password,
                                     const char* language,
                                     uint64_t restore_height);

// ── Queries ──────────────────────────────────────────────────────────────────

// Get balance. Returns JSON: {"balance":N,"unlocked_balance":N,"blocks_to_unlock":N} or NULL.
char* wallet2_ffi_get_balance(wallet2_handle* w, uint32_t account_index);

// Get address. Returns JSON: {"address":"...","addresses":[...]} or NULL.
char* wallet2_ffi_get_address(wallet2_handle* w, uint32_t account_index);

// Query key material. key_type: "mnemonic", "view_key", "spend_key".
// Returns JSON: {"key":"..."} or NULL.
char* wallet2_ffi_query_key(wallet2_handle* w, const char* key_type);

// Get wallet RPC version. Returns the packed version (major<<16 | minor).
uint32_t wallet2_ffi_get_version(void);

// ── Transfers ────────────────────────────────────────────────────────────────

// Send a transfer. `destinations_json` is a JSON array: [{"address":"...","amount":N},...]
// Returns JSON: {"tx_hash":"...","fee":N,"amount":N} or NULL on error.
char* wallet2_ffi_transfer(wallet2_handle* w,
                           const char* destinations_json,
                           uint32_t priority,
                           uint32_t account_index);

// Get transfer history. Returns JSON: {"in":[...],"out":[...],"pending":[...],"pool":[...]} or NULL.
char* wallet2_ffi_get_transfers(wallet2_handle* w,
                                bool in,
                                bool out,
                                bool pending,
                                bool failed,
                                bool pool,
                                uint32_t account_index);

// ── Control ──────────────────────────────────────────────────────────────────

// Request the wallet to stop (stores and signals shutdown). Returns 0 on success.
int wallet2_ffi_stop(wallet2_handle* w);

// Returns true if a wallet is currently open.
bool wallet2_ffi_is_open(const wallet2_handle* w);

// Get the height the wallet has synced to.
uint64_t wallet2_ffi_get_height(const wallet2_handle* w);

// ── Progress callback ────────────────────────────────────────────────────────

// Callback type for wallet progress events (transfer stages, FCMP precomputation,
// PQC rederivation). The callback is invoked from the wallet2 thread.
// - event_type: "transfer_stage", "fcmp_precompute", or "pqc_rederivation"
// - current: stage index or outputs completed
// - total: total stages or total outputs
// - detail: stage name (e.g. "generating_proof") or NULL
// - user_data: opaque pointer passed at registration time
typedef void (*wallet2_ffi_progress_callback)(
    const char* event_type,
    uint64_t current,
    uint64_t total,
    const char* detail,
    void* user_data);

// Register a progress callback. Pass NULL to unregister.
void wallet2_ffi_set_progress_callback(wallet2_handle* w,
                                       wallet2_ffi_progress_callback cb,
                                       void* user_data);

// ── Split transfer pipeline ──────────────────────────────────────────────────
// These two functions split the existing wallet2_ffi_transfer into a
// prepare → sign → finalize flow, enabling the Rust wallet-rpc to call
// shekyl-tx-builder::sign_transaction directly for proof generation.

/// Phase A: Build the transaction prefix (inputs selected, outputs constructed,
/// tx_extra populated) without generating cryptographic proofs.
///
/// Returns JSON with the unsigned transaction data needed for signing:
/// - tx_prefix_hash (32-byte hex)
/// - inputs: array of SpendInput-compatible objects (output_key, commitment,
///   amount, spend_key_x, spend_key_y, h_pqc, pqc_secret_key, leaf_chunk,
///   c1_layers, c2_layers)
/// - outputs: array of OutputInfo-compatible objects (dest_key, amount, amount_key)
/// - fee: u64
/// - tree: TreeContext object (reference_block, tree_root, tree_depth)
/// - tx_blob: hex-encoded serialized transaction prefix (for finalization)
///
/// Returns NULL on error (check wallet2_ffi_last_error_msg).
/// The caller must free the returned string with wallet2_ffi_free_string().
char* wallet2_ffi_prepare_transfer(wallet2_handle* w,
                                   const char* destinations_json,
                                   uint32_t priority,
                                   uint32_t account_index);

/// Phase C: Insert signed proofs into the transaction and broadcast.
///
/// `signed_proofs_json`: JSON-encoded SignedProofs from shekyl-tx-builder
///   (bulletproof_plus, commitments, ecdh_amounts, pseudo_outs, fcmp_proof,
///    pqc_auths, reference_block, tree_depth).
/// `tx_blob_hex`: the tx_blob returned by wallet2_ffi_prepare_transfer.
///
/// Returns JSON: {"tx_hash":"...","fee":N} or NULL on error.
/// The caller must free the returned string with wallet2_ffi_free_string().
char* wallet2_ffi_finalize_transfer(wallet2_handle* w,
                                    const char* signed_proofs_json,
                                    const char* tx_blob_hex);

// ── Scanner keys ─────────────────────────────────────────────────────────

// Export keys needed by the Rust scanner as JSON.
// Returns: {"spend_secret":"hex","view_secret":"hex","spend_public":"hex",
//           "view_public":"hex","x25519_sk":"hex","ml_kem_dk":"hex"}
// or NULL on error.
// The caller must free the returned string with wallet2_ffi_free_string().
char* wallet2_ffi_get_scanner_keys(wallet2_handle* w);

// ── Generic JSON-RPC dispatcher ──────────────────────────────────────────────

// Dispatch any wallet RPC method by name with JSON params.
// This covers the full 98-method surface of the C++ wallet_rpc_server.
// `method`: JSON-RPC method name (e.g., "get_accounts", "sweep_all").
// `params_json`: JSON object string with method parameters.
// Returns: JSON result string on success, NULL on failure (check last_error).
// The caller must free the returned string with wallet2_ffi_free_string().
char* wallet2_ffi_json_rpc(wallet2_handle* w, const char* method, const char* params_json);

#ifdef __cplusplus
} // extern "C"
#endif
