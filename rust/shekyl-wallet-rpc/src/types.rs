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

//! JSON-RPC request/response types matching `wallet_rpc_server_commands_defs.h`.

use serde::{Deserialize, Serialize};

// ── JSON-RPC envelope ────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

#[derive(Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: &'static str,
    pub id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
}

impl JsonRpcResponse {
    pub fn success(id: serde_json::Value, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: serde_json::Value, code: i32, message: String) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(JsonRpcError { code, message }),
        }
    }
}

// ── create_wallet ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateWalletParams {
    #[serde(default)]
    pub filename: String,
    #[serde(default)]
    pub password: String,
    #[serde(default = "default_language")]
    pub language: String,
}

// ── open_wallet ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct OpenWalletParams {
    pub filename: String,
    #[serde(default)]
    pub password: String,
    #[serde(default = "default_true")]
    pub autosave_current: bool,
}

// ── close_wallet ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CloseWalletParams {
    #[serde(default = "default_true")]
    pub autosave_current: bool,
}

// ── restore_deterministic_wallet ─────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RestoreDeterministicWalletParams {
    #[serde(default)]
    pub filename: String,
    pub seed: String,
    #[serde(default)]
    pub password: String,
    #[serde(default = "default_language")]
    pub language: String,
    #[serde(default)]
    pub restore_height: u64,
    #[serde(default)]
    pub seed_offset: String,
}

// ── generate_from_keys ───────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct GenerateFromKeysParams {
    #[serde(default)]
    pub filename: String,
    pub address: String,
    #[serde(default)]
    pub spendkey: String,
    pub viewkey: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub language: String,
    #[serde(default)]
    pub restore_height: u64,
}

// ── get_balance ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct GetBalanceParams {
    #[serde(default)]
    pub account_index: u32,
}

// ── get_address ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct GetAddressParams {
    #[serde(default)]
    pub account_index: u32,
}

// ── query_key ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct QueryKeyParams {
    pub key_type: String,
}

// ── transfer ─────────────────────────────────────────────────────────────────

#[derive(Deserialize, Serialize)]
pub struct TransferDestination {
    pub address: String,
    pub amount: u64,
}

#[derive(Deserialize)]
pub struct TransferParams {
    pub destinations: Vec<TransferDestination>,
    #[serde(default)]
    pub priority: u32,
    #[serde(default)]
    pub account_index: u32,
    #[serde(default)]
    pub payment_id: String,
    #[serde(default)]
    pub do_not_relay: bool,
    #[serde(default)]
    pub get_tx_key: bool,
    #[serde(default)]
    pub get_tx_hex: bool,
    #[serde(default)]
    pub get_tx_metadata: bool,
    #[serde(default)]
    pub unlock_time: u64,
}

// ── get_transfers ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct GetTransfersParams {
    #[serde(default)]
    pub r#in: bool,
    #[serde(default)]
    pub out: bool,
    #[serde(default)]
    pub pending: bool,
    #[serde(default)]
    pub failed: bool,
    #[serde(default)]
    pub pool: bool,
    #[serde(default)]
    pub account_index: u32,
}

// ── stop_wallet ──────────────────────────────────────────────────────────────
// (no params)

// ── get_version ──────────────────────────────────────────────────────────────
// (no params)

// ── defaults ─────────────────────────────────────────────────────────────────

fn default_language() -> String {
    "English".into()
}

fn default_true() -> bool {
    true
}
