// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved. BSD-3-Clause

//! JSON-RPC handlers for FROST multisig signing.
//!
//! Exposes the FROST signing protocol over JSON-RPC. All byte fields are
//! hex-encoded. DKG is handled via the `shekyl-wallet-core` API directly
//! (file-based ceremony), not over RPC.

use std::collections::HashMap;
use std::sync::Mutex;

use serde::Deserialize;
use serde_json::Value;

use shekyl_fcmp::frost_sal::FrostSalInput;
use shekyl_wallet_core::multisig::group::MultisigGroup;
use shekyl_wallet_core::multisig::signing::{
    MultisigSigningSession, PreprocessResponse, ShareResponse,
};

use crate::wallet::WalletError;

fn rpc_err(msg: impl Into<String>) -> WalletError {
    WalletError {
        code: -1,
        message: msg.into(),
    }
}

/// In-memory state for multisig signing sessions.
pub struct MultisigState {
    groups: HashMap<String, MultisigGroup>,
    signing_sessions: HashMap<String, MultisigSigningSession>,
    next_id: u64,
}

impl MultisigState {
    pub fn new() -> Self {
        Self {
            groups: HashMap::new(),
            signing_sessions: HashMap::new(),
            next_id: 0,
        }
    }

    fn next_session_id(&mut self) -> String {
        self.next_id += 1;
        format!("{:016x}", self.next_id)
    }

    /// Register a group (called after DKG completes via wallet-core API).
    pub fn register_group(&mut self, group: MultisigGroup) -> String {
        let id = hex::encode(group.group_id);
        self.groups.insert(id.clone(), group);
        id
    }
}

/// Multisig methods recognized by the dispatcher.
pub const MULTISIG_METHODS: &[&str] = &[
    "multisig_register_group",
    "multisig_list_groups",
    "multisig_create_signing",
    "multisig_sign_preprocess",
    "multisig_sign_add_preprocess",
    "multisig_sign_nonce_sums",
    "multisig_sign_own",
    "multisig_sign_add_shares",
    "multisig_sign_aggregate",
];

pub fn dispatch_multisig(
    state: &Mutex<MultisigState>,
    method: &str,
    params: Value,
) -> Result<Value, WalletError> {
    let mut ms = state
        .lock()
        .map_err(|e| rpc_err(format!("multisig lock poisoned: {e}")))?;

    match method {
        "multisig_register_group" => handle_register_group(&mut ms, params),
        "multisig_list_groups" => handle_list_groups(&ms),
        "multisig_create_signing" => handle_create_signing(&mut ms, params),
        "multisig_sign_preprocess" => handle_sign_preprocess(&mut ms, params),
        "multisig_sign_add_preprocess" => handle_sign_add_preprocess(&mut ms, params),
        "multisig_sign_nonce_sums" => handle_sign_nonce_sums(&mut ms, params),
        "multisig_sign_own" => handle_sign_own(&mut ms, params),
        "multisig_sign_add_shares" => handle_sign_add_shares(&mut ms, params),
        "multisig_sign_aggregate" => handle_sign_aggregate(&mut ms, params),
        _ => Err(rpc_err(format!("unknown multisig method: {method}"))),
    }
}

// ---------------------------------------------------------------------------
// Group management
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct RegisterGroupParams {
    group_json: String,
}

fn handle_register_group(ms: &mut MultisigState, params: Value) -> Result<Value, WalletError> {
    let p: RegisterGroupParams =
        serde_json::from_value(params).map_err(|e| rpc_err(format!("invalid params: {e}")))?;

    let group: MultisigGroup = serde_json::from_str(&p.group_json)
        .map_err(|e| rpc_err(format!("invalid group JSON: {e}")))?;

    let group_key = group
        .group_public_key()
        .map(|k| hex::encode(k))
        .unwrap_or_default();
    let group_id = ms.register_group(group);

    Ok(serde_json::json!({
        "group_id": group_id,
        "group_public_key": group_key,
    }))
}

fn handle_list_groups(ms: &MultisigState) -> Result<Value, WalletError> {
    let groups: Vec<Value> = ms
        .groups
        .iter()
        .map(|(id, g)| {
            serde_json::json!({
                "group_id": id,
                "threshold": g.threshold,
                "total": g.total,
                "our_index": g.our_index,
                "group_public_key": g.group_public_key().map(|k| hex::encode(k)).unwrap_or_default(),
            })
        })
        .collect();

    Ok(serde_json::json!({ "groups": groups }))
}

// ---------------------------------------------------------------------------
// Signing handlers
// ---------------------------------------------------------------------------

fn hex_to_32(s: &str, field: &str) -> Result<[u8; 32], WalletError> {
    let bytes = hex::decode(s).map_err(|e| rpc_err(format!("invalid {field} hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(rpc_err(format!("{field} must be 32 bytes")));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

#[derive(Deserialize)]
struct CreateSigningParams {
    group_id: String,
    inputs: Vec<InputParam>,
    included: Vec<u16>,
}

#[derive(Deserialize)]
struct InputParam {
    output_key: String,
    key_image_gen: String,
    commitment: String,
    spend_key_x: String,
    signable_tx_hash: String,
}

fn handle_create_signing(ms: &mut MultisigState, params: Value) -> Result<Value, WalletError> {
    let p: CreateSigningParams =
        serde_json::from_value(params).map_err(|e| rpc_err(format!("invalid params: {e}")))?;
    let group = ms
        .groups
        .get(&p.group_id)
        .ok_or_else(|| rpc_err("group not found"))?;

    let mut inputs = Vec::with_capacity(p.inputs.len());
    for inp in &p.inputs {
        inputs.push(FrostSalInput {
            output_key: hex_to_32(&inp.output_key, "output_key")?,
            key_image_gen: hex_to_32(&inp.key_image_gen, "key_image_gen")?,
            commitment: hex_to_32(&inp.commitment, "commitment")?,
            spend_key_x: hex_to_32(&inp.spend_key_x, "spend_key_x")?,
            signable_tx_hash: hex_to_32(&inp.signable_tx_hash, "signable_tx_hash")?,
        });
    }

    let session = MultisigSigningSession::new_coordinator(group, inputs, p.included)
        .map_err(|e| rpc_err(format!("signing session init failed: {e}")))?;

    let id = ms.next_session_id();
    ms.signing_sessions.insert(id.clone(), session);

    Ok(serde_json::json!({ "session_id": id }))
}

#[derive(Deserialize)]
struct SignGroupParams {
    session_id: String,
    group_id: String,
}

fn handle_sign_preprocess(ms: &mut MultisigState, params: Value) -> Result<Value, WalletError> {
    let p: SignGroupParams =
        serde_json::from_value(params).map_err(|e| rpc_err(format!("invalid params: {e}")))?;
    let group = ms
        .groups
        .get(&p.group_id)
        .ok_or_else(|| rpc_err("group not found"))?;
    let session = ms
        .signing_sessions
        .get_mut(&p.session_id)
        .ok_or_else(|| rpc_err("signing session not found"))?;

    let resp = session
        .preprocess_own(group)
        .map_err(|e| rpc_err(format!("preprocess failed: {e}")))?;

    let commitments_hex: Vec<String> = resp.commitments.iter().map(hex::encode).collect();

    Ok(serde_json::json!({
        "participant": resp.participant,
        "commitments": commitments_hex,
    }))
}

#[derive(Deserialize)]
struct AddPreprocessParams {
    session_id: String,
    participant: u16,
    commitments: Vec<String>,
}

fn handle_sign_add_preprocess(ms: &mut MultisigState, params: Value) -> Result<Value, WalletError> {
    let p: AddPreprocessParams =
        serde_json::from_value(params).map_err(|e| rpc_err(format!("invalid params: {e}")))?;
    let session = ms
        .signing_sessions
        .get_mut(&p.session_id)
        .ok_or_else(|| rpc_err("signing session not found"))?;

    let commitments: Result<Vec<Vec<u8>>, _> =
        p.commitments.iter().map(|s| hex::decode(s)).collect();
    let commitments = commitments.map_err(|e| rpc_err(format!("invalid commitment hex: {e}")))?;

    session
        .add_preprocess(PreprocessResponse {
            participant: p.participant,
            commitments,
        })
        .map_err(|e| rpc_err(format!("add_preprocess failed: {e}")))?;

    Ok(serde_json::json!({ "status": "ok" }))
}

#[derive(Deserialize)]
struct SessionIdParam {
    session_id: String,
}

fn handle_sign_nonce_sums(ms: &mut MultisigState, params: Value) -> Result<Value, WalletError> {
    let p: SessionIdParam =
        serde_json::from_value(params).map_err(|e| rpc_err(format!("invalid params: {e}")))?;
    let session = ms
        .signing_sessions
        .get_mut(&p.session_id)
        .ok_or_else(|| rpc_err("signing session not found"))?;

    let sums = session
        .nonce_sums_bytes()
        .map_err(|e| rpc_err(format!("nonce_sums failed: {e}")))?;
    let sums_hex: Vec<String> = sums.iter().map(hex::encode).collect();

    Ok(serde_json::json!({ "nonce_sums": sums_hex }))
}

fn handle_sign_own(ms: &mut MultisigState, params: Value) -> Result<Value, WalletError> {
    let p: SignGroupParams =
        serde_json::from_value(params).map_err(|e| rpc_err(format!("invalid params: {e}")))?;
    let group = ms
        .groups
        .get(&p.group_id)
        .ok_or_else(|| rpc_err("group not found"))?;
    let session = ms
        .signing_sessions
        .get_mut(&p.session_id)
        .ok_or_else(|| rpc_err("signing session not found"))?;

    let resp = session
        .sign_own(group)
        .map_err(|e| rpc_err(format!("sign_own failed: {e}")))?;

    let shares_hex: Vec<String> = resp.shares.iter().map(hex::encode).collect();

    Ok(serde_json::json!({
        "participant": resp.participant,
        "shares": shares_hex,
    }))
}

#[derive(Deserialize)]
struct AddSharesParams {
    session_id: String,
    participant: u16,
    shares: Vec<String>,
}

fn handle_sign_add_shares(ms: &mut MultisigState, params: Value) -> Result<Value, WalletError> {
    let p: AddSharesParams =
        serde_json::from_value(params).map_err(|e| rpc_err(format!("invalid params: {e}")))?;
    let session = ms
        .signing_sessions
        .get_mut(&p.session_id)
        .ok_or_else(|| rpc_err("signing session not found"))?;

    let mut shares = Vec::with_capacity(p.shares.len());
    for s in &p.shares {
        shares.push(hex_to_32(s, "share")?);
    }

    session
        .add_shares(ShareResponse {
            participant: p.participant,
            shares,
        })
        .map_err(|e| rpc_err(format!("add_shares failed: {e}")))?;

    Ok(serde_json::json!({ "status": "ok" }))
}

fn handle_sign_aggregate(ms: &mut MultisigState, params: Value) -> Result<Value, WalletError> {
    let p: SignGroupParams =
        serde_json::from_value(params).map_err(|e| rpc_err(format!("invalid params: {e}")))?;
    let group = ms
        .groups
        .get(&p.group_id)
        .ok_or_else(|| rpc_err("group not found"))?;
    let session = ms
        .signing_sessions
        .remove(&p.session_id)
        .ok_or_else(|| rpc_err("signing session not found"))?;

    let sal_proofs = session
        .aggregate(group)
        .map_err(|e| rpc_err(format!("aggregate failed: {e}")))?;

    Ok(serde_json::json!({
        "status": "aggregated",
        "num_inputs": sal_proofs.len(),
    }))
}
