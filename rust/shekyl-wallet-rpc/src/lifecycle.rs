// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Wallet lifecycle JSON-RPC methods (Phase 4b slice 1).
//!
//! `create_wallet`, `open_wallet`, `close_wallet`, `change_password`.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::rngs::OsRng;
use rand::RngCore;
use serde::Deserialize;
use serde_json::{json, Value};
use shekyl_crypto_pq::account::{
    generate_account_from_bip39, generate_account_from_raw_seed, DerivationNetwork, SeedFormat,
    MASTER_SEED_BYTES, RAW_SEED_BYTES,
};
use shekyl_crypto_pq::bip39::{mnemonic_from_entropy, SHEKYL_BIP39_ENTROPY_BYTES};
use shekyl_crypto_pq::wallet_envelope::KdfParams;
use shekyl_engine_core::{
    Capability, CapabilityInput, Credentials, DaemonClient, Engine, EngineCreateParams, Network,
    OpenedEngine, SoloSigner,
};
use shekyl_engine_file::paths::keys_path_from;
use shekyl_engine_file::SafetyOverrides;
use shekyl_engine_prefs::WalletPrefs;
use shekyl_rpc_transport::SimpleRequestRpc;
use zeroize::{Zeroize, Zeroizing};

use crate::error::WalletRpcError;
use crate::tenant::TenantState;
use crate::types::{WalletHandle, CAPABILITY_FULL};

/// Params for `create_wallet`.
#[derive(Debug, Deserialize)]
struct CreateWalletParams {
    name: String,
    password: String,
    #[serde(default = "default_language")]
    language: String,
}

fn default_language() -> String {
    "en".to_owned()
}

/// Params for `open_wallet`.
#[derive(Debug, Deserialize)]
struct OpenWalletParams {
    name: String,
    password: String,
}

/// Params for `change_password`.
#[derive(Debug, Deserialize)]
struct ChangePasswordParams {
    old_password: String,
    new_password: String,
}

/// Dispatch a lifecycle method against `tenants`.
pub async fn dispatch(
    tenants: &tokio::sync::Mutex<TenantState>,
    method: &str,
    params: &Value,
    kdf: KdfParams,
) -> Result<Value, WalletRpcError> {
    match method {
        "create_wallet" => create_wallet(tenants, params, kdf).await,
        "open_wallet" => open_wallet(tenants, params).await,
        "close_wallet" => close_wallet(tenants, params).await,
        "change_password" => change_password(tenants, params).await,
        _ => Err(WalletRpcError::MethodNotFound(method.to_owned())),
    }
}

async fn create_wallet(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
    kdf: KdfParams,
) -> Result<Value, WalletRpcError> {
    let p: CreateWalletParams = parse_object(params, "create_wallet")?;
    validate_wallet_name(&p.name)?;
    if p.language != "en" {
        return Err(WalletRpcError::InvalidParams(
            "only language \"en\" is supported".into(),
        ));
    }

    let mut state = tenants.lock().await;
    if state.tenant.is_open() {
        return Err(WalletRpcError::WalletAlreadyOpen);
    }

    let base = wallet_base(&state.wallet_dir, &p.name);
    if keys_path_from(&base).exists() {
        return Err(WalletRpcError::WalletFileExists);
    }

    let network = state.network;
    let daemon = make_daemon(&state.daemon_address).await?;
    let password = Zeroizing::new(p.password.into_bytes());
    let creds = Credentials::password_only(password.as_slice());

    let (master_seed, seed_format, backup) = generate_seed_material(network)?;

    let creation_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let create_params = EngineCreateParams {
        base_path: &base,
        credentials: &creds,
        network,
        capability: CapabilityInput::Full {
            master_seed_64: &master_seed,
            seed_format,
        },
        creation_timestamp,
        restore_height_hint: 0,
        kdf,
        overrides: SafetyOverrides::none(),
        prefs: WalletPrefs::default(),
    };

    // Engine::create is sync and may run Argon2; keep the async runtime
    // responsive on the multi-thread scheduler (same shape as engine tests).
    let engine =
        tokio::task::block_in_place(|| Engine::<SoloSigner>::create(create_params, daemon))
            .map_err(WalletRpcError::from)?;

    // Drop master seed as soon as create returns (Zeroizing on drop).
    drop(master_seed);

    let handle = wallet_handle(&p.name, &engine, None);
    state.tenant.set_open(p.name, engine);

    let mut result = json!({ "wallet": handle });
    match backup {
        SeedBackup::Mnemonic(m) => {
            result["mnemonic"] = Value::String(m);
        }
        SeedBackup::RawHex(h) => {
            result["raw_seed_hex"] = Value::String(h);
        }
    }
    Ok(result)
}

async fn open_wallet(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    let p: OpenWalletParams = parse_object(params, "open_wallet")?;
    validate_wallet_name(&p.name)?;

    let mut state = tenants.lock().await;
    if state.tenant.is_open() {
        return Err(WalletRpcError::WalletAlreadyOpen);
    }

    let base = wallet_base(&state.wallet_dir, &p.name);
    if !keys_path_from(&base).exists() {
        return Err(WalletRpcError::WalletFileNotFound);
    }

    let network = state.network;
    let daemon = make_daemon(&state.daemon_address).await?;
    let password = Zeroizing::new(p.password.into_bytes());
    let creds = Credentials::password_only(password.as_slice());

    let opened = tokio::task::block_in_place(|| {
        Engine::<SoloSigner>::open_full(&base, &creds, network, daemon, SafetyOverrides::none())
    })
    .map_err(WalletRpcError::from)?;

    let (engine, restore_hint) = match opened {
        OpenedEngine::Loaded(w) => (w, None),
        OpenedEngine::Restored {
            wallet,
            from_height,
        } => (wallet, Some(from_height as i64)),
    };

    let handle = wallet_handle(&p.name, &engine, restore_hint);
    state.tenant.set_open(p.name, engine);
    Ok(json!({ "wallet": handle }))
}

async fn close_wallet(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    require_empty_object(params, "close_wallet")?;

    let mut state = tenants.lock().await;
    let Some((_name, engine)) = state.tenant.take_open() else {
        return Err(WalletRpcError::WalletNotOpen);
    };

    // `credentials` is ignored on the steady-state close path.
    let creds = Credentials::password_only(b"");
    tokio::task::block_in_place(|| engine.close(&creds)).map_err(WalletRpcError::from)?;
    Ok(json!({}))
}

async fn change_password(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    let p: ChangePasswordParams = parse_object(params, "change_password")?;

    let mut state = tenants.lock().await;
    let Some(engine) = state.tenant.engine_mut() else {
        return Err(WalletRpcError::WalletNotOpen);
    };

    let old = Zeroizing::new(p.old_password.into_bytes());
    let new = Zeroizing::new(p.new_password.into_bytes());
    let old_creds = Credentials::password_only(old.as_slice());
    let new_creds = Credentials::password_only(new.as_slice());

    tokio::task::block_in_place(|| engine.change_password(&old_creds, &new_creds, None))
        .map_err(WalletRpcError::from)?;
    Ok(json!({}))
}

enum SeedBackup {
    Mnemonic(String),
    RawHex(String),
}

fn generate_seed_material(
    network: Network,
) -> Result<(Zeroizing<[u8; MASTER_SEED_BYTES]>, SeedFormat, SeedBackup), WalletRpcError> {
    let derivation = network_to_derivation(network);
    match network {
        Network::Mainnet | Network::Stagenet => {
            let mut entropy = [0u8; SHEKYL_BIP39_ENTROPY_BYTES];
            OsRng.fill_bytes(&mut entropy);
            let mnemonic = mnemonic_from_entropy(&entropy).map_err(|e| {
                WalletRpcError::InternalError(format!("mnemonic_from_entropy: {e}"))
            })?;
            entropy.zeroize();
            let (master, _blob) = generate_account_from_bip39(&mnemonic, "", derivation)
                .map_err(|e| WalletRpcError::InternalError(format!("bip39 account: {e}")))?;
            Ok((master, SeedFormat::Bip39, SeedBackup::Mnemonic(mnemonic)))
        }
        Network::Testnet => {
            let mut raw = [0u8; RAW_SEED_BYTES];
            OsRng.fill_bytes(&mut raw);
            let hex = hex_encode_lower(&raw);
            let (master, _blob) = generate_account_from_raw_seed(&raw, derivation)
                .map_err(|e| WalletRpcError::InternalError(format!("raw account: {e}")))?;
            raw.zeroize();
            Ok((master, SeedFormat::Raw32, SeedBackup::RawHex(hex)))
        }
    }
}

fn network_to_derivation(network: Network) -> DerivationNetwork {
    match network {
        Network::Mainnet => DerivationNetwork::Mainnet,
        Network::Testnet => DerivationNetwork::Testnet,
        Network::Stagenet => DerivationNetwork::Stagenet,
    }
}

fn wallet_handle(
    name: &str,
    engine: &Engine<SoloSigner>,
    restore_height_hint: Option<i64>,
) -> WalletHandle {
    WalletHandle {
        name: name.to_owned(),
        capability: capability_str(engine.capability()).to_owned(),
        network: network_str(engine.network()).to_owned(),
        restore_height_hint,
    }
}

fn capability_str(cap: Capability) -> &'static str {
    match cap {
        Capability::Full => CAPABILITY_FULL,
        Capability::ViewOnly => "VIEW_ONLY",
        Capability::HardwareOffload => "HARDWARE_OFFLOAD",
    }
}

fn network_str(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "MAINNET",
        Network::Testnet => "TESTNET",
        Network::Stagenet => "STAGENET",
    }
}

fn wallet_base(wallet_dir: &Path, name: &str) -> PathBuf {
    wallet_dir.join(format!("{name}.wallet"))
}

fn validate_wallet_name(name: &str) -> Result<(), WalletRpcError> {
    if name.is_empty() {
        return Err(WalletRpcError::InvalidParams(
            "wallet name must be non-empty".into(),
        ));
    }
    if name.contains('/') || name.contains('\\') || name.contains('\0') {
        return Err(WalletRpcError::InvalidParams(
            "wallet name must not contain path separators".into(),
        ));
    }
    if name == "." || name == ".." {
        return Err(WalletRpcError::InvalidParams(
            "wallet name must not be \".\" or \"..\"".into(),
        ));
    }
    Ok(())
}

fn parse_object<T: for<'de> Deserialize<'de>>(
    params: &Value,
    method: &str,
) -> Result<T, WalletRpcError> {
    match params {
        Value::Null => Err(WalletRpcError::InvalidParams(format!(
            "{method} requires a params object"
        ))),
        Value::Object(_) => serde_json::from_value(params.clone())
            .map_err(|e| WalletRpcError::InvalidParams(format!("{method} params: {e}"))),
        _ => Err(WalletRpcError::InvalidParams(format!(
            "{method} params must be an object"
        ))),
    }
}

fn require_empty_object(params: &Value, method: &str) -> Result<(), WalletRpcError> {
    match params {
        Value::Null => Ok(()),
        Value::Object(map) if map.is_empty() => Ok(()),
        Value::Object(_) => Err(WalletRpcError::InvalidParams(format!(
            "{method} takes no parameters"
        ))),
        _ => Err(WalletRpcError::InvalidParams(format!(
            "{method} params must be an object or omitted"
        ))),
    }
}

async fn make_daemon(daemon_address: &str) -> Result<DaemonClient, WalletRpcError> {
    let rpc = SimpleRequestRpc::new(daemon_address.to_owned())
        .await
        .map_err(|_e| WalletRpcError::DaemonUnreachable)?;
    Ok(DaemonClient::new(rpc))
}

fn hex_encode_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}
