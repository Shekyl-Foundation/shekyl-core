// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Wallet lifecycle JSON-RPC methods (Phase 4b slice 1).
//!
//! `create_wallet`, `open_wallet`, `close_wallet`, `change_password`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
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
    CapabilityInput, Credentials, DaemonClient, Engine, EngineCreateParams, Network, OpenError,
    OpenedEngine, SoloSigner,
};
use shekyl_engine_file::paths::keys_path_from;
use shekyl_engine_file::SafetyOverrides;
use shekyl_engine_prefs::WalletPrefs;
use shekyl_rpc_transport::SimpleRequestRpc;
use zeroize::{Zeroize, Zeroizing};

use crate::error::WalletRpcError;
use crate::params::{parse_required_object, require_empty_object};
use crate::tenant::{require_open_engine, TenantState};
use crate::types::{capability_mode_str, WalletHandle};

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

pub(crate) async fn create_wallet(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
    kdf: KdfParams,
) -> Result<Value, WalletRpcError> {
    let p: CreateWalletParams = parse_required_object(params, "create_wallet")?;
    validate_wallet_name(&p.name)?;
    if p.language != "en" {
        return Err(WalletRpcError::InvalidParams(
            "only language \"en\" is supported".into(),
        ));
    }

    // Short critical section: refuse if busy, reserve the opening slot,
    // snapshot config, then release the tenant mutex before slow work.
    let (base, network, daemon_address) = {
        let mut state = tenants.lock().await;
        if state.tenant.is_busy() {
            return Err(WalletRpcError::WalletAlreadyOpen);
        }
        let base = wallet_base(&state.wallet_dir, &p.name);
        if keys_path_from(&base).exists() {
            return Err(WalletRpcError::WalletFileExists);
        }
        state.tenant.begin_opening();
        (base, state.network, state.daemon_address.clone())
    };

    let created = create_wallet_engine(&base, network, &daemon_address, &p, kdf).await;
    let (engine, backup) = match created {
        Ok(v) => v,
        Err(e) => {
            tenants.lock().await.tenant.clear_opening();
            return Err(e);
        }
    };

    let handle = wallet_handle(&p.name, &engine, None);
    tenants.lock().await.tenant.set_open(p.name, engine);

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

/// Slow half of create: daemon connect + seed gen + Argon2 `Engine::create`.
/// Runs without holding the tenant mutex.
async fn create_wallet_engine(
    base: &Path,
    network: Network,
    daemon_address: &str,
    p: &CreateWalletParams,
    kdf: KdfParams,
) -> Result<(Engine<SoloSigner>, SeedBackup), WalletRpcError> {
    let daemon = make_daemon(daemon_address).await?;
    let password = Zeroizing::new(p.password.clone().into_bytes());
    let creds = Credentials::password_only(password.as_slice());

    let (master_seed, seed_format, backup) = generate_seed_material(network)?;

    let creation_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let create_params = EngineCreateParams {
        base_path: base,
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
    Ok((engine, backup))
}

pub(crate) async fn open_wallet(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    let p: OpenWalletParams = parse_required_object(params, "open_wallet")?;
    validate_wallet_name(&p.name)?;

    let (base, network, daemon_address) = {
        let mut state = tenants.lock().await;
        if state.tenant.is_busy() {
            return Err(WalletRpcError::WalletAlreadyOpen);
        }
        let base = wallet_base(&state.wallet_dir, &p.name);
        if !keys_path_from(&base).exists() {
            return Err(WalletRpcError::WalletFileNotFound);
        }
        state.tenant.begin_opening();
        (base, state.network, state.daemon_address.clone())
    };

    let opened = open_wallet_engine(&base, network, &daemon_address, &p).await;
    let (engine, restore_hint) = match opened {
        Ok(v) => v,
        Err(e) => {
            tenants.lock().await.tenant.clear_opening();
            return Err(e);
        }
    };

    let handle = wallet_handle(&p.name, &engine, restore_hint);
    tenants.lock().await.tenant.set_open(p.name, engine);
    Ok(json!({ "wallet": handle }))
}

/// Slow half of open: daemon connect + Argon2 `Engine::open_full`.
async fn open_wallet_engine(
    base: &Path,
    network: Network,
    daemon_address: &str,
    p: &OpenWalletParams,
) -> Result<(Engine<SoloSigner>, Option<i64>), WalletRpcError> {
    let daemon = make_daemon(daemon_address).await?;
    let password = Zeroizing::new(p.password.clone().into_bytes());
    let creds = Credentials::password_only(password.as_slice());

    let opened = tokio::task::block_in_place(|| {
        Engine::<SoloSigner>::open_full(base, &creds, network, daemon, SafetyOverrides::none())
    })
    .map_err(WalletRpcError::from)?;

    Ok(match opened {
        OpenedEngine::Loaded(w) => (w, None),
        OpenedEngine::Restored {
            wallet,
            from_height,
        } => (wallet, Some(from_height as i64)),
    })
}

pub(crate) async fn close_wallet(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    require_empty_object(params, "close_wallet")?;

    // Take the slot under a short mutex hold, then drop the guard before
    // try_unwrap / outstanding check / Engine::close (fsync / Argon2-free
    // but still file IO). Restore under a fresh lock if close cannot proceed.
    let (name, shared) = {
        let mut state = tenants.lock().await;
        state
            .tenant
            .take_open()
            .ok_or(WalletRpcError::WalletNotOpen)?
    };

    // Reclaim sole ownership before closing. If another task still holds a
    // clone (e.g. an in-flight refresh), restore the slot and fail loud rather
    // than evicting a still-live wallet we cannot actually close.
    let lock = match Arc::try_unwrap(shared) {
        Ok(lock) => lock,
        Err(shared) => {
            tenants.lock().await.tenant.restore_open(name, shared);
            return Err(WalletRpcError::InternalError(
                "cannot close: wallet engine still in use by another task".into(),
            ));
        }
    };
    let engine = lock.into_inner();

    // `Engine::close` consumes `self` and refuses when reservations are
    // outstanding — a refusal there would drop the engine and lose the wallet.
    // Check first (non-consuming) and re-install the wallet unchanged on refusal.
    let outstanding = engine.outstanding_pending_txs();
    if outstanding > 0 {
        tenants.lock().await.tenant.set_open(name, engine);
        return Err(WalletRpcError::from(OpenError::OutstandingPendingTx {
            count: outstanding,
        }));
    }

    // `credentials` is ignored on the steady-state close path.
    let creds = Credentials::password_only(b"");
    tokio::task::block_in_place(|| engine.close(&creds)).map_err(WalletRpcError::from)?;
    Ok(json!({}))
}

pub(crate) async fn change_password(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    let p: ChangePasswordParams = parse_required_object(params, "change_password")?;

    let shared = require_open_engine(tenants).await?;

    let old = Zeroizing::new(p.old_password.into_bytes());
    let new = Zeroizing::new(p.new_password.into_bytes());
    let old_creds = Credentials::password_only(old.as_slice());
    let new_creds = Credentials::password_only(new.as_slice());

    let mut engine = shared.write().await;
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
            let seed_hex = hex::encode(raw);
            let (master, _blob) = generate_account_from_raw_seed(&raw, derivation)
                .map_err(|e| WalletRpcError::InternalError(format!("raw account: {e}")))?;
            raw.zeroize();
            Ok((master, SeedFormat::Raw32, SeedBackup::RawHex(seed_hex)))
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
        capability: capability_mode_str(engine.capability()).to_owned(),
        network: network_str(engine.network()).to_owned(),
        restore_height_hint,
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

async fn make_daemon(daemon_address: &str) -> Result<DaemonClient, WalletRpcError> {
    let rpc = SimpleRequestRpc::new(daemon_address.to_owned())
        .await
        .map_err(|_e| WalletRpcError::DaemonUnreachable)?;
    Ok(DaemonClient::new(rpc))
}
