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
    Capability, CapabilityInput, Credentials, DaemonClient, Engine, EngineCreateParams, Network,
    OpenedEngine, PScanHandle, SoloSigner,
};
use shekyl_engine_file::paths::keys_path_from;
use shekyl_engine_file::SafetyOverrides;
use shekyl_engine_prefs::WalletPrefs;
use shekyl_rpc_transport::HttpRpc;
use tokio::sync::RwLock;
use zeroize::{Zeroize, Zeroizing};

use crate::error::WalletRpcError;
use crate::params::{parse_required_object, require_empty_object};
use crate::tenant::{require_open_engine, DaemonEndpoint, SharedEngine, TenantState};
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

/// Params for `restore_wallet`.
#[derive(Debug, Deserialize)]
struct RestoreWalletParams {
    name: String,
    password: String,
    mnemonic: String,
    /// Rescan floor: block height the wallet existed at. Optional; `0`
    /// (scan from genesis) when omitted.
    #[serde(default)]
    restore_height: Option<u64>,
    #[serde(default = "default_language")]
    language: String,
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
    let (base, network, daemon) = {
        let mut state = tenants.lock().await;
        if state.tenant.is_busy() {
            return Err(WalletRpcError::WalletAlreadyOpen);
        }
        let base = wallet_base(&state.wallet_dir, &p.name);
        if keys_path_from(&base).exists() {
            return Err(WalletRpcError::WalletFileExists);
        }
        state.tenant.begin_opening();
        (base, state.network, state.daemon.clone())
    };

    // Move password into Zeroizing before any slow work so the serde
    // String is consumed (no residual plaintext copy beside the wipeable vec).
    let password = Zeroizing::new(p.password.into_bytes());
    let created = create_wallet_engine(&base, network, &daemon, password, kdf).await;
    let (engine, backup) = match created {
        Ok(v) => v,
        Err(e) => {
            tenants.lock().await.tenant.clear_opening();
            return Err(e);
        }
    };

    let handle = wallet_handle(&p.name, &engine, None);
    // A freshly created wallet is a non-staker (no bond record), so
    // `start_pscan_if_staker` parks `None` here; the call is unconditional so
    // the embedder never branches on staking state (`81-no-protocol-knowledge`).
    let (shared, pscan) = match wrap_and_start_pscan(engine).await {
        Ok(v) => v,
        Err(e) => {
            tenants.lock().await.tenant.clear_opening();
            return Err(e);
        }
    };
    tenants.lock().await.tenant.set_open(p.name, shared, pscan);

    let mut result = json!({ "wallet": handle });
    match backup {
        // Move the String out (leave empty behind for Zeroizing to wipe):
        // no intermediate twin of the seed-backup material in memory.
        // zeroize 1.x has no into_inner; mem::take is the house pattern.
        SeedBackup::Mnemonic(mut m) => {
            result["mnemonic"] = Value::String(std::mem::take(&mut *m));
        }
        SeedBackup::RawHex(mut h) => {
            result["raw_seed_hex"] = Value::String(std::mem::take(&mut *h));
        }
    }
    Ok(result)
}

/// Slow half of create: daemon connect + seed gen + Argon2 `Engine::create`.
/// Runs without holding the tenant mutex.
async fn create_wallet_engine(
    base: &Path,
    network: Network,
    daemon: &DaemonEndpoint,
    password: Zeroizing<Vec<u8>>,
    kdf: KdfParams,
) -> Result<(Engine<SoloSigner>, SeedBackup), WalletRpcError> {
    let daemon = make_daemon(daemon).await?;
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

/// `restore_wallet` — recreate a wallet from its seed backup (WI-RPC-2a; the
/// deterministic inverse of `create_wallet`'s backup material).
///
/// Same tenant choreography as `create_wallet`: refuse-if-busy, reserve the
/// opening slot, slow work off the mutex, install or clear. The seed is key
/// material — it moves into a `Zeroizing` wrapper before any slow work and is
/// never echoed in errors or logs (rule 30). The seed format is
/// network-governed, matching create: mainnet/stagenet take a BIP-39 mnemonic,
/// testnet a 32-byte raw seed as hex. A seed that does not match the network's
/// format refuses as invalid params.
pub(crate) async fn restore_wallet(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
    kdf: KdfParams,
) -> Result<Value, WalletRpcError> {
    let p: RestoreWalletParams = parse_required_object(params, "restore_wallet")?;
    validate_wallet_name(&p.name)?;
    if p.language != "en" {
        return Err(WalletRpcError::InvalidParams(
            "only language \"en\" is supported".into(),
        ));
    }
    // The rescan floor is a u32 in the keys file; refuse out-of-range
    // instead of silently truncating.
    let restore_height = match p.restore_height {
        None => 0u32,
        Some(h) => u32::try_from(h)
            .map_err(|_| WalletRpcError::InvalidParams("restore_height out of range".into()))?,
    };
    // Seed material: consume the serde String immediately so every path —
    // including each early error return below — wipes it on drop.
    let mnemonic = Zeroizing::new(p.mnemonic);
    let password = Zeroizing::new(p.password.into_bytes());

    let (base, network, daemon) = {
        let mut state = tenants.lock().await;
        if state.tenant.is_busy() {
            return Err(WalletRpcError::WalletAlreadyOpen);
        }
        let base = wallet_base(&state.wallet_dir, &p.name);
        if keys_path_from(&base).exists() {
            return Err(WalletRpcError::WalletFileExists);
        }
        state.tenant.begin_opening();
        (base, state.network, state.daemon.clone())
    };

    let restored = restore_wallet_engine(
        &base,
        network,
        &daemon,
        password,
        &mnemonic,
        restore_height,
        kdf,
    )
    .await;
    let engine = match restored {
        Ok(v) => v,
        Err(e) => {
            tenants.lock().await.tenant.clear_opening();
            return Err(e);
        }
    };

    let restore_hint = (restore_height > 0).then_some(i64::from(restore_height));
    let handle = wallet_handle(&p.name, &engine, restore_hint);
    let (shared, pscan) = match wrap_and_start_pscan(engine).await {
        Ok(v) => v,
        Err(e) => {
            tenants.lock().await.tenant.clear_opening();
            return Err(e);
        }
    };
    tenants.lock().await.tenant.set_open(p.name, shared, pscan);

    // No seed backup in the result: the caller supplied the mnemonic.
    Ok(json!({ "wallet": handle }))
}

/// Slow half of restore: daemon connect + mnemonic derivation + Argon2
/// `Engine::create`. Runs without holding the tenant mutex.
async fn restore_wallet_engine(
    base: &Path,
    network: Network,
    daemon: &DaemonEndpoint,
    password: Zeroizing<Vec<u8>>,
    mnemonic: &str,
    restore_height: u32,
    kdf: KdfParams,
) -> Result<Engine<SoloSigner>, WalletRpcError> {
    let daemon = make_daemon(daemon).await?;
    let creds = Credentials::password_only(password.as_slice());

    // Seed format is network-governed, mirroring generate_seed_material on the
    // create path: mainnet/stagenet derive from a BIP-39 mnemonic; testnet
    // from a raw 32-byte seed (hex-encoded, as create returns it in
    // raw_seed_hex). Restoring a testnet wallet through the BIP-39 path would
    // wrongly reject it. Validation lives in the derivation; messages are
    // stable and detail-free — the seed is key material, never reflected
    // (rule 30).
    let (master_seed, seed_format) = match network {
        Network::Mainnet | Network::Stagenet => {
            let (master_seed, _blob) =
                generate_account_from_bip39(mnemonic, "", network_to_derivation(network)).map_err(
                    |_| {
                        WalletRpcError::InvalidParams(
                            "invalid mnemonic (or the network does not use BIP-39 seeds)".into(),
                        )
                    },
                )?;
            (master_seed, SeedFormat::Bip39)
        }
        Network::Testnet => {
            let decoded = Zeroizing::new(hex::decode(mnemonic.trim()).map_err(|_| {
                WalletRpcError::InvalidParams(
                    "invalid testnet seed (expected a 32-byte raw seed as hex)".into(),
                )
            })?);
            if decoded.len() != RAW_SEED_BYTES {
                return Err(WalletRpcError::InvalidParams(
                    "invalid testnet seed (expected a 32-byte raw seed as hex)".into(),
                ));
            }
            let mut raw = [0u8; RAW_SEED_BYTES];
            raw.copy_from_slice(&decoded);
            let derived = generate_account_from_raw_seed(&raw, network_to_derivation(network))
                .map_err(|_| WalletRpcError::InvalidParams("invalid testnet raw seed".into()));
            raw.zeroize();
            let (master_seed, _blob) = derived?;
            (master_seed, SeedFormat::Raw32)
        }
    };

    // A restored wallet's creation time is unknown; 0 keeps the scan floor
    // governed solely by restore_height.
    let create_params = EngineCreateParams {
        base_path: base,
        credentials: &creds,
        network,
        capability: CapabilityInput::Full {
            master_seed_64: &master_seed,
            seed_format,
        },
        creation_timestamp: 0,
        restore_height_hint: restore_height,
        kdf,
        overrides: SafetyOverrides::none(),
        prefs: WalletPrefs::default(),
    };

    let engine =
        tokio::task::block_in_place(|| Engine::<SoloSigner>::create(create_params, daemon))
            .map_err(WalletRpcError::from)?;
    drop(master_seed);
    Ok(engine)
}

pub(crate) async fn open_wallet(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    let p: OpenWalletParams = parse_required_object(params, "open_wallet")?;
    validate_wallet_name(&p.name)?;

    let (base, network, daemon) = {
        let mut state = tenants.lock().await;
        if state.tenant.is_busy() {
            return Err(WalletRpcError::WalletAlreadyOpen);
        }
        let base = wallet_base(&state.wallet_dir, &p.name);
        if !keys_path_from(&base).exists() {
            return Err(WalletRpcError::WalletFileNotFound);
        }
        state.tenant.begin_opening();
        (base, state.network, state.daemon.clone())
    };

    // Same password hand-off as create: consume the serde String into
    // Zeroizing before daemon connect / Argon2.
    let password = Zeroizing::new(p.password.into_bytes());
    let opened = open_wallet_engine(&base, network, &daemon, password).await;
    let (engine, restore_hint) = match opened {
        Ok(v) => v,
        Err(e) => {
            tenants.lock().await.tenant.clear_opening();
            return Err(e);
        }
    };

    let handle = wallet_handle(&p.name, &engine, restore_hint);
    // Auto-start the P-scan task for a staker (WI-1); a non-staker parks `None`.
    // A corrupt sealed P-scan state fails the open closed (see
    // `wrap_and_start_pscan`).
    let (shared, pscan) = match wrap_and_start_pscan(engine).await {
        Ok(v) => v,
        Err(e) => {
            tenants.lock().await.tenant.clear_opening();
            return Err(e);
        }
    };
    tenants.lock().await.tenant.set_open(p.name, shared, pscan);
    Ok(json!({ "wallet": handle }))
}

/// Slow half of open: daemon connect + Argon2 `Engine::open_full`.
async fn open_wallet_engine(
    base: &Path,
    network: Network,
    daemon: &DaemonEndpoint,
    password: Zeroizing<Vec<u8>>,
) -> Result<(Engine<SoloSigner>, Option<i64>), WalletRpcError> {
    let daemon = make_daemon(daemon).await?;
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
        } => (
            wallet,
            // Match other height projections in this crate (queries/project):
            // saturate rather than wrap on values > i64::MAX.
            Some(i64::try_from(from_height).unwrap_or(i64::MAX)),
        ),
    })
}

/// Take the open tenant and fully close its engine — the shared close
/// choreography (`close_wallet` and the first-stake intent reopen both use
/// it, so the restore-on-failure semantics cannot diverge): scan shutdown →
/// sole-ownership reclaim (restore + fail loud if another task holds a
/// clone) → persist-for-close (restore + fail loud on I/O). On success the
/// tenant slot is left in the **closing** reservation; the caller either
/// `clear_closing`s (a plain close) or, for a reopen, `clear_closing`s and
/// then `begin_opening`s (in that order — `begin_opening` debug-asserts
/// `!is_busy()`, so the closing reservation must drop first; the reopen
/// path does both under one tenant-mutex hold so no other call can slip
/// into the gap).
///
/// `expected_name`, when given, refuses (without touching the tenant) if
/// the currently open wallet is not the named one — the guard that keeps a
/// close-and-reopen caller from closing a wallet that was swapped in
/// between its inspection phase and this call.
async fn take_and_close_tenant(
    tenants: &tokio::sync::Mutex<TenantState>,
    expected_name: Option<&str>,
) -> Result<String, WalletRpcError> {
    let (name, shared, pscan) = {
        let mut state = tenants.lock().await;
        if let Some(expected) = expected_name {
            // Same mutex hold as `take_open`: check-then-take is atomic.
            if state.tenant.open_name() != Some(expected) {
                return Err(WalletRpcError::InternalError(
                    "the open wallet changed while the request was in flight; \
                     nothing was closed — retry"
                        .into(),
                ));
            }
        }
        state
            .tenant
            .take_open()
            .ok_or(WalletRpcError::WalletNotOpen)?
    };
    if let Some(handle) = pscan {
        handle.shutdown().await;
    }
    let lock = match Arc::try_unwrap(shared) {
        Ok(lock) => lock,
        Err(shared) => {
            let pscan = restart_pscan(&shared).await;
            tenants
                .lock()
                .await
                .tenant
                .restore_open(name, shared, pscan);
            return Err(WalletRpcError::InternalError(
                "cannot close: wallet engine still in use by another task".into(),
            ));
        }
    };
    let engine = lock.into_inner();
    if let Err(e) = tokio::task::block_in_place(|| engine.persist_for_close()) {
        let shared: SharedEngine = Arc::new(RwLock::new(engine));
        let pscan = restart_pscan(&shared).await;
        tenants.lock().await.tenant.set_open(name, shared, pscan);
        return Err(WalletRpcError::from(e));
    }
    drop(engine);
    Ok(name)
}

pub(crate) async fn close_wallet(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    require_empty_object(params, "close_wallet")?;
    take_and_close_tenant(tenants, None).await?;
    tenants.lock().await.tenant.clear_closing();
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

// `Zeroizing` so seed-backup material is wiped on drop if create fails or
// is abandoned before the RPC response is built. The value is held across
// `wrap_and_start_pscan` (an await) until export — not a long-lived wallet
// field; matching `shekyl-genesis-tool`'s wrap-at-birth of the same values.
// The export path moves the String into the JSON response (caller's to protect).
enum SeedBackup {
    Mnemonic(Zeroizing<String>),
    RawHex(Zeroizing<String>),
}

fn generate_seed_material(
    network: Network,
) -> Result<(Zeroizing<[u8; MASTER_SEED_BYTES]>, SeedFormat, SeedBackup), WalletRpcError> {
    let derivation = network_to_derivation(network);
    match network {
        Network::Mainnet | Network::Stagenet => {
            let mut entropy = [0u8; SHEKYL_BIP39_ENTROPY_BYTES];
            OsRng.fill_bytes(&mut entropy);
            // Wrap at birth (genesis-tool order) so the mnemonic is never a
            // bare String through account generation.
            let mnemonic = Zeroizing::new(mnemonic_from_entropy(&entropy).map_err(|e| {
                WalletRpcError::InternalError(format!("mnemonic_from_entropy: {e}"))
            })?);
            entropy.zeroize();
            let (master, _blob) = generate_account_from_bip39(&mnemonic, "", derivation)
                .map_err(|e| WalletRpcError::InternalError(format!("bip39 account: {e}")))?;
            Ok((master, SeedFormat::Bip39, SeedBackup::Mnemonic(mnemonic)))
        }
        Network::Testnet => {
            let mut raw = [0u8; RAW_SEED_BYTES];
            OsRng.fill_bytes(&mut raw);
            let seed_hex = Zeroizing::new(hex::encode(raw));
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

/// Build a [`DaemonClient`] for the tenant's daemon endpoint. Shared with
/// the wallet-less proof-check handlers (`proofs.rs`), which dial the
/// verifier's daemon without any open wallet — through the same endpoint
/// (address + proxy), so a proof check never bypasses the proxy posture.
pub(crate) async fn make_daemon(daemon: &DaemonEndpoint) -> Result<DaemonClient, WalletRpcError> {
    // SOCKS5h when a proxy is set: the daemon's block scan then resolves the
    // node hostname *at the proxy*, never leaking it to the local resolver.
    let rpc = HttpRpc::with_proxy(daemon.address.clone(), daemon.proxy.clone())
        .await
        .map_err(|e| {
            // Startup already refused a malformed address/proxy
            // (`validate_endpoint` in `server`), so what remains here is
            // connectivity-shaped; the client-facing error stays stable, but
            // the cause is never discarded (rule 82) — it lands in the
            // server log.
            tracing::warn!(error = %e, "daemon transport construction failed");
            WalletRpcError::DaemonUnreachable
        })?;
    Ok(DaemonClient::new(rpc))
}

/// Wrap a freshly opened / created engine in its shared arc and, for a staker,
/// spawn the driving P-scan task (WI-1) — the **sole production call site** for
/// [`Engine::start_pscan_if_staker`]. Returns the arc plus the embedder-held
/// [`PScanHandle`] (`None` for a non-staker), which the tenant parks for the
/// wallet's open lifetime and [`close_wallet`] shuts down.
///
/// A staker whose sealed P-scan state cannot load fails **closed** here
/// (`PScanStartError::LoadFailed` → the caller aborts the open): a staker must
/// not open into a state where its firewall scan is silently not running
/// (`00-mission` priority 2 — privacy is not a degraded mode).
async fn wrap_and_start_pscan(
    engine: Engine<SoloSigner>,
) -> Result<(SharedEngine, Option<PScanHandle>), WalletRpcError> {
    let shared: SharedEngine = Arc::new(RwLock::new(engine));
    let pscan = match Engine::start_pscan_if_staker(shared.clone()).await {
        Ok(handle) => handle,
        Err(e) => {
            // Log the detailed cause server-side — the boxed error can carry a
            // local path / internal schema detail that the stable client-facing
            // `WalletRpcError` deliberately withholds. Same discipline as
            // `restart_pscan`, and the fail-closed reason is spelled here.
            tracing::warn!(
                error = %e,
                "a staker's sealed P-scan state failed to load; aborting the open \
                 (fail-closed — a staker must not open with its firewall scan dark)"
            );
            return Err(e.into());
        }
    };
    Ok((shared, pscan))
}

/// Params for `stake` (the wallet-level first-stake entry,
/// `ARCHIVAL_STAKE_ACTIVATION_PLAN.md` §5.1 SA-DQ-1/SA-R1-d).
#[derive(serde::Deserialize)]
struct StakeParams {
    /// Wallet password — load-bearing, not UX: a mid-session wallet holds no
    /// seed (dropped at open), and only a credentialed reopen re-materializes
    /// it for the bootstrap persona derivation. Crosses a local transport
    /// only (SA-R1-d pin 2).
    password: String,
}

/// `stake` — make the open wallet a staker (the #332 activation entry).
///
/// The user asks to stake; the protocol dance is hidden (rule 81). What
/// actually runs (`ARCHIVAL_STAKE_ACTIVATION_PLAN.md` §5.0, SA-R1-b order):
///
/// 1. Idempotency fast-path reads + `Capability::Full` gate (SA-DQ-1).
/// 2. If no StakeEngine is resident (fresh first-stake): a credentialed
///    close → reopen **with the transient first-stake intent** (SA-R1-a) so
///    the actor spawns pre-persist, then the on-demand P-scan starts (the
///    `stake_in` funding must be scan-discovered before it can validate).
/// 3. The engine-side continuation (`Engine::first_stake`): preflight sweep
///    (W1-clean) → `persist_bond_record` → sign/assemble → the durable
///    `.wallet.pending` seal. **No broadcast** — the bond dispatch driver
///    sends at its GF-7 offset (SA-DQ-5, hold-across-reopen).
///
/// A refusal (`-29500..-29503`) leaves the wallet open and, for `-29500`,
/// wrote nothing durable — fund/sync and call `stake` again. A mid-flow
/// failure after the durable point is the W2 window; re-invoking `stake`
/// resumes it (the engine detects the durable-but-postless slot).
pub(crate) async fn stake(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    let p: StakeParams = parse_required_object(params, "stake")?;
    // Same password hand-off as create/open/change_password: consume the
    // serde String into Zeroizing before ANY other work, so every path —
    // including the continue path that never uses it and every early error
    // return — wipes it on drop (rule 35).
    let password = Zeroizing::new(p.password.into_bytes());

    // Phase 1 — inspect the open tenant: capability gate, idempotency reads,
    // slot choice (the engine's monotone cursor for a fresh stake; the
    // recorded bonded slot for a W2 resume — the user never names a slot,
    // rule 81). The tenant lock is held once for the engine clone, the
    // wallet name (which binds the later close to THIS wallet — a swapped
    // tenant refuses instead of being closed), and the parked-scan flag.
    // Auth note: on the continue/resume path (a StakeEngine already
    // resident) the password is NOT re-verified — the open session is the
    // authorization boundary, exactly as for every other method on an open
    // wallet; the password is consumed only when a credentialed reopen is
    // actually needed. Slot note: the resume pick is the FIRST bonded slot —
    // the single-slot genesis case; a multi-slot W2 resume re-invokes after
    // the arm-#3 open-time GC has collected the true phantoms.
    //
    // This read is deliberately PRE-reconcile and therefore defeasible: the
    // credentialed reopen below runs the SP-R0 open-time reconcile, which may
    // move the record: collect this slot as a phantom (arm #3) or burn the
    // cursor past it (arm #2). The engine re-validates against its own
    // reconciled state and refuses `WrongSlot`, surfaced as the `-29503`
    // domain code (re-invoke, nothing written) — never as an internal fault.
    // (Arm #4 adoption resolves to `-29502 AlreadyStaked` instead: the wallet
    // discovered it already holds a confirmed bond.) Resolving the
    // slot *after* reconciliation would delete the staleness outright, but the
    // elect tag is applied at spawn from the intent, so that is a change to
    // the intent's shape (`open_full_with_first_stake_intent`) and the spawn
    // gate — a different validation surface, tracked in `FOLLOWUPS.md`.
    let (shared, name, has_scan) = {
        let state = tenants.lock().await;
        let shared = state.tenant.engine().ok_or(WalletRpcError::WalletNotOpen)?;
        let name = state
            .tenant
            .open_name()
            .ok_or(WalletRpcError::WalletNotOpen)?
            .to_owned();
        (shared, name, state.tenant.has_pscan())
    };
    let (needs_intent_open, slot) = {
        let g = shared.read().await;
        let capability = g.capability();
        if capability != Capability::Full {
            return Err(WalletRpcError::CapabilityForbids {
                capability: capability_mode_str(capability).to_owned(),
            });
        }
        let ledger = g.ledger();
        let staking = &ledger.staking;
        let slot = if staking.staking_enabled {
            staking
                .bonded_slots
                .first()
                .copied()
                .unwrap_or_else(|| staking.monotone_current_slot_from_record())
        } else {
            staking.monotone_current_slot_from_record()
        };
        // A resident actor with NO parked scan (a start failure on an
        // earlier intent reopen, or a scan lost to a failed-close restore)
        // also takes the reopen: retrying into a dark scan would spin on a
        // funding discovery that can never happen (fail-closed, self-heal).
        (!g.has_stake_engine() || !has_scan, slot)
    };

    // The engine the continuation runs on IS the engine that was inspected
    // (continue path) or the one the intent reopen just installed — never a
    // re-acquired tenant slot a concurrent open could have swapped.
    let shared = if needs_intent_open {
        // Sole-ownership: this clone must drop before the close inside the
        // reopen reclaims the arc.
        drop(shared);
        reopen_with_first_stake_intent(tenants, &name, password, slot).await?
    } else {
        drop(password); // unused on the continue path — zeroizes here
        shared
    };
    let outcome = Engine::first_stake(shared, slot).await.map_err(|e| {
        use shekyl_engine_core::FirstStakeError as E;
        match e {
            E::BondInFlight => WalletRpcError::StakeInFlight,
            E::AlreadyStaked => WalletRpcError::AlreadyStaked,
            E::Funding(detail) => WalletRpcError::StakeNotReady { detail },
            // Daemon-side fee failure: the build-path code whose remedy
            // (check the daemon, retry) actually matches — never the
            // "fund and retry" misdiagnosis (rule 82).
            E::FeeEstimate(_) => WalletRpcError::FeeEstimationFailed,
            // W1-clean internal failures: state file / persona-id reads.
            // Funding cannot fix these, so they are not `-29500`.
            E::State(d) => WalletRpcError::InternalError(format!(
                "stake preflight failed ({d}); nothing durable was written"
            )),
            E::NoStakeEngine => {
                WalletRpcError::InternalError("stake: no stake engine after intent open".into())
            }
            // NOT an internal fault: the slot above is read from the engine
            // BEFORE the credentialed reopen, and that reopen runs the SP-R0
            // open-time reconcile — which can GC the picked slot as a phantom
            // (arm #3) or burn the cursor past it for a retired persona
            // (arm #2), either of which moves the record out from under the
            // read. The engine refuses fail-closed; the operator's remedy is to
            // call `stake` again, which reads the reconciled record. Rule 82: a
            // legitimate domain state gets a domain code, never `-32603`.
            //
            // Arm #4 adoption lands on `-29502 AlreadyStaked` instead, not
            // here: it re-arms `staking_enabled` with a slot that has a
            // matching bond post, so `first_stake`'s already-staked scan wins
            // the race to refuse — and it is the right answer.
            E::WrongSlot { .. } => WalletRpcError::StakeRecordMoved,
            // W2: durable slot may exist without a post — a `stake` re-invoke
            // resumes. Say so in the operator-facing text (rule 82).
            E::Persist(d) | E::Engine(d) => WalletRpcError::InternalError(format!(
                "stake failed mid-flow ({d}); call stake again to resume"
            )),
        }
    })?;

    Ok(json!({
        "slot": outcome.p_slot,
        "swept_inputs": outcome.swept_inputs,
        "resumed": outcome.resumed,
        "state": "pending_dispatch",
    }))
}

/// The SA-R1-a credentialed reopen: close the open tenant (the full
/// `close_wallet` discipline — scan shutdown, sole-ownership reclaim,
/// persist-for-close) and reopen it carrying the **transient** first-stake
/// intent, then start the on-demand P-scan (the intent-spawned actor makes
/// the persona scannable; `start_pscan_if_staker` would park `None` since
/// `staking_enabled` is still false). Returns the installed engine arc, so
/// the caller continues on exactly the wallet this function opened.
///
/// Ordering is the guardrail: **everything refusable happens before the
/// close.** The password is verified against the sealed envelope and the
/// daemon connection established while the wallet is still open, so a
/// mistyped password or an unreachable daemon refuses with the wallet
/// untouched — a failed `stake` must not log the user out. After the close,
/// the only reopen failures left are real file/system faults; those attempt
/// a best-effort plain reopen (same verified credentials) before giving up,
/// so even that residue usually restores the session.
async fn reopen_with_first_stake_intent(
    tenants: &tokio::sync::Mutex<TenantState>,
    expected_name: &str,
    password: Zeroizing<Vec<u8>>,
    slot: u32,
) -> Result<SharedEngine, WalletRpcError> {
    let (base, network, endpoint) = {
        let state = tenants.lock().await;
        (
            wallet_base(&state.wallet_dir, expected_name),
            state.network,
            state.daemon.clone(),
        )
    };

    // Verify-then-close (envelope KDF + AEAD auth, lock-free read; see
    // `WalletFile::verify_password`): the common failure — a wrong
    // password — refuses HERE, wallet still open.
    tokio::task::block_in_place(|| {
        shekyl_engine_file::WalletFile::verify_password(&base, password.as_slice())
    })
    .map_err(|e| match e {
        shekyl_engine_file::WalletFileError::Envelope(_) => WalletRpcError::InvalidPassword,
        other => WalletRpcError::InternalError(format!("stake: password verification: {other}")),
    })?;
    // Connect-then-close: a daemon refusal also lands pre-close.
    let daemon = make_daemon(&endpoint).await?;

    // Close via the shared choreography (identical restore-on-failure
    // semantics as `close_wallet`), name-bound so a concurrently swapped
    // wallet refuses instead of being closed, then transition the
    // reservation closing → opening under ONE mutex hold (no gap a
    // concurrent open could claim).
    let name = take_and_close_tenant(tenants, Some(expected_name)).await?;
    {
        let mut state = tenants.lock().await;
        state.tenant.clear_closing();
        state.tenant.begin_opening();
    }

    // Reopen with the intent (the transient SA-R1-a parameter — it exists
    // only on this call path and is `None` in every other open).
    let reopened = tokio::task::block_in_place(|| {
        let creds = Credentials::password_only(password.as_slice());
        Engine::<SoloSigner>::open_full_with_first_stake_intent(
            &base,
            &creds,
            network,
            daemon,
            SafetyOverrides::none(),
            slot,
        )
    });
    let engine = match reopened {
        Ok(OpenedEngine::Loaded(w)) | Ok(OpenedEngine::Restored { wallet: w, .. }) => w,
        Err(e) => {
            // Credentials verified and daemon connected above, so this is a
            // real file/system fault. Best-effort restore: a plain reopen
            // with the same verified password, re-arming the scan for a
            // staker — the user should not be logged out by a fault in a
            // non-close RPC.
            let restored = async {
                let pw = Zeroizing::new(password.as_slice().to_vec());
                let (engine, _hint) = open_wallet_engine(&base, network, &endpoint, pw).await?;
                wrap_and_start_pscan(engine).await
            }
            .await;
            let mut state = tenants.lock().await;
            match restored {
                Ok((shared, pscan)) => {
                    state.tenant.set_open(expected_name, shared, pscan);
                    tracing::warn!(
                        error = %e,
                        "first-stake intent reopen failed; the wallet was restored open \
                         without the intent"
                    );
                    return Err(WalletRpcError::InternalError(format!(
                        "stake: intent reopen failed ({e}); the wallet remains open — retry"
                    )));
                }
                Err(restore_err) => {
                    state.tenant.clear_opening();
                    tracing::error!(
                        error = %e,
                        restore_error = %restore_err,
                        "first-stake intent reopen failed AND the restore reopen failed; \
                         the wallet is closed"
                    );
                    return Err(WalletRpcError::InternalError(format!(
                        "stake: intent reopen failed ({e}) and the wallet could not be \
                         restored open; run open_wallet"
                    )));
                }
            }
        }
    };

    // On-demand P-scan under intent (fail-closed: without the scan the
    // `stake_in` funding can never validate, so a dark scan here is a
    // guaranteed-stuck stake, not a degraded one). On a start failure the
    // wallet stays open with the actor resident and NO parked scan — the
    // exact state the `stake` entry's `has_pscan` check routes back through
    // this reopen, so a retry re-attempts the scan instead of spinning dark.
    let shared: SharedEngine = Arc::new(RwLock::new(engine));
    match Engine::start_pscan(shared.clone()).await {
        Ok(handle) => {
            tenants
                .lock()
                .await
                .tenant
                .set_open(name, shared.clone(), Some(handle));
            Ok(shared)
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "first-stake intent reopen: on-demand P-scan failed to start; the next \
                 stake retry will reopen and re-attempt it"
            );
            tenants.lock().await.tenant.set_open(name, shared, None);
            Err(WalletRpcError::InternalError(format!(
                "stake: persona scan failed to start ({e}); wallet remains open — retry"
            )))
        }
    }
}

/// Re-arm the P-scan task on a restore path (a close that could not complete
/// leaves the wallet open). Unlike [`wrap_and_start_pscan`], a start failure
/// here degrades to `None` rather than propagating: the restore must not itself
/// fail and re-strand the engine, and the primary error the caller returns is
/// the close failure, not this. The failure is logged (never silent), and the
/// dark-scan window lasts only until the next successful close / reopen (the
/// `stake` entry also self-heals it: a resident actor with no parked scan
/// takes the intent reopen, which re-arms the scan).
async fn restart_pscan(shared: &SharedEngine) -> Option<PScanHandle> {
    match Engine::start_pscan_if_staker(shared.clone()).await {
        Ok(handle) => handle,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "failed to re-arm the P-scan task while restoring an open wallet after a \
                 non-completing close; the wallet stays open but its firewall scan is not \
                 running until the next close/reopen"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{close_wallet, create_wallet, open_wallet, restore_wallet, stake};
    use crate::tenant::{DaemonEndpoint, TenantState};

    use serde_json::json;
    use shekyl_crypto_pq::wallet_envelope::KdfParams;
    use shekyl_engine_core::Network;
    use shekyl_engine_core::__test_helpers::make_staker_for_test;
    use tokio::sync::Mutex;

    /// The fastest valid Argon2 profile (`m_log2` lower bound 8, `t`/`p` = 1) —
    /// the wallet-envelope validator documents this loose lower bound precisely
    /// so fixtures need not pay the production KDF cost.
    fn fast_kdf() -> KdfParams {
        KdfParams {
            m_log2: 8,
            t: 1,
            p: 1,
        }
    }

    fn tenants_in(dir: &std::path::Path) -> Mutex<TenantState> {
        Mutex::new(TenantState::new(
            dir.to_path_buf(),
            Network::Testnet,
            // A never-connecting daemon: create/open issue no eager RPC (the
            // engine tolerates an unreachable daemon; the P-scan task's first
            // tip fetch fails-and-retries inside the spawned loop), so the
            // lifecycle wiring is exercised without a live node.
            DaemonEndpoint {
                address: "http://127.0.0.1:1".to_string(),
                proxy: None,
            },
        ))
    }

    async fn assert_pscan(tenants: &Mutex<TenantState>, expected: bool, ctx: &str) {
        assert_eq!(tenants.lock().await.tenant.has_pscan(), expected, "{ctx}");
    }

    /// Non-staker lifecycle: neither create nor open parks a P-scan handle, and
    /// both close cleanly. The unconditional `start_pscan_if_staker` call is the
    /// quiet `Ok(None)` path here (the embedder never branches on staking state).
    #[tokio::test(flavor = "multi_thread")]
    async fn non_staker_open_parks_no_pscan_handle() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tenants = tenants_in(dir.path());

        create_wallet(
            &tenants,
            &json!({"name": "plain", "password": "pw"}),
            fast_kdf(),
        )
        .await
        .expect("create");
        assert_pscan(&tenants, false, "a fresh non-staker create parks no handle").await;

        close_wallet(&tenants, &json!({}))
            .await
            .expect("close after create");

        open_wallet(&tenants, &json!({"name": "plain", "password": "pw"}))
            .await
            .expect("reopen");
        assert_pscan(&tenants, false, "a non-staker reopen parks no handle").await;

        close_wallet(&tenants, &json!({}))
            .await
            .expect("close after reopen");
    }

    /// Staker lifecycle — **the check that survives `pub`.** Once the wallet is a
    /// staker, `open_wallet` spawns the StakeEngine and the embedder auto-starts
    /// the P-scan task (a parked handle), and `close_wallet` shuts that task down
    /// before reclaiming the engine arc. Deleting the start wiring makes the
    /// staker reopen park no handle (first assert fails); deleting the
    /// shutdown-before-`try_unwrap` wiring makes the final close fail-loud as
    /// "still in use" (last step fails). A `pub` fn in a lib crate cannot be
    /// caught by `dead_code`, so this behavioral gate is what keeps the call
    /// site live.
    #[tokio::test(flavor = "multi_thread")]
    async fn staker_open_parks_a_pscan_handle_and_close_shuts_it_down() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tenants = tenants_in(dir.path());

        // Create (non-staker), then make the wallet a staker by persisting a bond
        // record on the open engine — the only route to `staking_enabled` with no
        // RPC staking entry yet — and reopen so the open path spawns the
        // StakeEngine.
        create_wallet(
            &tenants,
            &json!({"name": "staker", "password": "pw"}),
            fast_kdf(),
        )
        .await
        .expect("create");
        assert_pscan(
            &tenants,
            false,
            "the staker wallet is still a non-staker at create time",
        )
        .await;

        {
            let shared = tenants
                .lock()
                .await
                .tenant
                .engine()
                .expect("engine open after create");
            let engine = shared.read().await;
            make_staker_for_test(&engine, 3).expect("persist bond record → staking_enabled");
        }

        close_wallet(&tenants, &json!({}))
            .await
            .expect("close after becoming a staker");

        open_wallet(&tenants, &json!({"name": "staker", "password": "pw"}))
            .await
            .expect("reopen staker");
        assert_pscan(
            &tenants,
            true,
            "a staker reopen auto-starts the P-scan task (start wiring)",
        )
        .await;

        // shutdown-before-try_unwrap: a live task's clone of the engine arc would
        // make `Arc::try_unwrap` fail and surface as the "still in use" error.
        close_wallet(&tenants, &json!({}))
            .await
            .expect("close shuts the P-scan task down and succeeds (shutdown wiring)");
        assert_pscan(&tenants, false, "close clears the parked handle").await;
    }

    /// The `stake` handler end-to-end against the never-connecting daemon:
    /// the full SA-R1-a intent dance runs (close → reopen-with-intent →
    /// actor + on-demand P-scan parked), the continuation fails W1-clean at
    /// the first daemon-touching pre-persist step — reported as `-29102`
    /// (fee estimation), the code whose remedy matches, NOT the `-29500`
    /// "fund and retry" misdiagnosis (rule 82) — the wallet REMAINS OPEN as
    /// an intent-spawned tenant, and a retry takes the continue path (no
    /// second reopen) to the same clean outcome.
    #[tokio::test(flavor = "multi_thread")]
    async fn stake_runs_the_intent_dance_and_fails_w1_clean_at_the_daemon_seam() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tenants = tenants_in(dir.path());

        // Not open yet: WalletNotOpen.
        let err = stake(&tenants, &json!({ "password": "pw" }))
            .await
            .expect_err("no wallet open");
        assert!(matches!(err, crate::error::WalletRpcError::WalletNotOpen));

        create_wallet(
            &tenants,
            &json!({ "name": "stakeme", "password": "pw" }),
            fast_kdf(),
        )
        .await
        .expect("create");

        // Param shape: password required.
        let err = stake(&tenants, &json!({})).await.expect_err("params");
        assert!(matches!(
            err,
            crate::error::WalletRpcError::InvalidParams(_)
        ));

        // The real call: intent dance + W1-clean daemon-fault diagnosis.
        let err = stake(&tenants, &json!({ "password": "pw" }))
            .await
            .expect_err("unreachable daemon fails pre-persist");
        assert!(
            matches!(err, crate::error::WalletRpcError::FeeEstimationFailed),
            "got {err:?}"
        );
        // The wallet stayed open, now intent-spawned with the scan parked.
        {
            let shared = crate::tenant::require_open_engine(&tenants)
                .await
                .expect("wallet still open after refusal");
            let g = shared.read().await;
            assert!(g.has_stake_engine(), "intent open spawned the actor");
            assert!(
                !g.ledger().staking.staking_enabled,
                "W1: refusal wrote nothing durable"
            );
        }
        assert_pscan(&tenants, true, "on-demand P-scan parked under intent").await;

        // Retry: the continue path (actor resident + scan parked, no
        // reopen) — same clean outcome, still nothing durable.
        let err = stake(&tenants, &json!({ "password": "pw" }))
            .await
            .expect_err("retry fails identically");
        assert!(matches!(
            err,
            crate::error::WalletRpcError::FeeEstimationFailed
        ));

        close_wallet(&tenants, &json!({})).await.expect("close");
    }

    /// A Stagenet tenant dir (mainnet/stagenet wallets carry the BIP-39
    /// backup that `restore_wallet` consumes; testnet is raw-seed).
    fn stagenet_tenants_in(dir: &std::path::Path) -> Mutex<TenantState> {
        Mutex::new(TenantState::new(
            dir.to_path_buf(),
            Network::Stagenet,
            DaemonEndpoint {
                address: "http://127.0.0.1:1".to_string(),
                proxy: None,
            },
        ))
    }

    /// The WI-RPC-2a restore contract: create → back up the mnemonic →
    /// restore under a new name reproduces the same primary address, and no
    /// backup material is echoed by the restore.
    #[tokio::test(flavor = "multi_thread")]
    async fn restore_round_trips_the_primary_address() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tenants = stagenet_tenants_in(dir.path());

        let created = create_wallet(
            &tenants,
            &json!({ "name": "orig", "password": "pw" }),
            fast_kdf(),
        )
        .await
        .expect("create");
        let mnemonic = created["mnemonic"].as_str().expect("mnemonic").to_owned();
        let orig_addr = crate::queries::get_primary_address(&tenants, &json!({}))
            .await
            .expect("address")["address"]
            .as_str()
            .expect("string")
            .to_owned();
        close_wallet(&tenants, &json!({})).await.expect("close");

        let restored = restore_wallet(
            &tenants,
            &json!({
                "name": "rest",
                "password": "other-pw",
                "mnemonic": mnemonic,
                "restore_height": 0,
            }),
            fast_kdf(),
        )
        .await
        .expect("restore");
        assert!(
            restored.get("mnemonic").is_none() && restored.get("raw_seed_hex").is_none(),
            "restore must not echo backup material"
        );
        assert_eq!(restored["wallet"]["name"], "rest");

        let rest_addr = crate::queries::get_primary_address(&tenants, &json!({}))
            .await
            .expect("address")["address"]
            .as_str()
            .expect("string")
            .to_owned();
        assert_eq!(orig_addr, rest_addr, "restore must reproduce the account");
        close_wallet(&tenants, &json!({})).await.expect("close");
    }

    /// Restore refusals: invalid mnemonic and raw-seed networks are
    /// `-32602` with a stable, mnemonic-free message; a name collision is
    /// `-29002`; an over-u32 restore_height refuses instead of truncating.
    /// Every refusal leaves the tenant idle (a follow-up create works).
    #[tokio::test(flavor = "multi_thread")]
    async fn restore_refusals_are_typed_and_leave_the_tenant_idle() {
        use crate::error::WalletRpcError;

        let dir = tempfile::tempdir().expect("tempdir");
        let tenants = stagenet_tenants_in(dir.path());

        let bad = restore_wallet(
            &tenants,
            &json!({ "name": "w", "password": "pw", "mnemonic": "not a mnemonic" }),
            fast_kdf(),
        )
        .await
        .expect_err("invalid mnemonic");
        match bad {
            WalletRpcError::InvalidParams(msg) => {
                assert!(!msg.contains("not a mnemonic"), "must not echo the input")
            }
            other => panic!("expected InvalidParams, got {other:?}"),
        }

        let too_high = restore_wallet(
            &tenants,
            &json!({
                "name": "w",
                "password": "pw",
                "mnemonic": "x",
                "restore_height": u64::from(u32::MAX) + 1,
            }),
            fast_kdf(),
        )
        .await
        .expect_err("restore_height out of range");
        assert!(matches!(too_high, WalletRpcError::InvalidParams(_)));

        // Tenant is idle after refusals: a real create works, and restoring
        // over its file refuses as a collision.
        let created = create_wallet(
            &tenants,
            &json!({ "name": "w", "password": "pw" }),
            fast_kdf(),
        )
        .await
        .expect("create after refusals");
        let mnemonic = created["mnemonic"].as_str().expect("mnemonic").to_owned();
        close_wallet(&tenants, &json!({})).await.expect("close");
        let collision = restore_wallet(
            &tenants,
            &json!({ "name": "w", "password": "pw", "mnemonic": mnemonic }),
            fast_kdf(),
        )
        .await
        .expect_err("file exists");
        assert!(matches!(collision, WalletRpcError::WalletFileExists));

        // Raw-seed network: a testnet tenant restores from a 32-byte raw seed
        // (hex), so garbage that is neither valid hex nor 32 bytes refuses as
        // typed InvalidParams (the positive round-trip is covered separately).
        let tdir = tempfile::tempdir().expect("tempdir");
        let testnet = tenants_in(tdir.path());
        let refused = restore_wallet(
            &testnet,
            &json!({ "name": "t", "password": "pw", "mnemonic": "x" }),
            fast_kdf(),
        )
        .await
        .expect_err("not a 32-byte raw seed");
        match refused {
            WalletRpcError::InvalidParams(msg) => {
                assert!(
                    !msg.contains('x') || msg.contains("hex"),
                    "must not echo the input"
                )
            }
            other => panic!("expected InvalidParams, got {other:?}"),
        }
    }

    /// #5 regression: a testnet wallet is raw-seed, so `restore_wallet` must
    /// accept the `raw_seed_hex` that `create_wallet` returns and reproduce the
    /// same primary address — the BIP-39-only path made testnet wallets
    /// unrecoverable.
    #[tokio::test(flavor = "multi_thread")]
    async fn testnet_restore_round_trips_the_raw_seed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tenants = tenants_in(dir.path());

        let created = create_wallet(
            &tenants,
            &json!({ "name": "orig", "password": "pw" }),
            fast_kdf(),
        )
        .await
        .expect("create");
        let raw_seed_hex = created["raw_seed_hex"]
            .as_str()
            .expect("testnet create returns raw_seed_hex")
            .to_owned();
        assert!(
            created.get("mnemonic").is_none(),
            "testnet create must not return a BIP-39 mnemonic"
        );
        let orig_addr = crate::queries::get_primary_address(&tenants, &json!({}))
            .await
            .expect("address")["address"]
            .as_str()
            .expect("string")
            .to_owned();
        close_wallet(&tenants, &json!({})).await.expect("close");

        let restored = restore_wallet(
            &tenants,
            &json!({
                "name": "rest",
                "password": "other-pw",
                "mnemonic": raw_seed_hex,
                "restore_height": 0,
            }),
            fast_kdf(),
        )
        .await
        .expect("testnet raw-seed restore");
        assert_eq!(restored["wallet"]["name"], "rest");

        let rest_addr = crate::queries::get_primary_address(&tenants, &json!({}))
            .await
            .expect("address")["address"]
            .as_str()
            .expect("string")
            .to_owned();
        assert_eq!(
            orig_addr, rest_addr,
            "raw-seed restore must reproduce the account"
        );
        close_wallet(&tenants, &json!({})).await.expect("close");
    }

    /// Verify-then-close: a `stake` with a wrong password refuses with
    /// `-29004` and the wallet REMAINS OPEN — the reopen leg must never
    /// close the wallet before the password is verified (a failed non-close
    /// RPC logging the user out was the review's finding).
    #[tokio::test(flavor = "multi_thread")]
    async fn stake_with_a_wrong_password_refuses_and_keeps_the_wallet_open() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tenants = tenants_in(dir.path());

        create_wallet(
            &tenants,
            &json!({ "name": "stakeme", "password": "pw" }),
            fast_kdf(),
        )
        .await
        .expect("create");

        let err = stake(&tenants, &json!({ "password": "wrong" }))
            .await
            .expect_err("wrong password refuses");
        assert!(
            matches!(err, crate::error::WalletRpcError::InvalidPassword),
            "got {err:?}"
        );

        // Still open (the wrong password never reached a close), and a
        // normal close still works.
        crate::tenant::require_open_engine(&tenants)
            .await
            .expect("wallet still open after the refusal");
        close_wallet(&tenants, &json!({})).await.expect("close");
    }
}
