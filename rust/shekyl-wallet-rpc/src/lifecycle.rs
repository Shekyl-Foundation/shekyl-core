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
    CapabilityInput, Credentials, DaemonClient, Engine, EngineCreateParams, Network, OpenedEngine,
    PScanHandle, SoloSigner,
};
use shekyl_engine_file::paths::keys_path_from;
use shekyl_engine_file::SafetyOverrides;
use shekyl_engine_prefs::WalletPrefs;
use shekyl_rpc_transport::SimpleRequestRpc;
use tokio::sync::RwLock;
use zeroize::{Zeroize, Zeroizing};

use crate::error::WalletRpcError;
use crate::params::{parse_required_object, require_empty_object};
use crate::tenant::{require_open_engine, SharedEngine, TenantState};
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

    // Move password into Zeroizing before any slow work so the serde
    // String is consumed (no residual plaintext copy beside the wipeable vec).
    let password = Zeroizing::new(p.password.into_bytes());
    let created = create_wallet_engine(&base, network, &daemon_address, password, kdf).await;
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
    password: Zeroizing<Vec<u8>>,
    kdf: KdfParams,
) -> Result<(Engine<SoloSigner>, SeedBackup), WalletRpcError> {
    let daemon = make_daemon(daemon_address).await?;
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

    // Same password hand-off as create: consume the serde String into
    // Zeroizing before daemon connect / Argon2.
    let password = Zeroizing::new(p.password.into_bytes());
    let opened = open_wallet_engine(&base, network, &daemon_address, password).await;
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
    daemon_address: &str,
    password: Zeroizing<Vec<u8>>,
) -> Result<(Engine<SoloSigner>, Option<i64>), WalletRpcError> {
    let daemon = make_daemon(daemon_address).await?;
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

pub(crate) async fn close_wallet(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    require_empty_object(params, "close_wallet")?;

    // Take the slot under a short mutex hold, then drop the guard before
    // try_unwrap / outstanding check / Engine::close (fsync / Argon2-free
    // but still file IO). `take_open` marks the tenant *closing* so a
    // concurrent create/open cannot claim the emptied slot while the mutex is
    // released — the failure paths below re-install via restore_open /
    // set_open (whose empty-slot asserts would panic if a new wallet had
    // slipped in). Restore under a fresh lock if close cannot proceed; clear
    // the reservation on success.
    let (name, shared, pscan) = {
        let mut state = tenants.lock().await;
        state
            .tenant
            .take_open()
            .ok_or(WalletRpcError::WalletNotOpen)?
    };

    // Stop the P-scan task (if any) and await its exit BEFORE reclaiming sole
    // ownership. The task holds its own clone of the engine arc, so a live
    // handle would make the `Arc::try_unwrap` below fail spuriously;
    // `PScanHandle::shutdown` deterministically observes the task's exit and the
    // release of that clone (start.rs "the step that makes a subsequent
    // Arc::try_unwrap → Engine::close possible").
    if let Some(handle) = pscan {
        handle.shutdown().await;
    }

    // Reclaim sole ownership before closing. If another task still holds a
    // clone (e.g. an in-flight refresh), restore the slot and fail loud rather
    // than evicting a still-live wallet we cannot actually close.
    let lock = match Arc::try_unwrap(shared) {
        Ok(lock) => lock,
        Err(shared) => {
            // The wallet stays open, so re-arm the scan we just shut down —
            // leaving a still-open staker unscanned is a silent privacy
            // regression (see `restart_pscan`) — then restore and fail loud.
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

    // Persist without consuming. `Engine::close(self)` drops `self` on any
    // `Err` (by-value signature), which would orphan the RPC session on a
    // transient I/O failure with no password available to reopen. Flush
    // first; restore the tenant slot on failure; only drop on success.
    if let Err(e) = tokio::task::block_in_place(|| engine.persist_for_close()) {
        // Keep the wallet open: re-wrap and re-arm the scan (same must-not-fail
        // posture as the try_unwrap restore above).
        let shared: SharedEngine = Arc::new(RwLock::new(engine));
        let pscan = restart_pscan(&shared).await;
        tenants.lock().await.tenant.set_open(name, shared, pscan);
        return Err(WalletRpcError::from(e));
    }
    drop(engine);
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
    let pscan = Engine::start_pscan_if_staker(shared.clone()).await?;
    Ok((shared, pscan))
}

/// Re-arm the P-scan task on a restore path (a close that could not complete
/// leaves the wallet open). Unlike [`wrap_and_start_pscan`], a start failure
/// here degrades to `None` rather than propagating: the restore must not itself
/// fail and re-strand the engine, and the primary error the caller returns is
/// the close failure, not this. The failure is logged (never silent), and the
/// dark-scan window lasts only until the next successful close / reopen.
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
    use super::{close_wallet, create_wallet, open_wallet};
    use crate::tenant::TenantState;

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
            "http://127.0.0.1:1".to_string(),
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
}
