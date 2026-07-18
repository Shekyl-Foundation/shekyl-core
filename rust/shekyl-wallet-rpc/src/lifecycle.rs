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

/// Take the open tenant and fully close its engine — the shared close
/// choreography (`close_wallet` and the first-stake intent reopen both use
/// it, so the restore-on-failure semantics cannot diverge): scan shutdown →
/// sole-ownership reclaim (restore + fail loud if another task holds a
/// clone) → persist-for-close (restore + fail loud on I/O). On success the
/// tenant slot is left in the **closing** reservation; the caller either
/// `clear_closing`s (a plain close) or transitions to `begin_opening` (a
/// reopen).
async fn take_and_close_tenant(
    tenants: &tokio::sync::Mutex<TenantState>,
) -> Result<String, WalletRpcError> {
    let (name, shared, pscan) = {
        let mut state = tenants.lock().await;
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
    take_and_close_tenant(tenants).await?;
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

/// Re-arm the P-scan task on a restore path (a close that could not complete
/// leaves the wallet open). Unlike [`wrap_and_start_pscan`], a start failure
/// here degrades to `None` rather than propagating: the restore must not itself
/// fail and re-strand the engine, and the primary error the caller returns is
/// the close failure, not this. The failure is logged (never silent), and the
/// dark-scan window lasts only until the next successful close / reopen.
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
/// A refusal (`-29500..-29502`) leaves the wallet open and, for `-29500`,
/// wrote nothing durable — fund/sync and call `stake` again. A mid-flow
/// failure after the durable point is the W2 window; re-invoking `stake`
/// resumes it (the engine detects the durable-but-postless slot).
pub(crate) async fn stake(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    let p: StakeParams = parse_required_object(params, "stake")?;

    // Phase 1 — inspect the open tenant: capability gate, idempotency reads,
    // slot choice (the engine's monotone cursor for a fresh stake; the
    // recorded bonded slot for a W2 resume — the user never names a slot,
    // rule 81). The arc clone drops before any reopen (its liveness would
    // fail the close's sole-ownership reclaim).
    // Auth note: on the continue/resume path (a StakeEngine already
    // resident) the password is NOT re-verified — the open session is the
    // authorization boundary, exactly as for every other method on an open
    // wallet; the password is consumed only when a credentialed reopen is
    // actually needed. Slot note: the resume pick is the FIRST bonded slot —
    // the single-slot genesis case; a multi-slot W2 resume re-invokes after
    // the arm-#3 open-time GC has collected the true phantoms.
    let (needs_intent_open, slot) = {
        let shared = require_open_engine(tenants).await?;
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
        (!g.has_stake_engine(), slot)
    };

    if needs_intent_open {
        reopen_with_first_stake_intent(tenants, p.password, slot).await?;
    }

    let shared = require_open_engine(tenants).await?;
    let outcome = Engine::first_stake(shared, slot).await.map_err(|e| {
        use shekyl_engine_core::FirstStakeError as E;
        match e {
            E::BondInFlight => WalletRpcError::StakeInFlight,
            E::AlreadyStaked => WalletRpcError::AlreadyStaked,
            E::Funding(detail) => WalletRpcError::StakeNotReady { detail },
            E::NoStakeEngine => {
                WalletRpcError::InternalError("stake: no stake engine after intent open".into())
            }
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
/// `staking_enabled` is still false).
async fn reopen_with_first_stake_intent(
    tenants: &tokio::sync::Mutex<TenantState>,
    password: String,
    slot: u32,
) -> Result<(), WalletRpcError> {
    let password = Zeroizing::new(password.into_bytes());

    // Close via the shared choreography (identical restore-on-failure
    // semantics as `close_wallet`), then transition the reservation
    // closing → opening.
    let name = take_and_close_tenant(tenants).await?;
    let (base, network, daemon_address) = {
        let mut state = tenants.lock().await;
        let base = wallet_base(&state.wallet_dir, &name);
        state.tenant.clear_closing();
        state.tenant.begin_opening();
        (base, state.network, state.daemon_address.clone())
    };

    // Reopen with the intent (the transient SA-R1-a parameter — it exists
    // only on this call path and is `None` in every other open).
    let reopened: Result<Engine<SoloSigner>, WalletRpcError> = async {
        let daemon = make_daemon(&daemon_address).await?;
        let creds = Credentials::password_only(password.as_slice());
        let opened = tokio::task::block_in_place(|| {
            Engine::<SoloSigner>::open_full_with_first_stake_intent(
                &base,
                &creds,
                network,
                daemon,
                SafetyOverrides::none(),
                slot,
            )
        })
        .map_err(WalletRpcError::from)?;
        Ok(match opened {
            OpenedEngine::Loaded(w) => w,
            OpenedEngine::Restored { wallet, .. } => wallet,
        })
    }
    .await;
    let engine = match reopened {
        Ok(v) => v,
        Err(e) => {
            tenants.lock().await.tenant.clear_opening();
            return Err(e);
        }
    };

    // On-demand P-scan under intent (fail-closed: without the scan the
    // `stake_in` funding can never validate, so a dark scan here is a
    // guaranteed-stuck stake, not a degraded one).
    let shared: SharedEngine = Arc::new(RwLock::new(engine));
    match Engine::start_pscan(shared.clone()).await {
        Ok(handle) => {
            tenants
                .lock()
                .await
                .tenant
                .set_open(name, shared, Some(handle));
            Ok(())
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "first-stake intent reopen: on-demand P-scan failed to start"
            );
            tenants.lock().await.tenant.set_open(name, shared, None);
            Err(WalletRpcError::InternalError(format!(
                "stake: persona scan failed to start ({e}); wallet remains open"
            )))
        }
    }
}

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
    use super::{close_wallet, create_wallet, open_wallet, stake};
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

    /// The `stake` handler end-to-end against the never-connecting daemon:
    /// the full SA-R1-a intent dance runs (close → reopen-with-intent →
    /// actor + on-demand P-scan parked), the continuation refuses at the
    /// first daemon-touching pre-persist step (`-29500`, W1-clean), the
    /// wallet REMAINS OPEN as an intent-spawned tenant, and a retry takes
    /// the continue path (no second reopen) to the same clean refusal.
    #[tokio::test(flavor = "multi_thread")]
    async fn stake_runs_the_intent_dance_and_refuses_w1_clean() {
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

        // The real call: intent dance + W1-clean refusal at the daemon seam.
        let err = stake(&tenants, &json!({ "password": "pw" }))
            .await
            .expect_err("unreachable daemon refuses pre-persist");
        assert!(
            matches!(err, crate::error::WalletRpcError::StakeNotReady { .. }),
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

        // Retry: the continue path (actor resident, no reopen) — same clean
        // refusal, still nothing durable.
        let err = stake(&tenants, &json!({ "password": "pw" }))
            .await
            .expect_err("retry refuses identically");
        assert!(matches!(
            err,
            crate::error::WalletRpcError::StakeNotReady { .. }
        ));

        close_wallet(&tenants, &json!({})).await.expect("close");
    }
}
