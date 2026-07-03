// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Track-2 end-to-end FAKECHAIN regtest: C++↔Rust FCMP++ verify parity.
//!
//! These tests spawn a real `shekyld --regtest` daemon and drive the production
//! [`Engine`] against it over the real RPC transport ([`DaemonClient`] /
//! [`SimpleRequestRpc`]). Unlike the rest of the engine test suite (which uses
//! the in-memory `TestDaemon` mock), the point here is the **submit/verify
//! direction**: a wallet-built FCMP++ proof, serialized into a tx and sent over
//! the wire, must be accepted by the daemon's consensus `shekyl_fcmp_verify`
//! against the daemon's own per-height curve-tree root.
//!
//! The ingest/reconstruct direction is already proven offline by
//! `shekyl-curve-tree`'s `recon_kat.rs` (Tier-A, generated from a live regtest):
//! wallet `build_layers` root == daemon header root at every height. Track 2
//! closes the other half.
//!
//! All tests are `#[ignore]`d: they require a `shekyld` binary, located via the
//! `SHEKYLD_BIN` env var. Run with:
//!
//! ```bash
//! SHEKYLD_BIN=/path/to/build/bin/shekyld \
//!   cargo test -p shekyl-engine-core --lib regtest_e2e -- --ignored --nocapture
//! ```

#![cfg(test)]

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::json;
use shekyl_rpc_client::Rpc;
use shekyl_rpc_transport::SimpleRequestRpc;
use tokio::sync::{Mutex, OwnedMutexGuard, RwLock};

/// `cargo test` runs tests in parallel; spawning multiple daemons concurrently
/// races on the RPC port and is resource-heavy (each mines blocks). Serialize all
/// regtest e2e tests through one async lock — held for the daemon's lifetime via
/// [`RegtestDaemon`], released on drop.
static SERIAL: OnceLock<Arc<Mutex<()>>> = OnceLock::new();

fn serial_lock() -> Arc<Mutex<()>> {
    SERIAL.get_or_init(|| Arc::new(Mutex::new(()))).clone()
}

/// A live `shekyld --regtest` daemon spawned for one test, with an ephemeral
/// data dir and RPC port. Killed and cleaned on drop.
pub(super) struct RegtestDaemon {
    child: Child,
    data_dir: PathBuf,
    rpc_port: u16,
    rpc: SimpleRequestRpc,
    /// Held for the daemon's lifetime to serialize e2e tests; released on drop.
    _serial: OwnedMutexGuard<()>,
}

/// `get_info` result fields we care about.
#[derive(Deserialize, Debug)]
struct GetInfoResp {
    height: u64,
}

/// `generateblocks` result fields we care about.
#[derive(Deserialize, Debug)]
pub(super) struct GenerateBlocksResp {
    height: u64,
    #[serde(default)]
    blocks: Vec<String>,
}

impl RegtestDaemon {
    /// Resolve the daemon binary from `SHEKYLD_BIN`. Panics with a clear message
    /// if unset — these tests are `#[ignore]`d and only run when explicitly
    /// invoked, so requiring the env var is the contract, not a surprise.
    fn binary() -> PathBuf {
        match std::env::var_os("SHEKYLD_BIN") {
            Some(p) => PathBuf::from(p),
            None => panic!(
                "SHEKYLD_BIN not set. Build the daemon (cmake --build build --target daemon) \
                 and run e.g. SHEKYLD_BIN=/abs/path/build/bin/shekyld cargo test ... -- --ignored"
            ),
        }
    }

    /// Grab an ephemeral localhost port by binding :0 and releasing it. Small
    /// TOCTOU window before the daemon binds, acceptable for a serial test.
    fn free_port() -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        l.local_addr().expect("local_addr").port()
    }

    /// Spawn the daemon and wait until its RPC answers `get_info`.
    pub(super) async fn start() -> RegtestDaemon {
        // Serialize across this test binary so no two in-process daemons race on
        // a port. Each instance uses a unique ephemeral port + temp datadir and
        // kills its own child (+ removes its datadir) on Drop, so no global daemon
        // sweep is needed. A `pkill -f shekyl-regtest-` would also kill a
        // concurrent `cargo test` *process*'s daemon — the in-process lock can't
        // serialize across processes — so it is deliberately not done here.
        let serial = serial_lock().lock_owned().await;

        let bin = Self::binary();
        let rpc_port = Self::free_port();
        let data_dir = std::env::temp_dir().join(format!("shekyl-regtest-{rpc_port}"));
        drop(std::fs::remove_dir_all(&data_dir));
        std::fs::create_dir_all(&data_dir).expect("create data dir");

        let log = std::fs::File::create(data_dir.join("daemon.log")).expect("daemon log");
        let child = Command::new(&bin)
            .args([
                "--regtest",
                "--offline",
                "--non-interactive",
                "--no-igd",
                "--fixed-difficulty",
                "1",
                "--rpc-bind-ip",
                "127.0.0.1",
                "--rpc-bind-port",
                &rpc_port.to_string(),
                "--data-dir",
                data_dir.to_str().expect("utf8 data dir"),
                "--log-level",
                "0",
            ])
            .stdout(Stdio::from(log.try_clone().expect("clone log")))
            .stderr(Stdio::from(log))
            .stdin(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {}: {e}", bin.display()));

        // Base URL only — `Rpc::json_rpc_call` appends the `json_rpc` route itself.
        // Long timeout: `generate_blocks` late in a deep-tree mine takes well over
        // the 30s default (each block ~2.5s; the depth-3 mine is ~750 blocks).
        let rpc = SimpleRequestRpc::with_custom_timeout(
            format!("http://127.0.0.1:{rpc_port}"),
            Duration::from_secs(180),
        )
        .await
        .expect("construct rpc client");

        let mut daemon = RegtestDaemon {
            child,
            data_dir,
            rpc_port,
            rpc,
            _serial: serial,
        };
        daemon.await_ready().await;
        daemon
    }

    /// Poll `get_info` until the daemon answers (or time out).
    async fn await_ready(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut last_err = String::new();
        let log_path = self.data_dir.join("daemon.log");
        while Instant::now() < deadline {
            // Fail fast if the daemon process already exited (bad SHEKYLD_BIN,
            // missing runtime deps, port-bind failure): polling for the full 60s
            // would only delay an unhelpful timeout. Point at the captured log so
            // the real cause is one `cat` away.
            if let Ok(Some(status)) = self.child.try_wait() {
                panic!(
                    "daemon exited early ({status}) before RPC became ready; see {}",
                    log_path.display()
                );
            }
            match self
                .rpc
                .json_rpc_call::<GetInfoResp>("get_info", None)
                .await
            {
                Ok(_) => return,
                Err(e) => last_err = format!("{e:?}"),
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        panic!(
            "daemon RPC never became ready (port {}) after 60s: {last_err}; see {}",
            self.rpc_port,
            log_path.display()
        );
    }

    pub(super) async fn height(&self) -> u64 {
        self.rpc
            .json_rpc_call::<GetInfoResp>("get_info", None)
            .await
            .expect("get_info")
            .height
    }

    /// The ephemeral RPC port the daemon bound. Observability harnesses open
    /// their own independent per-persona clients against it (each a distinct
    /// TCP connection), rather than sharing this instance's `rpc` client.
    pub(super) fn rpc_port(&self) -> u16 {
        self.rpc_port
    }

    /// Mine `n` blocks to `address` (FAKECHAIN-gated daemon RPC).
    pub(super) async fn generate_blocks(&self, n: u64, address: &str) -> GenerateBlocksResp {
        self.rpc
            .json_rpc_call::<GenerateBlocksResp>(
                "generateblocks",
                Some(json!({
                    "amount_of_blocks": n,
                    "wallet_address": address,
                    "starting_nonce": 0u32,
                })),
            )
            .await
            .expect("generateblocks")
    }

    /// Roll the chain back `n` blocks (FAKECHAIN-gated `/pop_blocks`, a direct
    /// route — not `json_rpc`). Exercises the daemon's `pop_block`
    /// deferred-insertion tree rollback (popping `H` removes the leaves of
    /// outputs created at `H − maturity`).
    pub(super) async fn pop_blocks(&self, n: u64) {
        self.rpc
            .rpc_call::<_, serde_json::Value>("pop_blocks", Some(json!({ "nblocks": n })))
            .await
            .expect("pop_blocks");
    }
}

impl Drop for RegtestDaemon {
    fn drop(&mut self) {
        drop(self.child.kill());
        drop(self.child.wait());
        drop(std::fs::remove_dir_all(&self.data_dir));
    }
}

/// Smoke test: the harness spawns a daemon, a fresh wallet's address is mineable,
/// and `generateblocks` advances the chain. De-risks the Phase-0 foundation
/// (spawn, RPC, wallet creation, address-format match) before layering the spend
/// path on top.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "Track-2 regtest: requires SHEKYLD_BIN; spawns a live daemon"]
async fn regtest_daemon_spawns_and_mines_to_wallet_address() {
    use super::lifecycle::{CapabilityInput, Credentials, EngineCreateParams};
    use super::{DaemonClient, Engine, SoloSigner};
    use shekyl_address::Network;
    use shekyl_crypto_pq::account::{SeedFormat, MASTER_SEED_BYTES};
    use shekyl_crypto_pq::wallet_envelope::KdfParams;
    use shekyl_engine_file::SafetyOverrides;
    use shekyl_engine_prefs::WalletPrefs;

    let daemon = RegtestDaemon::start().await;
    let rpc = SimpleRequestRpc::new(format!("http://127.0.0.1:{}", daemon.rpc_port))
        .await
        .expect("wallet rpc");
    let daemon_client = DaemonClient::new(rpc);

    let tmp = tempfile::tempdir().expect("wallet tempdir");
    let wallet_path = tmp.path().join("wallet");
    let seed = [0x11u8; MASTER_SEED_BYTES];
    let creds = Credentials::password_only(b"track2-test");

    // FAKECHAIN uses mainnet config/address format (cryptonote_config.h:372), so
    // the wallet is Mainnet + Bip39 (the only permitted seed format for Mainnet).
    let params = EngineCreateParams {
        base_path: &wallet_path,
        credentials: &creds,
        network: Network::Mainnet,
        capability: CapabilityInput::Full {
            master_seed_64: &seed,
            seed_format: SeedFormat::Bip39,
        },
        creation_timestamp: 0,
        restore_height_hint: 0,
        kdf: KdfParams {
            m_log2: 0x08,
            t: 1,
            p: 1,
        },
        overrides: SafetyOverrides::none(),
        prefs: WalletPrefs::default(),
    };
    let wallet = Engine::<SoloSigner>::create(params, daemon_client).expect("create wallet");
    let address = wallet
        .primary_address()
        .encode()
        .expect("encode wallet address");
    eprintln!("wallet address: {address}");

    let before = daemon.height().await;
    let resp = daemon.generate_blocks(3, &address).await;
    let after = daemon.height().await;
    eprintln!(
        "height {before} -> {after}; generateblocks returned height={}, {} blocks",
        resp.height,
        resp.blocks.len()
    );

    assert_eq!(
        resp.blocks.len(),
        3,
        "generateblocks should return 3 hashes"
    );
    assert!(after >= before + 3, "chain should advance by >= 3 blocks");
}

/// `get_curve_tree_path` was registered only in the legacy epee dispatch, so on the
/// default Rust/Axum transport it returned 404 — blocking a wallet from fetching a
/// spend membership path. This drives the live endpoint end-to-end: mine until early
/// coinbase outputs mature + drain into the reference tree, then fetch the path for the
/// first leaf and assert a well-formed, non-404 response (the call the send path makes).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "Track-2 regtest: requires SHEKYLD_BIN; spawns a live daemon"]
async fn e2e_get_curve_tree_path_returns_valid_path() {
    use super::lifecycle::{CapabilityInput, Credentials, EngineCreateParams};
    use super::{DaemonClient, Engine, SoloSigner};
    use shekyl_address::Network;
    use shekyl_crypto_pq::account::{SeedFormat, MASTER_SEED_BYTES};
    use shekyl_crypto_pq::wallet_envelope::KdfParams;
    use shekyl_engine_file::SafetyOverrides;
    use shekyl_engine_prefs::WalletPrefs;

    let daemon = RegtestDaemon::start().await;

    // The endpoint answering at all (not 404) is the fix this PR proves: the
    // curve-tree handlers are now in the Rust/Axum FFI dispatch, not only the
    // legacy epee map. This holds even on a fresh, empty tree.
    let info: serde_json::Value = daemon
        .rpc
        .json_rpc_call("get_curve_tree_info", None)
        .await
        .expect("get_curve_tree_info must not 404 (curve-tree endpoints wired into FFI dispatch)");
    eprintln!("curve_tree_info (fresh): {info}");

    // Mine enough for early coinbase outputs to mature + drain into the reference tree.
    let rpc = SimpleRequestRpc::new(format!("http://127.0.0.1:{}", daemon.rpc_port))
        .await
        .expect("wallet rpc");
    let tmp = tempfile::tempdir().expect("wallet tempdir");
    let wallet_path = tmp.path().join("wallet");
    let seed = [0x22u8; MASTER_SEED_BYTES];
    let creds = Credentials::password_only(b"track2-curve-tree");
    let params = EngineCreateParams {
        base_path: &wallet_path,
        credentials: &creds,
        // FAKECHAIN/regtest uses the mainnet config + address format
        // (cryptonote_config.h), so the wallet is Mainnet (Bip39 is the only seed
        // format permitted for Mainnet). There is no separate regtest address prefix;
        // verified end-to-end — the daemon accepts this address and mines to it.
        network: Network::Mainnet,
        capability: CapabilityInput::Full {
            master_seed_64: &seed,
            seed_format: SeedFormat::Bip39,
        },
        creation_timestamp: 0,
        restore_height_hint: 0,
        kdf: KdfParams {
            m_log2: 0x08,
            t: 1,
            p: 1,
        },
        overrides: SafetyOverrides::none(),
        prefs: WalletPrefs::default(),
    };
    let wallet =
        Engine::<SoloSigner>::create(params, DaemonClient::new(rpc)).expect("create wallet");
    let address = wallet.primary_address().encode().expect("encode address");

    // get_curve_tree_info answers non-404 even on a fresh tree — proves the *info*
    // endpoint is wired into the FFI dispatch, independent of any leaves existing.
    let info: serde_json::Value = daemon
        .rpc
        .json_rpc_call("get_curve_tree_info", None)
        .await
        .expect("get_curve_tree_info must not 404 (FFI dispatch wired)");
    assert_eq!(
        info.get("root")
            .and_then(serde_json::Value::as_str)
            .map(str::len),
        Some(64),
        "get_curve_tree_info.root must be 32-byte hex; got {info}"
    );

    // Mine in small batches (a single ~80-block call exceeds the RPC client timeout)
    // until output 0 is drained into the *reference* tree (tip − REF_ANCHOR_AGE). Poll
    // get_curve_tree_path itself rather than get_curve_tree_info.leaf_count: that is the
    // *tip* leaf count and races ahead of the reference tree the path is built against.
    // While the tree is still empty the call errors ("Curve tree is empty"); once leaves
    // exist but output 0 isn't yet at the reference height it returns Ok with empty paths;
    // either way we mine more (any Err is "not ready" — only an Ok with a non-empty path
    // is success). For output 0 the per-index WRONG_PARAM guard never fires: 0 < tip once
    // the tree is non-empty, and the empty-tree case errors out above it.
    const MINE_BATCH_BLOCKS: u64 = 10;
    const MAX_MINE_BATCHES: usize = 24; // upper bound ~240 blocks before giving up
    let mut path = serde_json::Value::Null;
    let mut mined = 0u64;
    for _ in 0..MAX_MINE_BATCHES {
        daemon.generate_blocks(MINE_BATCH_BLOCKS, &address).await;
        mined += MINE_BATCH_BLOCKS;
        if let Ok(resp) = daemon
            .rpc
            .json_rpc_call::<serde_json::Value>(
                "get_curve_tree_path",
                Some(json!({ "output_indices": [0u64] })),
            )
            .await
        {
            let has_path = resp
                .get("paths")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|a| !a.is_empty());
            if has_path {
                eprintln!("output 0 in reference tree after {mined} blocks: {resp}");
                path = resp;
                break;
            }
        }
    }
    assert!(
        !path.is_null(),
        "output 0 should have a reference-tree membership path within {mined} blocks"
    );

    let root = path
        .get("curve_tree_root")
        .and_then(serde_json::Value::as_str)
        .expect("curve_tree_root field");
    assert_eq!(
        root.len(),
        64,
        "curve_tree_root must be 32-byte hex; got {root:?}"
    );
    let paths = path
        .get("paths")
        .and_then(serde_json::Value::as_array)
        .expect("paths array");
    assert!(
        !paths.is_empty(),
        "output 0 should have a membership path in the reference tree"
    );
    assert_eq!(
        paths[0]
            .get("output_index")
            .and_then(serde_json::Value::as_u64),
        Some(0),
        "first path entry must be for output_index 0"
    );
    let path_blob = paths[0]
        .get("path_blob")
        .and_then(serde_json::Value::as_str)
        .expect("path_blob field");
    assert!(!path_blob.is_empty(), "path_blob must be non-empty");
}

/// Acceptance gate for the §8 step-4 scanner migration (shekyl-oxide → shekyl-wire
/// block/tx parse). Mine coinbase blocks to the wallet's own address, drive the
/// production [`Engine::start_refresh`] against the live daemon, and assert the
/// wallet reflects a real, matured (unlocked) coinbase balance.
///
/// This is the *refresh half* of [`e2e_fcmp_spend_accepted_by_daemon`], isolated so
/// it can pass independently of the (separate) tx-builder→shekyl-wire format work the
/// spend half still needs. Run before this migration, `start_refresh` failed at block
/// fetch with `RpcError::InvalidNode("invalid block")`: the legacy shekyl-oxide parse
/// dropped the coinbase `Null` committed base, so live daemon blocks would not
/// deserialize. Routing the fetch through the daemon-KAT'd shekyl-wire parse
/// (`DaemonEngine::fetch_scannable_block`) is what makes this green.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "Track-2 regtest: requires SHEKYLD_BIN; spawns a live daemon"]
async fn e2e_refresh_scans_coinbase_balance() {
    use super::refresh::RefreshOptions;
    use super::{DaemonClient, Engine, SoloSigner};
    use shekyl_scanner::LedgerBlockExt;
    use shekyl_units::AtomicUnits;

    let daemon = RegtestDaemon::start().await;

    // Create the wallet (FAKECHAIN = mainnet address format; see the get_curve_tree test).
    let rpc = SimpleRequestRpc::new(format!("http://127.0.0.1:{}", daemon.rpc_port))
        .await
        .expect("wallet rpc");
    let tmp = tempfile::tempdir().expect("wallet tempdir");
    let wallet_path = tmp.path().join("wallet");
    let seed = [0x44u8; shekyl_crypto_pq::account::MASTER_SEED_BYTES];
    let creds = super::lifecycle::Credentials::password_only(b"track2-refresh");
    let params = super::lifecycle::EngineCreateParams {
        base_path: &wallet_path,
        credentials: &creds,
        network: shekyl_address::Network::Mainnet,
        capability: super::lifecycle::CapabilityInput::Full {
            master_seed_64: &seed,
            seed_format: shekyl_crypto_pq::account::SeedFormat::Bip39,
        },
        creation_timestamp: 0,
        restore_height_hint: 0,
        kdf: shekyl_crypto_pq::wallet_envelope::KdfParams {
            m_log2: 0x08,
            t: 1,
            p: 1,
        },
        overrides: shekyl_engine_file::SafetyOverrides::none(),
        prefs: shekyl_engine_prefs::WalletPrefs::default(),
    };
    let wallet =
        Engine::<SoloSigner>::create(params, DaemonClient::new(rpc)).expect("create wallet");
    let address = wallet.primary_address().encode().expect("encode address");

    // Mine in batches past coinbase maturity, refreshing after each batch. The
    // `.expect("start_refresh")` / `.expect("refresh joins")` below are the load-bearing
    // assertions for this gate: that is where the pre-migration `InvalidNode` surfaced.
    const MINE_BATCH_BLOCKS: u64 = 10;
    const MAX_MINE_BATCHES: usize = 24; // ~240 blocks; well past the coinbase unlock window

    let arc = Arc::new(RwLock::new(wallet));
    let mut unlocked = AtomicUnits::ZERO;
    let mut total_height = 0u64;
    for _ in 0..MAX_MINE_BATCHES {
        daemon.generate_blocks(MINE_BATCH_BLOCKS, &address).await;
        Engine::start_refresh(arc.clone(), RefreshOptions::default())
            .await
            .expect("start_refresh")
            .join()
            .await
            .expect("refresh joins");
        {
            let g = arc.read().await;
            let ledger = g.ledger();
            total_height = ledger.ledger.height();
            unlocked = ledger.ledger.balance(total_height).unlocked;
        }
        if unlocked > AtomicUnits::ZERO {
            break;
        }
    }

    assert!(
        unlocked > AtomicUnits::ZERO,
        "wallet must reflect a matured coinbase balance after mining + refresh \
         (was InvalidNode pre-migration); got {unlocked:?} at height {total_height}"
    );
    eprintln!("scanned unlocked coinbase balance: {unlocked:?} at height {total_height}");
}

/// The §1.1 closure: a real FCMP++ spend built by the production Engine, submitted to a
/// live shekyld, and accepted by its consensus verify. submit_pending_tx returning Ok is
/// the proof — the daemon's mempool verify ran the FCMP++ membership/SAL proof, the PQC
/// auths, and the CT balance against the wallet-built, wire-serialized spend. This is the
/// live oracle the spec (FCMP_SPEND_SIGNING_PREIMAGE.md §5) names as the residual: it
/// validates the tx-builder→shekyl-wire serialization + PQC signing-preimage byte-for-byte
/// against the C++ daemon (no other test crosses the wallet→daemon spend boundary).
///
/// NORTH STAR (gated) — committed as the acceptance gate for the end-to-end
/// wallet→daemon spend. The two migrations it once waited on have both landed: (1)
/// the §8 step-4 scanner block-parsing migration onto the daemon-KAT'd `shekyl-wire`
/// parser, and (2) the tx-builder→`shekyl-wire` spend-format migration (the
/// `shekyl-oxide` serializers that originally diverged are dissolved). It remains
/// `#[ignore]`d on the live-daemon harness (`SHEKYLD_BIN` + a running regtest
/// daemon), which CI does not provide; run with a built daemon to exercise the full
/// wallet→daemon spend boundary.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "Track-2 north-star spend gate; needs SHEKYLD_BIN + a running regtest daemon (the scanner/tx-builder shekyl-wire migrations have landed)"]
async fn e2e_fcmp_spend_accepted_by_daemon() {
    use super::pending::{FeePriority, TxRecipient, TxRequest};
    use super::refresh::RefreshOptions;
    use super::{DaemonClient, Engine, SoloSigner};
    use shekyl_scanner::LedgerBlockExt;
    use shekyl_units::AtomicUnits;

    let daemon = RegtestDaemon::start().await;

    // Create the wallet (FAKECHAIN = mainnet address format; see the get_curve_tree test).
    let rpc = SimpleRequestRpc::new(format!("http://127.0.0.1:{}", daemon.rpc_port))
        .await
        .expect("wallet rpc");
    let tmp = tempfile::tempdir().expect("wallet tempdir");
    let wallet_path = tmp.path().join("wallet");
    let seed = [0x33u8; shekyl_crypto_pq::account::MASTER_SEED_BYTES];
    let creds = super::lifecycle::Credentials::password_only(b"track2-spend");
    let params = super::lifecycle::EngineCreateParams {
        base_path: &wallet_path,
        credentials: &creds,
        network: shekyl_address::Network::Mainnet,
        capability: super::lifecycle::CapabilityInput::Full {
            master_seed_64: &seed,
            seed_format: shekyl_crypto_pq::account::SeedFormat::Bip39,
        },
        creation_timestamp: 0,
        restore_height_hint: 0,
        kdf: shekyl_crypto_pq::wallet_envelope::KdfParams {
            m_log2: 0x08,
            t: 1,
            p: 1,
        },
        overrides: shekyl_engine_file::SafetyOverrides::none(),
        prefs: shekyl_engine_prefs::WalletPrefs::default(),
    };
    let wallet =
        Engine::<SoloSigner>::create(params, DaemonClient::new(rpc)).expect("create wallet");
    let address = wallet.primary_address().encode().expect("encode address");

    // Fund: mine in batches past coinbase maturity + tree drain so an output is spendable.
    const MINE_BATCH_BLOCKS: u64 = 10;
    const MAX_MINE_BATCHES: usize = 24;

    // refresh + balance + build + submit go through Arc<RwLock<Engine>> (start_refresh
    // owns the wallet for the async scan).
    let arc = Arc::new(RwLock::new(wallet));
    let mut unlocked = AtomicUnits::ZERO;
    for _ in 0..MAX_MINE_BATCHES {
        daemon.generate_blocks(MINE_BATCH_BLOCKS, &address).await;
        Engine::start_refresh(arc.clone(), RefreshOptions::default())
            .await
            .expect("start_refresh")
            .join()
            .await
            .expect("refresh joins");
        unlocked = {
            let g = arc.read().await;
            let ledger = g.ledger();
            ledger.ledger.balance(ledger.ledger.height()).unlocked
        };
        if unlocked > AtomicUnits::ZERO {
            break;
        }
    }
    assert!(
        unlocked > AtomicUnits::ZERO,
        "a matured coinbase must be spendable after mining + refresh; got {unlocked:?}"
    );
    eprintln!("spendable balance: {unlocked:?}");

    // Build a real FCMP++ spend (self-send half the balance; the engine adds change + fee).
    let request = TxRequest {
        recipients: vec![TxRecipient {
            address: address.clone(),
            amount_atomic_units: AtomicUnits::from_raw(unlocked.to_raw() / 2),
        }],
        priority: FeePriority::Standard,
    };

    // The output is spendable at the TIP (`unlocked > 0`), but the FCMP++ spend
    // selects against the REFERENCE block (tip − REF_ANCHOR_AGE) and the selected
    // output must be spendable THERE — which lags tip-maturity by a few blocks.
    // Build until the C2 reference-spendability gate clears (OutputNotYetSpendable
    // ⇒ mine more so the reference catches up).
    let mut pending = None;
    for _ in 0..MAX_MINE_BATCHES {
        let attempt = {
            let mut g = arc.write().await;
            g.build_pending_tx_async(&request).await
        };
        match attempt {
            Ok(p) => {
                pending = Some(p);
                break;
            }
            Err(super::error::SendError::OutputNotYetSpendable { wait_blocks, .. }) => {
                eprintln!("output not reference-spendable yet ({wait_blocks} blocks); mining more");
                daemon.generate_blocks(MINE_BATCH_BLOCKS, &address).await;
                Engine::start_refresh(arc.clone(), RefreshOptions::default())
                    .await
                    .expect("start_refresh")
                    .join()
                    .await
                    .expect("refresh joins");
            }
            Err(e) => panic!("build pending FCMP++ spend: {e:?}"),
        }
    }
    let pending = pending.expect("FCMP++ spend must build once the output is reference-spendable");
    eprintln!(
        "built spend: fee={:?}, tx_bytes={} B",
        pending.fee_atomic_units,
        pending.tx_bytes.len()
    );
    assert!(
        !pending.tx_bytes.is_empty(),
        "spend must serialize to bytes"
    );

    // Submit to the live daemon. Ok == the daemon's consensus verify ACCEPTED the spend
    // (FCMP++ proof + PQC auths + CT balance + wire format). This is the §1.1 proof.
    let tx_hash = {
        let mut g = arc.write().await;
        g.submit_pending_tx_async(pending.id, pending.content_gen)
            .await
            .expect("daemon must accept the FCMP++ spend (consensus verify)")
    };
    eprintln!("daemon accepted spend: {tx_hash:?}");

    // Block-accept: mine one block; the spend must confirm (separate verify path).
    daemon.generate_blocks(1, &address).await;
    let after = daemon.height().await;
    eprintln!("mined confirming block; height now {after}");
}

/// Create a Mainnet wallet (FAKECHAIN uses the mainnet address format) pointed at
/// the daemon RPC. Returns the engine, its tempdir (caller keeps it alive — it owns
/// the wallet files), and the encoded primary address.
async fn mainnet_wallet(
    rpc_port: u16,
    seed_byte: u8,
) -> (super::Engine<super::SoloSigner>, tempfile::TempDir, String) {
    let rpc = SimpleRequestRpc::new(format!("http://127.0.0.1:{rpc_port}"))
        .await
        .expect("wallet rpc");
    let tmp = tempfile::tempdir().expect("wallet tempdir");
    let wallet_path = tmp.path().join("wallet");
    let seed = [seed_byte; shekyl_crypto_pq::account::MASTER_SEED_BYTES];
    let creds = super::lifecycle::Credentials::password_only(b"track2");
    let params = super::lifecycle::EngineCreateParams {
        base_path: &wallet_path,
        credentials: &creds,
        network: shekyl_address::Network::Mainnet,
        capability: super::lifecycle::CapabilityInput::Full {
            master_seed_64: &seed,
            seed_format: shekyl_crypto_pq::account::SeedFormat::Bip39,
        },
        creation_timestamp: 0,
        restore_height_hint: 0,
        kdf: shekyl_crypto_pq::wallet_envelope::KdfParams {
            m_log2: 0x08,
            t: 1,
            p: 1,
        },
        overrides: shekyl_engine_file::SafetyOverrides::none(),
        prefs: shekyl_engine_prefs::WalletPrefs::default(),
    };
    let wallet = super::Engine::<super::SoloSigner>::create(params, super::DaemonClient::new(rpc))
        .expect("create wallet");
    let address = wallet.primary_address().encode().expect("encode address");
    (wallet, tmp, address)
}

/// Depth-3+ FCMP++ verify (CT-5 / #162 reopening trigger). The partial-branch-chunk
/// fix and CT-2 Tier-A both cover only **depth-2** (a single Helios branch). This
/// grows the curve tree past depth-2 — to a real **Selene** branch layer — and
/// proves a wallet-built spend over it is accepted by the daemon's consensus verify.
///
/// Drives by the daemon's **observed tree depth** (`get_curve_tree_info.depth`,
/// which is `fcmp_layers - 1`, so depth-3 = daemon depth 2), not a hardcoded
/// height: depth-3 needs `SELENE_CHUNK_WIDTH × HELIOS_CHUNK_WIDTH = 38 × 18`… in
/// practice ~684–701 drained leaves (~750 blocks, several minutes — a slow gate).
///
/// **Validates the depth-3 fix (was the #162 reopening trigger).** Before the
/// `db_lmdb::grow_curve_tree` → `shekyl_curve_tree_grow_upper_layers` rewiring, the
/// wallet `refresh` at depth-3 died with `CurveTreeIngest: curve-tree root mismatch
/// vs header`: the daemon's in-place incremental upper-layer deepening dropped the
/// pre-existing sibling when it created the first layer-2 Selene root, so its header
/// root diverged from the wallet's narrow `build_layers`. With the producer-side fix
/// the daemon recomposes every upper layer narrow (== `build_layers`), so the
/// refresh succeeds and a spend over the depth-3 tree is daemon-accepted. (Confirmed
/// 2026-06-27 against a locally-built fixed `shekyld`: daemon depth 2 / 701 leaves,
/// refresh OK, spend accepted.)
#[tokio::test(flavor = "multi_thread")]
#[ignore = "Track-2 regtest: requires SHEKYLD_BIN; slow (~750 blocks, several min)"]
async fn e2e_fcmp_spend_over_depth3_tree() {
    use super::pending::{FeePriority, TxRecipient, TxRequest};
    use super::refresh::RefreshOptions;
    use super::Engine;
    use shekyl_scanner::LedgerBlockExt;
    use shekyl_units::AtomicUnits;

    // The daemon's `get_curve_tree_depth` reports `fcmp_layers − 1`
    // (`blockchain.cpp`: `fcmp_layers = depth + 1`). A 3-layer tree — leaf Selene +
    // Helios branch + a real **Selene** branch (the #162 "depth-3+" target) — is
    // therefore daemon depth **2**, reached only at
    // `SELENE_CHUNK_WIDTH × HELIOS_CHUNK_WIDTH = 38 × 18 = 684` drained leaves
    // (~684 + COINBASE_LOCK blocks). This is intentionally a **slow** gate
    // (~750 blocks, several minutes); in-process depth-3 is already covered by
    // `shekyl-wire`'s `fcmp_spend_e2e` (a 700-output depth-3 tree). Daemon depth 1
    // (one Helios branch, the #162 "depth-2") is exercised by the keystone.
    const TARGET_DAEMON_DEPTH: u8 = 2; // = fcmp_layers 3 (a Selene branch layer)
    const MINE_BATCH_BLOCKS: u64 = 20;
    const MAX_MINE_BATCHES: usize = 60; // up to 1200 blocks (684 leaves ≈ 745)

    let daemon = RegtestDaemon::start().await;
    let (wallet, _tmp, address) = mainnet_wallet(daemon.rpc_port, 0x44).await;

    // Mine (no refresh needed — depth is the daemon's, not the wallet's) until the
    // tree reaches the target depth, then one more batch so the REFERENCE block
    // (tip − REF_ANCHOR_AGE) the spend selects against is also past the transition.
    let mut tree_depth = 0u8;
    for _ in 0..MAX_MINE_BATCHES {
        daemon.generate_blocks(MINE_BATCH_BLOCKS, &address).await;
        let info: serde_json::Value = daemon
            .rpc
            .json_rpc_call("get_curve_tree_info", None)
            .await
            .expect("get_curve_tree_info");
        tree_depth = info
            .get("depth")
            .and_then(serde_json::Value::as_u64)
            .and_then(|d| u8::try_from(d).ok())
            .unwrap_or(0);
        if tree_depth >= TARGET_DAEMON_DEPTH {
            eprintln!(
                "curve tree reached daemon depth {tree_depth} (= {} layers): {info}",
                tree_depth + 1
            );
            break;
        }
    }
    assert!(
        tree_depth >= TARGET_DAEMON_DEPTH,
        "curve tree must reach daemon depth >= {TARGET_DAEMON_DEPTH} ({} layers); got {tree_depth}",
        TARGET_DAEMON_DEPTH + 1
    );
    daemon.generate_blocks(MINE_BATCH_BLOCKS, &address).await;

    // Refresh so the wallet's local tree matches the daemon's depth-3 tree.
    let arc = Arc::new(RwLock::new(wallet));
    Engine::start_refresh(arc.clone(), RefreshOptions::default())
        .await
        .expect("start_refresh")
        .join()
        .await
        .expect("refresh joins");
    let unlocked = {
        let g = arc.read().await;
        let ledger = g.ledger();
        ledger.ledger.balance(ledger.ledger.height()).unlocked
    };
    assert!(
        unlocked > AtomicUnits::ZERO,
        "a matured coinbase must be spendable over the depth-3 tree; got {unlocked:?}"
    );
    eprintln!("spendable balance over depth-{tree_depth} tree: {unlocked:?}");

    // Build + submit an FCMP++ spend over the depth-3 tree (retry until the C2
    // reference-spendability gate clears). A depth-3 tree here holds ~700 small
    // coinbase outputs, so a large self-send would select more inputs than
    // FCMP_MAX_INPUTS (8). Spend a small amount so the input count stays bounded —
    // the spend AMOUNT is irrelevant to what this gate validates (a daemon-accepted
    // spend over a depth-3 tree); the depth is.
    // `unlocked` is far above the fee/dust floor (a depth-2+ tree means ~700 matured
    // coinbase outputs), so /500 is non-zero in practice; assert it so a degenerate
    // 0-amount request can never silently fail for a reason unrelated to the depth-3
    // gate. (Clamping to 1 au instead, as suggested, would build an invalid sub-fee
    // spend.)
    let spend_amount = unlocked.to_raw() / 500;
    assert!(
        spend_amount > 0,
        "depth-3 tree must yield a non-trivial spendable balance; got unlocked={unlocked:?}"
    );
    let request = TxRequest {
        recipients: vec![TxRecipient {
            address: address.clone(),
            amount_atomic_units: AtomicUnits::from_raw(spend_amount),
        }],
        priority: FeePriority::Standard,
    };
    let mut pending = None;
    for _ in 0..MAX_MINE_BATCHES {
        let attempt = {
            let mut g = arc.write().await;
            g.build_pending_tx_async(&request).await
        };
        match attempt {
            Ok(p) => {
                pending = Some(p);
                break;
            }
            Err(super::error::SendError::OutputNotYetSpendable { .. }) => {
                daemon.generate_blocks(MINE_BATCH_BLOCKS, &address).await;
                Engine::start_refresh(arc.clone(), RefreshOptions::default())
                    .await
                    .expect("start_refresh")
                    .join()
                    .await
                    .expect("refresh joins");
            }
            Err(e) => panic!("build pending FCMP++ spend over depth-3 tree: {e:?}"),
        }
    }
    let pending = pending.expect("FCMP++ spend must build over the depth-3 tree");
    eprintln!(
        "built depth-{tree_depth} spend: fee={:?}, tx_bytes={} B",
        pending.fee_atomic_units,
        pending.tx_bytes.len()
    );

    let tx_hash = {
        let mut g = arc.write().await;
        g.submit_pending_tx_async(pending.id, pending.content_gen)
            .await
            .expect("daemon must accept the FCMP++ spend over a depth-3 tree (consensus verify)")
    };
    eprintln!("daemon accepted depth-{tree_depth} spend: {tx_hash:?}");
    daemon.generate_blocks(1, &address).await;
}

/// Trim (reorg) self-consistency: popping the chain back to an earlier height must
/// restore the EXACT curve-tree root that growing to that height produced. Grow is
/// validated as consensus-correct (`e2e_fcmp_spend_over_depth3_tree`), so a trim that
/// reproduces the grow root is itself correct — `trim == grow⁻¹`. The reorg crosses a
/// Selene leaf-chunk boundary, so the pop-back recomposes the upper layer rather than
/// only trimming a partial leaf chunk — exercising the `db_lmdb::trim_curve_tree` →
/// `shekyl_curve_tree_grow_upper_layers` rewiring (the reorg twin of the grow fix:
/// the old in-place incremental upper propagation had the same drop-the-sibling
/// defect). Runs at depth-2 (a few minutes); the depth-3 deepening uses the identical
/// FFI already validated by the grow gate.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "Track-2 regtest: requires SHEKYLD_BIN; slow (depth-2 mine, a few min)"]
async fn e2e_trim_curve_tree_restores_grow_root() {
    // SELENE_CHUNK_WIDTH — outputs per Selene leaf node (a leaf-chunk boundary).
    const SELENE_CHUNK_WIDTH: u64 = 38;
    const MINE_BATCH_BLOCKS: u64 = 20;
    const MAX_MINE_BATCHES: usize = 30;

    async fn tree_info(daemon: &RegtestDaemon) -> (u8, u64, String) {
        let info: serde_json::Value = daemon
            .rpc
            .json_rpc_call("get_curve_tree_info", None)
            .await
            .expect("get_curve_tree_info");
        let depth = info
            .get("depth")
            .and_then(serde_json::Value::as_u64)
            .and_then(|d| u8::try_from(d).ok())
            .unwrap_or(0);
        let leaf_count = info
            .get("leaf_count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let root = info
            .get("root")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned();
        (depth, leaf_count, root)
    }

    let daemon = RegtestDaemon::start().await;
    let (_wallet, _tmp, address) = mainnet_wallet(daemon.rpc_port, 0x44).await;

    // Grow to depth-2 with >= 2 Selene leaf chunks, then record the anchor state.
    let mut anchor = None;
    for _ in 0..MAX_MINE_BATCHES {
        daemon.generate_blocks(MINE_BATCH_BLOCKS, &address).await;
        let (depth, leaf_count, root) = tree_info(&daemon).await;
        if depth >= 1 && leaf_count >= 2 * SELENE_CHUNK_WIDTH {
            anchor = Some((daemon.height().await, depth, leaf_count, root));
            break;
        }
    }
    let (anchor_height, anchor_depth, anchor_leaf, anchor_root) =
        anchor.expect("tree must reach depth-2 with >= 2 leaf chunks");
    eprintln!(
        "anchor: height={anchor_height} depth={anchor_depth} leaf_count={anchor_leaf} root={anchor_root}"
    );

    // Grow >= 1 more leaf-chunk boundary so the pop-back must recompose the upper
    // layer (not merely trim a single partial leaf chunk).
    let target_leaf = anchor_leaf + SELENE_CHUNK_WIDTH;
    let mut grew = false;
    for _ in 0..MAX_MINE_BATCHES {
        daemon.generate_blocks(MINE_BATCH_BLOCKS, &address).await;
        if tree_info(&daemon).await.1 >= target_leaf {
            grew = true;
            break;
        }
    }
    assert!(grew, "tree must grow >= 1 more leaf chunk past the anchor");
    let grown_height = daemon.height().await;
    assert!(grown_height > anchor_height, "chain must have advanced");

    // Reorg back to the anchor height: trim must restore the grow state exactly.
    daemon.pop_blocks(grown_height - anchor_height).await;
    let (depth, leaf_count, root) = tree_info(&daemon).await;
    eprintln!(
        "after pop to height {anchor_height}: depth={depth} leaf_count={leaf_count} root={root}"
    );
    assert_eq!(
        leaf_count, anchor_leaf,
        "trim must restore the anchor leaf count"
    );
    assert_eq!(depth, anchor_depth, "trim must restore the anchor depth");
    assert_eq!(
        root, anchor_root,
        "trim must restore the EXACT grow root (consensus-critical: trim == grow⁻¹)"
    );
}

// ===========================================================================
// CT-2 Tier-B fixture generator
// ===========================================================================

/// Mines the CT-2 Tier-B scenarios — a **multi-tx block** (coinbase + spend), a
/// **mixed-maturity collision** (a spend's `+10` regular outputs interleaving
/// with `+60` coinbases at the same drain height), and a **reorg-with-spend**
/// (rollback below a spend, re-mine + re-spend) — on a live regtest via the
/// proven keystone spend path, then writes
/// `shekyl-curve-tree/tests/fixtures/ct2_tier_b.json`.
///
/// It captures only the **deterministic projection** the reconstruct path needs
/// — per-height curve-tree root + per-output leaf identity (`output_key`,
/// `commitment`, `0x07`→`h_pqc`, `target`) — never raw tx blobs (random blinds /
/// one-time keys are not reproducible across runs; `shiny-prancing-flute.md`
/// amendment 11). The captured values ARE the on-chain ones, so `recon_tier_b.rs`
/// reconstructs each height's root deterministically and asserts it equals the
/// recorded consensus root.
///
/// Not a pass/fail gate — it regenerates the committed oracle. Run on demand:
/// ```bash
/// SHEKYLD_BIN=/path/to/build/bin/shekyld \
///   cargo test -p shekyl-engine-core --lib generate_ct2_tier_b_fixture -- --ignored --nocapture
/// ```
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "regenerates ct2_tier_b.json; needs SHEKYLD_BIN + a live regtest"]
async fn generate_ct2_tier_b_fixture() {
    const MINE_BATCH_BLOCKS: u64 = 10;
    const MAX_MINE_BATCHES: usize = 24;
    // Roll back fewer blocks than separate the spend from the tip (the spend
    // confirms, then MINE_BATCH_BLOCKS more are mined), so the spend survives the
    // reorg and the re-mined tail still diverges (fresh coinbase output keys).
    const REORG_DEPTH: u64 = 8;

    let daemon = RegtestDaemon::start().await;
    let (wallet, _tmp, address) = mainnet_wallet(daemon.rpc_port, 0x44).await;
    // A second wallet for its address only — the spend recipient (a real
    // non-change regular output, distinct from the self-send change).
    let (_recipient_wallet, _tmp2, recipient) = mainnet_wallet(daemon.rpc_port, 0x55).await;
    let arc = Arc::new(RwLock::new(wallet));

    // --- fund + spend (main chain): a transfer to `recipient` yields a multi-tx
    //     block (coinbase + spend) whose +10 regular outputs (recipient + change)
    //     are the mixed-maturity classes vs the +60 coinbases. ---
    mine_until_spendable(&daemon, &arc, &address, MINE_BATCH_BLOCKS, MAX_MINE_BATCHES).await;
    submit_tier_b_spend(
        &daemon,
        &arc,
        &address,
        &recipient,
        MINE_BATCH_BLOCKS,
        MAX_MINE_BATCHES,
    )
    .await;
    // Mine on so the spend's regular outputs mature + drain alongside later
    // coinbases (the collision the recon orders by (maturity, gindex)).
    daemon.generate_blocks(MINE_BATCH_BLOCKS, &address).await;
    let main_tip = daemon.height().await - 1;
    let main_chain = capture_chain(&daemon, "main", main_tip).await;
    eprintln!("captured main chain through height {main_tip}");

    // --- reorg-with-spend: roll the daemon back (shallower than the spend, which
    //     survives), refresh the wallet across the rollback, then re-mine + re-spend
    //     a divergent tail. The post-pop `refresh` is the exact path that surfaced
    //     the optimistic-spend state bug — it scans the block carrying the wallet's
    //     own (optimistically-marked) spend; with that fixed (in-flight `spent`
    //     without `spent_height` is now a valid shape, and `handle_reorg` un-marks
    //     orphaned confirmed spends) it completes, confirming the spend and re-mining
    //     a fresh-keyed tail whose per-height roots diverge from `main`. This drives
    //     the wallet's reorg-refresh end-to-end (the bug #2 e2e), and the captured
    //     chain carries both the surviving and the re-mined spend's mixed leaves. ---
    daemon.pop_blocks(REORG_DEPTH).await;
    refresh(&arc).await;
    mine_until_spendable(&daemon, &arc, &address, MINE_BATCH_BLOCKS, MAX_MINE_BATCHES).await;
    submit_tier_b_spend(
        &daemon,
        &arc,
        &address,
        &recipient,
        MINE_BATCH_BLOCKS,
        MAX_MINE_BATCHES,
    )
    .await;
    daemon.generate_blocks(MINE_BATCH_BLOCKS, &address).await;
    let reorg_tip = daemon.height().await - 1;
    let reorg_chain = capture_chain(&daemon, "reorg", reorg_tip).await;
    eprintln!("captured reorg chain through height {reorg_tip}");

    let fixture = json!({
        "_comment": "CT-2 Tier-B reconstruct-root oracle (multi-tx / mixed-maturity / \
            reorg-with-spend). Generated by generate_ct2_tier_b_fixture from a live \
            regtest shekyld via the keystone spend path. Each chain's \
            block[h].curve_tree_root is the C++ consensus header root; recon_tier_b.rs \
            reconstructs it from the per-tx leaf inputs (coinbase + spend) in drain \
            order (maturity, gindex). Deterministic projection only — no raw tx blobs.",
        "chains": [main_chain, reorg_chain],
    });
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../shekyl-curve-tree/tests/fixtures/ct2_tier_b.json"
    );
    std::fs::write(path, serde_json::to_string_pretty(&fixture).unwrap())
        .expect("write ct2_tier_b.json");
    eprintln!("wrote {path}");
}

/// Mine + refresh in batches until the wallet has a spendable (unlocked) balance.
async fn mine_until_spendable(
    daemon: &RegtestDaemon,
    arc: &Arc<RwLock<super::Engine<super::SoloSigner>>>,
    address: &str,
    batch: u64,
    max_batches: usize,
) {
    use shekyl_units::AtomicUnits;
    for _ in 0..max_batches {
        daemon.generate_blocks(batch, address).await;
        refresh(arc).await;
        if unlocked_balance(arc).await > AtomicUnits::ZERO {
            return;
        }
    }
    panic!("a matured coinbase must be spendable after mining + refresh");
}

/// Build (retrying past the C2 reference-spendability gate) + submit a transfer
/// to `recipient`, then mine one confirming block.
async fn submit_tier_b_spend(
    daemon: &RegtestDaemon,
    arc: &Arc<RwLock<super::Engine<super::SoloSigner>>>,
    address: &str,
    recipient: &str,
    batch: u64,
    max_batches: usize,
) {
    use super::pending::{FeePriority, TxRecipient, TxRequest};
    use shekyl_units::AtomicUnits;
    let amount = AtomicUnits::from_raw(unlocked_balance(arc).await.to_raw() / 4);
    let request = TxRequest {
        recipients: vec![TxRecipient {
            address: recipient.to_string(),
            amount_atomic_units: amount,
        }],
        priority: FeePriority::Standard,
    };
    let mut pending = None;
    for _ in 0..max_batches {
        let attempt = {
            let mut g = arc.write().await;
            g.build_pending_tx_async(&request).await
        };
        match attempt {
            Ok(p) => {
                pending = Some(p);
                break;
            }
            Err(super::error::SendError::OutputNotYetSpendable { .. }) => {
                daemon.generate_blocks(batch, address).await;
                refresh(arc).await;
            }
            Err(e) => panic!("build Tier-B spend: {e:?}"),
        }
    }
    let pending = pending.expect("Tier-B spend must build once reference-spendable");
    let tx_hash = {
        let mut g = arc.write().await;
        g.submit_pending_tx_async(pending.id, pending.content_gen)
            .await
            .expect("daemon must accept the Tier-B spend (consensus verify)")
    };
    eprintln!("daemon accepted Tier-B spend: {tx_hash:?}");
    daemon.generate_blocks(1, address).await;
}

async fn refresh(arc: &Arc<RwLock<super::Engine<super::SoloSigner>>>) {
    use super::refresh::RefreshOptions;
    super::Engine::start_refresh(arc.clone(), RefreshOptions::default())
        .await
        .expect("start_refresh")
        .join()
        .await
        .expect("refresh joins");
}

async fn unlocked_balance(
    arc: &Arc<RwLock<super::Engine<super::SoloSigner>>>,
) -> shekyl_units::AtomicUnits {
    use shekyl_scanner::LedgerBlockExt;
    let g = arc.read().await;
    let ledger = g.ledger();
    ledger.ledger.balance(ledger.ledger.height()).unlocked
}

/// Capture blocks `0..=tip` as one fixture chain (deterministic projection only).
///
/// Fetches each block + its **full** (unpruned) non-miner txs directly — not the
/// engine's `default_fetch_scannable_block`, whose `prune:true` leg currently
/// rejects an FCMP++ spend (the refresh-over-spends gap recorded in FOLLOWUPS).
/// The fixture needs only the prefix outputs + ct-base commitments + `0x07`, all
/// of which a full tx carries and `shekyl_wire::Transaction::from_bytes` parses.
async fn capture_chain(daemon: &RegtestDaemon, name: &str, tip: u64) -> serde_json::Value {
    let mut blocks = Vec::new();
    for height in 0..=tip {
        let block_resp: serde_json::Value = daemon
            .rpc
            .json_rpc_call("get_block", Some(json!({ "height": height })))
            .await
            .unwrap_or_else(|e| panic!("get_block {height}: {e:?}"));
        let blob = block_resp["blob"].as_str().expect("get_block blob hex");
        let block = shekyl_wire::Block::from_bytes(&hex_decode(blob))
            .unwrap_or_else(|e| panic!("parse block {height}: {e:?}"));

        let regular = if block.transaction_hashes.is_empty() {
            Vec::new()
        } else {
            let hashes_hex: Vec<String> =
                block.transaction_hashes.iter().map(hex::encode).collect();
            let resp: serde_json::Value = daemon
                .rpc
                .rpc_call(
                    "get_transactions",
                    Some(json!({ "txs_hashes": hashes_hex, "prune": false })),
                )
                .await
                .unwrap_or_else(|e| panic!("get_transactions @ {height}: {e:?}"));
            resp["txs"]
                .as_array()
                .expect("get_transactions txs array")
                .iter()
                .map(|t| {
                    let hex_blob = t["as_hex"]
                        .as_str()
                        .filter(|s| !s.is_empty())
                        .expect("full tx as_hex");
                    shekyl_wire::Transaction::from_bytes(&hex_decode(hex_blob))
                        .expect("parse full regular tx")
                })
                .collect()
        };
        blocks.push(capture_block(&block, &regular, height));
    }
    json!({ "name": name, "blocks": blocks })
}

fn hex_decode(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex")
}

/// One block's deterministic projection: per-height root + every tx's outputs
/// (coinbase first, then non-miner txs in block order), each output carrying the
/// leaf identity the reconstruct path needs.
fn capture_block(
    block: &shekyl_wire::Block,
    regular: &[shekyl_wire::Transaction],
    height: u64,
) -> serde_json::Value {
    use shekyl_wire::tx_extra::TxExtraField;
    use shekyl_wire::Ct;

    let txs: Vec<serde_json::Value> = std::iter::once((true, &block.miner_transaction))
        .chain(regular.iter().map(|tx| (false, tx)))
        .map(|(is_miner, tx)| {
            let base = match &tx.ct {
                Ct::Null(b) => b,
                Ct::Fcmp { base, .. } => base,
            };
            let outputs: Vec<serde_json::Value> = tx
                .prefix
                .outputs
                .iter()
                .enumerate()
                .map(|(i, o)| {
                    // Every output has a tree-leaf commitment (CtBase carries one
                    // per output for both Null and Fcmp).
                    let commitment = base
                        .commitments
                        .get(i)
                        .expect("ct base has a commitment per output");
                    json!({
                        "output_key": hex::encode(o.key),
                        "commitment": hex::encode(commitment),
                        // shekyl-wire only emits tagged-key outputs (Output::write).
                        "target": "tagged_key",
                    })
                })
                .collect();
            // The `0x07` per-output leaf-hash blob (empty if the tx carries none).
            let blob = tx
                .prefix
                .parse_extra()
                .ok()
                .and_then(|fields| {
                    fields.into_iter().find_map(|f| match f {
                        TxExtraField::PqcLeafHashes(b) => Some(b),
                        _ => None,
                    })
                })
                .unwrap_or_default();
            json!({
                "is_miner": is_miner,
                "pqc_leaf_hashes": hex::encode(&blob),
                "outputs": outputs,
            })
        })
        .collect();

    json!({
        "height": height,
        "curve_tree_root": hex::encode(block.header.curve_tree_root),
        "txs": txs,
    })
}
