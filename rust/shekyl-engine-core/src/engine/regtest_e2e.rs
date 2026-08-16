// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Track-2 end-to-end FAKECHAIN regtest: C++↔Rust FCMP++ verify parity.
//!
//! These tests spawn a real `shekyld --regtest` daemon and drive the production
//! [`Engine`] against it over the real RPC transport ([`DaemonClient`] /
//! [`HttpRpc`]). Unlike the rest of the engine test suite (which uses
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
//! The file also carries the PR-4 staker harness (`EMISSION_CLAIM_BUILDER.md`
//! §8 PR-4): a staker wallet funds its persona on-chain, the production P-scan
//! discovers the funding, and the production bond path assembles + dispatches
//! the bond post over the same live-daemon boundary, up to the daemon's
//! (pinned) submit-legs gap — the substrate the emission-claim e2e builds on
//! once the PR-4b daemon batteries land.
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
use shekyl_rpc_transport::HttpRpc;
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
/// Last 15 lines of the daemon's captured log, inlined into panics:
/// `RegtestDaemon::drop` removes the datadir (log included) as a panic
/// unwinds, so a "see the log file" pointer would name a deleted file.
fn log_tail(log_path: &std::path::Path) -> String {
    std::fs::read_to_string(log_path)
        .map(|s| {
            let lines: Vec<&str> = s.lines().collect();
            let start = lines.len().saturating_sub(15);
            lines[start..].join("\n")
        })
        .unwrap_or_else(|e| format!("(daemon log unreadable: {e})"))
}

pub(super) struct RegtestDaemon {
    child: Child,
    data_dir: PathBuf,
    rpc_port: u16,
    rpc: HttpRpc,
    /// Held for the daemon's lifetime to serialize e2e tests; released on drop.
    _serial: OwnedMutexGuard<()>,
}

/// `get_info` result fields we care about.
#[derive(Deserialize, Debug)]
struct GetInfoResp {
    height: u64,
    /// Pool population — the mined-yet signal for a submitted tx (see
    /// `mine_until_pool_empty`).
    #[serde(default)]
    tx_pool_size: u64,
    /// Cumulative destroyed atomic units — `compute_fee_burn`'s
    /// `actually_destroyed` term only (`blockchain.cpp` feeds it
    /// `block_burn_amount` and rolls it back on pop). The sibling
    /// `staker_pool_amount` term does *not* land here; it goes to the
    /// `archival_budget_accrual` row. See the A6 assertion for why the
    /// destroyed half is nonetheless evidence about the pool half.
    #[serde(default)]
    total_burned: u64,
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
        Self::start_with_settlement_epoch_blocks(None).await
    }

    /// Spawn the daemon with an optional `SHEKYL_SETTLEMENT_EPOCH_BLOCKS`
    /// override on the child's environment (the fakechain-only regtest
    /// lever the daemon arms at startup — the SEB gate at the top of
    /// `Blockchain::init`, before the genesis add). The emission
    /// e2e passes `Some(seb)` so epoch closes land in minutes; the wallet
    /// process arms the same value in-process (it does its own epoch
    /// arithmetic when it assembles a claim, and gates on the lever —
    /// `lifecycle.rs`). `None` runs the genesis-pinned schedule.
    pub(super) async fn start_with_settlement_epoch_blocks(seb: Option<u64>) -> RegtestDaemon {
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
        let mut cmd = Command::new(&bin);
        cmd.args([
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
        .stdin(Stdio::null());
        // The SEB lever rides the child env (the daemon reads it at startup,
        // arms on fakechain, refuses loudly on a bad value). `None` must
        // scrub the variable, not merely skip setting it: the child inherits
        // this process's environment, so a lever leaked from the developer's
        // or CI's shell would silently reschedule a test that intends the
        // genesis pin.
        match seb {
            Some(seb) => {
                cmd.env("SHEKYL_SETTLEMENT_EPOCH_BLOCKS", seb.to_string());
            }
            None => {
                cmd.env_remove("SHEKYL_SETTLEMENT_EPOCH_BLOCKS");
            }
        }
        let child = cmd
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {}: {e}", bin.display()));

        // Base URL only — `Rpc::json_rpc_call` appends the `json_rpc` route itself.
        // Long timeout: `generate_blocks` late in a deep-tree mine takes well over
        // the 30s default (each block ~2.5s; the depth-3 mine is ~750 blocks).
        let rpc = HttpRpc::with_custom_timeout(
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
                let tail = log_tail(&log_path);
                panic!("daemon exited early ({status}) before RPC became ready; log tail:\n{tail}");
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
        let tail = log_tail(&log_path);
        panic!(
            "daemon RPC never became ready (port {}) after 60s: {last_err}; log tail:\n{tail}",
            self.rpc_port,
        );
    }

    pub(super) async fn height(&self) -> u64 {
        self.rpc
            .json_rpc_call::<GetInfoResp>("get_info", None)
            .await
            .expect("get_info")
            .height
    }

    /// Transactions currently in the daemon's pool — the drain loop's
    /// condition and the pop legs' return-to-pool observable.
    pub(super) async fn tx_pool_size(&self) -> u64 {
        self.rpc
            .json_rpc_call::<GetInfoResp>("get_info", None)
            .await
            .expect("get_info")
            .tx_pool_size
    }

    /// Cumulative `total_burned` — the destroyed half of the §9.5 fee
    /// partition. The emission e2e samples it once, at epoch close, and
    /// pins it to 0 (A6 pool-half disposition).
    pub(super) async fn total_burned(&self) -> u64 {
        self.rpc
            .json_rpc_call::<GetInfoResp>("get_info", None)
            .await
            .expect("get_info")
            .total_burned
    }

    /// Inject an archival serve-credit bit for `(P, shard, E)` — the
    /// FAKECHAIN-only regtest lever (`on_inject_archival_serve_credit`,
    /// bits-only, **not** pop-symmetric: a pop below the injection height
    /// desyncs the bit, so every reorg leg floors its depth above it). The
    /// injected bit gives the epoch a non-zero `Σwork` and the persona a
    /// positive claimant share at close.
    pub(super) async fn inject_serve_credit(
        &self,
        p_canonical_id: &shekyl_types::PCanonicalId,
        shard_id: u64,
        settlement_epoch: u64,
    ) {
        self.rpc
            .json_rpc_call::<serde_json::Value>(
                "inject_archival_serve_credit",
                Some(json!({
                    "p_canonical_id": hex::encode(p_canonical_id.to_bytes()),
                    "shard_id": shard_id,
                    "settlement_epoch": settlement_epoch,
                })),
            )
            .await
            .expect("inject_archival_serve_credit");
    }

    /// The ephemeral RPC port the daemon bound. Observability harnesses open
    /// their own independent per-persona clients against it (each a distinct
    /// TCP connection), rather than sharing this instance's `rpc` client.
    pub(super) fn rpc_port(&self) -> u16 {
        self.rpc_port
    }

    /// Mine `n` blocks to `address` (FAKECHAIN-gated daemon RPC).
    pub(super) async fn generate_blocks(&self, n: u64, address: &str) -> GenerateBlocksResp {
        try_generate_blocks(&self.rpc, n, address)
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

/// Mine `n` blocks to `address` over `rpc` (FAKECHAIN-gated `generateblocks`),
/// returning the RPC error instead of panicking. Free-standing so a caller
/// that cannot borrow a [`RegtestDaemon`] into a `'static` task — the GF-7
/// sealing-run background miner, which owns an independent client and must
/// tolerate transient failures — shares the one request shape with
/// [`RegtestDaemon::generate_blocks`] rather than hand-rolling a copy that
/// drifts.
pub(super) async fn try_generate_blocks(
    rpc: &HttpRpc,
    n: u64,
    address: &str,
) -> Result<GenerateBlocksResp, shekyl_rpc_client::RpcError> {
    rpc.json_rpc_call::<GenerateBlocksResp>(
        "generateblocks",
        Some(json!({
            "amount_of_blocks": n,
            "wallet_address": address,
            "starting_nonce": 0u32,
        })),
    )
    .await
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
    let rpc = HttpRpc::new(format!("http://127.0.0.1:{}", daemon.rpc_port))
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
    let rpc = HttpRpc::new(format!("http://127.0.0.1:{}", daemon.rpc_port))
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
    use shekyl_scanner::WalletLedgerExt;
    use shekyl_units::AtomicUnits;

    let daemon = RegtestDaemon::start().await;

    // Create the wallet (FAKECHAIN = mainnet address format; see the get_curve_tree test).
    let rpc = HttpRpc::new(format!("http://127.0.0.1:{}", daemon.rpc_port))
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
            unlocked = ledger.balance_at(total_height).unlocked;
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
    use shekyl_scanner::WalletLedgerExt;
    use shekyl_units::AtomicUnits;

    let daemon = RegtestDaemon::start().await;

    // Create the wallet (FAKECHAIN = mainnet address format; see the get_curve_tree test).
    let rpc = HttpRpc::new(format!("http://127.0.0.1:{}", daemon.rpc_port))
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
            ledger.balance().unlocked
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
            // Build/submit take `&self` — use a read guard so the harness
            // matches production wallet-RPC locking and cannot mask
            // exclusive-lock regressions.
            let g = arc.read().await;
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
        let g = arc.read().await;
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

/// Mainnet [`EngineCreateParams`](super::lifecycle::EngineCreateParams) for the
/// regtest wallets: FAKECHAIN uses the mainnet address format, and the KDF is
/// the minimum-wall-clock relaxation the wallet-file tests share.
fn mainnet_params<'a>(
    base_path: &'a std::path::Path,
    creds: &'a super::lifecycle::Credentials<'a>,
    seed: &'a [u8; shekyl_crypto_pq::account::MASTER_SEED_BYTES],
) -> super::lifecycle::EngineCreateParams<'a> {
    super::lifecycle::EngineCreateParams {
        base_path,
        credentials: creds,
        network: shekyl_address::Network::Mainnet,
        capability: super::lifecycle::CapabilityInput::Full {
            master_seed_64: seed,
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
    }
}

/// Create a Mainnet wallet (FAKECHAIN uses the mainnet address format) pointed at
/// the daemon RPC. Returns the engine, its tempdir (caller keeps it alive — it owns
/// the wallet files), and the encoded primary address.
async fn mainnet_wallet(
    rpc_port: u16,
    seed_byte: u8,
) -> (super::Engine<super::SoloSigner>, tempfile::TempDir, String) {
    let seed = [seed_byte; shekyl_crypto_pq::account::MASTER_SEED_BYTES];
    let (wallet, tmp) = create_wallet(rpc_port, &seed, b"track2").await;
    let address = wallet.primary_address().encode().expect("encode address");
    (wallet, tmp, address)
}

/// The shared create step behind [`mainnet_wallet`] and [`staker_wallet`]:
/// tempdir, credentials, wallet RPC against the daemon port, and
/// `Engine::create` over [`mainnet_params`]. Callers layer their own
/// follow-ons (address derivation; the staker's persist → close → reopen).
/// The wallet base path is `tmp.path().join("wallet")`.
async fn create_wallet(
    rpc_port: u16,
    seed: &[u8; shekyl_crypto_pq::account::MASTER_SEED_BYTES],
    password: &'static [u8],
) -> (super::Engine<super::SoloSigner>, tempfile::TempDir) {
    let rpc = HttpRpc::new(format!("http://127.0.0.1:{rpc_port}"))
        .await
        .expect("wallet rpc");
    let tmp = tempfile::tempdir().expect("wallet tempdir");
    let wallet_path = tmp.path().join("wallet");
    let creds = super::lifecycle::Credentials::password_only(password);
    let params = mainnet_params(&wallet_path, &creds, seed);
    let wallet = super::Engine::<super::SoloSigner>::create(params, super::DaemonClient::new(rpc))
        .expect("create wallet");
    (wallet, tmp)
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
    use shekyl_scanner::WalletLedgerExt;
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
        ledger.balance().unlocked
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
            let g = arc.read().await;
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
        let g = arc.read().await;
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

/// Mine + refresh in batches until the wallet's unlocked balance reaches
/// `target`. Panics after `max_batches` batches.
async fn mine_until_unlocked_at_least(
    daemon: &RegtestDaemon,
    arc: &Arc<RwLock<super::Engine<super::SoloSigner>>>,
    address: &str,
    target: shekyl_units::AtomicUnits,
    batch: u64,
    max_batches: usize,
) {
    for _ in 0..max_batches {
        daemon.generate_blocks(batch, address).await;
        refresh(arc).await;
        if unlocked_balance(arc).await >= target {
            return;
        }
    }
    panic!("unlocked balance must reach {target:?} after mining + refresh");
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
    mine_until_unlocked_at_least(
        daemon,
        arc,
        address,
        AtomicUnits::from_raw(1),
        batch,
        max_batches,
    )
    .await;
}

/// Build (retrying past the C2 reference-spendability gate) + submit a transfer
/// to `recipient` for a quarter of the unlocked balance, then mine one
/// confirming block.
async fn submit_tier_b_spend(
    daemon: &RegtestDaemon,
    arc: &Arc<RwLock<super::Engine<super::SoloSigner>>>,
    address: &str,
    recipient: &str,
    batch: u64,
    max_batches: usize,
) {
    use shekyl_units::AtomicUnits;
    let amount = AtomicUnits::from_raw(unlocked_balance(arc).await.to_raw() / 4);
    transfer_to(daemon, arc, address, recipient, amount, batch, max_batches).await;
}

/// Build (retrying past the C2 reference-spendability gate) + submit a transfer
/// of exactly `amount` to `recipient`, then mine one confirming block.
async fn transfer_to(
    daemon: &RegtestDaemon,
    arc: &Arc<RwLock<super::Engine<super::SoloSigner>>>,
    address: &str,
    recipient: &str,
    amount: shekyl_units::AtomicUnits,
    batch: u64,
    max_batches: usize,
) {
    use super::pending::{FeePriority, TxRecipient, TxRequest};
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
            let g = arc.read().await;
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
            Err(e) => panic!("build transfer: {e:?}"),
        }
    }
    let pending = pending.expect("transfer must build once reference-spendable");
    let tx_hash = {
        let g = arc.read().await;
        g.submit_pending_tx_async(pending.id, pending.content_gen)
            .await
            .expect("daemon must accept the transfer (consensus verify)")
    };
    eprintln!("daemon accepted transfer: {tx_hash:?}");
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
    use shekyl_scanner::WalletLedgerExt;
    let g = arc.read().await;
    let ledger = g.ledger();
    ledger.balance().unlocked
}

// ---------------------------------------------------------------------------
// PR-4 staker harness (EMISSION_CLAIM_BUILDER.md §8 PR-4): staker wallet
// lifecycle + persona funding + production P-scan against the live daemon.
// ---------------------------------------------------------------------------

/// Test finality horizon for the P-scan. Production is the consensus
/// `ARCHIVAL_REORG_DEPTH_BLOCKS`; a shallow horizon (injected through the
/// crate-visible [`Engine::start_pscan_with`](super::Engine::start_pscan_with)
/// seam, which exists for exactly this) lets the harness reach scan finality
/// in blocks it can afford to mine.
const PSCAN_TEST_REORG_DEPTH: u64 = 4;

/// Create a STAKER Mainnet wallet against the daemon RPC: create → persist the
/// slot's bond record (flips `staking_enabled`) → close → reopen (`open_full`
/// spawns the `StakeEngine` for a staker — the same create/reopen shape as the
/// pscan auto-start lifecycle test). Returns the arc'd engine, its tempdir
/// (caller keeps it alive — it owns the wallet files), and the principal's
/// encoded primary address.
pub(super) async fn staker_wallet(
    rpc_port: u16,
    seed: &[u8; shekyl_crypto_pq::account::MASTER_SEED_BYTES],
    slot: super::stake_engine::PSlot,
) -> (
    Arc<RwLock<super::Engine<super::SoloSigner>>>,
    tempfile::TempDir,
    String,
) {
    let creds = super::lifecycle::Credentials::password_only(b"pr4-staker");
    let (engine, tmp) = create_wallet(rpc_port, seed, b"pr4-staker").await;
    let base_path = tmp.path().join("wallet");
    engine
        .persist_bond_record(slot)
        .expect("persist bond record");
    engine.close(&creds).expect("close created wallet");

    let rpc = HttpRpc::new(format!("http://127.0.0.1:{rpc_port}"))
        .await
        .expect("wallet rpc (reopen)");
    let opened = super::Engine::<super::SoloSigner>::open_full(
        &base_path,
        &creds,
        shekyl_address::Network::Mainnet,
        super::DaemonClient::new(rpc),
        shekyl_engine_file::SafetyOverrides::none(),
    )
    .expect("reopen staker wallet");
    let engine = opened.into_wallet();
    assert!(
        engine.stake_handle().is_some(),
        "a staker reopen spawns the StakeEngine"
    );
    let address = engine.primary_address().encode().expect("encode address");
    (Arc::new(RwLock::new(engine)), tmp, address)
}

/// The persona's on-chain receive address, derived in-test from the same
/// master seed the wallet holds. The production wallet derives the identical
/// bundle at open (`spawn_stake_engine_if_staker` → `derive_archival_p_keys`);
/// the harness re-derives only the PUBLIC halves so the principal can fund the
/// persona over an ordinary wallet-built transfer.
pub(super) fn persona_address(
    seed: &[u8; shekyl_crypto_pq::account::MASTER_SEED_BYTES],
    slot: u32,
) -> String {
    use shekyl_crypto_pq::account::{DerivationNetwork, SeedFormat};
    use shekyl_crypto_pq::archival_p::derive_archival_p_keys;
    let keys = derive_archival_p_keys(seed, DerivationNetwork::Mainnet, SeedFormat::Bip39, slot)
        .expect("derive persona keys");
    keys.to_address(shekyl_address::Network::Mainnet)
        .encode()
        .expect("encode persona address")
}

/// Run the production P-scan (tight cadence + the shallow
/// [`PSCAN_TEST_REORG_DEPTH`] horizon, via the injectable
/// [`Engine::start_pscan_with`](super::Engine::start_pscan_with) seam) until
/// the sealed `.wallet.pscan` state satisfies `pred`, then shut the task down
/// and return that state. The caller mines the finality horizon past the
/// blocks under test *before* calling; the scan then only has to catch up to
/// `tip − horizon`. Panics if no satisfying seal appears within the deadline.
async fn pscan_until(
    arc: &Arc<RwLock<super::Engine<super::SoloSigner>>>,
    pscan_seal: &std::path::Path,
    what: &str,
    pred: impl Fn(&shekyl_engine_state::pscan_state::PScanState) -> bool,
) -> shekyl_engine_state::pscan_state::PScanState {
    use super::pscan::start::load_pscan_state_for_engine;
    use super::pscan::task::PScanConfig;

    let handle = super::Engine::start_pscan_with(
        arc.clone(),
        PScanConfig {
            reorg_depth: PSCAN_TEST_REORG_DEPTH,
            // Small batches so each seal lands quickly: the sweep persists state
            // only at batch boundaries, and a debug-build scan-step is slow
            // enough that a whole-backlog batch could outlive the deadline
            // without ever sealing.
            batch_blocks: 16,
        },
        Duration::from_millis(150),
    )
    .await
    .expect("start pscan");

    let deadline = Instant::now() + Duration::from_secs(300);
    let mut last_report = Instant::now();
    let mut last_seal_mtime: Option<std::time::SystemTime> = None;
    loop {
        tokio::time::sleep(Duration::from_millis(200)).await;
        // Cheap change gate: the seal lands by atomic rename, so a changed
        // mtime is exactly "a new batch sealed" — only then pay the full
        // decrypt + decode of the sealed state (up to 1 500 polls fit in
        // the deadline; re-loading an unchanged seal every 200 ms is pure
        // waste). An absent/unreadable file falls through to the loader,
        // which reports the no-seal-yet state.
        let seal_mtime = std::fs::metadata(pscan_seal)
            .ok()
            .and_then(|m| m.modified().ok());
        if seal_mtime.is_some() && seal_mtime == last_seal_mtime {
            assert!(
                Instant::now() < deadline,
                "pscan did not observe {what} within the deadline"
            );
            continue;
        }
        last_seal_mtime = seal_mtime;
        if let Some(state) = load_pscan_state_for_engine(arc.clone())
            .await
            .expect("load pscan state")
        {
            if pred(&state) {
                handle.shutdown().await;
                return state;
            }
            if last_report.elapsed() > Duration::from_secs(2) {
                last_report = Instant::now();
                eprintln!(
                    "pscan progress: synced={:?}, funding={}, matches={}",
                    state.synced_height(),
                    state.funding_outputs().len(),
                    state.bond_post_matches().len(),
                );
            }
        } else if last_report.elapsed() > Duration::from_secs(2) {
            last_report = Instant::now();
            eprintln!("pscan progress: no seal yet");
        }
        assert!(
            Instant::now() < deadline,
            "pscan did not observe {what} within the deadline"
        );
    }
}

/// Mine in `blocks_per_batch` batches until the tx pool drains — the
/// locally-submitted tx's only route into a block on this offline daemon.
///
/// The submit path inserts at `relay_method::local` under the Dandelion++
/// embargo, and the miner only includes broadcast-visible txs
/// (`fill_block_template`'s `matches(relay_category::legacy)` gate); the
/// stem cannot send here, so inclusion waits for the embargo to expire and
/// fluff. Mining in batches rather than assuming one batch suffices. Pass
/// `blocks_per_batch = 1` when the caller needs the tx's block to be the
/// tip at return (the emission e2e's depth-1 pop leg pops exactly it).
async fn mine_until_pool_drains(
    daemon: &RegtestDaemon,
    principal: &str,
    what: &str,
    blocks_per_batch: u64,
) {
    let mine_deadline = Instant::now() + Duration::from_secs(240);
    // Condition checked BEFORE every batch: an already-drained pool must
    // not advance the chain. Callers passing `blocks_per_batch = 1` rely on
    // the tx's block being the tip when this returns (the A5a depth-1 pop
    // pops exactly it), and an unconditional first batch would bury it
    // under an empty block.
    while daemon.tx_pool_size().await > 0 {
        assert!(
            Instant::now() < mine_deadline,
            "{what} never left the pool (embargo/template gap?)"
        );
        daemon.generate_blocks(blocks_per_batch, principal).await;
        // The Dandelion++ embargo is wall-clock, not block-height: pause
        // between attempts rather than spinning the miner.
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// The confirmed-bond substrate [`stake_persona_to_confirmed_bond`] hands
/// back: the wallet handles plus the **block geography** the emission-claim
/// e2e derives its epoch arithmetic from. The geography is returned
/// explicitly — the helper mines a variable number of blocks (funding
/// maturity + reference-spendability + embargo drain are all
/// retry-until-ready), so callers must never re-derive heights from mined
/// counts.
struct ConfirmedBondFixture {
    /// The staker wallet engine (persona bonded and confirmed).
    arc: Arc<RwLock<super::Engine<super::SoloSigner>>>,
    /// The wallet's backing tempdir — an RAII guard, never read: hold the
    /// fixture or the wallet files vanish.
    _tmp: tempfile::TempDir,
    /// The principal's mining/funding address.
    principal: String,
    /// The bonded persona's canonical id (the bond post's identity).
    persona_id: shekyl_types::PCanonicalId,
    /// The sealed P-scan state path (for follow-on `pscan_until` calls).
    pscan_seal: std::path::PathBuf,
    /// The sealed scan state at confirmation: carries the bond-post match
    /// and the persona's surviving funding set (the `BondPostChange`
    /// change — the emission claim's fee-input substrate).
    state: shekyl_engine_state::pscan_state::PScanState,
    /// The pre-post funding gindexes `first_stake` swept (pruned from the
    /// sealed set by the arm-1 key-image watch).
    swept_gindexes: Vec<u64>,
    /// How many pre-post funding records the discovery scan found.
    pre_post_discovered: usize,
    /// Tip height when the confirmation scan sealed — the geography anchor
    /// for the emission e2e's epoch-close/inject/claim layout.
    confirmed_tip_height: u64,
}

/// How the confirmed-bond fixture enters the stake.
enum FixtureStake {
    /// The production [`Engine::first_stake`] entry (SP-R0 arm-#1
    /// production discharge) — the SA-R1 genesis posture: JoinMarket
    /// **CompleteTree** holdings. A complete-tree bond is foundation-shaped
    /// and market-EXCLUDED (`ARCHIVAL_CONSENSUS_STATE.md` §3.3 E-2;
    /// `market_member_at_epoch` returns false), so this arm's bond can
    /// never carry Σwork — it exercises the stake entry, not the reward
    /// market.
    FirstStake,
    /// The composed production steps — `mint_handle` →
    /// `persist_bond_record` → [`Engine::assemble_bond_post`] (which seals
    /// the pending post exactly as `first_stake` does) — with
    /// caller-chosen holdings: the **market** bond shape
    /// (`ShardSetCompact`) the emission-claim e2e earns from. Named
    /// deviation (PR-4c finding): no wallet entry posts a market bond
    /// today — `first_stake` hardcodes the CompleteTree genesis posture —
    /// so the market-bond wallet entry is a named follow-on, and until it
    /// lands this composition of the same production functions is the
    /// claimable-bond path.
    MarketBond(shekyl_archival_retention::HoldingsDescriptor),
}

/// Fund → stake → dispatch → confirm: the production staking sequence both
/// PR-4 e2e legs share (rule 19: one definition — the bond e2e asserts on
/// the returned fixture, the emission e2e builds its claim on it). The
/// caller owns the daemon spawn (and with it the SEB lever decision), the
/// stake entry (see [`FixtureStake`] — the emission e2e needs a market
/// bond), and the funding cushion: the cushion is (approximately) the
/// persona's `BondPostChange` change output, so the emission caller sizes
/// it to fund real ToKey claim-fee inputs where the bond caller only needs
/// it non-zero.
///
/// Every step retries-until-ready (funding maturity, reference
/// spendability, the Dandelion++ embargo), so the block geography is a
/// *result*, not an input — read it from the returned fixture.
async fn stake_persona_to_confirmed_bond(
    daemon: &RegtestDaemon,
    seed: &[u8; shekyl_crypto_pq::account::MASTER_SEED_BYTES],
    slot_raw: u32,
    funding_cushion: u64,
    stake_entry: FixtureStake,
) -> ConfirmedBondFixture {
    use super::bond_assembly::{BondAssemblyError, PBoundBytes, SpentRecordsDurablyPruned};
    use super::bond_orchestrator::FirstStakeError;
    use super::bond_orchestrator::BOND_SIZE_CEILING_BYTES;
    use super::pscan::start::pending_post_store_for_engine;
    use super::stake_engine::{PSlot, StakeEngineError};
    use super::traits::DaemonEngine;
    use super::transaction_submitter::BroadcastSubmitter;
    use shekyl_archival_retention::{bond_floor, HoldingsDescriptor, HoldingsKind, ShardSet};
    use shekyl_engine_state::pscan_state::MintLineageOutput;
    use shekyl_units::AtomicUnits;

    const MINE_BATCH_BLOCKS: u64 = 10;
    const MAX_MINE_BATCHES: usize = 24;

    let slot = PSlot::from_raw(slot_raw);
    let (arc, tmp, principal) = staker_wallet(daemon.rpc_port, seed, slot).await;

    // The bond fee is caller-chosen at this seam (the RPC stake entry's
    // contract), but a hardcoded constant is wrong on regtest: the daemon's
    // per-byte floor tracks the block reward, which is enormous on a young
    // chain (~69 000/byte at these heights ⇒ ~1.55e9 for a 22.5 KB post).
    // Derive the fee from the daemon's live estimate over the size ceiling;
    // the reward only decays as the test mines, so an early estimate stays
    // sufficient, and overpaying is harmless (the fee is a miner transfer,
    // not a conservation term).
    let bond_fee = {
        let estimates = arc
            .read()
            .await
            .daemon()
            .get_fee_estimates()
            .await
            .expect("daemon fee estimates");
        estimates
            .economy
            .calculate_fee_from_weight(BOND_SIZE_CEILING_BYTES)
    };
    eprintln!("bond fee from daemon estimate: {bond_fee}");

    // Fund the principal past the persona's needs (2×: the transfer's own fee
    // + selection churn), then fund the persona with one ordinary transfer.
    // The floor follows the entry's holdings shape.
    let floor_holdings = match &stake_entry {
        FixtureStake::FirstStake => HoldingsDescriptor {
            kind: HoldingsKind::CompleteTree,
            shard_ids: ShardSet::empty(),
        },
        FixtureStake::MarketBond(h) => h.clone(),
    };
    let funding = AtomicUnits::from_raw(bond_floor(&floor_holdings) + bond_fee + funding_cushion);
    mine_until_unlocked_at_least(
        daemon,
        &arc,
        &principal,
        AtomicUnits::from_raw(funding.to_raw() * 2),
        MINE_BATCH_BLOCKS,
        MAX_MINE_BATCHES,
    )
    .await;
    let p_address = persona_address(seed, slot_raw);
    transfer_to(
        daemon,
        &arc,
        &principal,
        &p_address,
        funding,
        MINE_BATCH_BLOCKS,
        MAX_MINE_BATCHES,
    )
    .await;

    // Discovery: push the shallow finality horizon past the funding block,
    // then run the production P-scan until the sealed state carries the
    // persona's funding output.
    daemon
        .generate_blocks(PSCAN_TEST_REORG_DEPTH + 2, &principal)
        .await;
    refresh(&arc).await;
    let pscan_seal = shekyl_engine_file::paths::pscan_state_path_from(&tmp.path().join("wallet"));
    let state = pscan_until(&arc, &pscan_seal, "the persona funding output", |s| {
        s.funding_outputs().iter().any(|r| r.p_slot == slot)
    })
    .await;
    let pre_post_discovered = state
        .funding_outputs()
        .iter()
        .filter(|r| r.p_slot == slot)
        .count();
    eprintln!("pscan discovered {pre_post_discovered} persona funding output(s)");

    // The stake entry (both arms end at the same `.wallet.pending` seal —
    // `assemble_bond_post`'s push_post — so everything downstream is
    // shared). The funding must be spendable at the anchored REFERENCE
    // block (tip − REF_ANCHOR_AGE), which lags tip maturity, so each arm
    // retries its typed not-ready refusals while mining.
    match &stake_entry {
        // Production SA-R1 entry (SP-R0 arm-#1 PRODUCTION-DISCHARGE leg):
        // preflight funding sweep → durable `persist_bond_record` → sign +
        // assemble → seal, driven exactly as the credentialed `stake` RPC
        // drives it; the `arm1_watch_pruning_live` witness is minted
        // inside the entry, so no `for_test` deviation remains here.
        FixtureStake::FirstStake => {
            let mut outcome = None;
            for _ in 0..MAX_MINE_BATCHES {
                // The fixture drives the production entry exactly as the RPC
                // does, and states its posture explicitly (D-3): this lane
                // exercises the Foundation CompleteTree bond. The
                // acknowledgment D-4 requires is an RPC-layer fact and is
                // deliberately not an engine parameter, so it has no place
                // here.
                match super::Engine::first_stake(
                    arc.clone(),
                    slot_raw,
                    super::StakePosture::FoundationCompleteTree,
                )
                .await
                {
                    Ok(o) => {
                        outcome = Some(o);
                        break;
                    }
                    Err(FirstStakeError::Funding(detail)) => {
                        eprintln!("first-stake funding not ready ({detail}); mining more");
                        daemon.generate_blocks(MINE_BATCH_BLOCKS, &principal).await;
                        refresh(&arc).await;
                    }
                    // Post-persist mid-flow failure — the documented W2
                    // window (e.g. the funding output cleared the preflight
                    // sweep but is not yet drained into the REFERENCE curve
                    // tree). The production recovery is re-invoking `stake`
                    // (`persist_bond_record` is re-entrant; the resume path
                    // re-mints the ticket), so the retry exercises the W2
                    // resume exactly as a wallet would.
                    Err(FirstStakeError::Engine(detail)) => {
                        eprintln!(
                            "first-stake W2 mid-flow failure ({detail}); mining and resuming"
                        );
                        daemon.generate_blocks(MINE_BATCH_BLOCKS, &principal).await;
                        refresh(&arc).await;
                    }
                    Err(e) => panic!("first_stake: {e}"),
                }
            }
            let outcome =
                outcome.expect("first_stake must succeed once the funding is reference-spendable");
            eprintln!(
                "first_stake sealed the bond post: slot {}, {} swept input(s), resumed={}",
                outcome.p_slot, outcome.swept_inputs, outcome.resumed
            );
        }
        // Market bond: the same production functions `first_stake`
        // composes, with the holdings the entry does not yet parameterize
        // (see [`FixtureStake::MarketBond`]). Assembly authorizes on the
        // handle alone; `persist_bond_record` is idempotent, so each retry
        // re-mints a fresh ticket.
        FixtureStake::MarketBond(holdings) => {
            let fee = AtomicUnits::from_raw(bond_fee);
            let mut sealed = false;
            for _ in 0..MAX_MINE_BATCHES {
                let (handle, ticket) = {
                    let g = arc.read().await;
                    let stake = g.stake_handle().expect("staker wallet has a stake engine");
                    let handle = stake.mint_handle(slot).await.expect("mint handle");
                    let ticket = g.persist_bond_record(slot).expect("persist bond record");
                    (handle, ticket)
                };
                match super::Engine::assemble_bond_post(
                    arc.clone(),
                    handle,
                    ticket,
                    holdings.clone(),
                    fee,
                    &SpentRecordsDurablyPruned::for_test(),
                )
                .await
                {
                    Ok(a) => {
                        eprintln!(
                            "assembled market bond post: {} B, {} funding input(s)",
                            a.bound_tx.bytes().len(),
                            a.funding_gindexes.len(),
                        );
                        sealed = true;
                        break;
                    }
                    // The reference-spendability ladder, one typed arm per
                    // stage: value shortfall at the reference, empty
                    // eligible set, and swept-but-not-yet-drained into the
                    // reference tree.
                    Err(StakeEngineError::Assembly(BondAssemblyError::InsufficientFunding {
                        available,
                        required,
                    })) => {
                        eprintln!(
                            "persona funding not yet reference-spendable \
                             ({available}/{required}); mining more"
                        );
                        daemon.generate_blocks(MINE_BATCH_BLOCKS, &principal).await;
                        refresh(&arc).await;
                    }
                    Err(StakeEngineError::Assembly(BondAssemblyError::NoSpendableFunding)) => {
                        eprintln!("persona funding set empty at the reference height; mining more");
                        daemon.generate_blocks(MINE_BATCH_BLOCKS, &principal).await;
                        refresh(&arc).await;
                    }
                    Err(StakeEngineError::Assembly(BondAssemblyError::OutputNotYetDrained {
                        gindex,
                    })) => {
                        eprintln!(
                            "funding output {gindex} not yet in the reference tree; mining more"
                        );
                        daemon.generate_blocks(MINE_BATCH_BLOCKS, &principal).await;
                        refresh(&arc).await;
                    }
                    Err(e) => panic!("assemble market bond post: {e:?}"),
                }
            }
            assert!(
                sealed,
                "the market bond post must assemble once the funding is reference-spendable"
            );
        }
    }

    // Re-lift the sealed pending post (SA-DQ-5: `first_stake` never
    // broadcasts) and dispatch through the audited posture→submitter choke
    // point — exactly what WI-3's block-timed driver does when the post
    // comes due (see the module docs for why the driver's decorrelation
    // timing is deliberately not exercised here).
    let post = {
        let pending_write_lock = { arc.read().await.pending_write_lock.clone() };
        let store = pending_post_store_for_engine(arc.clone(), pending_write_lock);
        store
            .read(|block| block.posts().first().cloned())
            .await
            .expect("pending-post read")
            .expect("first_stake seals exactly one pending post")
    };
    let bound = PBoundBytes::from_pending(&post);
    let persona_id = *bound.persona();
    let swept_gindexes: Vec<u64> = post.funding_gindexes.iter().map(|g| g.to_raw()).collect();
    let daemon_client = { arc.read().await.daemon().clone() };
    let submitter = BroadcastSubmitter::local(persona_id, Arc::new(daemon_client));
    let verdict = submitter.submit_bound(bound).await;

    // Accepted-and-applied (the promoted PR-4a tripwire): the daemon's
    // PR-4b bond-post Phase-C battery verifies the wallet-built post over
    // real RPC. Any rejection — Phase A, Phase C, transport — fails loudly.
    let receipt = verdict.unwrap_or_else(|e| {
        panic!(
            "daemon must accept the wallet-built bond post \
             (PR-4b battery landed; got {e:?})"
        )
    });
    eprintln!("bond post accepted by the daemon submit engine: {receipt:?}");

    // Applied: mine the accepted post into a block, then past the scan
    // horizon, and re-run the production P-scan — the sealed state must
    // carry the persona's bond-post match (rung-2 substrate) and a
    // `BondPostChange` change-funding output beyond the pre-post set (the
    // outputs the emission-claim e2e, PR-4c, spends from).
    //
    mine_until_pool_drains(daemon, &principal, "accepted bond post", 5).await;
    daemon
        .generate_blocks(PSCAN_TEST_REORG_DEPTH + 2, &principal)
        .await;
    refresh(&arc).await;
    let state = pscan_until(
        &arc,
        &pscan_seal,
        "the bond-post match + BondPostChange change funding",
        |s| {
            s.bond_post_matches()
                .iter()
                .any(|m| m.p_canonical_id == persona_id)
                && s.funding_outputs()
                    .iter()
                    .any(|r| r.p_slot == slot && r.lineage == MintLineageOutput::BondPostChange)
        },
    )
    .await;
    let confirmed_tip_height = daemon.height().await;

    ConfirmedBondFixture {
        arc,
        _tmp: tmp,
        principal,
        persona_id,
        pscan_seal,
        state,
        swept_gindexes,
        pre_post_discovered,
        confirmed_tip_height,
    }
}

/// PR-4 staker harness (`EMISSION_CLAIM_BUILDER.md` §8 PR-4): a staker wallet
/// funds its persona on-chain (a wallet-built FCMP++ transfer to the persona's
/// derived receive address — the production rung-1 `ExternalTransfer` funding),
/// the production P-scan discovers the funding, and the production bond path
/// ([`Engine::assemble_bond_post`](super::Engine::assemble_bond_post) →
/// posture→submitter choke point) dispatches the bond post over real RPC.
///
/// **Accepted-and-applied (the promoted PR-4a tripwire).** The daemon's
/// PR-4b bond-post Phase-C battery (`DAEMON_SUBMIT_VERDICT.md` §8.7.1 BP
/// rows; `shekyl-daemon-rpc/src/submit/verifier.rs::verify_bond_post`)
/// verifies the wallet-built post over real RPC. The trailing assertions
/// pin the full loop: submit accepted, bond mined, and the rung-2
/// bond-post match + `BondPostChange` change funding re-discovered by this
/// same production scan, with the swept pre-post funding records PRUNED
/// from the sealed state — the SP-R0 arm-#1 **production fire** (DQ-F):
/// the stake enters through [`Engine::first_stake`], whose preflight sweep
/// mints the `arm1_watch_pruning_live` witness, so the whole
/// persist → assemble → seal → dispatch → confirm → prune loop runs on
/// production code. The surviving funding set is the `BondPostChange`
/// change — the substrate the emission-claim e2e (PR-4c) spends from.
/// (This test was the PR-4a daemon-gap tripwire pinning the old
/// unimplemented-arm `Malformed` refusal; PR-4b promoted it.)
///
/// Bounded deviations from production, each named:
/// - The sealed pending post is re-lifted (`PBoundBytes::from_pending`) and
///   dispatched directly through the audited posture→submitter choke point
///   rather than by WI-3's block-timed dispatch driver: the driver's
///   decorrelation offsets span up to ~600 blocks (its timing law has its
///   own KATs); the harness proves the chain-facing contract.
/// - A shallow P-scan finality horizon + tight cadence via the injectable
///   `start_pscan_with` seam (see [`PSCAN_TEST_REORG_DEPTH`]).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "PR-4 staker harness; needs SHEKYLD_BIN + a built regtest daemon"]
async fn e2e_staker_bond_post_accepted_and_applied() {
    use super::stake_engine::PSlot;
    use shekyl_engine_state::pscan_state::MintLineageOutput;

    const SLOT: u32 = 0;
    /// Extra persona funding above `floor + fee`, so the sweep-all bond leaves
    /// a non-zero change output — the persona's rung-2 `BondPostChange` funding
    /// (the emission-claim e2e sizes its own, larger cushion).
    const FUNDING_CUSHION: u64 = 200_000_000;

    let daemon = RegtestDaemon::start().await;
    // Schedule guard (serial lock now held): this test's wallet epoch
    // arithmetic must run on the genesis pin. A sibling e2e that armed the
    // SEB lever in this process would otherwise bleed its schedule in
    // silently (the `OnceLock` is irreversible) — fail loudly instead.
    assert_eq!(
        shekyl_archival_retention::effective_settlement_epoch_blocks(),
        shekyl_archival_retention::SETTLEMENT_EPOCH_BLOCKS,
        "another test latched a levered settlement-epoch schedule in this process; \
         run the regtest e2es in separate processes"
    );
    let seed = [0x44u8; shekyl_crypto_pq::account::MASTER_SEED_BYTES];
    let slot = PSlot::from_raw(SLOT);
    let fixture = stake_persona_to_confirmed_bond(
        &daemon,
        &seed,
        SLOT,
        FUNDING_CUSHION,
        FixtureStake::FirstStake,
    )
    .await;

    let post_change = fixture
        .state
        .funding_outputs()
        .iter()
        .filter(|r| r.p_slot == slot && r.lineage == MintLineageOutput::BondPostChange)
        .count();
    let total = fixture
        .state
        .funding_outputs()
        .iter()
        .filter(|r| r.p_slot == slot)
        .count();
    // The swept pre-post funding records are PRUNED at scan time (SP-R0
    // arm 1: the key-image watch fires on the bond post's own funding
    // spends), so the persona's surviving funding set is the bond-post
    // change — the rung-2 substrate PR-4c spends from — not a superset of
    // the pre-post record(s).
    assert!(
        fixture
            .state
            .funding_outputs()
            .iter()
            .all(|r| !fixture.swept_gindexes.contains(&r.gindex.to_raw())),
        "the swept funding record must be pruned from the sealed set (SP-R0 arm 1)"
    );
    eprintln!(
        "bond post accepted-and-applied: match re-discovered; {post_change} \
         BondPostChange output(s), {total} persona funding output(s) \
         ({} pre-post record(s) swept+pruned)",
        fixture.pre_post_discovered
    );
}

/// PR-4c emission-claim harness (`EMISSION_CLAIM_BUILDER.md` §8 PR-4c): the
/// full staker reward loop over real RPC — serve credit injected under the
/// `SHEKYL_SETTLEMENT_EPOCH_BLOCKS` lever, the epoch closed by mining, the
/// claim built by the production CB-3 path ([`Engine::submit_emission_claim`]
/// — no parallel builder), accepted by the daemon's PR-4b emission battery
/// (`DAEMON_SUBMIT_VERDICT.md` §8.7.2 E-rows), and **applied**: the
/// claimed-set row lands, the loud reward vout pays exactly the epoch's
/// accrued budget, and the production P-scan re-discovers the reward as the
/// persona's rung-1 [`MintLineageOutput::EmissionReward`] funding.
///
/// **Block geography (pinned).** One settlement epoch is sized to hold the
/// whole bond substrate (`SEB = 512` ≫ the ~300 blocks the confirmed-bond
/// fixture mines), so the bond joins in epoch 0 — and the onset stagger
/// (`good_through`: a bond is a market member from `join_epoch + 1`, never
/// in its join epoch) makes **epoch 1 the first claimable epoch**: the
/// serve credit is injected for epoch 1, epoch 1 is mined closed, and the
/// claim targets it. Epoch 0 closes zero-work along the way — the
/// no-staker epoch whose budget is never minted (claims are wallet-timed
/// mints; an unclaimable epoch's accrual simply never enters supply) —
/// and the claim builder must EXCLUDE it (`claimed_epochs == [1]`), which
/// is the no-staker leg's e2e observable. The pinned ordering
/// `inject < referenceBlock < epoch_close < claim ≤ tip` follows from
/// claiming within `REF_ANCHOR_AGE` blocks of the close (the close-detect
/// loop mines in 3-block steps so the overshoot stays inside that
/// window). Blocks between the close and the claim carry no epoch-2 serve
/// credit — the zero-staker stretch the A5b pop leg straddles.
///
/// **Conservation (A6, `§9.5 item 8`).** The claim's reward vout must equal
/// `budget_atomic(1)` byte-exactly — the daemon's per-block accrual
/// `staker_emission + staker_pool_amount` (blockchain.cpp) summed over the
/// epoch, i.e. the staker-inflow identity over real RPC. At regtest e2e
/// activity the fee-pool half is **genuinely zero by the law**, and the
/// test pins that executably: `get_tx_volume_avg` is an integer per-block
/// mean over `SHEKYL_TX_VOLUME_WINDOW`, a handful of e2e txs floors it to
/// 0, and a zero volume operand zeroes `burn_pct` — so `compute_burn_split`
/// legitimately yields `staker_pool_amount = 0` (asserted via
/// `total_burned == 0`, the tied observable). Driving the pool half
/// positive needs a sustained ≥ 1 tx/block average — infeasible in an e2e;
/// the positive-pool split coverage is the B5 unit KAT family. The claim
/// itself still carries real `ToKey` fee inputs (`fee_gindexes`
/// non-empty), not the Q11 zero-fee form, so the fee-subset battery leg
/// runs live.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "PR-4 staker harness; needs SHEKYLD_BIN + a built regtest daemon"]
async fn e2e_emission_claim_accepted_and_applied() {
    use super::bond_assembly::SpentRecordsDurablyPruned;
    use super::claim_dispatch::EmissionClaimRequestError;
    use super::claim_orchestrator::ClaimOrchestrationError;
    use super::emission_source::fetch_emission_claim_source;
    use super::prpc::LocalNodeRpc;
    use super::stake_engine::PSlot;
    use super::traits::DaemonEngine;
    use shekyl_curve_tree::reference::REF_ANCHOR_AGE;
    use shekyl_engine_state::pscan_state::MintLineageOutput;
    use shekyl_units::AtomicUnits;

    const SLOT: u32 = 0;
    /// Settlement-epoch size under the lever: large enough that the whole
    /// confirmed-bond substrate (~300 blocks) fits inside epoch 0 (pinning
    /// the join epoch), small enough that mining epoch 1 closed is cheap.
    const SEB: u64 = 512;
    const SHARD_ID: u64 = 0;
    /// The claimed epoch. The bond joins in epoch 0 and the onset stagger
    /// (`good_through`) defers market membership to `join + 1`, so epoch 1
    /// is the first epoch whose serve credit carries weight.
    const TARGET_EPOCH: u64 = 1;
    /// Persona funding above `floor + bond fee`: becomes the sweep-all
    /// bond's `BondPostChange` change output (and the size of the second,
    /// post-bond transfer). The claim's fee must be covered by the single
    /// non-backing record alone (Q11 excludes the designated backing from
    /// the fee set), and the claim fee rides the ~48 KiB non-claims
    /// envelope at the young chain's ~69k/byte floor ≈ 3.4e9 — 12e9 gives
    /// each record standalone headroom.
    const CLAIM_FUNDING_CUSHION: u64 = 12_000_000_000;

    // (A1) Spawn the daemon FIRST — `start_with_settlement_epoch_blocks`
    // takes the e2e serial lock, so sibling `--ignored` tests cannot
    // interleave with the arming below — then arm the settlement-epoch
    // lever in THIS process before any of ITS epoch arithmetic latches
    // the genesis schedule (the daemon child is a separate process; its
    // FAKECHAIN arming reads the env at startup and is not in this race).
    //
    // Containment is honest, not perfect: the schedule is a process-wide
    // irreversible `OnceLock`, so serialization cannot UNDO a latch — if a
    // sibling ran first and did epoch arithmetic, `arm` refuses loudly
    // (`ArmedTooLate`), and if THIS test ran first, siblings that need the
    // genesis pin fail their own schedule guard (see the bond e2e) —
    // either direction is a loud named failure, never silent bleed. Run
    // the regtest e2es in separate processes (the module docs' one-test
    // invocation) for green runs.
    let daemon = RegtestDaemon::start_with_settlement_epoch_blocks(Some(SEB)).await;
    // The lever is set and deliberately NOT restored afterwards: it is the
    // only input `arm` reads, and once armed the schedule latch is
    // irreversible, so leaving the variable set keeps the process's two
    // views of the schedule CONSISTENT (env says levered, latch is
    // levered). Scrubbing it on the way out would leave the more dangerous
    // state — a levered process that reports no lever. Child processes do
    // not inherit it by accident: the spawn seam sets it explicitly for
    // `Some(seb)` and `env_remove`s it for `None`.
    std::env::set_var("SHEKYL_SETTLEMENT_EPOCH_BLOCKS", SEB.to_string());
    let armed = shekyl_archival_retention::arm_settlement_epoch_override_for_regtest()
        .expect("the SEB lever must arm before any epoch arithmetic latches the schedule");
    assert_eq!(armed, SEB, "armed schedule must be the lever value");

    // The shared confirmed-bond substrate runs entirely inside epoch 0.
    let seed = [0x55u8; shekyl_crypto_pq::account::MASTER_SEED_BYTES];
    let slot = PSlot::from_raw(SLOT);
    // The claimable bond must be a MARKET bond (`ShardSetCompact`): the
    // `first_stake` genesis posture (CompleteTree) is foundation-shaped and
    // market-excluded (E-2), so its Σwork is zero forever — surfaced by
    // this e2e's first close. The declared shard need not be frozen
    // (`bond_post.rs`: adding an unfrozen shard is valid), and an unfrozen
    // credited shard carries age 0 ⇒ `g(0) = WORK_MILLI_SCALE` ⇒ positive
    // work.
    let market_holdings = shekyl_archival_retention::HoldingsDescriptor {
        kind: shekyl_archival_retention::HoldingsKind::ShardSetCompact,
        shard_ids: shekyl_archival_retention::ShardSet::new(vec![SHARD_ID])
            .expect("one-shard holdings"),
    };
    let fixture = stake_persona_to_confirmed_bond(
        &daemon,
        &seed,
        SLOT,
        CLAIM_FUNDING_CUSHION,
        FixtureStake::MarketBond(market_holdings),
    )
    .await;
    assert!(
        fixture.confirmed_tip_height + 16 < SEB,
        "the bond substrate (tip {}) must fit inside epoch 0 (close {SEB}) with injection \
         room; raise SEB",
        fixture.confirmed_tip_height
    );

    // The claim spends TWO distinct persona outputs: the designated backing
    // (the membership proof — Q11 excludes it from the fee set
    // structurally, `BackingSet::fee_sweep`) and at least one fee input.
    // The sweep-all bond leaves exactly ONE (the `BondPostChange` change),
    // so fund the persona once more post-bond — an ordinary rung-1
    // ExternalTransfer — and re-run the production P-scan so the sealed
    // state carries both records before the claim reads it.
    transfer_to(
        &daemon,
        &fixture.arc,
        &fixture.principal,
        &persona_address(&seed, SLOT),
        shekyl_units::AtomicUnits::from_raw(CLAIM_FUNDING_CUSHION),
        10,
        24,
    )
    .await;
    daemon
        .generate_blocks(PSCAN_TEST_REORG_DEPTH + 2, &fixture.principal)
        .await;
    refresh(&fixture.arc).await;
    let state = pscan_until(
        &fixture.arc,
        &fixture.pscan_seal,
        "the post-bond fee funding (2 spendable persona records)",
        |s| {
            s.funding_outputs()
                .iter()
                .filter(|r| r.p_slot == slot)
                .count()
                >= 2
        },
    )
    .await;
    eprintln!(
        "persona holds {} funding record(s) pre-claim (backing + fee substrate)",
        state
            .funding_outputs()
            .iter()
            .filter(|r| r.p_slot == slot)
            .count()
    );

    // (A2) Inject one serve-credit bit for (persona, shard 0, TARGET_EPOCH).
    // The bit store is epoch-keyed and injection is height-free, but the
    // injection HEIGHT is what the pop legs must stay above (the store is
    // not pop-symmetric), so it is recorded here. Single claimant holding
    // all Σwork ⇒ its share is the whole epoch budget.
    let inject_height = daemon.height().await;
    daemon
        .inject_serve_credit(&fixture.persona_id, SHARD_ID, TARGET_EPOCH)
        .await;
    eprintln!("serve credit injected for epoch {TARGET_EPOCH} at height {inject_height}");

    // (A1 close) Mine until the daemon reports TARGET_EPOCH closed (budget
    // row written), in 3-block steps so the tip overshoots the close by
    // less than `REF_ANCHOR_AGE` — the pinned `referenceBlock < epoch_close`
    // ordering depends on claiming inside that window.
    let p_id_bytes = fixture.persona_id.to_bytes();
    let epoch_row = loop {
        let src = fetch_emission_claim_source(&daemon.rpc, &p_id_bytes)
            .await
            .expect("claim-source fetch");
        if let Some(row) = src
            .epochs
            .iter()
            .find(|e| e.settlement_epoch == TARGET_EPOCH && e.has_budget_row)
        {
            break row.clone();
        }
        let h = daemon.height().await;
        assert!(
            h < (TARGET_EPOCH + 1) * SEB + 64,
            "epoch {TARGET_EPOCH} never closed with a budget row by height {h} (SEB {SEB})"
        );
        daemon.generate_blocks(3, &fixture.principal).await;
    };
    let total_burned_at_close = daemon.total_burned().await;
    eprintln!(
        "epoch {TARGET_EPOCH} closed at {}: budget {} atomic, sigma-work {} milli, \
         {} credit pair(s); total_burned {}",
        epoch_row.close_block_height,
        epoch_row.budget_atomic,
        epoch_row.sigma_work_milli,
        epoch_row.credit_pairs.len(),
        total_burned_at_close,
    );
    assert!(
        !epoch_row.credit_pairs.is_empty(),
        "the injected serve credit must surface in the closed epoch's credit pairs"
    );
    assert!(
        epoch_row.sigma_work_milli > 0,
        "the closed epoch must carry the injected work (membership from join+1)"
    );
    assert!(
        epoch_row.budget_atomic > 0,
        "the closed epoch must have accrued a positive budget"
    );
    assert!(
        epoch_row.claimant_bond_idx.is_some(),
        "the fixture's bond must be a claimant in the closed epoch"
    );
    // A6 pool-half disposition (module docs): at e2e activity the integer
    // per-block volume mean floors to 0, a zero volume operand zeroes
    // `burn_pct`, and `compute_burn_split` then yields a zero pool half AND
    // a zero destroyed half from the same `burned` product — `total_burned`
    // is the tied observable, pinned here so an operand-law change
    // re-surfaces this disposition instead of silently shifting the budget.
    assert_eq!(
        total_burned_at_close, 0,
        "regtest e2e activity must floor the volume mean to 0 ⇒ zero fee burn \
         (pool-half disposition, §9.5 item 8; positive-pool coverage is the B5 KATs)"
    );
    // The no-staker epoch: epoch 0 (the join epoch) closed zero-work — its
    // budget row exists but Σwork is 0, so nothing of it is claimable and
    // its accrual never mints (never enters supply).
    let src_now = fetch_emission_claim_source(&daemon.rpc, &p_id_bytes)
        .await
        .expect("claim-source fetch");
    let join_epoch_row = src_now
        .epochs
        .iter()
        .find(|e| e.settlement_epoch == 0 && e.has_budget_row)
        .expect("the join epoch must have closed with a budget row");
    assert_eq!(
        join_epoch_row.sigma_work_milli, 0,
        "the join epoch must close zero-work (onset stagger: no membership in the join epoch)"
    );

    // (A3) Build and dispatch the claim through the production CB-3 path.
    // The fee rides swept `ToKey` inputs; derive it from the daemon's live
    // estimate over the claim's own production envelope — the ~48 KiB
    // `EMISSION_NON_CLAIMS_RESERVE_BYTES` (two fee-side FCMP++ proofs +
    // hybrid PQC auths + 16-vout worst case + Bp+ clawback) plus a small
    // vin allowance for the single claim row. The bond's 32 KiB ceiling is
    // too small here — a claim carries TWO input proofs where the bond
    // carries one (live run 4's daemon-side `FeeTooLow`); overpaying is a
    // miner transfer, never a conservation term.
    use super::emission_claim::EMISSION_NON_CLAIMS_RESERVE_BYTES;
    refresh(&fixture.arc).await;
    let claim_fee = {
        let estimates = fixture
            .arc
            .read()
            .await
            .daemon()
            .get_fee_estimates()
            .await
            .expect("daemon fee estimates");
        estimates
            .economy
            .calculate_fee_from_weight(EMISSION_NON_CLAIMS_RESERVE_BYTES + 2048)
    };
    let claim_rpc = LocalNodeRpc::new(
        format!("http://127.0.0.1:{}", daemon.rpc_port),
        Duration::from_secs(10),
    )
    .await
    .expect("loopback claim transport");
    let pruning_landed = SpentRecordsDurablyPruned::for_test();
    let mut receipt = None;
    let mut tip_before_claim = 0;
    for attempt in 0..4 {
        tip_before_claim = daemon.height().await;
        match super::Engine::submit_emission_claim(
            fixture.arc.clone(),
            &claim_rpc,
            slot,
            AtomicUnits::from_raw(claim_fee),
            &pruning_landed,
        )
        .await
        {
            Ok(r) => {
                receipt = Some(r);
                break;
            }
            // Resync-and-retry arms (the wallet's own docs): the tree or
            // header window lags the tip. Mine ONE block per retry — the
            // pinned ordering needs the successful attempt's reference to
            // stay below the close.
            Err(EmissionClaimRequestError::Claim(
                e @ (ClaimOrchestrationError::ReferenceUnanchorable { .. }
                | ClaimOrchestrationError::MissingBlockHash { .. }),
            )) => {
                eprintln!("claim attempt {attempt}: {e}; resyncing");
                daemon.generate_blocks(1, &fixture.principal).await;
                refresh(&fixture.arc).await;
            }
            Err(e) => panic!("submit_emission_claim: {e}"),
        }
    }
    let receipt = receipt.expect("claim must assemble and dispatch within the retry budget");
    eprintln!(
        "emission claim accepted: epochs {:?}, reward {}, {} fee input(s)",
        receipt.claim.claimed_epochs,
        receipt.claim.total_reward,
        receipt.claim.fee_gindexes.len(),
    );

    // (A4/A6) The dispatched claim's shape: epoch 0 claimed, real ToKey fee
    // inputs (not the Q11 zero-fee form), and the loud vout equal to the
    // epoch's whole budget byte-exactly (single claimant holding all Σwork
    // ⇒ `floor(budget·capped/Σwork) = budget`) — the staker-inflow
    // conservation identity `inflow = staker_emission + staker_pool_amount`
    // over real RPC.
    assert_eq!(
        receipt.claim.claimed_epochs,
        vec![TARGET_EPOCH],
        "the claim must claim exactly the work-bearing epoch — the zero-work join epoch \
         is EXCLUDED (the no-staker leg: unclaimable accrual never mints)"
    );
    assert!(
        !receipt.claim.fee_gindexes.is_empty(),
        "the claim must carry real ToKey fee inputs (A6)"
    );
    assert_eq!(
        receipt.claim.total_reward, epoch_row.budget_atomic,
        "single-claimant reward must equal the epoch's accrued budget byte-exactly \
         (conservation, both inflow halves)"
    );
    // Pinned geography: inject < referenceBlock < epoch_close < claim tip.
    // The wallet anchors at `synced_tip − REF_ANCHOR_AGE`; `tip_before_claim`
    // is the daemon height the successful attempt saw.
    let reference_est = tip_before_claim - REF_ANCHOR_AGE;
    assert!(
        inject_height < reference_est,
        "inject ({inject_height}) must precede the claim reference (~{reference_est})"
    );
    assert!(
        reference_est < epoch_row.close_block_height,
        "the claim reference (~{reference_est}) must precede the epoch close ({}) — \
         the A5c pop-through-reference geometry",
        epoch_row.close_block_height
    );

    // Applied: mine the claim in, then past the scan horizon; the daemon's
    // claimed-set row must land and the production P-scan must re-discover
    // the reward as the persona's rung-1 EmissionReward funding, amount
    // equal to the loud vout.
    mine_until_pool_drains(&daemon, &fixture.principal, "accepted emission claim", 1).await;
    let claim_mined_by_height = daemon.height().await;
    assert!(
        epoch_row.close_block_height < claim_mined_by_height,
        "claim mined ({claim_mined_by_height}) after the close ({})",
        epoch_row.close_block_height
    );
    let src = fetch_emission_claim_source(&daemon.rpc, &p_id_bytes)
        .await
        .expect("claim-source refetch");
    let claimed = src
        .bond
        .as_ref()
        .expect("bond context after claim")
        .claimed_settlement_epochs
        .clone();
    assert!(
        claimed.contains(&TARGET_EPOCH),
        "the daemon's claimed-set row for epoch {TARGET_EPOCH} must land (got {claimed:?})"
    );

    // ── (A5a) Depth-1 pop: undo exactly the claim block ──
    // The batch-1 drain left the claim block as the tip. Popping it must
    // clear the daemon's claimed-set row and return the claim tx to the
    // pool (`pop_block_from_blockchain` is tx-conserving), with the budget
    // row untouched (the pop stays above the close); re-mining must
    // re-include the identical bytes (popped txs re-enter at
    // `relay_method::block`, broadcast-visible — no embargo) and re-apply
    // the claimed-set row, the conservation operands byte-identical.
    let tip_with_claim = daemon.height().await;
    daemon.pop_blocks(1).await;
    let src_popped = fetch_emission_claim_source(&daemon.rpc, &p_id_bytes)
        .await
        .expect("claim-source after depth-1 pop");
    let claimed_after_pop = &src_popped
        .bond
        .as_ref()
        .expect("bond context after depth-1 pop")
        .claimed_settlement_epochs;
    assert!(
        !claimed_after_pop.contains(&TARGET_EPOCH),
        "depth-1 pop must clear the claimed-set row (got {claimed_after_pop:?})"
    );
    let row_popped = src_popped
        .epochs
        .iter()
        .find(|e| e.settlement_epoch == TARGET_EPOCH && e.has_budget_row)
        .expect("the budget row must survive a pop above the close");
    assert_eq!(
        row_popped.budget_atomic, epoch_row.budget_atomic,
        "the budget row must be untouched by a pop above the close"
    );
    let pool_after_pop = daemon.tx_pool_size().await;
    assert_eq!(
        pool_after_pop, 1,
        "the popped claim tx must return to the pool"
    );
    daemon.generate_blocks(1, &fixture.principal).await;
    let pool_after_remine = daemon.tx_pool_size().await;
    assert_eq!(
        pool_after_remine, 0,
        "the re-mined block must re-include the claim"
    );
    assert_eq!(daemon.height().await, tip_with_claim);
    let src_remined = fetch_emission_claim_source(&daemon.rpc, &p_id_bytes)
        .await
        .expect("claim-source after depth-1 re-mine");
    assert!(
        src_remined
            .bond
            .as_ref()
            .expect("bond context after re-mine")
            .claimed_settlement_epochs
            .contains(&TARGET_EPOCH),
        "re-mining the identical claim must re-apply the claimed-set row"
    );
    let row_remined = src_remined
        .epochs
        .iter()
        .find(|e| e.settlement_epoch == TARGET_EPOCH && e.has_budget_row)
        .expect("budget row after re-mine");
    assert_eq!(
        (row_remined.budget_atomic, row_remined.sigma_work_milli),
        (epoch_row.budget_atomic, epoch_row.sigma_work_milli),
        "conservation operands must hold byte-identically across pop + re-mine (A5a)"
    );
    eprintln!("A5a depth-1 pop/re-mine: claimed-set cleared and re-applied byte-identically");

    // ── (A5b) Epoch-straddling pop: undo the close itself ──
    // Depth reaches the close block; the floor stays strictly above the
    // injection height — the serve-credit store is NOT pop-symmetric, so a
    // pop below the inject would desync the bits. The popped range holds
    // the close and the post-close blocks that carry no epoch-1 serve
    // credit (the zero-staker stretch). Undoing the close must delete the
    // budget row and the claimed-set row together; re-mining must re-close
    // epoch 0 from the pop-surviving credit bits byte-identically, then
    // re-apply the claim (the drain loop tolerates the claim being
    // template-skipped until the re-close lands).
    let tip = daemon.height().await;
    assert!(
        inject_height < epoch_row.close_block_height,
        "pop floor (close {}) must sit strictly above the inject ({inject_height})",
        epoch_row.close_block_height
    );
    // Convention: `close_block_height` is the close OPERAND `(E+1)·SEB`;
    // the close itself fires while CONNECTING the epoch's last block,
    // index `close_block_height − 1` (blockchain_db.cpp: the accrual
    // comment — "the close of epoch E fires while connecting E's last
    // block (operand prev_height + 1)"), and `height()` is the chain
    // LENGTH — so undoing the close means popping down to length
    // `close_block_height − 1`.
    let straddle_depth = tip - (epoch_row.close_block_height - 1);
    daemon.pop_blocks(straddle_depth).await;
    let src_straddle = fetch_emission_claim_source(&daemon.rpc, &p_id_bytes)
        .await
        .expect("claim-source after straddling pop");
    assert!(
        !src_straddle
            .epochs
            .iter()
            .any(|e| e.settlement_epoch == TARGET_EPOCH && e.has_budget_row),
        "the straddling pop must undo the close (budget row deleted)"
    );
    if let Some(bond) = src_straddle.bond.as_ref() {
        assert!(
            !bond.claimed_settlement_epochs.contains(&TARGET_EPOCH),
            "the straddling pop must clear the claimed-set row"
        );
    }
    mine_until_pool_drains(
        &daemon,
        &fixture.principal,
        "re-applied emission claim (A5b)",
        1,
    )
    .await;
    let src_reclosed = fetch_emission_claim_source(&daemon.rpc, &p_id_bytes)
        .await
        .expect("claim-source after re-close");
    let row_reclosed = src_reclosed
        .epochs
        .iter()
        .find(|e| e.settlement_epoch == TARGET_EPOCH && e.has_budget_row)
        .expect("the epoch must re-close from the pop-surviving credit bits");
    assert_eq!(
        (row_reclosed.budget_atomic, row_reclosed.sigma_work_milli),
        (epoch_row.budget_atomic, epoch_row.sigma_work_milli),
        "the re-closed epoch must be byte-identical (accrual blocks below the floor \
         untouched; credit bits pop-surviving)"
    );
    assert!(
        src_reclosed
            .bond
            .as_ref()
            .expect("bond context after re-close")
            .claimed_settlement_epochs
            .contains(&TARGET_EPOCH),
        "the claim must re-apply after the re-close (A5b)"
    );
    eprintln!(
        "A5b straddling pop (depth {straddle_depth}, floor {}): close undone and \
         re-closed byte-identically, claim re-applied",
        epoch_row.close_block_height
    );

    daemon
        .generate_blocks(PSCAN_TEST_REORG_DEPTH + 2, &fixture.principal)
        .await;
    refresh(&fixture.arc).await;
    let expected_reward = receipt.claim.total_reward;
    let state = pscan_until(
        &fixture.arc,
        &fixture.pscan_seal,
        "the EmissionReward funding output",
        |s| {
            s.funding_outputs().iter().any(|r| {
                r.p_slot == slot
                    && r.lineage == MintLineageOutput::EmissionReward
                    && r.amount.to_raw() == expected_reward
            })
        },
    )
    .await;
    let rewards = state
        .funding_outputs()
        .iter()
        .filter(|r| r.p_slot == slot && r.lineage == MintLineageOutput::EmissionReward)
        .count();
    eprintln!(
        "emission claim accepted-and-applied: claimed-set {claimed:?}; {rewards} \
         EmissionReward output(s) of {expected_reward} atomic re-discovered by the \
         production P-scan (inject {inject_height} < ref ~{reference_est} < close {} < \
         claim ≤ {claim_mined_by_height})",
        epoch_row.close_block_height,
    );

    // ── (A5c) Deep pop through the claim's reference block ──
    // The pop floor sits just below the claim's reference anchor (still far
    // above the inject), so the pop undoes the claim, both epoch closes,
    // and the block the claim's FCMP++ membership proof anchors to.
    // Re-mined blocks carry new hashes, so the popped claim tx is
    // structurally stranded — its proof binds a reference root that no
    // longer exists on the rebuilt chain. The correct terminal state: the
    // chain re-converges to the same height (the stranded tx must never
    // re-apply or wedge the miner), the claimed epoch re-closes
    // byte-identically from the pop-surviving credit bits, and the
    // claimed-set stays EMPTY. Building the replacement claim against the
    // rebuilt root is the retire/resubmit slice (the named B2 follow-on,
    // matching the bond precedent): the wallet's one-live-claim-per-persona
    // rule holds the pending record until that slice retires it.
    let tip_c = daemon.height().await;
    let pop_floor_c = reference_est - 1;
    assert!(
        inject_height < pop_floor_c,
        "the A5c floor ({pop_floor_c}) must stay above the inject ({inject_height})"
    );
    let depth_c = tip_c - pop_floor_c;
    daemon.pop_blocks(depth_c).await;
    daemon.generate_blocks(depth_c, &fixture.principal).await;
    assert_eq!(
        daemon.height().await,
        tip_c,
        "the chain must re-converge past the stranded claim (no miner wedge)"
    );
    let src_c = fetch_emission_claim_source(&daemon.rpc, &p_id_bytes)
        .await
        .expect("claim-source after deep-pop re-mine");
    let row_c = src_c
        .epochs
        .iter()
        .find(|e| e.settlement_epoch == TARGET_EPOCH && e.has_budget_row)
        .expect("the claimed epoch must re-close on the rebuilt chain");
    assert_eq!(
        (row_c.budget_atomic, row_c.sigma_work_milli),
        (epoch_row.budget_atomic, epoch_row.sigma_work_milli),
        "the rebuilt close must be byte-identical (bits survive; accrual below the floor)"
    );
    if let Some(bond) = src_c.bond.as_ref() {
        assert!(
            !bond.claimed_settlement_epochs.contains(&TARGET_EPOCH),
            "the stranded claim must NOT re-apply against the rebuilt root (its proof \
             binds a popped reference)"
        );
    }
    eprintln!(
        "A5c deep pop (depth {depth_c}, floor {pop_floor_c} < ref): chain re-converged, \
         epoch re-closed byte-identically, claimed-set empty (stranded claim inert) — \
         replacement claim is the B2 retire/resubmit slice"
    );
}

/// DS-PR-2 **T-DS-6 ∧ T-DS-7 composite wire-shape arm — the full
/// transfer-vs-drain byte-diff over real end-to-end txs**
/// (`ARCHIVAL_DRAIN_SEND_FD2.md` §5 composite arm; the in-slice
/// drain-vs-drain normalized diff rode DS-PR-1, and the design pins the
/// "against a real transfer" byte-diff to this DS-PR-2 regtest e2e — "a real
/// end-to-end transfer tx must exist to diff against").
///
/// A real 1-in/2-out confidential **transfer** (the ordinary `sign_tx` send
/// path) and a real 1-in/2-out `P`→principal **drain** ([`Engine::submit_drain`])
/// must serialize byte-identically once their hidden/committed/priced leaves
/// are flattened: the drain wears the modal transfer's wire skeleton — no
/// output-count (T-DS-6), no `tx_extra` / `unlock_time` / `ct_type`
/// distinguisher (T-DS-7), no proof-arity tell. Parity is already
/// compile-time by construction (both build their `WireEncodeInput` through
/// the single shared [`assemble_transfer_wire`](super::sign_bridge) constructor);
/// this e2e is the final confirmation over the live boundary, and both txs are
/// **daemon-accepted** (consensus verify at submit), so the arm is proven on
/// real, on-chain-valid bytes rather than a builder artifact.
///
/// The transfer is a small principal self-send (one large coinbase input, two
/// confidential outputs: recipient + change). The drain is a PARTIAL sweep of
/// the persona's single `BondPostChange` funding record (one input, principal
/// payment + `P`-space change), sized so change ≥ [`EXIT_FEE_RESERVE_ATOMIC`]
/// — a live persona keeps its exit-fee reserve (DS-4). Fees differ (transfer
/// weight-priced, drain caller-priced), so [`normalize_fcmp_wire_shape`]
/// flattens the public `fee` alongside the hidden leaves; the raw bytes are
/// asserted distinct first, so the normalized equality is not vacuous.
///
/// [`normalize_fcmp_wire_shape`]: super::test_support::normalize_fcmp_wire_shape
///
/// [`EXIT_FEE_RESERVE_ATOMIC`]: shekyl_standoff::EXIT_FEE_RESERVE_ATOMIC
#[tokio::test(flavor = "multi_thread")]
#[ignore = "PR-4 staker harness; needs SHEKYLD_BIN + a built regtest daemon"]
async fn e2e_drain_wire_shape_matches_a_real_transfer() {
    use super::drain_dispatch::DrainRequestError;
    use super::drain_orchestrator::DrainOrchestrationError;
    use super::pending::{FeePriority, TxRecipient, TxRequest};
    use super::stake_engine::PSlot;
    use super::traits::DaemonEngine;
    use shekyl_standoff::EXIT_FEE_RESERVE_ATOMIC;
    use shekyl_units::AtomicUnits;
    use shekyl_wire::{Ct, Input, Transaction};

    const SLOT: u32 = 0;
    /// The persona's `BondPostChange` record ≈ this cushion; sized well above
    /// `payment + fee + reserve` so a PARTIAL drain selects the single record
    /// and leaves change ≥ the exit-fee reserve (both txs stay 1-in/2-out).
    const FUNDING_CUSHION: u64 = 12_000_000_000;

    let daemon = RegtestDaemon::start().await;
    // Schedule guard (serial lock now held): a sibling e2e that armed the SEB
    // lever in this process would bleed its schedule in silently (the
    // `OnceLock` is irreversible) — fail loudly instead.
    assert_eq!(
        shekyl_archival_retention::effective_settlement_epoch_blocks(),
        shekyl_archival_retention::SETTLEMENT_EPOCH_BLOCKS,
        "another test latched a levered settlement-epoch schedule in this process; \
         run the regtest e2es in separate processes"
    );
    let seed = [0x66u8; shekyl_crypto_pq::account::MASTER_SEED_BYTES];
    let slot = PSlot::from_raw(SLOT);
    let fixture = stake_persona_to_confirmed_bond(
        &daemon,
        &seed,
        SLOT,
        FUNDING_CUSHION,
        FixtureStake::FirstStake,
    )
    .await;
    let principal = fixture.principal.clone();

    // The confirmed sweep-all bond leaves exactly one persona funding record
    // (the `BondPostChange` change) — the drain's single input.
    let persona_records = fixture
        .state
        .funding_outputs()
        .iter()
        .filter(|r| r.p_slot == slot)
        .count();
    assert_eq!(
        persona_records, 1,
        "the confirmed sweep-all bond must leave exactly one persona funding record to drain"
    );

    // ── A real 1-in/2-out transfer: capture its build-time wire bytes ──
    // A small principal self-send covered by a single coinbase output. Retry
    // past the C2 reference-spendability gate exactly as `transfer_to` does;
    // `PendingTx::tx_bytes` carries the signed bytes (build-time reference; the
    // skeleton diff zeroes `reference_block`, so a submit-time re-anchor is
    // irrelevant to the shape).
    refresh(&fixture.arc).await;
    let request = TxRequest {
        recipients: vec![TxRecipient {
            address: principal.clone(),
            amount_atomic_units: AtomicUnits::from_raw(100_000_000),
        }],
        priority: FeePriority::Standard,
    };
    let mut built = None;
    for _ in 0..24 {
        let attempt = {
            let g = fixture.arc.read().await;
            g.build_pending_tx_async(&request).await
        };
        match attempt {
            Ok(p) => {
                built = Some(p);
                break;
            }
            Err(super::error::SendError::OutputNotYetSpendable { .. }) => {
                daemon.generate_blocks(10, &principal).await;
                refresh(&fixture.arc).await;
            }
            Err(e) => panic!("build transfer: {e:?}"),
        }
    }
    let built = built.expect("transfer must build once reference-spendable");
    let transfer_bytes = built.tx_bytes.clone();
    {
        let g = fixture.arc.read().await;
        g.submit_pending_tx_async(built.id, built.content_gen)
            .await
            .expect("daemon must accept the transfer (consensus verify)");
    }
    mine_until_pool_drains(&daemon, &principal, "accepted transfer", 1).await;
    refresh(&fixture.arc).await;

    // ── A real 1-in/2-out drain: assemble + dispatch through submit_drain ──
    // Caller-priced fee over a generous envelope (overpay is a miner transfer,
    // never a conservation term); the daemon's acceptance at submit is the
    // real-bytes proof. Payment + fee + reserve < record ⇒ change > 0 and ≥
    // the exit-fee reserve (live persona), so the drain stays a partial
    // 1-in/2-out sweep.
    let drain_fee = {
        let estimates = fixture
            .arc
            .read()
            .await
            .daemon()
            .get_fee_estimates()
            .await
            .expect("daemon fee estimates");
        estimates.economy.calculate_fee_from_weight(32_768)
    };
    let drain_payment = AtomicUnits::from_raw(2_000_000_000);
    assert!(
        FUNDING_CUSHION > drain_payment.to_raw() + drain_fee + EXIT_FEE_RESERVE_ATOMIC,
        "fixture must keep the partial drain's change ≥ the exit-fee reserve \
         (payment {} + fee {drain_fee} + reserve {EXIT_FEE_RESERVE_ATOMIC} < cushion \
         {FUNDING_CUSHION})",
        drain_payment.to_raw(),
    );
    let mut receipt = None;
    for attempt in 0..4 {
        match super::Engine::submit_drain(
            fixture.arc.clone(),
            slot,
            drain_payment,
            AtomicUnits::from_raw(drain_fee),
            &super::bond_assembly::SpentRecordsDurablyPruned::for_test(),
        )
        .await
        {
            Ok(r) => {
                receipt = Some(r);
                break;
            }
            // Resync-and-retry: the tree or header window lags the tip.
            Err(DrainRequestError::Drain(
                e @ DrainOrchestrationError::ReferenceUnanchorable { .. },
            )) => {
                eprintln!("drain attempt {attempt}: {e}; resyncing");
                daemon.generate_blocks(1, &principal).await;
                refresh(&fixture.arc).await;
            }
            Err(e) => panic!("submit_drain: {e}"),
        }
    }
    let receipt = receipt.expect("drain must assemble and dispatch within the retry budget");
    let drain_bytes = receipt.drain.bound_tx.bytes().to_vec();
    eprintln!(
        "drain accepted by daemon: {} swept input(s), payment {}",
        receipt.drain.funding_gindexes.len(),
        drain_payment.to_raw(),
    );
    mine_until_pool_drains(&daemon, &principal, "accepted drain", 1).await;

    // ── The byte-diff: normalized skeletons identical, raw bytes distinct ──
    let mut cursor: &[u8] = &transfer_bytes;
    let transfer_tx = Transaction::read(&mut cursor).expect("transfer parses whole");
    assert!(cursor.is_empty(), "transfer bytes fully consumed");
    let mut cursor: &[u8] = &drain_bytes;
    let drain_tx = Transaction::read(&mut cursor).expect("drain parses whole");
    assert!(cursor.is_empty(), "drain bytes fully consumed");

    // Structural variables the normalizer does NOT flatten — a count delta
    // would survive the normalized diff, but pin them explicitly so a harness
    // change (a 2-in coinbase spend, a builder dummy output) fails loudly here
    // rather than as an opaque byte mismatch below.
    for (label, tx) in [("transfer", &transfer_tx), ("drain", &drain_tx)] {
        assert_eq!(
            tx.prefix.outputs.len(),
            2,
            "{label} must be the modal 2-out shape"
        );
        let tokey = tx
            .prefix
            .inputs
            .iter()
            .filter(|i| matches!(i, Input::ToKey { .. }))
            .count();
        assert_eq!(tokey, 1, "{label} must spend exactly one ToKey input");
        assert_eq!(
            tx.prefix.unlock_time, 0,
            "{label} unlock_time must be builder-zeroed"
        );
        assert!(
            matches!(tx.ct, Ct::Fcmp { .. }),
            "{label} must be an FCMP++ spend"
        );
    }

    // Non-vacuous: the raw bytes genuinely differ (distinct hidden amounts,
    // fees, keys) — otherwise the normalized equality below proves nothing.
    assert_ne!(
        super::test_support::whole_tx_wire_bytes(&transfer_tx),
        super::test_support::whole_tx_wire_bytes(&drain_tx),
        "raw transfer/drain bytes must differ"
    );

    let mut transfer_norm = transfer_tx;
    let mut drain_norm = drain_tx;
    super::test_support::normalize_fcmp_wire_shape(&mut transfer_norm);
    super::test_support::normalize_fcmp_wire_shape(&mut drain_norm);
    assert_eq!(
        super::test_support::whole_tx_wire_bytes(&transfer_norm),
        super::test_support::whole_tx_wire_bytes(&drain_norm),
        "a real drain is wire-identical to a real modal 2-out transfer modulo \
         hidden/committed/priced leaves — no output-count (T-DS-6), tx_extra / \
         unlock_time / ct_type (T-DS-7), or proof-arity distinguisher"
    );

    eprintln!(
        "T-DS-6 ∧ T-DS-7 e2e: a real drain is byte-identical to a real transfer \
         (normalized skeleton), both daemon-accepted"
    );
}

/// SP-R0 **arm #3 — PRODUCTION-DISCHARGE leg** (DQ-F): the SA-DQ-3
/// activation-induced **persist-then-no-broadcast crash**, driven against the
/// live regtest chain. `persist_bond_record` runs (the activation's durable
/// point — the W2 crash form: no assemble, no pending post, no broadcast),
/// the **production P-scan** exhaustively covers the real chain (the persona
/// posted nothing anywhere in `covered`), and the next **production open**
/// collects the phantom through the assemble-time sweep: the wallet reverts
/// to a clean non-staker. The W3 guard is exercised by construction — no
/// pending post exists, so the pending-record bridge does not veto.
///
/// This is the same fixture the in-tree CI lane
/// (`tests/sp_r0_arm3_fire.rs`) drives over fixture blocks; here the
/// evidence is the live daemon's chain through the real scan — the
/// production-discharge form.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "SP-R0 arm-#3 production discharge; needs SHEKYLD_BIN + a built regtest daemon"]
async fn e2e_arm3_phantom_slot_collected_at_open() {
    use super::stake_engine::PSlot;

    const SLOT: u32 = 0;
    let daemon = RegtestDaemon::start().await;
    // Schedule guard (see the bond e2e): wallet epoch arithmetic here must
    // run on the genesis pin; a sibling-armed levered schedule fails loudly.
    assert_eq!(
        shekyl_archival_retention::effective_settlement_epoch_blocks(),
        shekyl_archival_retention::SETTLEMENT_EPOCH_BLOCKS,
        "another test latched a levered settlement-epoch schedule in this process; \
         run the regtest e2es in separate processes"
    );
    let seed = [0x45u8; shekyl_crypto_pq::account::MASTER_SEED_BYTES];
    let slot = PSlot::from_raw(SLOT);
    // `staker_wallet` IS the crash fixture: it persists the bond record (the
    // durable point) and reopens — no assemble, no pending post, no
    // broadcast ever happens. The reopened wallet is the W2 phantom staker.
    let (arc, tmp, principal) = staker_wallet(daemon.rpc_port, &seed, slot).await;
    {
        let g = arc.read().await;
        assert!(g.ledger().staking.staking_enabled);
        assert!(g.has_stake_engine(), "the phantom staker derives + spawns");
    }

    // Give the chain a body and let the production scan exhaustively cover
    // it — the persona posted nothing, so the sealed evidence carries
    // confirmed absence over `covered`.
    daemon
        .generate_blocks(PSCAN_TEST_REORG_DEPTH + 12, &principal)
        .await;
    refresh(&arc).await;
    let pscan_seal = shekyl_engine_file::paths::pscan_state_path_from(&tmp.path().join("wallet"));
    let state = pscan_until(&arc, &pscan_seal, "a non-trivial covered range", |s| {
        s.cursor().synced_height().to_raw() >= 8
    })
    .await;
    assert!(
        state.bond_post_matches().is_empty(),
        "the phantom persona posted nothing"
    );

    // Close, reopen: the arm-#3 sweep runs at open, before derive.
    //
    // Sole-ownership reclaim is deliberate and deterministic here, not
    // brittle: `Engine::close(self, ..)` CONSUMES the engine (a lock-guard
    // close is not type-possible), and every clone-holder has provably
    // exited by this point — `pscan_until` shut its task down before
    // returning (the WI-1 shutdown contract releases the task's engine-arc
    // clone) and `refresh` joins to completion. This is the same fail-loud
    // posture as `close_wallet`'s production reclaim: if a future edit
    // leaves a task holding a clone, the panic below names the bug rather
    // than letting the test proceed against a still-live wallet.
    let creds = super::lifecycle::Credentials::password_only(b"pr4-staker");
    let lock = Arc::try_unwrap(arc).unwrap_or_else(|_| {
        panic!(
            "engine arc still has co-owners at close: a spawned task \
             (scan/refresh) was not shut down before the reopen step"
        )
    });
    lock.into_inner()
        .close(&creds)
        .expect("close phantom staker");
    let rpc = HttpRpc::new(format!("http://127.0.0.1:{}", daemon.rpc_port))
        .await
        .expect("wallet rpc (reopen)");
    let reopened = super::Engine::<super::SoloSigner>::open_full(
        &tmp.path().join("wallet"),
        &creds,
        shekyl_address::Network::Mainnet,
        super::DaemonClient::new(rpc),
        shekyl_engine_file::SafetyOverrides::none(),
    )
    .expect("reopen after the scan sealed confirmed absence")
    .into_wallet();
    assert!(
        !reopened.ledger().staking.staking_enabled,
        "arm #3 (production discharge): the phantom slot is collected and the \
         wallet reverts to a non-staker"
    );
    assert!(reopened.ledger().staking.bonded_slots.is_empty());
    assert!(
        !reopened.has_stake_engine(),
        "no actor spawns for the collected phantom"
    );
    eprintln!("arm #3 production discharge: phantom bonded_slots[{SLOT}] collected at open");
    reopened.close(&creds).expect("close");
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
