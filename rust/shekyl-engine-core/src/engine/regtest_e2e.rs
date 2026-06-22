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
use shekyl_rpc::Rpc;
use shekyl_simple_request_rpc::SimpleRequestRpc;
use tokio::sync::{Mutex, OwnedMutexGuard};

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
struct RegtestDaemon {
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
struct GenerateBlocksResp {
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
    async fn start() -> RegtestDaemon {
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
        let rpc = SimpleRequestRpc::new(format!("http://127.0.0.1:{rpc_port}"))
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

    async fn height(&self) -> u64 {
        self.rpc
            .json_rpc_call::<GetInfoResp>("get_info", None)
            .await
            .expect("get_info")
            .height
    }

    /// Mine `n` blocks to `address` (FAKECHAIN-gated daemon RPC).
    async fn generate_blocks(&self, n: u64, address: &str) -> GenerateBlocksResp {
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

    // Mine in 10-block batches (a single ~80-block call exceeds the RPC client
    // timeout) until coinbase outputs mature + drain into the reference tree.
    let mut leaf_count = 0u64;
    let mut mined = 0u64;
    for _ in 0..24 {
        daemon.generate_blocks(10, &address).await;
        mined += 10;
        let info: serde_json::Value = daemon
            .rpc
            .json_rpc_call("get_curve_tree_info", None)
            .await
            .expect("get_curve_tree_info must not 404");
        leaf_count = info
            .get("leaf_count")
            .and_then(serde_json::Value::as_u64)
            .expect("leaf_count field");
        if leaf_count > 0 {
            eprintln!("reference tree populated after {mined} blocks: leaf_count={leaf_count}");
            break;
        }
    }
    assert!(
        leaf_count > 0,
        "reference tree should populate within {mined} blocks; got leaf_count={leaf_count}"
    );

    // Fetch the membership path for the first leaf.
    let path: serde_json::Value = daemon
        .rpc
        .json_rpc_call(
            "get_curve_tree_path",
            Some(json!({ "output_indices": [0u64] })),
        )
        .await
        .expect("get_curve_tree_path must not 404");
    eprintln!("curve_tree_path([0]): {path}");

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
