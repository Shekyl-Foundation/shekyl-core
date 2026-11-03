// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `tx show` against a real regtest daemon.
//!
//! Ignored: it needs `SHEKYLD_BIN` built from this tree, because the
//! assertion reads the armed daemon's request line (`--dev-rpc`). A
//! wallet-held id is asked of the report after the wallet has been dropped,
//! so a scan poll is not in the delta the assertion reads.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use shekyl_rpc_client::Rpc;
use shekyl_rpc_transport::HttpRpc;
use shekyl_rpc_types::{DaemonNetwork, GetBlockRequest, GetBlockResponse};

use super::{report, DaemonEndpoint, TxShow};

#[test]
#[ignore = "needs SHEKYLD_BIN built from this tree; spawns a regtest daemon"]
fn tx_show_reads_the_wallet_or_the_daemon() {
    let daemon = Regtest::spawn();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let found = runtime.block_on(daemon.wallet_and_genesis());
    // The scan's requests have returned. A line still arriving is the
    // sink flushing one of them, and it must land before the snapshot
    // the held id is judged against.
    let _flushed = daemon.delta_after(Duration::from_secs(1));

    let records = format!("wallet holds {}", found.held);
    let held_at = daemon.marks();
    let held = report(&TxShow {
        id: &found.held,
        wallet_records: Some(&records),
        body: false,
        daemon: Some(&daemon.endpoint()),
    })
    .expect("the wallet's record");
    let held_delta = daemon.delta_after_mark(&held_at, Duration::from_secs(1));
    assert_eq!(held, records, "a held id is the wallet's record");
    assert!(
        !held_delta.contains("rpc request:"),
        "a held id asks nothing of the daemon:\n{held_delta}"
    );

    let foreign_at = daemon.marks();
    let foreign = report(&TxShow {
        id: &found.genesis,
        wallet_records: Some(""),
        body: false,
        daemon: Some(&daemon.endpoint()),
    })
    .unwrap_or_else(|error| panic!("the daemon's view: {error}"));
    let foreign_delta = daemon.delta_until(&foreign_at, "rpc request: /get_transactions");
    assert!(
        foreign.contains("Found in blockchain"),
        "an id the wallet does not hold is the daemon's view:\n{foreign}"
    );
    assert!(
        foreign_delta.contains("rpc request: /get_transactions"),
        "the daemon's view is a request the log records:\n{foreign_delta}"
    );

    let body_at = daemon.marks();
    let body = report(&TxShow {
        id: &found.held,
        wallet_records: Some(&records),
        body: true,
        daemon: Some(&daemon.endpoint()),
    })
    .expect("the bytes");
    let body_delta = daemon.delta_until(&body_at, "rpc request: /get_transactions");
    assert!(
        body.starts_with(&records),
        "the wallet's record stays the report:\n{body}"
    );
    assert!(
        body.lines()
            .any(|line| line.len() > 64 && line.bytes().all(|b| b.is_ascii_hexdigit())),
        "--body fetches the serialized bytes:\n{body}"
    );
    assert!(
        body_delta.contains("rpc request: /get_transactions"),
        "--body is a daemon request:\n{body_delta}"
    );
    assert!(
        !body.contains("The daemon now knows you asked for this transaction."),
        "a loopback daemon is not announced: the operator asked a daemon on this machine:\n{body}"
    );
}

struct Found {
    held: String,
    genesis: String,
}

struct Regtest {
    child: Child,
    data_dir: PathBuf,
    config_dir: PathBuf,
    url: String,
    logs: Vec<PathBuf>,
}

impl Regtest {
    fn spawn() -> Self {
        let bin = std::env::var_os("SHEKYLD_BIN").unwrap_or_else(|| {
            panic!(
                "SHEKYLD_BIN not set. Build the daemon from this tree and pass \
                 SHEKYLD_BIN=<build>/bin/shekyld"
            )
        });
        let rpc_port = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("port")
            .local_addr()
            .expect("addr")
            .port();
        let data_dir = std::env::temp_dir().join(format!("shekyl-tx-show-{rpc_port}"));
        drop(std::fs::remove_dir_all(&data_dir));
        std::fs::create_dir_all(&data_dir).expect("data dir");
        let config_dir = private_config_dir(rpc_port);
        let stdout = std::fs::File::create(data_dir.join("daemon.log")).expect("stdout log");
        let stderr = stdout.try_clone().expect("stderr log");
        let mine = mine_address(&SEED);
        let mut cmd = Command::new(bin);
        cmd.args([
            "--network",
            "regtest",
            "--dev-difficulty",
            "1",
            "--dev-rpc",
            "--tor",
            "off",
            "--clearnet",
            "off",
            "--rpc-admin-listen",
            &format!("127.0.0.1:{rpc_port}"),
            "--data-dir",
            data_dir.to_str().expect("utf8 data dir"),
            "--config-file",
            config_dir
                .join("shekyld.toml")
                .to_str()
                .expect("utf8 config"),
            "--log-file",
            data_dir.join("shekyld.log").to_str().expect("utf8 log"),
            "--log-level",
            "info",
            "--mine-address",
            &mine,
        ])
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .stdin(Stdio::null());
        let child = cmd.spawn().unwrap_or_else(|error| {
            drop(std::fs::remove_dir_all(&data_dir));
            drop(std::fs::remove_dir_all(&config_dir));
            panic!("spawn shekyld: {error}");
        });
        Self {
            child,
            logs: vec![data_dir.join("shekyld.log"), data_dir.join("daemon.log")],
            data_dir,
            config_dir,
            url: format!("http://127.0.0.1:{rpc_port}"),
        }
    }

    fn endpoint(&self) -> DaemonEndpoint<'_> {
        DaemonEndpoint {
            url: &self.url,
            proxy: None,
            network: DaemonNetwork::Fakechain,
            loopback: true,
            down_hint: None,
        }
    }

    fn marks(&self) -> Vec<u64> {
        self.logs.iter().map(|path| file_len(path)).collect()
    }

    fn delta_since(&self, marks: &[u64]) -> String {
        self.logs
            .iter()
            .zip(marks)
            .map(|(path, before)| {
                let text = std::fs::read_to_string(path).unwrap_or_default();
                let start = usize::try_from(*before).unwrap_or(0).min(text.len());
                text[start..].to_owned()
            })
            .collect()
    }

    fn delta_after(&self, wait: Duration) -> String {
        let marks = self.marks();
        std::thread::sleep(wait);
        self.delta_since(&marks)
    }

    fn delta_after_mark(&self, marks: &[u64], wait: Duration) -> String {
        std::thread::sleep(wait);
        self.delta_since(marks)
    }

    fn delta_until(&self, marks: &[u64], needle: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let delta = self.delta_since(marks);
            if delta.contains(needle) || Instant::now() >= deadline {
                return delta;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    async fn wallet_and_genesis(&self) -> Found {
        let rpc = HttpRpc::with_custom_timeout(self.url.clone(), Duration::from_secs(180))
            .await
            .expect("rpc client");
        await_ready(&rpc, &self.logs).await;
        await_template(&rpc).await;

        let dir = tempfile::tempdir().expect("wallet dir");
        let wallet_path = dir.path().join("wallet");
        let creds = shekyl_engine_core::Credentials::password_only(b"tx-show");
        let params = shekyl_engine_core::EngineCreateParams {
            base_path: &wallet_path,
            credentials: &creds,
            network: shekyl_address::Network::Mainnet,
            capability: shekyl_engine_core::CapabilityInput::Full {
                master_seed_64: &SEED,
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
        let wallet = shekyl_engine_core::Engine::<shekyl_engine_core::SoloSigner>::create(
            params,
            shekyl_engine_core::DaemonClient::verifying(rpc.clone(), regtest_expectation()),
        )
        .expect("create wallet");
        let wallet = std::sync::Arc::new(tokio::sync::RwLock::new(wallet));

        let mut held = None;
        for _ in 0..5 {
            rpc.json_rpc_call::<shekyl_rpc_types::mining::GenerateBlocksResponse>(
                "generateblocks",
                Some(serde_json::json!({ "count": 1 })),
            )
            .await
            .expect("generate one block");
            shekyl_engine_core::Engine::start_refresh(
                wallet.clone(),
                shekyl_engine_core::RefreshOptions::default(),
            )
            .await
            .expect("start refresh")
            .join()
            .await
            .expect("refresh joins");
            let engine = wallet.read().await;
            let hashes: Vec<String> = engine
                .ledger()
                .ledger
                .transfers()
                .iter()
                .map(|row| row.tx_hash.to_string())
                .collect();
            drop(engine);
            if let Some(hash) = hashes.into_iter().next() {
                held = Some(hash);
                break;
            }
        }
        let held = held.unwrap_or_else(|| {
            panic!(
                "the wallet scanned no coinbase; daemon log:\n{}",
                self.delta_since(&[0, 0])
            )
        });

        let genesis = rpc
            .json_rpc_call::<GetBlockResponse>(
                "get_block",
                Some(
                    serde_json::to_value(GetBlockRequest {
                        hash: String::new(),
                        height: 0,
                        fill_pow_hash: false,
                    })
                    .expect("get_block params"),
                ),
            )
            .await
            .expect("genesis block")
            .miner_tx_hash
            .to_string();
        assert_ne!(
            genesis, held,
            "the genesis miner transaction is the unheld id; the wallet holds it"
        );
        drop(wallet);
        Found { held, genesis }
    }
}

impl Drop for Regtest {
    fn drop(&mut self) {
        drop(self.child.kill());
        drop(self.child.wait());
        drop(std::fs::remove_dir_all(&self.data_dir));
        drop(std::fs::remove_dir_all(&self.config_dir));
    }
}

fn regtest_expectation() -> shekyl_engine_core::DaemonExpectation {
    shekyl_engine_core::DaemonExpectation {
        network: shekyl_address::Network::Mainnet,
        fakechain: shekyl_engine_core::FakechainPolicy::Accept,
    }
}

const SEED: [u8; shekyl_crypto_pq::account::MASTER_SEED_BYTES] = [0x44; 64];

fn mine_address(seed: &[u8; shekyl_crypto_pq::account::MASTER_SEED_BYTES]) -> String {
    use shekyl_crypto_pq::account::{rederive_account, DerivationNetwork, SeedFormat};
    rederive_account(seed, DerivationNetwork::Mainnet, SeedFormat::Bip39)
        .expect("the wallet's keys")
        .to_address(shekyl_address::Network::Mainnet)
        .encode()
        .expect("the address")
}

async fn await_ready(rpc: &HttpRpc, logs: &[PathBuf]) {
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut last = String::new();
    while Instant::now() < deadline {
        match rpc
            .json_rpc_call::<shekyl_rpc_types::GetInfoResponse>("get_info", None)
            .await
        {
            Ok(_) => return,
            Err(error) => last = error.to_string(),
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let tail: String = logs
        .iter()
        .map(|path| std::fs::read_to_string(path).unwrap_or_default())
        .collect();
    panic!("daemon RPC never became ready: {last}\n{tail}");
}

async fn await_template(rpc: &HttpRpc) {
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut last = String::new();
    while Instant::now() < deadline {
        match rpc
            .json_rpc_call::<shekyl_rpc_types::mining::GetMinerDataResponse>("get_miner_data", None)
            .await
        {
            Ok(_) => return,
            Err(error) => last = error.to_string(),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the daemon posted no block template: {last}");
}

fn file_len(path: &Path) -> u64 {
    std::fs::metadata(path).map(|meta| meta.len()).unwrap_or(0)
}

/// A directory only this account can enter, holding one empty configuration
/// file. The daemon refuses a file with a directory above it that another
/// account could write, which rules out the data directory under `TMPDIR`.
fn private_config_dir(rpc_port: u16) -> PathBuf {
    let parent = config_base().join(".shekyl-regtest");
    let dir = parent.join(format!("tx-show-{rpc_port}"));
    drop(std::fs::remove_dir_all(&dir));
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&dir).expect("private config dir");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    drop(
        options
            .open(dir.join("shekyld.toml"))
            .expect("empty config file"),
    );
    dir
}

fn config_base() -> PathBuf {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let me = std::fs::metadata("/proc/self")
            .map(|meta| meta.uid())
            .expect("this process's uid");
        let candidates = [
            std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from),
            std::env::var_os("HOME").map(PathBuf::from),
            Some(PathBuf::from("/run")),
        ];
        for base in candidates.into_iter().flatten() {
            let owned = base.ancestors().all(|dir| {
                std::fs::metadata(dir)
                    .map(|meta| (meta.uid() == 0 || meta.uid() == me) && meta.mode() & 0o022 == 0)
                    .unwrap_or(false)
            });
            if base.is_dir() && owned {
                return base;
            }
        }
    }
    panic!(
        "no directory this account owns the whole way up for the daemon's empty configuration file"
    );
}
