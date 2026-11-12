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

use shekyl_rpc_client::{wire, Rpc, RpcMethod};
use shekyl_rpc_transport::HttpRpc;
use shekyl_rpc_types::kinds::{Count, Height, NoParams};
use shekyl_rpc_types::wire::block::{BlockSelect, GenerateCount, HeaderSelect};
use shekyl_rpc_types::wire::shared::{Selector, Slot};
use shekyl_rpc_types::Network;

use super::{report, TxShow};

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
    let client = daemon.client();
    let held_at = daemon.marks();
    let held = report(&TxShow {
        id: &found.held,
        wallet_records: Some(&records),
        body: false,
        daemon: Some(&client),
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
        daemon: Some(&client),
    })
    .unwrap_or_else(|error| panic!("the daemon's view: {error}"));
    let foreign_delta = daemon.delta_until(&foreign_at, &request_line(transactions_method()));
    assert!(
        foreign.contains("Found in blockchain"),
        "an id the wallet does not hold is the daemon's view:\n{foreign}"
    );
    assert!(
        foreign_delta.contains(&request_line(transactions_method())),
        "the daemon's view is a request the log records:\n{foreign_delta}"
    );
    // The handshake is JSON-RPC. Logging the path would say `/json_rpc`
    // and this line would be absent. Red edit: log `request.uri().path()`.
    assert!(
        foreign_delta.contains(&request_line(version_method())),
        "a JSON-RPC request is logged as its method name:\n{foreign_delta}"
    );

    let body_at = daemon.marks();
    let body = report(&TxShow {
        id: &found.held,
        wallet_records: Some(&records),
        body: true,
        daemon: Some(&client),
    })
    .expect("the bytes");
    let body_delta = daemon.delta_until(&body_at, &request_line(transactions_method()));
    assert!(
        body.starts_with(&records),
        "the wallet's record stays the report:\n{body}"
    );
    let printed = body_line(&body).expect("a base64 body line");
    let decoded = decode_body(printed);
    let wire = daemon_body_bytes(&daemon.url, &found.held);
    assert_eq!(
        decoded, wire,
        "--body's base64 is the bytes the daemon returned"
    );
    assert!(
        body_delta.contains(&request_line(transactions_method())),
        "--body is a daemon request:\n{body_delta}"
    );
}

/// A wallet read that fails does not ask the daemon.
///
/// Red edit: `read_wallet` returns an empty record on error. The command
/// then treats the id as unheld and the request log gains a line.
#[test]
#[ignore = "needs SHEKYLD_BIN built from this tree; spawns a regtest daemon"]
fn a_failed_wallet_read_does_not_ask_the_daemon() {
    let daemon = Regtest::spawn();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let rpc = HttpRpc::with_custom_timeout(daemon.url.clone(), Duration::from_secs(30))
            .await
            .expect("rpc client");
        await_ready(&rpc, &daemon.logs).await;
    });
    drop(runtime);

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("port");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);
    let session =
        crate::rpc_client::RpcSession::connect(&format!("http://127.0.0.1:{port}"), None, false)
            .expect("the dead socket still constructs a session");
    session.set_open("wallet");
    let client = crate::daemon::DaemonClient::new(&daemon.url, None, None, Network::Regtest)
        .expect("daemon client");
    let at = daemon.marks();
    let error = super::command(&session, Some(&client), &"ab".repeat(32), false)
        .expect_err("the wallet read fails");
    let delta = daemon.delta_after_mark(&at, Duration::from_secs(1));
    assert!(
        error
            .message
            .contains("Failed to read this wallet's transactions"),
        "{}",
        error.message
    );
    assert!(
        !delta.contains("rpc request:"),
        "a failed wallet read asked the daemon:\n{delta}"
    );
}

/// The §13 words against a difficulty-1 regtest daemon, with blocks mined.
///
/// The client is on regtest, a network like the others (NI-R1, NI-R4),
/// as `--network regtest` makes it. A second client bound to mainnet is refused
/// before it renders: the handshake is `version`, and `chain_height` is not
/// asked.
/// `daemon stop` is last, and the process exits.
#[test]
#[ignore = "needs SHEKYLD_BIN built from this tree; spawns a regtest daemon"]
fn section_13_words_answer_a_regtest_daemon() {
    use crate::resolve::View;
    let mut daemon = Regtest::spawn();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let rpc = HttpRpc::with_custom_timeout(daemon.url.clone(), Duration::from_secs(30))
            .await
            .expect("rpc client");
        await_ready(&rpc, &daemon.logs).await;
        await_template(&rpc).await;
    });
    drop(runtime);

    let client = daemon.client();
    let mined = client
        .call::<wire::DevBlockGenerate>(&GenerateCount { count: Count(3) })
        .expect("mine three blocks");
    // `chain height` prints the block count: the new tip plus one.
    let height = (mined.height.0 + 1).to_string();

    let shown = crate::console::execute(&client, &View::ChainHeight).expect("chain height");
    assert_eq!(
        shown.trim(),
        height,
        "chain height is the mined height: {shown}"
    );

    let headers = crate::console::execute(&client, &View::BlockHeaderList { from: 1, to: 3 })
        .expect("block header list");
    let header_count = headers.matches("height:").count();
    assert_eq!(header_count, 3, "three headers:\n{headers}");
    let rewards: Vec<shekyl_units::AtomicUnits> = headers
        .lines()
        .filter_map(|line| line.split("reward ").nth(1))
        .map(|shown| {
            shekyl_units::AtomicUnits::from_skl_str(shown.trim()).expect("a header reward")
        })
        .collect();
    assert_eq!(rewards.len(), 3, "three header rewards:\n{headers}");
    // The header `reward` is the miner transaction's outputs. The coinbase
    // sum is the coins those blocks generated, miner and staker legs. From
    // height 1 the staker share is on, so the two figures meet at that
    // split rather than as one number. The fee leg is zero: the blocks
    // list no transactions.
    let miner = shekyl_units::AtomicUnits::checked_sum(rewards).expect("the reward sum");
    let sum = crate::console::execute(&client, &View::ChainCoinbaseSum { from: 1, to: 3 })
        .expect("coinbase sum");
    assert!(
        sum.contains("fee: 0.000000000 SKL"),
        "empty blocks pay no fee: {sum}"
    );
    let printed = sum
        .lines()
        .find_map(|line| line.strip_prefix("emission: ")?.strip_suffix(" SKL"))
        .unwrap_or_else(|| panic!("no emission line: {sum}"));
    let emission = shekyl_units::AtomicUnits::from_skl_str(printed).expect("the emission");
    let share = shekyl_economics::emission_share_at(1);
    assert_eq!(shekyl_economics::emission_share_at(2), share);
    assert_eq!(shekyl_economics::emission_share_at(3), share);
    assert_ne!(share, 0, "heights 1..=3 are inside the emission split");
    let scale = u128::from(shekyl_economics::params::SCALE);
    let whole = emission.to_raw();
    let staker_of_sum = u128::from(whole) * u128::from(share) / scale;
    let miner_of_sum = whole - u64::try_from(staker_of_sum).expect("the staker leg fits");
    let drift = miner.to_raw().abs_diff(miner_of_sum);
    assert!(
        drift <= 3,
        "header rewards {} are the miner leg of emission {printed} (drift {drift} atomics)",
        miner.to_skl_string()
    );

    let stats =
        crate::console::execute(&client, &View::ChainStats { last: 3 }).expect("chain stats");
    assert!(stats.contains("Last 3:"), "{stats}");
    let alt = crate::console::execute(&client, &View::ChainAlt).expect("chain alt");
    assert!(alt.contains("0 alternate chains found:"), "{alt}");

    for view in [
        View::PeerList {
            white: true,
            gray: true,
            max: None,
        },
        View::PeerConnections,
    ] {
        let text = crate::console::execute(&client, &view)
            .unwrap_or_else(|error| panic!("{}: {error}", view.label()));
        assert!(text.contains("P2P: offline"), "{}:\n{text}", view.label());
    }
    let net = crate::console::execute(&client, &View::P2pStats).expect("p2p stats");
    assert!(net.contains("Received") && net.contains("Sent"), "{net}");

    let host = "203.0.113.9";
    let added = crate::console::execute(
        &client,
        &View::BanAdd {
            ip: host.to_owned(),
            duration: Some(30),
        },
    )
    .expect("ban add");
    assert!(added.contains(host) && added.contains("30 s"), "{added}");
    let shown_ban = crate::console::execute(
        &client,
        &View::BanShow {
            ip: host.to_owned(),
        },
    )
    .expect("ban show");
    assert!(shown_ban.contains("banned"), "{shown_ban}");
    let listed = crate::console::execute(&client, &View::BanList).expect("ban list");
    assert!(listed.contains(host), "{listed}");
    let lifted = crate::console::execute(
        &client,
        &View::BanRemove {
            ip: host.to_owned(),
        },
    )
    .expect("ban remove");
    assert!(lifted.contains("lifted"), "{lifted}");

    let before = crate::console::execute(
        &client,
        &View::OptionShow {
            name: Some("log-level".to_owned()),
        },
    )
    .expect("option show");
    assert!(before.contains("log-level"), "{before}");
    let set = crate::console::execute(
        &client,
        &View::OptionSet {
            name: "log-level".to_owned(),
            value: "debug".to_owned(),
        },
    )
    .expect("option set");
    assert!(set.contains("debug"), "{set}");
    let after = crate::console::execute(
        &client,
        &View::OptionShow {
            name: Some("log-level".to_owned()),
        },
    )
    .expect("option show again");
    assert!(after.contains("debug"), "{after}");

    let startup = crate::console::execute(
        &client,
        &View::OptionSet {
            name: "data-dir".to_owned(),
            value: "/tmp/shekyl-not-runtime".to_owned(),
        },
    )
    .expect_err("a startup row is refused");
    assert!(
        startup.contains("RefusedByMethod"),
        "startup row is the daemon's class and diagnostic: {startup}"
    );

    let view = daemon.view_client();
    let grant = crate::console::execute(
        &view,
        &View::OptionSet {
            name: "log-level".to_owned(),
            value: "info".to_owned(),
        },
    )
    .expect_err("the view listener refuses option set");
    assert!(grant.contains("OutsideTheGrant"), "{grant}");

    let flushed =
        crate::console::execute(&client, &View::TxpoolFlush { id: None }).expect("txpool flush");
    assert!(flushed.contains("flushed the pool"), "{flushed}");
    let relay = crate::console::execute(
        &client,
        &View::TxRelay {
            hash: "cd".repeat(32),
        },
    )
    .expect_err("an unknown id is refused");
    assert!(!relay.is_empty(), "{relay}");

    let started =
        crate::commands::mine::cmd_mine_start(Some(&client), Some(1)).expect("mine start");
    assert_eq!(started["started"], true, "{started}");
    let mining = crate::commands::mine::cmd_mine_status(Some(&client)).expect("mine status");
    assert_eq!(mining["active"], true, "{mining}");
    crate::commands::mine::cmd_mine_stop(Some(&client)).expect("mine stop");

    let marks = daemon.marks();
    let wrong = crate::daemon::DaemonClient::new(&daemon.url, None, None, Network::Mainnet)
        .expect("a mainnet client of the same daemon");
    let mismatch = crate::console::execute(&wrong, &View::ChainHeight).expect_err("wrong network");
    assert!(mismatch.contains("network mismatch"), "{mismatch}");
    let asked = daemon.delta_since(&marks);
    assert!(
        !asked.contains(&request_line(<wire::ChainHeight as RpcMethod>::NAME)),
        "a wrong network is refused before rendering:\n{asked}"
    );

    crate::console::execute(&client, &View::DaemonStop).expect("daemon stop");
    daemon.wait_exit();
}

fn transactions_method() -> &'static str {
    <wire::TxList as RpcMethod>::NAME
}

fn version_method() -> &'static str {
    <wire::Version as RpcMethod>::NAME
}

fn request_line(name: &str) -> String {
    format!("rpc request: {name}")
}

fn body_line(report: &str) -> Option<&str> {
    report.lines().rev().find(|line| decode_body_ok(line))
}

fn decode_body(line: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(line)
        .expect("base64")
}

fn decode_body_ok(line: &str) -> bool {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(line)
        .is_ok_and(|bytes| !bytes.is_empty())
}

fn daemon_body_bytes(url: &str, id: &str) -> Vec<u8> {
    let rpc =
        shekyl_rpc_transport::SyncDaemon::connect(url.to_owned(), None, Duration::from_secs(30))
            .expect("daemon client");
    let reply = rpc
        .call::<wire::TxList>(&wire::tx::TxListQuery {
            id: vec![shekyl_rpc_types::hash::HashHex::from_hex(id).expect("an id")],
            prune: false,
        })
        .expect("tx_list");
    match reply.into_iter().next() {
        Some(Slot::Item(entry)) => entry.body.0,
        other => panic!("the daemon returned the transaction: {other:?}"),
    }
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
    view_url: String,
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
        let view_port = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("view port")
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
            "--rpc-view-listen",
            &format!("127.0.0.1:{view_port}"),
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
        let child =
            shekyl_tor_control_client::spawn_lock::spawn(&mut cmd).unwrap_or_else(|error| {
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
            view_url: format!("http://127.0.0.1:{view_port}"),
        }
    }

    fn client(&self) -> crate::daemon::DaemonClient {
        crate::daemon::DaemonClient::new(&self.url, None, None, Network::Regtest)
            .expect("daemon client")
    }

    fn view_client(&self) -> crate::daemon::DaemonClient {
        crate::daemon::DaemonClient::new(&self.view_url, None, None, Network::Regtest)
            .expect("view client")
    }

    fn wait_exit(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if self.child.try_wait().ok().flatten().is_some() {
                return;
            }
            if Instant::now() >= deadline {
                panic!("the daemon did not exit after daemon stop");
            }
            std::thread::sleep(Duration::from_millis(100));
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
            network: shekyl_address::Network::Regtest,
            capability: shekyl_engine_core::CapabilityInput::Full { seed: &SEED },
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
            rpc.call::<wire::DevBlockGenerate>(GenerateCount { count: Count(1) })
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
            .call::<wire::BlockHeaderShow>(HeaderSelect(BlockSelect {
                select: Selector::Height(Height(0)),
                pow: false,
                prune: None,
            }))
            .await
            .expect("genesis header")
            .coinbase
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
        network: shekyl_address::Network::Regtest,
    }
}

const SEED: [u8; shekyl_crypto_pq::account::SEED_BYTES] = [0x44; 32];

fn mine_address(seed: &[u8; shekyl_crypto_pq::account::SEED_BYTES]) -> String {
    shekyl_crypto_pq::account::account_from_seed(seed, shekyl_address::Network::Regtest)
        .expect("the wallet's keys")
        .1
        .to_address(shekyl_address::Network::Regtest)
        .encode()
        .expect("the address")
}

/// The announcement sentence has three owners. This spawn checks it
/// through `scripts/armed_lever.py --check-log`, the same check the
/// shell harness uses, so the sentence is not copied here.
fn this_spawn_announced(logs: &[PathBuf]) -> bool {
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts/armed_lever.py");
    logs.iter().any(|path| {
        std::process::Command::new("python3")
            .arg(&script)
            .arg("--check-log")
            .arg(path)
            .status()
            .is_ok_and(|status| status.success())
    })
}

async fn await_ready(rpc: &HttpRpc, logs: &[PathBuf]) {
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut last = String::new();
    while Instant::now() < deadline {
        match rpc.call::<wire::DaemonStatus>(NoParams).await {
            Ok(_) => {
                let text: String = logs
                    .iter()
                    .map(|path| std::fs::read_to_string(path).unwrap_or_default())
                    .collect();
                assert!(
                    this_spawn_announced(logs),
                    "the daemon did not announce the armed lever at start:\n{text}"
                );
                return;
            }
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
        match rpc.call::<wire::BlockTemplate>(NoParams).await {
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
