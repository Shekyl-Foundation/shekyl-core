// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The CLI scripting surface: one JSON line per command, one wallet session,
//! and the same words as a one-shot.
//!
//! These tests do not mine. A refused send is the failure the envelope has
//! to carry. The daemon script beside them is the pattern for a daemon-
//! backed run; it stays ignored until `SHEKYLD_BIN` is set.

use std::path::{Path, PathBuf};
use std::process::{Child, Command};

use serde_json::Value;

mod common;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_shekyl-cli")
}

fn write_password(dir: &Path) -> std::path::PathBuf {
    let path = dir.join("password");
    common::write_secret_file(&path, "script-password\n");
    path
}

fn run(args: &[&str]) -> (i32, String, String) {
    let config = if args.contains(&"--daemon-endpoint") {
        common::offline_channel_config()
    } else {
        common::empty_config()
    };
    run_config(args, &config)
}

fn run_config(args: &[&str], config: &common::EmptyConfig) -> (i32, String, String) {
    let output = Command::new(bin())
        .arg("--config-file")
        .arg(config.path())
        .args(args)
        .output()
        .expect("spawn shekyl-cli");
    let code = output.status.code().unwrap_or(1);
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    (code, stdout, stderr)
}

fn lines(stdout: &str) -> Vec<Value> {
    stdout
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_str(line).unwrap_or_else(|e| panic!("{e} in {line}")))
        .collect()
}

/// Create, open, balance, and a send that is refused for lack of `--yes`.
/// The seed stays in the seed file. The envelopes do not carry it.
#[test]
fn a_script_session_emits_one_json_line_per_command() {
    let dir = tempfile::tempdir().expect("tempdir");
    let password = write_password(dir.path());
    let seed = dir.path().join("seed");
    let wallets = dir.path().join("wallets");
    let (code, stdout, stderr) = run(&[
        "--json",
        "--network",
        "stagenet",
        "--wallet-dir",
        wallets.to_str().unwrap(),
        "--daemon-endpoint",
        "127.0.0.1:1",
        "--wallet-password-file",
        password.to_str().unwrap(),
        "wallet",
        "create",
        "scripted",
        "--mnemonic-file",
        seed.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "stderr:\n{stderr}\nstdout:\n{stdout}");
    let created = &lines(&stdout)[0];
    assert_eq!(created["ok"], true);
    assert_eq!(created["command"], "wallet create");
    assert_eq!(created["result"]["name"], "scripted");
    assert!(created["result"].get("mnemonic").is_none());
    assert!(created["result"].get("raw_seed_hex").is_none());
    assert!(seed.is_file(), "the seed file is the backup");
    assert!(!stdout.contains("seed words") && !stdout.to_lowercase().contains("mnemonic"));

    let script = dir.path().join("session.txt");
    std::fs::write(&script, "# comment\nbalance\nsend 1 not-an-address\n").expect("script");
    let (code, stdout, stderr) = run(&[
        "--json",
        "--script-file",
        script.to_str().unwrap(),
        "--network",
        "stagenet",
        "--wallet-dir",
        wallets.to_str().unwrap(),
        "--wallet-file",
        wallets.join("scripted.wallet").to_str().unwrap(),
        "--wallet-password-file",
        password.to_str().unwrap(),
        "--daemon-endpoint",
        "127.0.0.1:1",
    ]);
    assert_eq!(
        code, 1,
        "a refused send stops the script\nstderr:\n{stderr}\nstdout:\n{stdout}"
    );
    let rows = lines(&stdout);
    assert!(rows.len() >= 2, "{stdout}");
    assert_eq!(rows[0]["command"], "wallet open");
    assert_eq!(rows[0]["ok"], true);
    let balance = rows
        .iter()
        .find(|row| row["command"] == "balance")
        .expect("balance");
    assert_eq!(balance["ok"], true, "{balance}");
    let refused = rows.last().expect("refusal");
    assert_eq!(refused["ok"], false, "{refused}");
    assert!(!refused["error"]["message"].as_str().unwrap().is_empty());
}

/// A create that never reaches the server still names `wallet create`, not
/// a shared "scripted" bucket, and keeps the local refusal code.
#[test]
fn a_failed_create_names_create() {
    let dir = tempfile::tempdir().expect("tempdir");
    let seed = dir.path().join("seed");
    let wallets = dir.path().join("wallets");
    let (code, stdout, stderr) = run(&[
        "--json",
        "--network",
        "stagenet",
        "--wallet-dir",
        wallets.to_str().unwrap(),
        "--daemon-endpoint",
        "127.0.0.1:1",
        "wallet",
        "create",
        "no-password",
        "--mnemonic-file",
        seed.to_str().unwrap(),
    ]);
    assert_eq!(code, 1, "stderr:\n{stderr}\nstdout:\n{stdout}");
    let rows = lines(&stdout);
    assert_eq!(rows.len(), 1, "{stdout}");
    assert_eq!(rows[0]["command"], "wallet create");
    assert_eq!(rows[0]["ok"], false);
    assert_eq!(rows[0]["error"]["code"], 1);
    assert!(!rows[0]["error"]["message"].as_str().unwrap().is_empty());
}

/// A script file and a command are two sessions. Neither runs, and the
/// refusal is the table's, on standard error.
#[test]
fn a_script_file_and_a_command_are_refused_before_either_runs() {
    let (code, stdout, stderr) = run(&[
        "--json",
        "--script-file",
        "/no/such/script",
        "--network",
        "stagenet",
        "wallet",
        "create",
        "ignored",
        "--mnemonic-file",
        "/tmp/shekyl-should-not-create",
    ]);
    assert_eq!(code, 2, "stderr:\n{stderr}\nstdout:\n{stdout}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.contains("script-file"), "{stderr}");
    assert!(!Path::new("/tmp/shekyl-should-not-create").exists());
}

/// A global option after the command words is told where it goes.
#[test]
fn an_option_after_the_command_is_told_to_go_before_it() {
    let (code, stdout, stderr) = run(&[
        "--json",
        "--network",
        "stagenet",
        "--daemon-endpoint",
        "127.0.0.1:1",
        "wallet",
        "create",
        "w",
        "--debug",
    ]);
    assert_eq!(code, 1, "{stderr}\n{stdout}");
    let rows = lines(&stdout);
    let message = rows[0]["error"]["message"].as_str().expect("a message");
    assert!(message.contains("put it before the command"), "{message}");
}

/// `help` is the prompt command; `--help` is the options.
#[test]
fn one_shot_help_is_the_prompt_command() {
    let (code, stdout, stderr) = run(&[
        "--json",
        "--network",
        "stagenet",
        "--daemon-endpoint",
        "127.0.0.1:1",
        "help",
    ]);
    assert_eq!(code, 0, "stderr:\n{stderr}\nstdout:\n{stdout}");
    let rows = lines(&stdout);
    assert_eq!(rows.len(), 1, "{stdout}");
    assert_eq!(rows[0]["command"], "help");
    assert_eq!(rows[0]["ok"], true);
    assert!(rows[0]["result"]["text"]
        .as_str()
        .unwrap()
        .contains("stake"));
}

/// The same words, one command, then exit.
#[test]
fn a_one_shot_uses_the_prompt_grammar_and_exits() {
    let dir = tempfile::tempdir().expect("tempdir");
    let password = write_password(dir.path());
    let seed = dir.path().join("seed");
    let wallets = dir.path().join("wallets");
    let (code, stdout, stderr) = run(&[
        "--json",
        "--network",
        "stagenet",
        "--wallet-dir",
        wallets.to_str().unwrap(),
        "--daemon-endpoint",
        "127.0.0.1:1",
        "--wallet-password-file",
        password.to_str().unwrap(),
        "wallet",
        "create",
        "once",
        "--mnemonic-file",
        seed.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{stderr}\n{stdout}");

    let (code, stdout, stderr) = run(&[
        "--json",
        "--network",
        "stagenet",
        "--wallet-dir",
        wallets.to_str().unwrap(),
        "--wallet-file",
        wallets.join("once.wallet").to_str().unwrap(),
        "--wallet-password-file",
        password.to_str().unwrap(),
        "--daemon-endpoint",
        "127.0.0.1:1",
        "balance",
    ]);
    assert_eq!(code, 0, "{stderr}\n{stdout}");
    let rows = lines(&stdout);
    assert!(
        rows.iter()
            .any(|row| row["command"] == "balance" && row["ok"] == true),
        "{stdout}"
    );

    let (code, stdout, stderr) = run(&[
        "--json",
        "--network",
        "stagenet",
        "--wallet-dir",
        wallets.to_str().unwrap(),
        "--wallet-file",
        wallets.join("once.wallet").to_str().unwrap(),
        "--wallet-password-file",
        password.to_str().unwrap(),
        "--daemon-endpoint",
        "127.0.0.1:1",
        "stake",
        "release",
    ]);
    assert_eq!(code, 1, "release without --yes refuses\n{stderr}\n{stdout}");
    let rows = lines(&stdout);
    let release = rows
        .iter()
        .find(|row| row["command"] == "stake release")
        .expect("release");
    assert_eq!(release["ok"], false, "{release}");
    assert!(
        release["error"]["message"]
            .as_str()
            .unwrap()
            .contains("--yes"),
        "{release}"
    );
}

/// A daemon this test owns. Drop kills, reaps, and removes the data
/// directory, including when an assertion panics. Dropping a bare `Child`
/// does not.
struct SpawnedDaemon {
    child: Child,
    data_dir: PathBuf,
}

impl SpawnedDaemon {
    fn spawn(bin: &std::ffi::OsStr, rpc_port: u16) -> Self {
        let data_dir = shekyl_os_account::test_fixture::path(&format!("cli-daemon-{rpc_port}"))
            .expect("a fixture path");
        drop(std::fs::remove_dir_all(&data_dir));
        // Made as the daemon makes a data directory: it refuses an existing
        // one other accounts can enter (`config.data-dir.exposed`).
        shekyl_os_account::create_account_dir_all(&data_dir).expect("data dir");
        let port = rpc_port.to_string();
        // Both connectors off is the offline posture: no listener, no
        // dial, so no p2p port to pick (INPUT_GRAMMAR.md §5).
        let mut child = Command::new(bin);
        child
            .args([
                "--network",
                "testnet",
                // The default file is the machine's (`/etc/shekyl`); a host
                // that runs a testnet node keeps its settings there.
                "--config-file",
                "none",
                "--clearnet",
                "off",
                "--tor",
                "off",
                "--rpc-admin-listen",
                "none",
                "--rpc-socket-dir",
                data_dir.to_str().expect("utf8"),
                "--rpc-listen",
                &format!("127.0.0.1:{port}"),
                "--data-dir",
                data_dir.to_str().expect("utf8"),
                "--log-file",
                &data_dir.join("shekyld.log").display().to_string(),
                "--log-level",
                "info",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let child = child.spawn();
        match child {
            Ok(child) => Self { child, data_dir },
            Err(error) => {
                drop(std::fs::remove_dir_all(&data_dir));
                panic!("spawn shekyld: {error}");
            }
        }
    }
}

impl SpawnedDaemon {
    /// Until the channel listener at `address` accepts. A daemon that exits
    /// first fails at once, with its log; one still starting after
    /// [`DAEMON_READY`] fails then. A loaded host takes tens of seconds to
    /// make the channel key and open the store before it listens.
    fn wait_accepting(&mut self, address: &str) {
        let deadline = std::time::Instant::now() + DAEMON_READY;
        let log = || std::fs::read_to_string(self.data_dir.join("shekyld.log")).unwrap_or_default();
        loop {
            if std::net::TcpStream::connect(address).is_ok() {
                return;
            }
            if let Some(status) = self.child.try_wait().expect("the daemon's status") {
                panic!(
                    "the daemon ended before it listened on {address}: {status}\n{}",
                    log()
                );
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the daemon did not listen on {address} within {DAEMON_READY:?}\n{}",
                log()
            );
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }
}

/// How long a spawned daemon may take to listen: the bound the tunnel's
/// end_to_end gives its daemon (`READY`).
const DAEMON_READY: std::time::Duration = std::time::Duration::from_secs(120);

impl Drop for SpawnedDaemon {
    fn drop(&mut self) {
        drop(self.child.kill());
        drop(self.child.wait());
        drop(std::fs::remove_dir_all(&self.data_dir));
    }
}

/// The script in `tests/scripts/daemon_session.txt`, against a live
/// daemon this test starts: testnet with both connectors off, so it holds
/// the testnet genesis and nothing else. Ignored: CI does not build `shekyld` in the
/// Rust lane. Run with `SHEKYLD_BIN` set and `--ignored`.
#[test]
#[ignore = "daemon pattern: needs SHEKYLD_BIN and spawns shekyld --network testnet offline"]
fn daemon_script_drives_balance_refresh_and_a_refused_send() {
    let bin = std::env::var_os("SHEKYLD_BIN").unwrap_or_else(|| {
        panic!(
            "SHEKYLD_BIN not set. Build the daemon and pass \
             SHEKYLD_BIN=<build>/bin/shekyld"
        )
    });
    let rpc_port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("port");
        listener.local_addr().expect("addr").port()
    };
    // Owned from the moment the process exists. A panic in the readiness
    // or wallet assertions still kills and reaps it and removes its data
    // directory; dropping a bare `Child` does neither.
    let mut daemon = SpawnedDaemon::spawn(&bin, rpc_port);
    let address = format!("127.0.0.1:{rpc_port}");
    daemon.wait_accepting(&address);

    let config = common::empty_config();
    let root = config.path().parent().unwrap();
    let owner = shekyl_rpc_transport::local::LocalTarget::test_override(
        shekyl_wallet_rpc::Network::Testnet,
        &shekyl_rpc_rendezvous::Instance::Default,
        Some(&daemon.data_dir),
        None,
    );
    let public = owner
        .call::<shekyl_rpc_client::wire::RpcBundleShow>(
            &shekyl_rpc_types::kinds::NoParams,
            shekyl_rpc_transport::local::CALL_WITHIN,
        )
        .unwrap();
    let bundle = root.join("daemon.bundle");
    std::fs::write(
        &bundle,
        shekyl_rpc_transport::channel::bundle_text(&public.bundle.0),
    )
    .unwrap();
    let key_file = root.join("client.key");
    let key = shekyl_rpc_transport::channel::create_client_key(&key_file).unwrap();
    owner
        .call::<shekyl_rpc_client::wire::RpcClientAdd>(
            &shekyl_rpc_types::wire::rpc::ClientCeiling {
                fingerprint: shekyl_rpc_types::hash::HashHex::from_bytes(
                    *key.public().fingerprint().as_bytes(),
                ),
                ceiling: vec![shekyl_rpc_types::wire::rpc::CeilingWord::Wallet],
            },
            shekyl_rpc_transport::local::CALL_WITHIN,
        )
        .unwrap();
    std::fs::write(
        config.path(),
        format!(
            "daemon-bundle-file = {}\nrpc-key-file = {}\n",
            serde_json::json!(bundle),
            serde_json::json!(key_file)
        ),
    )
    .unwrap();
    let dir = tempfile::tempdir().expect("tempdir");
    let password = write_password(dir.path());
    let seed = dir.path().join("seed");
    let wallets = dir.path().join("wallets");
    let (code, stdout, stderr) = run_config(
        &[
            "--json",
            "--network",
            "testnet",
            "--daemon-endpoint",
            &address,
            "--wallet-dir",
            wallets.to_str().unwrap(),
            "--wallet-password-file",
            password.to_str().unwrap(),
            "wallet",
            "create",
            "wallet",
            "--mnemonic-file",
            seed.to_str().unwrap(),
        ],
        &config,
    );
    assert_eq!(code, 0, "{stderr}\n{stdout}");

    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/scripts/daemon_session.txt");
    let (code, stdout, stderr) = run_config(
        &[
            "--json",
            "--script-file",
            script.to_str().unwrap(),
            "--network",
            "testnet",
            "--daemon-endpoint",
            &address,
            "--wallet-dir",
            wallets.to_str().unwrap(),
            "--wallet-file",
            wallets.join("wallet.wallet").to_str().unwrap(),
            "--wallet-password-file",
            password.to_str().unwrap(),
        ],
        &config,
    );
    drop(daemon);

    let rows = lines(&stdout);
    assert!(
        rows.iter()
            .any(|row| row["command"] == "balance" && row["ok"] == true),
        "balance against the daemon\n{stderr}\n{stdout}"
    );
    assert!(
        rows.iter()
            .any(|row| row["command"] == "wallet refresh" && row["ok"] == true),
        "refresh against the daemon\n{stderr}\n{stdout}"
    );
    assert!(
        rows.iter()
            .any(|row| row["command"] == "chain" && row["ok"] == true),
        "chain against the daemon\n{stderr}\n{stdout}"
    );
    // The script intentionally leaves its recipient placeholder unexpanded.
    // A transport or enrollment fault must not pass as the wallet's refusal.
    assert_eq!(code, 1, "{stderr}\n{stdout}");
    let send = rows.last().expect("send");
    assert_eq!(send["command"], "send");
    assert_eq!(send["ok"], false, "{send}");
    assert_eq!(
        send["error"]["code"],
        i64::from(shekyl_wallet_rpc::WalletRpcErrorCode::InvalidRecipient.as_i32()),
        "{send}"
    );
}
