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

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};

use serde_json::Value;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_shekyl-cli")
}

fn write_password(dir: &Path) -> std::path::PathBuf {
    let path = dir.join("password");
    let mut file = std::fs::File::create(&path).expect("password file");
    writeln!(file, "script-password").expect("write password");
    path
}

fn run(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(bin())
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
        "--daemon-address",
        "127.0.0.1:1",
        "create",
        "scripted",
        "--seed-out",
        seed.to_str().unwrap(),
        "--password-file",
        password.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "stderr:\n{stderr}\nstdout:\n{stdout}");
    let created = &lines(&stdout)[0];
    assert_eq!(created["ok"], true);
    assert_eq!(created["command"], "create");
    assert_eq!(created["result"]["name"], "scripted");
    assert!(created["result"].get("mnemonic").is_none());
    assert!(created["result"].get("raw_seed_hex").is_none());
    assert!(seed.is_file(), "the seed file is the backup");
    assert!(!stdout.contains("seed words") && !stdout.to_lowercase().contains("mnemonic"));

    let script = dir.path().join("session.txt");
    std::fs::write(&script, "# comment\nbalance\nsend 1 not-an-address\n").expect("script");
    let (code, stdout, stderr) = run(&[
        "--json",
        "--script",
        script.to_str().unwrap(),
        "--network",
        "stagenet",
        "--wallet-dir",
        wallets.to_str().unwrap(),
        "--wallet",
        "scripted",
        "--password-file",
        password.to_str().unwrap(),
        "--daemon-address",
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

/// A create that never reaches the server still names `create`, not a
/// shared "scripted" bucket, and keeps the local refusal code.
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
        "--daemon-address",
        "127.0.0.1:1",
        "create",
        "no-password",
        "--seed-out",
        seed.to_str().unwrap(),
    ]);
    assert_eq!(code, 1, "stderr:\n{stderr}\nstdout:\n{stdout}");
    let rows = lines(&stdout);
    assert_eq!(rows.len(), 1, "{stdout}");
    assert_eq!(rows[0]["command"], "create");
    assert_eq!(rows[0]["ok"], false);
    assert_eq!(rows[0]["error"]["code"], 1);
    assert!(!rows[0]["error"]["message"].as_str().unwrap().is_empty());
}

/// `--script` and a subcommand are two invocations. Neither runs.
#[test]
fn script_and_a_subcommand_are_refused_before_either_runs() {
    let (code, stdout, stderr) = run(&[
        "--json",
        "--script",
        "/no/such/script",
        "--network",
        "stagenet",
        "create",
        "ignored",
        "--seed-out",
        "/tmp/shekyl-should-not-create",
    ]);
    assert_eq!(code, 1, "stderr:\n{stderr}\nstdout:\n{stdout}");
    let rows = lines(&stdout);
    assert_eq!(rows.len(), 1, "{stdout}");
    assert_eq!(rows[0]["command"], "session");
    assert_eq!(rows[0]["ok"], false);
    assert!(rows[0]["error"]["message"]
        .as_str()
        .unwrap()
        .contains("--script"));
}

/// `help` is the prompt command. Clap's help subcommand must not take it.
#[test]
fn one_shot_help_is_the_prompt_command() {
    let (code, stdout, stderr) = run(&[
        "--json",
        "--network",
        "stagenet",
        "--daemon-address",
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
        "--daemon-address",
        "127.0.0.1:1",
        "create",
        "once",
        "--seed-out",
        seed.to_str().unwrap(),
        "--password-file",
        password.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{stderr}\n{stdout}");

    let (code, stdout, stderr) = run(&[
        "--json",
        "--network",
        "stagenet",
        "--wallet-dir",
        wallets.to_str().unwrap(),
        "--wallet",
        "once",
        "--password-file",
        password.to_str().unwrap(),
        "--daemon-address",
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
        "--wallet",
        "once",
        "--password-file",
        password.to_str().unwrap(),
        "--daemon-address",
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
        let data_dir = std::env::temp_dir().join(format!("shekyl-cli-daemon-{rpc_port}"));
        drop(std::fs::remove_dir_all(&data_dir));
        std::fs::create_dir_all(&data_dir).expect("data dir");
        let port = rpc_port.to_string();
        let p2p_port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("p2p port");
            listener.local_addr().expect("addr").port().to_string()
        };
        let child = Command::new(bin)
            .args([
                "--testnet",
                "--offline",
                "--non-interactive",
                "--no-igd",
                "--p2p-bind-ip",
                "127.0.0.1",
                "--p2p-bind-port",
                &p2p_port,
                "--rpc-bind-ip",
                "127.0.0.1",
                "--rpc-bind-port",
                &port,
                "--data-dir",
                data_dir.to_str().expect("utf8"),
                "--log-level",
                "1",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
        match child {
            Ok(child) => Self { child, data_dir },
            Err(error) => {
                drop(std::fs::remove_dir_all(&data_dir));
                panic!("spawn shekyld: {error}");
            }
        }
    }
}

impl Drop for SpawnedDaemon {
    fn drop(&mut self) {
        drop(self.child.kill());
        drop(self.child.wait());
        drop(std::fs::remove_dir_all(&self.data_dir));
    }
}

/// The script in `tests/scripts/daemon_session.txt`, against a live
/// daemon this test starts: `--testnet --offline`, so it holds the testnet
/// genesis and nothing else. Not `--regtest`: that daemon reports
/// `fakechain`, and the shipped wallet path refuses it on identity
/// (`FakechainPolicy::Refuse`). Ignored: CI does not build `shekyld` in the
/// Rust lane. Run with `SHEKYLD_BIN` set and `--ignored`.
#[test]
#[ignore = "daemon pattern: needs SHEKYLD_BIN and spawns shekyld --testnet --offline"]
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
    let daemon = SpawnedDaemon::spawn(&bin, rpc_port);
    let address = format!("127.0.0.1:{rpc_port}");
    let mut up = false;
    for _ in 0..50 {
        if std::net::TcpStream::connect(&address).is_ok() {
            up = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    assert!(up, "daemon did not accept RPC on {address}");

    let dir = tempfile::tempdir().expect("tempdir");
    let password = write_password(dir.path());
    let seed = dir.path().join("seed");
    let wallets = dir.path().join("wallets");
    let (code, stdout, stderr) = run(&[
        "--json",
        "--network",
        "testnet",
        "--daemon-address",
        &address,
        "--wallet-dir",
        wallets.to_str().unwrap(),
        "create",
        "wallet",
        "--seed-out",
        seed.to_str().unwrap(),
        "--password-file",
        password.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{stderr}\n{stdout}");

    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/scripts/daemon_session.txt");
    let (code, stdout, stderr) = run(&[
        "--json",
        "--script",
        script.to_str().unwrap(),
        "--network",
        "testnet",
        "--daemon-address",
        &address,
        "--wallet-dir",
        wallets.to_str().unwrap(),
        "--wallet",
        "wallet",
        "--password-file",
        password.to_str().unwrap(),
    ]);
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
    // The script's last line is a refused send, and it is why the process
    // exits 1. The daemon holds only genesis, so the wallet has no synced
    // block to build against, and the build says so before it reads the
    // recipient: the pattern's `<recipient>` placeholder is never decoded
    // here. The code is the assertion. `ok == false` alone would also pass
    // on a refusal that never reached the wallet's state. This test does
    // not reach the balance: that needs a mined block, and a daemon the
    // wallet accepts mines at the network's real difficulty.
    assert_eq!(code, 1, "{stderr}\n{stdout}");
    let send = rows.last().expect("send");
    assert_eq!(send["command"], "send");
    assert_eq!(send["ok"], false, "{send}");
    assert_eq!(
        send["error"]["code"],
        i64::from(shekyl_wallet_rpc::WalletRpcErrorCode::WalletNotSynced.as_i32()),
        "{send}"
    );
}
