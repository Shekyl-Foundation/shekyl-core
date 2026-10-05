// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The CLI scripting surface: one JSON line per command, one wallet session,
//! and the same words as a one-shot.
//!
//! These tests do not mine. A refused send is the failure the envelope has
//! to carry. The regtest script beside them is the pattern for a daemon-
//! backed run; it stays ignored until `SHEKYLD_BIN` is set.

use std::io::Write;
use std::path::Path;
use std::process::Command;

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
        .find(|row| row["command"] == "release")
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

/// The script in `tests/scripts/regtest_session.txt`, against a live
/// `--regtest` daemon. Ignored: CI does not build `shekyld` in the Rust
/// lane. Run with `SHEKYLD_BIN` set and `--ignored`.
#[test]
#[ignore = "regtest pattern: needs SHEKYLD_BIN and spawns shekyld --regtest"]
fn regtest_script_drives_balance_refresh_and_a_refused_send() {
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
    let data_dir = std::env::temp_dir().join(format!("shekyl-cli-regtest-{rpc_port}"));
    drop(std::fs::remove_dir_all(&data_dir));
    std::fs::create_dir_all(&data_dir).expect("data dir");
    let mut daemon = Command::new(&bin)
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
            data_dir.to_str().expect("utf8"),
            "--log-level",
            "1",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn shekyld");

    let address = format!("127.0.0.1:{rpc_port}");
    let mut up = false;
    for _ in 0..50 {
        if std::net::TcpStream::connect(&address).is_ok() {
            up = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    assert!(up, "regtest daemon did not accept RPC on {address}");

    let dir = tempfile::tempdir().expect("tempdir");
    let password = write_password(dir.path());
    let seed = dir.path().join("seed");
    let wallets = dir.path().join("wallets");
    let (code, stdout, stderr) = run(&[
        "--json",
        "--network",
        "mainnet",
        "--daemon-address",
        &address,
        "--wallet-dir",
        wallets.to_str().unwrap(),
        "create",
        "regtest",
        "--seed-out",
        seed.to_str().unwrap(),
        "--password-file",
        password.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{stderr}\n{stdout}");

    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/scripts/regtest_session.txt");
    let (code, stdout, stderr) = run(&[
        "--json",
        "--script",
        script.to_str().unwrap(),
        "--network",
        "mainnet",
        "--daemon-address",
        &address,
        "--wallet-dir",
        wallets.to_str().unwrap(),
        "--wallet",
        "regtest",
        "--password-file",
        password.to_str().unwrap(),
    ]);
    let killed = daemon.kill();
    let waited = daemon.wait();
    assert!(
        killed.is_ok() || waited.is_ok(),
        "regtest daemon did not exit"
    );
    drop(std::fs::remove_dir_all(&data_dir));

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
    // An empty wallet cannot pay. The script's last line is that refusal,
    // and it is why the process exits 1.
    assert_eq!(code, 1, "{stderr}\n{stdout}");
    assert_eq!(rows.last().expect("send")["command"], "send");
    assert_eq!(rows.last().expect("send")["ok"], false);
}
