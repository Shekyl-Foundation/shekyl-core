// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A refused start leaves its refusal in the log file (Rick, 2026-11-18):
//! every start refusal goes through one path, which writes standard error
//! and the log file when it can be opened. A service's standard error may
//! reach no one, so its log is where an operator looks.
//!
//! Each test re-executes this binary as the daemon child, which runs
//! `shekyl_daemon::run::main_loading` with its platform naming the test's
//! own directories, as `service_rendezvous.rs` does.

#![cfg(unix)]

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use shekyl_daemon_config::{Network, Platform};

const CHILD_DIR: &str = "SHEKYL_TEST_REFUSAL_CHILD_DIR";
const CHILD_ARGS: &str = "SHEKYL_TEST_REFUSAL_CHILD_ARGS";

/// In the daemon child: run the start with the arguments the test named
/// (one per line in `CHILD_ARGS`) and exit with its status.
fn run_child_if_requested() {
    let Some(dir) = std::env::var_os(CHILD_DIR) else {
        return;
    };
    let dir = PathBuf::from(dir);
    let extra = std::env::var(CHILD_ARGS).expect("the child's arguments");
    let log = dir.join("shekyld.log");
    let mut args: Vec<std::ffi::OsString> = [
        "shekyld",
        "--network",
        "regtest",
        "--clearnet",
        "off",
        "--tor",
        "off",
        "--log-file",
        log.to_str().expect("a UTF-8 path"),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    args.extend(extra.lines().map(std::ffi::OsString::from));
    let status = shekyl_daemon::run::main_loading(
        &args,
        &Platform {
            home: Some(dir.clone()),
            service_parent: Some(dir.clone()),
            session_dir: None,
            service_rendezvous: Some(dir.join("run")),
        },
        shekyl_daemon_config::load_default_file_unread,
    );
    std::process::exit(status);
}

/// The test's directory, laid out as an installer lays out a service's.
fn workdir() -> tempfile::TempDir {
    use std::os::unix::fs::DirBuilderExt;
    let dir = tempfile::tempdir().expect("a directory");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(dir.path().join("shekyl"))
        .expect("the data home");
    std::fs::DirBuilder::new()
        .mode(0o755)
        .create(dir.path().join("run"))
        .expect("the rendezvous directory");
    dir
}

/// Run the daemon child to its exit with `args`; its exit code, its
/// standard error and its log file (empty when absent).
fn run(test: &str, dir: &Path, args: &[&str]) -> (i32, String, Option<String>) {
    let stderr = File::create(dir.join("stderr")).expect("the stderr file");
    let mut command = Command::new(std::env::current_exe().expect("this test binary"));
    command
        .args(["--exact", test, "--nocapture"])
        .env(CHILD_DIR, dir)
        .env(CHILD_ARGS, args.join("\n"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr));
    let status = shekyl_spawn::spawn_lock::with(|| command.status()).expect("the daemon child");
    (
        status.code().expect("an exit code"),
        std::fs::read_to_string(dir.join("stderr")).unwrap_or_default(),
        std::fs::read_to_string(dir.join("shekyld.log")).ok(),
    )
}

/// A refused service start: its refusal is in the log file, the same words
/// standard error has. As root the walk refuses the service before the
/// lock (the log file is appended to as the logger would); as any other
/// account the service starts its logging, and the channel's key, which
/// another account can read, fails its RPC after the logger runs. Red edit:
/// write a start's refusal to standard error alone, as `exit::refuse` did.
#[test]
fn a_refused_service_start_leaves_its_refusal_in_the_log() {
    const NAME: &str = "a_refused_service_start_leaves_its_refusal_in_the_log";
    run_child_if_requested();
    let dir = workdir();
    // SAFETY: `geteuid` reads this process's credentials and cannot fail.
    let root = unsafe { libc::geteuid() } == 0;
    let expected = if root {
        "config.service.root"
    } else {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let data = shekyl_daemon_config::paths::data_dir_default(
            &dir.path().join("shekyl"),
            Network::Regtest,
        );
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&data)
            .expect("the data directory");
        let key = data.join(shekyl_rpc_rendezvous::CHANNEL_KEY_FILE);
        std::fs::write(&key, b"readable by everyone").expect("the planted key");
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644))
            .expect("the planted key's mode");
        "the RPC channel cannot start"
    };
    let (code, stderr, log) = run(NAME, dir.path(), &["--service"]);
    assert_ne!(code, 0, "the start was refused\nstderr:\n{stderr}");
    assert!(stderr.contains(expected), "stderr:\n{stderr}");
    let log = log.unwrap_or_else(|| panic!("no log file\nstderr:\n{stderr}"));
    let line = stderr
        .lines()
        .find(|line| line.contains(expected))
        .and_then(|line| line.strip_prefix("shekyld: "))
        .expect("the refusal's line");
    assert!(
        log.contains(line),
        "the log does not hold the refusal {line:?}\nlog:\n{log}"
    );
}

/// `--config-verify` writes nothing, a refused one included: no log file
/// appears. The same refusal without it is in the log. Red edit: name the
/// log file in a verify run too, and the check creates it.
#[test]
fn a_refused_verify_writes_no_log_and_a_refused_start_does() {
    const NAME: &str = "a_refused_verify_writes_no_log_and_a_refused_start_does";
    run_child_if_requested();
    let dir = workdir();
    // A data directory that is a file: the walk refuses it, before the
    // lock, on every account.
    let data = dir.path().join("not-a-directory");
    std::fs::write(&data, b"").expect("the file in the data directory's place");
    let data = data.to_str().expect("a UTF-8 path");

    let (code, stderr, log) = run(NAME, dir.path(), &["--data-dir", data, "--config-verify"]);
    assert_ne!(code, 0, "the check refused\nstderr:\n{stderr}");
    assert!(log.is_none(), "the check wrote a log:\n{log:?}");

    let (code, stderr, log) = run(NAME, dir.path(), &["--data-dir", data]);
    assert_ne!(code, 0, "the start refused\nstderr:\n{stderr}");
    let line = stderr
        .lines()
        .find_map(|line| line.strip_prefix("shekyld: "))
        .unwrap_or_else(|| panic!("no refusal\nstderr:\n{stderr}"));
    let log = log.unwrap_or_else(|| panic!("no log file\nstderr:\n{stderr}"));
    assert!(log.contains(line), "log:\n{log}\nstderr:\n{stderr}");
}
