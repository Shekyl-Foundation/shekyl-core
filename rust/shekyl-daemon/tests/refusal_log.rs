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
/// lock, at its rendezvous directory (the log file is appended to as the
/// logger would); as any other
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
        // The walk checks the service's rendezvous directory first, and
        // refuses a root daemon there.
        "config.service.rendezvous"
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

/// A start a store refuses on its file writes none of the daemon's state:
/// the data directory holds the refused file, unchanged, and the lock the
/// start took, with no marker, chain store or RPC file beside them. The
/// refusal is in the log. Red edit: drop `Node::preflight` from the start,
/// and the marker and the channel's files appear.
#[test]
fn a_start_a_store_refuses_leaves_only_its_lock_and_its_log() {
    const NAME: &str = "a_start_a_store_refuses_leaves_only_its_lock_and_its_log";
    const POOL_FILE: &str = "pool.db";
    const FOREIGN: &[u8] = b"these bytes were never a redb database, and are not an empty file";
    run_child_if_requested();
    use std::os::unix::fs::DirBuilderExt;
    let dir = workdir();
    let data = dir.path().join("data");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&data)
        .expect("the data directory");
    std::fs::write(data.join(POOL_FILE), FOREIGN).expect("the foreign pool file");
    let socket_dir = dir.path().join("socket");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&socket_dir)
        .expect("the socket directory");

    let (code, stderr, log) = run(
        NAME,
        dir.path(),
        &[
            "--data-dir",
            data.to_str().expect("a UTF-8 path"),
            "--rpc-socket-dir",
            socket_dir.to_str().expect("a UTF-8 path"),
        ],
    );
    assert_ne!(code, 0, "the start was refused\nstderr:\n{stderr}");
    let expected = "the node did not start";
    assert!(stderr.contains(expected), "stderr:\n{stderr}");
    let log = log.unwrap_or_else(|| panic!("no log file\nstderr:\n{stderr}"));
    assert!(log.contains(expected), "log:\n{log}");

    let mut entries: Vec<String> = std::fs::read_dir(&data)
        .expect("the data directory")
        .map(|entry| {
            entry
                .expect("an entry")
                .file_name()
                .into_string()
                .expect("UTF-8")
        })
        .collect();
    entries.sort();
    let mut allowed = vec![
        shekyl_daemon_config::lock::LOCK_FILE.to_owned(),
        POOL_FILE.to_owned(),
    ];
    allowed.sort();
    assert_eq!(entries, allowed, "stderr:\n{stderr}");
    assert_eq!(
        std::fs::read(data.join(POOL_FILE)).expect("the pool file"),
        FOREIGN,
        "the refused file was written"
    );
    assert_eq!(
        std::fs::read_dir(&socket_dir)
            .expect("the socket directory")
            .count(),
        0,
        "a refused start bound its socket"
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

/// A refused start whose log file is a FIFO with no reader exits at once,
/// its refusal on standard error, and writes nothing into the FIFO: the
/// refusal path opens the log non-blocking and takes only a regular file.
/// Red edit: open the log with a plain blocking append, and the child
/// hangs on the FIFO until this test's deadline kills it (Copilot, #1439).
#[test]
fn a_refused_start_with_a_fifo_for_its_log_exits_at_once() {
    const NAME: &str = "a_refused_start_with_a_fifo_for_its_log_exits_at_once";
    /// Far beyond a refusal's few milliseconds, far below a hang's forever.
    const EXITS_WITHIN: std::time::Duration = std::time::Duration::from_secs(30);
    run_child_if_requested();
    let dir = workdir();
    let fifo = dir.path().join("shekyld.log");
    let fifo_c = std::ffi::CString::new(fifo.to_str().expect("a UTF-8 path")).expect("no NUL");
    // SAFETY: `fifo_c` is a NUL-terminated path; mkfifo reads it only.
    assert_eq!(
        unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) },
        0,
        "the FIFO"
    );
    // A data directory that is a file: the walk refuses it before the lock.
    let data = dir.path().join("not-a-directory");
    std::fs::write(&data, b"").expect("the file in the data directory's place");

    let stderr_path = dir.path().join("stderr");
    let stderr = File::create(&stderr_path).expect("the stderr file");
    let mut command = Command::new(std::env::current_exe().expect("this test binary"));
    command
        .args(["--exact", NAME, "--nocapture"])
        .env(CHILD_DIR, dir.path())
        .env(
            CHILD_ARGS,
            ["--data-dir", data.to_str().expect("a UTF-8 path")].join("\n"),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr));
    let mut child = shekyl_spawn::spawn_lock::with(|| command.spawn()).expect("the daemon child");
    let deadline = std::time::Instant::now() + EXITS_WITHIN;
    let status = loop {
        if let Some(status) = child.try_wait().expect("the child's state") {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            drop(child.kill());
            drop(child.wait());
            panic!("the refused start hung on its FIFO log file");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
    assert_ne!(
        status.code(),
        Some(0),
        "the start refused\nstderr:\n{stderr}"
    );
    assert!(stderr.contains("shekyld: "), "stderr:\n{stderr}");
    use std::os::unix::fs::FileTypeExt;
    assert!(
        std::fs::symlink_metadata(&fifo)
            .expect("the FIFO")
            .file_type()
            .is_fifo(),
        "the FIFO is left as it was"
    );
}
