// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The CLI's in-process wallet server listens on a socket in a private
//! directory it makes (`shekyl-rpc-<pid>-<n>`, under `XDG_RUNTIME_DIR`, else
//! the temp directory), and removes that directory when the CLI ends. On
//! FreeBSD every run left it behind, the socket still in it, and nothing said
//! so (2026-11-21).
//!
//! This test kills nothing: the CLI answers `version`, reads the end of its
//! input and ends on its own. Both places the directory can be made are
//! pointed at this test's own directory, so the check sees this run alone.
//!
//! The tests after the first: a CLI whose output is closed mid-session ends
//! through that same shutdown (before, `println!` panicked and the abort
//! skipped it), and a server's start removes directories this account owns
//! that no server still holds. A directory whose lock is held stays. A run
//! with no session has no wallet; a closed output there exits 1 and does not
//! claim one was saved (Rick, 2026-11-21).
//!
//! **What turns these red.** `InProcessHandle::shutdown` not removing the
//! directory, or the CLI ending without calling it; a write that panics on
//! a closed output; a start without the sweep; a sweep that decides by pid
//! instead of the lock; a sweep that removes a directory whose lock is held;
//! a run with no session returning before the closed-output exit.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use shekyl_wallet_rpc::{DIR_PREFIX, LOCK_FILE, SOCKET_FILE};

mod common;

#[test]
fn a_cli_that_ends_at_its_input_leaves_no_socket_directory() {
    let scratch = tempfile::tempdir().expect("tempdir");
    let runtime = scratch.path().join("runtime");
    std::fs::create_dir(&runtime).expect("runtime dir");
    let wallets = scratch.path().join("wallets");
    let stderr_path = scratch.path().join("stderr");
    let listing = || -> Vec<String> {
        std::fs::read_dir(&runtime)
            .expect("list the runtime dir")
            .map(|e| {
                e.expect("an entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .filter(|n| n.starts_with(DIR_PREFIX))
            .collect()
    };

    let config = common::empty_config();
    let mut child = Command::new(env!("CARGO_BIN_EXE_shekyl-cli"))
        .arg("--config-file")
        .arg(config.path())
        .args(["--network", "stagenet", "--daemon-endpoint", "127.0.0.1:1"])
        .arg("--wallet-dir")
        .arg(&wallets)
        .env("XDG_RUNTIME_DIR", &runtime)
        .env("TMPDIR", &runtime)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(std::fs::File::create(&stderr_path).expect("stderr file"))
        .spawn()
        .expect("spawn shekyl-cli");
    let stderr_of = || std::fs::read_to_string(&stderr_path).unwrap_or_default();
    let mut stdin = child.stdin.take().expect("piped stdin");
    writeln!(stdin, "version").expect("write a command");
    let mut stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
    let mut answer = String::new();
    stdout.read_line(&mut answer).expect("read the answer");
    assert!(
        answer.starts_with("shekyl-cli "),
        "shekyl-cli did not answer `version`; stderr:\n{}",
        stderr_of()
    );
    // The server is up and its directory is there: the check below has a
    // subject (rule 47).
    assert_eq!(
        listing().len(),
        1,
        "the running CLI's socket directory is not under the test's runtime dir: {:?}",
        listing()
    );

    drop(stdin);
    std::io::copy(&mut stdout, &mut std::io::sink()).expect("drain the CLI's output");
    let status = child.wait().expect("reap shekyl-cli");
    assert!(
        status.success(),
        "shekyl-cli did not end cleanly at the end of its input: {status}; stderr:\n{}",
        stderr_of()
    );
    assert!(
        listing().is_empty(),
        "the CLI left its socket directory behind: {:?}; stderr:\n{}",
        listing(),
        stderr_of()
    );
}

/// The CLI's arguments for a session in `scratch`, its server's directory
/// under `runtime`. The configuration file outlives the command: `config`
/// is the caller's to hold.
fn cli(scratch: &Path, runtime: &Path, config: &common::EmptyConfig) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_shekyl-cli"));
    command
        .arg("--config-file")
        .arg(config.path())
        .args(["--network", "stagenet", "--daemon-endpoint", "127.0.0.1:1"])
        .arg("--wallet-dir")
        .arg(scratch.join("wallets"))
        .env("XDG_RUNTIME_DIR", runtime)
        .env("TMPDIR", runtime);
    command
}

/// The `shekyl-rpc-*` names in `runtime`.
fn socket_dirs(runtime: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(runtime)
        .expect("list the runtime dir")
        .map(|e| {
            e.expect("an entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|n| n.starts_with(DIR_PREFIX))
        .collect();
    names.sort();
    names
}

/// A password file this account alone reads, as the CLI requires.
fn password_file(scratch: &Path) -> std::path::PathBuf {
    let path = scratch.join("pw");
    common::write_secret_file(&path, "s3cret\n");
    path
}

/// The reader of the CLI's output goes away mid-session (a crashed parent,
/// `| head`) while a wallet is open. The CLI ends through its shutdown: the
/// wallet is closed (its close saves the state file, a new file in place of
/// the old), the socket directory is gone, one line says why on standard
/// error, and the exit status is 1. Nothing is killed: the CLI is handed one
/// more command and the end of its input.
#[test]
fn a_cli_whose_output_is_closed_closes_its_wallet_and_leaves_no_socket_directory() {
    use std::os::unix::fs::MetadataExt as _;

    let scratch = tempfile::tempdir().expect("tempdir");
    let config = common::empty_config();
    let runtime = scratch.path().join("runtime");
    std::fs::create_dir(&runtime).expect("runtime dir");
    let password = password_file(scratch.path());

    let created = cli(scratch.path(), &runtime, &config)
        .arg("--wallet-password-file")
        .arg(&password)
        .args(["wallet", "create", "w", "--mnemonic-file"])
        .arg(scratch.path().join("seed"))
        .stdin(Stdio::null())
        .output()
        .expect("run shekyl-cli create");
    assert!(
        created.status.success(),
        "create failed: {}",
        String::from_utf8_lossy(&created.stderr)
    );
    let wallets = scratch.path().join("wallets");
    let state = ["w.wallet", "w"]
        .iter()
        .map(|n| wallets.join(n))
        .find(|p| p.is_file())
        .expect("the created wallet's state file");

    let stderr_path = scratch.path().join("stderr");
    let mut child = cli(scratch.path(), &runtime, &config)
        .arg("--wallet-file")
        .arg(scratch.path().join("wallets").join("w.wallet"))
        .arg("--wallet-password-file")
        .arg(&password)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(std::fs::File::create(&stderr_path).expect("stderr file"))
        .spawn()
        .expect("spawn shekyl-cli");
    let stderr_of = || std::fs::read_to_string(&stderr_path).unwrap_or_default();
    let mut stdin = child.stdin.take().expect("piped stdin");
    writeln!(stdin, "version").expect("write a command");
    let mut stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
    let mut answer = String::new();
    loop {
        answer.clear();
        let read = stdout.read_line(&mut answer).expect("read the output");
        assert!(
            read > 0,
            "shekyl-cli did not answer `version`; stderr:\n{}",
            stderr_of()
        );
        if answer.starts_with("shekyl-cli ") {
            break;
        }
    }
    // The session is up with the wallet open: its state file, as it is now.
    let before = std::fs::metadata(&state).expect("state metadata").ino();
    assert_eq!(
        socket_dirs(&runtime).len(),
        1,
        "the running CLI's socket directory"
    );

    drop(stdout);
    // The pipe may already refuse this if the CLI has ended; either way the
    // CLI has no reader for its next answer.
    drop(writeln!(stdin, "version"));
    drop(stdin);
    let status = child.wait().expect("reap shekyl-cli");
    let said = stderr_of();
    assert_eq!(
        status.code(),
        Some(1),
        "shekyl-cli did not end with status 1 ({status}); stderr:\n{said}"
    );
    assert!(
        said.contains("the output was closed"),
        "no line says why the session ended; stderr:\n{said}"
    );
    assert!(
        said.contains("the open wallet was closed and saved"),
        "the wallet was open and its state was saved, and the line does not say so; stderr:\n{said}"
    );
    assert!(
        socket_dirs(&runtime).is_empty(),
        "the CLI left its socket directory behind: {:?}; stderr:\n{said}",
        socket_dirs(&runtime)
    );
    let after = std::fs::metadata(&state).expect("state metadata").ino();
    assert_ne!(
        before, after,
        "the wallet's state file was not saved at the close; stderr:\n{said}"
    );
}

/// A directory named for a private socket, with no lock held.
fn plant_socket_dir(runtime: &Path, pid: u32, spawn: u64) -> std::path::PathBuf {
    let dir = runtime.join(format!("{DIR_PREFIX}{pid}-{spawn}"));
    std::fs::create_dir(&dir).expect("plant a socket directory");
    std::fs::write(dir.join(SOCKET_FILE), b"").expect("plant its socket");
    dir
}

/// No held lock means the directory is not a running server's, whatever pid
/// is in the name. One is named for this test, which is running, and has no
/// lock. One is named for a process that has ended and has a lock file nobody
/// holds. The next CLI removes both. Red edit: keep a directory because its
/// pid runs, or keep one because a lock file exists.
#[test]
fn a_directory_without_a_held_lock_is_removed_at_the_next_start() {
    use std::os::unix::fs::OpenOptionsExt as _;

    let scratch = tempfile::tempdir().expect("tempdir");
    let config = common::empty_config();
    let runtime = scratch.path().join("runtime");
    std::fs::create_dir(&runtime).expect("runtime dir");
    // Spawn 1 and 3, not 0: the CLI's own server is `<its pid>-0`, and the
    // kernel may reuse the ended process's pid for that CLI.
    let running_name = plant_socket_dir(&runtime, std::process::id(), 1);
    let mut ended = Command::new("true").spawn().expect("run true");
    let ended_pid = ended.id();
    ended.wait().expect("reap true");
    let released = plant_socket_dir(&runtime, ended_pid, 3);
    drop(
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(released.join(LOCK_FILE))
            .expect("a lock file nobody holds"),
    );

    let out = cli(scratch.path(), &runtime, &config)
        .arg("version")
        .stdin(Stdio::null())
        .output()
        .expect("run shekyl-cli");
    assert!(
        out.status.success(),
        "shekyl-cli version failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !running_name.exists(),
        "a directory named for a running pid, with no lock, was left behind"
    );
    assert!(
        !released.exists(),
        "a directory whose lock is not held was left behind"
    );
}

/// A dead pid is not what makes a directory stale. The test holds the lock,
/// so the CLI is another process and must leave the directory in place.
/// Waiting is bounded: a sweep that blocks on the lock instead of skipping
/// it would not finish. Red edit: remove the directory because its pid runs
/// no process.
#[test]
fn a_directory_whose_lock_is_held_is_left_in_place() {
    use std::os::unix::fs::OpenOptionsExt as _;

    let scratch = tempfile::tempdir().expect("tempdir");
    let config = common::empty_config();
    let runtime = scratch.path().join("runtime");
    std::fs::create_dir(&runtime).expect("runtime dir");
    let mut ended = Command::new("true").spawn().expect("run true");
    let ended_pid = ended.id();
    ended.wait().expect("reap true");
    // Not spawn 0: that is the name the CLI's own server takes if it is given
    // this pid.
    let held = plant_socket_dir(&runtime, ended_pid, 3);
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(held.join(LOCK_FILE))
        .expect("lock file");
    lock.lock().expect("hold the lock");

    let mut child = cli(scratch.path(), &runtime, &config)
        .arg("version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn shekyl-cli");
    let started = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        if started.elapsed() > std::time::Duration::from_secs(30) {
            drop(child.kill());
            drop(child.wait());
            panic!("shekyl-cli did not finish; a held lock must be skipped, not waited on");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    let mut stderr = String::new();
    drop(
        child
            .stderr
            .take()
            .expect("stderr")
            .read_to_string(&mut stderr),
    );
    drop(lock);
    assert!(
        status.success(),
        "shekyl-cli version failed ({status}); stderr:\n{stderr}"
    );
    assert!(
        held.join(SOCKET_FILE).exists(),
        "a directory whose lock is held was removed"
    );
}

/// `--version` writes one line and returns with no session. Its output is a
/// pipe whose read end is already closed, so the write fails. The process
/// exits 1 and does not claim a wallet was saved: there was none. Red edit:
/// return from `main` before the closed-output exit.
#[test]
fn a_closed_output_with_no_session_does_not_claim_a_saved_wallet() {
    let (reader, writer) = std::io::pipe().expect("pipe");
    drop(reader);
    let mut child = Command::new(env!("CARGO_BIN_EXE_shekyl-cli"))
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(writer)
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn shekyl-cli");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("stderr")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    let status = child.wait().expect("reap shekyl-cli");
    assert_eq!(
        status.code(),
        Some(1),
        "a closed output exited {status}; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("the output was closed"),
        "no line says why it ended; stderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("wallet"),
        "a command with no wallet claimed one; stderr:\n{stderr}"
    );
}
