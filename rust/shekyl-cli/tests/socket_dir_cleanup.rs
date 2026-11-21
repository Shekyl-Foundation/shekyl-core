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
//! skipped it), and a server's start removes the directories a killed
//! process left, never a running process's (Rick, 2026-11-21).
//!
//! **What turns these red.** `InProcessHandle::shutdown` not removing the
//! directory, or the CLI ending without calling it; a write that panics on
//! a closed output; a start without the sweep, or a sweep that does not ask
//! whether the pid runs.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};

/// The directory's name begins with this (`private_socket_dir`).
const PRIVATE_DIR_PREFIX: &str = "shekyl-rpc-";

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
            .filter(|n| n.starts_with(PRIVATE_DIR_PREFIX))
            .collect()
    };

    let mut child = Command::new(env!("CARGO_BIN_EXE_shekyl-cli"))
        .args(["--network", "stagenet", "--daemon-address", "127.0.0.1:1"])
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
/// under `runtime`.
fn cli(scratch: &Path, runtime: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_shekyl-cli"));
    command
        .args(["--network", "stagenet", "--daemon-address", "127.0.0.1:1"])
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
        .filter(|n| n.starts_with(PRIVATE_DIR_PREFIX))
        .collect();
    names.sort();
    names
}

/// A password file this account alone reads, as the CLI requires.
fn password_file(scratch: &Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let path = scratch.join("pw");
    std::fs::write(&path, "s3cret\n").expect("write the password file");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .expect("owner-only password file");
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
    let runtime = scratch.path().join("runtime");
    std::fs::create_dir(&runtime).expect("runtime dir");
    let password = password_file(scratch.path());

    let created = cli(scratch.path(), &runtime)
        .args(["create", "w", "--seed-out"])
        .arg(scratch.path().join("seed"))
        .arg("--password-file")
        .arg(&password)
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
    let mut child = cli(scratch.path(), &runtime)
        .arg("--wallet")
        .arg("w")
        .arg("--password-file")
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

/// A process this account ran was killed and left its socket directory, the
/// socket in it. The next CLI's server removes it at start. The pid is one
/// that ran and ended a moment ago, so no process runs under it.
#[test]
fn a_stale_socket_directory_of_an_ended_process_is_removed_at_the_next_start() {
    let scratch = tempfile::tempdir().expect("tempdir");
    let runtime = scratch.path().join("runtime");
    std::fs::create_dir(&runtime).expect("runtime dir");
    let mut ended = Command::new("true").spawn().expect("run true");
    let pid = ended.id();
    ended.wait().expect("reap true");
    let stale = runtime.join(format!("{PRIVATE_DIR_PREFIX}{pid}-0"));
    std::fs::create_dir(&stale).expect("plant the stale directory");
    std::fs::write(stale.join("wallet-rpc.sock"), b"").expect("plant its socket");

    let out = cli(scratch.path(), &runtime)
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
        !stale.exists(),
        "the stale directory of ended pid {pid} is still there: {:?}",
        socket_dirs(&runtime)
    );
}

/// A running process's socket directory is never touched: one named for a
/// process that runs while the CLI starts, and one named for this test
/// process, both stay, their sockets in them.
#[test]
fn a_running_process_socket_directory_is_left_alone() {
    let scratch = tempfile::tempdir().expect("tempdir");
    let runtime = scratch.path().join("runtime");
    std::fs::create_dir(&runtime).expect("runtime dir");
    let mut running = Command::new("sleep").arg("60").spawn().expect("run sleep");
    let planted: Vec<_> = [running.id(), std::process::id()]
        .iter()
        .map(|pid| {
            let dir = runtime.join(format!("{PRIVATE_DIR_PREFIX}{pid}-0"));
            std::fs::create_dir(&dir).expect("plant a live directory");
            std::fs::write(dir.join("wallet-rpc.sock"), b"").expect("plant its socket");
            dir
        })
        .collect();

    let out = cli(scratch.path(), &runtime)
        .arg("version")
        .stdin(Stdio::null())
        .output()
        .expect("run shekyl-cli");
    drop(running.kill());
    running.wait().expect("reap sleep");
    assert!(
        out.status.success(),
        "shekyl-cli version failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    for dir in &planted {
        assert!(
            dir.join("wallet-rpc.sock").exists(),
            "a running process's directory was touched: {}",
            dir.display()
        );
    }
}
