// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The wallet RPC server's stops on Unix (`shekyl_process::stop`; Rick,
//! 2026-11-20), judged from outside the process that takes them:
//!
//! - its stops are armed before its listener is bound, so a `SIGTERM` in
//!   the bind window is a clean stop that leaves no socket file;
//! - started with `SIGINT` ignored, it keeps the ignore, says so once, and
//!   stops cleanly on `SIGTERM`;
//! - a socket a running server answers on is not taken over, one a killed
//!   server left is replaced, and a file that is not a socket is not
//!   removed: a killed server's next start is clean.
//!
//! The first runs the library's two start steps in a re-executed child of
//! this test binary; the others run the binary. The test binary itself
//! never arms the stops, so no signal can end it.
//! `SHEKYL_WALLET_RPC_STOP_CHILD` is this harness's re-exec marker, read
//! by the test binary alone; no shipped binary reads it (IG-13).

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use shekyl_wallet_rpc::{AuthConfig, ListenAddr, Network, ServerConfig};

const CHILD_MARKER: &str = "SHEKYL_WALLET_RPC_STOP_CHILD";
/// The child's working directory: its socket and wallet directory.
const CHILD_DIR: &str = "SHEKYL_WALLET_RPC_STOP_CHILD_DIR";

/// The child signals itself after the arm and before the bind.
const IN_THE_WINDOW: &str = "in-the-window";
/// The control: the child signals itself before the arm.
const BEFORE_THE_ARM: &str = "before-the-arm";

/// How long a start, a stop or a line may take.
const WITHIN: Duration = Duration::from_secs(30);
/// How long an ignored signal must leave the server running.
const IGNORED_HOLDS: Duration = Duration::from_secs(1);

/// The line a start with `SIGINT` ignored says, on standard error.
const IGNORED_LINE: &str = "shekyl-wallet-rpc: Ctrl-C is off because the program that started \
     shekyl-wallet-rpc asked for it. Stop it with SIGTERM or the service stop.";

/// A temporary directory only this account can enter. The wallet RPC binds
/// its socket only in such a directory, and tempfile makes its directories
/// with the umask's default mode (0755 under umask 022).
fn owner_only_tempdir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .expect("an owner-only temporary directory")
}

/// A short socket name: a socket path must fit `sun_path` (104 bytes on
/// macOS and FreeBSD).
fn socket_in(dir: &Path) -> PathBuf {
    dir.join("s")
}

fn send(signal: &str, pid: u32) {
    let sent = Command::new("kill")
        .args([&format!("-{signal}"), &pid.to_string()])
        .status()
        .expect("run kill");
    assert!(sent.success(), "kill -{signal} {pid}");
}

/// In the re-executed child: the library's two start steps with a
/// `SIGTERM` to itself between them (or, for the control, before both).
fn run_child_if_asked() -> bool {
    let Ok(mode) = std::env::var(CHILD_MARKER) else {
        return false;
    };
    // The test harness has printed `test <name> ... ` with no newline: end
    // that line, so `served` is a line of its own.
    println!();
    let dir = PathBuf::from(std::env::var_os(CHILD_DIR).expect("the child's directory"));
    let wallets = dir.join("wallets");
    std::fs::create_dir_all(&wallets).expect("the wallet directory");
    let config = ServerConfig {
        listen: ListenAddr::Uds(socket_in(&dir)),
        wallet_dir: wallets,
        network: Network::Stagenet,
        daemon: shekyl_wallet_rpc::tenant::DaemonTarget::Address {
            url: "http://127.0.0.1:1".into(),
            proxy: None,
        },
        auth: AuthConfig::Disabled,
        kdf: shekyl_crypto_pq::wallet_envelope::KdfParams::default(),
        tor_file: shekyl_wallet_rpc::server::TorFile::discover(),
    };
    if mode == BEFORE_THE_ARM {
        send("TERM", std::process::id());
        std::thread::sleep(WITHIN);
        return true;
    }
    let armed = shekyl_wallet_rpc::arm_server(config).expect("the start arms");
    send("TERM", std::process::id());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    runtime
        .block_on(armed.serve())
        .expect("the server stops cleanly");
    println!("served");
    true
}

/// What a child said and how it ended.
struct ChildRun {
    status: std::process::ExitStatus,
    stdout: String,
    stderr: String,
}

/// Runs this binary on `test` in `mode`, its output to files, and waits at
/// most [`WITHIN`]: a child that does not end is killed and reaped, and the
/// test fails saying so, rather than waiting on it for ever.
fn child_run(test: &str, mode: &str, dir: &Path) -> ChildRun {
    let out = dir.join(format!("{mode}.stdout"));
    let err = dir.join(format!("{mode}.stderr"));
    let mut child = Command::new(std::env::current_exe().expect("this test binary"))
        .args(["--exact", test, "--nocapture", "--test-threads", "1"])
        .env(CHILD_MARKER, mode)
        .env(CHILD_DIR, dir)
        .stdin(Stdio::null())
        .stdout(std::fs::File::create(&out).expect("the stdout file"))
        .stderr(std::fs::File::create(&err).expect("the stderr file"))
        .spawn()
        .expect("the child runs");
    let read = |path: &Path| std::fs::read_to_string(path).unwrap_or_default();
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll the child") {
            break status;
        }
        if start.elapsed() >= WITHIN {
            drop(child.kill());
            drop(child.wait());
            panic!(
                "the {mode} child did not end within {WITHIN:?}\nstdout:\n{}\nstderr:\n{}",
                read(&out),
                read(&err)
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    ChildRun {
        status,
        stdout: read(&out),
        stderr: read(&err),
    }
}

/// **A `SIGTERM` in the bind window stops the server cleanly and leaves
/// no socket file** (Rick, 2026-11-20). The child arms, signals itself,
/// and only then binds and serves: the stop it already holds ends the
/// serve at once, and the socket it bound is removed. The control signals
/// before the arm and dies by the signal, so the window is real. Red edit:
/// arm in `serve` after the bind (the child dies by signal 15, or leaves
/// the socket).
#[test]
fn a_sigterm_in_the_bind_window_stops_cleanly_and_leaves_no_socket() {
    const TEST: &str = "a_sigterm_in_the_bind_window_stops_cleanly_and_leaves_no_socket";
    if run_child_if_asked() {
        return;
    }
    use std::os::unix::process::ExitStatusExt;
    let control = owner_only_tempdir();
    let before = child_run(TEST, BEFORE_THE_ARM, control.path());
    assert_eq!(
        before.status.signal(),
        Some(libc::SIGTERM),
        "the control: a SIGTERM before the arm is the signal's death: {:?}",
        before.status
    );

    let dir = owner_only_tempdir();
    let out = child_run(TEST, IN_THE_WINDOW, dir.path());
    let said = &out.stdout;
    assert!(
        out.status.success() && said.lines().any(|line| line == "served"),
        "the stop in the bind window was not a clean stop: {:?}\nstdout:\n{said}\nstderr:\n{}",
        out.status,
        out.stderr
    );
    assert!(
        !socket_in(dir.path()).exists(),
        "the clean stop left the socket file behind"
    );
}

/// A `shekyl-wallet-rpc` on `socket`, its standard error to a file.
struct Server {
    child: Child,
    stderr: PathBuf,
}

impl Server {
    /// Starts the binary on `socket`, with `SIGINT` set to `SIG_IGN` when
    /// `ignore_sigint` (as a non-interactive background list sets it) and to
    /// `SIG_DFL` otherwise, and `SIGHUP` and `SIGTERM` to `SIG_DFL`: set
    /// between fork and exec, so the test does not depend on what the
    /// process that started it ignored. A shell cannot reset a signal that
    /// was ignored when it started.
    fn start(dir: &Path, socket: &Path, name: &str, ignore_sigint: bool) -> Self {
        Self::start_with(dir, socket, name, ignore_sigint, None)
    }

    /// [`Self::start`], and with `umask` the child runs under that umask;
    /// it also makes `control` with mode 0777 first, under the same umask,
    /// so the test can show the umask was live in the child.
    fn start_with(
        dir: &Path,
        socket: &Path,
        name: &str,
        ignore_sigint: bool,
        umask: Option<(libc::mode_t, std::ffi::CString)>,
    ) -> Self {
        use std::os::unix::process::CommandExt;
        let wallets = dir.join(format!("wallets-{name}"));
        std::fs::create_dir_all(&wallets).expect("the wallet directory");
        let stderr = dir.join(format!("stderr-{name}"));
        let mut command = Command::new(env!("CARGO_BIN_EXE_shekyl-wallet-rpc"));
        command
            .args(["--network", "stagenet", "--disable-rpc-login"])
            .arg(format!("--rpc-bind=uds://{}", socket.display()))
            .arg("--wallet-dir")
            .arg(&wallets)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(&stderr).expect("the stderr file"));
        // SAFETY: the closure runs between fork and exec and calls only
        // `signal`, `umask` and `mkdir`, which are async-signal-safe, plus
        // the errno read on failure, on a path made before the fork. It
        // sets this child's stop dispositions and umask and makes the
        // control directory, and no other state.
        unsafe {
            command.pre_exec(move || {
                if let Some((mask, control)) = &umask {
                    libc::umask(*mask);
                    if libc::mkdir(control.as_ptr(), 0o777) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                let interrupt = if ignore_sigint {
                    libc::SIG_IGN
                } else {
                    libc::SIG_DFL
                };
                for (signal, disposition) in [
                    (libc::SIGINT, interrupt),
                    (libc::SIGTERM, libc::SIG_DFL),
                    (libc::SIGHUP, libc::SIG_DFL),
                ] {
                    if libc::signal(signal, disposition) == libc::SIG_ERR {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        let child = command.spawn().expect("spawn shekyl-wallet-rpc");
        Self { child, stderr }
    }

    fn said(&self) -> String {
        std::fs::read_to_string(&self.stderr).unwrap_or_default()
    }

    /// Waits until `socket` answers, or panics with what was said.
    fn wait_answering(&mut self, socket: &Path) {
        let start = Instant::now();
        while std::os::unix::net::UnixStream::connect(socket).is_err() {
            if let Some(status) = self.child.try_wait().expect("poll the server") {
                panic!(
                    "the server ended before it answered ({status}):\n{}",
                    self.said()
                );
            }
            assert!(
                start.elapsed() < WITHIN,
                "the server did not answer:\n{}",
                self.said()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// The exit status, once the server ends within [`WITHIN`].
    fn ended(&mut self) -> std::process::ExitStatus {
        let start = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().expect("poll the server") {
                return status;
            }
            assert!(
                start.elapsed() < WITHIN,
                "the server did not end:\n{}",
                self.said()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn still_running(&mut self) -> bool {
        self.child.try_wait().expect("poll the server").is_none()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        drop(self.child.kill());
        drop(self.child.wait());
    }
}

/// **Started with `SIGINT` ignored, the server ignores Ctrl-C, says so,
/// and stops cleanly on `SIGTERM`** (IG-14; Rick, 2026-11-20). The control
/// is the same start without the ignore: `SIGINT` stops it cleanly, and no
/// line is said. Red edits: open the `SIGINT` stream whatever the
/// disposition (the server stops on it), or drop the line.
#[test]
fn started_with_sigint_ignored_it_ignores_ctrl_c_says_so_and_stops_cleanly_on_sigterm() {
    let dir = owner_only_tempdir();
    let socket = socket_in(dir.path());

    let mut control = Server::start(dir.path(), &socket, "control", false);
    control.wait_answering(&socket);
    send("INT", control.child.id());
    let status = control.ended();
    assert!(
        status.success(),
        "the control's SIGINT: {status}\n{}",
        control.said()
    );
    assert!(
        !control.said().contains("Ctrl-C is off"),
        "{}",
        control.said()
    );
    assert!(!socket.exists(), "the control's clean stop left its socket");

    let mut server = Server::start(dir.path(), &socket, "ignored", true);
    server.wait_answering(&socket);
    assert!(
        server.said().lines().any(|line| line == IGNORED_LINE),
        "the start did not say Ctrl-C is off:\n{}",
        server.said()
    );
    send("INT", server.child.id());
    std::thread::sleep(IGNORED_HOLDS);
    assert!(
        server.still_running(),
        "SIGINT stopped it:\n{}",
        server.said()
    );
    send("TERM", server.child.id());
    let status = server.ended();
    assert!(status.success(), "SIGTERM: {status}\n{}", server.said());
    assert!(!socket.exists(), "the clean stop left its socket");
}

/// **A killed server's next start is clean, and a running one is not taken
/// over** (kill safety; Rick, 2026-11-20). A second server on a running
/// server's socket refuses and leaves it answering; after `kill -9` the
/// socket file is left, and the next start replaces it; a regular file at
/// the path is refused and kept. Red edit: remove whatever is at the path
/// (the second start takes over the live socket, and the file is gone).
#[test]
fn a_killed_servers_socket_is_replaced_and_a_live_one_is_not_taken_over() {
    let dir = owner_only_tempdir();
    let socket = socket_in(dir.path());

    let mut first = Server::start(dir.path(), &socket, "first", false);
    first.wait_answering(&socket);
    let mut rival = Server::start(dir.path(), &socket, "rival", false);
    let status = rival.ended();
    assert!(!status.success(), "the rival started over a live socket");
    assert!(
        rival.said().contains("another server answers on"),
        "the rival's refusal:\n{}",
        rival.said()
    );
    assert!(
        std::os::unix::net::UnixStream::connect(&socket).is_ok(),
        "the running server's socket was taken from it"
    );

    send("KILL", first.child.id());
    first.ended();
    assert!(
        socket.exists(),
        "the control: a kill leaves the socket file"
    );
    let mut next = Server::start(dir.path(), &socket, "next", false);
    next.wait_answering(&socket);
    send("TERM", next.child.id());
    let status = next.ended();
    assert!(
        status.success(),
        "the next start's stop: {status}\n{}",
        next.said()
    );

    let file = dir.path().join("f");
    std::fs::write(&file, b"not a socket").expect("a regular file");
    let mut over_a_file = Server::start(dir.path(), &file, "file", false);
    let status = over_a_file.ended();
    assert!(!status.success(), "a start over a regular file succeeded");
    assert!(
        over_a_file
            .said()
            .contains("is not a socket; it is not replaced"),
        "{}",
        over_a_file.said()
    );
    assert_eq!(
        std::fs::read(&file).expect("the file is kept"),
        b"not a socket"
    );
}

/// **With umask 002, nothing but the owner can reach the socket at any
/// point during startup** (Rick, 2026-11-21). The socket's own mode is set
/// only after its bind, so the directory carries the startup: the server
/// makes a missing directory 0700 whatever the umask, and it is 0700 from
/// the first moment it exists, polled while the server starts. The control:
/// a directory the child made under the same umask with mode 0777 is
/// group-writable (0775), so the umask was live. Red edit: make the
/// directory with `create_dir_all` (it appears 0775).
#[test]
fn with_umask_002_only_the_owner_can_reach_the_socket_during_startup() {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let dir = owner_only_tempdir();
    let control = dir.path().join("control");
    let control_c = std::ffi::CString::new(control.as_os_str().as_bytes()).expect("a path");
    let socket_dir = dir.path().join("made");
    let socket = socket_dir.join("s");
    let mut server = Server::start_with(
        dir.path(),
        &socket,
        "umask",
        false,
        Some((0o002, control_c)),
    );
    let me = std::fs::metadata(dir.path())
        .expect("the test's directory")
        .uid();
    let start = Instant::now();
    let mut seen = Vec::new();
    while std::os::unix::net::UnixStream::connect(&socket).is_err() {
        if let Ok(meta) = std::fs::symlink_metadata(&socket_dir) {
            seen.push((meta.permissions().mode() & 0o777, meta.uid()));
        }
        if let Some(status) = server.child.try_wait().expect("poll the server") {
            panic!(
                "the server ended before it answered ({status}):\n{}",
                server.said()
            );
        }
        assert!(
            start.elapsed() < WITHIN,
            "the server did not answer:\n{}",
            server.said()
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    let control_mode = std::fs::metadata(&control)
        .expect("the control")
        .permissions()
        .mode();
    assert_eq!(
        control_mode & 0o777,
        0o775,
        "the control: umask 002 was live in the child"
    );
    let last = std::fs::metadata(&socket_dir).expect("the socket's directory");
    seen.push((last.permissions().mode() & 0o777, last.uid()));
    assert!(
        seen.iter().all(|&(mode, uid)| mode == 0o700 && uid == me),
        "the socket's directory was ever more than the owner's: {seen:?} (octal modes: 448 is 0700)"
    );
    let socket_mode = std::fs::metadata(&socket)
        .expect("the socket")
        .permissions()
        .mode();
    assert_eq!(
        socket_mode & 0o777,
        0o600,
        "the bound socket is the owner's alone"
    );
    send("TERM", server.child.id());
    assert!(server.ended().success(), "{}", server.said());
}

/// **An existing group-writable directory is refused, naming it**, and no
/// socket is bound there (Rick, 2026-11-21): the same rule as the tunnel's.
/// The control is the same start in an owner-only directory, which serves.
/// Red edit: bind in any directory that exists.
#[test]
fn a_group_writable_socket_directory_is_refused_naming_it() {
    use std::os::unix::fs::PermissionsExt;
    let dir = owner_only_tempdir();

    let private = dir.path().join("private");
    std::fs::create_dir(&private).expect("a directory");
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    let mut control = Server::start(dir.path(), &private.join("s"), "private", false);
    control.wait_answering(&private.join("s"));
    send("TERM", control.child.id());
    assert!(control.ended().success(), "the control: {}", control.said());

    let shared = dir.path().join("shared");
    std::fs::create_dir(&shared).expect("a directory");
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o770)).expect("chmod");
    let socket = shared.join("s");
    let mut server = Server::start(dir.path(), &socket, "shared", false);
    let status = server.ended();
    assert!(!status.success(), "a group-writable directory was used");
    let said = server.said();
    assert!(
        said.contains(&format!(
            "{} must be a directory only this account can enter",
            shared.display()
        )),
        "the refusal names the directory: {said}"
    );
    assert!(
        !socket.exists(),
        "no socket was bound in the refused directory"
    );
}
