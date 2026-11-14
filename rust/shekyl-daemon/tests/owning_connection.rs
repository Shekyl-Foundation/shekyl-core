// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The owning connection (`INPUT_GRAMMAR.md` IG-Q106; GS-C3): a wallet that
//! starts its own daemon hands it one end of a connected pair, reads its
//! ready line, calls it on the owner's leg through "this computer"'s client,
//! and holds its life by the connection.
//!
//! Each test re-executes this binary in a role: the daemon (which runs
//! `shekyl_daemon::run::main` with a private `--rpc-socket-dir`, as every
//! harness does), a parent that launches the daemon and is then killed, or
//! a sleeper the parent leaves behind. The daemon is launched through the
//! shared launcher (`shekyl_spawn::pair::EndPair::spawn`), the one a GUI
//! uses.

use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use shekyl_daemon_config::Platform;
use shekyl_network::Network;
use shekyl_rpc_channel::Instance;
use shekyl_rpc_transport::local::{LocalFault, LocalTarget};
use shekyl_spawn::owning::read_ready;
use shekyl_spawn::pair::{keep_in_child, End, EndPair, WindowError};

/// This process's role, when it is a child.
const ROLE: &str = "SHEKYL_TEST_OWNING_ROLE";
/// The working directory the roles share.
const DIR: &str = "SHEKYL_TEST_OWNING_DIR";
/// The daemon's data directory's name under the working directory.
const DATA: &str = "SHEKYL_TEST_OWNING_DATA";
/// The daemon's `--owning-connection` value: a number, `file` for a
/// regular file's descriptor the daemon role opens itself, or absent.
const END: &str = "SHEKYL_TEST_OWNING_END";
/// More daemon arguments, separated by the unit separator.
const EXTRA: &str = "SHEKYL_TEST_OWNING_EXTRA";
/// The parent role leaves a sleeper behind when this is set.
const LEAVE_A_SLEEPER: &str = "SHEKYL_TEST_OWNING_SLEEPER";
/// The test the roles re-execute.
const TEST: &str = "SHEKYL_TEST_OWNING_TEST";

/// How long the ready line may take.
const READY: Duration = Duration::from_secs(120);
/// How long a stop may take, from the close to the exit.
const STOP_ARRIVES: Duration = Duration::from_secs(60);
/// Spacing of the polls.
const POLL: Duration = Duration::from_millis(50);

/// Run the role this process was started in, and exit; return when this
/// process is the test itself.
fn run_role_if_requested() {
    let Some(role) = std::env::var_os(ROLE) else {
        return;
    };
    let dir = PathBuf::from(std::env::var_os(DIR).expect("the working directory"));
    match role.to_str() {
        Some("daemon") => std::process::exit(daemon(&dir)),
        Some("parent") => parent(&dir),
        Some("sleeper") => sleeper(&dir),
        other => panic!("unknown role {other:?}"),
    }
}

/// The daemon role: `run::main` with the harness's arguments.
fn daemon(dir: &Path) -> i32 {
    let data = std::env::var(DATA).expect("the data directory's name");
    let data_dir = dir.join(&data);
    let log_file = data_dir.join("shekyld.log");
    let socket_dir = dir.join("s");
    let mut args: Vec<String> = [
        "shekyld",
        "--network",
        "regtest",
        "--clearnet",
        "off",
        "--rpc-admin-listen",
        "none",
        "--rpc-socket-dir",
        socket_dir.to_str().expect("a UTF-8 path"),
        "--data-dir",
        data_dir.to_str().expect("a UTF-8 path"),
        "--log-file",
        log_file.to_str().expect("a UTF-8 path"),
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    // A regular file's descriptor, held open for the daemon's life.
    let mut _file = None;
    match std::env::var(END).ok().as_deref() {
        None => {}
        Some("file") => {
            let file = File::create(dir.join("not-a-socket")).expect("a regular file");
            args.extend([
                "--owning-connection".to_owned(),
                raw_number(&file).to_string(),
            ]);
            _file = Some(file);
        }
        Some(number) => args.extend(["--owning-connection".to_owned(), number.to_owned()]),
    }
    if let Ok(extra) = std::env::var(EXTRA) {
        args.extend(extra.split('\u{1f}').map(str::to_owned));
    }
    if !args.iter().any(|a| a == "--tor") {
        args.extend(["--tor".to_owned(), "off".to_owned()]);
    }
    let args: Vec<std::ffi::OsString> = args.into_iter().map(Into::into).collect();
    shekyl_daemon::run::main(
        &args,
        &Platform {
            home: Some(dir.to_path_buf()),
            program_data: None,
            session_dir: None,
            service_rendezvous: None,
        },
    )
}

/// The parent role: launch the daemon, wait for its ready line, say so on
/// standard output, optionally leave a sleeper behind, and wait to be
/// killed while holding the parent's end.
fn parent(dir: &Path) -> ! {
    let test = std::env::var(TEST).expect("the test name");
    let (mut daemon, ours) = launch(&test, dir, "data", &[]);
    let _ours = ready_or_panic(&mut daemon, ours, dir, "data");
    let mut line = format!("ready {}", daemon.id());
    if std::env::var_os(LEAVE_A_SLEEPER).is_some() {
        let mut command = Command::new(std::env::current_exe().expect("this test binary"));
        command
            .args(["--exact", &test, "--nocapture", "--include-ignored"])
            .env(ROLE, "sleeper")
            .env(DIR, dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[allow(
            clippy::zombie_processes,
            reason = "the sleeper outlives this parent on purpose; it is reparented and reaped there"
        )]
        let sleeper = shekyl_spawn::spawn_lock::with(|| command.spawn()).expect("the sleeper");
        line.push_str(&format!(" {}", sleeper.id()));
    }
    let mut out = std::io::stdout();
    writeln!(out, "{line}").expect("the parent's line");
    out.flush().expect("the parent's line");
    // Held until killed: the daemon's life is this process's.
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

/// The sleeper role: outlive the parent, until the test releases it, its
/// directory goes, or a bound passes.
fn sleeper(dir: &Path) -> ! {
    let deadline = Instant::now() + Duration::from_secs(300);
    // Released by the test, or by its directory's removal.
    while Instant::now() < deadline && dir.exists() && !dir.join("release").exists() {
        std::thread::sleep(POLL);
    }
    std::process::exit(0)
}

#[cfg(unix)]
fn raw_number(file: &File) -> u64 {
    use std::os::fd::AsRawFd;
    u64::try_from(file.as_raw_fd()).expect("a descriptor is non-negative")
}

#[cfg(windows)]
fn raw_number(file: &File) -> u64 {
    use std::os::windows::io::AsRawHandle;
    file.as_raw_handle() as u64
}

/// A working directory with the private socket directory, as a harness
/// makes it. On Windows the daemon makes the directory itself, labelled.
fn workdir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("a directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        // A configuration file in it is checked with its directory.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("the directory's mode");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(dir.path().join("s"))
            .expect("the socket directory");
    }
    dir
}

/// This binary again, as the daemon of `test`, in `dir` with the data
/// directory `data`.
fn daemon_command(test: &str, dir: &Path, data: &str, extra: &[&str]) -> Command {
    std::fs::create_dir_all(dir.join(data)).expect("the data directory");
    let stderr = File::create(dir.join(format!("{data}.stderr"))).expect("the stderr file");
    let mut command = Command::new(std::env::current_exe().expect("this test binary"));
    command
        .args(["--exact", test, "--nocapture", "--include-ignored"])
        .env(ROLE, "daemon")
        .env(DIR, dir)
        .env(DATA, data)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr));
    if !extra.is_empty() {
        command.env(EXTRA, extra.join("\u{1f}"));
    }
    command
}

/// Launch the daemon through the shared launcher: it inherits one end of a
/// fresh pair, and the parent keeps the other.
fn launch(test: &str, dir: &Path, data: &str, extra: &[&str]) -> (Child, End) {
    let pair = EndPair::new().expect("a pair");
    let mut command = daemon_command(test, dir, data, extra);
    let launched = EndPair::spawn(pair, |number| {
        command.env(END, number.to_string());
        keep_in_child(&mut command, number);
        command.spawn()
    });
    match launched {
        Ok(launched) => launched,
        Err(WindowError::Open(e)) => panic!("the pair could not be handed over: {e}"),
        Err(WindowError::Spawn { error, .. }) => panic!("the daemon did not start: {error}"),
        Err(WindowError::Close { error, .. }) => panic!("the parent's copy stayed open: {error}"),
    }
}

/// Read the ready line, bounded; panic with the daemon's evidence if it
/// does not come.
fn ready_or_panic(daemon: &mut Child, mut ours: End, dir: &Path, data: &str) -> End {
    bound(&ours);
    if let Err(e) = read_ready(&mut ours) {
        let status = daemon.try_wait().ok().flatten();
        panic!(
            "no ready line ({e}); the daemon's status {status:?}\n{}",
            evidence(dir, data)
        );
    }
    ours
}

/// Bound reads on the parent's end by [`READY`]. macOS refuses the option
/// (`EINVAL`) on a socket whose peer has already closed; a read there
/// returns at once, so it needs no bound.
fn bound(end: &End) {
    match end.set_read_timeout(Some(READY)) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => {}
        Err(e) => panic!("a read bound: {e}"),
    }
}

/// "This computer"'s client, told the harness's directory.
fn target(dir: &Path) -> LocalTarget {
    LocalTarget::resolve(Network::Regtest, &Instance::Default, Some(&dir.join("s")))
        .expect("a named directory")
}

fn log(dir: &Path, data: &str) -> String {
    std::fs::read_to_string(dir.join(data).join("shekyld.log")).unwrap_or_default()
}

fn stderr(dir: &Path, data: &str) -> String {
    std::fs::read_to_string(dir.join(format!("{data}.stderr"))).unwrap_or_default()
}

fn evidence(dir: &Path, data: &str) -> String {
    format!("log:\n{}\nstderr:\n{}", log(dir, data), stderr(dir, data))
}

/// The exit status, if `child` ends within `within`.
fn ended_within(child: &mut Child, within: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("the child's state") {
            return Some(status);
        }
        std::thread::sleep(POLL);
    }
    None
}

/// Whether `condition` holds within `within`.
fn holds_within(within: Duration, mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if condition() {
            return true;
        }
        std::thread::sleep(POLL);
    }
    condition()
}

/// What the daemon announces when its starting process lets go.
const CLOSED: &str = "the process that started this daemon closed its owning connection";

/// Kill the child, if it still runs, and reap it.
fn reap(child: &mut Child) {
    if child.try_wait().ok().flatten().is_none() {
        drop(child.kill());
        drop(child.wait());
    }
}

/// **Tests 1 and 2: ready, then owner calls; the close stops it.** The
/// ready line arrives only once the rendezvous exists; the parent then
/// calls `mine_status` (`mining-control`, the owner's) through "this
/// computer"'s client, and it is admitted. Closing the parent's end stops
/// the daemon cleanly: exit 0, the stop announced, the rendezvous removed.
/// Red edit: write the ready line before the RPC's start, and the
/// rendezvous assertion fails.
#[test]
fn ready_then_owner_calls_and_the_close_stops_it() {
    const NAME: &str = "ready_then_owner_calls_and_the_close_stops_it";
    run_role_if_requested();
    let dir = workdir();
    let (mut daemon, ours) = launch(NAME, dir.path(), "data", &[]);
    let ours = ready_or_panic(&mut daemon, ours, dir.path(), "data");
    let target = target(dir.path());
    assert!(
        target.path().exists(),
        "the ready line came before the rendezvous {}",
        target.path().display()
    );
    let status = target
        .call::<shekyl_rpc_client::wire::MineStatus>(&shekyl_rpc_types::kinds::NoParams)
        .unwrap_or_else(|e| {
            panic!(
                "mine_status over the owner's leg: {e}\n{}",
                evidence(dir.path(), "data")
            )
        });
    drop(status);

    drop(ours);
    let exit = ended_within(&mut daemon, STOP_ARRIVES).unwrap_or_else(|| {
        reap(&mut daemon);
        panic!(
            "the daemon kept running after the close\n{}",
            evidence(dir.path(), "data")
        )
    });
    assert!(exit.success(), "{exit}\n{}", evidence(dir.path(), "data"));
    assert!(
        log(dir.path(), "data").contains(CLOSED),
        "{}",
        evidence(dir.path(), "data")
    );
    assert!(
        !target.path().exists(),
        "a clean stop removes the rendezvous"
    );
    assert!(
        matches!(target.dial(), Err(LocalFault::NotRunning { .. })),
        "{:?}",
        target.dial().err()
    );
}

/// Start the parent role for `test`, with or without a sleeper, and read
/// its line: the daemon's pid, and the sleeper's.
fn spawn_parent(test: &str, dir: &Path, sleeper: bool) -> (Child, Vec<u32>) {
    let mut command = Command::new(std::env::current_exe().expect("this test binary"));
    command
        .args(["--exact", test, "--nocapture", "--include-ignored"])
        .env(ROLE, "parent")
        .env(DIR, dir)
        .env(TEST, test)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::from(
            File::create(dir.join("parent.stderr")).expect("the parent's stderr"),
        ));
    if sleeper {
        command.env(LEAVE_A_SLEEPER, "1");
    }
    let mut parent = shekyl_spawn::spawn_lock::with(|| command.spawn()).expect("the parent");
    let mut lines = BufReader::new(parent.stdout.take().expect("the parent's stdout")).lines();
    // libtest prints its own lines first; ours starts with `ready`.
    let line = lines
        .find_map(|line| line.ok().filter(|l| l.starts_with("ready ")))
        .unwrap_or_else(|| {
            reap(&mut parent);
            panic!(
                "the parent never said ready\nparent:\n{}\n{}",
                std::fs::read_to_string(dir.join("parent.stderr")).unwrap_or_default(),
                evidence(dir, "data")
            )
        });
    let pids = line
        .split_whitespace()
        .skip(1)
        .map(|p| p.parse().expect("a pid"))
        .collect();
    (parent, pids)
}

/// The daemon stopped on its own: it announced the close, removed its
/// rendezvous, and released its data directory's lock, which it holds
/// until its last statement.
fn assert_stopped_after_the_parent(dir: &Path) {
    let target = target(dir);
    let stopped = holds_within(STOP_ARRIVES, || {
        log(dir, "data").contains(CLOSED)
            && !target.path().exists()
            && shekyl_daemon_config::Lock::take(&dir.join("data")).is_ok()
    });
    assert!(
        stopped,
        "the daemon outlived its killed parent\n{}",
        evidence(dir, "data")
    );
}

/// **Test 3: a crashed parent cannot orphan it.** The parent launches the
/// daemon and is killed (`SIGKILL`; `TerminateProcess` on Windows), with no
/// chance to close anything: the kernel closes its end, and the daemon
/// stops. Red edit: start the watch's thread without reading (never call
/// `wait_for_close`), and the daemon outlives the parent.
#[test]
fn a_killed_parent_cannot_orphan_the_daemon() {
    const NAME: &str = "a_killed_parent_cannot_orphan_the_daemon";
    run_role_if_requested();
    let dir = workdir();
    let (mut parent, _pids) = spawn_parent(NAME, dir.path(), false);
    parent.kill().expect("kill the parent");
    drop(parent.wait());
    assert_stopped_after_the_parent(dir.path());
}

/// **Test 3a: no other child of the parent holds the parent's end.** After
/// the launch the parent starts an unrelated child that outlives it; then
/// the parent is killed. The daemon still stops: a copy of the parent's
/// end in any other process would keep the connection open and orphan the
/// node. Red edit: clear `FD_CLOEXEC` on the parent's end (set
/// `HANDLE_FLAG_INHERIT` on Windows) before the sleeper's spawn, and the
/// daemon outlives the parent.
#[test]
fn a_child_the_parent_leaves_behind_does_not_hold_the_daemon() {
    const NAME: &str = "a_child_the_parent_leaves_behind_does_not_hold_the_daemon";
    run_role_if_requested();
    let dir = workdir();
    let (mut parent, pids) = spawn_parent(NAME, dir.path(), true);
    assert_eq!(pids.len(), 2, "the daemon's pid and the sleeper's");
    parent.kill().expect("kill the parent");
    drop(parent.wait());
    let stopped = std::panic::catch_unwind(|| assert_stopped_after_the_parent(dir.path()));
    // The sleeper is released whatever the verdict.
    File::create(dir.path().join("release")).expect("release the sleeper");
    if let Err(panic) = stopped {
        std::panic::resume_unwind(panic);
    }
}

/// **Test 5: a second start refuses.** While one GUI-started daemon runs, a
/// second of the same account, network and instance (its own data
/// directory, so it is the rendezvous that refuses it) writes no ready
/// line, exits with the typed refusal, and leaves the first answering.
/// Red edit: skip the start-up dial, and the second daemon writes its
/// ready line.
#[test]
fn a_second_start_refuses_with_no_ready_line() {
    const NAME: &str = "a_second_start_refuses_with_no_ready_line";
    run_role_if_requested();
    let dir = workdir();
    let (mut first, ours) = launch(NAME, dir.path(), "first", &[]);
    let ours = ready_or_panic(&mut first, ours, dir.path(), "first");

    let (mut second, mut theirs) = launch(NAME, dir.path(), "second", &[]);
    bound(&theirs);
    let ready = read_ready(&mut theirs);
    let exit = ended_within(&mut second, STOP_ARRIVES);
    reap(&mut second);
    assert!(
        ready.is_err(),
        "the second daemon wrote a ready line\n{}",
        evidence(dir.path(), "second")
    );
    assert_eq!(
        exit.and_then(|s| s.code()),
        Some(2),
        "{}",
        evidence(dir.path(), "second")
    );
    assert!(
        stderr(dir.path(), "second").contains("config.socket.running"),
        "{}",
        evidence(dir.path(), "second")
    );
    target(dir.path())
        .call::<shekyl_rpc_client::wire::MineStatus>(&shekyl_rpc_types::kinds::NoParams)
        .expect("the first daemon still answers");

    drop(ours);
    let exit = ended_within(&mut first, STOP_ARRIVES);
    reap(&mut first);
    assert!(
        exit.is_some_and(|s| s.success()),
        "{}",
        evidence(dir.path(), "first")
    );
}

/// Run the daemon role with `end` and `extra`, and return its exit code and
/// standard error.
fn refused(
    test: &str,
    dir: &Path,
    data: &str,
    end: Option<&str>,
    extra: &[&str],
) -> (Option<i32>, String) {
    let mut command = daemon_command(test, dir, data, extra);
    if let Some(end) = end {
        command.env(END, end);
    }
    let mut child = shekyl_spawn::spawn_lock::with(|| command.spawn()).expect("the daemon");
    let exit = ended_within(&mut child, STOP_ARRIVES);
    reap(&mut child);
    (exit.and_then(|s| s.code()), stderr(dir, data))
}

/// **Test 6: bad values refuse, each with its typed diagnostic.** A number
/// this process does not hold, a regular file's descriptor, a standard
/// stream's number, and the option with `service`. The option in a
/// configuration file (`config.value.surface`) is the configuration's
/// refusal, asserted where the file is read
/// (`shekyl-daemon-config` `the_owning_connection_is_the_command_lines_and_not_a_services`):
/// a file here would first meet the file-permission check on every
/// ancestor of the test's directory. Red edit: drop the socket check in
/// `shekyl_spawn::owning::adopt`, and the regular file is refused for the
/// wrong reason.
#[test]
fn bad_owning_connections_refuse_with_their_diagnostics() {
    const NAME: &str = "bad_owning_connections_refuse_with_their_diagnostics";
    run_role_if_requested();
    let dir = workdir();

    let (code, err) = refused(NAME, dir.path(), "closed", Some("1000000"), &[]);
    assert_eq!(code, Some(2), "{err}");
    assert!(err.contains("config.owning-connection.unusable"), "{err}");

    let (code, err) = refused(NAME, dir.path(), "file", Some("file"), &[]);
    assert_eq!(code, Some(2), "{err}");
    assert!(err.contains("config.owning-connection.unusable"), "{err}");
    assert!(err.contains("not a socket"), "{err}");

    let (code, err) = refused(NAME, dir.path(), "standard", Some("2"), &[]);
    assert_eq!(code, Some(2), "{err}");
    assert!(err.contains("config.value.range"), "{err}");

    // A valid end, so the refusal is the pair's and not the adoption's. On
    // Windows `service` is refused before the session is read (RT-W14).
    #[cfg(unix)]
    service_refuses_the_owning_connection(NAME, dir.path());
}

/// Test 6's last case: the option with `service`, given a valid end.
#[cfg(unix)]
fn service_refuses_the_owning_connection(test: &str, dir: &Path) {
    let (mut child, _ours) = launch(test, dir, "service", &["--service"]);
    let exit = ended_within(&mut child, STOP_ARRIVES);
    reap(&mut child);
    let err = stderr(dir, "service");
    assert_eq!(exit.and_then(|s| s.code()), Some(2), "{err}");
    assert!(err.contains("config.value.conflict"), "{err}");
    assert!(err.contains("owning-connection"), "{err}");
}

/// **Test 4: Tor does not hold the connection.** With the managed Tor
/// running, the daemon's end is in no Tor descriptor (Linux, from
/// `/proc`), and closing the parent's end stops the daemon and its Tor.
/// Needs the pinned Tor binary: `SHEKYL_TEST_PINNED_TOR_BINARY`. Red edit:
/// drop `FD_CLOEXEC` from the adoption, and Tor's descriptors hold the
/// daemon's end.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "needs the pinned Tor binary: SHEKYL_TEST_PINNED_TOR_BINARY"]
fn tor_does_not_hold_the_owning_connection() {
    const NAME: &str = "tor_does_not_hold_the_owning_connection";
    run_role_if_requested();
    let tor = std::env::var("SHEKYL_TEST_PINNED_TOR_BINARY")
        .expect("SHEKYL_TEST_PINNED_TOR_BINARY names the pinned Tor binary");
    let dir = workdir();
    let (mut daemon, ours) = launch(
        NAME,
        dir.path(),
        "data",
        &["--tor", "managed", "--tor-file", &tor],
    );
    let ours = ready_or_panic(&mut daemon, ours, dir.path(), "data");
    let daemon_pid = daemon.id();
    let tor_pid = {
        let mut found = None;
        let seen = holds_within(READY, || {
            found = children_of(daemon_pid)
                .into_iter()
                .find(|pid| comm(*pid).as_deref() == Some("tor"));
            found.is_some()
        });
        assert!(
            seen,
            "no managed Tor appeared\n{}",
            evidence(dir.path(), "data")
        );
        found.expect("seen")
    };
    // The daemon's end, by the socket's inode, from the number it adopted.
    let number = owning_number(daemon_pid).expect("the daemon's command line names its end");
    let ours_inode = std::fs::read_link(format!("/proc/{daemon_pid}/fd/{number}"))
        .expect("the daemon holds its end");
    let held: Vec<PathBuf> = std::fs::read_dir(format!("/proc/{tor_pid}/fd"))
        .expect("Tor's descriptors")
        .filter_map(Result::ok)
        .filter_map(|entry| std::fs::read_link(entry.path()).ok())
        .collect();
    assert!(
        !held.contains(&ours_inode),
        "Tor holds the owning connection {}",
        ours_inode.display()
    );

    drop(ours);
    let exit = ended_within(&mut daemon, STOP_ARRIVES);
    reap(&mut daemon);
    assert!(
        exit.is_some_and(|s| s.success()),
        "{}",
        evidence(dir.path(), "data")
    );
    let tor_gone = holds_within(STOP_ARRIVES, || {
        std::fs::read_to_string(format!("/proc/{tor_pid}/stat"))
            .map_or(true, |stat| stat.contains(") Z "))
    });
    assert!(tor_gone, "the managed Tor outlived the daemon");
}

#[cfg(target_os = "linux")]
fn children_of(parent: u32) -> Vec<u32> {
    std::fs::read_dir("/proc")
        .expect("/proc")
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
        .filter(|pid| {
            std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .ok()
                .and_then(|stat| {
                    let after = stat.rsplit_once(") ")?.1;
                    after.split_whitespace().nth(1)?.parse::<u32>().ok()
                })
                == Some(parent)
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn comm(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|c| c.trim().to_owned())
}

/// The daemon's `--owning-connection` number: the role reads it from its
/// environment.
#[cfg(target_os = "linux")]
fn owning_number(pid: u32) -> Option<String> {
    let environ = std::fs::read(format!("/proc/{pid}/environ")).ok()?;
    environ
        .split(|b| *b == 0)
        .filter_map(|entry| std::str::from_utf8(entry).ok())
        .find_map(|entry| entry.strip_prefix(&format!("{END}=")).map(str::to_owned))
}
