// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The managed tor's command line, environment, control connection, and the one
//! file it may read.
//!
//! [`managed_tor_command`] is the whole launch a user gets. It is infallible:
//! the fallible steps come before it. [`LaunchEnvironment::resolve`] is, on
//! Windows, the system-directory lookup; [`ControlPair::new`] makes the control
//! connection; the blank file and the data directory are prepared
//! ([`prepare_data_directory`], [`install_blank_config`]). [`ControlPair::spawn`]
//! runs the command with tor's end handed over.
//!
//! **The control connection is inherited, not dialled** (`TOR_SUPERVISOR.md`
//! `TSR-Q7`, §4.7). Tor is started with `__OwningControllerFD` naming its end of a
//! connected socket pair, and treats it as an owning control connection that is
//! already authenticated. So the managed launch opens no control port, writes no
//! port file and no cookie, and sends no `TAKEOWNERSHIP`: there is no window between
//! the spawn and ownership, and no listener another local process could reach.
//! Tor exits when the connection closes, which is what a parent's death does.
//!
//! The option list is closed. Non-anonymous onion serving is one of the things
//! it holds shut; the other half is [`super::onion::OnionFlags`].

use std::ffi::OsStr;
#[cfg(windows)]
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use tokio::process::{Child, Command};

#[cfg(windows)]
use super::actor::SystemDirectoryError;
use super::actor::{ControlError, ControlRead, ControlWrite, ManagedTor};
use crate::binary::VerifiedTorBinary;

/// `LD_LIBRARY_PATH`. One absolute directory, the verified binary's own.
#[cfg(target_os = "linux")]
const LOADER_PATH_VARIABLE: &str = "LD_LIBRARY_PATH";

/// What the pinned Windows `tor.exe` needs in order to start. Never copied
/// from the parent's environment.
#[cfg(windows)]
const SYSTEM_ROOT_VARIABLE: &str = "SystemRoot";

/// The file options that would otherwise name files compiled into tor.
///
/// The unit test that lists these names writes them out again on purpose.
/// It is the oracle; this array is only what the builder loops.
const LAUNCH_OWNED_FILES: [&str; 4] = [
    "--torrc-file",
    "--defaults-torrc",
    "--GeoIPFile",
    "--GeoIPv6File",
];

/// The number tor is told its end of the control connection has: a file
/// descriptor on Unix, a socket on Windows.
#[cfg(unix)]
pub(crate) type TorEndNumber = std::os::fd::RawFd;
/// The number tor is told its end of the control connection has: a file
/// descriptor on Unix, a socket on Windows.
#[cfg(windows)]
pub(crate) type TorEndNumber = std::os::windows::io::RawSocket;

/// The highest standard stream. Std moves the child's stdin, stdout and stderr
/// onto 0, 1 and 2 before it runs `pre_exec`, so tor's end must be above them.
#[cfg(unix)]
const LAST_STANDARD_STREAM: std::os::fd::RawFd = 2;

/// Name of the one zero-length file those four options share.
pub(crate) const BLANK_FILE_NAME: &str = "blank";

/// Tor's notice log, inside the data directory. The path is passed unquoted:
/// `Log <severity> file <FILENAME>` takes the remainder of the value as the
/// filename, so a quote would become part of the name.
pub(crate) const LOG_FILE_NAME: &str = "tor.log";

/// Owner read/write. Applied again after create, so the umask cannot loosen it.
#[cfg(unix)]
const BLANK_FILE_OWNER_ONLY: u32 = 0o600;

/// Owner access only. Applied to the directory fd, which does not follow a
/// symlink planted at the final component.
#[cfg(unix)]
const DIRECTORY_OWNER_ONLY: u32 = 0o700;

/// A file we created has one link. A hard link has more, and truncating it
/// would truncate the other name.
#[cfg(unix)]
const SOLE_LINK: u64 = 1;

/// `FILE_FLAG_OPEN_REPARSE_POINT`. The open then names the reparse point
/// itself, so a symlink is visible as a symlink.
#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

/// A link count above this is a second name for the file.
#[cfg(windows)]
const SINGLE_LINK: u32 = 1;

/// The at-most-one variable the managed tor receives, already resolved.
///
/// One variant per target. The command applies [`Self::variable`] and nothing
/// else, so the environment a test reads off the command is this value.
pub(crate) enum LaunchEnvironment {
    /// Linux: the loader searches the directory the pin gate checked.
    #[cfg(target_os = "linux")]
    LoaderPath(PathBuf),
    /// Windows: `SystemRoot` from `GetSystemWindowsDirectoryW`.
    #[cfg(windows)]
    SystemRoot(OsString),
    /// Every other target, including macOS, sets nothing. `DYLD_*` stays unset.
    #[cfg(not(any(target_os = "linux", windows)))]
    Cleared,
}

impl LaunchEnvironment {
    /// Resolve the one variable, or fail before spawn.
    ///
    /// `binary` is read on Linux only, where the loader path is the witness's
    /// directory. On Windows the value comes from the system call.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(unused_variables, reason = "only Linux reads the witness directory")
    )]
    #[cfg_attr(
        not(windows),
        expect(
            clippy::unnecessary_wraps,
            reason = "only the Windows system-directory lookup can fail"
        )
    )]
    pub(crate) fn resolve(binary: &VerifiedTorBinary) -> Result<Self, ControlError> {
        #[cfg(target_os = "linux")]
        let environment = Self::LoaderPath(binary.library_dir().to_path_buf());
        #[cfg(windows)]
        let environment =
            Self::SystemRoot(system_windows_directory().map_err(ControlError::SystemDirectory)?);
        #[cfg(not(any(target_os = "linux", windows)))]
        let environment = Self::Cleared;
        Ok(environment)
    }

    /// The one variable this target sets after `env_clear`.
    ///
    /// A target either always sets one or always sets none. The empty case is
    /// the absence of this method, not an `Option` that one target's build
    /// would always fill.
    #[cfg(any(target_os = "linux", windows))]
    pub(crate) fn variable(&self) -> (&'static str, &OsStr) {
        match self {
            #[cfg(target_os = "linux")]
            Self::LoaderPath(dir) => (LOADER_PATH_VARIABLE, dir.as_os_str()),
            #[cfg(windows)]
            Self::SystemRoot(root) => (SYSTEM_ROOT_VARIABLE, root.as_os_str()),
        }
    }

    #[cfg_attr(
        not(any(target_os = "linux", windows)),
        allow(unused_variables, reason = "this target sets no variable")
    )]
    fn apply(&self, cmd: &mut Command) {
        #[cfg(any(target_os = "linux", windows))]
        {
            let (name, value) = self.variable();
            cmd.env(name, value);
        }
    }
}

/// The command line and environment the managed tor is launched with.
///
/// Infallible. [`LaunchEnvironment::resolve`] has already produced `environment`.
pub(crate) fn managed_tor_command(
    managed: &ManagedTor,
    tor_end: TorEndNumber,
    environment: &LaunchEnvironment,
) -> Command {
    // The witness type guarantees this path passed the hash-pin gate and is
    // canonical: the file hashed is the file named.
    let mut cmd = Command::new(managed.tor_binary.as_path());
    // No inherited environment (`TOR_BUNDLE_DISTRIBUTION.md` TB-7 part 2).
    // `LD_PRELOAD`, `LD_LIBRARY_PATH` or `DYLD_INSERT_LIBRARIES` from a shell,
    // a unit file or a profile would load code into the process whose files
    // were just verified. `Command::get_envs` does not show this clear; the
    // re-exec test reads the child's own environment.
    cmd.env_clear();
    environment.apply(&mut cmd);
    cmd.arg("--DataDirectory")
        .arg(&managed.data_dir)
        // The control connection: tor's end of the pair, already authenticated and
        // owning. No control port, port file or cookie exists.
        .arg("--__OwningControllerFD")
        .arg(tor_end.to_string())
        // Tor writes `state` and its caches less often (TSR §1, Disk).
        .arg("--AvoidDiskWrites")
        .arg("1")
        .arg("--SocksPort")
        .arg(managed.socks_port.as_arg())
        // A file log in the (owner-only, caller-owned) data directory so a
        // `Spawn` failure is diagnosable. The actor's own errors stay
        // content-free. `notice` carries bootstrap and warnings, not circuit
        // ids, targets or SOCKS usernames.
        //
        // The path is passed **unquoted on purpose**. Tor's
        // `Log <severity> file <FILENAME>` grammar takes the entire remainder
        // of the option value as the filename, so an embedded space is
        // preserved. A quote becomes part of the filename.
        .arg("--Log")
        .arg(format!(
            "notice file {}",
            managed.data_dir.join(LOG_FILE_NAME).display()
        ))
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // Every file tor would otherwise find by itself is named, and named as
    // ours: one zero-length file in the data directory. With no `--torrc-file`
    // tor loads its default torrc, and with no `--defaults-torrc` its default
    // `torrc-defaults`. On Unix both sit under the compiled-in `CONFDIR`, which
    // for the pinned Linux bundle is `/var/tmp/dist/tor/etc/tor`. On Windows
    // they sit under the user's `APPDATA`, found through the shell API, so the
    // cleared environment does not move them. The GeoIP files are found the
    // same way, and tor parses them whatever the torrc says. A zero-length
    // GeoIP file maps no address to a country; a future knob that selects
    // nodes by country needs a real file.
    let blank = blank_config_path(&managed.data_dir);
    for option in LAUNCH_OWNED_FILES {
        cmd.arg(option).arg(&blank);
    }
    // ---------------------------------------------------------------------------------
    // NON-ANONYMOUS SERVING IS HELD SHUT HERE, and this is one half of a two-half rule.
    //
    // tor can be put into single-hop / non-anonymous onion mode by *two* independent
    // routes, and they are foreclosed by *different* mechanisms in *different* files:
    //
    //   1. `ADD_ONION`'s `NonAnonymous` flag — foreclosed **by type**: it is not a member
    //      of `control::onion::OnionFlags`, and `onion_line_is_never_non_anonymous`
    //      asserts over every representable flag/PoW combination that it can never reach
    //      the wire.
    //   2. **torrc / config** — `HiddenServiceNonAnonymousMode` (which additionally
    //      requires `SocksPort 0`) — foreclosed **by construction, right here**, by two
    //      things together. The configuration files tor reads are named, and they are
    //      ours and zero-length (`--torrc-file`, `--defaults-torrc`, and the two GeoIP
    //      files beside them, above). Leaving those options out does not close this
    //      route: tor then reads its compiled-in defaults. And every other option is
    //      one of the typed ones above: there is no `extra_args` and no `+Option` append.
    //
    // The two halves cannot see each other. The `OnionFlags` test does not fire when
    // someone adds a knob here. **When the anticipated future typed knobs arrive
    // (bridges, an upstream proxy), non-anonymous mode is on the list of things this
    // discipline is holding shut** — a knob that reaches `HiddenServiceNonAnonymousMode`
    // or zeroes the `SocksPort` re-opens route 2 while route 1's test stays green.
    // ---------------------------------------------------------------------------------
    //
    // The one caller-toggleable knob (`ManagedTor::disable_network`): an offline tor
    // for the child-lifecycle test. A typed bool, not a flag passthrough.
    if managed.disable_network {
        cmd.arg("--DisableNetwork").arg("1");
    }
    inherit_in_the_child_only(&mut cmd, tor_end);
    cmd
}

/// Unix: clear close-on-exec on tor's end in the child, after `fork`. The parent's
/// copy keeps it, so no other spawn can inherit tor's end, concurrent or not.
#[cfg(unix)]
fn inherit_in_the_child_only(cmd: &mut Command, tor_end: TorEndNumber) {
    // SAFETY: the closure runs in the child between `fork` and `exec`. It calls only
    // `fcntl`, which is async-signal-safe, and allocates nothing (`last_os_error`
    // reads `errno` into an inline value).
    unsafe {
        cmd.pre_exec(move || {
            let flags = libc::fcntl(tor_end, libc::F_GETFD);
            if flags < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::fcntl(tor_end, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// Windows marks tor's end inheritable around the spawn instead
/// ([`ControlPair::spawn`]); nothing is set on the command.
#[cfg(not(unix))]
fn inherit_in_the_child_only(_cmd: &mut Command, _tor_end: TorEndNumber) {}

/// The managed tor's control connection before the spawn: our end, and tor's.
///
/// Unix: a `socketpair`, both ends close-on-exec as std makes them. Windows: a
/// loopback TCP pair, accepted only from our own connect, both ends not inheritable
/// as std makes them.
pub(crate) struct ControlPair {
    ours: OurEnd,
    tors: OurEnd,
}

#[cfg(unix)]
type OurEnd = std::os::unix::net::UnixStream;
#[cfg(windows)]
type OurEnd = std::net::TcpStream;

impl ControlPair {
    /// Make the connected pair.
    #[cfg(unix)]
    pub(crate) fn new() -> Result<Self, ControlError> {
        use std::os::fd::AsRawFd;
        let (ours, tors) = OurEnd::pair().map_err(|_| ControlError::Spawn)?;
        // A process started with a standard stream closed hands those numbers out
        // again; tor's end there would be overwritten by the child's stdio.
        if tors.as_raw_fd() <= LAST_STANDARD_STREAM {
            return Err(ControlError::Spawn);
        }
        Ok(Self { ours, tors })
    }

    /// Make the connected pair. The listener is bound to loopback and accepts one
    /// connection; one that does not come from our own connect is refused, so
    /// another local process that races into the accept gets nothing and the launch
    /// fails instead.
    #[cfg(windows)]
    pub(crate) fn new() -> Result<Self, ControlError> {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .map_err(|_| ControlError::Spawn)?;
        let address = listener.local_addr().map_err(|_| ControlError::Spawn)?;
        let ours = OurEnd::connect(address).map_err(|_| ControlError::Spawn)?;
        let (tors, peer) = listener.accept().map_err(|_| ControlError::Spawn)?;
        if Some(peer) != ours.local_addr().ok() {
            return Err(ControlError::Spawn);
        }
        Ok(Self { ours, tors })
    }

    /// The number tor is given in `--__OwningControllerFD`.
    #[cfg(unix)]
    pub(crate) fn tor_end(&self) -> TorEndNumber {
        use std::os::fd::AsRawFd;
        self.tors.as_raw_fd()
    }

    /// The number tor is given in `--__OwningControllerFD`.
    #[cfg(windows)]
    pub(crate) fn tor_end(&self) -> TorEndNumber {
        use std::os::windows::io::AsRawSocket;
        self.tors.as_raw_socket()
    }

    /// Spawn `cmd` with tor's end handed to the child, then close our copy of it.
    ///
    /// **Our copy of tor's end is closed before this returns.** While the parent holds
    /// it, the socket stays open whatever tor does, and a read on our end would never
    /// see tor's death. The death path depends on this.
    ///
    /// The spawn holds [`crate::spawn_lock`]. On Windows that lock is what keeps the
    /// inheritable window private to this spawn.
    pub(crate) fn spawn(
        self,
        cmd: &mut Command,
    ) -> Result<(Child, ControlRead, ControlWrite), ControlError> {
        let Self { ours, tors } = self;
        let child = {
            let _spawning = crate::spawn_lock::hold();
            let spawned = spawn_inheriting(cmd, &tors);
            drop(tors);
            spawned?
        };
        let (read, write) = into_halves(ours)?;
        Ok((child, read, write))
    }
}

/// Test builds only: a sleeper process that inherits a copy of tor's end and lives
/// `lives`, handed to the test through `sleeper` (`TSR-F16`, case C6b).
#[cfg(test)]
pub(crate) struct LeakTorEnd {
    pub(crate) lives: std::time::Duration,
    pub(crate) sleeper: tokio::sync::oneshot::Sender<std::process::Child>,
}

#[cfg(test)]
impl ControlPair {
    /// Leak tor's end into a sleeper that lives `leak.lives`. Unix: the sleeper's
    /// `pre_exec` clears close-on-exec, as the launch does. Windows: the end is marked
    /// inheritable around the sleeper's spawn, under the spawn lock.
    pub(crate) fn leak(&self, leak: LeakTorEnd) -> Result<(), ControlError> {
        let seconds = leak.lives.as_secs().max(1);
        #[cfg(unix)]
        let sleeper = {
            use std::os::unix::process::CommandExt;
            let tor_end = self.tor_end();
            let mut cmd = std::process::Command::new("/bin/sleep");
            cmd.arg(seconds.to_string())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            // SAFETY: as in `inherit_in_the_child_only`: `fcntl` only, no allocation.
            unsafe {
                cmd.pre_exec(move || {
                    let flags = libc::fcntl(tor_end, libc::F_GETFD);
                    if flags < 0
                        || libc::fcntl(tor_end, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            crate::spawn_lock::spawn(&mut cmd).map_err(|_| ControlError::Spawn)?
        };
        #[cfg(windows)]
        let sleeper = {
            // `ping -n N` waits about N - 1 seconds.
            let mut cmd = std::process::Command::new("ping");
            cmd.args(["-n", &(seconds + 1).to_string(), "127.0.0.1"])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            let _spawning = crate::spawn_lock::hold();
            set_inheritable(&self.tors, true)?;
            let spawned = cmd.spawn();
            set_inheritable(&self.tors, false)?;
            spawned.map_err(|_| ControlError::Spawn)?
        };
        leak.sleeper.send(sleeper).ok();
        Ok(())
    }
}

#[cfg(unix)]
fn spawn_inheriting(cmd: &mut Command, _tors: &OurEnd) -> Result<Child, ControlError> {
    cmd.spawn().map_err(|_| ControlError::Spawn)
}

/// Mark tor's end inheritable, spawn, and clear the mark, all under the spawn lock the
/// caller holds.
#[cfg(windows)]
fn spawn_inheriting(cmd: &mut Command, tors: &OurEnd) -> Result<Child, ControlError> {
    set_inheritable(tors, true)?;
    let spawned = cmd.spawn().map_err(|_| ControlError::Spawn);
    // Cleared whatever the spawn did; the caller closes the handle next regardless.
    let cleared = set_inheritable(tors, false);
    let child = spawned?;
    cleared.map(|()| child)
}

#[cfg(windows)]
fn set_inheritable(socket: &OurEnd, inherit: bool) -> Result<(), ControlError> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Foundation::{SetHandleInformation, HANDLE_FLAG_INHERIT};
    let flags = if inherit { HANDLE_FLAG_INHERIT } else { 0 };
    // A socket from the base provider is a kernel handle. The value is `usize`-wide
    // on every Windows target; the cast restores it.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "a SOCKET is pointer-sized on Windows"
    )]
    let handle = socket.as_raw_socket() as usize as windows_sys::Win32::Foundation::HANDLE;
    // SAFETY: `handle` is the socket `socket` holds open for the call's duration.
    if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, flags) } == 0 {
        return Err(ControlError::Spawn);
    }
    Ok(())
}

#[cfg(unix)]
fn into_halves(ours: OurEnd) -> Result<(ControlRead, ControlWrite), ControlError> {
    ours.set_nonblocking(true)
        .map_err(|_| ControlError::Spawn)?;
    let (read, write) = tokio::net::UnixStream::from_std(ours)
        .map_err(|_| ControlError::Spawn)?
        .into_split();
    Ok((Box::pin(read), Box::pin(write)))
}

#[cfg(windows)]
fn into_halves(ours: OurEnd) -> Result<(ControlRead, ControlWrite), ControlError> {
    ours.set_nonblocking(true)
        .map_err(|_| ControlError::Spawn)?;
    let (read, write) = tokio::net::TcpStream::from_std(ours)
        .map_err(|_| ControlError::Spawn)?
        .into_split();
    Ok((Box::pin(read), Box::pin(write)))
}

/// The zero-length file the managed tor is given as its torrc, its defaults
/// torrc and both GeoIP files.
pub(crate) fn blank_config_path(data_dir: &Path) -> PathBuf {
    data_dir.join(BLANK_FILE_NAME)
}

/// Create the data directory and, on Unix, make the final component owner-only.
///
/// A symlink at the final component is refused. Parents may be symlinks
/// (`/var/tmp`). The mode is set on the directory fd opened with `O_NOFOLLOW`,
/// so a symlink planted between the check and the chmod is not followed.
/// The same-user attacker who can already write the directory is out of scope.
pub(crate) async fn prepare_data_directory(path: &Path) -> Result<(), ControlError> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(meta) if meta.file_type().is_symlink() => return Err(ControlError::Spawn),
        Ok(meta) if !meta.is_dir() => return Err(ControlError::Spawn),
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            tokio::fs::create_dir_all(path)
                .await
                .map_err(|_| ControlError::Spawn)?;
        }
        Err(_) => return Err(ControlError::Spawn),
    }
    #[cfg(unix)]
    secure_owned_directory(path).await?;
    Ok(())
}

/// Write the blank file tor is about to be pointed at.
///
/// The open does not follow a symlink. An existing regular file is truncated
/// only when it has a single link and, on Unix, is owned by the caller. A
/// hard link is left untouched: truncating it would change the other name.
pub(crate) async fn install_blank_config(data_dir: &Path) -> Result<(), ControlError> {
    write_blank_file(&blank_config_path(data_dir)).await
}

#[cfg(unix)]
async fn secure_owned_directory(path: &Path) -> Result<(), ControlError> {
    use std::os::unix::fs::PermissionsExt;

    let directory = tokio::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
        .await
        .map_err(|_| ControlError::Spawn)?;
    let meta = directory
        .metadata()
        .await
        .map_err(|_| ControlError::Spawn)?;
    if !meta.is_dir() || !owned_by_caller(&meta) {
        return Err(ControlError::Spawn);
    }
    directory
        .set_permissions(std::fs::Permissions::from_mode(DIRECTORY_OWNER_ONLY))
        .await
        .map_err(|_| ControlError::Spawn)
}

#[cfg(unix)]
fn owned_by_caller(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: `geteuid` has no preconditions. It returns the effective user id.
    meta.uid() == unsafe { libc::geteuid() }
}

#[cfg(unix)]
async fn write_blank_file(path: &Path) -> Result<(), ControlError> {
    match tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(BLANK_FILE_OWNER_ONLY)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .await
    {
        Ok(file) => restrict_blank_file(&file).await,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            reuse_our_blank_file(path).await
        }
        Err(_) => Err(ControlError::Spawn),
    }
}

#[cfg(unix)]
async fn reuse_our_blank_file(path: &Path) -> Result<(), ControlError> {
    use std::os::unix::fs::MetadataExt;

    // No `truncate` yet: a hard link must still hold its bytes when we refuse.
    let file = tokio::fs::OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .await
        .map_err(|_| ControlError::Spawn)?;
    let meta = file.metadata().await.map_err(|_| ControlError::Spawn)?;
    if !meta.is_file() || meta.nlink() != SOLE_LINK || !owned_by_caller(&meta) {
        return Err(ControlError::Spawn);
    }
    file.set_len(0).await.map_err(|_| ControlError::Spawn)?;
    restrict_blank_file(&file).await
}

#[cfg(unix)]
async fn restrict_blank_file(file: &tokio::fs::File) -> Result<(), ControlError> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(BLANK_FILE_OWNER_ONLY))
        .await
        .map_err(|_| ControlError::Spawn)
}

#[cfg(windows)]
async fn write_blank_file(path: &Path) -> Result<(), ControlError> {
    // `truncate(false)`: the open itself must not discard an existing file.
    // The link count is checked first, and only then is a sole link emptied.
    let file = tokio::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .await
        .map_err(|_| ControlError::Spawn)?;
    let meta = file.metadata().await.map_err(|_| ControlError::Spawn)?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(ControlError::Spawn);
    }
    if link_count(&file)? > SINGLE_LINK {
        return Err(ControlError::Spawn);
    }
    file.set_len(0).await.map_err(|_| ControlError::Spawn)
}

/// `nNumberOfLinks` for an open file. `std`'s `number_of_links` is unstable,
/// and the one field does not justify the `Win32_Storage_FileSystem` module.
/// The query is one call on a handle already open, not a path walk.
#[cfg(windows)]
fn link_count(file: &tokio::fs::File) -> Result<u32, ControlError> {
    use std::os::windows::io::AsRawHandle;

    let mut info = std::mem::MaybeUninit::<ByHandleFileInformation>::zeroed();
    // SAFETY: `file` holds the handle open. `info` is a writable struct of the
    // documented layout. A zero return writes nothing we read.
    let wrote = unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr()) };
    if wrote == 0 {
        return Err(ControlError::Spawn);
    }
    // SAFETY: a nonzero return means the call wrote the whole struct.
    Ok(unsafe { info.assume_init() }.number_of_links)
}

/// `BY_HANDLE_FILE_INFORMATION`, field for field. Fifty-two bytes.
#[cfg(windows)]
#[repr(C)]
struct ByHandleFileInformation {
    _attributes: u32,
    _creation_low: u32,
    _creation_high: u32,
    _access_low: u32,
    _access_high: u32,
    _write_low: u32,
    _write_high: u32,
    _volume_serial: u32,
    _size_high: u32,
    _size_low: u32,
    number_of_links: u32,
    _index_high: u32,
    _index_low: u32,
}

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn GetFileInformationByHandle(
        file: *mut core::ffi::c_void,
        info: *mut ByHandleFileInformation,
    ) -> i32;
}

#[cfg(not(any(unix, windows)))]
async fn write_blank_file(path: &Path) -> Result<(), ControlError> {
    tokio::fs::write(path, b"")
        .await
        .map_err(|_| ControlError::Spawn)
}

/// The Windows system directory, from `GetSystemWindowsDirectoryW`.
///
/// The system-wide directory, not the per-session one `GetWindowsDirectoryW`
/// would return under Terminal Services. The call reads no environment.
/// Without this value the pinned `tor.exe` (0.4.9.13) aborts at startup with
/// `0xC0000409` (observed on Windows, 2026-10-15).
#[cfg(windows)]
fn system_windows_directory() -> Result<OsString, SystemDirectoryError> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;

    // SAFETY: a null buffer with a size of zero writes nothing. The call
    // returns the size the buffer needs, terminating null included, or 0
    // on failure. The OS error is read before any further call.
    let needed = unsafe { GetSystemWindowsDirectoryW(std::ptr::null_mut(), 0) };
    if needed == 0 {
        return Err(SystemDirectoryError::from_last_os_error());
    }
    let len = usize::try_from(needed).map_err(|_| SystemDirectoryError::UnusableLength)?;
    let mut buf = vec![0u16; len];
    // SAFETY: `buf` holds `needed` u16s and the call writes at most that many,
    // including the terminating null. On success the return excludes that null.
    let written = unsafe { GetSystemWindowsDirectoryW(buf.as_mut_ptr(), needed) };
    if written == 0 || written >= needed {
        return Err(SystemDirectoryError::UnusableLength);
    }
    let chars = usize::try_from(written).map_err(|_| SystemDirectoryError::UnusableLength)?;
    buf.truncate(chars);
    Ok(OsString::from_wide(&buf))
}

// --- What tor's notice log says it opened -----------------------------------
//
// The live launch asserts on this classifier. The line shapes are pinned
// beside it, so a dialect change fails in the unit gate.

/// A file tor's notice log says it read, looked for, or parsed.
///
/// Production does not parse the log. The live launch test and the fixtures
/// below share this reading, so it exists only when tests are compiled.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LoggedFile {
    /// `Read configuration file "%s".`
    ConfigRead,
    /// Any other `configuration file "%s"` mention, including the lowercase
    /// `Unable to open configuration file` form.
    ConfigMention,
    /// `Parsing GEOIP IPv4|IPv6 file %s.`
    GeoipParse,
    /// `Failed to open GEOIP file %s.`
    GeoipOpen,
}

/// One file named by one log line.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LogMention<'a> {
    pub(crate) kind: LoggedFile,
    pub(crate) path: &'a str,
}

/// `Read configuration file "` — more specific than the mention below, and
/// checked first so a read is not also a mention.
#[cfg(test)]
const MARKER_CONFIG_READ: &str = "Read configuration file \"";
/// `Configuration file "` — tor's "not present, using reasonable defaults".
#[cfg(test)]
const MARKER_CONFIG_MENTION: &str = "Configuration file \"";
/// Lowercase, after the two arms above. `Unable to open configuration file`.
#[cfg(test)]
const MARKER_CONFIG_OPEN: &str = "configuration file \"";
/// `Parsing GEOIP IPv4 file %s.` / `Parsing GEOIP IPv6 file %s.`
#[cfg(test)]
const MARKER_GEOIP_PARSE: &str = "Parsing GEOIP ";
/// The path sits after this, inside a parse line.
#[cfg(test)]
const MARKER_GEOIP_FILE: &str = " file ";
/// `Failed to open GEOIP file %s.`
#[cfg(test)]
const MARKER_GEOIP_OPEN: &str = "Failed to open GEOIP file ";

/// Every configuration or GeoIP file a tor notice log names, in order.
#[cfg(test)]
pub(crate) fn files_named_in_tor_log(log: &str) -> Vec<LogMention<'_>> {
    log.lines().filter_map(mention_in_line).collect()
}

#[cfg(test)]
fn mention_in_line(line: &str) -> Option<LogMention<'_>> {
    // Specificity is the order. A read contains neither of the later
    // configuration markers as a case-sensitive substring of its own marker,
    // and the parse marker is not a prefix of the open marker.
    if let Some(rest) = after(line, MARKER_CONFIG_READ) {
        return Some(quoted_path(LoggedFile::ConfigRead, rest));
    }
    if let Some(rest) = after(line, MARKER_CONFIG_MENTION) {
        return Some(quoted_path(LoggedFile::ConfigMention, rest));
    }
    if let Some(rest) = after(line, MARKER_CONFIG_OPEN) {
        return Some(quoted_path(LoggedFile::ConfigMention, rest));
    }
    if let Some(rest) = after(line, MARKER_GEOIP_PARSE) {
        let path = rest
            .split_once(MARKER_GEOIP_FILE)
            .map(|(_, path)| strip_sentence_period(path))
            .unwrap_or(rest);
        return Some(LogMention {
            kind: LoggedFile::GeoipParse,
            path,
        });
    }
    if let Some(rest) = after(line, MARKER_GEOIP_OPEN) {
        return Some(LogMention {
            kind: LoggedFile::GeoipOpen,
            path: strip_sentence_period(rest),
        });
    }
    None
}

#[cfg(test)]
fn after<'a>(line: &'a str, marker: &str) -> Option<&'a str> {
    line.split_once(marker).map(|(_, rest)| rest)
}

#[cfg(test)]
fn quoted_path<'a>(kind: LoggedFile, rest: &'a str) -> LogMention<'a> {
    let path = rest.split_once('"').map(|(path, _)| path).unwrap_or(rest);
    LogMention { kind, path }
}

/// Tor ends the unquoted GeoIP sentences with one `.`. A path that itself
/// ends in `.` keeps that dot: only the sentence's own is removed.
#[cfg(test)]
fn strip_sentence_period(text: &str) -> &str {
    text.strip_suffix('.').unwrap_or(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn launch_arguments(disable_network: bool) -> Vec<String> {
        let dir = tempfile::tempdir().expect("fixture directory");
        let managed = managed_fixture(dir.path(), disable_network);
        let environment =
            LaunchEnvironment::resolve(&managed.tor_binary).expect("launch environment");
        let pair = ControlPair::new().expect("control pair");
        managed_tor_command(&managed, pair.tor_end(), &environment)
            .as_std()
            .get_args()
            .map(|arg| {
                let Some(text) = arg.to_str() else {
                    panic!("a launch argument is not utf-8: {arg:?}");
                };
                text.to_owned()
            })
            .collect()
    }

    fn managed_fixture(dir: &Path, disable_network: bool) -> ManagedTor {
        ManagedTor {
            tor_binary: VerifiedTorBinary::unchecked_for_test(dir.join("tor")),
            data_dir: dir.join("data"),
            socks_port: super::super::actor::SocksPort::Auto,
            disable_network,
            exit_observer: None,
            leak: None,
        }
    }

    /// The `--Name` of each name/value pair on the launch.
    fn launch_option_names(disable_network: bool) -> Vec<String> {
        let args = launch_arguments(disable_network);
        assert!(
            args.len().is_multiple_of(2),
            "an argument is not part of a --Name value pair: {args:?}"
        );
        args.chunks(2)
            .map(|pair| {
                assert!(
                    pair[0].starts_with("--") && !pair[0].contains('='),
                    "an option is not the typed --Name form: {}",
                    pair[0]
                );
                pair[0].clone()
            })
            .collect()
    }

    /// The launch surface is a closed list. A new option fails here first.
    /// The names are written out, not taken from [`LAUNCH_OWNED_FILES`].
    #[test]
    fn the_managed_launch_surface_is_the_typed_options() {
        let base = [
            "--DataDirectory",
            "--__OwningControllerFD",
            "--AvoidDiskWrites",
            "--SocksPort",
            "--Log",
            "--torrc-file",
            "--defaults-torrc",
            "--GeoIPFile",
            "--GeoIPv6File",
        ];
        assert_eq!(launch_option_names(false), base);
        let mut offline = base.to_vec();
        offline.push("--DisableNetwork");
        assert_eq!(launch_option_names(true), offline);
    }

    /// Each file tor would otherwise find from its compiled-in defaults is
    /// named, and all four name the one blank file. The list is an oracle,
    /// independent of [`LAUNCH_OWNED_FILES`].
    #[test]
    fn the_launch_names_its_own_blank_file() {
        let dir = tempfile::tempdir().expect("fixture directory");
        let managed = managed_fixture(dir.path(), false);
        let environment =
            LaunchEnvironment::resolve(&managed.tor_binary).expect("launch environment");
        let pair = ControlPair::new().expect("control pair");
        let cmd = managed_tor_command(&managed, pair.tor_end(), &environment);
        let args: Vec<&OsStr> = cmd.as_std().get_args().collect();
        let blank = blank_config_path(&managed.data_dir);
        for option in [
            "--torrc-file",
            "--defaults-torrc",
            "--GeoIPFile",
            "--GeoIPv6File",
        ] {
            let at = args
                .iter()
                .position(|arg| *arg == option)
                .unwrap_or_else(|| panic!("{option} is not on the launch"));
            assert_eq!(
                args.get(at + 1).copied().map(Path::new),
                Some(blank.as_path()),
                "{option} names the blank file"
            );
        }
    }

    /// The control connection is tor's inherited end, named by number, and the
    /// value of each fixed option is what §4.7 rules.
    #[test]
    fn the_launch_hands_tor_its_end_and_avoids_disk_writes() {
        let dir = tempfile::tempdir().expect("fixture directory");
        let managed = managed_fixture(dir.path(), false);
        let environment =
            LaunchEnvironment::resolve(&managed.tor_binary).expect("launch environment");
        let pair = ControlPair::new().expect("control pair");
        let cmd = managed_tor_command(&managed, pair.tor_end(), &environment);
        let args: Vec<&OsStr> = cmd.as_std().get_args().collect();
        let value = |option: &str| {
            let at = args
                .iter()
                .position(|arg| *arg == option)
                .unwrap_or_else(|| panic!("{option} is not on the launch"));
            args.get(at + 1).copied()
        };
        let number = pair.tor_end().to_string();
        assert_eq!(
            value("--__OwningControllerFD"),
            Some(OsStr::new(&number)),
            "tor is told its own end"
        );
        assert_eq!(value("--AvoidDiskWrites"), Some(OsStr::new("1")));
    }

    /// The spawn hands tor its end, and closes the parent's copy: a read on our end
    /// sees EOF once the child exits. If the parent kept its copy, the read would wait
    /// forever, which is the property the death path rests on.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_parent_closes_its_copy_of_tors_end() {
        use tokio::io::AsyncReadExt;
        let pair = ControlPair::new().expect("control pair");
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "exit 0"]);
        inherit_in_the_child_only(&mut cmd, pair.tor_end());
        let (mut child, mut read, _write) = pair.spawn(&mut cmd).expect("spawn");
        child.wait().await.expect("the child exits");
        let mut byte = [0u8; 1];
        let eof = tokio::time::timeout(std::time::Duration::from_secs(5), read.read(&mut byte))
            .await
            .expect("EOF, not a wait on our own copy")
            .expect("read");
        assert_eq!(eof, 0);
    }

    /// Tor's end reaches the child it is meant for, and no other. The first child is
    /// handed it and finds it open; a second spawned while the pair exists, which is
    /// not handed it, finds it closed: close-on-exec is cleared in the first child
    /// only.
    #[cfg(unix)]
    #[tokio::test]
    async fn only_the_child_handed_tors_end_holds_it() {
        let pair = ControlPair::new().expect("control pair");
        let number = pair.tor_end();
        let probe = format!("test -e /dev/fd/{number}");

        let mut other = std::process::Command::new("/bin/sh");
        other.args(["-c", &probe]);
        let other_status = crate::spawn_lock::status(&mut other).expect("the other spawn runs");
        assert!(
            !other_status.success(),
            "a spawn not handed tor's end does not hold it"
        );

        let mut handed = Command::new("/bin/sh");
        handed.args(["-c", &probe]);
        inherit_in_the_child_only(&mut handed, number);
        let (mut child, _read, _write) = pair.spawn(&mut handed).expect("spawn");
        assert!(
            child.wait().await.expect("exits").success(),
            "the child handed tor's end holds it"
        );
    }

    /// The variable list on the built command.
    ///
    /// `Command::get_envs` returns only variables this builder set. It cannot
    /// see `env_clear`, so a launch that copied the parent's `SystemRoot`, or
    /// that dropped the clear, still passes here when the parent happens to
    /// hold the same value. The spawn that reads the child's own environment
    /// is [`managed_tor_child_inherits_no_environment`].
    #[test]
    fn the_managed_launch_environment_is_exact() {
        let dir = tempfile::tempdir().expect("fixture directory");
        let managed = managed_fixture(dir.path(), false);
        let environment =
            LaunchEnvironment::resolve(&managed.tor_binary).expect("launch environment");
        let pair = ControlPair::new().expect("control pair");
        let cmd = managed_tor_command(&managed, pair.tor_end(), &environment);
        let envs: Vec<(&OsStr, Option<&OsStr>)> = cmd.as_std().get_envs().collect();
        #[cfg(any(target_os = "linux", windows))]
        let expected = {
            let (name, value) = environment.variable();
            vec![(OsStr::new(name), Some(value))]
        };
        #[cfg(not(any(target_os = "linux", windows)))]
        let expected: Vec<(&OsStr, Option<&OsStr>)> = Vec::new();
        assert_eq!(envs, expected);
        #[cfg(windows)]
        {
            let root = system_windows_directory().expect("GetSystemWindowsDirectoryW");
            assert_eq!(
                envs.first().and_then(|(_, value)| *value),
                Some(root.as_os_str()),
                "SystemRoot is the system call's value"
            );
        }
    }

    /// Set in the re-executed copy of this test binary.
    const ENV_TEST_DIR: &str = "SHEKYL_TEST_LAUNCHER_ENV_DIR";
    const ENV_SENTINEL_NAME: &str = "SHEKYL_TEST_SENTINEL";
    const ENV_SENTINEL_VALUE: &str = "must-not-reach-tor";
    const PRELOAD_NAME: &str = "LD_PRELOAD";
    const PRELOAD_VALUE: &str = "/nonexistent/shekyl-test-preload.so";

    /// What `/bin/sh` sets for itself on the way to `exec`. Not inherited,
    /// and not filtered on Windows: a leak of one of these names there is real.
    #[cfg(unix)]
    const SHELL_OWN_VARIABLES: [&str; 3] = ["PWD", "SHLVL", "_"];

    /// A directory that is not the Windows directory. The re-executed test
    /// process sets it as its own `SystemRoot` before the launch; the managed
    /// child must not keep it.
    #[cfg(windows)]
    const POISON_SYSTEM_ROOT: &str = r"C:\shekyl-not-a-windows-directory";

    /// Tells the re-executed process to poison its `SystemRoot` once the control
    /// pair exists. It cannot start with the poison: Winsock loads its providers
    /// from the Windows directory, so the pair's loopback bind fails under a wrong
    /// `SystemRoot` (`WSAEPROVIDERFAILEDINIT`, 10106; seen on Windows, 2026-10-16).
    #[cfg(windows)]
    const POISON_AFTER_PAIR: &str = "SHEKYL_TEST_POISON_SYSTEM_ROOT";

    #[cfg(windows)]
    const SHIM_FILE_NAME: &str = "tor.exe";
    #[cfg(not(windows))]
    const SHIM_FILE_NAME: &str = "tor";

    /// The managed tor inherits nothing from its parent's environment.
    ///
    /// `Command` cannot be asked whether it was cleared, so this spawns. The
    /// parent has to really carry the variables, or their absence in the child
    /// proves nothing. The test re-executes itself rather than `set_var` in a
    /// process shared with every other test: the outer half stages a shim and
    /// reads what the shim wrote, the inner half is the process whose
    /// environment is dirty.
    ///
    /// On Windows the inner half poisons its own `SystemRoot` once the control
    /// pair exists (Winsock needs the real one to make it). The shim is a small
    /// Rust program, because `CreateProcess` will not run a `.cmd` the way
    /// Unix runs a shell script. The dump's `SystemRoot` has to be the system
    /// call's value.
    #[tokio::test]
    async fn managed_tor_child_inherits_no_environment() {
        if let Some(dir) = std::env::var_os(ENV_TEST_DIR) {
            run_inner_half(&dir).await;
            return;
        }
        run_outer_half();
    }

    async fn run_inner_half(dir: &OsStr) {
        assert!(
            std::env::var_os(ENV_SENTINEL_NAME).is_some(),
            "the inner half's environment is not dirty"
        );
        assert!(
            std::env::var_os(PRELOAD_NAME).is_some(),
            "the inner half's environment is not dirty"
        );
        let dir = PathBuf::from(dir);
        let managed = ManagedTor {
            tor_binary: VerifiedTorBinary::unchecked_for_test(dir.join(SHIM_FILE_NAME)),
            data_dir: dir.join("data"),
            socks_port: super::super::actor::SocksPort::Auto,
            disable_network: true,
            exit_observer: None,
            leak: None,
        };
        let pair = ControlPair::new().expect("control pair");
        // From here on this process's own `SystemRoot` is wrong, through the
        // resolve and the spawn: the child's must still be the system call's.
        // A single-test process, so the `set_var` races nothing.
        #[cfg(windows)]
        {
            assert!(
                std::env::var_os(POISON_AFTER_PAIR).is_some(),
                "the outer half asks for the poison"
            );
            std::env::set_var(SYSTEM_ROOT_VARIABLE, POISON_SYSTEM_ROOT);
            assert_eq!(
                std::env::var(SYSTEM_ROOT_VARIABLE).as_deref(),
                Ok(POISON_SYSTEM_ROOT),
                "the inner half holds the poisoned SystemRoot"
            );
        }
        let environment =
            LaunchEnvironment::resolve(&managed.tor_binary).expect("launch environment");
        let mut cmd = managed_tor_command(&managed, pair.tor_end(), &environment);
        let (mut child, _read, _write) = pair.spawn(&mut cmd).expect("spawn the shim");
        let status = child.wait().await.expect("wait for the shim");
        assert!(status.success(), "shim exited {status}");
    }

    fn run_outer_half() {
        let dir = tempfile::tempdir().expect("fixture directory");
        let dir_path = dir
            .path()
            .canonicalize()
            .expect("canonical fixture directory");
        std::fs::create_dir(dir_path.join("data")).expect("data directory");
        stage_environment_shim(&dir_path);

        let test_name = concat!(
            module_path!(),
            "::managed_tor_child_inherits_no_environment"
        )
        .split_once("::")
        .expect("module path has a crate segment")
        .1;
        let mut reexec =
            std::process::Command::new(std::env::current_exe().expect("test executable"));
        reexec
            .args([test_name, "--exact", "--nocapture", "--test-threads=1"])
            .env(ENV_TEST_DIR, &dir_path)
            .env(PRELOAD_NAME, PRELOAD_VALUE)
            .env(ENV_SENTINEL_NAME, ENV_SENTINEL_VALUE);
        #[cfg(windows)]
        reexec.env(POISON_AFTER_PAIR, "1");
        let output = crate::spawn_lock::output(&mut reexec).expect("re-execute the test binary");
        assert!(
            output.status.success(),
            "inner half failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        // The inner half must have run the test, not matched nothing and exited 0.
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "inner half ran no test:\n{}",
            String::from_utf8_lossy(&output.stdout)
        );

        let environ = std::fs::read_to_string(dir_path.join("data").join("environ"))
            .expect("the shim wrote its environment");
        // Names and values apart, and **only names ever reach a failure message**:
        // when this test fails it is because the parent's environment leaked, and
        // a developer's or a runner's environment holds credentials.
        let vars = dumped_variables(&environ);
        let names: Vec<&str> = vars.iter().map(|(name, _)| *name).collect();
        assert!(
            !names.contains(&PRELOAD_NAME),
            "{PRELOAD_NAME} reached the child (variables present: {names:?})"
        );
        assert!(
            !names.contains(&ENV_SENTINEL_NAME),
            "an inherited variable reached the child (variables present: {names:?})"
        );
        assert_child_environment(&vars, &names, &dir_path);
    }

    fn dumped_variables(environ: &str) -> Vec<(&str, &str)> {
        let vars = environ
            .lines()
            .filter_map(|line| line.split_once('='))
            .collect::<Vec<_>>();
        #[cfg(unix)]
        let vars = vars
            .into_iter()
            .filter(|(name, _)| !SHELL_OWN_VARIABLES.contains(name))
            .collect();
        vars
    }

    #[cfg(target_os = "linux")]
    fn assert_child_environment(vars: &[(&str, &str)], names: &[&str], dir: &Path) {
        assert_eq!(names, ["LD_LIBRARY_PATH"], "the child's whole environment");
        assert_eq!(Path::new(vars[0].1), dir, "the loader path");
    }

    #[cfg(windows)]
    fn assert_child_environment(vars: &[(&str, &str)], names: &[&str], _dir: &Path) {
        let root = system_windows_directory().expect("GetSystemWindowsDirectoryW");
        let root = root.to_str().expect("the system directory is unicode");
        assert_eq!(
            names,
            [SYSTEM_ROOT_VARIABLE],
            "the child's whole environment"
        );
        assert_ne!(
            vars[0].1, POISON_SYSTEM_ROOT,
            "the child kept the poisoned SystemRoot"
        );
        assert_eq!(vars[0].1, root, "SystemRoot is the system call's value");
    }

    #[cfg(not(any(target_os = "linux", windows)))]
    fn assert_child_environment(_vars: &[(&str, &str)], names: &[&str], _dir: &Path) {
        assert!(names.is_empty(), "the child's whole environment: {names:?}");
    }

    #[cfg(unix)]
    fn stage_environment_shim(dir: &Path) {
        use std::os::unix::fs::PermissionsExt;
        /// The shim must be executable. The mode is the shim's, not the blank file's.
        const SHIM_EXECUTABLE: u32 = 0o755;
        // `$2` is `--DataDirectory`'s value: the arguments are
        // `--DataDirectory <path> ...`, and `$0` is the script.
        const UNIX_ENV_DUMP_SHIM: &str = "#!/bin/sh\nexec /usr/bin/env > \"$2/environ\"\n";
        let shim = dir.join(SHIM_FILE_NAME);
        std::fs::write(&shim, UNIX_ENV_DUMP_SHIM).expect("write the shim");
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(SHIM_EXECUTABLE))
            .expect("mark the shim executable");
    }

    /// Compiled in the outer half, where `rustc` is on `PATH` (cargo, CI).
    /// The test binary cannot be the shim: libtest owns its `main`.
    #[cfg(windows)]
    fn stage_environment_shim(dir: &Path) {
        const ENV_DUMP_SHIM: &str = r#"
fn main() {
    let mut args = std::env::args_os().skip(1);
    let _option = args.next();
    let data = args.next().expect("data directory");
    let mut out = std::path::PathBuf::from(data);
    out.push("environ");
    let mut body = String::new();
    for (name, value) in std::env::vars() {
        body.push_str(&name);
        body.push('=');
        body.push_str(&value);
        body.push('\n');
    }
    std::fs::write(out, body).expect("environ");
}
"#;
        let source = dir.join("env_dump_shim.rs");
        std::fs::write(&source, ENV_DUMP_SHIM).expect("write the shim source");
        let mut rustc = std::process::Command::new("rustc");
        rustc
            .args(["--edition", "2021", "-o"])
            .arg(dir.join(SHIM_FILE_NAME))
            .arg(&source);
        let compiled = crate::spawn_lock::output(&mut rustc)
            .expect("rustc is on PATH for the environment shim");
        assert!(
            compiled.status.success(),
            "environment shim failed to compile:\n{}",
            String::from_utf8_lossy(&compiled.stderr)
        );
    }

    #[cfg(not(any(unix, windows)))]
    fn stage_environment_shim(_dir: &Path) {
        panic!("the environment shim has no form on this target");
    }

    /// The permission bits, without the file-type bits `mode()` also returns.
    #[cfg(unix)]
    const PERMISSION_BITS: u32 = 0o777;

    #[cfg(unix)]
    async fn prepared_data_dir() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("fixture directory");
        let data = dir.path().join("data");
        prepare_data_directory(&data).await.expect("data directory");
        (dir, data)
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_blank_file_is_created_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, data) = prepared_data_dir().await;
        install_blank_config(&data)
            .await
            .expect("create the blank file");
        let blank = blank_config_path(&data);
        assert_eq!(std::fs::read(&blank).expect("read the blank file"), b"");
        let mode = std::fs::metadata(&blank)
            .expect("metadata")
            .permissions()
            .mode()
            & PERMISSION_BITS;
        assert_eq!(mode, BLANK_FILE_OWNER_ONLY);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_next_launch_truncates_our_blank_file() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, data) = prepared_data_dir().await;
        let blank = blank_config_path(&data);
        std::fs::write(&blank, b"previous").expect("a previous blank file");
        install_blank_config(&data)
            .await
            .expect("truncate our file");
        assert_eq!(std::fs::read(&blank).expect("read the blank file"), b"");
        let mode = std::fs::metadata(&blank)
            .expect("metadata")
            .permissions()
            .mode()
            & PERMISSION_BITS;
        assert_eq!(mode, BLANK_FILE_OWNER_ONLY);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_symlink_is_not_followed() {
        let (dir, data) = prepared_data_dir().await;
        let original = dir.path().join("original");
        std::fs::write(&original, b"kept").expect("symlink target");
        std::os::unix::fs::symlink(&original, blank_config_path(&data)).expect("symlink");
        let error = install_blank_config(&data)
            .await
            .expect_err("a symlink is refused");
        assert!(matches!(error, ControlError::Spawn));
        assert_eq!(std::fs::read(&original).expect("target"), b"kept");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_hard_link_is_not_truncated() {
        let (dir, data) = prepared_data_dir().await;
        let original = dir.path().join("original");
        std::fs::write(&original, b"kept").expect("hard-link target");
        std::fs::hard_link(&original, blank_config_path(&data)).expect("hard link");
        let error = install_blank_config(&data)
            .await
            .expect_err("a hard link is refused");
        assert!(matches!(error, ControlError::Spawn));
        assert_eq!(std::fs::read(&original).expect("original"), b"kept");
        assert_eq!(
            std::fs::read(blank_config_path(&data)).expect("the other name"),
            b"kept"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_data_directory_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, data) = prepared_data_dir().await;
        let mode = std::fs::symlink_metadata(&data)
            .expect("metadata")
            .permissions()
            .mode()
            & PERMISSION_BITS;
        assert_eq!(mode, DIRECTORY_OWNER_ONLY);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_symlink_data_directory_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("fixture directory");
        let real = dir.path().join("real");
        /// The mode the target had before the refusal. It must still have it.
        const ORIGINAL_DIRECTORY_MODE: u32 = 0o755;
        std::fs::create_dir(&real).expect("real directory");
        std::fs::set_permissions(
            &real,
            std::fs::Permissions::from_mode(ORIGINAL_DIRECTORY_MODE),
        )
        .expect("mode of the real directory");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink directory");
        let error = prepare_data_directory(&link)
            .await
            .expect_err("a symlink directory is refused");
        assert!(matches!(error, ControlError::Spawn));
        let mode = std::fs::symlink_metadata(&real)
            .expect("metadata")
            .permissions()
            .mode()
            & PERMISSION_BITS;
        assert_eq!(
            mode, ORIGINAL_DIRECTORY_MODE,
            "the symlink target keeps its mode"
        );
    }

    /// Paths the fixtures name. `DOTTED` itself ends in `.`.
    const OURS: &str = "/data/blank";
    const DOTTED: &str = "/data/blank.";
    const FOREIGN_TORRC: &str = "/var/tmp/dist/tor/etc/tor/torrc";
    const FOREIGN_GEOIP: &str = "/var/tmp/dist/tor/share/tor/geoip";

    #[test]
    fn the_log_classifier_names_each_file_tor_reports() {
        let log = format!(
            "\
Oct 15 00:00:00.000 [notice] Read configuration file \"{OURS}\".
Oct 15 00:00:00.001 [warn] Configuration file \"{OURS}\" not present, using reasonable defaults.
Oct 15 00:00:00.002 [warn] Unable to open configuration file \"{FOREIGN_TORRC}\".
Oct 15 00:00:00.003 [notice] Read configuration file \"{DOTTED}\".
Oct 15 00:00:00.004 [notice] Parsing GEOIP IPv4 file {OURS}.
Oct 15 00:00:00.005 [notice] Parsing GEOIP IPv6 file {DOTTED}.
Oct 15 00:00:00.006 [warn] Failed to open GEOIP file {FOREIGN_GEOIP}.
Oct 15 00:00:00.007 [notice] Bootstrapped 0%: Starting
"
        );
        // A read is not also counted as a mention: one line, one mention.
        let mentions = files_named_in_tor_log(&log);
        assert_eq!(
            mentions,
            vec![
                LogMention {
                    kind: LoggedFile::ConfigRead,
                    path: OURS,
                },
                LogMention {
                    kind: LoggedFile::ConfigMention,
                    path: OURS,
                },
                LogMention {
                    kind: LoggedFile::ConfigMention,
                    path: FOREIGN_TORRC,
                },
                LogMention {
                    kind: LoggedFile::ConfigRead,
                    path: DOTTED,
                },
                LogMention {
                    kind: LoggedFile::GeoipParse,
                    path: OURS,
                },
                LogMention {
                    kind: LoggedFile::GeoipParse,
                    path: DOTTED,
                },
                LogMention {
                    kind: LoggedFile::GeoipOpen,
                    path: FOREIGN_GEOIP,
                },
            ]
        );
    }
}
