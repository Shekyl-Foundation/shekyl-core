// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The managed tor's command line, environment, and the one file it may read.
//!
//! [`managed_tor_command`] is the whole launch a user gets. It is infallible:
//! the only fallible step is [`LaunchEnvironment::resolve`], and on Windows
//! that step is the system-directory lookup. The environment is a closed set
//! (`TOR_BUNDLE_DISTRIBUTION.md` TB-7 part 2, as amended 2026-10-16). The blank file and the data
//! directory are prepared before the command is spawned
//! ([`prepare_data_directory`], [`install_blank_config`]).
//!
//! The option list is closed. Non-anonymous onion serving is one of the things
//! it holds shut; the other half is [`super::onion::OnionFlags`].

use std::ffi::OsStr;
#[cfg(windows)]
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use tokio::process::Command;

#[cfg(windows)]
use super::actor::SystemDirectoryError;
use super::actor::{ControlError, ManagedTor};

/// Where OpenSSL reads its configuration. Tor initialises OpenSSL without
/// `OPENSSL_INIT_NO_LOAD_CONFIG` (`crypto_openssl_mgt.c` at `tor-0.4.9.13` and
/// `tor-0.4.9.14`), so with this unset OpenSSL reads `openssl.cnf` under its
/// compiled-in `OPENSSLDIR`. For every Expert Bundle that is
/// `/var/tmp/dist/openssl/ssl`, a path any local account can create, and a
/// configuration there can name a provider or engine module that OpenSSL
/// loads into tor. The launch names the blank file instead: an empty
/// configuration loads no module, and the default provider is built in.
const OPENSSL_CONF_VARIABLE: &str = "OPENSSL_CONF";

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

/// The managed tor's whole environment, already resolved: a closed set, each
/// value from a trusted source and none from the parent's environment
/// (`TOR_BUNDLE_DISTRIBUTION.md` TB-7 part 2, as amended 2026-10-16).
///
/// | Variable | Target | Source |
/// | --- | --- | --- |
/// | `OPENSSL_CONF` | all | the launcher's blank file in the data directory |
/// | `LD_LIBRARY_PATH` | Linux | the verified witness's directory |
/// | `SystemRoot` | Windows | `GetSystemWindowsDirectoryW` |
///
/// macOS sets `OPENSSL_CONF` only; `DYLD_*` stays unset. `OPENSSL_MODULES` and
/// `OPENSSL_ENGINES` are not set: with no configuration naming a module,
/// nothing reads them, and `HardwareAccel` stays off. The command applies
/// [`Self::variables`] and nothing else, so the environment a test reads off
/// the command is this value.
pub(crate) struct LaunchEnvironment {
    openssl_conf: PathBuf,
    /// Linux: the loader searches the directory the pin gate checked.
    #[cfg(target_os = "linux")]
    loader_path: PathBuf,
    /// Windows: `SystemRoot` from `GetSystemWindowsDirectoryW`.
    #[cfg(windows)]
    system_root: OsString,
}

impl LaunchEnvironment {
    /// Resolve the closed set for `managed`, or fail before spawn.
    ///
    /// The witness is read on Linux only, where the loader path is its
    /// directory. On Windows `SystemRoot` comes from the system call.
    #[cfg_attr(
        not(windows),
        expect(
            clippy::unnecessary_wraps,
            reason = "only the Windows system-directory lookup can fail"
        )
    )]
    pub(crate) fn resolve(managed: &ManagedTor) -> Result<Self, ControlError> {
        Ok(Self {
            openssl_conf: blank_config_path(&managed.data_dir),
            #[cfg(target_os = "linux")]
            loader_path: managed.tor_binary.library_dir().to_path_buf(),
            #[cfg(windows)]
            system_root: system_windows_directory().map_err(ControlError::SystemDirectory)?,
        })
    }

    /// Every variable this target sets after `env_clear`, by name.
    pub(crate) fn variables(&self) -> Vec<(&'static str, &OsStr)> {
        vec![
            (OPENSSL_CONF_VARIABLE, self.openssl_conf.as_os_str()),
            #[cfg(target_os = "linux")]
            (LOADER_PATH_VARIABLE, self.loader_path.as_os_str()),
            #[cfg(windows)]
            (SYSTEM_ROOT_VARIABLE, self.system_root.as_os_str()),
        ]
    }

    fn apply(&self, cmd: &mut Command) {
        for (name, value) in self.variables() {
            cmd.env(name, value);
        }
    }
}

/// The command line and environment the managed tor is launched with.
///
/// Infallible. [`LaunchEnvironment::resolve`] has already produced `environment`.
pub(crate) fn managed_tor_command(
    managed: &ManagedTor,
    port_file: &Path,
    environment: &LaunchEnvironment,
) -> Command {
    // The witness type guarantees this path passed the hash-pin gate and is
    // canonical: the file hashed is the file named.
    let mut cmd = Command::new(managed.tor_binary.as_path());
    // No inherited environment, then the closed set (`TOR_BUNDLE_DISTRIBUTION.md`
    // TB-7 part 2, as amended 2026-10-16). `LD_PRELOAD`, `LD_LIBRARY_PATH`,
    // `DYLD_INSERT_LIBRARIES` or `OPENSSL_CONF` from a shell, a unit file or a
    // profile would load code into the process whose files were just verified.
    // `Command::get_envs` does not show this clear; the re-exec test reads the
    // child's own environment.
    cmd.env_clear();
    environment.apply(&mut cmd);
    cmd.arg("--DataDirectory")
        .arg(&managed.data_dir)
        .arg("--ControlPort")
        .arg("auto")
        .arg("--ControlPortWriteToFile")
        .arg(port_file)
        .arg("--CookieAuthentication")
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
    cmd
}

/// The zero-length file the managed tor is given as its torrc, its defaults
/// torrc and both GeoIP files, and OpenSSL as its configuration.
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
    use crate::binary::VerifiedTorBinary;

    fn launch_arguments(disable_network: bool) -> Vec<String> {
        let dir = tempfile::tempdir().expect("fixture directory");
        let managed = managed_fixture(dir.path(), disable_network);
        let environment = LaunchEnvironment::resolve(&managed).expect("launch environment");
        managed_tor_command(&managed, &dir.path().join("control_port"), &environment)
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
            "--ControlPort",
            "--ControlPortWriteToFile",
            "--CookieAuthentication",
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
        let environment = LaunchEnvironment::resolve(&managed).expect("launch environment");
        let cmd = managed_tor_command(&managed, &dir.path().join("control_port"), &environment);
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

    /// The variable set on the built command, against an oracle written out
    /// here rather than read from [`LaunchEnvironment::variables`].
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
        let environment = LaunchEnvironment::resolve(&managed).expect("launch environment");
        let cmd = managed_tor_command(&managed, &dir.path().join("control_port"), &environment);
        let mut envs: Vec<(&OsStr, Option<&OsStr>)> = cmd.as_std().get_envs().collect();
        envs.sort();
        let blank = blank_config_path(&managed.data_dir);
        #[cfg(target_os = "linux")]
        let mut expected = vec![
            (
                OsStr::new("LD_LIBRARY_PATH"),
                Some(managed.tor_binary.library_dir().as_os_str()),
            ),
            (OsStr::new("OPENSSL_CONF"), Some(blank.as_os_str())),
        ];
        #[cfg(windows)]
        let root = system_windows_directory().expect("GetSystemWindowsDirectoryW");
        #[cfg(windows)]
        let mut expected = vec![
            (OsStr::new("OPENSSL_CONF"), Some(blank.as_os_str())),
            (OsStr::new("SystemRoot"), Some(root.as_os_str())),
        ];
        #[cfg(not(any(target_os = "linux", windows)))]
        let mut expected = vec![(OsStr::new("OPENSSL_CONF"), Some(blank.as_os_str()))];
        expected.sort();
        assert_eq!(envs, expected);
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
    /// process is given it as `SystemRoot`; the managed child must not keep it.
    #[cfg(windows)]
    const POISON_SYSTEM_ROOT: &str = r"C:\shekyl-not-a-windows-directory";

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
    /// On Windows the outer half poisons `SystemRoot`. The shim is a small
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
        #[cfg(windows)]
        assert_eq!(
            std::env::var(SYSTEM_ROOT_VARIABLE).as_deref(),
            Ok(POISON_SYSTEM_ROOT),
            "the inner half must be the process that holds the poisoned SystemRoot"
        );
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
        };
        let environment = LaunchEnvironment::resolve(&managed).expect("launch environment");
        let status = managed_tor_command(&managed, &dir.join("control_port"), &environment)
            .spawn()
            .expect("spawn the shim")
            .wait()
            .await
            .expect("wait for the shim");
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
        reexec.env(SYSTEM_ROOT_VARIABLE, POISON_SYSTEM_ROOT);
        let output = reexec.output().expect("re-execute the test binary");
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

    /// The value the dump holds for `name`. Only reached after the names
    /// matched, so a missing name here is a test defect, not a leak.
    fn dumped<'a>(vars: &[(&str, &'a str)], name: &str) -> &'a str {
        vars.iter()
            .find(|(n, _)| *n == name)
            .map(|(_, value)| *value)
            .unwrap_or_else(|| panic!("{name} is not in the child's environment"))
    }

    /// `OPENSSL_CONF` names the launcher's blank file, the same path whichever
    /// target: the data directory is the shim's `data`.
    fn assert_openssl_conf(vars: &[(&str, &str)], dir: &Path) {
        assert_eq!(
            Path::new(dumped(vars, "OPENSSL_CONF")),
            blank_config_path(&dir.join("data")),
            "OPENSSL_CONF is the launcher's blank file"
        );
    }

    #[cfg(target_os = "linux")]
    fn assert_child_environment(vars: &[(&str, &str)], names: &[&str], dir: &Path) {
        let mut sorted = names.to_vec();
        sorted.sort_unstable();
        assert_eq!(
            sorted,
            ["LD_LIBRARY_PATH", "OPENSSL_CONF"],
            "the child's whole environment"
        );
        assert_eq!(
            Path::new(dumped(vars, "LD_LIBRARY_PATH")),
            dir,
            "the loader path"
        );
        assert_openssl_conf(vars, dir);
    }

    #[cfg(windows)]
    fn assert_child_environment(vars: &[(&str, &str)], names: &[&str], dir: &Path) {
        let root = system_windows_directory().expect("GetSystemWindowsDirectoryW");
        let root = root.to_str().expect("the system directory is unicode");
        let mut sorted = names.to_vec();
        sorted.sort_unstable();
        assert_eq!(
            sorted,
            ["OPENSSL_CONF", SYSTEM_ROOT_VARIABLE],
            "the child's whole environment"
        );
        let system_root = dumped(vars, SYSTEM_ROOT_VARIABLE);
        assert_ne!(
            system_root, POISON_SYSTEM_ROOT,
            "the child kept the poisoned SystemRoot"
        );
        assert_eq!(system_root, root, "SystemRoot is the system call's value");
        assert_openssl_conf(vars, dir);
    }

    #[cfg(not(any(target_os = "linux", windows)))]
    fn assert_child_environment(vars: &[(&str, &str)], names: &[&str], dir: &Path) {
        assert_eq!(names, ["OPENSSL_CONF"], "the child's whole environment");
        assert_openssl_conf(vars, dir);
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
        let compiled = std::process::Command::new("rustc")
            .args(["--edition", "2021", "-o"])
            .arg(dir.join(SHIM_FILE_NAME))
            .arg(&source)
            .output()
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

    /// A configuration that makes OpenSSL load a provider module that does not
    /// exist, with diagnostics on, so a failed load fails OpenSSL's start.
    /// Without `config_diagnostics` OpenSSL ignores configuration errors at
    /// start, and a merely malformed file proves nothing.
    fn provider_loading_config(module: &Path) -> String {
        format!(
            "config_diagnostics = 1\nopenssl_conf = openssl_init\n[openssl_init]\n\
             providers = provider_sect\n[provider_sect]\nprobe = probe_sect\n\
             [probe_sect]\nmodule = {}\nactivate = 1\n",
            module.display()
        )
    }

    /// How long a launch gets to either write its control-port file or exit.
    const LAUNCH_VERDICT_WINDOW: std::time::Duration = std::time::Duration::from_secs(30);

    /// `true` when the launched tor wrote its control-port file (it came up),
    /// `false` when it exited first. The child is reaped either way, before
    /// the caller's temporary directory can drop.
    async fn launch_comes_up(mut cmd: Command, port_file: &Path) -> bool {
        let mut child = cmd.spawn().expect("spawn the managed tor");
        let came_up = tokio::select! {
            _ = child.wait() => false,
            () = async {
                while !port_file.exists() {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            } => true,
            () = tokio::time::sleep(LAUNCH_VERDICT_WINDOW) => {
                panic!("the managed tor neither came up nor exited within {LAUNCH_VERDICT_WINDOW:?}")
            }
        };
        child.start_kill().ok();
        child.wait().await.ok();
        came_up
    }

    /// OpenSSL inside the managed tor reads the file `OPENSSL_CONF` names, and
    /// the launch's own value lets tor start.
    ///
    /// Tor initialises OpenSSL without `OPENSSL_INIT_NO_LOAD_CONFIG`, so with
    /// the variable unset OpenSSL reads `openssl.cnf` under its compiled-in
    /// `OPENSSLDIR`, `/var/tmp/dist/openssl/ssl` in every Expert Bundle: a
    /// path any local account can create, holding a configuration that can
    /// name a module for OpenSSL to load into tor. Two arms of one launch:
    /// as built, tor comes up; with only `OPENSSL_CONF` pointed at a
    /// configuration that loads a provider module which does not exist, tor
    /// fails to start. The second arm proves this binary's OpenSSL honours the
    /// variable; [`the_managed_launch_environment_is_exact`] proves the launch
    /// sets it to the blank file. Nothing is planted at the host's real
    /// `OPENSSLDIR`.
    #[tokio::test]
    #[ignore = "requires a Tor binary via SHEKYL_TEST_TOR_BINARY"]
    async fn openssl_reads_only_the_launchers_configuration() {
        let dir = tempfile::tempdir().expect("fixture directory");
        let managed = ManagedTor {
            tor_binary: VerifiedTorBinary::unchecked_for_test(crate::test_support::tor_binary()),
            data_dir: dir.path().join("data"),
            socks_port: super::super::actor::SocksPort::Auto,
            disable_network: true,
            exit_observer: None,
        };
        prepare_data_directory(&managed.data_dir)
            .await
            .expect("data directory");
        install_blank_config(&managed.data_dir)
            .await
            .expect("the blank file");
        let environment = LaunchEnvironment::resolve(&managed).expect("launch environment");

        let port_file = dir.path().join("control_port_as_built");
        let as_built = managed_tor_command(&managed, &port_file, &environment);
        assert!(
            launch_comes_up(as_built, &port_file).await,
            "the launch as built must start: its OPENSSL_CONF is the blank file"
        );

        let config = dir.path().join("loads-a-missing-provider.cnf");
        let module = dir.path().join("no-such-provider-module");
        std::fs::write(&config, provider_loading_config(&module)).expect("write the config");
        let port_file = dir.path().join("control_port_with_provider");
        let mut with_provider = managed_tor_command(&managed, &port_file, &environment);
        with_provider.env(OPENSSL_CONF_VARIABLE, &config);
        assert!(
            !launch_comes_up(with_provider, &port_file).await,
            "a configuration naming a provider module must stop tor: OpenSSL reads OPENSSL_CONF"
        );
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
