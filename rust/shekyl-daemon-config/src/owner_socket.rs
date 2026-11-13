// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Where the owner's socket goes, checked before anything is bound
//! (`docs/design/RPC_CHANNEL.md` RT-15, §7.1).
//!
//! A run-as-me daemon serves its owner on a Unix socket named by a hash of
//! the network id and the instance, `<dir>/shekyl-<name>.sock`, directly
//! inside a directory that is the containment: owned by the daemon's
//! account, closed to everyone else, on a local filesystem. That directory
//! is the account's session directory ([`Platform::session_dir`]) or, on a
//! host with none, one the operator names (`rpc-socket-dir`, IG-Q104). The
//! daemon asserts the directory rather than adopting it, and refuses to
//! start naming the condition that failed. A service serves no owner socket
//! (IG-Q105), so it has no plan.
//!
//! This is the walk's half: it creates nothing. Binding, the start-up dial
//! and the watch are the RPC's (`shekyl_daemon_rpc::owner`).

use std::path::PathBuf;

use shekyl_options::{Code, Diagnostic, Source};
use shekyl_rpc_channel::{rendezvous_name, Instance};

use crate::marker::NetworkId;
use crate::platform::{Platform, RunMode};
use crate::sections::DaemonConfig;

/// The checked place for the owner's leg: on Unix the socket, on Windows
/// the rendezvous file that names the pipe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerSocketPlan {
    /// Unix: the socket, `<dir>/shekyl-<name>.sock`. Windows: the rendezvous
    /// file, `<dir>\shekyl-<name>`.
    pub path: PathBuf,
    /// The directory that holds it.
    pub dir: PathBuf,
    /// Unix: the account that owns the directory, which is this daemon's.
    #[cfg(unix)]
    pub owner: u32,
    /// Windows: the data home `%LOCALAPPDATA%\Shekyl` the default
    /// rendezvous directory sits in, which the start creates owner-only and
    /// labelled when it does not exist. `None` for a named directory, whose
    /// parent is the operator's, and on Unix.
    pub data_home: Option<PathBuf>,
    /// The instance, as the start line names it.
    pub instance: Instance,
}

impl OwnerSocketPlan {
    /// The instance as an operator reads it: `default`, or its name.
    #[must_use]
    pub fn instance_label(&self) -> &str {
        self.instance.label()
    }
}

/// The owner's leg for this configuration, checked, with nothing created:
/// `None` for a service, which serves no owner's leg (IG-Q105).
///
/// On Unix the leg is a socket in the session directory or `rpc-socket-dir`.
/// On Windows it is a pipe named in a rendezvous file in
/// `%LOCALAPPDATA%\Shekyl\rendezvous`, or in the directory `rpc-socket-dir`
/// names on a test host; a directory that already exists must pass the
/// rendezvous directory's check (its owner, its protections, its no-read-up
/// label), and one that does not is created by the start.
///
/// `named_source` is where `rpc-socket-dir` came from, for the refusal.
///
/// # Errors
///
/// - `config.socket-dir.none`: a run-as-me daemon with no session directory
///   (Unix) or no local application data folder (Windows), and no
///   `rpc-socket-dir`;
/// - `config.socket-dir.unusable`: the directory fails its check;
/// - `config.socket-dir.path-long`: on Unix, the socket's path is over the
///   platform's limit.
pub fn plan(
    config: &DaemonConfig,
    platform: &Platform,
    network_id: &NetworkId,
    named_source: Source,
) -> Result<Option<OwnerSocketPlan>, Diagnostic> {
    if config.run_mode == RunMode::Service {
        return Ok(None);
    }
    let name = rendezvous_name(network_id, &config.rpc.instance);
    let default_dir = default_dir(platform);
    let (dir, source, option) = match (&config.rpc.socket_dir, &default_dir) {
        (Some(named), _) => (named.clone(), named_source, Some("rpc-socket-dir")),
        (None, Some(default)) => (default.clone(), Source::Machine, None),
        (None, None) => {
            return Err(Diagnostic::new(Code::SocketDirNone, Source::Machine)
                .param("looked", session_dir_description()));
        }
    };
    let refuse = |code: Code| {
        let d = Diagnostic::new(code, source.clone());
        match option {
            Some(name) => d.option(name),
            None => d,
        }
    };
    let unusable = |found: String| {
        refuse(Code::SocketDirUnusable)
            .param("path", dir.display().to_string())
            .param("found", found)
    };
    #[cfg(unix)]
    {
        let owner = assert_dir(&dir).map_err(unusable)?;
        let path = dir.join(format!("shekyl-{name}.sock"));
        let length = path.as_os_str().len();
        if length + 1 > SUN_PATH_MAX {
            return Err(refuse(Code::SocketPathLong)
                .param("path", path.display().to_string())
                .param("length", length.to_string())
                .param("limit", (SUN_PATH_MAX - 1).to_string()));
        }
        Ok(Some(OwnerSocketPlan {
            path,
            dir,
            owner,
            data_home: None,
            instance: config.rpc.instance.clone(),
        }))
    }
    #[cfg(not(unix))]
    {
        let _ = &refuse;
        if dir.exists() {
            shekyl_win_sec::rendezvous::check_owner_only_labelled(&dir)
                .map_err(|e| unusable(e.to_string()))?;
        }
        let data_home = match (&config.rpc.socket_dir, &platform.home) {
            (None, Some(home)) => Some(home.join("Shekyl")),
            _ => None,
        };
        Ok(Some(OwnerSocketPlan {
            path: dir.join(format!("shekyl-{name}")),
            dir,
            data_home,
            instance: config.rpc.instance.clone(),
        }))
    }
}

/// Where the owner's leg goes when `rpc-socket-dir` is unset: the session
/// directory on Unix, `%LOCALAPPDATA%\Shekyl\rendezvous` on Windows (Rick,
/// 2026-11-12).
fn default_dir(platform: &Platform) -> Option<PathBuf> {
    if cfg!(windows) {
        platform
            .home
            .as_ref()
            .map(|home| home.join("Shekyl").join("rendezvous"))
    } else {
        platform.session_dir.clone()
    }
}

/// A service's rendezvous directory, checked (`RPC_CHANNEL.md` §7.1; Rick,
/// 2026-11-12): `None` for a daemon run as its user, and on Windows, where
/// `service` waits for RT-W14. The directory is fixed per platform
/// ([`Platform::service_rendezvous`]) and checked, never adopted: the
/// daemon is not root, and the directory exists, is not a link, is owned by
/// the daemon's account, and is not writable by its group or by others. A
/// non-service account that gives `service` fails the ownership check.
///
/// # Errors
///
/// `config.service.rendezvous`, naming the condition that failed.
#[cfg(unix)]
pub fn service_rendezvous(
    config: &DaemonConfig,
    platform: &Platform,
) -> Result<Option<PathBuf>, Diagnostic> {
    if config.run_mode != RunMode::Service {
        return Ok(None);
    }
    let refuse = |path: &str, found: String| {
        Diagnostic::new(Code::ServiceRendezvous, Source::Cli)
            .option("service")
            .param("path", path)
            .param("found", found)
    };
    let Some(dir) = &platform.service_rendezvous else {
        return Err(refuse(
            "(none)",
            "this platform names no service rendezvous directory".to_owned(),
        ));
    };
    check_service_dir(dir, rustix::process::geteuid().as_raw())
        .map(|()| Some(dir.clone()))
        .map_err(|found| refuse(&dir.display().to_string(), found))
}

/// On Windows `service` waits for RT-W14, and a start refuses it before
/// the walk (`sections::build`), so there is no directory to check yet.
///
/// # Errors
///
/// None on Windows.
#[cfg(not(unix))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "one signature on every platform; Unix refuses here"
)]
pub fn service_rendezvous(
    _config: &DaemonConfig,
    _platform: &Platform,
) -> Result<Option<PathBuf>, Diagnostic> {
    Ok(None)
}

/// The service directory's conditions for the account `me`, in the order a
/// refusal names them; the error is the clause that failed, path included.
#[cfg(unix)]
fn check_service_dir(dir: &std::path::Path, me: u32) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let shown = dir.display();
    if me == 0 {
        return Err("the daemon runs as root".to_owned());
    }
    let meta = std::fs::symlink_metadata(dir).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => format!("{shown} does not exist"),
        _ => format!("{shown} cannot be read: {e}"),
    })?;
    if meta.file_type().is_symlink() {
        return Err(format!("{shown} is a symbolic link"));
    }
    if !meta.is_dir() {
        return Err(format!("{shown} is not a directory"));
    }
    if meta.uid() != me {
        return Err(format!(
            "{shown} is owned by uid {}, not this account (uid {me})",
            meta.uid()
        ));
    }
    let mode = meta.permissions().mode() & 0o7777;
    if mode & 0o022 != 0 {
        return Err(format!(
            "{shown} is writable by its group or by others (mode {mode:04o})"
        ));
    }
    Ok(())
}

/// A Unix socket path's buffer, its terminator included: `sun_path` is 108
/// bytes on Linux and 104 on macOS and the BSDs (`RPC_CHANNEL.md` §7.1).
#[cfg(unix)]
const SUN_PATH_MAX: usize = if cfg!(target_os = "linux") { 108 } else { 104 };

/// What a refusal says the daemon looked for.
fn session_dir_description() -> &'static str {
    if cfg!(windows) {
        "the local application data folder is not reported"
    } else if cfg!(target_os = "linux") {
        "/run/user/<uid> does not exist"
    } else if cfg!(target_os = "macos") {
        "the per-user temporary directory is not reported"
    } else {
        "this platform reports none"
    }
}

/// The directory is this account's alone: it exists, is a directory and not
/// a link, is owned by the effective user, has mode 0700, and is on a local
/// filesystem. Returns its owner; the error is the condition that failed,
/// in the operator's words.
#[cfg(unix)]
pub fn assert_dir(dir: &std::path::Path) -> Result<u32, String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let meta = std::fs::symlink_metadata(dir).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => "it does not exist".to_owned(),
        _ => format!("it cannot be read: {e}"),
    })?;
    if meta.file_type().is_symlink() {
        return Err("it is a symbolic link; name the directory itself".to_owned());
    }
    if !meta.is_dir() {
        return Err("it is not a directory".to_owned());
    }
    let me = rustix::process::geteuid().as_raw();
    if meta.uid() != me {
        return Err(format!(
            "it is owned by uid {}, not this account (uid {me})",
            meta.uid()
        ));
    }
    let mode = meta.permissions().mode() & 0o7777;
    if mode != 0o700 {
        return Err(format!("its mode is {mode:04o}, not 0700"));
    }
    if !is_local(dir).map_err(|e| format!("its filesystem cannot be read: {e}"))? {
        return Err("it is on a network filesystem".to_owned());
    }
    Ok(me)
}

/// Whether the filesystem holding `dir` is local. On Linux the filesystem's
/// magic number is not one of the network filesystems'; elsewhere the mount
/// carries `MNT_LOCAL`.
#[cfg(target_os = "linux")]
fn is_local(dir: &std::path::Path) -> std::io::Result<bool> {
    /// `statfs(2)`'s `f_type` for the network filesystems (`linux/magic.h`):
    /// NFS, SMB, CIFS, SMB2, Coda, AFS, 9p and Ceph.
    const NETWORK: [i64; 8] = [
        0x6969,
        0x517B,
        0xFF53_4D42,
        0xFE53_4D42,
        0x7375_7245,
        0x5346_414F,
        0x0102_1997,
        0x00C3_6400,
    ];
    let stat = rustix::fs::statfs(dir)?;
    #[allow(
        clippy::cast_lossless,
        clippy::unnecessary_cast,
        reason = "f_type's width differs between the libc and raw backends"
    )]
    let kind = stat.f_type as i64;
    // `f_type` is a signed word on some targets: compare on the low 32 bits,
    // where every magic number lives.
    Ok(!NETWORK.contains(&(kind & 0xFFFF_FFFF)))
}

/// Whether the filesystem holding `dir` is local: the mount's `MNT_LOCAL`.
#[cfg(all(unix, not(target_os = "linux")))]
fn is_local(dir: &std::path::Path) -> std::io::Result<bool> {
    let stat = rustix::fs::statfs(dir)?;
    // `u32` on macOS, `u64` on FreeBSD.
    let flags = u64::from(stat.f_flags);
    #[allow(clippy::cast_sign_loss, reason = "a flag bit, never negative")]
    let local = libc::MNT_LOCAL as u64;
    Ok(flags & local != 0)
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use super::*;
    use crate::network::Network;
    use crate::resolve::{choosers, resolve};
    use crate::table::TABLE;

    fn config(cli: &[&str]) -> DaemonConfig {
        let args: Vec<std::ffi::OsString> = cli.iter().map(Into::into).collect();
        let cli = shekyl_options::read_cli(&TABLE, args).unwrap();
        let (network, mode) = choosers(&cli);
        let mut resolved = resolve(&TABLE, network, cli, Vec::new()).unwrap();
        crate::build(&mut resolved, network, mode, &platform(None), None).unwrap()
    }

    fn platform(session: Option<&Path>) -> Platform {
        Platform {
            home: Some(PathBuf::from("/srv/op")),
            program_data: None,
            session_dir: session.map(Path::to_path_buf),
            service_rendezvous: None,
        }
    }

    fn private_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    fn id() -> NetworkId {
        Network::Regtest.network_id()
    }

    #[test]
    fn the_socket_is_named_by_the_network_and_instance_inside_the_session_directory() {
        let session = private_dir();
        let plan = plan(
            &config(&["--network", "regtest"]),
            &platform(Some(session.path())),
            &id(),
            Source::Cli,
        )
        .unwrap()
        .expect("a run-as-me daemon has an owner socket");
        let name = rendezvous_name(&id(), &Instance::Default);
        assert_eq!(
            plan.path,
            session.path().join(format!("shekyl-{name}.sock"))
        );
        assert_eq!(plan.instance_label(), "default");
        assert_eq!(plan.owner, rustix::process::geteuid().as_raw());
    }

    /// A named directory wins over the session directory.
    #[test]
    fn a_named_directory_is_used_in_place_of_the_session_directory() {
        let named = private_dir();
        let session = private_dir();
        let dir = named.path().to_str().unwrap();
        let plan = plan(
            &config(&["--network", "regtest", "--rpc-socket-dir", dir]),
            &platform(Some(session.path())),
            &id(),
            Source::Cli,
        )
        .unwrap()
        .unwrap();
        assert_eq!(plan.dir, named.path());
    }

    /// No session directory and none named: the refusal names the ways
    /// forward. Red edit: fall back to the temporary directory and this
    /// start succeeds.
    #[test]
    fn no_session_directory_and_none_named_refuses() {
        let d = plan(
            &config(&["--network", "regtest"]),
            &platform(None),
            &id(),
            Source::Cli,
        )
        .unwrap_err();
        assert_eq!(d.code, Code::SocketDirNone);
        let words = d.render();
        for way in ["--service", "loginctl enable-linger", "--rpc-socket-dir"] {
            assert!(words.contains(way), "{words}");
        }
    }

    /// A service serves no owner socket, so it needs no directory at all.
    #[test]
    fn a_service_has_no_owner_socket() {
        let c = config(&[
            "--network",
            "regtest",
            "--service",
            "--data-dir",
            "/var/lib/shekyl",
            "--log-file",
            "/var/log/shekyl/shekyld.log",
        ]);
        assert_eq!(plan(&c, &platform(None), &id(), Source::Cli), Ok(None));
    }

    /// Each condition on the directory is asserted, not adopted, and the
    /// refusal names the one that failed. Red edit: drop the mode check and
    /// the 0755 case passes.
    #[test]
    fn a_directory_that_is_not_this_accounts_alone_is_refused_by_condition() {
        let refused = |dir: &Path| {
            let d = plan(
                &config(&[
                    "--network",
                    "regtest",
                    "--rpc-socket-dir",
                    dir.to_str().unwrap(),
                ]),
                &platform(None),
                &id(),
                Source::Cli,
            )
            .unwrap_err();
            assert_eq!(d.code, Code::SocketDirUnusable);
            assert_eq!(d.option.as_deref(), Some("rpc-socket-dir"));
            d.params
                .iter()
                .find(|(k, _)| *k == "found")
                .map(|(_, v)| v.clone())
                .unwrap()
        };
        let base = private_dir();
        assert!(refused(&base.path().join("absent")).contains("does not exist"));

        let open = base.path().join("open");
        std::fs::create_dir(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(refused(&open).contains("0755"));

        let file = base.path().join("file");
        std::fs::write(&file, b"").unwrap();
        assert!(refused(&file).contains("not a directory"));

        let target = base.path().join("target");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
        let link = base.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(refused(&link).contains("symbolic link"));
    }

    /// The path limit is checked with the name in place, before any bind.
    #[test]
    fn a_socket_path_over_the_platforms_limit_is_refused() {
        let base = private_dir();
        let mut deep = base.path().to_path_buf();
        while deep.as_os_str().len() < SUN_PATH_MAX {
            deep.push("d".repeat(20));
        }
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::set_permissions(&deep, std::fs::Permissions::from_mode(0o700)).unwrap();
        let d = plan(
            &config(&[
                "--network",
                "regtest",
                "--rpc-socket-dir",
                deep.to_str().unwrap(),
            ]),
            &platform(None),
            &id(),
            Source::Cli,
        )
        .unwrap_err();
        assert_eq!(d.code, Code::SocketPathLong);
    }

    fn service_config() -> DaemonConfig {
        config(&[
            "--network",
            "regtest",
            "--service",
            "--data-dir",
            "/var/lib/shekyl",
            "--log-file",
            "/var/log/shekyl/shekyld.log",
        ])
    }

    fn with_rendezvous(dir: &Path) -> Platform {
        Platform {
            service_rendezvous: Some(dir.to_path_buf()),
            ..platform(None)
        }
    }

    /// The service's directory, the account's and closed to writers other
    /// than it, is accepted; a daemon run as its user is not asked.
    #[test]
    fn a_service_accepts_its_own_closed_rendezvous_directory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            service_rendezvous(&service_config(), &with_rendezvous(dir.path())),
            Ok(Some(dir.path().to_path_buf()))
        );
        let session = private_dir();
        assert_eq!(
            service_rendezvous(
                &config(&["--network", "regtest"]),
                &with_rendezvous(session.path())
            ),
            Ok(None)
        );
    }

    /// Each condition is checked, not adopted, and the refusal names the one
    /// that failed. Red edit: drop the group/other write check and the 0775
    /// case is accepted.
    #[test]
    fn a_service_rendezvous_directory_is_refused_by_condition() {
        let found = |dir: &Path| {
            let d = service_rendezvous(&service_config(), &with_rendezvous(dir)).unwrap_err();
            assert_eq!(d.code, Code::ServiceRendezvous);
            assert_eq!(d.option.as_deref(), Some("service"));
            d.params
                .iter()
                .find(|(k, _)| *k == "found")
                .map(|(_, v)| v.clone())
                .unwrap()
        };
        let base = tempfile::tempdir().unwrap();
        assert!(found(&base.path().join("absent")).contains("does not exist"));

        let open = base.path().join("open");
        std::fs::create_dir(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert!(found(&open).contains("writable by its group or by others"));

        let target = base.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let link = base.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(found(&link).contains("symbolic link"));

        let none = Platform {
            service_rendezvous: None,
            ..platform(None)
        };
        let d = service_rendezvous(&service_config(), &none).unwrap_err();
        assert_eq!(d.code, Code::ServiceRendezvous);
    }

    /// A root daemon is refused whatever the directory is.
    #[test]
    fn a_root_service_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            check_service_dir(dir.path(), 0),
            Err("the daemon runs as root".to_owned())
        );
    }

    /// A non-service account that gives `service` is refused: the
    /// directory is not its own. `/` stands for a directory the service
    /// manager gave another account. Runs as an ordinary account.
    #[test]
    fn a_non_service_account_giving_service_is_refused() {
        assert!(
            !rustix::process::geteuid().is_root(),
            "run the tests as an ordinary account"
        );
        let d =
            service_rendezvous(&service_config(), &with_rendezvous(Path::new("/"))).unwrap_err();
        let found = &d.params.iter().find(|(k, _)| *k == "found").unwrap().1;
        // The refusal names the owner's uid; the assertion message does not
        // repeat it (CodeQL rust/cleartext-logging, alert 199).
        assert!(
            found.contains("owned by uid 0"),
            "the refusal does not name the owner"
        );
    }

    /// A directory owned by another account is refused. The test must run
    /// as an ordinary account: as root, `/` is the test's own directory and
    /// the case it checks does not exist.
    #[test]
    fn a_directory_owned_by_another_account_is_refused() {
        assert!(
            !rustix::process::geteuid().is_root(),
            "run the tests as an ordinary account"
        );
        // `/` is root's on every Unix the tests run on.
        let found = assert_dir(Path::new("/")).unwrap_err();
        // The refusal names the owner's uid; the assertion message does not
        // repeat it (CodeQL rust/cleartext-logging, alert 199).
        assert!(
            found.contains("owned by uid 0"),
            "the refusal does not name the owner"
        );
    }
}
