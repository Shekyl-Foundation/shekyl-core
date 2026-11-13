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

/// The checked place for the owner's socket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerSocketPlan {
    /// The socket's path: `<dir>/shekyl-<name>.sock`.
    pub path: PathBuf,
    /// The directory that holds it.
    pub dir: PathBuf,
    /// The account that owns the directory, which is this daemon's.
    pub owner: u32,
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

/// The owner's socket for this configuration, checked: `None` for a
/// service, which serves no owner socket, and on Windows, whose owner leg is
/// a pipe.
///
/// `named_source` is where `rpc-socket-dir` came from, for the refusal.
///
/// # Errors
///
/// - `config.socket-dir.none`: a run-as-me daemon with no session directory
///   and no `rpc-socket-dir`;
/// - `config.socket-dir.unusable`: the directory is missing, a link, not a
///   directory, not this account's, not mode 0700, or on a network
///   filesystem;
/// - `config.socket-dir.path-long`: the socket's path is over the
///   platform's limit.
pub fn plan(
    config: &DaemonConfig,
    platform: &Platform,
    network_id: &NetworkId,
    named_source: Source,
) -> Result<Option<OwnerSocketPlan>, Diagnostic> {
    if config.run_mode == RunMode::Service || cfg!(windows) {
        return Ok(None);
    }
    let (dir, source, option) = match (&config.rpc.socket_dir, &platform.session_dir) {
        (Some(named), _) => (named.clone(), named_source, Some("rpc-socket-dir")),
        (None, Some(session)) => (session.clone(), Source::Machine, None),
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
    let owner = assert_dir(&dir).map_err(|found| {
        refuse(Code::SocketDirUnusable)
            .param("path", dir.display().to_string())
            .param("found", found)
    })?;
    let name = rendezvous_name(network_id, &config.rpc.instance);
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
        instance: config.rpc.instance.clone(),
    }))
}

/// A Unix socket path's buffer, its terminator included: `sun_path` is 108
/// bytes on Linux and 104 on macOS and the BSDs (`RPC_CHANNEL.md` §7.1).
const SUN_PATH_MAX: usize = if cfg!(target_os = "linux") { 108 } else { 104 };

/// What a refusal says the daemon looked for.
fn session_dir_description() -> &'static str {
    if cfg!(target_os = "linux") {
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

/// Windows has no socket directory; its owner leg is a pipe.
#[cfg(not(unix))]
pub fn assert_dir(_dir: &std::path::Path) -> Result<u32, String> {
    Err("a socket directory is a Unix directory".to_owned())
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
    #[allow(
        clippy::cast_sign_loss,
        clippy::unnecessary_cast,
        reason = "the flag word's type differs between the BSDs"
    )]
    let flags = stat.f_flags as u64;
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
        assert!(found.contains("owned by uid 0"), "{found}");
    }
}
