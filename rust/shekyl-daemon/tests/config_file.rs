// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The loader's file path, end to end through `shekyl_daemon_config::load`:
//! a named file is read and its value reaches the configuration, and the
//! permission check refuses the file, and a directory above it, when a
//! principal besides this account can write them.
//!
//! The pieces have their own tests (`file.rs`: the walk over described
//! entries, and `open` on real files). This one holds that `load` takes
//! that path for a file it is named. `shekyl-node`'s tests build their
//! configuration from the command line alone, so they do not.
//!
//! Unix only: Windows judges the file by its access-control list
//! (`shekyl-win-sec`), which a test cannot set up as these mode bits do.

#![cfg(unix)]

use std::ffi::OsString;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use shekyl_daemon_config::{load, load_default_file_unread, Platform, TABLE};
use shekyl_options::{read_cli, Code};

/// The configuration file's name in [`private_place`]'s directory.
const CONFIG_FILE: &str = "shekyld-regtest.toml";

/// A directory of this test's own, in a place the permission walk accepts:
/// every directory above it writable by root and this account alone. The
/// candidates, nearest first: the target directory's own temporary
/// directory, then the account's home. `/tmp` is never one: it is
/// world-writable, and the walk refuses it. None qualifying fails the test,
/// naming each refusal (rule 47).
///
/// On a host whose umask is `0002` (this lane's workstation, and any fleet
/// box set up the same way) the build tree is group-writable, so the walk
/// refuses the target directory and the home is tried. That refusal is the
/// walk working as designed: a directory another principal can write is
/// refused, wherever it is.
///
/// In either place the directory is a uniquely named subdirectory
/// (`shekyl-config-file-` and a random suffix), mode `0700`, held by a
/// [`Place`] from the moment it exists, so the test leaves nothing behind in
/// the account's home, a panic included.
fn private_place() -> Place {
    let candidates = std::iter::once(PathBuf::from(env!("CARGO_TARGET_TMPDIR")))
        .chain(shekyl_process::platform::current().home);
    let mut refusals = Vec::new();
    for root in candidates {
        let dir = match tempfile::Builder::new()
            .prefix("shekyl-config-file-")
            .tempdir_in(&root)
        {
            Ok(dir) => Place(Some(dir)),
            Err(e) => {
                refusals.push(format!("{}: {e}", root.display()));
                continue;
            }
        };
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("the directory's mode");
        let probe = dir.path().join("probe.toml");
        write_private(&probe, "");
        match shekyl_daemon_config::file::open(&probe, true) {
            Ok(Some(_)) => {
                std::fs::remove_file(&probe).expect("the probe goes");
                return dir;
            }
            Ok(None) => refusals.push(format!("{}: read as absent", root.display())),
            Err(d) => refusals.push(format!("{}: {}", root.display(), d.render())),
        }
    }
    panic!(
        "no directory this account alone can write: {}",
        refusals.join("; ")
    );
}

/// [`private_place`]'s directory, removed when the guard drops, during a
/// panic's unwind too. The test may leave its mode at `0770` and its file at
/// `0620`; the guard sets the directory back to `0700` and removes it with
/// everything in it. A removal that fails is said, not swallowed (the
/// `TempDir` it holds would drop the error): a panic when the test is not
/// already panicking, a line on stderr when it is, since a second panic
/// would abort the run.
struct Place(Option<tempfile::TempDir>);

impl Place {
    fn path(&self) -> &Path {
        self.0
            .as_ref()
            .expect("the directory is held until the guard drops")
            .path()
    }
}

impl Drop for Place {
    fn drop(&mut self) {
        let Some(dir) = self.0.take() else {
            return;
        };
        let path = dir.path().to_path_buf();
        let mode = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700));
        let removal = dir.close();
        let failed: Vec<String> = [
            mode.err()
                .map(|e| format!("setting its mode back to 0700: {e}")),
            removal.err().map(|e| format!("removing it: {e}")),
        ]
        .into_iter()
        .flatten()
        .collect();
        if failed.is_empty() {
            return;
        }
        let says = format!(
            "the test's directory {} was not cleaned up: {}",
            path.display(),
            failed.join("; ")
        );
        if std::thread::panicking() {
            eprintln!("{says}");
        } else {
            panic!("{says}");
        }
    }
}

/// `text` at `path`, mode `0600`.
fn write_private(path: &Path, text: &str) {
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut file| file.write_all(text.as_bytes()))
        .expect("the configuration file");
}

/// `load` on a regtest command line naming `file`, with the data and log
/// under `dir`.
fn load_naming(
    dir: &Path,
    file: &Path,
) -> Result<shekyl_daemon_config::Loaded, Vec<shekyl_options::Diagnostic>> {
    let data = dir.join("data");
    let log = dir.join("shekyld.log");
    let args: Vec<OsString> = [
        "--network",
        "regtest",
        "--config-file",
        file.to_str().expect("a UTF-8 path"),
        "--data-dir",
        data.to_str().expect("a UTF-8 path"),
        "--log-file",
        log.to_str().expect("a UTF-8 path"),
    ]
    .iter()
    .map(OsString::from)
    .collect();
    let cli = read_cli(&TABLE, args).expect("the command line");
    load(
        cli,
        &Platform {
            home: Some(dir.to_path_buf()),
            service_parent: None,
            session_dir: None,
            service_rendezvous: None,
        },
    )
}

/// The one refusal `load` gave, by code.
fn refused(
    result: Result<shekyl_daemon_config::Loaded, Vec<shekyl_options::Diagnostic>>,
) -> shekyl_options::Diagnostic {
    let Err(mut ds) = result else {
        panic!("the load was accepted")
    };
    assert_eq!(ds.len(), 1, "{ds:?}");
    ds.remove(0)
}

/// A named file is read: its `log-level` is the configuration's. A file
/// a principal besides this account can write is refused at the file, and
/// a directory above it that one can write is refused at that directory,
/// each naming the place and the principal.
///
/// Red edits: `load` reads no file it is named (the level stays the
/// default); `file::open` skips the write check (both refusals pass).
#[test]
fn a_named_file_is_read_and_a_writable_file_or_directory_is_refused() {
    let place = private_place();
    let dir = place.path();
    let file = dir.join(CONFIG_FILE);
    write_private(&file, "log-level = \"debug\"\n");

    let loaded = load_naming(dir, &file).expect("a private file is accepted");
    assert_eq!(loaded.file_read.as_deref(), Some(file.as_path()));
    assert_eq!(
        loaded.config.logging.level, "debug",
        "the file's value is read"
    );

    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o620))
        .expect("the file's mode");
    let d = refused(load_naming(dir, &file));
    assert_eq!(d.code, Code::FilePermissions, "{d:?}");
    assert_eq!(d.get("path"), Some(file.display().to_string().as_str()));
    assert!(
        d.get("principal")
            .is_some_and(|p| p.starts_with("its group")),
        "{d:?}"
    );

    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600))
        .expect("the file's mode");
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o770))
        .expect("the directory's mode");
    let d = refused(load_naming(dir, &file));
    assert_eq!(d.code, Code::FilePermissions, "{d:?}");
    assert_eq!(d.get("path"), Some(dir.display().to_string().as_str()));
    assert!(
        d.get("principal")
            .is_some_and(|p| p.starts_with("its group")),
        "{d:?}"
    );
}

/// The load a test of the daemon's entry point uses leaves only the
/// *default* file unread. A file the command line names is read as `load`
/// reads it, so such a test can still be about a file. With none named,
/// no file is read and the path announced is the default's.
///
/// Red edits: `load_default_file_unread` skips a named file too (the level
/// stays the default). The other direction, reading the default file, shows
/// only on a host that has one: there `file_read` is set.
#[test]
fn the_default_file_unread_load_still_reads_a_named_file() {
    let place = private_place();
    let dir = place.path();
    let file = dir.join(CONFIG_FILE);
    write_private(&file, "log-level = \"debug\"\n");
    let platform = Platform {
        home: Some(dir.to_path_buf()),
        service_parent: None,
        session_dir: None,
        service_rendezvous: None,
    };
    let cli = |list: &[&str]| {
        let args: Vec<OsString> = list.iter().map(OsString::from).collect();
        read_cli(&TABLE, args).expect("the command line")
    };

    let named = load_default_file_unread(
        cli(&[
            "--network",
            "regtest",
            "--config-file",
            file.to_str().expect("a UTF-8 path"),
        ]),
        &platform,
    )
    .expect("a private file is accepted");
    assert_eq!(named.file_read.as_deref(), Some(file.as_path()));
    assert_eq!(named.config.logging.level, "debug");

    let unnamed = load_default_file_unread(cli(&["--network", "regtest"]), &platform)
        .expect("no file is a configuration");
    assert_eq!(unnamed.file_read, None);
    assert_eq!(
        unnamed.config_file,
        shekyl_daemon_config::ConfigFileChoice::Default("/etc/shekyl/shekyld-regtest.toml".into()),
        "the path announced is the default's"
    );
    assert_ne!(unnamed.config.logging.level, "debug");
}

/// **`config-file none` reads no file, wherever one is** (Rick,
/// 2026-11-18). A program that starts its own daemon asks for the command
/// line and the defaults alone, so its node means the same on every
/// machine, whatever another install keeps in the shared file. `load` (the
/// production loader, which reads the default file) is given `none`: no
/// file is read, not even a default one present on the host, and the
/// choice is `None`. Red edit: in `config_file`, read the default file for
/// `Value::Word` (`file_read` is the host's default file where it has one,
/// and the choice is `Default`).
#[test]
fn config_file_none_reads_no_file() {
    let place = private_place();
    let platform = Platform {
        home: Some(place.path().to_path_buf()),
        service_parent: None,
        session_dir: None,
        service_rendezvous: None,
    };
    let args: Vec<OsString> = ["--network", "regtest", "--config-file", "none"]
        .iter()
        .map(OsString::from)
        .collect();
    let loaded = load(read_cli(&TABLE, args).expect("the command line"), &platform)
        .expect("no file is a configuration");
    assert_eq!(loaded.file_read, None);
    assert_eq!(
        loaded.config_file,
        shekyl_daemon_config::ConfigFileChoice::None
    );
}
