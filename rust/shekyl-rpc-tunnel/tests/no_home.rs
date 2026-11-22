// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The tunnel run by an account with no home (Rick, 2026-11-21): the
//! packaged `shekyl-tunnel` has none, and its unit names the configuration
//! file, the key file and the log file. The account's root is read only
//! for a default path, so the given paths make a key and a run, and a
//! default that needs the missing home is refused, naming the option to
//! give.
//!
//! A named configuration file is checked: no one but root and this account
//! may write it or any directory above it, so `/tmp` (world-writable) is
//! never its place. The file lives in a directory of this test's own under
//! cargo's temporary target directory or, where a umask of 0002 makes that
//! group-writable, the account's home, mode 0700, as the daemon's
//! `config_file.rs` places its own.

#![cfg(unix)]

use std::ffi::OsString;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use shekyl_daemon_config::Platform;
use shekyl_rpc_tunnel::config::{load, Action};

fn no_home() -> Platform {
    Platform {
        home: None,
        service_parent: None,
        session_dir: None,
        service_rendezvous: None,
    }
}

fn args(words: &[&str]) -> Vec<OsString> {
    words.iter().map(OsString::from).collect()
}

fn write_private(path: &Path, text: &str) {
    use std::io::Write as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .expect("a private file");
    file.write_all(text.as_bytes()).expect("written");
}

/// A 0700 directory the configuration-file check accepts, or the test fails
/// naming each place it refused (rule 47).
fn private_place() -> tempfile::TempDir {
    let candidates = std::iter::once(PathBuf::from(env!("CARGO_TARGET_TMPDIR")))
        .chain(shekyl_process::platform::current().home);
    let mut refusals = Vec::new();
    for root in candidates {
        let dir = match tempfile::Builder::new()
            .prefix("shekyl-tunnel-no-home-")
            .tempdir_in(&root)
        {
            Ok(dir) => dir,
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

/// A node's bundle, written where the run reads it.
fn bundle_file(dir: &Path) -> PathBuf {
    let key = shekyl_rpc_channel::handshake::StaticKeypair::generate().expect("a key");
    let mut bytes = key.public().x25519().to_vec();
    bytes.extend_from_slice(key.public().mlkem_ek());
    let path = dir.join("node.bundle");
    std::fs::write(&path, shekyl_rpc_transport::channel::bundle_text(&bytes)).expect("written");
    path
}

/// **With no home, the given paths make a key and a run.** Red edit: read
/// the account's root before the arguments (`config.path.no-home` refuses
/// both).
#[test]
fn with_no_home_the_given_paths_make_a_key_and_a_run() {
    let dir = private_place();
    let config = dir.path().join("shekyl-rpc-tunnel.toml");
    write_private(&config, "");
    let key = dir.path().join("k.key");
    let made = load(
        args(&[
            "--rpc-key-create",
            "--config-file",
            config.to_str().expect("a UTF-8 path"),
            "--rpc-key-file",
            key.to_str().expect("a UTF-8 path"),
        ]),
        &no_home(),
    );
    match made {
        Ok(Action::KeyCreate(got)) => assert_eq!(got, key),
        Ok(_) => panic!("rpc-key-create was not a key creation"),
        Err(faults) => panic!("rpc-key-create with no home was refused: {faults:?}"),
    }
    let bundle = bundle_file(dir.path());
    let run = load(
        args(&[
            "--network",
            "regtest",
            "--config-file",
            config.to_str().expect("a UTF-8 path"),
            "--rpc-key-file",
            key.to_str().expect("a UTF-8 path"),
            "--log-file",
            dir.path().join("t.log").to_str().expect("a UTF-8 path"),
            "--daemon-endpoint",
            "203.0.113.5:29501",
            "--daemon-bundle-file",
            bundle.to_str().expect("a UTF-8 path"),
            "--listen",
            "127.0.0.1:29600",
        ]),
        &no_home(),
    );
    match run {
        Ok(Action::Run(config)) => assert_eq!(config.key_file, key),
        Ok(_) => panic!("a run was not a run"),
        Err(faults) => panic!("a run with no home was refused: {faults:?}"),
    }
}

/// **With no home, a default that needs it is refused, naming the option
/// to give**: the configuration file's, then the key file's once that is
/// given, then the log file's once both are. Red edit: name `config-file`
/// for every default.
#[test]
fn with_no_home_a_needed_default_names_the_option_to_give() {
    let dir = private_place();
    let config = dir.path().join("shekyl-rpc-tunnel.toml");
    write_private(&config, "");
    let key = dir.path().join("k.key");
    let bundle = bundle_file(dir.path());
    let refused = |words: &[&str]| -> Vec<(&'static str, Option<String>)> {
        match load(args(words), &no_home()) {
            Err(faults) => faults
                .iter()
                .map(|d| (d.code.as_str(), d.option.clone()))
                .collect(),
            Ok(_) => panic!("not refused: {words:?}"),
        }
    };
    let no_home_for = |option: &str| vec![("config.path.no-home", Some(option.to_owned()))];
    let config_path = config.to_str().expect("a UTF-8 path");
    assert_eq!(refused(&["--rpc-key-create"]), no_home_for("config-file"));
    assert_eq!(
        refused(&["--rpc-key-create", "--config-file", config_path]),
        no_home_for("rpc-key-file")
    );
    assert_eq!(
        refused(&[
            "--network",
            "regtest",
            "--config-file",
            config_path,
            "--rpc-key-file",
            key.to_str().expect("a UTF-8 path"),
            "--daemon-endpoint",
            "203.0.113.5:29501",
            "--daemon-bundle-file",
            bundle.to_str().expect("a UTF-8 path"),
            "--listen",
            "127.0.0.1:29600",
        ]),
        no_home_for("log-file")
    );
}
