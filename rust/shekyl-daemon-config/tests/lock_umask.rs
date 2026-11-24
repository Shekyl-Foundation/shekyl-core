// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A new data directory under each kind of umask.
//!
//! The umask is process-wide, so each case takes the lock in a child process.
//! These tests live in their own binary because of that child: a fork holds a
//! copy of every descriptor until its `exec`, so spawning one beside the lock's
//! unit tests could keep a just-released `flock` held and fail them.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use shekyl_daemon_config::lock::Lock;
use shekyl_os_account::directory::PERMISSION_BITS;
use shekyl_os_account::{test_fixture, OWNER_ONLY_DIR_MODE};

/// The variable naming the data directory [`umask_child`] takes.
const UMASK_CHILD: &str = "SHEKYL_LOCK_UMASK_CHILD";

/// The permission bits of `dir`.
fn mode_of(dir: &Path) -> u32 {
    std::fs::metadata(dir).unwrap().permissions().mode() & PERMISSION_BITS
}

/// Takes the lock in the process [`take_under_umask`] starts, under its
/// umask, and prints the outcome. Not a test of its own.
#[test]
#[ignore = "run by take_under_umask, in a process with its own umask"]
fn umask_child() {
    let Some(data) = std::env::var_os(UMASK_CHILD) else {
        return;
    };
    match Lock::take(Path::new(&data)) {
        Ok(_held) => println!("UMASK-CHILD ok"),
        Err(d) => println!(
            "UMASK-CHILD {} path={} mode={} umask={}",
            d.code.as_str(),
            d.get("path").unwrap_or_default(),
            d.get("mode").unwrap_or_default(),
            d.get("umask").unwrap_or_default()
        ),
    }
}

/// [`Lock::take`] of `data` in a child process under `umask`.
fn take_under_umask(umask: &str, data: &Path) -> String {
    let out = std::process::Command::new("/bin/sh")
        .args(["-c", "umask \"$1\"; shift; exec \"$@\"", "sh", umask])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "umask_child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(UMASK_CHILD, data)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    stdout
        .split_once("UMASK-CHILD ")
        .and_then(|(_, outcome)| outcome.lines().next())
        .unwrap_or_else(|| panic!("the child reported nothing: {stdout}"))
        .to_owned()
}

/// Under the umasks that leave the owner's bits, a new data directory and
/// the data home above it come out `0700`. Red edit: create them with
/// `create_dir_all` (`0755` under `022`).
#[test]
fn a_new_data_directory_is_0700_under_every_ordinary_umask() {
    let d = test_fixture::tempdir().unwrap();
    for umask in ["022", "002", "027", "077"] {
        let home = d.path().join(format!("home{umask}"));
        let data = home.join("testnet");
        assert_eq!(take_under_umask(umask, &data), "ok", "umask {umask}");
        for dir in [&home, &data] {
            assert_eq!(
                mode_of(dir),
                OWNER_ONLY_DIR_MODE,
                "{} under umask {umask}",
                dir.display()
            );
        }
    }
}

/// A umask that strips the owner's own bits refuses the start, naming the
/// owner's digit, and leaves nothing made; no mode is changed to rescue it.
/// Red edit: drop the check after `mkdir`, and the short directory is taken
/// for the data directory.
#[test]
fn an_owner_stripping_umask_refuses_the_start_and_is_named() {
    let d = test_fixture::tempdir().unwrap();
    for (umask, mode, named) in [
        ("0277", "0500", "02xx"),
        ("0477", "0300", "04xx"),
        ("0177", "0600", "01xx"),
        ("0777", "0000", "07xx"),
    ] {
        let home = d.path().join(format!("home{umask}"));
        let data = home.join("testnet");
        assert_eq!(
            take_under_umask(umask, &data),
            format!(
                "config.data-dir.umask path={} mode={mode} umask={named}",
                home.display()
            )
        );
        assert!(!home.exists(), "nothing is left under umask {umask}");
    }
}
