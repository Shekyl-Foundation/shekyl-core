// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Symlink-safety property for the file-sink chmod sweep.
//!
//! `shekyl-logging::appender::chmod_matching_files_0600` walks the sink
//! directory and clamps every prefix-matching regular file to `0600`.
//! Using `fs::set_permissions` on a symlink on Linux follows the link
//! and chmods the *target*, so a planted symlink whose name matches
//! `filename_prefix` would let an attacker who can create files in the
//! log dir trick the logger into clobbering an unrelated file's mode.
//!
//! This test plants a symlink alongside a real sink file, runs the
//! reapply helper, and asserts that:
//!
//! 1. the real regular file is clamped to `0600`;
//! 2. the symlink's *target* (a sibling file we intentionally keep at
//!    `0644`) is untouched.
//!
//! Gated on `#[cfg(unix)]` because the attack (and the defense) are
//! Unix-only; POSIX-mode semantics don't apply on Windows.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;

use shekyl_logging::__test_only_reapply_file_modes;

#[test]
fn chmod_sweep_does_not_follow_prefix_matching_symlinks() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let dir_path = dir.path();

    let prefix = "sink.log";
    let real_sink = dir_path.join(prefix);
    fs::write(&real_sink, b"real sink content").expect("write real sink");
    fs::set_permissions(&real_sink, fs::Permissions::from_mode(0o644))
        .expect("set initial mode on real sink");

    // Victim file: a sibling we deliberately place *outside* the prefix
    // pattern and at `0644` so a naive chmod-through-symlink would be
    // loudly observable.
    let victim = dir_path.join("unrelated-victim.conf");
    fs::write(&victim, b"victim content").expect("write victim");
    fs::set_permissions(&victim, fs::Permissions::from_mode(0o644))
        .expect("set initial mode on victim");

    // Planted symlink. Its filename matches `prefix` (so the sweep's
    // `starts_with(prefix)` filter selects it) and its target is the
    // victim file. If the sweep follows the symlink, the victim's mode
    // flips to `0600`; if the sweep skips non-regular entries, the
    // victim stays at `0644`.
    let planted = dir_path.join(format!("{prefix}.planted"));
    std::os::unix::fs::symlink(&victim, &planted).expect("create planted symlink");

    __test_only_reapply_file_modes(dir_path, prefix).expect("reapply modes");

    let real_mode = fs::metadata(&real_sink)
        .expect("stat real sink")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        real_mode, 0o600,
        "real sink file must be clamped to 0600; got {real_mode:o}"
    );

    // `fs::metadata` follows symlinks, which is exactly what we want:
    // we're asserting the property of the *target*.
    let victim_mode = fs::metadata(&victim)
        .expect("stat victim")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        victim_mode, 0o644,
        "victim file reached through a planted symlink must NOT be \
         chmod'd by the sweep; got {victim_mode:o}"
    );

    // Sanity: the symlink itself still exists and still points where we
    // planted it. Failing to assert this would leave the door open for
    // a "fix" that silently deleted the symlink to sidestep the real
    // property.
    let link_target = fs::read_link(&planted).expect("read_link");
    assert_eq!(link_target, victim);
}
