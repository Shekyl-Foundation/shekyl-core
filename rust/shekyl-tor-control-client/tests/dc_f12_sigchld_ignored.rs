// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! DC-F12 (`docs/design/DAEMON_CONFIG_CUTOVER.md` §11): a notify spawn takes
//! the managed Tor's exit status away from its reaper.
//!
//! `tools::spawn` with `wait = false` (the path every `--block-notify`,
//! `--reorg-notify` and `--block-rate-notify` event takes) sets the whole
//! process's `SIGCHLD` disposition to `SIG_IGN` (`src/common/spawn.cpp:124`).
//! Under that disposition the kernel reaps every child as it exits, so a
//! later `wait` on the managed Tor finds no child to report: the actor's
//! `child.wait()` in `TorChild::shutdown` can no longer return the status it
//! publishes as `TorExit::Reaped`.
//!
//! This test reproduces the syscall that line makes, not the C++ path: a
//! Rust test cannot link `tools::spawn`, and the defect is the disposition,
//! whichever caller sets it. It lives in a binary of its own because a
//! signal disposition is process-wide and every test in one binary shares a
//! process. The cutover's notify runner (§2.10) reaps its own children and
//! never changes a disposition; its test is the positive twin of this one.

#![cfg(unix)]

use std::time::Duration;

use tokio::process::Command;

#[test]
fn an_ignored_sigchld_takes_the_exit_status_from_a_tokio_child() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        // Control: under the default disposition the status comes back.
        let mut control =
            shekyl_tor_control_client::spawn_lock::with(|| Command::new("true").spawn())
                .expect("spawn `true` under the default disposition");
        let status = control
            .wait()
            .await
            .expect("the control child reports its status");
        assert!(
            status.success(),
            "the control child must exit cleanly: {status:?}"
        );

        // What `tools::spawn` does after it starts a notify command.
        // SAFETY: `signal(2)` with a valid signal number and the `SIG_IGN`
        // constant; it reads and writes no memory of ours. This process is
        // this test's own binary, so the disposition reaches nothing else.
        let previous = unsafe { libc::signal(libc::SIGCHLD, libc::SIG_IGN) };
        assert_ne!(previous, libc::SIG_ERR, "signal(SIGCHLD, SIG_IGN) failed");

        let mut child =
            shekyl_tor_control_client::spawn_lock::with(|| Command::new("true").spawn())
                .expect("spawn `true` under SIG_IGN");
        let outcome = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
        assert!(
            !matches!(outcome, Ok(Ok(_))),
            "with SIGCHLD ignored the kernel reaps the child itself, so wait() \
             must not return an exit status; it returned {outcome:?}"
        );
    });
}
