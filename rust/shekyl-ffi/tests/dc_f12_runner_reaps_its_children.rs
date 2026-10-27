// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! DC-F12's positive twin (`docs/design/DAEMON_CONFIG_CUTOVER.md` §11,
//! §2.10): the Rust notify runner reaps its own children and changes no
//! signal disposition, so a child spawned beside one of the runner's (the
//! managed Tor, in the daemon) still gets its exit status back from
//! `wait()`. The negative half, that the C++ path's `SIG_IGN` took that
//! status away, is `shekyl-tor-control-client`'s
//! `tests/dc_f12_sigchld_ignored.rs`. A binary of its own, as that one is:
//! a disposition is process-wide, and this test's claim is about the whole
//! process after the runner has run a command.

#![cfg(unix)]

use std::time::Duration;

use shekyl_daemon_config::sections::Notify;
use shekyl_ffi::notify_ffi::Runner;
use tokio::process::Command;

#[test]
fn a_child_spawned_beside_the_runners_still_reports_its_status() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("runtime");
    let notify = Notify {
        block: Some(vec!["/bin/true".to_owned(), "{height}".to_owned()]),
        reorg: Some(vec!["/bin/true".to_owned(), "{removed}".to_owned()]),
        block_rate: Some(vec!["/bin/true".to_owned(), "{window}".to_owned()]),
    };
    let runner = Runner::new(&notify, runtime.handle().clone());
    runner.block(1, &[0u8; 32]);
    runner.reorg(2, 4, 2, 1);
    runner.block_rate(600, 1, 5);
    for _ in 0..200 {
        if runner.in_flight() == [false; 3] {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        runner.in_flight(),
        [false; 3],
        "every command was awaited by the runner"
    );

    // The twin of the negative test's second spawn: under the disposition
    // the runner leaves in place, the status comes back.
    let status = runtime.block_on(async {
        let mut child =
            shekyl_tor_control_client::spawn_lock::with(|| Command::new("true").spawn())
                .expect("spawn `true`");
        tokio::time::timeout(Duration::from_secs(5), child.wait())
            .await
            .expect("wait() returned within the timeout")
            .expect("wait() returned a status, not ECHILD")
    });
    assert!(status.success(), "{status:?}");
}
