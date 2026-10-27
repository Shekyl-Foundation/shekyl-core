// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What one INBOUND connection costs a node (`PWD-I7`, rule 76).
//!
//! The per-host inbound cap was deleted 2026-09-22. The ceiling that replaced
//! it is derived from the process descriptor limit (`InboundCeiling`), not
//! from a memory constant. This rig is why: memory does not bind. A quiescent
//! inbound connection was free in RSS on the floor device, so the safety
//! bound counts descriptors.
//!
//! **This is the instrument, not a number that ships.** It prints a table.
//! Rule 76 expects the floor to move; the rig stays re-runnable so a later
//! measurement can be compared with the one that selected descriptors.
//!
//! **Two arms** (`DAEMON_RELAY_PRIVACY.md` §80.4, rule 76 item 3): run it on
//! the floor device and on a development machine, and record the ratio.
//! Cross-machine ratios are measured, never assumed.
//!
//! ```bash
//! SHEKYLD_BIN=/abs/path/build/bin/shekyld \
//!   cargo test -p shekyl-levin --test inbound_cost_bench -- --ignored --nocapture
//! ```
//!
//! Three costs the table records. Memory was measured and does not bind;
//! descriptors are what the safety bound uses:
//!
//!   * **`VmRSS`** — steady-state resident set, the term a ceiling is usually
//!     derived against.
//!   * **`VmHWM`** — peak resident set since start. Q12-R14 measured daemon
//!     startup at roughly twice steady state, so the binding constraint may be
//!     a transient rather than the plateau, and a ceiling derived from `VmRSS`
//!     alone would be derived against the wrong number.
//!   * **open descriptors** — one socket per inbound connection, against
//!     `RLIMIT_NOFILE`. This is a configuration bound rather than a hardware
//!     one, so it is reported separately and never folded into the memory
//!     figure.
//!
//! # This rig measures per-connection COST, not inbound CAPACITY — and it
//! # cannot be made to measure capacity, because it runs over loopback
//!
//! **An accepted socket's uniqueness comes from the REMOTE endpoint.** A
//! listener's connections are distinguished by `(remote_ip, remote_port)`, so
//! accepting consumes no local ephemeral port — inbound capacity is not
//! bounded by the source-port range. But when both sides share `127.0.0.1`,
//! every connection burns a *client* source port, and **the client's
//! ephemeral range becomes the binding constraint long before anything about
//! accepting is exercised.**
//!
//! That is not a theoretical hazard. Measured on Windows 2026-09-22 while
//! answering a different question: a loopback run failed at **15,306
//! connections with `WSAENOBUFS`** — an error whose documented meaning is
//! buffer/pool exhaustion — and instrumenting showed non-paged pool had moved
//! **8.5 MB with 35 GB free**, while **15,422 of 16,384 ephemeral ports** were
//! gone. The error code named one mechanism and the measurement found
//! another. Reading the cause off the error would have filed *"system pool
//! bounds connections at ~15k"*, which is an artifact of the instrument and
//! says nothing about inbound.
//!
//! **So: never sweep this rig toward the ephemeral-port range and read the
//! stall as a property of the daemon.** The ranges are roughly 28k on Linux
//! (`net.ipv4.ip_local_port_range`) and 16k on Windows. `STEPS` stays orders
//! of magnitude below that deliberately, which is what keeps the *cost*
//! measurement valid; a capacity measurement needs multiple source addresses
//! and is a different instrument.
//!
//! Each simulated peer completes a real `COMMAND_HANDSHAKE` and then services
//! its socket, because a connection the daemon has dropped costs nothing and
//! would measure as a free peer.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

mod live_daemon;
use live_daemon::{spawn_peer, Daemon};

/// Inbound counts to sample. The first is the baseline; every later row's
/// marginal cost is taken against its predecessor, so a non-linear term shows
/// up as a drifting per-connection figure rather than hiding in an average.
const STEPS: &[usize] = &[0, 16, 32, 64, 128];

// ---------------------------------------------------------------------------
// Process sampling
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct Sample {
    rss_kib: u64,
    hwm_kib: u64,
    /// Exact open-descriptor count, or `None` when `/proc/<pid>/fd` is not
    /// readable. **Never zero as a stand-in for unknown**: reading `fd/`
    /// needs `PTRACE_MODE_READ`, which a hardened `/proc` or a sandbox
    /// refuses even for one's own child, and a silent `0` there would report
    /// "descriptors are free" when the truth is "not measured".
    fds: Option<usize>,
    /// Allocated fd-table slots from `status`, which needs no ptrace. A
    /// power-of-two ceiling rather than a count, so it bounds `fds` from
    /// above and is the fallback when the exact count is unavailable.
    fd_slots: u64,
}

fn sample(pid: u32) -> Sample {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).expect("read status");
    let field = |name: &str| -> u64 {
        status
            .lines()
            .find(|l| l.starts_with(name))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    };
    let fds = std::fs::read_dir(format!("/proc/{pid}/fd"))
        .map(std::iter::Iterator::count)
        .ok();
    Sample {
        rss_kib: field("VmRSS:"),
        hwm_kib: field("VmHWM:"),
        fds,
        fd_slots: field("FDSize:"),
    }
}

// ---------------------------------------------------------------------------
// Daemon under measurement
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// The bench
// ---------------------------------------------------------------------------

#[ignore = "measurement rig: requires SHEKYLD_BIN; spawns a live daemon and many sockets"]
#[test]
fn inbound_connection_cost_table() {
    let daemon = Daemon::start("inbound_cost_bench");
    let pid = daemon.pid();

    // Let the daemon settle before the baseline: a sample taken while startup
    // allocation is still in flight attributes startup cost to connection 1.
    std::thread::sleep(Duration::from_secs(5));

    println!("\n=== inbound connection cost — {} ===", host_label());
    println!(
        "SHEKYLD_BIN={:?}",
        std::env::var("SHEKYLD_BIN").unwrap_or_default()
    );
    println!(
        "{:>6}  {:>6}  {:>10}  {:>10}  {:>8}  {:>8}   {:>14}",
        "n_req", "live", "VmRSS KiB", "VmHWM KiB", "fds", "fd_slots", "marg RSS KiB"
    );

    let stop = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::new();
    let mut prev: Option<(usize, Sample)> = None;

    for &n in STEPS {
        while handles.len() < n {
            handles.push(spawn_peer(
                daemon.p2p_port,
                Arc::clone(&stop),
                Arc::new(AtomicBool::new(false)),
            ));
            std::thread::sleep(Duration::from_millis(25));
        }
        // Settle: buffers allocate on use, not on accept.
        std::thread::sleep(Duration::from_secs(10));

        // Count peers still connected. The table's `n_req` is what was
        // LAUNCHED; a peer the daemon dropped costs nothing, so dividing by
        // `n_req` would understate the per-connection figure. Marginals are
        // taken against `live`.
        let live = handles.iter().filter(|h| !h.is_finished()).count();
        let s_now = sample(pid);
        let mr = match prev {
            Some((plive, ps)) if live > plive => {
                let dn = i64::try_from(live - plive).unwrap_or(1).max(1);
                let d_rss = i64::try_from(s_now.rss_kib).unwrap_or(0)
                    - i64::try_from(ps.rss_kib).unwrap_or(0);
                tenths(d_rss * 10 / dn)
            }
            _ => "-".into(),
        };
        println!(
            "{n:>6}  {live:>6}  {:>10}  {:>10}  {:>8}  {:>8}   {:>14}",
            s_now.rss_kib,
            s_now.hwm_kib,
            s_now
                .fds
                .map_or_else(|| "n/a".to_string(), |v| v.to_string()),
            s_now.fd_slots,
            mr
        );
        prev = Some((live, s_now));
    }

    stop.store(true, Ordering::Relaxed);
    println!(
        "\nfds `n/a` means /proc/<pid>/fd was not readable -- it needs\n\
         PTRACE_MODE_READ, which a hardened /proc or a sandbox refuses even\n\
         for one's own child. It is NOT zero; fd_slots (FDSize, no ptrace\n\
         required) is the readable upper bound in that case."
    );
    println!(
        "NOTE: VmHWM is the peak since start. If it exceeds the final VmRSS by\n\
         more than the table's total growth, the binding constraint is STARTUP,\n\
         not steady state, and the ceiling must be derived against the peak.\n\
         Record BOTH arms (floor device and dev machine) and the ratio: rule 76\n\
         item 3 — cross-machine ratios are measured, never assumed.\n"
    );
}

/// Render tenths of a unit without a float cast (`x` is value * 10).
fn tenths(x: i64) -> String {
    format!("{}.{}", x / 10, (x % 10).abs())
}

fn host_label() -> String {
    let model = std::fs::read_to_string("/proc/device-tree/model")
        .map(|s| s.trim_end_matches('\0').trim().to_string())
        .unwrap_or_default();
    if model.is_empty() {
        std::fs::read_to_string("/proc/cpuinfo")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("model name"))
                    .map(|l| l.split(':').nth(1).unwrap_or("").trim().to_string())
            })
            .unwrap_or_else(|| "unknown".into())
    } else {
        model
    }
}
