// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The full-disk gate's clocks, and the live walk that fills a small disk.
//!
//! A `#[path]` child of the regtest harness. The production debug-macro
//! lint treats a file as test code only when the file itself carries this
//! attribute.
//!
//! Two clocks bind every mine call. The disk window is how long the
//! filesystem has to fill. A refusal run opens on the first refused or
//! timed-out call and closes on the first success; while it is open the
//! call in flight is cut to the time the run has left. The process
//! exiting is taken ahead of either clock.

#![cfg(test)]

use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use super::{log_tail, try_generate_blocks, HttpRpc, PathBuf, RegtestDaemon, RegtestSpawn};
#[cfg(target_os = "linux")]
use std::process::{Child, ExitStatus};

/// How long the disk has to fill, from the start of the walk.
const WITHIN: Duration = Duration::from_secs(30 * 60);

/// How long the daemon may stay up once mining is refused without a
/// break. A daemon that ends itself is gone in well under a second; the
/// half-up node of 2026-11-02 stayed 34 minutes.
const UP_AFTER_REFUSAL: Duration = Duration::from_secs(120);

/// Gap between refused calls, so a fast refusal does not spin the RPC.
/// Never longer than the run has left.
const PAUSE_AFTER_REFUSAL: Duration = Duration::from_millis(500);

const _: () = assert!(PAUSE_AFTER_REFUSAL.as_millis() < UP_AFTER_REFUSAL.as_millis());

/// Blocks per call. Small, so a call on a loaded host stays inside the
/// harness's HTTP timeout.
#[cfg(target_os = "linux")]
const CHUNK: u64 = 8;

/// More blocks than the largest accepted filesystem holds: a block adds
/// about 6.4 KiB to the store (measured 2026-11-11, 537 blocks).
#[cfg(target_os = "linux")]
const MINE_AT_MOST: u64 = 2_000;

/// How often a wait polls the daemon process. `std::process::Child` has
/// no async wait; this is the cadence of the race against the mine call.
#[cfg(target_os = "linux")]
const DAEMON_POLL: Duration = Duration::from_millis(100);

/// The largest filesystem the full-disk gate accepts.
#[cfg(target_os = "linux")]
const SMALL_DISK_AT_MOST_KIB: u64 = 2 * 1024;

/// One unbroken run of refused mining calls.
///
/// `started` is the first refusal and does not move. `answer` is the
/// latest answer, kept for the verdict if the run outlives its bound.
struct RefusalRun {
    started: Instant,
    answer: String,
}

impl RefusalRun {
    fn begin(answer: String, now: Instant) -> Self {
        Self {
            started: now,
            answer,
        }
    }

    /// A later refusal of this same run. The start does not move.
    fn with_later_answer(mut self, answer: String) -> Self {
        self.answer = answer;
        self
    }

    fn remaining(&self, now: Instant) -> Duration {
        UP_AFTER_REFUSAL.saturating_sub(now.saturating_duration_since(self.started))
    }

    fn pause(&self, now: Instant) -> Duration {
        PAUSE_AFTER_REFUSAL.min(self.remaining(now))
    }
}

/// Which clock cuts the mine call about to be made, and how long it may sit.
#[derive(Clone, Copy)]
enum CallBudget {
    /// No refusal run is open, or the disk window ends first.
    Disk(Duration),
    /// A refusal run is open and it ends first, the call in flight included.
    Refusal(Duration),
}

/// The disk window and, once mining has been refused, the run that must
/// end it. A success drops the run. The budget is derived from the two,
/// so a caller cannot wait on one and report the other.
struct Clocks {
    disk_full_by: Instant,
    refusal: Option<RefusalRun>,
}

impl Clocks {
    fn starting_at(now: Instant) -> Self {
        Self::until(now + WITHIN)
    }

    fn until(disk_full_by: Instant) -> Self {
        Self {
            disk_full_by,
            refusal: None,
        }
    }

    /// The earlier end. When the two ends coincide, the refusal run is
    /// the verdict: mining has already failed.
    fn budget(&self, now: Instant) -> CallBudget {
        let until_disk = self.disk_full_by.saturating_duration_since(now);
        match &self.refusal {
            Some(run) => {
                let left = run.remaining(now);
                if left <= until_disk {
                    CallBudget::Refusal(left)
                } else {
                    CallBudget::Disk(until_disk)
                }
            }
            None => CallBudget::Disk(until_disk),
        }
    }

    fn mined(&mut self) {
        self.refusal = None;
    }

    /// Record a refusal and return how long to wait before the next call.
    fn refused(&mut self, answer: String, now: Instant) -> Duration {
        let open = match self.refusal.take() {
            Some(open) => open.with_later_answer(answer),
            None => RefusalRun::begin(answer, now),
        };
        let pause = open.pause(now);
        self.refusal = Some(open);
        pause
    }

    fn refusal_answer(&self) -> Option<&str> {
        self.refusal.as_ref().map(|run| run.answer.as_str())
    }
}

/// What one raced mine call came to.
#[cfg(target_os = "linux")]
enum MineWait {
    Exited(ExitStatus),
    Mined,
    Refused(String),
    /// The budget elapsed. The child was polled again after the sleep,
    /// and it was still up.
    Budget(CallBudget),
}

/// Poll until the child has exited. Reaped here, and not polled again
/// by the caller that receives the status.
#[cfg(target_os = "linux")]
async fn child_exited(child: &mut Child) -> ExitStatus {
    loop {
        if let Some(status) = child.try_wait().expect("wait for the daemon") {
            return status;
        }
        tokio::time::sleep(DAEMON_POLL).await;
    }
}

/// One mine call, raced against the child and against `budget`.
///
/// A zero budget never starts the call. When the budget's sleep wins,
/// the child is polled once more before the budget is reported: an exit
/// during the last poll gap is the process ending, and that verdict
/// comes first.
#[cfg(target_os = "linux")]
async fn wait_for_mine(child: &mut Child, rpc: &HttpRpc, budget: CallBudget) -> MineWait {
    let (CallBudget::Disk(limit) | CallBudget::Refusal(limit)) = budget;
    if limit.is_zero() {
        return match child.try_wait().expect("wait for the daemon") {
            Some(status) => MineWait::Exited(status),
            None => MineWait::Budget(budget),
        };
    }
    // `biased`: an exit and a spent budget can be ready together, and
    // the exit is the verdict. The call is the middle arm so a returned
    // answer is taken ahead of the sleep when both complete at once.
    let step = tokio::select! {
        biased;
        status = child_exited(child) => Step::Exited(status),
        result = try_generate_blocks(rpc, CHUNK) => Step::Answer(result),
        () = tokio::time::sleep(limit) => Step::Slept,
    };
    match step {
        Step::Exited(status) => MineWait::Exited(status),
        Step::Answer(Ok(_)) => MineWait::Mined,
        Step::Answer(Err(error)) => MineWait::Refused(format!("{error:?}")),
        Step::Slept => match child.try_wait().expect("wait for the daemon") {
            Some(status) => MineWait::Exited(status),
            None => MineWait::Budget(budget),
        },
    }
}

#[cfg(target_os = "linux")]
enum Step {
    Exited(ExitStatus),
    Answer(Result<super::GenerateBlocksResp, shekyl_rpc_client::RpcError>),
    Slept,
}

/// The pause between refused calls, ended early when the process does.
#[cfg(target_os = "linux")]
async fn exit_during(child: &mut Child, pause: Duration) -> Option<ExitStatus> {
    if pause.is_zero() {
        return child.try_wait().expect("wait for the daemon");
    }
    let step = tokio::select! {
        biased;
        status = child_exited(child) => Pause::Exited(status),
        () = tokio::time::sleep(pause) => Pause::Slept,
    };
    match step {
        Pause::Exited(status) => Some(status),
        Pause::Slept => child.try_wait().expect("wait for the daemon"),
    }
}

#[cfg(target_os = "linux")]
enum Pause {
    Exited(ExitStatus),
    Slept,
}

/// The filesystem the full-disk gate fills: the directory `SHEKYL_SMALL_DISK`
/// names, which must be the mount point of a filesystem no larger than
/// [`SMALL_DISK_AT_MOST_KIB`]. The daemon reads no environment; this is
/// the test's own input, as `SHEKYLD_BIN` is. CI mounts that filesystem
/// on the job; a hand run sets the variable.
///
/// A directory on a large disk would make the gate mine until its block
/// bound and fail there, long after the cause, so the size is asserted
/// first (rule 47).
#[cfg(target_os = "linux")]
fn small_disk() -> PathBuf {
    let dir = PathBuf::from(std::env::var_os("SHEKYL_SMALL_DISK").expect(
        "SHEKYL_SMALL_DISK not set. It names the mount point of a filesystem \
         of at most 2 MiB, for a hand run of this gate",
    ));
    let output = shekyl_tor_control_client::spawn_lock::output(
        std::process::Command::new("df").arg("-Pk").arg(&dir),
    )
    .expect("run df");
    assert!(output.status.success(), "df {}: {output:?}", dir.display());
    let table = String::from_utf8(output.stdout).expect("df prints utf-8");
    let row: Vec<&str> = table
        .lines()
        .nth(1)
        .unwrap_or_else(|| panic!("df printed no row: {table}"))
        .split_whitespace()
        .collect();
    let size_kib: u64 = row
        .get(1)
        .and_then(|blocks| blocks.parse().ok())
        .unwrap_or_else(|| panic!("df's size column: {table}"));
    assert_eq!(
        row.last().copied(),
        dir.to_str(),
        "SHEKYL_SMALL_DISK is not a filesystem's mount point: {table}"
    );
    assert!(
        size_kib <= SMALL_DISK_AT_MOST_KIB,
        "the filesystem at {} holds {size_kib} KiB, more than the {SMALL_DISK_AT_MOST_KIB} KiB \
         the gate fills in its block bound",
        dir.display()
    );
    dir
}

/// **A full disk stops the daemon, and it says so when it happens**
/// (the CS-5 rehearsal of 2026-11-02). There a store commit met
/// `ENOSPC`, the ingest service stopped, and the daemon stayed up: nothing
/// was logged, `daemon_status` answered from the old height, and the one record
/// printed 34 minutes later at SIGTERM.
///
/// The daemon's chain is on a small filesystem and its log is not. The
/// test mines until a commit fails. It sends no signal. The daemon must
/// then, on its own: log the fault at `error` when the service records it,
/// log that it stops on it, and exit with a failure status.
///
/// The walk fails on its own in two other ways, both while the process is
/// still up. The disk never fills: [`WITHIN`], or [`MINE_AT_MOST`] blocks.
/// Mining is refused without a break: the refusal run ends at
/// [`UP_AFTER_REFUSAL`], and that bound is the mine call's own budget, so
/// a call that keeps its socket open cannot outlive the run. One refused
/// or timed-out call is not that failure. A call that succeeds drops the
/// run, so a single timeout on a loaded host is not the verdict. The
/// process exiting is; the log is then read.
///
/// No lever: the daemon is the released binary under its released options,
/// and the disk is really full.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "Track-2 regtest: requires SHEKYLD_BIN and SHEKYL_SMALL_DISK; spawns a live daemon"]
async fn a_full_disk_stops_the_daemon_with_an_error_line_and_a_failed_exit() {
    const RECORDED: &str = "the ingest service stops on a fault: ";
    const STOPS: &str = "the ingest service stopped: ";
    let disk = small_disk();
    let serial = super::serial_lock().lock_owned().await;
    let mut daemon = RegtestDaemon::spawn(
        RegtestSpawn::new(Some(serial)).with_chain_dir(disk.join("full-disk-gate")),
    )
    .await;
    let mut clocks = Clocks::starting_at(Instant::now());
    let mut mined = 0u64;
    let status = loop {
        if mined >= MINE_AT_MOST {
            if let Some(status) = daemon.child.try_wait().expect("wait for the daemon") {
                break status;
            }
            panic!(
                "mined {mined} blocks and the disk at {} never filled",
                disk.display()
            );
        }
        match wait_for_mine(
            &mut daemon.child,
            &daemon.rpc,
            clocks.budget(Instant::now()),
        )
        .await
        {
            MineWait::Exited(status) => break status,
            MineWait::Mined => {
                mined += CHUNK;
                clocks.mined();
            }
            MineWait::Refused(answer) => {
                let pause = clocks.refused(answer, Instant::now());
                if let Some(status) = exit_during(&mut daemon.child, pause).await {
                    break status;
                }
            }
            MineWait::Budget(CallBudget::Refusal(_)) => {
                let answer = clocks
                    .refusal_answer()
                    .expect("a refusal budget is an open run");
                panic!(
                    "the daemon has refused to mine for {UP_AFTER_REFUSAL:?} ({answer}) after \
                     {mined} blocks and is still up: a half-up node. Its log tail:\n{}",
                    log_tail(&daemon.data_dir.join("shekyld.log"))
                );
            }
            MineWait::Budget(CallBudget::Disk(_)) => {
                panic!(
                    "{WITHIN:?} on, the daemon is still up with {mined} blocks mined: the disk at {} \
                     did not fill. Its log tail:\n{}",
                    disk.display(),
                    log_tail(&daemon.data_dir.join("shekyld.log"))
                );
            }
        }
    };
    let log_path = daemon.data_dir.join("shekyld.log");
    let log = std::fs::read_to_string(&log_path).expect("the daemon's log");
    let tail = log_tail(&log_path);
    assert!(
        !status.success(),
        "the daemon exited {status} after its disk filled; a failure status was owed. Tail:\n{tail}"
    );
    let recorded = log
        .lines()
        .find(|line| line.contains(RECORDED))
        .unwrap_or_else(|| panic!("no line records the fault ({RECORDED:?}). Tail:\n{tail}"));
    assert!(
        recorded.contains("ERROR"),
        "the fault is recorded below `error`: {recorded}"
    );
    assert!(
        recorded.contains("No space left on device"),
        "the fault recorded is not the full disk: {recorded}"
    );
    let stops = log
        .lines()
        .find(|line| line.contains(STOPS))
        .unwrap_or_else(|| {
            panic!("no line says the daemon stops on it ({STOPS:?}). Tail:\n{tail}")
        });
    assert!(
        stops.contains("ERROR") && stops.contains("; the daemon stops"),
        "the stop line: {stops}"
    );
}

#[test]
fn a_success_drops_the_refusal_run_and_the_disk_window_binds_again() {
    let now = Instant::now();
    let mut clocks = Clocks::starting_at(now);
    assert!(matches!(clocks.budget(now), CallBudget::Disk(left) if left == WITHIN));

    let later = now + Duration::from_secs(30);
    let _ = clocks.refused("mine.stopping".to_string(), now);
    let _ = clocks.refused("timed out".to_string(), later);
    // The run keeps its start and takes the latest answer: the verdict
    // quotes what the daemon said last.
    assert_eq!(clocks.refusal_answer(), Some("timed out"));
    let refusal_left = UP_AFTER_REFUSAL
        .checked_sub(Duration::from_secs(30))
        .expect("30s fits in the refusal bound");
    assert!(matches!(
        clocks.budget(later),
        CallBudget::Refusal(left) if left == refusal_left
    ));

    clocks.mined();
    assert_eq!(clocks.refusal_answer(), None, "a success closes the run");
    let disk_left = WITHIN
        .checked_sub(Duration::from_secs(30))
        .expect("30s fits in the disk window");
    assert!(matches!(
        clocks.budget(later),
        CallBudget::Disk(left) if left == disk_left
    ));
}

#[test]
fn an_open_refusal_run_cuts_the_call_to_the_time_it_has_left() {
    let now = Instant::now();
    let mut clocks = Clocks::until(now + Duration::from_secs(3_600));
    let _ = clocks.refused("mine.stopping".to_string(), now);
    let almost = now
        + UP_AFTER_REFUSAL
            .checked_sub(Duration::from_secs(1))
            .expect("1s fits in the refusal bound");
    assert!(
        matches!(clocks.budget(almost), CallBudget::Refusal(left) if left == Duration::from_secs(1))
    );

    let at_end = now + UP_AFTER_REFUSAL;
    assert!(matches!(clocks.budget(at_end), CallBudget::Refusal(left) if left.is_zero()));
    let past = at_end + Duration::from_secs(1);
    assert!(matches!(clocks.budget(past), CallBudget::Refusal(left) if left.is_zero()));
}

#[test]
fn the_disk_window_binds_when_it_ends_before_the_refusal_run() {
    let now = Instant::now();
    let mut clocks = Clocks::until(now + Duration::from_secs(10));
    let _ = clocks.refused("mine.stopping".to_string(), now);
    assert!(
        matches!(clocks.budget(now), CallBudget::Disk(left) if left == Duration::from_secs(10))
    );
}

#[test]
fn the_pause_after_a_refusal_stops_at_the_end_of_the_run() {
    let now = Instant::now();
    let mut clocks = Clocks::starting_at(now);
    assert_eq!(
        clocks.refused("mine.stopping".to_string(), now),
        PAUSE_AFTER_REFUSAL
    );
    let near_end = (now + UP_AFTER_REFUSAL)
        .checked_sub(Duration::from_millis(100))
        .expect("100ms fits in the refusal bound");
    assert_eq!(
        clocks.refused("mine.stopping".to_string(), near_end),
        Duration::from_millis(100)
    );
}
