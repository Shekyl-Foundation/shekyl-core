// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The notify runner (`DAEMON_CONFIG_CUTOVER.md` §2.10, DC-Q14): the owner
//! of `notify-block`, `notify-reorg` and `notify-block-rate`.
//!
//! Each C++ event site pushes the event's facts through one export per
//! kind and returns at once; the chain path never waits on a child. The
//! runner fills the row's `{name}` placeholders (IG-Q5: braces are the only
//! syntax, a placeholder may sit inside an argument), runs the argument
//! array with no shell, a cleared environment, a null standard input and
//! no inherited standard output or error, and awaits each child on the
//! daemon's runtime, so every child is reaped by the process that spawned
//! it and no signal disposition changes (DC-F12). At most one command is in
//! flight per kind; an event that arrives while one runs is dropped, and
//! the drops are counted and reported in the log line the running command
//! writes when it completes.
//!
//! The glossary terms are rendered here, from the facts the C++ holds:
//! `{split-height}` is the last block both chains share, `{height}` on a
//! reorg is the new tip, `{window}` is in seconds.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use shekyl_daemon_config::sections::Notify;

/// The three event kinds, one command each.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Block,
    Reorg,
    BlockRate,
}

impl Kind {
    const fn name(self) -> &'static str {
        match self {
            Self::Block => "notify-block",
            Self::Reorg => "notify-reorg",
            Self::BlockRate => "notify-block-rate",
        }
    }
}

/// One kind's command and its in-flight state.
struct Slot {
    command: Vec<String>,
    in_flight: AtomicBool,
    dropped: AtomicU64,
}

/// The runner: the configured commands and the runtime their children
/// run on.
pub struct Runner {
    slots: [Option<Arc<Slot>>; 3],
    handle: tokio::runtime::Handle,
}

impl Runner {
    /// A runner over the notify section, spawning on `handle`.
    #[must_use]
    pub fn new(notify: &Notify, handle: tokio::runtime::Handle) -> Self {
        let slot = |command: &Option<Vec<String>>| {
            command.as_ref().map(|c| {
                Arc::new(Slot {
                    command: c.clone(),
                    in_flight: AtomicBool::new(false),
                    dropped: AtomicU64::new(0),
                })
            })
        };
        Self {
            slots: [
                slot(&notify.block),
                slot(&notify.reorg),
                slot(&notify.block_rate),
            ],
            handle,
        }
    }

    /// A new block: `{height}`, `{hash}`.
    pub fn block(&self, height: u64, hash: &[u8; 32]) {
        self.push(
            Kind::Block,
            &[("height", height.to_string()), ("hash", hex(hash))],
        );
    }

    /// A reorganization, from the C++ facts: the height of the first block
    /// of the new chain, the new chain's block count, the blocks added and
    /// the blocks removed. `{split-height}` is the last block both chains
    /// share and `{height}` the new tip.
    pub fn reorg(&self, first_new: u64, count: u64, added: u64, removed: u64) {
        self.push(
            Kind::Reorg,
            &[
                ("split-height", first_new.saturating_sub(1).to_string()),
                ("height", count.saturating_sub(1).to_string()),
                ("added", added.to_string()),
                ("removed", removed.to_string()),
            ],
        );
    }

    /// A block-rate warning: `{window}` in seconds, `{observed}` and
    /// `{expected}` block counts.
    pub fn block_rate(&self, window_s: u32, observed: u64, expected: u64) {
        self.push(
            Kind::BlockRate,
            &[
                ("window", window_s.to_string()),
                ("observed", observed.to_string()),
                ("expected", expected.to_string()),
            ],
        );
    }

    /// Whether a command of this kind is running now.
    #[must_use]
    pub fn in_flight(&self) -> [bool; 3] {
        let state = |s: &Option<Arc<Slot>>| {
            s.as_ref()
                .is_some_and(|s| s.in_flight.load(Ordering::SeqCst))
        };
        [
            state(&self.slots[0]),
            state(&self.slots[1]),
            state(&self.slots[2]),
        ]
    }

    fn push(&self, kind: Kind, fills: &[(&str, String)]) {
        let Some(slot) = &self.slots[kind as usize] else {
            return;
        };
        if slot.in_flight.swap(true, Ordering::SeqCst) {
            slot.dropped.fetch_add(1, Ordering::SeqCst);
            return;
        }
        let argv = fill(&slot.command, fills);
        let slot = Arc::clone(slot);
        self.handle.spawn(async move {
            let outcome = run(&argv).await;
            let dropped = slot.dropped.swap(0, Ordering::SeqCst);
            match outcome {
                Ok(status) => tracing::info!(
                    target: "notify",
                    "{} ran {}: {status}; {dropped} event(s) dropped while it ran",
                    kind.name(),
                    argv[0].to_string_lossy()
                ),
                Err(e) => tracing::warn!(
                    target: "notify",
                    "{} could not run {}: {e}; {dropped} event(s) dropped meanwhile",
                    kind.name(),
                    argv[0].to_string_lossy()
                ),
            }
            slot.in_flight.store(false, Ordering::SeqCst);
        });
    }
}

/// The argument array with every `{name}` replaced by its fill, in every
/// argument including the program's path.
fn fill(command: &[String], fills: &[(&str, String)]) -> Vec<OsString> {
    command
        .iter()
        .map(|arg| {
            let mut out = arg.clone();
            for (name, value) in fills {
                out = out.replace(&format!("{{{name}}}"), value);
            }
            OsString::from(out)
        })
        .collect()
}

/// Runs one filled command to completion: no shell, no environment, a null
/// standard input, and nothing of ours on its standard output or error.
async fn run(argv: &[OsString]) -> std::io::Result<std::process::ExitStatus> {
    let (program, args) = argv.split_first().expect("a command has its program first");
    let mut cmd = tokio::process::Command::new(PathBuf::from(program));
    cmd.args(args)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(false);
    cmd.status().await
}

fn hex(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(64);
    for b in bytes {
        write!(s, "{b:02x}").expect("writing to a String cannot fail");
    }
    s
}

static RUNNER: OnceLock<Mutex<Option<Runner>>> = OnceLock::new();

fn runner() -> &'static Mutex<Option<Runner>> {
    RUNNER.get_or_init(|| Mutex::new(None))
}

fn with_runner(f: impl FnOnce(&Runner)) {
    if let Some(r) = runner()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
    {
        f(r);
    }
}

/// Installs the runner the exports push to: the daemon's Rust `main()`
/// calls this once from the notify section, before the core exists. A
/// second install replaces the first; the children of the first finish on
/// their own.
pub fn install(notify: &Notify, handle: tokio::runtime::Handle) {
    *runner()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Runner::new(notify, handle));
}

/// A new block at `height` with the 32-byte `hash`. Returns at once; a
/// null `hash` is ignored.
///
/// # Safety
///
/// `hash` is null or points at 32 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_notify_block(height: u64, hash: *const u8) {
    if hash.is_null() {
        return;
    }
    // SAFETY: the caller's contract above.
    let hash: &[u8; 32] = unsafe { &*hash.cast::<[u8; 32]>() };
    with_runner(|r| r.block(height, hash));
}

/// A reorganization: the height of the first block of the new chain, the
/// new chain's block count, the blocks added and the blocks removed. The
/// runner renders the glossary terms from these. Returns at once.
#[no_mangle]
pub extern "C" fn shekyl_notify_reorg(first_new: u64, count: u64, added: u64, removed: u64) {
    with_runner(|r| r.reorg(first_new, count, added, removed));
}

/// A block-rate warning over a window of `window_s` seconds in which
/// `observed` blocks arrived where `expected` were due. Returns at once.
#[no_mangle]
pub extern "C" fn shekyl_notify_block_rate(window_s: u32, observed: u64, expected: u64) {
    with_runner(|r| r.block_rate(window_s, observed, expected));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholders_are_filled_inside_any_argument_and_elsewhere_left_alone() {
        let argv = fill(
            &[
                "/bin/prog".to_owned(),
                "{height}".to_owned(),
                "--hash={hash}".to_owned(),
                "{height}-{height}".to_owned(),
                "literal".to_owned(),
            ],
            &[("height", "7".to_owned()), ("hash", "ab".to_owned())],
        );
        let shown: Vec<String> = argv
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(shown, ["/bin/prog", "7", "--hash=ab", "7-7", "literal"]);
    }

    #[test]
    fn the_reorg_terms_are_the_glossarys() {
        // First new block at 10 and a new count of 13: the last shared block
        // is 9, the new tip 12.
        let argv = fill(
            &[
                "/p".to_owned(),
                "{split-height}".to_owned(),
                "{height}".to_owned(),
            ],
            &[("split-height", 9.to_string()), ("height", 12.to_string())],
        );
        assert_eq!(argv[1], "9");
        assert_eq!(argv[2], "12");
    }

    #[test]
    fn an_unconfigured_kind_and_a_missing_runner_are_quiet() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let runner = Runner::new(&Notify::default(), rt.handle().clone());
        runner.block(1, &[0; 32]);
        runner.reorg(1, 2, 1, 0);
        runner.block_rate(600, 1, 5);
        assert_eq!(runner.in_flight(), [false; 3]);
        // The exports before any install: nothing to push to, nothing
        // happens.
        shekyl_notify_reorg(1, 2, 1, 0);
        shekyl_notify_block_rate(600, 1, 5);
    }

    /// The runner's children: no shell, the environment cleared, the
    /// placeholders filled, one in flight per kind with the overflow
    /// counted; and the DC-F12 twin, that a child spawned beside the
    /// runner's still reports its status, because the runner reaps its
    /// own and changes no disposition.
    #[cfg(unix)]
    #[test]
    fn children_run_filled_without_a_shell_or_an_environment_one_in_flight_per_kind() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        // The command is a shell by the operator's choice, which is the one
        // way a test can observe the environment the child was given; the
        // runner itself adds no shell: the program is argv[0].
        let script = format!(
            "printf '%s %s inherited=%s\\n' \"$1\" \"$2\" \"$(env | grep -c -E '^(HOME|PATH|USER|LANG)=')\" >> {}; sleep 0.3",
            out.display()
        );
        let notify = Notify {
            block: Some(vec![
                "/bin/sh".to_owned(),
                "-c".to_owned(),
                script,
                "sh".to_owned(),
                "{height}".to_owned(),
                "h={hash}".to_owned(),
            ]),
            reorg: None,
            block_rate: None,
        };
        let runner = Runner::new(&notify, rt.handle().clone());
        let hash = [0xabu8; 32];
        runner.block(5, &hash);
        // While the first runs, two more arrive and are dropped.
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert_eq!(runner.in_flight(), [true, false, false]);
        runner.block(6, &hash);
        runner.block(7, &hash);
        for _ in 0..100 {
            if !runner.in_flight()[0] {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_eq!(runner.in_flight(), [false; 3], "the child was awaited");
        let text = std::fs::read_to_string(&out).unwrap();
        assert_eq!(
            text,
            format!("5 h={} inherited=0\n", "ab".repeat(32)),
            "one run, the placeholders filled, nothing of ours in the environment"
        );
        assert_eq!(
            runner.slots[0]
                .as_ref()
                .unwrap()
                .dropped
                .load(Ordering::SeqCst),
            0,
            "reported and cleared"
        );

        // After the first completes, the next event runs again.
        runner.block(8, &hash);
        for _ in 0..100 {
            if !runner.in_flight()[0] {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let text = std::fs::read_to_string(&out).unwrap();
        assert_eq!(text.lines().count(), 2);

        // DC-F12's positive twin: a child spawned beside the runner's gets
        // its status back, so nothing reaped it from under us.
        let status = rt
            .block_on(async { tokio::process::Command::new("true").status().await })
            .expect("a sibling child reports its status");
        assert!(status.success());
    }
}
