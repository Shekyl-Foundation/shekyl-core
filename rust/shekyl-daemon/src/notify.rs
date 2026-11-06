// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The notify runner (`DAEMON_CONFIG_CUTOVER.md` §2.10, DC-Q14): the owner
//! of `notify-block`, `notify-reorg` and `notify-block-rate`.
//!
//! The runner fills the row's `{name}` placeholders (IG-Q5: braces are the
//! only syntax, a placeholder may sit inside an argument), runs the
//! argument array with no shell, a cleared environment, a null standard
//! input and no inherited standard output or error, and awaits each child
//! on the daemon's runtime, so every child is reaped by the process that
//! spawned it and no signal disposition changes (DC-F12). At most one
//! command is in flight per kind; an event that arrives while one runs is
//! dropped, and the drops are counted and reported in the log line the
//! running command writes when it completes.
//!
//! `notify-block` is pushed from the chain's tip watch
//! ([`shekyl_node::Node::tips`]) by [`drive_blocks`]: every publication
//! with a tip is a block event at the tip's height. `notify-reorg` and
//! `notify-block-rate` have no pusher: the C++ event sites the design
//! named never called the exports (nothing in the tree ever did), ingest's
//! deep-reorg watch carries a different shape and fires only past the lock
//! window, and no Rust monitor measures the block rate. Their rows are
//! judged and their commands never run until a pusher is ruled
//! (`docs/FOLLOWUPS.md`, the notify runner's pushers).
//!
//! The glossary terms are rendered here: `{split-height}` is the last
//! block both chains share, `{height}` on a reorg is the new tip,
//! `{window}` is in seconds.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use shekyl_daemon_config::sections::Notify;
use shekyl_node::TipChanged;
use tokio::sync::watch;

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

    /// A reorganization: the height of the first block of the new chain,
    /// the new chain's block count, the blocks added and the blocks
    /// removed. `{split-height}` is the last block both chains share and
    /// `{height}` the new tip. No pusher yet (the module's note).
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
    /// `{expected}` block counts. No pusher yet (the module's note).
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
/// standard input, and nothing of ours on its standard output or error. On
/// Windows the one variable a program needs to start, `SystemRoot`, is set
/// from the OS and never from this process's environment, the rule the Tor
/// launcher follows (`TOR_BUNDLE_DISTRIBUTION.md` TB-7 part 2).
///
/// On Unix the child inherits standard input, output and error and no other
/// descriptor ([`shekyl_tor_control_client::inherit`]): nothing this
/// process holds is the operator's command's (§2.10).
///
/// The spawn takes the spawn lock (`TOR_SUPERVISOR.md` §4.7): this runs in
/// the daemon's process, which launches the managed Tor, and on Windows a
/// child started while the launch holds Tor's end inheritable would inherit
/// it and hide Tor's death (`TSR-F16`). The lock covers the spawn alone; the
/// wait is outside it.
async fn run(argv: &[OsString]) -> std::io::Result<std::process::ExitStatus> {
    let (program, args) = argv.split_first().expect("a command has its program first");
    let mut cmd = tokio::process::Command::new(PathBuf::from(program));
    cmd.args(args)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(false);
    shekyl_tor_control_client::inherit::stdio_only(&mut cmd);
    #[cfg(windows)]
    {
        let root = shekyl_win_sec::system_dir::system_windows_directory()
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        cmd.env("SystemRoot", root);
    }
    let mut child = shekyl_tor_control_client::spawn_lock::with(|| cmd.spawn())?;
    child.wait().await
}

fn hex(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(64);
    for b in bytes {
        write!(s, "{b:02x}").expect("writing to a String cannot fail");
    }
    s
}

/// Pushes `notify-block` for every tip the chain publishes: the tip's
/// height (its count less one) and its hash. Runs until the watch's
/// sender, the node's ingest, is gone. The publication at start, and a
/// publication with no tip (an empty store before genesis connects), push
/// nothing: the operator asked to hear of blocks, not of the daemon
/// starting.
pub async fn drive_blocks(runner: Arc<Runner>, mut tips: watch::Receiver<TipChanged>) {
    // The value present at start is the chain as found, not an arrival.
    tips.mark_unchanged();
    while tips.changed().await.is_ok() {
        let Some(tip) = tips.borrow_and_update().tip else {
            continue;
        };
        let height = tip.count.to_raw().saturating_sub(1);
        runner.block(height, tip.top_id.as_bytes());
    }
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
            .block_on(async {
                let mut child = shekyl_tor_control_client::spawn_lock::with(|| {
                    tokio::process::Command::new("true").spawn()
                })?;
                child.wait().await
            })
            .expect("a sibling child reports its status");
        assert!(status.success());
    }

    /// A descriptor opened without close-on-exec, as a library in the
    /// daemon's process might open one. Closed when dropped.
    #[cfg(unix)]
    struct Planted(std::os::fd::OwnedFd);

    #[cfg(unix)]
    impl Planted {
        fn open() -> Self {
            use std::os::fd::AsRawFd;
            let fd = rustix::fs::open(
                "/dev/null",
                rustix::fs::OFlags::RDONLY,
                rustix::fs::Mode::empty(),
            )
            .expect("/dev/null opens");
            assert!(fd.as_raw_fd() >= 3, "a descriptor above stdio");
            Self(fd)
        }

        fn number(&self) -> i32 {
            use std::os::fd::AsRawFd;
            self.0.as_raw_fd()
        }
    }

    #[cfg(unix)]
    fn run_now(argv: &[&str]) -> std::process::ExitStatus {
        let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(run(&argv))
            .expect("the command runs")
    }

    /// The operator's command inherits standard input, output and error and
    /// nothing else (§2.10): a planted descriptor without close-on-exec does
    /// not reach it. Fails when [`run`] stops calling
    /// [`shekyl_tor_control_client::inherit::stdio_only`].
    #[cfg(unix)]
    #[test]
    fn the_command_does_not_inherit_a_descriptor_left_open_without_cloexec() {
        let planted = Planted::open();
        // `/dev/fd/N`, not `<&N`: dash takes only one-digit descriptor
        // numbers in a redirection, and a test process can hold ten.
        let status = run_now(&[
            "/bin/sh",
            "-c",
            &format!("test -e /dev/fd/{}", planted.number()),
        ]);
        assert!(
            !status.success(),
            "the planted descriptor reached the command"
        );
    }

    /// The whole table on Linux: every descriptor the command holds from 3 up is
    /// `ls`'s own handle on the directory it lists, so the command was handed
    /// 0, 1 and 2 only.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_command_holds_only_stdio_on_linux() {
        let _planted = Planted::open();
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("fds");
        let out_arg = out.to_str().expect("a UTF-8 temporary path");
        let status = run_now(&[
            "/bin/sh",
            "-c",
            "exec /bin/ls -l /proc/self/fd > \"$1\"",
            "sh",
            out_arg,
        ]);
        assert!(status.success(), "the listing ran");
        let listing = std::fs::read_to_string(&out).unwrap();
        let mut held = Vec::new();
        for line in listing.lines() {
            let Some((name, target)) = line.split_once(" -> ") else {
                continue;
            };
            let fd: u32 = name
                .rsplit(' ')
                .next()
                .and_then(|n| n.parse().ok())
                .expect("a descriptor number before the arrow");
            held.push(fd);
            if fd >= 3 {
                assert!(
                    target.starts_with("/proc/") && target.ends_with("/fd"),
                    "descriptor {fd} reached the command: {target}"
                );
            }
        }
        assert!(
            [0, 1, 2].iter().all(|fd| held.contains(fd)),
            "the listing names stdio: {listing}"
        );
    }

    /// **`notify-block` is pushed from the tip watch**: the tip found at
    /// start is not an event, a publication with no tip is not one, and
    /// each later tip runs the command once with the tip's height and
    /// hash. The driver ends when the publisher is gone.
    #[cfg(unix)]
    #[test]
    fn the_tip_watch_pushes_a_block_event_per_published_tip_and_not_the_start() {
        use shekyl_node::ChainTip;
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let notify = Notify {
            block: Some(vec![
                "/bin/sh".to_owned(),
                "-c".to_owned(),
                format!("printf '%s %s\\n' \"$1\" \"$2\" >> {}", out.display()),
                "sh".to_owned(),
                "{height}".to_owned(),
                "{hash}".to_owned(),
            ]),
            reorg: None,
            block_rate: None,
        };
        let runner = Arc::new(Runner::new(&notify, rt.handle().clone()));
        let tip = |count: u64, byte: u8| {
            Some(ChainTip {
                count: shekyl_types::ChainCount::from_raw(count),
                cumulative_difficulty: shekyl_difficulty::CumulativeDifficulty::ZERO,
                top_id: shekyl_types::BlockHash::from_bytes([byte; 32]),
            })
        };
        let (tx, rx) = watch::channel(TipChanged {
            seq: 0,
            tip: tip(9, 0x09),
        });
        let driver = rt.spawn(drive_blocks(Arc::clone(&runner), rx));
        let settle = |runner: &Runner| {
            for _ in 0..200 {
                if !runner.in_flight()[0] {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        };
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!out.exists(), "the tip found at start is not an event");
        tx.send_replace(TipChanged {
            seq: 1,
            tip: tip(10, 0xaa),
        });
        std::thread::sleep(std::time::Duration::from_millis(50));
        settle(&runner);
        tx.send_replace(TipChanged { seq: 2, tip: None });
        std::thread::sleep(std::time::Duration::from_millis(50));
        settle(&runner);
        tx.send_replace(TipChanged {
            seq: 3,
            tip: tip(11, 0xbb),
        });
        std::thread::sleep(std::time::Duration::from_millis(50));
        settle(&runner);
        let text = std::fs::read_to_string(&out).unwrap();
        assert_eq!(
            text,
            format!("9 {}\n10 {}\n", "aa".repeat(32), "bb".repeat(32)),
            "one event per tip, at the tip's height; none for the empty publication"
        );
        drop(tx);
        rt.block_on(async {
            tokio::time::timeout(std::time::Duration::from_secs(5), driver)
                .await
                .expect("the driver ends with its publisher")
                .expect("the driver did not panic");
        });
    }
}
