# `BA-T5` session 3: the `SH-3` confirming block — the shipped priority mechanism beside a syncing daemon, in two scheduler topologies. Floor run of 2026-10-12 (a discovery run)

**State of this record: PRE-REGISTERED. No observation has been taken.**
Everything below the heading "Registered before the run" was committed and
pushed before the device was claimed for the measured run. The results are
added under "Reading" by a later commit; the registered text is not edited
after the run. A later change of reading gets its own section that says so.

This session confirms `SH-3`
([`ARCHIVAL_CHALLENGE_MECHANISM.md`](../design/ARCHIVAL_CHALLENGE_MECHANISM.md)
§9.8, ruled 2026-10-09): the serving host runs its threads below the
daemon's CPU priority, from inside the process, with no setting. Session 2
([`ba_t5_serve_floor_device_20261009.md`](ba_t5_serve_floor_device_20261009.md))
measured what an *external* `nice 19` on the whole serving process did
beside a syncing daemon: the daemon kept 90 to 97 % of its no-serve sync
rate and serving still delivered 5 to 8 responses per second. The
mechanism that shipped lowers only the serving runtime's threads, by
their own call, and this session asks whether that gives the daemon the
same. The floor device is the Raspberry Pi 4 Model B of
[`76-device-provisioning-floor`](../../.cursor/rules/76-device-provisioning-floor.mdc).
Devices are named by role.

## What this session is

**A discovery run, not a cut line** (the 2026-10-08 ruling). Predictions
are registered before the run and recorded against the measurements, with
no pass or fail. The one ledger effect is `serving_priority_nice` moving
from *estimated* to *current* on this session's T1 capture, with the
measured value; if the value falls outside the estimate's 0.90 to 1.00
band, the record says so beside the estimate.

## The questions

1. **Does the shipped mechanism give the syncing daemon back what the
   external `nice 19` did in session 2?** Per-thread nice 19, set by each
   serving thread as it starts, against a whole process niced from
   outside.
2. **Does that depend on how the daemon and the wallet are placed in the
   scheduler?** Nice orders threads within one scheduling group. A daemon
   and a wallet in different control groups, with the `cpu` controller
   between them, are weighted against each other as groups, and the
   threads' nice values decide nothing across that line.

## Registered before the run

### Topologies

| | Daemon | Serving probe | What it represents |
| --- | --- | --- | --- |
| **T1** | Started by the run script as its child, in the probe's own session scope | The same session scope | The GUI wallet supervising `shekyld` as a sidecar |
| **T2′** | Started in its own session (`setsid`) inside a transient scope of this user's own systemd instance (`systemd-run --user --scope`) | The login session's scope | **An approximation of T2**, a Pi staker's resident system service beside a wallet in a user session |

**T2 itself is not run.** T2 is the daemon as a transient *system* unit
(`sudo systemd-run --unit=… -p User=… <daemon>`), which this lane cannot
start: it has no root on the floor device, and the resident
`shekyld-testnet.service` is part of the measured condition and is not
touched. T2′ is the shape this user can make without root. Whether it
answers the same question as T2 is decided by the scheduling context,
read before the run and recorded here:

### The scheduling context, read on 2026-10-12 before the run

Read on the floor device by this lane, read-only, before the claim; the
run captures the same facts again before the first block and after the
last of each topology, and the reading uses the captured rows, not these.

- `/proc/sys/kernel/sched_autogroup_enabled` = `1`.
- cgroup v2. `cgroup.subtree_control` lists `cpu memory pids` at the root,
  at `user.slice`, at `user-<uid>.slice`, at `user@<uid>.service` and at
  `system.slice`: **the `cpu` controller is enabled at every level** that
  separates these processes.
- The resident daemon is in `/system.slice/shekyld-testnet.service`; a
  login session is in `/user.slice/user-<uid>.slice/session-<n>.scope`; a
  `systemd-run --user --scope` process is in
  `/user.slice/user-<uid>.slice/user@<uid>.service/app.slice/run-<id>.scope`.
  Each is its own cgroup with its own `cpu.weight`.

**What that predicts, written before the reading (P2).** In T1 the daemon
and the probe share one cgroup (the session scope) and so one scheduling
group: nice orders their threads against each other, and the mechanism is
expected to reproduce session 2 (P1). In T2′ the two are in different
cgroups under `user-<uid>.slice`, whose `subtree_control` enables `cpu`,
so the kernel weights the daemon's scope and the session's scope against
each other as groups (both at the default `cpu.weight` 100) before any
thread's nice is consulted. **Hypothesis (a) is predicted for T2′**: the
daemon's share falls toward the normal-priority control. The same
structure holds for T2 proper — `system.slice` and `user.slice` are
sibling cgroups under a root whose `subtree_control` enables `cpu` — so
T2′ is a fair approximation of T2 for this question: in both, the line
nice cannot cross is a cgroup boundary with the `cpu` controller on it.
If the captured context differs from this (the controller off, or the
two in one cgroup), the reading script says which hypothesis the captured
context selects, and that selection is the registered prediction; this
paragraph then stands as what the pre-run read said.

### What is measured, per cell

A cell is one topology and one serving arm:

- **mech8**, **mech64**: the mechanism — the probe's serving runtime built
  through the single constructor (`shekyl_runtime::runtime_with_thread_hooks`)
  with the serving host's budget (2 workers, `MAX_INFLIGHT` blocking
  threads) and the start hook the host installs, each thread lowering its
  own priority with `shekyl_thread_priority::lower_current_thread`
  (`BAT5_PRIORITY=thread`); 8 or 64 in flight, 512 whole fetches per
  block. The probe is not `shekyl-p-host`: it serves synthetic shards with
  an ephemeral key and has no onion; what it shares with the host is the
  constructor, the budget and the call.
- **ctrl8**: the control — the same runtime and budget with no hook, every
  thread at the priority it inherits (`BAT5_PRIORITY=budget`); 8 in
  flight, 4,096 whole fetches per block, long enough for the daemon to
  write three log lines while serving cuts its rate to a third.

For each block: responses per second and CPU per response over the
responses served; p50, p90, p99 and maximum wake lateness on the serving
executor; the daemon's sync rate over the block's window; and **the nice
value of every thread of the probe**, read from `/proc/<pid>/task/*/stat`
eight seconds into the block, as a histogram of thread name and nice. A
mechanism block whose serving-runtime threads (`sk-serving-prob…`) do not
all read nice 19 is **void**: the mechanism did not take, and the block
measured something else. A control block whose serving threads read
anything but their inherited nice is void the same way.

Three passes per topology, inside one sync of the chain (the testnet chain
is about 4,800 blocks on 2026-10-12, about 30 minutes at the daemon's
session-2 rate; a pass is about eight minutes). Each pass is one no-serve
window, then the three cells in the pass's registered order — pass 1:
mech8, mech64, ctrl8; pass 2: ctrl8, mech8, mech64; pass 3: mech64,
ctrl8, mech8 — each followed by a no-serve window of 45 s. At least three
blocks per cell. A pass does not start if fewer than 600 blocks remain in
the sync.

### How the sync rate and the share are read

- **Windows** are read from the daemon's own `Synced H/T` log lines
  stamped at or after the environment row written when the window
  opened, by session 2's corrected reading; the poll seeds its "seen"
  line at start, so no window begins on a point from the one before.
- **A window is valid** under session 2's rule, unchanged: at least three
  in-window points, at most one at which the height did not advance, the
  last height above the first, the target not reached.
- **A block's share** is its window's rate over the mean of its two
  adjacent no-serve windows — the one that ended as the block started and
  the one that began as it ended — so the denominator is the daemon's own
  rate at the same heights. A block beside one void window takes the other
  alone; beside two it has no share. Session 2's denominator, the
  topology's median no-serve rate, is printed beside it for comparison
  with that session's figures. Cell figures are medians over the pass
  blocks.

### Registered predictions

| # | Quantity | Prediction |
| --- | --- | --- |
| P1 | T1 with the mechanism: the daemon's share of its no-serve sync rate at N = 8 and N = 64 | 90 to 100 %, reproducing session 2's external-nice arm |
| P2 | T2′ with the mechanism | Two hypotheses. **(a)** if `cpu` is enabled between the two cgroups, or autogroup separates the two sessions, the share falls toward the normal-priority control, because nice does not cross groups. **(b)** if neither applies, T2′ matches T1. **From the context above, (a) is predicted.** Read as: (a) holds when the T2′ mechanism share at N = 8 sits nearer the T2′ control's share than T1's mechanism share; (b) holds when it sits within 10 points of T1's |
| P3 | Serving throughput with the mechanism, N = 8 and N = 64, both topologies | 5 to 17 responses per second, as in session 2's nice arm |
| P4 | Serving executor p99 wake lateness with the mechanism, N = 8 and N = 64, both topologies | 0.05 to 0.8 s: serving yielding, as intended and inside the 30 s write-stall timeout |

Each is read against the measurement in the same row of the reading and
marked **held** or **missed**; neither is a pass or a fail.

### Arms and rig

- **Serving arm:** `dev` at the commit named in the reading, one tree;
  release profile, `RUSTFLAGS` unset, rustc 1.94.0 on the device. The probe
  is the session-2 probe with the `BAT5_PRIORITY` arm added and its length
  check following the unframed body of PR #1015 (the shard and its
  envelope, nothing more; sessions 1 and 2 served a framed body a few
  bytes longer per response). Store on the USB SSD, written once before
  the first pass and opened by every block; the resident daemon not
  mining.
- **The syncing daemon:** a second testnet daemon under the probe's own
  user, own data directory on the SSD, resyncing the whole chain from a
  testnet staker on the LAN over the encrypted clearnet transport,
  accepting no inbound peers; wiped and started again for each topology.
  In T1 it is the run script's child; in T2′ it is started with
  `systemd-run --user --scope --unit=<name> -- setsid --fork --wait <daemon>`
  and stopped with its scope at the end.
- **Context capture:** before the first block and after the last of each
  topology: `sched_autogroup_enabled`, the root's `subtree_control`, and
  for the daemon and for the run script (the probe's parent, which the
  probe inherits): `/proc/<pid>/cgroup`, `/proc/<pid>/autogroup`, the
  parent cgroup's `cgroup.controllers` and `cgroup.subtree_control`, and
  the cgroup's `cpu.weight`; plus the resident daemon's cgroup. Per
  block: the probe's own cgroup and autogroup and its thread histogram.
- **The sync poll** is session 2's, as fixed in its review.
- **Environment rows** before and after every block and pass, as in
  session 2.

### Void conditions

A block is void and re-run if the probe exits non-zero, or if its thread
reading shows the mechanism did not take (above), or if the resident
daemon restarts during it. A window is void by the rule above. The
session is void if the serving arm was not built from the commit named in
the reading, or if a topology's context capture is missing.

### Landing

The reading, the four capture files per topology
(`_t1_{obs,env,sync,ctx}.tsv`, `_t2p_…`), and the reader
`scripts/bench/ba_t5_session3_reading.py` with its selftest.
`serving_priority_nice` moves to *current* on the T1 capture, the record
carrying the measured share (the lower of the two mechanism cells). If
T2′ shows (a), no code changes in this PR: the record names the fix — a
lower CPU weight for the wallet's serving host, its own cgroup or a unit
setting — and a `FOLLOWUPS` row carries it for a ruling. §9.8 gets a
dated note with each topology's result.

## Reading

*Not yet taken.*

## Files

*Added with the reading.* The probe is
`rust/shekyl-p-serve/tests/ba_t5_floor_probe.rs` (`BAT5_PRIORITY`); the
run script is `scripts/bench/ba_t5_session3_run.sh`, the sync poll
`scripts/bench/ba_t5_sync_poll.sh`; the reader
`scripts/bench/ba_t5_session3_reading.py`, with a selftest.
