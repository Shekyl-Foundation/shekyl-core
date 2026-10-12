# `BA-T5` session 3: the `SH-3` confirming block — the shipped priority mechanism beside a syncing daemon, in two scheduler topologies. Floor run of 2026-10-12 (a discovery run)

**State of this record: RUN COMPLETE, 2026-10-12 15:45Z to 16:27Z (the
second start; the first is discarded, as the registration history says).**
Everything below the heading "Registered before the run" was committed and
pushed before the measured run, and was last amended at `004ed6c6df`,
before the start that counts. The results are under "Reading"; the
registered text is not edited after the run. A later change of reading
gets its own section that says so.

**In one paragraph.** With the daemon and the serving probe in one cgroup
(T1, the sidecar shape), the shipped mechanism gives the syncing daemon
**93 % of its no-serve sync rate at N = 8 and 91 % at N = 64**,
reproducing session 2's external nice (90 to 97 %), against 38 % for the
same runtime at normal priority; serving runs at 6.6 and 7.9 responses per
second with p99 wake lateness of 82 and 697 ms. With the daemon in a
different cpu cgroup (T2′, the approximation of a resident service), the
mechanism gives the daemon **65 % at N = 8** — between the normal-priority
control's 29 % and T1's 93 %, matching neither registered hypothesis — and
serving runs at 18 to 23 per second with p99 lateness of 19 to 100 ms: the
serving group takes the fair share the cgroup weights give it, and nice
inside that group lowers its load but does not yield it. Every mechanism
block's serving threads read nice 19 in `/proc`; no control block's did.
`serving_priority_nice` is measured at **0.91** on the T1 capture, inside
its 0.90 to 1.00 estimate. P1 held; P2, P3 and P4 missed, each on the T2′
side and each in the same direction: the daemon kept less and serving
took more than a shared scheduling group would allow. The fix for the
resident-service shape is a CPU weight for the wallet's serving host, its
own cgroup or a unit setting, carried as a follow-up for a ruling.

*Registration history.* Registered at `71c3bf0db9`. A rehearsal of both
topologies in miniature (`BAT5_S3_DRY=1`, 2026-10-12 14:53Z, discarded)
showed every path working — the T2′ daemon starting in its scope and
stopping with it, the context rows, the thread reading with every serving
thread at nice 19 — and two things the registration did not know: under
`tmux` the run script's cgroup is tmux's own scope in the user's systemd
instance (`user@<uid>.service/tmux-spawn-….scope`), not a login session
scope, and the T2′ daemon's scope sits under `app.slice`, which does not
enable `cpu` for its children, so the group the scheduler weighs for the
daemon is `app.slice` itself. The split the P2 reasoning rests on is
unchanged — two cpu cgroups at equal weight under one parent with the
controller on — but it is one level higher than written below. This
amendment adds the *effective cpu cgroup* of each process to the capture
(the nearest ancestor whose parent enables `cpu`), makes it the reader's
first test for P2, and changes nothing else. That registration was
`b5c9de437e`. **The first measured start under it (14:59Z to 15:38Z) is
discarded**: three of its six `mech64` blocks exited 101 when a response
was reset mid-read — the endpoint's 30 s write-stall timeout dropping a
connection that made no progress for that long, at 64 in flight with the
serving threads at nice 19 beside the syncing daemon. The probe treated
the reset as a failed block, as it had treated a refusal before session
2's amendment, and for the same reason the fix is the same: a cut
response is recorded (an `outcome` of `cut` on its `OBS` row, a `cut`
count on the `BLOCK` row) and the block goes on, retrying nothing. The
endpoint does not count a cut response as served, so throughput over
`served` is unchanged in meaning; the reader prints the cuts per block
and per cell. The first start's other readings (every mechanism block's
serving threads at nice 19, the T2′ daemon in its own scope, the context
rows) are not quoted; the run is repeated whole under this registration.
Pushed before the second start.

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
  parent cgroup's `cgroup.controllers` and `cgroup.subtree_control`, the
  cgroup's `cpu.weight`, and the effective cpu cgroup — the nearest
  ancestor whose parent enables `cpu` — with its weight; plus the resident
  daemon's cgroup. Per
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

Taken 2026-10-12 from the second start's capture, tree `004ed6c6df`,
probe sha256 `3f65399b9645c17e…`, rustc 1.94.0, release profile. Per
topology: the store-writing block and nine cells, every one exited 0;
21 sync windows, none opened on a point from before it (the fixed poll);
every registered cell, window, environment row and context row present.
The resident daemon was not mining and did not restart. The numbers
below are what `ba_t5_session3_reading.py` prints over the eight capture
files; the T2′ `mech64` one-interval figures are computed beside it and
labelled.

### The scheduling context, as captured

| | T1 | T2′ |
| --- | --- | --- |
| Daemon's cgroup | `…/user@<uid>.service/tmux-spawn-<id>.scope` (the run script's own) | `…/user@<uid>.service/app.slice/ba-t5-s3-<stamp>.scope` |
| Serving probe's cgroup | the same scope | `…/user@<uid>.service/tmux-spawn-<id>.scope` |
| Effective cpu cgroup of each | one: the tmux scope (`cpu.weight` 100) | daemon: `app.slice`; probe: the tmux scope (each `cpu.weight` 100, siblings under `user@<uid>.service`, whose `subtree_control` enables `cpu`) |
| `sched_autogroup_enabled` | 1 | 1 |
| P2 hypothesis the reader selects from this | (b): one cgroup | **(a)**: different cpu cgroups |

The resident daemon sits in `/system.slice/shekyld-testnet.service`,
a sibling of `user.slice` under a root whose `subtree_control` enables
`cpu`: the same split as T2′, one level higher. T2′ reproduces T2's
structure for this question.

### The cells

Cell medians over the three passes. Share: the block's sync rate over the
mean of its two adjacent no-serve windows (session 2's median-of-all
denominator in brackets). The no-serve medians were 2.81 blocks/s (T1,
range 2.73 to 2.96) and 2.84 (T2′, 2.66 to 2.97): the daemon ran evenly
through both syncs, unlike session 2's threefold spread, so the two
denominators agree to a point or two.

| Topology | Cell | Daemon's share of no-serve | Responses/s | p99 wake lateness | Cut responses | Serving threads at nice 19 |
| --- | --- | --- | --- | --- | --- | --- |
| T1 | mech8 | **93 %** (91) — 79, 93, 94 | 6.6 (5.3 to 11.4) | 82 ms | 0 of 1,536 | every block |
| T1 | mech64 | **91 %** (90) — 90, 91, 96 | 7.9 (7.2 to 16.7) | 697 ms | 2 of 1,536 | every block |
| T1 | ctrl8 | 38 % (37) — 37, 38, 38 | 31.4 | 7.1 ms | 0 of 12,288 | none |
| T2′ | mech8 | **65 %** (65) — 65, 65, 65 | 18.4 | 18.7 ms | 0 of 1,536 | every block |
| T2′ | mech64 | *void under the registered rule* (one-interval reading, two of three blocks: 51 %, 52 %) | 23.4 | 100 ms | 2 of 1,536 | every block |
| T2′ | ctrl8 | 29 % (29) — 29, 29, 30 | 35.0 | 5.6 ms | 0 of 12,288 | none |

*The T2′ `mech64` windows.* At 23 responses per second a 512-fetch block
lasts 22 s, and the daemon wrote at most two log lines inside it; the
registered rule needs three. Two of the three windows hold one interval
of about 14 s, which reads 1.45 and 1.47 blocks/s against adjacent
no-serve windows of 2.82 to 2.97 — about 51 %, printed here outside the
rule and in no median. The third window holds one point and reads
nothing. The cell's share is unmeasured under the rule; what the two
intervals say is consistent with `mech8`'s 65 % and the direction of P2.

### The mechanism took

Every mechanism block's probe showed its serving-runtime threads
(`sk-serving-prob…`) at nice 19 and nothing else at 19 — the two
requester workers and the test's own threads at 0 — 23 to 66 serving
threads per block (two workers and the blocking threads the in-flight
count needed). Every control block's serving threads read 0. The thread
histograms are in the `_ctx.tsv` files, one row per block.

### The predictions, against the measurements

| # | Prediction | Measured | |
| --- | --- | --- | --- |
| P1 | T1 with the mechanism keeps 90 to 100 % at N = 8 and N = 64 | 93 % and 91 % | **held** |
| P2 | T2′ with the mechanism: (a) predicted from the context — the share falls toward the normal-priority control; (b) it matches T1 | 65 % at N = 8: 36 points above the control's 29 %, 28 points below T1's 93 %; by the registered reading nearer T1 than the control but not within 10 points of it | **missed** — neither (a) nor (b) as registered |
| P3 | Serving throughput with the mechanism 5 to 17 responses/s | T1 6.6 and 7.9; T2′ 18.4 and 23.4 | **missed** (T2′) |
| P4 | Serving executor p99 wake lateness with the mechanism 0.05 to 0.8 s | T1 82 and 697 ms; T2′ 19 and 100 ms | **missed** (T2′ at N = 8) |

What the three misses say together is one thing, and it is the thing P2
was registered to find: in T2′ the serving group is weighed against the
daemon's group as a group, and inside its own group the serving threads'
nice 19 is measured against the two requester workers and nothing else.
The group takes about the fair share its `cpu.weight` entitles it to under
contention, serves at 18 to 23 per second with a lightly loaded executor,
and the daemon keeps 65 % — more than the 29 % it keeps against the same
runtime at normal priority, because a group whose runnable threads carry
nice-19 weights presents a far smaller load to the scheduler's balancing
and to the parent's fair-share accounting than one whose threads carry
nice-0 weights, but far less than the 93 % it keeps when the two share a
group and nice orders every thread against every other. The registered
reading of P2 drew its line at "nearer the control" and "within ten
points of T1"; the measurement landed between the two lines.

### Cut responses at N = 64

Two of 1,536 responses in each topology's `mech64` cell were cut: the
endpoint's 30 s write-stall timeout dropped a connection that made no
progress for that long while the serving threads yielded at nice 19
beside the syncing daemon. None at N = 8, none in any control block. The
first start, before the probe recorded a cut as data, lost three of its
six `mech64` blocks to this. A witness fetching from a persona in that
state would see a reset and retry under `SF-D6`; two in 1,536 is the
measured rate at the floor's worst case.

### The ledger row

`serving_priority_nice` moves from *estimated* to *current* on this
session's T1 capture (`ba_t5_serve_floor_device_20261012_t1_obs.tsv`,
tree `004ed6c6df`). The measured value is the lower of the two T1
mechanism cells, **0.91** of the no-serve sync rate — inside the 0.90 to
1.00 estimate taken from session 2's external-nice arm.

### Environment

- T1: 55.0 to 78.4 °C over 26 samples; 3 of 26 between-block clock samples
  below 1.8 GHz (1.1 to 1.6 GHz, the governor's transients, as session 2
  argued); `MemAvailable` ≥ 5,764 MB; the syncing daemon 350 to 621 MB RSS
  over a 4,800-block chain.
- T2′: 67.7 to **80.3 °C**, the board already warm from T1's sync and
  serving at 18 to 35 responses per second through its passes; every
  clock sample at 1.8 GHz; `MemAvailable` ≥ 5,790 MB. The one reading over
  80 °C is at the end of the second pass; CPU per response is 65 to 67 ms
  in every cell of both topologies, so the clock held through the blocks.
- Two syncs of the 4,800-block chain, each about 23 minutes at 2.8 blocks
  per second with the probe idle; three passes fitted inside each with
  more than 600 blocks to spare.

### Limits of this run

- **T2′ is not T2.** The resident-service shape proper puts the daemon in
  `system.slice` against the wallet in `user.slice`; T2′ puts it in
  `app.slice` against the tmux scope, both under `user@<uid>.service`.
  The structure the result turns on — two cpu cgroups at equal weight
  under a parent with the controller on — is the same; the weights and
  the surrounding load are the device's, not a staker's.
- **P2's registered reading could not say "in between".** It offered two
  lines and the measurement fell between them; the miss is the reading's
  coarseness as much as the hypothesis's. The next registration of this
  question should predict the daemon's share as a band from the cgroup
  weights, not as a choice between two endpoints.
- **The T2′ `mech64` cell has no share under the rule.** At 23 responses
  per second the block is too short for three log lines; a later run at
  this throughput needs 1,024 fetches or more in that cell.
- **Three blocks per cell**, as in session 2; the T2′ cells are
  remarkably tight (65, 65, 65; 29, 29, 30), the T1 cells less so
  (79 to 94 at `mech8`, where the first block ran during the daemon's
  early, slower sync).
- **Not measured:** the real T2, Tor, a cold cache, other shard sizes, a
  CPU weight on the serving group.

## Files

- `ba_t5_serve_floor_device_20261012_t1_obs.tsv` (sha256 `cf5637bcbdbeddd4b3e94299a66242c4ba12b828e07633db84417194b1c64952`),
  `_t1_env.tsv` (`d90d5ef30a81ee4e943cd8d35c2f6a9a9bcae8731c3ec99fe9843995da5d2d45`),
  `_t1_sync.tsv` (`afb2a967e514f1b71d720b8e76d6afcebe6e56c0b81186338e5cb18a642e71ef`),
  `_t1_ctx.tsv` (`a335a50de867866c996ee656ca6543c97caea92185cd674b4e952fe28f45e6cf`): topology T1.
- `ba_t5_serve_floor_device_20261012_t2p_obs.tsv` (`6f7ae28d7a45c71a0dac05b67417c943d3cdbb1ef26f74db065efbad887e6cf2`),
  `_t2p_env.tsv` (`600c5f0e9711d042f071e2ba5f5df800d4a17aa28885cccd5c64618feb0bd7d0`),
  `_t2p_sync.tsv` (`040cc4bb5b5776e880954dc2e028930c34d55b895a859e548f564a4b31a4bda3`),
  `_t2p_ctx.tsv` (`22970af981dd40306e98fd7ffb65003ff2d841b466c08c83bb9df9fce36341e3`): topology T2′.
  The files are byte-identical to the ones the device wrote (checksums
  matched on both sides). Headers name roles, not hosts.
- The probe is `rust/shekyl-p-serve/tests/ba_t5_floor_probe.rs`
  (`BAT5_PRIORITY`, the `Fetch` outcome); the run script
  `scripts/bench/ba_t5_session3_run.sh`, the sync poll
  `scripts/bench/ba_t5_sync_poll.sh`; the reader
  `scripts/bench/ba_t5_session3_reading.py`, with a selftest of fifteen
  cases. The first start's outputs and the rehearsal's were removed from
  the device with the run directory and are not in the tree.
