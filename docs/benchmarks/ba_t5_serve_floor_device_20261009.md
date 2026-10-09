# `BA-T5` session 2: serving beside a syncing daemon, the in-flight sweep, and time to first byte. Floor run of 2026-10-09 (a discovery run)

**State of this record: RUN COMPLETE, 2026-10-09 02:22Z to 03:24Z (the
fourth start; the three before it are discarded, as the registration
history says).** Everything below the heading "Registered before the run"
was committed and pushed before the device was claimed for the run, and
was last amended at `301ed05b73`, before the start that counts. The
results are under "Reading"; the registered text is not edited after the
run. A later change of reading gets its own section that says so.

**In one paragraph.** Beside a daemon syncing the chain at 3.3 cores, the
floor device serves full segments at 37 to 41 per second, 70 % of its
idle rate, with p99 executor wake lateness under 61 ms at every N up to
64 — and the daemon keeps about a third, 31 to 37 %, of the sync rate it
has with the probe idle. The serving process at `nice 19` gives the
daemon 90 to 97 % of that rate back and serves at 5 to 8 per second, a
seventh to a fifth of normal priority, with p99 lateness up to 641 ms.
Throughput is flat from N = 16 in every state; p99 lateness rises
steeply with N, more than doubling across each of the first two doublings
and by a third to a half across the last; CPU per response is 66 to 72 ms
whatever the state or N. Time to first
byte at one in flight is 0.19 ms p50 with the daemon idle, 1.85 ms under
sync; the open pre-head estimate is settled. At N = 64, the cap, the
endpoint refused one connection in 2,048 under sync. Five of the seven
predictions held; P1 and P4 missed, both in the direction of the device
doing better than predicted.

This session extends the run of 2026-10-07
([`ba_t5_serve_floor_device_20261007.md`](ba_t5_serve_floor_device_20261007.md)):
same device, the same probe with one mode added, and the same reading
rules where the lines are the same. The floor device is the Raspberry Pi
4 Model B of
[`76-device-provisioning-floor`](../../.cursor/rules/76-device-provisioning-floor.mdc),
ruled on 2026-10-07 to be the ground floor for the serve path. Devices are
named by role.

## What this session is

**A discovery run, not a cut line** (maintainer's ruling, 2026-10-08,
amending the brief). It measures how the serve path behaves on the
smallest device the project supports when the daemon beside it is busy,
and it records what was predicted beside what was measured. It is not a
recommendation to serve shards from the floor device, it grades nothing
as pass or fail, and it does not set `MAX_INFLIGHT`.

*Registration history.* A first registration was pushed at `67e9775d14`
(01:10Z) with lines (c), (d), (e) graded pass or fail, a rule that would
have set `MAX_INFLIGHT` from the sweep, and no nice-19 arm. The
maintainer replaced that framing before the device was claimed for the
run; that registration was pushed at `3c21d9ec6b` (01:25Z). **A first
start under it was aborted** at 01:41Z, eight minutes in, when the sync
poll's RPC reads of the syncing daemon came back empty: under a sync that
takes three cores, a `get_height` call took 6 to 9 seconds and the poll's
2-second timeout saw nothing, so every sync window of that start was void
on its face. Its eleven blocks (one idle pass, one sync pass) are
discarded and are not in the capture. This registration amends the
method — the sync rate is read from the daemon's own log, the serving
blocks are longer so a window holds enough points, and the window
validity rule is restated in those terms — and nothing else. It is the
registration that stands, with one further amendment: **the second start
(01:44Z) was stopped at 02:04Z, in its first nice pass.** Its idle and
sync passes were sound and its sync windows all valid, but at nice 19
beside a syncing daemon the serve runs at about 6 responses per second,
so a 2,048-fetch block took 332 s, and four of them with their windows
cannot sit inside a 13-minute sync: the later cells of every nice pass
would have been void and the session incomplete. Nice blocks are 512
fetches, about 85 s, which a window of about ten points covers. The
second start's 12 blocks are discarded and are not in the capture; the
numbers it showed are not quoted in the reading. That text was pushed at
`c9158e71a5` before the third start. **The third start (02:07Z) stopped
itself at 02:14Z**, seven blocks in, when the probe exited 101 on the
first `sync` block at N = 64: with 64 in flight against a cap of 64, the
endpoint refused one connection — past `MAX_INFLIGHT` the accept loop
drops the stream without writing a byte, by design — and the probe, which
had never run at N equal to the cap, read the empty close as a response
cut short and failed the block. The refusal is one of the quantities this
registration says each cell records, so the probe was wrong to die on it.
The sequence is in the capture it left: the refused connection was opened
at a batch boundary, after the requester had seen every stream of the
previous batch close, while one connection task on the loaded board had
not yet dropped its permit. The idle pass's N = 64 block, 2,048 fetches
with no refusal, is the control. This amendment: the probe records a
connection closed without a byte as a refusal (a 0 on its `OBS` row, the
endpoint's own count on the `BLOCK` row) and goes on, retrying nothing,
since a retry changes the offered load; the reading divides by the
responses served, not the fetches attempted, and reports a block whose
probe-side and endpoint-side refusal counts disagree. At one in flight,
where no refusal can occur, an empty close is still a fault. The serve
path is not changed. The third start's seven blocks are discarded and are
not in the capture. This text is pushed before the fourth start. Every
earlier text is in the branch history.

## The questions

1. **What does serving do to a daemon that is syncing, and what does the
   syncing daemon do to serving?** Session 1's daemon was idle, at 0.2 %
   of one core. In the setup trial for this session a syncing daemon took
   about 3.3 of the board's four cores for its whole duration.
2. **How do throughput, CPU, executor wake lateness and the daemon's sync
   rate move with the number of responses in flight, and where does each
   curve bend?** `MAX_INFLIGHT` is 64 today, a declared placeholder, and
   the ledger row `p_serve_max_inflight` is `unmeasured`. **It stays
   unmeasured after this run**, citing this capture as evidence; the
   constant is not set here.
3. **Does running the serving process at `nice 19` give the daemon back
   its sync rate, and at what cost to serving?**
4. **Is the work before the first byte under 1 ms?** The estimate is open;
   session 1 bounded it from above at 2.2 ms with a whole abandoned
   request. This run settles it or replaces it.

## Registered before the run

### What is measured, per cell

A cell is one daemon state and one in-flight count N, at full segment
from the on-disk store, 2,048 whole fetches per block (512 in the nice
state, where the serve is slow by design), at least three blocks per
cell. For each block: responses per second and CPU per response, both
over the responses served; the endpoint's refusals (a fetch the endpoint
closed without a byte is counted, not served, and not retried); p50, p90,
p99 and maximum wake lateness on the
endpoint's executor; and, when the daemon is syncing, its sync rate in
blocks per second over the block's window, read from its own height.
Between serving blocks in a syncing pass, no-serve windows of 45 s give
the sync rate with the probe idle.

### Predictions, recorded against the measurements

These are what I expect, written before looking. Each is read against
the measurement in the same row of the reading and marked **held** or
**missed**; neither is a pass or a fail of the device.

| # | Quantity | Prediction |
| --- | --- | --- |
| P1 | p99 wake lateness under sync (the line that was (c)) | Above 100 ms by N = 16, and already above it at N = 8 is possible |
| P2 | Board temperature and memory across the session (the line that was (d)) | Never reaches 80 °C; `MemAvailable` never below 512 MB; `SwapFree` never falls (no swap is configured) |
| P3 | Sync rate while serving, as a share of the no-serve rate (the line that was (e)) | Below 75 % by N = 16, possibly at N = 8. The 75 % is the brief's figure, kept here as a prediction and nothing more |
| P4 | Serving throughput under sync against N | A knee at N = 16: little gain beyond it, because the board is saturated |
| P5 | The same sweep at `nice 19` | Sync rate back to at least 90 % of the no-serve rate at every N; serving throughput at most half of what it is at normal priority under sync |
| P6 | Time to first byte at one in flight, daemon idle | p50 under 1 ms, by a small margin (x86 reads 70 µs; this path is about ten times slower on the floor); p99 under 5 ms |
| P7 | Executor wake lateness with the daemon idle | Within a factor of two of session 1 at N = 8 (5.6 ms p99) and rising with N |

### How the curves are read

For each daemon state and each quantity (throughput, CPU per response,
p99 wake lateness, sync rate), the reading prints the per-cell median
against N and the change at each doubling of N. **The knee** of a curve
is reported as the first doubling at which the quantity moves by more
than its stated step: for throughput, a gain of less than 10 % (the curve
has gone flat); for p99 lateness and CPU per response, a rise of more
than 50 %; for sync rate, a fall of more than 25 %. These are readings of
where each curve bends, defined now so the numbers do not choose them;
they are not thresholds anything is judged against.

### Time to first byte, against the open estimate

At one in flight, full segment from the store, daemon idle: TTFB is
measured by the requester from its last request byte written to its
first response byte received, and the whole response is then read and
checked, n ≥ 300. At one in flight the wall-clock TTFB bounds from above
every serial step `P` takes before its first byte, so a p50 under 1 ms
**settles** the open `serve_prehead_work_floor` estimate (its band of 0
to 1 ms holds under a bound inside it), and a p50 of 1 ms or more
**replaces** it with the measured figure, recorded as a retired estimate
beside the measurement. The same block is run under sync and recorded.

### Arms and rig

- **Serving arm:** `dev` at the pinned commit named in the reading, one
  tree. Release profile, `RUSTFLAGS` unset, rustc 1.94.0 on the device.
  Store on the USB SSD, written once before the first pass and opened by
  every block; chunk size and conditions as in session 1; the resident
  daemon not mining.
- **Daemon states, three passes each, interleaved idle, sync, nice:**
  - **idle:** the device's resident testnet daemon only, synced and
    following the tip, as in session 1.
  - **sync:** the resident daemon as above, **plus a second testnet
    daemon under the probe's own user**, with its own data directory on
    the SSD, resyncing the whole chain from a testnet staker on the LAN
    over the encrypted clearnet transport, accepting no inbound peers,
    wiped and started again for every pass.
  - **nice:** as `sync`, with the serving process started under
    `nice -n 19`. The same sweep, with sync rate and serving throughput
    recorded.
  - **no-serve syncing** is the 45-second window before and after every
    serving block in a sync or nice pass, with the probe idle; it is
    interleaved so drift shows in both.
- **Departure from the brief, stated:** the brief says to wipe *the*
  daemon's data directory and resync. The resident daemon is a system
  service, this lane has no root on the device, and the estate protocol
  forbids restarting it. So the syncing daemon is a second one and the
  resident daemon stays as it was in session 1, idle at about 0.2 % of a
  core. The board carries two daemons' memory and one daemon's sync load.
- **N = 128 is not run.** The brief asked for it with a test-only override
  of `MAX_INFLIGHT`; none exists, and the brief says to add none in that
  case. The sweep is N in {8, 16, 32, 64}.
- **Order.** Within a pass the four in-flight counts run in the order
  registered for the pass — pass 1: 32, 64, 8, 16; pass 2: 16, 8, 64, 32;
  pass 3: 64, 16, 32, 8 — so that each N sits at a different point of the
  sync in each pass.
- **The sync poll** reads the syncing daemon's height from the daemon's
  own standard output, where it writes `Synced H/T` about every eight
  seconds while syncing, once a second checking for a new line; the
  window's rate is the height gained between its first and last such
  line over those lines' own timestamps. The daemon's RPC is not used:
  under sync load it answers in 6 to 9 seconds (measured in the aborted
  first start). The poll's cost is one `tail` and one `grep` per second
  and is charged to the environment's remainder.
- **A syncing window is valid** if the daemon's height advanced throughout
  it: at least three log points in the window, at most one point at which
  the height did not advance from the previous one, the last height above
  the first, and the target not reached at the last point. A void
  window's block is reported and excluded from its cell's sync-rate
  median. A serving block of 2,048 fetches is 35 to 70 seconds under sync,
  and one of 512 at nice 19 about 85 seconds, so a window holds four to
  ten points.
- **The sync-speed trial** that set this up: the second daemon synced the
  2,228-block testnet chain from the LAN staker at 2.7 to 2.9 blocks per
  second, about 13 minutes end to end, at 3.3 cores, board 46 to 70 °C.
  One pass of four serving blocks with its windows is about eight
  minutes, so each pass sits inside one sync.

### Void conditions

A block is void and re-run if the probe exits non-zero or the resident
daemon restarts during it. The session is void if the serving arm was not
built from the commit named in the reading.

## Reading

Taken 2026-10-09 from the fourth start's capture, tree `301ed05b73`,
probe sha256 `74d70aaad8f7…`, rustc 1.94.0, release profile. 39 blocks
(the store-writing block, 36 cells, two TTFB blocks), every one exited 0;
55 sync windows, none void; every registered cell present. The resident
daemon was not mining and did not restart (its RSS 641.8 to 642.0 MB
throughout). The numbers below are what `ba_t5_session2_reading.py`
prints over the three capture files.

### The serving blocks, by state and N

Cell medians over three blocks; the per-block table is in the reading
script's output and the blocks in `_obs.tsv`.

| State | N | Responses/s | CPU per response | p99 wake lateness | Sync rate, share of no-serve | Refused |
| --- | --- | --- | --- | --- | --- | --- |
| idle | 8 | 51.1 | 72 ms | 5.5 ms | — | 0 |
| idle | 16 | 55.5 | 69 ms | 11.7 ms | — | 0 |
| idle | 32 | 56.7 | 69 ms | 35.8 ms | — | 0 |
| idle | 64 | 55.2 | 71 ms | 51.6 ms | — | 0 |
| sync | 8 | 36.9 | 66 ms | 7.2 ms | 37 % (2 valid windows: 36, 38; the third, one interval: 27) | 0 |
| sync | 16 | 40.5 | 66 ms | 14.3 ms | 31 % (1 valid: 31; one interval: 30, 28) | 0 |
| sync | 32 | 40.9 | 66 ms | 45.0 ms | 32 % (1 valid: 32; one interval: 26, 30) | 0 |
| sync | 64 | 40.4 | 67 ms | 60.0 ms | 31 % (2 valid: 30, 32; one interval: 27) | 1 of 6,144 |
| nice | 8 | 6.2 (5.5 to 17.1) | 68 ms | 74.8 ms | 96 % (95, 96, 97) | 0 |
| nice | 16 | 5.8 (4.8 to 10.3) | 67 ms | 199.0 ms | 97 % (93, 97, 99) | 0 |
| nice | 32 | 6.8 (5.4 to 7.4) | 66 ms | 564.6 ms | 94 % (92, 94, 98) | 0 |
| nice | 64 | 8.2 (7.2 to 13.0) | 67 ms | 641.4 ms | 90 % (90, 90, 93) | 0 |

The no-serve sync rate, median over the fifteen quiet windows of each
state: **2.92 blocks/s** in the sync passes, **2.81 blocks/s** in the nice
passes. Its spread is wide — 0.93 to 3.00 blocks/s with the probe idle —
and the slow windows sit at the same heights in every pass (about 560 to
720, and the windows after 1,100), so the daemon's own rate depends on
where in the chain it is, as much as on anything beside it. The shares in
the table are each block's rate over its state's median no-serve rate, as
registered; the per-pass spread in brackets is largely that chain
position, which the interleaved orders put at a different N each pass.

*How the sync windows are read, and why six serving windows are void.*
A window's rate is derived from the daemon's `Synced H/T` log lines
stamped at or after the window opened (see "What this reading corrects"
below). Under sync, a 2,048-fetch block lasts about 50 s and the daemon,
slowed by the serving beside it, writes a line every 15 to 20 s, so a
serving window holds two to four in-window points; the registered rule
needs three, and six of the twelve sync-state serving windows hold two.
Those are void under the rule and excluded from the cell medians, which
rest on one or two windows each. Their single interval is a measurement
all the same — 15 to 20 s of the daemon's own height — and is printed
beside, labelled, never in the medians: every one of the six reads
between 26 and 30 %, where the valid windows read 30 to 38 %. The
nice-state serving windows are 30 to 110 s long and hold four to fifteen
points; none is void.

### The curves, and where each bends

Read by the registered steps (throughput: a gain under 10 % at a
doubling; lateness and CPU: a rise over 50 %; sync rate: a fall over
25 %).

- **Throughput is flat from N = 16 in every state.** Idle: +9 % from 8 to
  16, then +2 % and −3 %. Sync: +9.8 % from 8 to 16, then +1 % and −1 %.
  The knee is at N = 8 in both, by a hair in the sync state (the reading
  prints the 9.8 % as "+10 %"). At nice 19 the curve has no shape the
  medians can show: 6.2, 5.8, 6.8, 8.2, inside a spread of 4.8 to 17.1
  that is the daemon's phase, not N.
- **p99 wake lateness rises steeply with N, and the rise slows at the
  last doubling.** Idle 5.5 → 11.7 → 35.8 → 51.6 ms (× 2.1, × 3.1,
  × 1.44); sync 7.2 → 14.3 → 45.0 → 60.0 ms (× 2.0, × 3.1, × 1.33); nice
  74.8 → 199 → 565 → 641 ms (× 2.7, × 2.8, × 1.14). More than doubling
  across each of the first two doublings, a third to a half across the
  last, a seventh at nice 19. The knee, by the registered step of a rise
  over 50 %, is at N = 8 in all three. Under sync, lateness is 1.2 to
  1.3 × idle at the same N; at nice 19 it is 12 to 17 × idle.
- **CPU per response has no knee and no state.** 66 to 72 ms at every
  cell, the same figure as session 1's 67.2 ms at one in flight. The
  idle cells of pass 3, at 72 to 76 °C, read 69 to 72 ms against 66 to
  70 ms in pass 1 at 60 to 73 °C: about 4 % more CPU time per response at
  the hotter board (see "Environment").
- **The daemon's sync rate under serving does not depend on N.** 37, 31,
  32, 31 % of no-serve at N = 8, 16, 32, 64 (the one-interval windows
  read 26 to 30 %): no doubling moves it by 25 %. What the serving
  process takes is a share of the four cores, and it takes about the same
  share at every N, because the board is saturated from N = 8: 37 to 41
  responses/s × 66 ms ≈ 2.5 to 2.7 cores for the probe, and the daemon,
  which took 3.3 cores alone, is left 1.3 to 1.4, about 40 % of what it
  had — it keeps a little less than that, which is the scheduler's share
  for one busy process against a probe with many runnable threads. At
  nice 19 the serving process yields almost all of it: the daemon keeps
  90 to 97 % and the probe serves at 5 to 8/s, 0.4 to 0.6 of a core.

### The predictions, against the measurements

| # | Prediction | Measured | |
| --- | --- | --- | --- |
| P1 | p99 wake lateness under sync above 100 ms by N = 16 | 14.3 ms at N = 16; 60.0 ms at N = 64; never above 100 ms inside the sweep | **missed** |
| P2 | Board under 80 °C; `MemAvailable` never below 512 MB; swap never falls | 58.4 to 78.4 °C; lowest `MemAvailable` 5,840 MB; no swap configured | **held** |
| P3 | Sync rate below 75 % of no-serve by N = 16, possibly at N = 8 | 37 % at N = 8 | **held** |
| P4 | Throughput under sync has its knee at N = 16 | Flat from N = 8: +9.8 % to N = 16, then ±1 % | **missed** |
| P5 | At nice 19: sync rate ≥ 90 % at every N; serving throughput ≤ half of normal priority | 96, 97, 94, 90 % (N = 64 holds by half a point: 90.5); throughput 17, 14, 17, 20 % of the sync state's | **held**, both halves |
| P6 | TTFB at one in flight, daemon idle: p50 under 1 ms, p99 under 5 ms | p50 0.19 ms, p90 0.22, p99 0.31, max 0.33 ms, n = 300 | **held** |
| P7 | Idle p99 lateness within 2 × session 1 at N = 8 (5.6 ms), rising with N | 5.5 ms at N = 8; 11.7, 35.8, 51.6 ms | **held** |

Where the predictions missed, the device did better than I expected: I
had pictured lateness under sync blowing past 100 ms as the daemon
fought the probe for the cores, and it did not — the executor's workers
are woken within 60 ms at 64 in flight with three cores' worth of sync
running beside them. And I had the throughput knee one doubling too
late: the board is saturated at eight in flight, idle or not.

### Time to first byte, and the pre-head estimate

At one in flight, full segment from the store, n = 300 each:

| Daemon | p50 | p90 | p99 | max |
| --- | --- | --- | --- | --- |
| idle | 0.19 ms | 0.22 ms | 0.31 ms | 0.33 ms |
| syncing | 1.85 ms | 3.53 ms | 3.95 ms | 6.47 ms |

The idle p50 is a bound from above on every serial step `P` takes before
its first byte — parse, anchor gate, shard open, pre-flight, head — and
it sits inside the 0 to 1 ms band, so by the registered rule the open
`serve_prehead_work_floor` estimate is **settled**: it moves to a
measured constant on this capture in the ledger. Session 1's 2.2 ms was
a whole abandoned request with one chunk read and hashed; the pre-head
step alone is a tenth of it. Under sync the same step is 1.85 ms p50 —
ten times idle — which is scheduling delay, not work: the pre-head
instruction count is flat (`BA-T3`), and the request waits behind the
sync for a core.

*Where the clock started.* In this capture the requester's clock
started after its `write_all` of the request returned, not before the
write. On a fresh loopback socket that write completes inside one
`send` syscall with no await between the syscall's return and the
reading of the clock, so the interval the endpoint could already have
been working in — from the kernel taking the last request byte to the
syscall returning — is the syscall's own return path, microseconds
against a 190 µs reading, and the settlement does not turn on it. The
probe now starts the clock before the write, so a later capture's figure
includes the request write and is a bound from above with nothing
outside it.

### The refusal at N = 64

One connection in 6,144 was refused in the sync cells at N = 64
(`sync.3.N64`: 2,047 served, 1 refused, and the probe's count of empty
closes agrees with the endpoint's), none at any other N or in the idle
cells. It is the mechanism the third start exposed, now recorded instead
of fatal: the requester opens its next 64 connections the instant it has
seen the last stream of the previous 64 close, and a connection task's
in-flight permit is dropped after its stream, so on a loaded board the
reconnect can arrive at a full table. For a requester that behaves this
way, the cap is N − ε rather than N. That is an input to `BA-Q4`: the
constant's value, and whether the permit should outlive the stream, are
decided there, not here. The serve path was not changed by this run.

### Environment

- **Temperature:** 58.4 °C at the first sample; 78.4 °C at the hottest,
  first reached at the end of the second nice pass and again twice in the
  third sync pass; 77.9 °C at the last sample. From the second pass on
  the board sat between 68 and 78 °C, with no cooling window long enough
  to bring it down: the quiet windows are 45 s and the daemon is syncing
  through them.
- **Clock:** 26 of the 96 environment samples read a CPU clock below
  1.8 GHz, between 1.2 and 1.7 GHz, at 58 to 78 °C — including the very
  first sample, at 58 °C, before any load. The governor is `ondemand`
  with thirteen steps from 600 MHz to 1.8 GHz, and every sample is taken
  between blocks, while the load is changing, so an intermediate value
  there is the governor on its way up or down and says little about the
  clock *during* a block. The firmware's throttle flags cannot be read
  without root on this device. The oracle for the clock during a block is
  CPU time per response, which is flat at 66 to 72 ms across the session
  and 5 % higher in the hottest idle pass than the coolest: if the clock
  had been held at 1.2 GHz through a block, that figure would be half
  again as large. So the board ran at or near full clock through the
  serving blocks, with at most a few per cent lost to heat late in the
  session. A later run that wants the clock during a block should read
  `cpufreq/stats/time_in_state` before and after it.
- **Memory:** two daemons resident. The syncing daemon 357 to 368 MB RSS
  across its nine lives; the resident daemon 642 MB; `MemAvailable` never
  below 5,840 MB of the board's 8 GB; no swap.
- **The sync poll's cost:** one `tail` and one `grep` a second, charged
  to the environment's remainder; it ran through every sync and nice
  pass and through no idle block.

### Limits of this run

- **Three blocks per cell, and fewer valid sync windows than that.** The
  sync-share spread in brackets shows what three buys: the chain position
  the interleaving moves around dominates the per-pass numbers, and three
  passes are enough to place the medians, not to put error bars on them.
  Under the registered three-point rule the sync-state cells rest on one
  or two windows each; the one-interval reading of the rest sits 2 to 8
  points below them. A later run that wants three valid windows per cell
  under sync should make its serving blocks about twice as long (4,096
  fetches, about 100 s), which still fits four of them and their quiet
  windows inside one sync.
- **The daemon's own rate varies threefold with chain position**, with
  the probe idle. The share figures use the state-wide median no-serve
  rate, as registered. A rate read against the no-serve window at the
  same heights would be tighter, and would need the quiet windows to
  cover the same heights as the blocks, which the interleaving prevents.
- **The second daemon is the departure from the brief.** The resident
  daemon idled at 642 MB; the board carried two daemons' memory and one
  daemon's sync load. A run with the resident daemon itself syncing would
  differ in memory by one daemon and in nothing this run measures.
- **The nice-19 blocks are 512 fetches**, a quarter of the others, and
  at 5 to 17 responses per second each still ran 30 to 110 s; their
  throughput medians sit inside a spread set by the daemon's phase.
- **Three starts were discarded before this one**, for the reasons the
  registration history gives; no number from them is quoted here. The
  figures the discarded starts showed were in line with these.
- **Not measured:** Tor, a cold cache, shard sizes other than the full
  segment, the clock during a block, N = 128.

### What this reading corrects (second commit, 2026-10-09, found in review)

The reading above replaces the one first committed with this capture.
Nothing in the capture files changed; the reading script changed, and
four summaries did. In the order that matters:

1. **The sync poll's first point belonged to the previous window.** The
   poll started with its "seen" line empty, so the newest `Synced H/T`
   line at the moment a window opened — written by the daemon during the
   previous window — was recorded as the window's first point, and 44 of
   the 55 windows' summaries spanned time from before they opened. For a
   serving window that meant one interval of the preceding no-serve rate
   folded in, and for a no-serve window one interval of the preceding
   serving rate: serving rates read high, no-serve rates read low, and
   every share read toward 100 %. The point is identifiable by its
   timestamp against the environment row written when the window opened,
   and the reading now derives every window from its in-window points
   alone. The no-serve medians moved from 2.52 and 2.77 to 2.92 and 2.81
   blocks/s; the sync-state shares from 46, 41, 37, 38 % to 37, 31, 32,
   31 %; the nice-state shares from 97, 98, 93, 94 % to 96, 97, 94, 90 %.
   Six sync-state serving windows fell below the registered three points
   once their borrowed point was dropped and are void, which is why the
   sync cells rest on one or two windows and the one-interval reading is
   printed beside them. **No prediction's verdict changed**: P3 held at
   N = 8 before and after, and P5's sync-rate half holds at every N, N = 64
   by half a point. The poll script now seeds its "seen" line with the
   newest line at start, so a later capture carries no such point and
   reads the same under either reading. The `SH-3` confirming run, which
   re-measures the sync share with the shipped priority mechanism, runs
   on the fixed poll.
2. **"p99 lateness doubles with each doubling of N" overstated the last
   step**, which is × 1.44 idle, × 1.33 under sync and × 1.14 at nice 19.
   The curves section now carries the per-step ratios, and the same
   sentence was corrected in the changelog, the alignment document and
   the `p_serve_max_inflight` carrier.
3. **The TTFB clock started after the request write returned.** Bounded
   above in "Time to first byte"; the probe now starts it before the
   write.
4. **The completeness check was weaker than the registration.** It
   accepted a capture with no `EXIT` row for a block, with three no-serve
   windows per state where fifteen were registered, and with one
   environment row. It now requires one zero exit for every registered
   block, fifteen no-serve windows per syncing state, and the environment
   row before and after every block and pass. This capture meets all
   three; the selftest holds a failing case for each.

Also corrected in the run script, for the next run and not this capture:
a syncing daemon that fails to reach height 50 in time is stopped before
the pass moves on, and every path is made absolute before the script
changes directory.

## Files

- `ba_t5_serve_floor_device_20261009_obs.tsv` — the capture: per-fetch
  `OBS` rows, `BLOCK`, `LATE`, `TTFB` and `EXIT` rows, `NOTE` rows for each
  sync daemon start and pass order; header names the tree, the probe's
  hash and the conditions. One header line differs from the file the
  device wrote: the run script had put the LAN staker's address in the
  "syncing daemon" line, and this repository names roles, not hosts, so
  that line now says "a testnet staker on the LAN, port 12021" and the
  script writes it that way from now on. No data row is changed.
- `ba_t5_serve_floor_device_20261009_env.tsv` — one `ENV` row before and
  after every block and pass: temperature, governor, clock, load,
  jiffies, both daemons' RSS, the syncing daemon's height, memory, swap.
- `ba_t5_serve_floor_device_20261009_sync.tsv` — the sync poll: `SYNCH`
  points and one `SYNC` summary per window.
- The probe is `rust/shekyl-p-serve/tests/ba_t5_floor_probe.rs` with the
  `ttfb` mode and the refusal recording added; the run script is
  `scripts/bench/ba_t5_session2_run.sh` and the sync poll
  `scripts/bench/ba_t5_sync_poll.sh`; the reading is
  `scripts/bench/ba_t5_session2_reading.py`, with a selftest. Two fixes
  to the reading landed with the reading itself and are not a change of
  rule: it steps over the store-writing block, which is a load block in
  no state, and it reads the syncing daemon's RSS from the right column.
  The environment section's clock line was added at the same time.
