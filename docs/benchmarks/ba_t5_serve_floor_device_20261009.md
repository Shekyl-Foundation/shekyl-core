# `BA-T5` session 2: serving beside a syncing daemon, the in-flight sweep, and time to first byte. Floor run of 2026-10-09 (a discovery run)

**State of this record: PRE-REGISTERED. No observation has been taken.**
Everything below the heading "Registered before the run" was committed and
pushed before the device was claimed for the run. The results are added
under "Reading" by a later commit; the registered text is not edited after
the run. A later change of reading gets its own section that says so.

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
run, and this is the registration that stands: pushed before the claim,
not edited afterwards. The first registration's text is in the branch
history and nothing in it was measured.

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
from the on-disk store, 256 whole fetches per block, at least three
blocks per cell. For each block: responses per second; CPU per response;
the endpoint's refusals; p50, p90, p99 and maximum wake lateness on the
endpoint's executor; and, when the daemon is syncing, its sync rate in
blocks per second over the block's window, read from its own height.
Between serving blocks in a syncing pass, no-serve windows of 30 s give
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
  - **no-serve syncing** is the 30-second window before and after every
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
- **The sync poll** reads the syncing daemon's height once a second over
  its local RPC for every window. Its cost, one `curl` and one `python3`
  start per second, is about 6 % of one core while it runs; it is charged
  to the environment's remainder and not to the probe or the daemon.
- **A syncing window is valid** if the daemon's height advanced throughout
  it: at most 2 one-second polls at which the height did not move, the
  end height above the start height, and the target not reached inside
  the window. A void window's block is reported and excluded from its
  cell's sync-rate median.
- **The sync-speed trial** that set this up: the second daemon synced the
  2,228-block testnet chain from the LAN staker at 2.7 to 2.9 blocks per
  second, about 13 minutes end to end, at 3.3 cores, board 46 to 70 °C.
  One pass of four serving blocks with its windows is about five minutes,
  so each pass sits inside one sync.

### Void conditions

A block is void and re-run if the probe exits non-zero or the resident
daemon restarts during it. The session is void if the serving arm was not
built from the commit named in the reading.

## Reading

*Not yet taken.*

## Files

*Added with the reading.* The probe is
`rust/shekyl-p-serve/tests/ba_t5_floor_probe.rs` with the `ttfb` mode
added; the run script is `scripts/bench/ba_t5_session2_run.sh` and the
sync poll `scripts/bench/ba_t5_sync_poll.sh`; the reading is
`scripts/bench/ba_t5_session2_reading.py`, with a selftest.
