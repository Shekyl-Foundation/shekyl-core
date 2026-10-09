# `BA-T5` session 2: serving beside a syncing daemon, the in-flight sweep, and time to first byte. Floor run of 2026-10-09

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

## The questions

1. **Does serving harm a daemon that is syncing?** Session 1's daemon was
   idle, at 0.2 % of one core. Sync is when the daemon is busiest: in the
   setup trial for this session it took about 3.3 of the board's four
   cores for its whole duration.
2. **What is `MAX_INFLIGHT`?** Today it is 64, a declared placeholder
   (`rust/shekyl-p-serve/src/serve.rs`), and the ledger row
   `p_serve_max_inflight` is `unmeasured`.
3. **Is the work before the first byte under 1 ms?** The estimate is open;
   session 1 bounded it from above at 2.2 ms with a whole abandoned
   request.

## Registered before the run

### Lines carried over, re-graded under sync

- **(c)** p99 wake lateness on the endpoint's executor ≤ 100 ms. Read as
  the worst p99 over a cell's serving blocks.
- **(d)** no thermal throttling, read as the board never reaching 80 °C;
  `MemAvailable` ≥ 512 MB throughout; swap not growing, read as
  `SwapFree` never falling between consecutive environment samples. (d)
  is read across the whole session, so one failure fails every N.

### New line (e): daemon harm

While serving at N in flight, the syncing daemon's sync rate — blocks per
second from its own height over the serving block's window — is at least
**75 %** of its rate in the no-serve windows of the same session. Read as:
the median of a cell's serving-window rates over the median of every
no-serve window's rate.

*Why that line:* sync is a one-time catch-up, so it can absorb a bounded
slowdown; (c) stays the hard constraint on the daemon's deadlines.
**The figure is the brief's, and needs the maintainer's acceptance before
the run; if he sets another, that one is what is registered here.**

*What makes a syncing window valid.* The daemon's height must advance
throughout it: at most 2 one-second polls at which the height did not
move, the end height above the start height, and the target height not
reached inside the window. A serving block whose window is void does not
count toward its cell, and a cell with fewer than three valid windows
fails (e) for want of evidence, not for a measured harm.

### The BA-Q4 question, registered as a rule

For N in {8, 16, 32, 64}, at full segment from the on-disk store, with the
daemon syncing:

- **`MAX_INFLIGHT` = the largest N at which (c), (d) and (e) all hold,
  reading the sweep upward and stopping at the first N that fails.** A
  higher N that holds above a failing one is not counted; it is a
  non-monotone result and is reported as a finding.
- If every tested N holds, the record says "CPU does not bind at or below
  64; not searched beyond", and the constant is set by BA-Q4's other half,
  slow-reader permit exhaustion, not by this run.
- If N = 8 fails, that is the headline finding, and the constant is not
  derived here.
- **N = 128 is not run.** The brief asked for it with a test-only override
  of the constant; no such override exists, and the brief says to add
  none in that case. The sweep stops at the constant's own value.

If the rule sets a value other than 64, the constant change is a separate
code PR that cites this capture.

### Pre-head line

At one in flight, full segment from the store, with the daemon idle: time
to first byte **p50 < 1 ms and p99 < 5 ms**, n ≥ 300. TTFB is measured
by the requester, from its last request byte written to its first
response byte received, and the whole response is then read and checked,
so these are served responses. At one in flight the wall-clock TTFB
bounds from above every serial step `P` takes before its first byte, so
a pass settles the open estimate and a fail replaces it with the measured
figure. The same block is also run under sync and reported, not graded.

### What I expect, written before looking

- **(e) is the line most likely to fail, and at low N.** Sync takes 3.3
  cores in the trial; serving a full segment costs about 60 ms of CPU per
  response. At N = 8 session 1 served 52 per second, about 3 cores. The
  two cannot both have what they had alone on a 4-core board. I expect
  the sync rate to fall well below 75 % by N = 16, and would not be
  surprised at N = 8.
- **(c) is likely to fail where (e) does**, since the same contention that
  slows the daemon holds the executor's workers; the daemon's threads are
  not nicer than the probe's.
- **(d)** the board ran at 67 °C in the trial with sync alone at 46 °C
  ambient-ish start. With serving on top I expect the high 60s to low
  70s, under the 80 °C line, and no memory pressure (the syncing daemon
  is about 370 MB resident).
- **TTFB** p50 under 1 ms at idle: on x86 it is 70 µs; the floor is
  roughly ten times slower on this path, so about 0.7 ms. I expect a pass
  by a small margin and would not be surprised by a fail on p50.

### Arms and rig

- **Serving arm:** `dev` at the pinned commit named in the reading, one
  tree. Release profile, `RUSTFLAGS` unset, rustc 1.94.0 on the device.
  Store on the USB SSD; chunk size and conditions as in session 1; the
  resident daemon not mining.
- **Daemon states, alternated pass by pass, three passes each:**
  - **idle:** the device's resident testnet daemon only, synced and
    following the tip, as in session 1.
  - **sync:** the resident daemon as above, **plus a second testnet
    daemon under the probe's own user**, with its own data directory on
    the SSD, resyncing the whole chain from a testnet staker on the LAN
    over the encrypted clearnet transport, accepting no inbound peers. It
    is wiped and started again for every pass. Its sync is what lines
    (c), (d) and (e) are read against.
  - **no-serve syncing** is the 30-second window before and after every
    serving block in a sync pass, with the probe idle. It is interleaved
    with the serving blocks, so drift shows up in both.
- **Departure from the brief, stated:** the brief says to wipe *the*
  daemon's data directory and resync. The resident daemon is a system
  service, this lane has no root on the device, and the estate protocol
  forbids restarting it. So the syncing daemon is a second one, and the
  resident daemon stays as it was in session 1, idle at about 0.2 % of a
  core. The board therefore carries two daemons' memory, which (d) sees,
  and one daemon's sync load, which is the condition under test.
- **Order.** Within a pass the four in-flight counts run in the order
  registered for the pass — pass 1: 32, 64, 8, 16; pass 2: 16, 8, 64, 32;
  pass 3: 64, 16, 32, 8 — so that each N sits at a different point of the
  sync in each pass and none lines up with sync progress. Each
  serving block is 256 whole fetches. The store is written once, before
  the first pass, and every block opens it; no block builds a store.
- **The sync poll** reads the syncing daemon's height once a second over
  its local RPC for every window, serving and no-serve. Its cost, one
  `curl` and one `python3` start per second, is about 6 % of one core
  while it runs; it is charged to the environment's remainder and not to
  the probe or the daemon.
- **The sync-speed trial** that set this up: the second daemon synced the
  2,228-block testnet chain from the LAN staker at 2.7 to 2.9 blocks per
  second, about 13 minutes end to end, at 3.3 cores, board 46 to 67 °C.
  One pass of four serving blocks with its windows is about five minutes,
  so each pass sits inside one sync.

### Void conditions

A block is void and re-run if the probe exits non-zero or the resident
daemon restarts during it. A syncing window is void by the rule above. The
session is void if the serving arm was not built from the commit named in
the reading.

## Reading

*Not yet taken.*

## Files

*Added with the reading.* The probe is
`rust/shekyl-p-serve/tests/ba_t5_floor_probe.rs` with the `ttfb` mode
added; the run script is `scripts/bench/ba_t5_session2_run.sh` and the
sync poll `scripts/bench/ba_t5_sync_poll.sh`; the reading is
`scripts/bench/ba_t5_session2_reading.py`, with a selftest.
