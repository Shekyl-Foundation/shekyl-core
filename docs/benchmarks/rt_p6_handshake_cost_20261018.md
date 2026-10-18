# `RT-P6`: what a handshake costs on the floor device, each side. Registration of 2026-10-18

**State of this record: registered; not yet run.** The run waits for the
maintainer's read of this registration, as RT-P4's did, and for a quiet
claim on the floor device. A dry run on the floor device is recorded below
the registration once it has been made, and it is not data. Results are
added under "Results"; the section "Registered before the run" is not
edited afterwards. An amendment made before any registered result is read
is dated and says what changed.

## The question

`RPC_CHANNEL.md` §9, RT-P6: what does the channel's `hybridXK` handshake
cost on the floor device (rule 76: the Pi 4), on each side? Three
decisions are made from the answer, not before it:

- **The handshake deadline**, a constant derived from this measurement and
  not chosen (§4.3, §9).
- **§4.3's amplification bound.** Each unauthenticated message 1 costs the
  daemon one Diffie-Hellman and one decapsulation. That work is bounded by
  `conn_limit` admission and by the deadline, and §4.3 leaves whether more
  is needed to this measurement.
- **The tunnel's session pool size** (§8, RT-W11), which a handshake's cost
  justifies.

It also gives the cost of sealing and opening one record at each response
class RT-O6 ruled on 2026-10-18 (512, 16,384 and 65,535 bytes), which RT-W9
step 5's framer pays per record.

## Registered before the run

**Subject.** `shekyl-rpc-channel`'s handshake (`Client`, `Daemon`,
`PendingSession`) and `shekyl-noise`'s `Direction`, at the commit the run
is made from. Built with `cargo build --release` under the workspace's
pinned toolchain (1.94.0) and release profile, on the floor device itself,
from a fresh clone of that commit.

**Instrument.** `rust/shekyl-rpc-channel/examples/rt_p6_handshake_cost.rs`.
It runs both roles in one process, pinned to one core with `taskset -c 3`.
Each timed region is a single call between two clock reads, on the wall
clock (`Instant`) and on the thread's CPU clock
(`CLOCK_THREAD_CPUTIME_ID`). The raw samples are written one per row:

1. **Every step of a full handshake.** The client's `start`,
   `read_message2`, `write_message3`, `read_message4`, and
   `into_directions` with the first record's seal; the daemon's
   `read_message1`, `write_message2`, `read_message3`, `write_message4`
   and `open_first_message`. The two static identities are made before the
   loop. The ephemeral keys each step draws are part of its cost, as in
   production. Message 3's and message 4's payloads are 64 bytes each:
   their encoding is RT-W10's and is fixed-length (§6.2), and a symmetric
   cipher's cost barely depends on the length.
2. **A stranger's message 1:** the daemon's `read_message1` on a
   well-formed message 1 from an honest client, and on 2,320 random bytes.
   Every message is made before its loop, into one array: RT-P4's first
   registration failed because its harness built inputs inside the timed
   loop.
3. **One record at each class:** `Direction::seal` and `Direction::open` of
   512, 16,384 and 65,535 bytes of random plaintext. Every plaintext and
   ciphertext is made before its loop. This is the AEAD's cost.
   `ClassedRecord`'s header byte and its header protection do not exist
   until RT-W9 step 5; they are measured there.

**Counts:** 200 warm-up handshakes, not recorded; then 10,000 handshakes;
10,000 messages 1 of each kind; 10,000 seals and 10,000 opens at each class.

**Statistics** (`scripts/bench/rt_p6_summary.py`, its tests in
`scripts/bench/test_rt_p6_summary.py`, run in CI):
- For each step: the median, 90th and 99th percentiles and the maximum of
  both clocks, nearest-rank.
- The same for each side's total per handshake, and for both sides
  together.
- For the stranger's message 1: the daemon's CPU time.
- For the records: seal and open time per class, and CPU nanoseconds per
  byte.

**Gates.** A run that fails any of these is void, and the failure is
recorded:

- Every handshake step succeeds; every honest message 1 is accepted and no
  random one is (the harness asserts it).
- The kernel's under-voltage alarm (`rpi_volt`) stays clear for the run.
- The core spends at least 99 % of the run at its top clock speed, by
  `cpufreq/stats/time_in_state` read at both ends. `vcgencmd
  get_throttled` needs root on that device and is not readable, as RT-P4
  recorded; the alarm and the time-at-speed are what can be read instead.

**Conditions recorded at the start and the end:**
- the governor and the SoC temperature;
- the one-minute load;
- the under-voltage alarm;
- the time-at-speed counters and the count of clock-speed changes;
- whether the standing testnet daemon is active, and its CPU use over the
  run.

**The standing testnet daemon — a question for the maintainer.** The floor
device runs `shekyld-testnet` as part of the estate. A quiet claim does
not stop it, and a daemon following the chain takes CPU now and then,
which can bend a timing taken on a 4-core device. This registration
**proposes leaving it running** and pinning the harness to a core of its
own: core 3, which the daemon's threads may still be scheduled on. Its
CPU time over the run is recorded, so its effect is bounded and visible.
The alternative is to have its owner stop it for the run. That is not
this lane's to decide.

**Build and attempts.** The floor device builds from a fresh clone of the
pushed commit and runs the dry cell first (50 of each), then the
registered cell. At most two registered attempts: a void attempt is
recorded with its cause, the cause is fixed, and the second attempt is made
under the same lines.

**Captures:** `docs/benchmarks/rt_p6_handshake_cost_20261018_captures/`,
with the three raw files, the summary, the conditions and `SHA256SUMS`.
The handshake deadline constant gets its measurement-ledger row when it
lands in code (RT-W9 step 5 or RT-W10), with `measured_by = ["RT-P6"]` and
this capture.

**Derivations — PROPOSED, for the maintainer to rule.** RT-P6 measures
compute only. The network is not in it.

- **Handshake deadline.**
  - **Proposed:** the 99th percentile of both sides' CPU per handshake on
    the floor device, plus five one-way transits (messages 1 to 4 and the
    first record) at the ledger's anonymity-zone transit assumption, all
    rounded up to the next whole second.
  - The transit assumption is `ANON_ZONE_TRANSIT_ASSUMPTION_MS` = 1,625 ms
    (`rust/shekyl-relay-privacy/src/verify_cost.rs`; ledger row
    `anon_zone_transit_assumption_ms`, status *unmeasured*, carried by
    BA-T9). The deadline would therefore inherit an unmeasured term, and its
    ledger row says so.
  - With that assumption the network part is 8,125 ms, and the compute part
    adds what this run measures.
- **Amplification.**
  - Reported: the daemon's CPU per stranger's message 1, as a median and a
    99th percentile.
  - Proposed reading: at `conn_limit` concurrent handshakes, a sender can
    hold `conn_limit` × that much CPU busy per deadline. Whether that needs
    a further bound is §4.3's decision.
- **Tunnel pool.** Reported: the client's cost per handshake. The pool size
  is RT-W11's decision.

**What this does not measure.**
- The network, and contention beyond the standing daemon recorded above.
- The header byte and header protection of `ClassedRecord`.
- An x86 machine: the floor device is the provisioning floor, and RT-P6
  asks about it alone.

## Dry run

None yet.

## Results

None yet.
