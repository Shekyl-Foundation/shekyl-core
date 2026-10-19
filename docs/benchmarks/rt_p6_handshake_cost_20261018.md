# `RT-P6`: what a handshake costs on the floor device, each side. Registration of 2026-10-18

**State of this record: measured, 2026-10-19.** The registered cell ran
on the floor device under a quiet claim and passed both gates. The
derivations below remain proposals for the maintainer to rule. The dry
run is recorded below the registration, and it is not data. Results are
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

*Amended 2026-10-19, before any result was read. The first registration
(`311266fb4`) timed `Daemon::new` inside the `read_message1` sample, kept
one plaintext per recorded seal, and timed random 2,320-byte messages.
`read_message1` refuses a random encapsulation key before either long-term
operation, so those samples never paid the decapsulation or the
Diffie-Hellman. The summary treated a step missing from one iteration as a
zero and omitted the CPU 90th percentile and the CPU maximum. The
amplification paragraph multiplied by `conn_limit` as though that were a
count of attempts per deadline; `ConnGuard` releases its slot on drop.
The question is unchanged. What follows is the method.*

**Subject.** `shekyl-rpc-channel`'s handshake (`Client`, `Daemon`,
`PendingSession`) and `shekyl-noise`'s `Direction`, at the commit the run
is made from. Built with `cargo build --release` under the workspace's
pinned toolchain (1.94.0) and release profile, on the floor device itself,
from a fresh clone of that commit.

**Instrument.** `rust/shekyl-rpc-channel/examples/rt_p6_handshake_cost.rs`.
It runs on Linux. Any other host compiles the example and exits without
writing a run, because the registered CPU clock is Linux's
`CLOCK_THREAD_CPUTIME_ID` and the host is the Pi 4. On the floor device it
runs both roles in one process, pinned to one core with `taskset -c 3`.
Each timed region is one call between two clock reads, on the wall clock
(`Instant`) and on the thread's CPU clock. The raw samples are written one
per row. The summary is `scripts/bench/rt_p6_summary.py`.

1. **Every step of a full handshake.** The client's `start`,
   `read_message2`, `write_message3`, `read_message4`, and
   `into_directions` with the first record's seal (`first_record`); the
   daemon's `new` (the initial symmetric state: protocol name, prologue,
   static keys), `read_message1`, `write_message2`, `read_message3`,
   `write_message4` and `open_first_message`. `new` and `read_message1`
   are separate samples. The two static identities are made before the
   loop. The ephemeral keys each step draws are part of its cost, as in
   production. Message 3's and message 4's payloads are 64 bytes each:
   their encoding is RT-W10's and is fixed-length (§6.2), and a symmetric
   cipher's cost barely depends on the length.
2. **A stranger's message 1.** Two kinds, both made before the timed
   reads. **honest:** a message 1 from `Client::start`. **tag_flipped:**
   that message with the last byte of its tag flipped (`TAG_LEN` is the
   suffix). The encapsulation key and the ciphertext still parse, so
   `read_message1` pays the decapsulation and the X25519 Diffie-Hellman
   and then the tag fails. For each message the daemon's `new` and
   `read_message1` are timed as two calls. The attempt is their sum.
   Every honest message is accepted and no tag-flipped one is.
3. **One record at each class:** `Direction::seal` and `Direction::open`
   of 512, 16,384 and 65,535 bytes. One plaintext of that length is filled
   before the timed loop and reused. The ciphertexts are the seals'
   outputs, kept for the open loop: about 626 MiB at the 65,535-byte class
   (10,000 ciphertexts of 65,535 + 16 bytes), plus one plaintext. This is
   `Direction`'s cost. The session has already carried the handshake's
   first record, so the first recorded nonce is 1. `Direction` rekeys
   every 1,000 nonces (`REKEY_NONCES`). Ten of the 10,000 samples of each
   operation include that HKDF. When those ten are the slowest, the
   maximum includes a rekey and the 99th percentile does not: nearest rank
   9,900 of 10,000. `ClassedRecord`'s header byte and its header protection
   do not exist until RT-W9 step 5; they are measured there.

**Counts.** Each cell warms up, and the warmup is not recorded: 5 on the
dry cell, 200 on the registered cell. The record warmup is that many seals
and opens at the class, on a session that is then dropped, so the timed
nonces still start at 1 and the cipher has already seen the length. Then
10,000 handshakes; 10,000 messages 1 of each kind; 10,000 seals and 10,000
opens at each class.

**Statistics** (`scripts/bench/rt_p6_summary.py`, its tests in
`scripts/bench/test_rt_p6_summary.py`, run in CI). Percentiles are
nearest-rank. For each series: the median, the 90th and 99th percentiles
and the maximum, of both clocks.

- Each handshake step.
- Each side's total per handshake, and both sides together. A side's total
  is the sum of that iteration's steps. Both is the sum of the two sides.
- A stranger's message 1, for each kind, in three parts: `new`,
  `read_message1`, and the attempt (`new` + `read_message1` of that same
  message).
- Seal and open at each class, and CPU nanoseconds per byte from the CPU
  median.

The summary refuses a capture that is not this shape, and names the
defect: a handshake step missing from an iteration, repeated, or
unexpected; a message-1 kind missing, repeated, unexpected, or accepted
against its kind; a record class or operation missing, repeated, or
unexpected; a missing file. The tests' control is a complete fixture whose
medians the test computes itself. A refusal with no such control would stay
green if the loader rejected every file.

**Gates.** A run that fails any of these is void, and the failure is
recorded:

- Every handshake step succeeds. Every honest message 1 is accepted and no
  tag-flipped one is. The harness asserts it, and the summary refuses a
  file that says otherwise.
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
pushed commit and runs the dry cell first (the dry counts above), then the
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
    adds what this run measures. The compute part includes the daemon's
    `new` and `read_message1` as separate steps of the same handshake.
- **Amplification.**
  - Reported: the daemon's CPU for one message-1 attempt, for each kind,
    as a median, a 90th, a 99th and a maximum. The attempt is that
    message's `new` plus its `read_message1`. The figure used for a bound
    is the greater of the two kinds at that percentile. Both kinds pay the
    decapsulation and the Diffie-Hellman. The honest kind also builds the
    next handshake state. The tag-flipped kind stops at the tag.
  - `conn_limit` is how many connections may be in flight.
    `ConnGuard` releases its slot when it is dropped, so a sender who
    finishes or abandons an attempt can take the slot again inside one
    deadline. `conn_limit` × the cost of one attempt is a picture of
    concurrency. It is not a count of attempts per deadline, and it is not
    a bound on sustained CPU.
  - This run measures the cost of one attempt. It does not measure how
    many attempts the daemon admits in a deadline: that is a rate, and the
    network is not in the run. Whether §4.3 needs a further bound is
    decided from those two facts kept apart.
- **Tunnel pool.** Reported: the client's cost per handshake. The pool size
  is RT-W11's decision.

**What this does not measure.**

- The network, and therefore how many attempts fit in a deadline.
  Contention beyond the standing daemon recorded above is not in the run
  either.
- The header byte and header protection of `ClassedRecord`.
- An x86 machine: the floor device is the provisioning floor, and RT-P6
  asks about it alone.

## Dry run

Two, neither of them data.

- **On the development workstation**, before the registration was pushed:
  an instrument check that the harness runs and writes its three files.
- **On the floor device**, in the registered sequence: the dry cell (50 of
  each, after 5 warm-up handshakes) at 18:56:58Z, 1 s, exit 0. The summary
  script read its files without a refusal.

## Results

**The registered cell passed both gates.** The figures below are its
summary (`rt_p6_summary.py`), as produced. Captures, with checksums:
[`rt_p6_handshake_cost_20261018_captures/`](rt_p6_handshake_cost_20261018_captures/).
The three raw files are there gzipped (`gzip -9n`), with the summary, the
conditions and the run's step log.

### Conditions, recorded as registered

- **Device and build:** the floor device (Raspberry Pi 4, Cortex-A72, 4
  cores, 1.8 GHz top clock), under a quiet claim. A fresh clone of
  `02f7665bae` (`dev`, carrying this registration as merged), built in
  release with toolchain 1.94.0 in 170 s.
- **Timing:** a 180 s cool-down, the dry cell, then the registered cell
  pinned to core 3, 18:57:59Z to 18:59:17Z (78 s).
- **The standing testnet daemon** was left running, as the registration
  proposed. The maintainer said to start the run after merging the
  registration with that proposal in it. The daemon was active at every
  reading and used 70 ms of CPU over the registered cell (7 ticks).

| | Before the registered cell | End |
|---|---|---|
| Governor | `ondemand` | `ondemand` |
| SoC temperature | 46.3 °C | 52.1 °C |
| Load, 1 min | 0.10 | 0.83 |
| Under-voltage alarm | 0 | 0 |
| Clock-speed changes, total | 7,446,668 | 7,446,700 |

**Gates.**
- The harness's assertions held: every step succeeded, all 10,000 honest
  messages 1 were accepted, and no tag-flipped one was.
- The under-voltage alarm stayed clear.
- Time at top clock over the registered cell: 7,843 of 7,852 ticks at 1.8
  GHz, **99.89 %**, against the registered 99 %.

### Each step (µs)

| Side | Step | n | Wall median | Wall p90 | Wall p99 | Wall max | CPU median | CPU p90 | CPU p99 | CPU max |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| client | `start` | 10000 | 873.3 | 885.7 | 890.9 | 989.0 | 875.2 | 882.9 | 887.0 | 976.4 |
| daemon | `new` | 10000 | 8.6 | 8.6 | 9.3 | 31.6 | 10.0 | 10.1 | 16.9 | 28.7 |
| daemon | `read_message1` | 10000 | 630.6 | 643.5 | 647.4 | 700.9 | 632.4 | 640.6 | 643.9 | 715.5 |
| daemon | `write_message2` | 10000 | 863.5 | 876.1 | 881.1 | 1,364.6 | 865.4 | 873.3 | 877.2 | 1,294.3 |
| client | `read_message2` | 10000 | 622.7 | 636.1 | 640.0 | 724.2 | 624.6 | 633.2 | 636.4 | 734.6 |
| client | `write_message3` | 10000 | 345.3 | 352.8 | 366.6 | 391.9 | 346.9 | 354.5 | 363.4 | 379.7 |
| daemon | `read_message3` | 10000 | 352.0 | 371.4 | 373.4 | 480.6 | 353.6 | 368.7 | 370.2 | 491.4 |
| daemon | `write_message4` | 10000 | 240.4 | 248.1 | 261.0 | 357.7 | 242.2 | 249.9 | 258.3 | 362.2 |
| client | `read_message4` | 10000 | 292.2 | 313.0 | 314.5 | 335.1 | 294.1 | 310.2 | 311.6 | 336.3 |
| client | `first_record` | 10000 | 6.7 | 6.9 | 7.7 | 29.6 | 8.2 | 8.4 | 9.6 | 25.7 |
| daemon | `open_first_message` | 10000 | 7.2 | 7.3 | 8.4 | 34.5 | 8.7 | 8.8 | 10.1 | 33.5 |

### Per handshake (µs)

| Total | n | Wall median | Wall p90 | Wall p99 | Wall max | CPU median | CPU p90 | CPU p99 | CPU max |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| client | 10000 | 2,152.8 | 2,165.8 | 2,178.8 | 2,348.5 | 2,157.3 | 2,167.2 | 2,177.2 | 2,343.8 |
| daemon | 10000 | 2,113.6 | 2,120.6 | 2,135.9 | 2,945.1 | 2,119.1 | 2,126.1 | 2,136.1 | 2,907.8 |
| both | 10000 | 4,265.1 | 4,277.9 | 4,296.3 | 5,262.7 | 4,275.1 | 4,287.2 | 4,298.4 | 5,246.8 |

### A stranger's message 1 (µs)

| Kind | Part | n | Accepted | Wall median | Wall p90 | Wall p99 | Wall max | CPU median | CPU p90 | CPU p99 | CPU max |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| honest | `new` | 10000 | 10000 | 8.5 | 8.5 | 15.1 | 90.3 | 9.9 | 10.0 | 16.7 | 70.2 |
| honest | `read_message1` | 10000 | 10000 | 628.4 | 641.1 | 682.5 | 800.8 | 630.2 | 638.4 | 685.6 | 789.6 |
| honest | `attempt` | 10000 | 10000 | 636.9 | 649.6 | 693.5 | 810.6 | 640.1 | 648.4 | 697.1 | 810.2 |
| tag_flipped | `new` | 10000 | 0 | 8.6 | 9.9 | 16.2 | 117.8 | 10.0 | 11.4 | 18.1 | 81.9 |
| tag_flipped | `read_message1` | 10000 | 0 | 629.4 | 677.2 | 802.5 | 1,137.7 | 631.1 | 680.4 | 802.9 | 1,089.1 |
| tag_flipped | `attempt` | 10000 | 0 | 637.9 | 687.4 | 815.7 | 1,163.7 | 641.1 | 692.6 | 818.5 | 1,117.1 |

### One record at each class (µs)

| Class (bytes) | Op | n | Wall median | Wall p90 | Wall p99 | Wall max | CPU median | CPU p90 | CPU p99 | CPU max | ns per byte (CPU median) |
|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 512 | seal | 10000 | 4.3 | 4.3 | 4.6 | 891.3 | 5.7 | 5.7 | 6.2 | 884.2 | 11.07 |
| 512 | open | 10000 | 4.3 | 4.4 | 4.7 | 25.1 | 5.6 | 5.8 | 6.1 | 21.4 | 11.03 |
| 16,384 | seal | 10000 | 113.2 | 119.5 | 145.6 | 1,066.0 | 114.7 | 121.1 | 139.8 | 1,060.1 | 7.00 |
| 16,384 | open | 10000 | 111.1 | 116.9 | 130.0 | 158.5 | 112.6 | 118.4 | 127.4 | 147.1 | 6.87 |
| 65,535 | seal | 10000 | 448.6 | 468.9 | 1,263.6 | 2,042.1 | 450.1 | 465.7 | 1,257.2 | 1,996.8 | 6.87 |
| 65,535 | open | 10000 | 441.8 | 458.8 | 468.7 | 564.1 | 443.3 | 456.2 | 463.9 | 533.4 | 6.76 |

### Reading the figures

- **A full handshake** costs each side about 2.16 ms of CPU (client median
  2,157.3 µs, daemon 2,119.1 µs), and 4,298.4 µs for both together at the
  99th percentile. The wall clock tracks the CPU clock within a few
  microseconds at every percentile up to the 99th.
- **The 65,535-byte seal's tail is the harness's own.** Its 99th
  percentile is 1,257.2 µs against a median of 450.1 µs, while the open at
  the same size has a 99th percentile of 463.9 µs.
  - The slow seals (307 above 800 µs) are periodic: one every 32 samples,
    from sample 205 to sample 9,992, and none among the opens.
  - The seal loop keeps every ciphertext, as registered (about 626 MiB).
    Thirty-two ciphertexts of 65,551 bytes is 2 MiB, so these are the heap
    growing and touching fresh pages.
  - The cipher's own 99th percentile at that size is the open's, 463.9 µs,
    and the seal's 90th percentile, 465.7 µs, agrees with it.
  - The registered figure stands as recorded; this says what it contains.
- **Rekey is not visible.** The registration expected the ten samples that
  include a rekey to be each operation's slowest. They are not.
  - At 512 bytes they rank 18th to 25th slowest.
  - At the larger classes they are lost among other variation.
  - A rekey's HKDF does not show in these percentiles or maxima.

### The derivations, applied as proposed — for the maintainer to rule

- **Handshake deadline:** the 99th percentile of both sides' CPU per
  handshake (4,298.4 µs), plus five one-way transits at
  `ANON_ZONE_TRANSIT_ASSUMPTION_MS` (5 × 1,625 ms = 8,125 ms), is
  8,129.3 ms. Rounded up to the next whole second: **9 s**.
  - The compute part is 0.05 % of it. The deadline is set by the transit
    assumption, which is *unmeasured* (BA-T9).
- **Amplification:** the daemon's CPU for one message-1 attempt (`new` +
  `read_message1`).
  - Median: 640.1 µs honest, 641.1 µs tag-flipped.
  - 99th percentile: 697.1 µs honest, 818.5 µs tag-flipped. **The figure
    for a bound is 818.5 µs**, the greater of the two.
  - At the median, one core serves about 1,560 attempts a second.
  - At the median, an attempt is 641.1 of the daemon's 2,119.1 µs per
    handshake, about 30 %.
  - How many attempts arrive in a deadline is a rate, which this run does
    not measure.
- **Tunnel pool:** a handshake costs the client 2,157.3 µs of CPU at the
  median and 2,177.2 µs at the 99th percentile, on top of two round
  trips.
- **The response classes:** sealing or opening a record costs about 6.9 ns
  per byte at the two larger classes, and 11 ns per byte at 512 bytes:
  - 512 bytes: about 5.7 µs;
  - 16,384 bytes: about 115 µs;
  - 65,535 bytes: about 450 µs.

  A submission padded to its fixed size pays the 65,535 class's cost per
  full record.
