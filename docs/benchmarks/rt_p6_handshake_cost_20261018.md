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

None yet.

## Results

None yet.
