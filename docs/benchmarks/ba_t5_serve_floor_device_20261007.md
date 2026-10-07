# `BA-T5`: can the floor device serve archival shards? Floor run of 2026-10-07

**State of this record: RUN COMPLETE, 2026-10-07 05:03Z to 07:25Z.**

**The floor device can serve every shard production serves today.** A
servable shard is a frozen segment, and a frozen segment is always a full
one. On that frame all four lines hold, with the margins under "Reading".

**One line failed as it was registered, and the registration was wrong
about what it named.** Line (a) was registered to be read against a
one-leaf frame as "the smallest frame". Production cannot serve a frame
that small. Read that way the line fails (8.4 ms against 5), and under
the registered rule the other lines then go ungraded; the registered
text and that outcome are left exactly as they were. The one-leaf figure
is kept as a **projection** for any future design that serves short
frames, labelled as one
([`76-device-provisioning-floor`](../../.cursor/rules/76-device-provisioning-floor.mdc),
discipline 5). Reading line (a) on production's frame instead of the
registered one is a change made after the run. It rests on a fact about
the code and not on the numbers, it is stated here first for that
reason, and it is the maintainer's to accept or refuse.

Everything under "Registered before the run" was committed and pushed
before the first timed block (`f1b551b4cb`, amended once at `625488e5ed`,
also before the run) and has not been edited since.

## The question

Ruled by the maintainer, 2026-10-07: **the Pi 4 is the ground floor for the
serve path as well as for the daemon.** If the design fits there, the
published minimum for a serving staker is the Pi, and that is the reason.
If it does not, this record says where it fails and the minimum is set
from that failure. The answer is categorical either way: the floor device
can serve shards, or it cannot.

The floor device is the Raspberry Pi 4 Model B of
[`76-device-provisioning-floor`](../../.cursor/rules/76-device-provisioning-floor.mdc).
Devices are named by role here.

## Registered before the run

### The verdict, and the four lines it is drawn from

The floor device **can serve** if all four hold. The lines were set by the
maintainer before the run, from figures already in the tree.

| # | Criterion | Line | Why that line |
| --- | --- | --- | --- |
| a | CPU per abandoned request, before the requester has received anything | Does not grow from the smallest frame to a full segment (ratio ≤ 1.5), and stays under 5 ms | The `BA-Q3` invariant: `P` does no work that scales with the shard until the requester has received the bytes that work is for. Anything that scales is a defect, whatever the device |
| b | Responses per second at eight in flight | ≥ 0.5 per second | Ten times the honest demand the ruling takes from `U1b`, 0.046 reads per second per device. Abuse is bounded by (a) and the permit cap, not by throughput |
| c | Wake lateness on the endpoint's executor, p99, with a daemon alongside | ≤ 100 ms | Well under the tightest daemon deadline that shares the board: the clearnet gap of 1.430 s and the Tor gap of 2.6 s (`p2p_cutover_crossbuild_20260929.md`). Serving must not degrade the node |
| d | Serving plus daemon, sustained for one hour at the (b) rate | No thermal throttling; memory within the 8 GB board with the daemon resident | A floor device runs both roles |

If any of (b) to (d) fails, this record states which and by how much, and
the change it requires follows from the failed line: a lower
`MAX_INFLIGHT`, a stated serving minimum above the floor device, or a
design change. **If (a) fails, that is a code defect, and nothing else in
this record is graded until it is fixed.**

How each line is read from the run, fixed now so the numbers cannot choose:

- **(a)** `ABANDON` rows. CPU per abandoned request is the process's CPU
  over a batch of 200 divided by 200. The ratio is the full segment from
  the on-disk store over the one-leaf frame; both figures must be under
  5 ms. The same requester against a shard that is not held is reported
  beside them as the cost of a request that serves nothing, and is not
  subtracted for the verdict. Graded on arm B if #995 has merged by the
  time this record lands and on arm A otherwise; both are reported.
- **(b)** `BLOCK` rows of mode `load`: fetches divided by wall time, per
  block. The line is met if the **lowest** block of the graded arm is at
  or above 0.5 per second.
- **(c)** `LATE` rows. The line is met if the **highest** p99 over the
  graded arm's eight-in-flight blocks and over every minute of its
  sustained hour is at or below 100 ms.
- **(d)** The sustained hour at one fetch every two seconds (0.5 per
  second). No thermal throttling is read as: the board temperature,
  sampled every 30 s, never reaches 80 °C, the point at which this board's
  firmware begins to throttle. The firmware's own throttled flag is not
  readable on this device without root, and that is stated as a limit, not
  hidden. Memory is read as: the probe's and the daemon's resident sizes
  together stay under the board's memory, `MemAvailable` never falls below
  512 MB, and swap use does not grow.

### What I expect, written down before looking

- **(a) may fail on its 5 ms half, at the smallest frame, and not for the
  reason the line was drawn.** A one-leaf response is 128 bytes of body.
  The whole of it fits in the socket buffer, so the write succeeds whether
  or not the requester ever reads it, and `P` goes on to sign. An
  abandoned one-leaf request therefore costs one hybrid signature, which
  on x86 is most of a millisecond and on this device may be several. A
  full segment does not fit, the write fails after the first chunk or
  two, and `P` never signs. So I expect the ratio (full over smallest) to
  be **below one**, and the smallest frame to be the expensive one. If
  that is what the run shows, the invariant holds as written (the bytes
  were handed over) and the 5 ms half measures the signature scheme.
- **(b)** will pass by two orders of magnitude: run 3 read 40 to 60
  responses per second on the single-pass tree.
- **(c)** I expect both arms to pass the 100 ms line, and arm B to have
  the lower p99 if hashing on the executor is what held workers. If B is
  not lower, the hypothesis behind #995 is wrong about the 19 ms and this
  record will say so.
- **(d)** I expect a pass: 0.5 responses per second is about 3 % of one
  core.

### Arms

| Arm | Tree | What differs |
| --- | --- | --- |
| A | `dev` at `42233bd135` | The delivery digest is folded on the async executor, after the blocking-pool read returns |
| B | `bfcf46c092`, the code commit of PR #995, whose parent is `42233bd135` | The read and the fold are one blocking-pool step |

The two trees differ by that commit alone. Same toolchain (rustc 1.94.0,
aarch64), release profile, `RUSTFLAGS` unset. Arms alternate A, B within
every round.

### Conditions

- **The daemon is resident in every block.** A testnet `shekyld` runs on
  the device as a system service, following the chain, not mining. This
  lane has no root on the device and cannot stop it, so there is **no
  arm without the daemon**. That is a departure from the brief, which
  asked for both. It is the condition lines (c) and (d) are about; what
  is lost is the comparison that would say how much of any lateness the
  daemon itself contributes. Its CPU share, height and sync state are
  sampled at every block boundary.
- Loopback only. No Tor. Those are `BA-T7`'s conditions.
- The store is on the USB SSD.
- Governor and board temperature at the start and end of every block.
  The governor is `ondemand` and cannot be changed without root.
- Warm cache for every block except the cold blocks. **A cold fetch is
  the first fetch of a fresh process over a store file whose pages have
  just been dropped** (`sync`, then `dd iflag=nocache`, checked with
  `fincore` to read zero resident bytes). Two things forced that shape.
  The global page cache cannot be dropped without root, so only the store
  file's pages are. And a store written by the probe's own process sits
  in the store's in-process cache whatever the kernel has dropped, so the
  reader has to be a new process over an existing file. The control for
  it is the same fresh process without the drop, which separates "cold
  disk" from "new process".
- Nothing else runs on the device: it is held under a quiet claim.

### The signature scheme

The sign phase times **today's receipt signature: Ed25519 + ML-DSA-65,
the hybrid, under `shekyl/archival-attestation-scheme-v3`.** The receipt
key is ruled to move to Ed25519 + FN-DSA-1024
(`ARCHIVAL_SERVE_CREDIT_SPEC.md`, the Slice C Round 0 specification,
open as pull request #993 when this was written and not on `dev`; not built). When that lands,
the sign phase is re-run alone; the rest of this session does not depend
on the scheme. FN-DSA signing is expected to be cheaper than the ML-DSA
hybrid on this core. If so, every figure here that includes a signature
is conservative, and the verdict with it.

### Blocks

Each invocation of the probe opens a fresh store, so every block starts
from the same state.

| Phase | Mode | Per arm | What it yields |
| --- | --- | --- | --- |
| 0 | `idle` | 1 block of 10 s | What the lateness task reads when nothing is served |
| 1 | `phase` | 4 rounds; each 50 fetches at one in flight at each of three sizes (full segment from the store, an eighth of a segment and one leaf from memory), after 5 discarded; and 25 each of read, hash and sign alone | Per-response time at three sizes, n = 200 per cell; the phase split, n = 100 per cell |
| 2 | `cold` | 10 fresh-process fetches with the store's pages dropped before each, and 10 without the drop as the control | First-read cost from the SSD, apart from the cost of a new process |
| 3 | `load` | 6 rounds of 128 fetches at eight in flight, full segment from the store | Throughput and wake lateness. Six blocks per arm, to settle run 3's 59.6 against 39.7 |
| 4 | `abandon` | 2 rounds of 200 abandoned requests per cell: not held, one leaf, full segment from memory, full segment from the store | Line (a), n = 400 per cell |
| 5 | `sustain` | 1 hour at one fetch every 2 s, full segment from the store, B then A | Lines (c) and (d) |

The phase split is by subtraction and says so: read, hash and sign are
each timed alone on one thread, and "write and everything else" is the
whole response less those three.

### What the probe cannot measure, known now

- **Chunks read per abandoned request.** The brief asked for this from a
  counting provider. The counting body is test-only inside the crate and
  is not reachable from a probe that builds against an unmodified arm.
  The probe reports instead the bytes transmitted on loopback per
  abandoned request, which bounds the chunks from above: the loop reads at
  most one chunk past what it wrote. `serve_invariant_tests.rs` asserts
  the chunk count itself, with both socket buffers pinned.
- **Server CPU apart from the requester's.** One process holds both, as
  in runs 1 to 3. The requester of an abandoned request does almost
  nothing; the not-held cell shows what "almost" is.

### Void conditions

A block is void, and is re-run and reported as re-run, if: the probe
exits non-zero; the daemon restarts, or stops following the chain, during
it; the board temperature reaches 80 °C during a block that is not the
sustained hour; or another process uses more than 5 % of a core during it.
The session is void if the two arms were not built from the commits named
above.

## Reading

70 blocks, every one exited 0, the probe's error stream empty. Board
45.3 to 60.4 °C. The daemon stayed up on one process throughout,
synchronized, not mining, and its height went from 895 to 974. Graded arm:
**A**, because #995 had not merged when this landed; B is reported beside
it in every table.

### Line (a): holds on the frame production serves; failed as registered, on a frame it cannot

CPU per abandoned request, n = 400 per cell:

| Abandoned request for | Arm A | Arm B | Bytes on loopback per request | |
| --- | ---: | ---: | ---: | --- |
| a full segment, from the store | 3.91 ms | 3.82 ms | 721 | **production's frame** |
| a full segment, from memory | 3.16 ms | 3.09 ms | 721 | the same size without the store's read path |
| one leaf, from memory | 8.43 ms | 8.28 ms | 929 / 924 | *projection: a size production cannot serve* |
| a shard that is not held (serves nothing) | 1.70 ms | 1.70 ms | 770 | the cost of a request that serves nothing |

**What production can serve.** `StoreShardProvider` answers with a frozen
segment or with nothing, and the store opens a frozen segment as exactly
`leaves_per_segment()` leaves (`LeafStore::open_frozen_segment_body`). An
unfrozen, partial segment is the 404. So the smallest frame production
serves is the full segment, and it is the only one.

- **On that frame line (a) holds.** An abandoned full segment costs
  3.9 ms of CPU, under the 5 ms line, and with one servable size there is
  nothing for it to grow from: the ratio is 1. About 720 bytes reach
  loopback per abandoned request, the head and nothing of the body: the
  first chunk's write is refused, so `P` reads and hashes one chunk it
  cannot send and stops. That is the one-chunk lookahead
  `serve_invariant_tests.rs` asserts.
- **As registered, against the one-leaf frame, it fails**: 8.4 ms against
  5. The ratio half holds even there (full over one-leaf is 0.46: CPU
  falls as the shard grows).
- **Why the projected frame is expensive.** A 128-byte body fits in the
  socket buffer whether or not the requester reads it, so every write
  succeeds and `P` does the whole response, signature included, for a
  requester that has gone. A one-leaf response served back to back costs
  4.8 ms of CPU; abandoned, with a 30 ms gap before the next, 8.4 ms.
  What the extra 3.6 ms is has not been established.
- **What the projection is for.** If a later design serves frames small
  enough to be buffered whole, it must not sign until the requester has
  taken the body, which a successful write cannot tell it. Nothing needs
  that today.

### Lines (b), (c) and (d)

Ungraded under the registered rule while (a) as registered stands
failed; each holds.

| Line | Arm A | Arm B | Line | |
| --- | --- | --- | --- | --- |
| (b) responses per second at eight in flight, lowest of six blocks | 40.8 | 51.9 | ≥ 0.5 | holds, by 80 to 100 times |
| (c) wake lateness p99, worst of the eight-in-flight blocks and of every minute of the hour | 57.5 ms | 5.6 ms | ≤ 100 ms | holds |
| (d) hottest in the sustained hour | 50.6 °C | 55.0 °C | < 80 °C | holds |
| (d) lowest memory available in the hour | 6,580 MB | 6,569 MB | ≥ 512 MB | holds |

Line (d), further: the probe's resident size was 65 to 86 MB and the
daemon's 377 to 387 MB on a 7.6 GB board. **Its swap clause was not
captured**: the environment rows carry no swap counter. The device has no
swap configured (`SwapTotal` 0 kB, read before the run and again an hour
after it), so there was nothing to grow, but that is an observation
outside the capture and is reported as one. Each hour served
1,801 full segments, one every two seconds, every one whole.

### What moving the hash off the executor did (#995)

| | Arm A: hash on the executor | Arm B: hash in the blocking-pool hop |
| --- | --- | --- |
| Full segment, one in flight, median / mean / p95 (n = 200) | 57.7 / 58.5 / 67.3 ms | 52.1 / 53.1 / 61.4 ms |
| Responses per second, eight in flight, six blocks | 40.8, 43.9, 56.3, 56.4, 41.6, 55.6 | 52.4, 52.9, 51.9, 52.4, 52.6, 52.4 |
| Wake lateness p99, eight in flight, six blocks | 50.3, 57.5, 37.1, 28.1, 50.6, 33.4 ms | 5.0, 5.5, 5.3, 5.5, 5.6, 5.4 ms |
| Wake lateness maximum, eight in flight | 93.6 ms | 8.6 ms |
| Wake lateness p99, idle endpoint | 1.19 ms | 1.18 ms |
| Wake lateness p99, sustained hour, worst minute | 1.31 ms | 1.29 ms |
| CPU per response, eight in flight | 65 to 71 ms | 68 to 69 ms |

- **The hypothesis behind #995 holds.** With the hash on the executor, a
  1 ms sleep on the endpoint's runtime wakes up to 57 ms late at the 99th
  percentile under eight in flight, and 94 ms late at worst. With the hash
  in the hop it is 5.6 ms and 8.6 ms. The idle reading is 1.2 ms, the
  timer's own grain, so the figures are that much above nothing.
- **A full response is 5.6 ms faster** at one in flight.
- **Run 3's two blocks that disagreed are explained.** Arm A is bimodal:
  three blocks near 41 responses per second and three near 56. Arm B
  reads 52 in all six. The work per response is the same (CPU per
  response is within a few milliseconds); what varies in A is how the
  executor's workers happen to be held.
- At one fetch every two seconds, lateness is at the timer's grain on
  both arms. The starvation is a property of load, not of serving at the
  honest rate.

### Where a full segment's time goes

Each phase timed alone on one thread, n = 100; the remainder is by
subtraction.

| Phase | Arm A | Arm B |
| --- | ---: | ---: |
| Read from the store, at the serve loop's chunk size | 11.8 ms | 11.7 ms |
| Delivery digest | 23.9 ms | 23.9 ms |
| Signature (Ed25519 + ML-DSA-65) | 2.1 ms | 2.5 ms |
| Write, hand-offs and everything else | 19.9 ms | 14.0 ms |
| **Whole response, one in flight** | **57.7 ms** | **52.1 ms** |

- **The digest alone is 23.9 ms**, the figure run 1 measured. Run 3's
  "43 ms for the digest" was the single-pass tree less the tree before
  #954, which is everything that tree gained and not the hash alone.
  Here the hash is 23.9 ms of a 57.7 ms response and 19.9 ms is left
  over after read, hash and sign are taken out. So the 19 ms run 3 could
  not attribute is not the hash costing more inside the stream; it is in
  that remainder. Moving the hash off the executor recovers 6 ms of it.
  What the other 14 ms is, this run does not say: it holds the socket
  writes, 51 blocking-pool hand-offs, and the requester's reads.
- **The signature is cheap on this core**: median 2.5 ms, mean 3.0 ms,
  maximum 11.8 ms over 200. The FN-DSA-1024 receipt key is expected to be
  cheaper still, so figures here that include a signature are
  conservative.
- Smaller shards, whole response at one in flight: an eighth of a segment
  8.2 / 8.7 ms, one leaf 3.6 / 3.9 ms (A / B).

### Cold

A full segment read by a fresh process with the store's pages dropped
(checked: zero bytes resident before every one): **716 ms (A), 714 ms
(B)**, median of 10. The same fresh process with the file cached: 88 ms
and 78 ms. So the first read of a shard that is not in memory costs about
630 ms more, once, from this SSD over USB 3.

### Against what was predicted

| Quantity | Predicted | Measured (arm A / arm B) | |
| --- | --- | --- | --- |
| Responses per second, eight in flight | 37 to 60 | median of six blocks 49.7 / 52.4 | held |
| Work before the first byte | under 1 ms per request | not isolated; bounded from above at 2.2 / 2.1 ms by a whole abandoned request | **still open** |
| Median per response, one in flight | 40 to 60 ms (falsified by run 3 at 67.2 ms) | 57.7 / 52.1 ms | see below |
| An abandoned one-leaf frame costs a signature | expected | 8.4 ms, more than a served one | as expected |
| Arm B lowers p99 lateness | expected | 57.5 to 5.6 ms | as expected |

- **Work before the first byte is not settled by this run.** The probe
  cannot stop the clock at the head. What it measures is a whole
  abandoned request, which also holds one chunk read, one chunk hashed
  and a refused write: 2.2 ms over a request that serves nothing. That is
  an upper bound on the pre-head work, and an upper bound above 1 ms says
  nothing about whether the thing itself is under 1 ms. The estimate
  stays open in the ledger, with this bound in its basis; what settles it
  is a floor block that times the pre-head step alone. `BA-T3` counts
  that step at 13.6 thousand instructions.
- **The 40 to 60 ms prediction.** Run 3 measured 67.2 ms and the ledger
  records the prediction as falsified against that capture. This run
  reads 57.7 ms on the same serve order, inside the band. The two runs
  differ in the instrument: run 3's requesters shared the endpoint's
  runtime, and here they have their own. The ledger row stays as it is,
  a prediction judged against the capture that judged it; this is the
  note that the instrument moved the number by about 10 ms.

### Limits of this run

- **No arm without the daemon**, as registered. Its share of one core
  was 0.2 % at the median block and 1.3 to 2.0 % across the sustained
  hours, so it was a light neighbour: this run does not show serving
  beside a daemon that is busy syncing.
- **The void condition on other load could not be tested as written.**
  Total CPU on the board less the probe's and the daemon's leaves 4 to 6 %
  of one core in the sustained hours. That remainder holds this run's own
  sampler and the probe's store build, which the probe does not count as
  its own; it was not separated from a foreign process. The device was
  held under a quiet claim.
- **One environment sample of 380 lacks the daemon's state**: its RPC did
  not answer within five seconds at the end of arm A's second
  eight-in-flight block. The daemon's process and height were unchanged.
- **The run began 67 seconds after the second build ended**, with the
  board at 56 °C; run 3 waited five minutes. The first blocks ran warmer
  than the last (60 against 46 °C).
- Throttling was read from temperature, the cold cache was the store
  file's pages, and chunks read per abandoned request came from loopback
  bytes, all as registered.
- **The registration named a frame production cannot serve** as the
  smallest, in how line (a) is read. Whether a one-leaf frame is servable
  was checkable in the code before the run and was not checked.
- Loopback only. A requester over Tor takes the bytes far more slowly,
  which is `BA-T7`.

## Files

- `ba_t5_serve_floor_device_20261007_obs.tsv`
  (sha256 `d427e84c57f9c6d0d9bbc338588b59d79a3e663ebb67456614720a26a7da9502`):
  the probe's rows, and one `EXIT` row per block. Row kinds and columns
  are in the probe's header.
- `ba_t5_serve_floor_device_20261007_env.tsv`
  (sha256 `5642decb27e7b9a2d903df86f11fea815f5d39b4bde874c6dddbefffd1c1ff12`):
  one `ENV` row at each block boundary and every 30 s of the sustained
  hours; its first line names the columns.
- The probe: `rust/shekyl-p-serve/tests/ba_t5_floor_probe.rs`, ignored
  by default, one source for both arms. **As run** it is the file at
  commit `625488e5ed` (sha256
  `0e842db5d25b0ca718993123a3bbff335bfa9188a424f4b0a275a8a73bfd3f3a`).
  It has since been changed on review to keep its store in a child
  directory of its own and to say which of its bodies are production's;
  neither change touches what is timed.
- The reading: `python3 scripts/bench/ba_t5_reading.py <obs> <env>` prints
  every figure above, refuses a capture that is not the complete
  registered run, and applies the four lines, line (a) both as registered
  and on production's frame.
