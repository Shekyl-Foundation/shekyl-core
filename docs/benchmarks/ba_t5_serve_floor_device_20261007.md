# `BA-T5`: can the floor device serve archival shards? Floor run of 2026-10-07

**State of this record: PRE-REGISTERED. No observation has been taken.**
Everything below the heading "Registered before the run" was committed and
pushed before the first timed block. The results are added under "Reading"
by a later commit; the registered text is not edited after the run except
to mark a void condition that fired.

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
- Warm cache for every block except the cold blocks. **Cold cache is the
  store file's pages only**, dropped with `dd iflag=nocache` before each
  fetch of a cold block, because the global page cache cannot be dropped
  without root. Whether the drop took effect is checked with `fincore` on
  the store file and recorded.
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
| 2 | `cold` | 1 block of 10 fetches, store pages dropped before each | First-read cost from the SSD |
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

*Not yet taken.*

## Files

*Added with the reading.* The probe is committed with this record:
`rust/shekyl-p-serve/tests/ba_t5_floor_probe.rs`, ignored by default, the
same source for both arms.
