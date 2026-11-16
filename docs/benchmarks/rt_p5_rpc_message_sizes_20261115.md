# `RT-P5`, sizes on the 4.x wire: HTTP message sizes per method on a generated wallet's traffic. Registration of 2026-11-15

**State of this record: measured.** Both registered runs passed every
gate and the determinism check. Two of the three questions this record
answers move against RT-O6, and come to the maintainer as findings
("Findings", below). The section
"Registered before the run" is committed before any run on the host and
is not edited afterwards. An amendment made before any registered result
is read is dated and says what changed. Results are added under
"Results".

## The question

`RPC_CHANNEL.md` §4.4 pads channel records to size classes (RT-O6). The
classes were derived from the registration of 2026-10-17
([`rt_p5_rpc_message_sizes_20261017.md`](rt_p5_rpc_message_sizes_20261017.md)),
whose trace was the 3.x wire: REST paths and 3.x JSON-RPC names. The
4.0 rename and its successors (`CORE_RPC_VERSION` 4.6 at this
registration) carry every method as JSON-RPC on `/json_rpc` (RW-Q1) under
new names and new reply shapes. The maintainer ruled (2026-11-12) that
RT-P5's size part is measured again on the 4.x wire, as a new
registration, before RT-W12's first production commit.

The question is the first registration's, asked of the 4.x wire: **the
size of every HTTP message, per method and direction, in a generated
wallet's traffic with a daemon**, and the candidate class tables derived
from it. This record answers three things the 2026-10-17 record's
rulings rest on:

1. **The response classes.** RT-O6 (re-ruled 2026-10-18) took `K` = 3
   with each derived boundary rounded up to the next power of two: 512,
   16,384 and 65,535. Does this trace's `K` = 3 table round to the same
   three classes?
2. **The request direction.** RT-O6's ruling rests on "every other
   request is 431 bytes or smaller": a submission cannot hide among
   requests, and no other request needs a class above 512. Is every
   request other than a submission still at most 512 bytes?
3. **The submission's encoding.** RT-O6 part 2 records that a submission
   body was the transaction hex-encoded in JSON, twice its bytes. The
   derivation reports the encoding `a + f × length` this trace shows.

## Registered before the run

*Amended three times, 2026-11-15/16, before any registered result was
read. Third, while the registered runs were made and before either was
read: the derivation script read `run.json`'s curve figures under
`curve_tree_info`, a key the 4.0 rename's port of the instrument
(`c346e38e55`) had renamed `curve`, so `derive` failed on the second dry
run's files. The script reads the instrument's key (`RUN_CURVE_KEY`), a
test holds the two equal, and another runs `derive` over a written run.
The instrument, the traffic and the rule are unchanged; the registered
runs are made from the second amendment's build, and derived with this
commit's script. Second, after
the dry run: the wallet's refresh reads each block with `block_show`,
which carries the block's transactions, and never calls `block_list`
(the chain-ingest fetch's method), so the dry run failed the subject gate
and named the labels it carried (`block_show`, `chain_height`, `fee`,
`tx_submit`, `version`). The subject and the script's block batch are
`json_rpc:block_show`. `dev` was merged into the branch with it, so the
host's clone and both builds are made again, fresh, from the commit that
carries this amendment, and the dry run is made again from that build.
First, (the build had
started, nothing had run). The instrument now writes its files before it
reads the gates, and a missing subject names the labels the trace does
carry. A run that fails a gate is still void; its files now show why, so
a wrong subject name is found from the dry run's files instead of
needing another run to discover. The host's build was made again from the
amended commit.*

**Subject, instrument, unit and flush policy: the 2026-10-17
registration's, unchanged** except where this section says otherwise.
The instrument is `engine::regtest_e2e::rt_p5`
(`rust/shekyl-engine-core/src/engine/regtest_e2e_rt_p5.rs`): a counting
TCP proxy between the production engine's daemon client (`HttpRpc`,
HTTP/1.1 only) and `shekyld --regtest`, every byte of every connection
split into whole messages after the traffic stops. A request to
`/json_rpc` is labelled `json_rpc:` and its JSON-RPC `method`; a response
carries its request's label. One HTTP message is one flush, the policy
the 2026-10-17 record registered and RT-W9 step 5b observed with
`shekyl-rpc-stream` through hyper.

**The generated traffic: the 2026-10-17 cell, unchanged.** A funding
wallet matures with a twenty-block margin; a fan-out of four
sixteen-output transactions mined in one block; the measured wallet
syncs and spends the eight shapes 1 × 2, 2 × 2, 4 × 2, 8 × 2, 1 × 16,
2 × 16, 4 × 16 and 8 × 16, each mined into the next block; a wallet
restored from the measured wallet's seed syncs the whole chain. A build
refused as `OutputNotYetSpendable` mines one block and builds again; any
other refusal fails the run. Blocks are mined with the armed lever
`dev_block_generate` over the harness's own connection, which is not
traced.

**What changed in the instrument for the 4.x wire**, in this
registration's commit:

- **Seeds.** The registered run uses `0x53` (funder) and `0x54` (measured
  and restored wallet); the dry run uses `0xD3` and `0xD4`. None of the
  four was used by the 2026-10-17 registration (`0x51`, `0x52`, `0xD1`,
  `0xD2`). Each run writes into its own directory, which must not exist
  beforehand.
- **The subjects the trace must carry** (rule 47) are 4.x methods:
  `json_rpc:tx_submit`, `json_rpc:block_show`, `json_rpc:chain_height`
  and `json_rpc:fee`. They are the submission, the block read, the tip
  read and the fee read the wallet's daemon client makes. If the dry run
  shows the wallet reaching a method this list should name in place of
  one of them, that is an amendment, made before the registered run.
- **The record constants** are read from `shekyl-noise`
  (`MAX_RECORD_PLAINTEXT`, `OCCUPANCY_LEN`), which did not exist when
  the first registration restated them. The derivation script cannot
  import them; its tests check its two numbers against the crate's
  definitions.
- **The derivation script** (`scripts/bench/rt_p5_classes.py`) names the
  submission `json_rpc:tx_submit`, the block batch a `json_rpc:block_show`
  response, and spend building `json_rpc:fee`. The derivation rule is
  unchanged.

**Gates: the 2026-10-17 registration's**, with the subjects above:

- The proxy recorded no read or write fault, and every proxied
  connection closed within 60 s of its wallet closing.
- Every byte of every connection parsed into whole messages, and each
  connection has as many responses as requests.
- The trace carries the four subjects above, and every JSON-RPC request
  names its method.
- At least one message is larger than one record's payload, 65,533 bytes.
- No build is refused except as not yet spendable.
- The fan-out block carries all four fan-out transactions; each of the
  measured wallet's spends has its registered shape, read back from the
  built transaction, and is in the block mined after it.
- There is one submission message per built transaction.
- Each built transaction's wire length equals the weight crate's
  structural size predictor at some tree depth, recorded as the depth it
  was built at.

**How the classes are derived: the 2026-10-17 rule, unchanged**
(`rt_p5_classes.py derive`): records split at 65,533 bytes with the
two-byte occupancy; for each `K` from 1 to 8, the largest class 65,535
and the other `K − 1` classes minimising total padding over every record
of the trace, both directions together; the classes a submission falls
in and what shares them; the submission at tree depths 1 to 8 from the
size predictor and the body encoding the trace shows.

**What this record adds to the derivation's output**, read against the
three questions above and stated in the results as found, not judged:

- the `K` = 3 table's two lower boundaries, each rounded up to the next
  power of two, beside RT-O6's 512 and 16,384;
- the largest request other than a submission, beside 512;
- the submission body's encoding (`a`, `f`).

**This record does not choose `K` or the classes.** If the 4.x trace
moves any of the three answers, the finding goes to the maintainer, who
rules whether RT-O6's classes or its premise change. RT-W11's tunnel
pads to whatever RT-O6 rules.

**Determinism: the 2026-10-17 rule, unchanged.** The registered cell is
run twice, back to back, from the same commit and seeds; the classes are
derived from the first, and `rt_p5_classes.py compare` checks the
second: for every wallet, method and direction, the same number of
messages, each within 64 bytes or 1 %, whichever is larger. A failed
comparison voids the pair.

**Attempts.** At most two registered attempts. A void attempt is
recorded with its cause, the cause is fixed, and the second is made under
the same lines.

**Host.** The maintainer ruled (2026-11-15) that the host does not
matter, because RT-P5 measures byte sizes, and that the run is made on
any unclaimed fleet host and recorded. The host is **`skl-staker-test`**,
a testnet staker VM (x86-64, 8 vCPU, 15 GiB, Ubuntu 24.04), the same
class of machine as the 2026-10-17 run's. It is claimed shared on the
estate ledger. Its standing testnet daemon keeps running untouched; its
load is recorded with the results, as information.

**The build.** On that host, from a fresh clone of the commit that
carries this registration: the daemon in Release and the engine's test
binary in the test profile, with the workspace's pinned toolchain
(1.94.0). The dry run and the two registered runs are made from the same
build. The commit, the host's load and its daemon's state at the start
and the end are recorded with the results.

**What this trace does not carry: the 2026-10-17 record's list,
unchanged** (the miner leg, the P-scan's full-body fetch, other clients
of the daemon, mainnet's mix and tree depth), under the same rule-21
reopen: the classes are derived again from a registered mainnet trace.

## Dry run

Made on the host, seeds `0xD3` and `0xD4`. It is a check of the
instrument, not data, and its sizes are not read here.

- **First attempt, 2026-11-16 02:16Z, 842 s: stopped at the subject
  gate.** Every traffic step passed (the fan-out, the eight shapes, each
  confirmed in its block); the gate found no `json_rpc:block_list` and
  named the labels the trace carries. Fixed by the second amendment.
- **Second attempt, 2026-11-16 02:48Z, 662 s: passed every gate**, from a
  fresh clone and build of `3e0e2be4ad`. `derive` over its files failed
  on the curve key, fixed by the third amendment.

## Results

**Both registered runs passed every gate, and the determinism check
passes.** The classes below are derived from the first run, by the
registered rule, with the third amendment's script. **`K` and the
classes are the maintainer's, and are not chosen here.** Captures, with
checksums matched against the host's:
[`rt_p5_rpc_message_sizes_20261115_captures/`](rt_p5_rpc_message_sizes_20261115_captures/)
(the two registered runs, the second dry run, the run log and the host's
state at each step).

### Conditions, recorded as registered

- **Host:** `skl-staker-test`, a testnet staker VM (x86-64, 8 vCPU,
  15 GiB, Ubuntu 24.04), claimed shared on the estate ledger. Its testnet
  daemon (`shekyld --network testnet`) was active at every check.
- **Build:** a fresh clone of `3e0e2be4ad` (the second amendment, `dev`
  at `d3f9e639c4` merged in), toolchain 1.94.0, with bindgen pointed at
  gcc's header directory; nothing installed. The daemon in Release, the
  engine's test binary in the test profile.
- **Runs, 2026-11-16 (UTC):** second dry run 02:48 (662 s), passed; first
  registered run 03:00 (708 s), passed; second 03:12 (607 s), passed.
- **Load average** (1, 5, 15 min, against 8 vCPU): 5.30, 6.61, 6.68 at
  the dry run's start; 2.98, 4.30, 5.52 at the first registered run's;
  3.24, 4.26, 4.93 at the end.
- **Chain:** height 117; curve tree at height 116, one layer, 125 leaves.

**Determinism:** `rt_p5_classes.py compare` on the two registered runs:
**PASS**, 26 groups (wallet, method and direction), the same message
count in each and every matched message within tolerance. The two
`transactions.csv` files are byte-identical.

### HTTP message sizes per method (first registered run)

788 messages; 797 records after splitting at 65,533 bytes.

| Method | Direction | Count | Min | Median | Max | Records |
|---|---|---:|---:|---:|---:|---:|
| `json_rpc:block_show` | request | 325 | 195 | 196 | 197 | 325 |
| `json_rpc:block_show` | response | 325 | 2,888 | 2,900 | 113,652 | 327 |
| `json_rpc:chain_height` | request | 35 | 162 | 162 | 162 | 35 |
| `json_rpc:chain_height` | response | 35 | 330 | 331 | 331 | 35 |
| `json_rpc:fee` | request | 19 | 153 | 153 | 153 | 19 |
| `json_rpc:fee` | response | 19 | 274 | 274 | 274 | 19 |
| `json_rpc:tx_submit` | request | 12 | 17,819 | 70,031 | 102,544 | 19 |
| `json_rpc:tx_submit` | response | 12 | 241 | 241 | 241 | 12 |
| `json_rpc:version` | request | 3 | 157 | 157 | 157 | 3 |
| `json_rpc:version` | response | 3 | 469 | 469 | 470 | 3 |

### Candidate tables, by the registered rule

| K | Classes | Padding | Padding / payload |
|---:|---|---:|---:|
| 1 | 65,535 | 49,980,724 | 2222.3% |
| 2 | 2,905, 65,535 | 2,695,074 | 119.8% |
| 3 | 333, 2,905, 65,535 | 1,542,818 | 68.6% |
| 4 | 333, 2,905, 30,781, 65,535 | 604,460 | 26.9% |
| 5 | 333, 2,905, 9,699, 30,781, 65,535 | 267,148 | 11.9% |
| 6 | 333, 2,905, 9,699, 30,781, 48,121, 65,535 | 180,078 | 8.0% |
| 7 | 199, 333, 2,905, 9,699, 30,781, 48,121, 65,535 | 128,890 | 5.7% |
| 8 | 199, 333, 2,905, 7,088, 13,068, 30,781, 48,121, 65,535 | 87,341 | 3.9% |

**What shares a submission's class:** for every `K` from 2 to 8 a
submission's records share their classes only with `block_show`
responses (23 records), the block reads larger than one record; at `K`
= 1 with everything. In the request direction a submission shares no
class with any other request at any `K` ≥ 2.

### The three questions

1. **The response classes: moved.** The `K` = 3 table's two lower
   boundaries are 333 and 2,905; rounded up to the next power of two they
   are **512 and 4,096**, against RT-O6's 512 and 16,384. The 3.x trace's
   middle cluster was the `get_block` responses (median 11,104 bytes); on
   the 4.x wire a block's read is `block_show`, whose responses are a
   median 2,900 bytes. The ruled 16,384 still holds every one of them, at
   more padding.
2. **The request direction: holds.** The largest request other than a
   submission is 197 bytes (`block_show`), at most 512.
3. **The submission's encoding: changed.** Every submission body is
   66 bytes plus its transaction base64-encoded, `66 + 4 × ⌈n / 3⌉`,
   exactly, for all twelve: the `bytes` kind's one encoding (IG-6), where
   the 3.x wire's was hex, twice the bytes. The 4.x submissions are
   17,819 to 102,544 bytes, against 26,599 to 153,688 on 3.x.
   `SUBMISSION_CAP` (`shekyl-rpc-stream`) already counts the largest
   admissible transaction base64-encoded, four largest-class records, so
   the padded submission's size is unchanged by this.

### A submission at greater tree depth

The registered script fits a submission body as `a + f × length` with
whole `f`, which base64's rounding is not; it reports that no projection
is made. The table below is computed for this record from the encoding
found in question 3 (`66 + 4 × ⌈n / 3⌉`) and the weight crate's size at
each depth (`transactions.csv`); the head is the smallest submission's,
less `content-length`'s digits (100 bytes), plus the body's. At the built
depth (2) it reproduces every measured submission. Message bytes:

| Shape (in × out) | d=1 | d=2 | d=3 | d=4 | d=5 | d=6 | d=7 | d=8 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 × 2 | 16,967 | 17,819 | 18,331 | 19,183 | 19,695 | 20,551 | 19,783 | 20,635 |
| 2 × 2 | 26,759 | 28,463 | 27,355 | 29,063 | 29,743 | 29,487 | 28,891 | 29,915 |
| 4 × 2 | 42,671 | 46,087 | 45,319 | 46,087 | 47,111 | 47,195 | 46,939 | 48,303 |
| 8 × 2 | 74,415 | 78,599 | 78,511 | 79,963 | 81,671 | 82,439 | 82,863 | 84,915 |
| 1 × 16 | 40,911 | 41,767 | 42,279 | 43,131 | 43,643 | 44,495 | 43,727 | 44,583 |
| 2 × 16 | 50,703 | 52,411 | 51,303 | 53,007 | 53,691 | 53,435 | 52,839 | 53,863 |
| 4 × 16 | 66,619 | 70,031 | 69,263 | 70,031 | 71,055 | 71,143 | 70,887 | 72,251 |
| 8 × 16 | 98,363 | 102,544 | 102,460 | 103,912 | 105,616 | 106,384 | 106,812 | 108,860 |

The largest, 108,860 bytes at depth 8, is two largest-class records; a
padded submission is four (`SUBMISSION_RECORDS`).

## Findings, for the maintainer

- **F1 — the middle response class.** RT-O6's `K` = 3 classes were
  512, 16,384 and 65,535, from the 3.x trace. On the 4.x wire the same
  rule gives 512, 4,096 and 65,535. Keeping 16,384 is safe (every
  response it held still fits) and pads the block reads between 2,905 and
  4,096 bytes up to 16,384; moving to 4,096 pads less. The classes are
  `shekyl-rpc-stream`'s `CLASS_LENGTHS`; a change is a wire change of the
  channel.
- **F2 — the submission's encoding.** RT-O6 part 2's sentence "the
  submission's body is the transaction hex-encoded in JSON, twice its
  bytes" no longer describes the wire: it is base64. The padded
  submission's size, `SUBMISSION_CAP`, already counts base64, so nothing
  in code moves; the sentence in `RPC_CHANNEL.md` §4.4 does.
