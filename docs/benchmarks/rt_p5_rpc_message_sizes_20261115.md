# `RT-P5`, sizes on the 4.x wire: HTTP message sizes per method on a generated wallet's traffic. Registration of 2026-11-15

**State of this record: registered, not yet run.** The section
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

*Amended twice, 2026-11-15, before any registered run. Second, after
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

## Results

Not yet measured.
