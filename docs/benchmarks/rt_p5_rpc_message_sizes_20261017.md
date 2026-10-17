# `RT-P5`, sizes: HTTP message sizes per method on a generated wallet's traffic. Registration of 2026-10-17

**State of this record: measured.** Both registered runs passed every
gate and the determinism check, on the staker VM the maintainer ruled.
The candidate tables are below; `K` is the maintainer's choice. Results
also carry a finding against RT-O6's premise (direction). The dry run is
recorded below the registration, and it is not data.
The registered run starts only after the maintainer has answered the one
departure this registration names (the host, below). Results are added
under "Results" and the section "Registered before the run" is not edited
afterwards. An amendment made before any registered result is read is
dated and says what changed.

## The question

`RPC_CHANNEL.md` §4.4 pads every channel record to one of a small set of
size classes, so that a path observer cannot tell a remote wallet's
`submit_transaction` from any other message of the same class
(RT-O6). The classes are not chosen in the design; they are derived from
the HTTP message sizes the channel will carry. RT-P5 has two registered
parts (RT-O21, sequencing re-ruled 2026-10-12). This is the first:
**the size of every HTTP message, per method and direction, in a
generated wallet's traffic with a daemon**, from which the candidate
class tables are derived. The second part, the record boundaries the
stream adapter actually emits, is observed in RT-W9 step 5 under the flush
policy registered here.

Which wallet was ruled with RT-O21: a generated one, syncing a generated
regtest chain that carries full-size transactions, and submitting from it.
No existing testnet wallet is used. The classes ship from this trace and
are derived again when a mainnet RPC trace is registered in the
measurement ledger (the rule-21 reopen recorded in RT-O21).

## Registered before the run

*Amended three times, 2026-10-17, after the dry run and before any
registered run. First: the traffic below states two waits the instrument needed
(step 1's margin and step 3's unlock wait). Second: the wallet defect the
dry run found is fixed in this PR, so the refusal it produced voids a run
instead of being waited out, and the registered run is made from the fixed
tree. Third: the maintainer ruled the host (below). "Dry run" says what
forced the first two.*

**Subject.** The bytes a stream adapter over the channel would carry
between the wallet's daemon client and the daemon: every HTTP/1.1
message whole (start line, headers, body, and chunked framing if any), in
each direction, labelled by the method it calls. A REST call is labelled
by its path. A call to `/json_rpc` is labelled `json_rpc:` and the
JSON-RPC `method` from its body. A response carries its request's label.
The client is the production engine's daemon client (`HttpRpc`, which
speaks HTTP/1.1 only: `hyper` with its `http1` feature, no `http2`). The
daemon is `shekyld --regtest`.

**Instrument.** `engine::regtest_e2e::rt_p5`
(`rust/shekyl-engine-core/src/engine/regtest_e2e_rt_p5.rs`), a test-only
child of the regtest harness. Each wallet dials the daemon through its own
TCP proxy on loopback. The proxy forwards every byte unchanged and keeps a
copy. Nothing is parsed while traffic flows: after every wallet has
closed, the copy of each connection is split into messages, and every
byte must belong to exactly one message. This is the counting shim at the
plaintext RPC layer that RT-O21 ruled, not a packet capture, and not a
layer inside the server, which would see parsed requests rather than the
bytes that cross. The parser's cases are unit tests in the same module
and run in every CI build of the crate.

**The generated traffic.** One cell, in this order, against one freshly
spawned regtest daemon:

1. **A funding wallet matures.** Blocks are mined to it in batches of ten,
   the wallet refreshing after each, until it can spend; then twenty more
   (`FANOUT_MARGIN_BLOCKS`). Its selection is largest-first and its oldest
   coinbases are its largest, so the margin puts the fan-out's inputs well
   past the reference block's spendability boundary, and no block is mined
   between the four fan-out builds.
2. **The fan-out.** The funder builds four transactions, each paying the
   measured wallet fifteen outputs of one amount `unit` (sixteen outputs
   with the change), submits all four, and they are mined together in one
   block. `unit` is the funder's unlocked balance at that point divided by
   120, so the fan-out spends at most half of it. One block carrying four
   sixteen-output transactions is what makes a `get_transactions` reply
   larger than one record.
3. **The measured wallet syncs and spends.** It refreshes from genesis,
   blocks are mined one at a time until every fan-out output is unlocked,
   and then it spends eight shapes in turn, as (inputs × outputs): 1 × 2, 2 × 2,
   4 × 2, 8 × 2, 1 × 16, 2 × 16, 4 × 16, 8 × 16. Eight inputs and sixteen
   outputs are the maxima (`shekyl_fcmp::MAX_INPUTS`,
   `shekyl_wire::transaction::MAX_OUTPUTS`). A spend of `k` inputs asks for
   `(k − 1) × unit + unit / 2`, paid to the funder in one output, or in
   fifteen equal outputs for a sixteen-output shape. The wallet's selection
   is largest-first, its largest outputs are the fan-out's `unit` outputs,
   and every change it makes is smaller than `unit`, so `k` is the fewest
   that cover the amount. Each spend is mined into the next block and the
   wallet refreshes.
4. **A restored wallet syncs the whole chain.** A new wallet from the
   measured wallet's seed refreshes from genesis, over blocks that carry
   every shape above.

**When a build is refused for an output not yet in the tree.** The wallet
refuses a build that would spend an output not yet spendable at the
reference block with `OutputNotYetSpendable`; the instrument then mines one
block and builds again, as a user waits. Any other refusal fails the run,
among them `CurveTreeUnavailable` with `OutputNotDrained`: an output the
wallet's gate admitted that the tree at the reference block does not hold,
the defect the dry run found (below) and this PR fixes.

Blocks are mined with the daemon's armed test lever `generateblocks`,
over the harness's own connection, which is not traced: it is not a
production capability on the channel (`RPC_CHANNEL.md` §6.1, RT-O9.2).

**Seeds.** The registered run uses seed bytes `0x51` (funder) and `0x52`
(measured and restored wallet). The dry run uses `0xD1` and `0xD2`, the
same cell, so every shape and gate is exercised before the registered run
and nothing the dry run writes can be read as registered data. Each run
writes into its own directory, named for its cell, which must not exist
beforehand.

**Gates.** A run that fails any of these is void, and the failure is
recorded:

- The proxy recorded no read or write fault, and every proxied
  connection closed within 60 s of its wallet closing.
- Every byte of every connection parsed into whole messages, and each
  connection has as many responses as requests.
- The trace carries `/submit_transaction`, `json_rpc:get_block`,
  `/get_transactions` and `/get_o_indexes.bin`, and every JSON-RPC request
  names its method.
- At least one message is larger than one record's payload, 65,533 bytes.
- No build is refused except as not yet spendable (above).
- The fan-out block carries all four fan-out transactions; each of the
  measured wallet's spends has its registered shape, read back from the
  built transaction, and is in the block mined after it.
- There is one submission message per built transaction.
- Each built transaction's wire length equals the weight crate's
  structural size predictor (`shekyl_tx_weight::predict_size_and_weight`)
  at some tree depth. That depth is recorded as the depth it was built at.

**The unit and the flush policy.** The stream adapter of step 5 combines
writes until a flush (RT-O21). It cuts records when the writer flushes,
or when its buffer holds a full record of the largest class; a message
larger than one record is cut into full records and a tail. This
registration takes **one HTTP message as one flush**: `hyper` writes a
message whose body has a known length and then flushes once. That is
what step 5 observes. If step 5 sees a message flushed in more than one
piece (a head flushed before its body, say), the classes are derived again
from the boundaries it observes, and that re-derivation is recorded there.

**How the classes are derived** (`scripts/bench/rt_p5_classes.py derive`,
its tests in `scripts/bench/test_rt_p5_classes.py`, run in CI):

- Each message of `n` bytes becomes the records the flush policy makes:
  `⌊n / 65,533⌋` full records and, if anything remains, a tail. A record
  needs its payload plus the two-byte occupancy (`OCCUPANCY_LEN`); a full
  record needs `MAX_RECORD_PLAINTEXT` = 65,535 (`RPC_CHANNEL.md` §4.4; both
  constants land in code in step 5).
- A table of `K` classes always holds 65,535 as its largest. For each `K`
  from 1 to 8, the other `K − 1` classes are the ones that minimise the
  total padding over every record of the trace, both directions together.
  The search's result is checked against an exhaustive search in its
  tests.
- For each `K` the output gives the classes, the total padding, the
  padding as a share of the payload, and, the property RT-O6 names, which
  other methods and directions have records in the classes a submission
  falls in.
- **This record does not choose `K`.** Fewer classes hide more and pad
  more; the choice is a privacy decision, and it is the maintainer's. The
  table and the sharing list are what it is made from.
- **A submission at greater tree depth.** The regtest chain's curve tree
  is shallow, and a membership proof grows with depth, so a submission on
  a deeper tree is larger. For every built transaction, the output also
  gives the submission message's size at depths 1 to 8, from the same
  size predictor and the body encoding the trace shows. This is reported
  beside the tables and does not enter the derivation.

**Determinism.** The registered cell is run twice, back to back, from the
same commit and seeds; the classes are derived from the first. The second
is compared with the first (`rt_p5_classes.py compare`): for every
wallet, method and direction, the same number of messages, and each, in
size order, within 64 bytes or 1 % of its counterpart, whichever is
larger. What can differ between runs and is allowed for: digits of
`content-length` and of numbers in JSON bodies (heights, timestamps,
amounts, fees), the port in a `host` header, and the randomness inside
each transaction, which does not change its length. A failed comparison
voids the pair.

**Attempts.** At most two registered attempts. A void attempt is
recorded with its cause, the cause is fixed, and the second attempt is
made under the same lines. Both are recorded in order.

**Host — ruled by the maintainer, 2026-10-17.** RT-O21 recommended a
testnet daemon on the floor device with the wallet on another internal
host. The same day's ruling on which wallet replaced the testnet with a
generated regtest chain, which the harness spawns on the machine the test
runs on, and message sizes are a function of the bytes, not of the
processor that produced them. The maintainer ruled the host: **one of the
testnet estate's staker VMs** (x86-64, 8 vCPU, 15 GiB, Ubuntu 24.04),
whose standing testnet daemon keeps running untouched. The run is claimed
on the estate ledger as shared: a measurement of sizes is not bent by
background load. The dry run was made on the development workstation;
nothing it wrote is data.

**The build.** On that VM, from a fresh clone of the commit that carries
this amendment: the daemon in Release, and the engine's test binary, with
the workspace's pinned toolchain (1.94.0). The commit is recorded with the
results, with the VM's load and the daemon's state at the start and the
end.

**What this trace does not carry**, so its classes are read with their
reach:

- **The miner leg** (`get_block_template`, `submit_block`,
  `get_miner_data`): the chain is mined with the test lever, so no
  external miner's messages are in the trace.
- **The P-scan's full-body fetch**: the staking wallet's scan of whole
  transactions. No wallet here stakes.
- **Other clients of the daemon**: the GUI wallet, the console, and the
  wallet RPC's own clients (the `shekyl-wallet-rpc` leg, RT-W12).
- **Mainnet's mix of transactions and its tree depth.** The trace's
  transactions are the registered shapes, on a shallow tree.

The rule-21 reopen above covers all four: the classes are derived again
from a registered mainnet trace.

## Dry run

Made 2026-10-17 on the development workstation, daemon in Release from
this branch, seeds `0xD1` and `0xD2`. It is a check of the instrument, not
data, and its sizes are not read here.

- **First attempts, each stopped by a gate or a refusal, each fixed before
  the next:**
  - The funder's second fan-out build was refused at assembly:
    `CurveTreeUnavailable` with `OutputNotDrained` for global output 8, at
    height 71. This is the wallet defect below.
  - Mining a block on that refusal let the earlier fan-out transactions
    land in separate blocks, so the gate requiring all four in one block
    failed. The fix is step 1's margin.
  - The measured wallet's first spend was refused as `InsufficientFunds`
    with nothing available: its fan-out outputs had not reached
    `SPENDABLE_AGE`. The fix is step 3's unlock wait.
- **Final dry run: passed**, in 262 s. Every gate held. The chain reached
  height 117, and the daemon reported curve-tree depth 1. One refusal of
  the defect's form occurred, in the measured wallet's spends at height
  108, and was recorded. `rt_p5_classes.py derive` ran end to end on the
  trace, including the fit of the submission encoding.

**The wallet defect the dry run found.** The wallet's spend gate (`C2`)
admits an output when its eligible height equals the reference height
(`rust/shekyl-engine-core/src/engine/transfer/engine.rs:462`). The tree
whose root is committed at height `H` holds only leaves matured by
`H − 1` (`drained_through`,
`rust/shekyl-curve-tree/src/client.rs:1551`, pinned by the CT-2 vectors),
and the daemon agrees. So an output exactly at the boundary is selected,
and assembly refuses it. The same comparison was in five more places on
the wallet's paths: the drain projection and selection, the bond funding
filter, the claim pre-filter and the backing set. The fix is in this PR:
one predicate, `shekyl_curve_tree::in_tree_at_reference`, used at all of
them, with a test that reproduces the boundary and was seen failing first.

## Results

**Both registered runs passed every gate, and the determinism check
passes.** The classes below are derived from the first run, by the rule
registered above. **`K` is the maintainer's choice and is not made here.**
Captures, with checksums:
[`rt_p5_rpc_message_sizes_20261017_captures/`](rt_p5_rpc_message_sizes_20261017_captures/).

### Conditions, recorded as registered

- **Host:** a staker VM of the testnet estate (x86-64, 8 vCPU, 15 GiB,
  Ubuntu 24.04). It was claimed shared on the estate ledger, and its
  standing testnet daemon was active at every check.
- **Build:** a fresh clone of `9ead6beb6c` (this PR's head at the third
  amendment, `dev` with #1088 merged in), with toolchain 1.94.0. The
  daemon was built in Release, the engine's test binary in the test
  profile.
  - The first attempt at the test binary stopped before any run: a
    benchmark-only dev-dependency (`valgrind-requests`, through `gungraun`)
    runs bindgen, and the VM's libclang could not find `stdbool.h`.
  - The build was resumed with bindgen pointed at gcc 13's header
    directory (`BINDGEN_EXTRA_CLANG_ARGS`). No package was installed. The
    clone, checkout and daemon build stood.
- **Runs, 2026-10-17 (UTC):**
  - dry run 12:48 to 12:59 (637 s), passed;
  - first registered run to 13:12 (813 s), passed;
  - second to 13:22 (572 s), passed.
- **Load average:** 0.65 at the start, 1.15 before the first registered run
  and 1.27 at the end, against 8 vCPU.
- **Chain:** height 117, curve-tree depth 1 (the daemon's count; the size
  predictor below counts layers, so it reads the same tree as depth 2).

**Determinism:** `rt_p5_classes.py compare` on the two registered runs:
**PASS**, 36 groups (wallet, method and direction), the same message count
in each and every matched message within tolerance. The two
`transactions.csv` files are byte-identical.

### HTTP message sizes per method (first registered run)

1,474 messages; 1,500 records after splitting at 65,533 bytes.

| Method | Direction | Count | Min | Median | Max | Records |
|---|---|---:|---:|---:|---:|---:|
| `/get_height` | request | 35 | 84 | 84 | 84 | 35 |
| `/get_height` | response | 35 | 287 | 288 | 288 | 35 |
| `/get_o_indexes.bin` | request | 325 | 168 | 168 | 168 | 325 |
| `/get_o_indexes.bin` | response | 325 | 234 | 234 | 266 | 325 |
| `/get_transactions` | request | 18 | 230 | 230 | 431 | 18 |
| `/get_transactions` | response | 18 | 16,684 | 63,124 | 338,644 | 34 |
| `/submit_transaction` | request | 12 | 26,599 | 104,920 | 153,688 | 22 |
| `/submit_transaction` | response | 12 | 207 | 207 | 207 | 12 |
| `json_rpc:get_block` | request | 325 | 201 | 203 | 204 | 325 |
| `json_rpc:get_block` | response | 325 | 11,038 | 11,104 | 44,912 | 325 |
| `json_rpc:get_fee_estimate` | request | 19 | 154 | 154 | 154 | 19 |
| `json_rpc:get_fee_estimate` | response | 19 | 263 | 263 | 263 | 19 |
| `json_rpc:get_version` | request | 3 | 161 | 161 | 161 | 3 |
| `json_rpc:get_version` | response | 3 | 509 | 509 | 510 | 3 |

### Candidate tables, by the registered rule

| K | Classes | Padding | Padding / payload |
|---:|---|---:|---:|
| 1 | 65,535 | 91,577,059 | 1362.3% |
| 2 | 11,357, 65,535 | 13,452,383 | 200.1% |
| 3 | 290, 11,357, 65,535 | 1,123,745 | 16.7% |
| 4 | 290, 11,357, 27,534, 65,535 | 629,732 | 9.4% |
| 5 | 290, 11,357, 27,534, 52,278, 65,535 | 444,134 | 6.6% |
| 6 | 236, 512, 11,357, 27,534, 52,278, 65,535 | 345,485 | 5.1% |
| 7 | 236, 512, 11,144, 11,882, 27,534, 52,278, 65,535 | 257,190 | 3.8% |
| 8 | 236, 512, 11,144, 11,882, 27,534, 44,914, 52,278, 65,535 | 190,914 | 2.8% |

The registered list of what shares a submission's classes, for every `K`,
is in `derive_registered_1.md`. It counts records of every method in
those classes, in both directions together.

### A reading the registered output does not make: direction

*This is a reading of the registered output, made after it was seen. It
changes nothing in the derivation and is reported for the decision on
`K`.*

A path observer sees which way each record travels. A submission is a
request, from the wallet to the daemon. Counting only requests, the
records sharing a submission's classes are:

| K | Submission request records | Other requests in the same classes |
|---:|---:|---|
| 1, 2 | 22 | every request in the trace (725) |
| 3, 4, 5 | 22 | `/get_transactions` ×2 |
| 6, 7, 8 | 22 | none |

Every other request in the trace is 431 bytes or smaller, and every
submission is 26,599 bytes or larger. So in the request direction, from
`K` = 3 on, a record of a submission's class is a submission, whatever
the classes are. Padding hides a submission among the records going
the same way only at `K` ≤ 2, and those tables pad the payload by 200 % or
more.

`RPC_CHANNEL.md` §4.4 (RT-O6) states the mechanism as "a submission is
indistinguishable from a block-fetch response of the same class". In this
trace, block-fetch responses (`json_rpc:get_block`, `/get_transactions`)
do share a submission's classes, but they travel in the other direction.
**This is a finding against RT-O6's premise, for the maintainer**: on this
traffic, size classes do not hide when a wallet submits. They do hide which
method a response answers and how large it is within its class.

### Two observations on the submission

- **A submission is sent hex-encoded in JSON.** For every submission in
  the trace, the body is `14 + 2 ×` the transaction's wire length, so the
  upload is twice the transaction.
- **A submission's size at greater tree depth:** from the weight crate's
  predictor, with the body encoding above.
  - From the depth it was built at to its largest size at any depth up to
    8, a submission grows by 2.8 % to 15.9 % (the 1 × 2 shape grows most).
  - For a submission larger than one record, a deeper tree changes only
    its tail record; a smaller submission is one record, which a deeper
    tree can move to a larger class.
  - Proof size is not monotonic in depth: for four inputs it is smaller at
    3 layers than at 2.
  - The per-transaction table is in `derive_registered_1.md`.

### Where RT-P5's sizes part stands

- **Measured, by the registered method, on the ruled host.**
- **What remains for its own deciders:**
  - The choice of `K`.
  - The direction finding above, which bears on whether size classes are
    the mechanism RT-O6 needs at all.
- **What remains for later steps:** the record boundaries the adapter
  actually emits, observed in RT-W9 step 5 under the flush policy
  registered here.
- **Reopen:** the classes are derived again from a registered mainnet
  trace (RT-O21).
