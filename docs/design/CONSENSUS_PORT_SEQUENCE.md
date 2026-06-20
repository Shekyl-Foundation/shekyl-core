# Consensus Port Sequence — C++ → all-Rust, genesis critical path

**Status:** Strategy locked 2026-06-20 (two independent analyses converged).
**Authoritative for:** the order, method, and retirement discipline of the
C++ → Rust consensus port. **Parents:**
[`TRACK2_REGTEST_PARITY.md`](TRACK2_REGTEST_PARITY.md) (the differential rig
this generalizes), the `consensus-port-gates-genesis` decision frame.
**Binding decision:** logged in
[`../V3_WALLET_DECISION_LOG.md`](../V3_WALLET_DECISION_LOG.md) (2026-06-20,
"redb for the daemon store; serializer ported replicate-exact before any
deliberate format change").

---

## 0. Why this gates genesis

The all-Rust consensus port is **on the genesis critical path and gates the
rule freeze.** You cannot freeze consensus rules on an implementation you are
mid-replacing — the Rust consensus must be the *proven reference* before the
rules harden, or you retrofit frozen rules to it afterward. So genesis-freeze
waits on consensus-port-complete.

**Collapsing each C++↔Rust FFI seam *is* the migration.** At every
serialize/parse/verify seam, the Rust side we collapse toward becomes the
*sole* implementation; the C++ side retires (it is not kept in sync). The C++
body is the **reference oracle** during the port — the only existing
implementation of the intended rules, with no chain history to validate against
pre-genesis. Therefore every piece moved is **differentially tested** against
C++ over a corpus, asserting identical results, *before* C++ retires.

**The hazard to guard hardest:** retiring a C++ piece because Rust passes the
*current* tests, when the tests are not yet a complete spec of that piece. Once
C++ is gone, the corpus *becomes* the consensus spec — so the corpus must be
comprehensive enough to BE the spec before the oracle retires, not after.

---

## 1. Pin A — the binary blob and the JSON surface are decoupled; the field rename never touches the wire

The transaction type is serialized through **four independent paths** that do
**not** share a frozen layer:

| Path | Where | Carries field names? | Frozen at genesis? |
|---|---|---|---|
| **Binary archive** (consensus wire / tx-hash) | `binary_archive.h`; `transaction`'s `BEGIN_SERIALIZE_OBJECT` in `cryptonote_basic.h` | **No** — positional | **Yes** (this is the only true freeze) |
| Template JSON archive | `json_archive.h` (template-driven off the *same* `serialize()` method) | Yes (emits the tag) | No |
| Hand-written RPC JSON | `serialization/json_object.cpp` (separate rapidjson impl) | Yes | No (RPC surface) |
| Boost serialization | `cryptonote_basic/cryptonote_boost_serialization.h` | Positional + type name | No (in-memory/portable) |

The decisive fact: **`binary_archive`'s `tag()` and `begin_object()` are
no-ops** — `void tag(const char *) { }` at
[`src/serialization/binary_archive.h:71`](../../src/serialization/binary_archive.h#L71).
The consensus wire blob is **positional and carries no field names.** The
`ar.tag("rct_signatures")` calls (e.g.
[`cryptonote_basic.h:481`](../../src/cryptonote_basic/cryptonote_basic.h#L481)
and the `serialize_base` path ~`:548`) compile to nothing in the binary
archive.

**Consequences:**
- The `rct_signatures` → `ct_signatures` rename is **binary-blob- and
  tx-hash-invariant by construction.** Confirm against locked vectors and it is
  green for free.
- The genesis-frozen thing is therefore **only the binary layout**, not any
  field name. The rename's risk lives **entirely in the JSON/RPC surface**, and
  that surface is split across **two independent C++ implementations** (template
  JSON archive + `json_object.cpp`) that must agree — exactly the
  kept-in-sync-pair hazard, except it is C++/C++ today. That is itself the
  argument for **collapsing both JSON emitters into one Rust JSON path** during
  the port.

So the rename is not one gate but several, and **none of them is on the
consensus path.** Replicate-exact (binary) and deliberate-format-change (the
JSON rename) are cleanly separable.

---

## 2. Pin B — DUPSORT is inherited debt the tree already abandoned; redb is the direction of travel

Eight tables open with `MDB_DUPSORT | MDB_DUPFIXED`
([`db_lmdb.cpp:1597-1613`](../../src/blockchain_db/lmdb/db_lmdb.cpp#L1597)):
`BLOCK_INFO`, `BLOCK_HEIGHTS`, `TXS_PRUNABLE_HASH`, `TXS_PRUNABLE_TIP`,
`TX_INDICES`, `OUTPUT_TXS`, `OUTPUT_AMOUNTS`, `SPENT_KEYS` — all **inherited
Monero**.

But the codebase already carries a standing instruction against the pattern:
[`db_lmdb.cpp:1651-1652`](../../src/blockchain_db/lmdb/db_lmdb.cpp#L1651) —
*"INVARIANT: Shekyl curve-tree state uses composite keys. No DUPSORT. … If
you're reaching for MDB_DUPSORT, stop and use a composite key instead,"* with
the V7 restructure note at
[`db_lmdb.cpp:97`](../../src/blockchain_db/lmdb/db_lmdb.cpp#L97) ("curve-tree
tables restructured — composite keys replace DUPSORT"). The genuinely-new,
hot, **daemon↔wallet-shared** structure — the FCMP++ curve tree — is *already*
composite-keyed on both sides
([`db_lmdb.cpp:1659-1673`](../../src/blockchain_db/lmdb/db_lmdb.cpp#L1659)).
redb has no DUPSORT; you model it with composite-key tables — which is exactly
where the codebase already decided to go.

**Cursor-pattern conversion** (the two DUPSORT idioms both convert):
- exact key+value dup match (`MDB_GET_BOTH`) → composite-key **point lookup**;
- range positioning (`MDB_SET_RANGE`) → redb **`range()`** over the composite
  ordering.

**Design constraint:** model these as **composite-key `Table`s, not redb
`MultimapTable`.** `MultimapTable` iterates values within a key but does not
give range positioning *across* the composite ordering that `MDB_SET_RANGE`
needs, and it stores each dup as a separate B-tree entry (losing both
`DUPFIXED` density and the single-call bulk read). Re-key to a proper `Table`.

**One thing to confirm, not assume:** under FCMP++ with hidden amounts,
`OUTPUT_AMOUNTS` likely collapses to a single amount bucket (RingCT outputs are
amount-0), making its DUPSORT role degenerate and the conversion trivial. If a
surviving *consensus* query still hits `OUTPUT_AMOUNTS` *by amount* (vs. by
global index), that is the one table that genuinely wants a multimap; confirm
before modeling.

### The redb decision (committed)

**redb, not heed.** Defended on:
1. **It's already the engine.** `redb = "4.1.0"` is the workspace dep
   ([`rust/Cargo.toml`](../../rust/Cargo.toml), used by `shekyl-curve-tree`,
   `shekyl-engine-core`); there is **zero heed/lmdb in the Rust tree.** heed
   would *introduce* the only C-FFI storage seam into an otherwise pure-Rust
   stack. The daemon and wallet/engine can share one tree-store impl (Pin B:
   the tree is already composite-keyed on both sides).
2. **It kills the pre-sized-map footgun.** liblmdb's `DEFAULT_MAPSIZE` +
   `do_resize`/`need_resize`/`check_and_resize_for_batch` + the `lmdb_resized`
   callback (`db_lmdb.{h,cpp}`) are a known operational hazard on an
   unboundedly-growing daemon DB. redb grows dynamically; the class disappears.
3. **Trusted base / reproducibility.** Removes liblmdb (C) from the daemon's
   TCB and Guix graph, and the MSVC FFI risk already cited as decisive for the
   wallet. Consistency of reasoning across wallet and daemon is itself a virtue.
4. **`pop_block` atomicity by construction.** The reorg undo
   (`blockchain_db.h`) becomes a redb `WriteTransaction` (all-or-nothing),
   retiring the resize-aware manual batching wholesale.

**Not defended on speed.** heed is zero-copy: liblmdb is mmap'd and hands back a
borrowed `&[u8]`; the FFI cost is per-*call* C overhead, not a per-byte
transcode, and the blob→struct step is identical under either engine. On raw
reads liblmdb's mmap path historically edges redb. Do not argue redb on
throughput.

**The one real cost, and why it's acceptable.** With heed the Rust daemon could
read the same on-disk LMDB file as the C++ oracle (a byte-level shared-DB
cross-check). redb forecloses that — different on-disk format. But consensus is
over **logical chain state**, not on-disk bytes: the differential test that
matters feeds the same block sequence to both daemons and asserts identical
tip, cumulative difficulty, output set, key-image set, and tree root. The
shared-DB cross-check is a stronger-test nicety, not a correctness requirement.

**Risk asymmetry that de-risks the bet:** the on-disk format is **node-local —
not a consensus wire format, does not freeze at genesis.** Unlike the
serializer, redb is reversible without a hardfork (a node migrates engines —
painful, not a fork). The stressnet gate proves redb-at-blockchain-scale before
genesis.

**Rule-21 reopen trigger:** stressnet shows redb write-amplification or
large-DB latency outside an agreed envelope vs. the C++/liblmdb oracle —
measurable, decided on numbers.

---

## 3. The differential rig and the corpus-is-spec retirement gate

Every stage is validated against the live C++ oracle; every retirement is
behind a **corpus-is-spec** gate with a rule-21 reopen trigger.

- **Oracle-emit:** run C++ at scale to produce canonical blobs (Track-2's
  `RegtestDaemon` generalized). Persist the **deterministic projection** — raw
  daemon blobs + expected parsed structure / logical state — never
  wallet-randomized artifacts (real spends carry random blinds/keys/shuffle).
- **Round-trip + cross-impl verdict:** `parse(serialize(x)) == x` (bit-identity)
  and C++/Rust **accept-reject agreement** on malformed input.
- **The completeness danger is the conditional matrix, not the leaves.** The
  encoders have total domains — fuzzable to saturation. Where "the tests aren't
  yet a complete spec" bites is the *conditional framing*: version gates,
  coinbase-vs-spend, type-dependent presence of `txnFee`/`referenceBlock`/
  prunable, multi-output coinbase, pruned-vs-prunable. Corpus completeness =
  **enumerating that matrix explicitly**, not just byte-fuzzing primitives.
- **Replicate a read-side parse rule, too.** `pqc_auths` is parsed
  EOF-tolerantly:
  [`cryptonote_basic.h:494-501`](../../src/cryptonote_basic/cryptonote_basic.h#L494)
  — a blob ending right after the rct base is *accepted* (pqc_auths cleared,
  pruned form). The Rust parser must replicate this or it will reject valid
  pruned blobs; the corpus must contain the pruned form deliberately.

---

## 4. The first concrete sequence

Ordered by dependency × consensus-risk, FFI-collapse-maximizing.

### Stage 0 — Build the instrument, port nothing
Generalize the Track-2 regtest parity harness (Phase 0) into the consensus-port
differential rig: oracle-emit, structured fuzzer (malformed/boundary inputs),
round-trip + cross-impl-verdict assertions, under the existing determinism +
aarch64 CI lanes. **Self-test the rig against the already-collapsed difficulty
seam** (`shekyl_difficulty_lwma1_next`) — the one proven seam validates the
rig, not vice-versa. **Reopen:** if corpus generation isn't bit-deterministic
cross-platform, stop — a non-deterministic rig can't be an oracle.

### Stage 1 — Serializer foundation, bottom-up, replicate-exact (the spine)
Eat `src/serialization/` as a stack of small pure encoders, smallest first:
- **1a** varint/fixed/byte primitives (`binary_utils.h`) — fuzzable to domain
  saturation; the corpus-completeness rehearsal. Rust parallel already exists in
  `shekyl-io` (`read_varint`/`read_vec`/`CompressedPoint`).
- **1b** crypto-type encoders (`crypto.h`).
- **1c** containers / variants / tuples.
- **1d** composites: tx-prefix → full transaction (the `serialize()` at
  [`cryptonote_basic.h:481`](../../src/cryptonote_basic/cryptonote_basic.h#L481),
  incl. `serialize_rctsig_base`/`serialize_rctsig_prunable` in
  [`src/fcmp/rctTypes.h`](../../src/fcmp/rctTypes.h)) → block.

Oracle assertion per unit: round-trip bit-identity, C++/Rust accept-reject
agreement on malformed input, tx-hash invariance. **Retirement gate:** a C++
encoder retires only when its corpus is exhaustive enough to BE the spec —
provable for primitives; for composites, every field / optional-present-absent /
variant arm / pruned-vs-prunable combination plus fuzzer saturation with **zero
new divergences over an agreed CPU-hour budget.** **Reopen:** any
post-retirement divergence ⇒ the corpus wasn't the spec; halt all retirements,
expand methodology.

> **Active finding (the live entry point to 1d).** The vendored `shekyl-oxide`
> binary tx/rct deserializer has never met a live block; `Block::read` fails
> `UnexpectedEof` on a real PQC coinbase. Confirmed divergences vs. the oracle,
> all pure-layout: (i) the coinbase (`RCTTypeNull`) base **carries**
> `enc_amounts`/`enc_labels`/`outPk`, but Rust returns `None` after the type
> byte ([`rctTypes.h:209-280`](../../src/fcmp/rctTypes.h#L209)); (ii)
> `referenceBlock` is a 32-byte hash in the **base**
> ([`rctTypes.h:206`](../../src/fcmp/rctTypes.h#L206)), not a `u64` in prunable;
> (iii) `curve_trees_tree_depth` is a distinct prunable field
> ([`rctTypes.h:378`](../../src/fcmp/rctTypes.h#L378)) Rust mislabels as
> `reference_block`; (iv) `pqc_auths` is a structured **tx-level** array
> ([`cryptonote_basic.h:334-353`](../../src/cryptonote_basic/cryptonote_basic.h#L334),
> [`:504-515`](../../src/cryptonote_basic/cryptonote_basic.h#L504)), not the
> prunable blob-vec Rust reads. Coinbase first, then spend, then staked; see
> [`TRACK2_REGTEST_PARITY.md`](TRACK2_REGTEST_PARITY.md).

### Stage 2 — `rct→ct` rename, on the now-Rust serializer
Deliberate format change, isolated from replicate-exact. Per Pin A: the
binary/tx-hash invariance gate is green by construction (verify vs. locked
vectors); the work is **collapsing the two C++ JSON emitters into one Rust JSON
path** carrying `ct_signatures`. **Reopen:** any tx-hash or binary delta under
the rename ⇒ a non-tag path leaked the name into the blob; stop and find it.

### Stage 3 — Storage: redb `blockchain_db` (parallelizable with Stage 1)
Storage stores blobs → testable on raw blobs before the typed serializer lands.
Convert the 8 DUPSORT tables to composite-key tables (Pin B); `pop_block`
atomicity → redb `WriteTransaction`, retiring the `do_resize`/
`check_and_resize_for_batch` machinery wholesale. **Oracle:** identical block
sequences to C++/liblmdb and Rust/redb, assert identical logical state (tip,
cumulative difficulty, output set, spent-key set, tree root) — never on-disk
bytes. **Reopen:** stressnet outside the agreed write-amp/large-DB-latency
envelope.

### Stage 4 — tx validation + tx_pool
With typed values (Stage 1) and storage (Stage 3): `tx_verification_utils`,
`tx_pqc_verify`, `tx_sanity_check`, `cryptonote_tx_utils`, then `tx_pool`.
**Oracle:** corpus of valid + invalid txs, identical verdict **and rejection
reason.** **Retirement gate:** corpus covers every rejection-reason path.

### Stage 5 — `blockchain.cpp` body + RandomX verifier wiring
The validation body. Wire `shekyl-pow-randomx` into block PoW-check here,
differentially gated by the `shekyl-randomx-differential` harness against the
`external/randomx-v2` C reference. **The miner stays C.** **Oracle:** full-block
validation corpus covering every consensus-rule violation.

### Stage 6 — orchestration + transport + hardfork
`cryptonote_core.cpp` (orchestrator), then `cryptonote_protocol` + `p2p/levin`
(transport — large but lower consensus-risk, since its payload is already
validated by Stage 5), then hardforks (tiny but consensus-critical version
gating; port alongside the body it gates).

### Stage 7 — Retire the C++ shell
FFI has inverted: Rust owns consensus; the only deliberate C left is the
RandomX-v2 miner; liblmdb is gone (redb); the `shekyl_ffi.h` crypto seam
becomes in-process Rust calls.

### Off-critical-path parallel track (anytime)
Pure-math leaf seams (`shekyl-economics`, `shekyl-staking`, remaining
difficulty) — independent, low-risk, but **explicitly not rig-hardening for the
serializer**, so they never gate the spine.

---

## 5. Source-citation discipline

Line numbers above were verified directly except where attributed to the
parallel analysis (`json_object.cpp` `toJsonValue` site,
`cryptonote_boost_serialization.h` site, `blockchain_db.h` `pop_block` line, the
`MDB_SET_RANGE` site count, `db_lmdb.h` resize-machinery lines). Re-verify those
at implementation time; they are directionally confirmed (the files appear in
the rename/resize surface) but their exact lines were not independently checked
here.
