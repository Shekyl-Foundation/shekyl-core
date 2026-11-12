# Shard view — the view hash of a `W`-byte shard and the fetch that produces it

**Status:** OPEN — Round 0 opened 2026-10-08. `SV-D1`, `SV-D2`, `SV-D3`,
`SV-D9` **RULED** (Rick, 2026-10-08, in review of the shard-view plan);
`SV-D4`…`SV-D8` **PROPOSED** with defaults, built as proposed and reopened on
review. `SV-D10` **PROPOSED 2026-10-10** (byte-derived texture layer; default
not now). `SV-D9` is **LIFTED 2026-11-12** (#1344): every node with a Tor
serves the view through its fetch scheduler; a node with Tor off refuses it.
Landing order §4: steps 1, 2a, 2b, 3 and 4 **landed** (2026-10-08/09).
2c's serve read landed 2026-10-10: `StoreShardProvider` over a
`BodyStoreReader`, the writer owned by `StakeEngine` (`WSS-Q1`(a)).
Fill (`WSS-Q4`) remains open. Erase (`WSS-Q8`) runs when the pin-release gate clears a shard. The reader
decrypted, so `WSS-Q13` was not met, until 2026-11-02 (#1261): the provider
now reads through a body-store actor that owns the store and its key, one
chunk copy per message (`CURVE_TREE_CLIENT.md` §11.1). The round stays OPEN on `SV-D4`…`SV-D8`'s
review and `SV-D10`. Visualization continuation
(entropy audit, CVD gate, candidate.v2 criteria) is in
[`../V3_SHARD_VISUALIZATION.md`](../V3_SHARD_VISUALIZATION.md) *SV-D
continuation*.
Identifier family `SV-D` (index row `SV-D1…SV-Dn`, registered at birth per
rule 94 §1). Decision authority: Rick. Companion to
[`../V3_SHARD_VISUALIZATION.md`](../V3_SHARD_VISUALIZATION.md) (what a
rendering is), [`ARCHIVAL_SHARD_FETCH.md`](ARCHIVAL_SHARD_FETCH.md) (the
client that fetches a shard), and
[`ARCHIVAL_SHARD_SELECTION_LIST.md`](ARCHIVAL_SHARD_SELECTION_LIST.md) §14
item 2 (the operator RPC this document re-grounds).

**One sentence.** Any wallet, and shekyl-web, draws any archival shard from a
seven-field aggregate the daemon produces by **fetching the shard body from an
archivist and hashing the archival bytes it verified** — never from skeleton
rows alone — so that a view is ordinary shard traffic and the picture is a
function of the bytes an archivist actually holds.

---

## 1. What was found (the premises this round corrects)

Recorded as findings, not as a plan, because each refutes a sentence some
live document still carried on 2026-10-08.

1. **The wire's `shard_hash` was the retired geometry's root.** The
   `request_archival_shard` response copied the frozen curve-tree sub-root
   `R_k` (`FrozenSegmentRecord.r_k`; the leaf-segment partition `PDM-Q12`
   retired) into `shard_hash`. A `W`-byte shard (`SHT-Q2`,
   `shekyl_types::shard_of`) has no stored hash and, until this round, no
   definition. The visualization's seed was therefore undefined for every
   shard that exists.
2. **The fetch never needed a shard-level hash.** Sub-PR 2 of the fetch
   round verifies **per transaction** against the two retained digests
   (`txs_prunable_hash`, `txs_pqc_auth_hash`). A shard-level hash is the
   visualization's identifier, not the challenge's, and the two must not be
   confused (`SV-D1`).
3. **The five counts are skeleton-derivable; the hash must not be.** Block,
   transaction, output, coinbase-output counts and the timestamp span are
   permanent skeleton rows every node keeps after pruning. A view hash that
   were also skeleton-derivable would make the fetch pointless — exactly the
   wrong shape, since the fetch *is* the point (`SV-D2`).
4. **Nothing in the view path was buildable.** `shekyl-p-fetch` ships the
   leaf unit (`ServedFrameHeader`, `R_k` recompute — the frame deleted
   2026-10-08, `R_k` leaves with the client commit); the tx-range body is
   fetch Sub-PR 2, unbuilt at round open; the C++ shim's
   `shekyl_daemon_operator_shard_fetch` was a typed miss (deleted with
   `SV-D3`, step 3); the serve side for `W`-shard bodies is the wallet
   lane's store rebuild (`WSS-`, behind `WSS-Q1`); and the daemon's store
   can answer none of the scheduler's facts (`SV-D9`). The ordering in §4
   follows from this.
5. **The method is admin-only and must stay so while it fetches** (`SV-D6`; SUPERSEDED 2026-11-10 by IG-Q91: it is in `chain`, bounded by IG-Q90).

---

## 2. Rulings

### `SV-D1` — RULED 2026-10-08: the view hash requires the pruned components

The visualization's `shard_hash` is a digest **over the shard's archival
bytes** — each in-domain transaction's prunable region and `pqc_auths`, the
`SHT-Q2` archival good — in storage order. It is **not** derivable from
skeleton rows: a node that discarded the body cannot compute it, and a node
that holds only the per-transaction verification digests cannot either.

```text
view_hash(k) = cSHAKE256(
    customization = "shekyl/archival-shard-view-hash-v1",
    input = shard_id_le[8]
          ‖ for each tx_id in [b_k, b_{k+1}) in storage order:
                txid[32]
              ‖ prunable_len_le[8]  ‖ prunable_bytes
              ‖ pqc_auths_len_le[8] ‖ pqc_auths_bytes
)[..32]
```

- **Distinct from the verification digests.** `txs_prunable_hash` and
  `txs_pqc_auth_hash` are per-transaction, retained on every node, folded
  into the txid, and are what a challenge's per-tx verify checks. The view
  hash is per-shard, never a skeleton row, never consensus, and never on the
  wire from `P` — a value supplied by the archivist would be a claim about
  the body, and the picture is a function of the body.
- **The input is the bytes, not their digests.** Folding the two retained
  digests would reproduce finding 3. The function takes byte slices; a call
  site that passes a digest is the review's catch, and the gate is `rg` for
  the function's name finding no caller that passes `txs_prunable_hash` or
  `txs_pqc_auth_hash`.
- **Length-framed and txid-bound.** The per-tx `txid` binds order and
  identity; the two length prefixes keep the concatenation injective.
- **Domain separation** per rule 30: a new cSHAKE256 customization string,
  registered in `shekyl-crypto-pq`'s domain registry with the other
  `shekyl/…-v1` strings.
- **One home** (rules 05 and 18): the word `ShardViewHash` is a
  `shekyl-types` newtype beside the other 32-byte names; the computation
  is `shekyl_archival_retention::ShardViewHasher`, a streaming fold
  (`begin(ShardId)`, `fold_tx(ArchivalTx { txid, prunable, pqc_auths })`,
  `finish() -> ShardViewHash`) in the crate that owns the other archival
  cSHAKE labels, with `shard_view_hash(..)` as that hasher run once. The
  fetch client folds it in the same pass that verifies (`SV-D8`); a local
  holder folds it over its own store; the Python fake chain in
  `shekyl-dev/visualization` mirrors the same fold over its synthetic
  component bytes so recipe pins stay shared. The known answer
  (`known_answer_v1`, shard 7, two transactions) is pinned on both sides.
- **Falsifiers.** A store with the archival bytes discarded returns a typed
  refusal, never a hash; the KAT vector pins the fold over a two-transaction
  fixture; flipping one archival byte that leaves every skeleton row intact
  is impossible by construction (the txid moves), so the avalanche check is
  the visualization's existing one over the resulting hash.

### `SV-D2` — RULED 2026-10-08: the aggregate is the product of a real fetch

A view request is a **fourth scheduler** of the same `fetch()` challenge and
organic reads use (`SF-D1`, `SL-D8` §10.2), and its answer is built from the
body that fetch verified: `shard_hash` by `SV-D1`'s fold, `tx_count` and
`output_count` by counting what streamed past, with `block_count`,
`coinbase_output_count` and `time_range_seconds` read from skeleton rows for
the shard's block span (`SV-D4`). The fetch is the point — a view adds
ordinary shard traffic an archivist cannot distinguish from a read — and a
skeleton-only answer is **REJECTED** for the view. Answering from bytes this
node already holds (a staker's own set, or a prior view-cache) is still this
scheduler, as `SF-D1` already allows.

### `SV-D3` — RULED 2026-10-08: nothing of this is written in C++

The daemon's part is served natively in `shekyl-daemon-rpc` behind a `RK-D7`
facts trait. `src/rpc/archival_shard_fetch.{h,cpp}`,
`core_rpc_server::on_request_archival_shard` and
`COMMAND_RPC_REQUEST_ARCHIVAL_SHARD` are deleted, not kept as a shim, and the
`shekyl_daemon_operator_shard_fetch` FFI goes with its last C++ caller. The
scheduler, the verifier, the hash and the cache are Rust
(`20-rust-vs-cpp-policy.mdc`: parses untrusted input, defines a contract other
code consumes).

*Landed 2026-10-08 (step 3).* `shekyl_daemon_rpc::shard_view` holds the
trait (`ShardViewFacts`), the method and its refusal mapping; the wire types
are `shekyl_rpc_types::archival` (`CORE_RPC_VERSION` 3.43; 3.42 was taken by `get_info.already_generated_coins` on merge); every C++ site
named above, `src/shekyl/shekyl_daemon_fetch.h`, the C ABI struct and the
`core_rpc_ffi.cpp` dispatch row are deleted. The C++ error-code header keeps
the three slots (-22, -24, -25) as a note so they are not re-minted there.
The facts trait's one shipped implementation is `SV-D9`'s.

### `SV-D4` — PROPOSED: aggregate semantics for a `W`-byte shard

A shard is a `tx_id` range `[b_k, b_{k+1})` (`PDM-Q-F32`, `SHT-Q2`); its
boundaries fall mid-block. Default semantics, one definition per field:

| Field | Definition | Source |
|---|---|---|
| `tx_count` | in-domain transactions in `[b_k, b_{k+1})` | the verified stream |
| `output_count` | outputs of those transactions **plus** coinbase outputs of the block span | stream + skeleton |
| `coinbase_output_count` | coinbase outputs of every block in `[h_first, h_last]`, where `h_first` holds `b_k` and `h_last` holds `b_{k+1} − 1` | skeleton |
| `block_count` | `h_last − h_first + 1` | skeleton |
| `time_range_seconds` | `timestamp(h_last) − timestamp(h_first)` | skeleton |
| `shard_hash` | `SV-D1` | the verified stream |

A block that holds a boundary is counted in **both** adjacent shards; this is
stated rather than hidden because `coinbase_ratio` reads it. Shards are
non-empty by the static relation `max archival length < W`, so the span is
never empty. `coinbase_ratio` stays a derived feature
(`coinbase_output_count / output_count`, ruling A).

### `SV-D5` — PROPOSED: closed shards only; cache keyed on the close

The open tip shard is refused with a typed error, never rendered: its
picture would change every block and the integrity signal
(`V3_SHARD_VISUALIZATION.md` property 1) would false-alarm. A closed shard's
aggregate is immutable below the reorg window, so it is cached keyed on
`(shard_id, close_height, hash_of(close_height))` and invalidated when the
block at `close_height` changes. The response carries `close_height` so the
rendering-spec version can be pinned to chain data (the *Spec version is
chain data* ruling).

*As built (2b, 3).* The scheduler's `ViewRefusal::Open { shard_id,
open_shard, remaining_to_close }` carries how many archival bytes the open
shard still needs when that is the shard asked for (`None` for an id past
it); the RPC answers it as `RefusedByMethod`, `shard.open`.
A closed shard no drawn holder served is `RefusedByMethod`, `shard.unavailable`,
with the attempt count; the per-attempt errors are the daemon's log
(`SF-D12`), not the wire's. The cache key is the close block's hash alone —
`close_height` is a function of the shard under one chain, so the pair adds
nothing the hash does not already distinguish. **A viewer's key is
`(shard_id, shard_hash)`** (amended 2026-10-09 on review): the close block's
hash is not on the wire, and `close_height` alone would keep a stale picture
across a reorg that replaces the closing block at the same height; the view
hash moves with the body, which is what a cached picture is a function of.

### `SV-D6` — SUPERSEDED 2026-11-10 by `INPUT_GRAMMAR.md` IG-Q90 and IG-Q91: the method is in `chain`, under a bound

SUPERSEDED: `shard_fetch` is in the `chain` grant (IG-Q91), so a wallet on
the view listener reads a closed shard's view. The cost this section kept
the method restricted for — a call spends an archivist's Tor bandwidth on a
3 MB body — is bounded instead (IG-Q90, `RPC_CHANNEL.md` §6.3): bounded
callers share one flight, a cached view and a joined flight are free, a
refused caller is `bound.shard` and is not queued, and the bundle
producer's reads hold slots no view takes. Built 2026-11-12 (#1344).

### `SV-D7` — PROPOSED: ruling A's criterion re-keyed to the `SHT-Q2` unit

Ruling A's admissibility criterion says *"data any holder of the shard can
read from the shard's serialized blocks"*. A holder under `SHT-Q2` holds the
**archival good** (prunable regions and `pqc_auths`), not blocks; block
headers, coinbases and timestamps are skeleton rows every node holds. The
criterion's intent is unchanged — a rendering publishes nothing that holding
the shard does not — and its wording is re-keyed: *held archival bytes plus
the skeleton every node holds*. The four admitted features remain admitted
under the re-keyed text; the hash input is the archival good only (`SV-D1`).

### `SV-D8` — PROPOSED: the hash is folded by the verifying pass

Sub-PR 2's client verifies **as it reads**, one transaction resident
(`PDM-Q6` item 5). The view hash is one 32-byte running state folded by that
same pass after each transaction verifies; a refused transaction aborts the
fold and the fetch. No body is buffered to be hashed afterwards, so `SF-D7`'s
memory leg (`N` times one transaction's peak) is unchanged by the view.

### `SV-D9` — RULED 2026-10-08, LIFTED 2026-11-12 (#1344): the daemon had no facts source for the view until the store cutover

**Finding.** The scheduler (step 2b) reads two things no shipped daemon can
answer. `ShardFacts::shard(k)` needs a `W`-shard skeleton: the shard's
`ExpectedShard` (the per-transaction `TxidParts` rows of its tx-id range and
the cumulative archival length ahead of it) and the block span the range
falls in. `HolderSource::holders_of(k)` needs the shard's bonded holders
with their serving endpoints and hybrid verifying keys. The daemon runs on the C++ LMDB
(`DAEMON_REDB_STORE.md`: *the daemon still opens LMDB only*), and the LMDB
has **no `txs_archival_len` row** — that column is born Rust-only in
`shekyl-chain-store` (`codec/schema_version.rs`) — so it cannot place a
`SHT-Q2` boundary at all; its shard surfaces (`archival_shard_coverage.cpp`,
`get_archival_emission_claim_source`) are keyed on the retired leaf-segment
partition. Its bond-record read reaches Rust only as a per-id presence probe
(`get_archival_bond_hybrid_pubkey` behind `SubmitFactsFfi::bond_record_exists`),
not as holders-per-shard with endpoints. `shekyl-chain-store` has the
per-transaction length and the bond records, but no shard-range or
cumulative-archival-length index either; that read is owed with the cutover.

**Ruling** (Rick, in review of the shard-view plan: *"That is definitely a
blocker. We do need to wait on that, or that becomes the plan."*). No C++ is
written to close the gap (`SV-D3`), and no Rust adapter is faked over the
LMDB. Step 3 landed the RPC over its `RK-D7` trait with one interim
implementation that refused every request with its own code, a statement
about the daemon (*this daemon holds no archival skeleton and serves no
shard view*), so a viewer showed that state and never mistook it for a miss
(`23-disposition-visibility`). The scheduler was linked into the daemon
image with no production caller: **STAGED**, consumer named below. That
interim implementation, its refusal and the wallet's cause for it are
deleted (Rick, 2026-11-12): once the lift below landed, no daemon wrote it.

**Lifted (as built at `34255a8945`, #1344).** The store flip (`DRS-X`)
made `shekyl-chain-store` the daemon's live store, with the shard-range read,
the block span for a tx-id range and the bond records joined to serving
endpoints (`shekyl_chain_ingest::shard_facts`). A node with a Tor builds
one fetch scheduler over those facts (`rust/shekyl-node/src/producer.rs`),
shared with the bundle producer when it mines, and hands the RPC
`DeskViewFacts`, the `ViewDesk` adapter (`rust/shekyl-node/src/shard_view.rs`),
through the node's handles. `shekyl-node` is where the store and the
scheduler meet; the RPC crates stay out of the fetch client
(`check_p_fetch_dep_cut.py`). A node with Tor off has no client to read
through and hands the RPC `TorOff`, which refuses `shard.tor-off`
(IG-Q90). The falsifier's line exists: `impl ShardViewFacts for
DeskViewFacts` in `rust/shekyl-node/src/shard_view.rs`, over
`shekyl-chain-store` rows. A daemon with no node answers `NotReady` like
every other absent handle.

**`PDM-Q9` note.** The view cache is an in-memory map of a public aggregate,
held by the RESTRICTED listener's process and keyed on the close block's hash.
It is episodic — gone at restart, re-derived from a fetch — and correlates
with nothing about this node's own holdings, so it is not the persistent,
posture-correlated serving state `PDM-Q9` forbids in the daemon. If a future
change proposes persisting it, that is a `PDM-Q9` question, not a cache
tuning.

### `SV-D10` — PROPOSED 2026-10-10: a byte-derived texture is a new wire field, not a v1 layer

**The question.** Should `shard_fetch` / `get_shard_view` grow a
small, deterministic sketch of the shard's archival bytes — a 64×64
local-entropy map or a byte-class histogram on a Hilbert-curve layout —
so a later compositor can paint a texture that *is* the shard, not only
a hash of it?

**Why it is a round question.** The renderer today sees the aggregate
(`SV-D1` hash + `SV-D4` counts). Folding a sketch into the view is a
wire change and a new renderer input, so it cannot land as a
`RENDER_REVISION` bump inside `candidate.v1` (*Spec version is chain
data*; `V3_SHARD_VISUALIZATION.md` *candidate.v2 criteria*). The
verifying pass (`SV-D8`) already touches every byte; the sketch is
nearly free *to compute*. It is not free *to specify*.

**Admissibility.** The sketch is a deterministic function of
holder-readable archival bytes (ruling A, re-keyed `SV-D7`). It
publishes nothing holding the shard does not. Closed-world: it is chain
data, not a locale or a wallet setting.

**Default (rule 21): not now.** candidate.v1 stays hash-seeded. No field
is reserved on the wire (a reserved field is a `RESERVED` contract
entry, not a code symbol — `23-disposition-visibility`).

**Reopening criterion.** The perceptible-bit audit in
`V3_SHARD_VISUALIZATION.md` is ruled **and** a named viewer (CLI, GUI
Shards page, or shekyl-web) can state a job the hash picture cannot do
that the texture would. Re-evaluation shape: design-round 1 of this
question, decided by Rick; a `candidate.v2` is minted in the same change
that admits the field.

**Falsifier of a silent land.** `rg 'texture|byte_sketch|binvis|hilbert'
rust/shekyl-rpc-types rust/shekyl-wallet-contract rust/shekyl-shard-visual`
returns a production field or renderer input before this question is
RULED admit.

---

## 3. What the view does not add

No archivist HTTP path beyond `RF-R1`'s `/shard/{id}`. No body on any wallet
RPC or web response. No browser port of the compositor. No caller tag: the
archivist sees a read. No pass record: only the challenge caller files one
(`SF-D8`), so a view cannot be farmed for serve credit.

---

## 4. Dependencies and landing order

Each PR lands on `dev` inside rule 06's window; this is a sequence, not a
branch.

| Step | What | Owner | Blocked on |
|---|---|---|---|
| 1 | `SV-D1`'s fold in `shekyl-types`, its KAT, the domain-registry entry; the Python mirror and re-pinned fixtures | this round | — |
| 2a | fetch Sub-PR 2 client: tx-range frame, streaming per-tx `ContentVerify`, range-derived response ceiling, `ServedFrameHeader` / `recompute_segment_r_k` out of the client path | `SF-` (FOLLOWUPS row) | — |
| 2b | the scheduler: `shekyl-archival-fetch-sched` as a real `fetch()` scheduler (holder draw `SF-D10`, `MAX_INFLIGHT = 8`, `SF-D6` outcomes), the view caller folding `SV-D1`/`SV-D4`, the `SV-D5` cache | this round | 2a |
| 2c | the serve read: `StoreShardProvider` over a `BodyStoreReader` streams the tx-range frame. The writer is `StakeEngine`'s (`WSS-Q1`(a)). Fill (`WSS-Q4`) is not written, so an empty store answers 404 until fill. Erase (`WSS-Q8`) runs when the pin-release gate clears a shard. The reader decrypted (`WSS-Q13` unmet) until 2026-11-02, when the reads moved to the store's owning actor (#1261) | the wallet lane (`WSS-`) | fill `WSS-Q4`, erase `WSS-Q8` |
| 3 | the method natively in `shekyl-daemon-rpc` (`shard_fetch` since 4.0); C++ deleted (`SV-D3`); `close_height` on the wire — **landed 2026-10-08** over the interim refusing facts (deleted 2026-11-12); the `ViewDesk` adapter in `rust/shekyl-node` — **landed 2026-11-12** (#1344, `SV-D9` lifted) | this round | 2b |
| 4 | wallet RPC method (contract registry), CLI and GUI local render, shekyl-web server PNG route — **landed 2026-10-09**: `get_shard_view` SPECIFIED (`wallet_rpc.yaml` 0.11.0; codes `-29534` `SHARD_STILL_OPEN`, `-29535` `SHARD_UNAVAILABLE`, `-29536` `SHARD_VIEW_NOT_OFFERED` with `data.cause` `restricted` \| `skeleton_absent`; 0.17.0 adds the cause `tor_off` and `-29537` `SHARD_VIEW_BUSY` for `bound.shard`), the daemon call and refusal mapping once in `shekyl-wallet-contract::shard_view::fetch_shard_view`, served by `shekyl-wallet-rpc`; CLI `shard fetch <id> [--png <path>] [--size <n>]`; GUI `get_shard_view` contract adapter drawing locally; `shekyl-shard-render` (`shekyl-shard-visual`, feature `cli`) for shekyl-web, whose `/api/shards/{id}/view[/png]` routes call the site daemon's unrestricted listener; the `ArchivalShardSource` stub deleted | this round | 3 |

**What a viewer shows today.** A daemon with a Tor fetches the view, so a
viewer shows the picture or one of the states below. A daemon with Tor off
answers `shard.tor-off`, and the viewer shows *not offered by this
daemon*. A bounded caller turned away while another's flight is out sees
`-29537`, a transient state to retry.

A fetch against the serve reads the tx-range frame from `P`'s body store
(`StoreShardProvider`). Fill (`WSS-Q4`) is not written, so a store that
holds no shard answers 404 and the viewer shows *"this archive could not
be retrieved"*, a visible state, never an empty picture (rule 82). That
404 is an empty store, not evidence against the holder (`SF-D8`
amendment, 2026-10-08). Erase at the second absent epoch (`WSS-Q8`)
asks the stake actor to drop that shard's body row when the pin-release
gate clears it. The reader decrypted, so `WSS-Q13` was not met, until
2026-11-02 (#1261, `CURVE_TREE_CLIENT.md` §11.1).

---

## 5. Reopening

- `SV-D1` reopens only if the archival good's definition moves (`SHT-Q2`
  re-keyed); the customization string then bumps to `-v2` and the spec
  version activates at a height (*Spec version is chain data*).
- `SV-D2` reopens if a storage-only path is shown to exercise the serve
  endpoint end to end without a fetch client (the same clause as `SF-D1`).
- `SV-D4`…`SV-D8` are defaults; the review that lands step 2b rules them.
- `SV-D9` is lifted (2026-11-12). A proposal to answer the view from
  anything but the chain store's rows, or from C++, reopens `SV-D3`.
- `SV-D10` reopens only on the criterion above (ruled audit + named
  viewer job). A drive-by texture on `candidate.v1` is a defect, not a
  landing.
