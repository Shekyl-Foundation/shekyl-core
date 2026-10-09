# Shard view — the view hash of a `W`-byte shard and the fetch that produces it

**Status:** OPEN — Round 0 opened 2026-10-08. `SV-D1`, `SV-D2`, `SV-D3`
**RULED** (Rick, 2026-10-08, in review of the shard-view plan); `SV-D4`…`SV-D8`
**PROPOSED** with defaults, built as proposed and reopened on review.
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
   fetch Sub-PR 2, unbuilt at round open; `shekyl_daemon_operator_shard_fetch` is a typed
   miss; the serve side for `W`-shard bodies is the wallet lane's store
   rebuild (`WSS-`, behind `WSS-Q1`). The ordering in §4 follows from this.
5. **The method is admin-only and must stay so while it fetches** (`SV-D6`).

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

The open tip shard is refused with a typed error (`ShardOpen { shard_id,
closes_at_or_after }`), never rendered: its picture would change every block
and the integrity signal (`V3_SHARD_VISUALIZATION.md` property 1) would
false-alarm. A closed shard's aggregate is immutable below the reorg window,
so it is cached keyed on `(shard_id, close_height, hash_of(close_height))` and
invalidated when the block at `close_height` changes. The response carries
`close_height` so the rendering-spec version can be pinned to chain data
(the *Spec version is chain data* ruling).

### `SV-D6` — PROPOSED: the method stays restricted

`request_archival_shard` stays in `RESTRICTED_METHODS` (`RK-D6`). A call
spends an archivist's Tor bandwidth on a 3 MB body; opened to remote-wallet
callers it is a way to make any node hammer the archivist set. Viewers reach
it through a daemon they operate: a wallet's local daemon, or shekyl-web's
site daemon called server-side on its unrestricted listener. **Reopen if** a
skeleton-only read method is ever wanted for a different purpose; that would
be a new name, not this one relaxed.

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
| 2c | the serve side: a `ShardProvider` over `P`'s body store serving the tx-range frame | the wallet lane (`WSS-`) | `WSS-Q1` |
| 3 | `request_archival_shard` natively in `shekyl-daemon-rpc`; C++ deleted (`SV-D3`); `close_height` on the wire | this round | 2b |
| 4 | wallet RPC method (contract registry), CLI and GUI local render, shekyl-web server PNG route | this round | 3 |

Until 2c lands every fetch against the still-wired leaf-segment provider
ends `ContentRefused` — the body `P` signs is not the tx-range body the
client expects — and every viewer shows *"this archive could not be
retrieved"*, a visible state, never an empty picture (rule 82). That
interim refusal is a property of the provider, not of `P`: no consumer may
read it as evidence against the holder (`SF-D8` amendment, 2026-10-08).

---

## 5. Reopening

- `SV-D1` reopens only if the archival good's definition moves (`SHT-Q2`
  re-keyed); the customization string then bumps to `-v2` and the spec
  version activates at a height (*Spec version is chain data*).
- `SV-D2` reopens if a storage-only path is shown to exercise the serve
  endpoint end to end without a fetch client (the same clause as `SF-D1`).
- `SV-D4`…`SV-D8` are defaults; the review that lands step 2b rules them.
