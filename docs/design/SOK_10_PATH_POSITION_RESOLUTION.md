# SOK-10 — path position resolution

**Status:** OPEN — Round 0 (sweep). No design round. No production code.

**Owner:** the path-FFI lane (this branch, `feat/sok-10-path-position-resolution`).
FOLLOWUPS routes SOK-10 here as "PDM-Q-F9's"; that is this lane. The next reader
does not re-derive it.

**Pin:** `dev` = `8494f2a27f8b88aecdb11bb9548be5c70f3e9357` (merge of PR #779).
Every code claim below was re-read at this SHA. Line numbers are of this pin.

**Halt.** This file is the Phase 0 sweep record. Round 1 (rule 26 design) does
not start until the maintainer says so. Nothing in §2 is ruled.

Implements *from* [`DRS_E1_SOUT_KI.md`](DRS_E1_SOUT_KI.md) §3.4 / findings table
SOK-10 (routed off that surface, rule 22), [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md)
the SOK-10 row, [`CT2_DRAIN_ORDER.md`](CT2_DRAIN_ORDER.md),
[`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) `get_curve_tree_path`,
[`ARCHIVAL_PRUNED_DAEMON_MODE.md`](ARCHIVAL_PRUNED_DAEMON_MODE.md) F9,
[`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) S-CURVE / S-OUT-KI,
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2 `SOK-1…SOK-N`.
Nothing here re-opens S-OUT-KI's Q1–Q4.

---

## 1. Sweep record

### 1.1 Defect at source — SOK-10 as recorded, verified

`PathStore` takes one `u64` named `pos` for both the leaf and the output
record:

```29:36:rust/shekyl-fcmp/src/rpc_path.rs
pub trait PathStore {
    fn leaf(&self, pos: u64) -> Result<[u8; LEAF_BYTES], PathAssembleError>;
    fn layer_hash(&self, layer: u8, chunk: u64) -> Result<[u8; 32], PathAssembleError>;
    /// Compressed Ed25519 `(O, C)` for `chunk_outputs`. Distinct from the
    /// leaf's Wei25519 x-coords; a missing row is the same class as a missing
    /// leaf (PDM-Q-F9).
    fn output_oc(&self, pos: u64) -> Result<([u8; 32], [u8; 32]), PathAssembleError>;
}
```

`append_layer0` uses the same `pos` for both. `output_idx` is treated as a
tree position (`chunk_idx = output_idx / selene_cw`):

```72:96:rust/shekyl-fcmp/src/rpc_path.rs
fn append_layer0(
    store: &impl PathStore,
    output_idx: u64,
    ref_leaf_count: u64,
    selene_cw: u64,
    out: &mut AssembledRpcPath,
) -> Result<u64, PathAssembleError> {
    let chunk_idx = output_idx / selene_cw;
    // ...
    for pos in chunk_start..chunk_end {
        let leaf = store.leaf(pos)?;
        // ...
        let (o, c) = store.output_oc(pos)?;
```

The C++ callback that implements `output_oc` does **not** resolve the
position. It passes `pos` to `get_output_key(0, pos)` — a **global output
index** in the amount-0 bucket:

```64:71:src/cryptonote_core/curve_tree_path.cpp
  bool read_output_oc(void* ctx, uint64_t pos, uint8_t o_out[32], uint8_t c_out[32])
  {
    return guarded(ctx, [&](const BlockchainDB& db) {
      const output_data_t od = db.get_output_key(0, pos);
      std::memcpy(o_out, od.pubkey.data, 32);
      std::memcpy(c_out, od.commitment.bytes, 32);
      return true;
    });
  }
```

`leaf` is the matching half done right: `read_leaf` calls
`get_curve_tree_leaf_by_tree_position(pos, …)` (`curve_tree_path.cpp:50–:54`;
`db_lmdb.cpp:9655–:9669` keys `m_curve_tree_leaves` by that `uint64_t`).
The grow path writes the same key as `old_leaf_count + i`
(`db_lmdb.cpp:9103–:9110`, local name `global_idx` notwithstanding).

`get_leaf_output_index` / `get_output_leaf_index` exist because the two
indexes are not equal (`blockchain_db.h:2660–:2671`). LMDB tables
`m_output_to_leaf` / `m_leaf_to_output` are live (`db_lmdb.h:968–:969`;
bodies `db_lmdb.cpp:9001–:9046`). C++ newtypes name the split
(`shekyl_types.h:118–:131`: `TreePosition` vs `OutputIndex` — "NOT equal
to TreePosition in general"). Drain order is `(maturity, gindex)`; coinbase
defers 60 blocks (`CT2_DRAIN_ORDER.md:85`; `FCMP_PLUS_PLUS.md:57–:65`;
`CT2_DRAIN_ORDER.md` framing correction 1, coinbase `+60` not `+10`).

`get_output_key` on a miss throws `OUTPUT_DNE` (`db_lmdb.cpp:3728–:3752`).
`guarded` swallows that to `false` (`curve_tree_path.cpp:31–:48`), which
Rust reports as `PathAssembleError::MissingOutputKey` — fail-closed on a
**hole**. The SOK-10 case is the other direction: `pos` as a gindex usually
**hits** some other output (leaf-set ⊆ indexed-set, `CT2_DRAIN_ORDER.md` §2.2;
tree positions are `0..leaf_count-1` and gindexes `0..num_outputs-1` with
`leaf_count ≤ num_outputs`), so the callback returns `true` with the wrong
`(O, C)`. Silent-wrong `chunk_outputs`, not a named miss.

The prover rebuilds siblings from those `(O, I, C)` plus `CM.x`
(`proof.rs:377–:385`). Wrong `chunk_outputs` ⇒ wrong rebuilt siblings ⇒
the proof fails verification. Fail-closed; not a soundness hole; live
liveness. Inherited from pre-extraction C++ (`f2df035e7`), as SOK-10
already records.

Recorded fix (not designed this round): Rust assembler resolves
`TreePosition → GlobalOutputIndex` before `output_oc`, via `leaf_to_output`
(S-CURVE's read on redb; `get_leaf_output_index` on LMDB today). Rule 20:
the resolution is Rust; C++ stays a callback shim.

### 1.2 Wallet `output_indices` semantics — (c)

**(c) something else.** The production Engine spend path does not send
`get_curve_tree_path` at all. SOK-10 as recorded is still true of the
**daemon assembler** given a tree-position request (the (a) shape, on that
assembler only). It is not (b) in production, because nothing on the spend
path puts a `GlobalOutputIndex` on this wire. The field name and the
handler disagree; that is a separate finding (SOK-11, §2), not folded into
SOK-10.

Evidence:

- `rpc_path.rs:8–:13` states the split: this assembler is **not**
  `CurveTreeClient::assemble_path`. The wallet rebuilds layers from a
  locally-held leaf stream.
- Production spend calls `CurveTreeClient::assemble_path`
  (`curve_tree_actor.rs:501`). That function resolves **by `gindex`** to a
  drain-order position on its own stream (`assemble.rs:72–:116`, comment
  "resolve by `gindex`, the tree's unique key"; linear scan of
  `drained_sorted` which is `(maturity, gindex)`). It never talks to the
  daemon path RPC.
- Workspace grep of `get_curve_tree_path` as a production wallet caller:
  none, except the e2e below, the disposable spike `extract_shard.rs`, and
  comments. `shekyl-rpc-types` `output_indices` at `transactions.rs:77/:152`
  is `get_transactions` mined global indexes, a different RPC.
- The daemon handler bounds `req.output_indices` against `tip_leaf_count`
  and `ref_leaf_count` (`core_rpc_server.cpp:1522–:1541`) — leaf counts,
  i.e. **tree positions**. `assemble_rpc_path`'s precondition is
  `output_idx < ref_leaf_count` (`rpc_path.rs:174–:178`). The assembler
  then uses that value as `pos` in `chunk_idx = output_idx / selene_cw`.
- The wire field is named `output_indices`. `FCMP_PLUS_PLUS.md:377–:396`
  specifies `{ "output_indices": [uint64, ...] }` and does not say which
  index family. The same doc's tree section (`:57–:65`) *does* say tree
  position ≠ global output index. The RPC section does not cite that split.
- In-tree RPC callers:
  1. `e2e_get_curve_tree_path_returns_valid_path`
     (`regtest_e2e.rs:761–:853`) sends `[0u64]` after mining coinbase-only
     until leaf 0 is in the reference tree. At that fixture, gindex 0 and
     tree position 0 coincide. The doc comment (`:754–:758`) still says
     "the call the send path makes" — the send path does not make this call
     (rule 16: comment that outlived its architecture).
  2. `shekyl-sp-t3-spike` `extract_shard.rs:101–:123` sends
     `base + c * CHUNK_WIDTH` for `c in 0..684` — **tree-position-shaped**
     sampling of one leaf per Selene chunk, despite the JSON key name.
- `ProveInput`'s doc (`proof.rs:177–:180`) still says "the C++ wallet
  constructs this … from the Merkle path from `get_curve_tree_path`".
  Wallet2 is deleted; the live constructor is local `assemble_path`.

So: if a client sends a tree position (what the handler implements, what
the spike sends, what the e2e happens to send), `leaf(pos)` is the right
leaf and `output_oc(pos)` is SOK-10 — **(a) of the daemon assembler**. If a
client followed the field name and sent a `GlobalOutputIndex`, the handler
would treat it as a tree position: the **whole path** would be for the
wrong leaf whenever the two diverge — **(b), latent, not production**. That
latent is SOK-11, not a silent widening of SOK-10.

### 1.3 Fixtures — why nothing fails today, and the chain that would

Every in-tree test that reaches this assembler keys `(O, C)` by the same
integer it uses as a tree position:

| Fixture | What it pins | Why it cannot see SOK-10 |
| --- | --- | --- |
| `rpc_path.rs` `MapStore::filled` (`:251–:266`, tests `:304–:375`) | leaves and `ocs` both inserted at `pos in 0..n` | identity map `pos ≡ gindex` is the test model |
| `tests/unit_tests/curve_tree_path_fail_closed.cpp` `HoleyTreeDB` (`:22–:64`) | `get_output_key(amount, index)` keyed by `index`; `get_leaf_output_index` not overridden (`testdb.h:248–:249` returns `false`) | same identity; PDM-Q-F9 miss/throw coverage only |
| `e2e_get_curve_tree_path_returns_valid_path` | `[0]` on a coinbase-only mine-until-drain | first drained leaf is gindex 0 (coinbase-only preserves gindex order among drained outputs: maturity is `h+60`, strictly increasing with height) |
| `extract_shard.rs` | tree-position chunk starts | spike, not a divergence test |

**Coinbase-only ⇒ leaf order == gindex order among drained outputs.** All
maturities are `h+60`; drain sort `(maturity, gindex)` then matches scan
order. That is every current fixture.

**The breaking chain** (FOLLOWUPS falsifier, restated at source): a
normal-tx output drains before an earlier coinbase's leaf.

- Genesis / height-0 coinbase matures at 60, first appears in the tree on
  connect of height 61 (`CT2_DRAIN_ORDER.md` framing correction 1;
  `drained_through = H − 1`).
- A regular vout in block 1 matures at `1+10 = 11`, drains on connect of
  height 12.
- At height 12, leaf 0 is that regular output (some `gindex ≥ 1`, after
  genesis coinbase vouts), **not** gindex 0. `get_output_key(0, 0)` still
  returns the genesis coinbase. `chunk_outputs[0]` is then the wrong
  `(O, C)` for the leaf sitting at position 0.

Assert: `chunk_outputs[j]` is the output whose leaf sits at tree position
`j` (`get_leaf_output_index(TreePosition{j})` → `OutputIndex` →
`get_output_key(0, that)`). No current test builds this chain.

### 1.4 Types — every `u64` crossing

| Site | What the `u64` is | Type that would catch a swap |
| --- | --- | --- |
| `PathStore::leaf` / `output_oc` / FFI `shekyl_ct_read_*_fn` (`shekyl_ffi.h:1441–:1443`; `curve_tree_path_ffi.rs:17–:22`) | raw `pos: u64`; comments say tree position; `output_oc`'s C++ body treats it as gindex | none at the FFI; C++ `TreePosition` / `OutputIndex` stop at `BlockchainDB` |
| `assemble_rpc_path(..., output_idx: u64, ...)` | tree position (chunk math, bounds vs `ref_leaf_count`) | none |
| RPC JSON `output_indices` | unlabeled; handler implements tree position | none (JSON number) |
| `shekyl::db::TreePosition` / `OutputIndex` (`shekyl_types.h:118–:131`) | C++ strong ids; `get_leaf_output_index` takes / returns them | live on LMDB mapping reads; **not** used by `read_output_oc` |
| `shekyl_types::GlobalOutputIndex` (`lib.rs:355–:362`) | ledger-wide gindex (`next_output_seq`) | lives in `shekyl-types`; PathStore does not take it. Its own doc says "assigned densely to every output **in drain order**" — that sentence names the wrong order (gindex is scan order; drain order is tree position). Adjacent, not this lane's row. |
| `shekyl_types::LeafIndex` (`lib.rs:441–:445`) | position **inside a frozen segment**, "not a ledger-wide `GlobalOutputIndex` and not a curve-tree drain-order `TreePosition`" | names `TreePosition` as a type that **does not exist** in `shekyl-types` |
| `shekyl_curve_tree::TreePosition` (`types.rs:166–:170`) | drain-order dense position | wallet-client crate; daemon assembler does not depend on `shekyl-curve-tree` (`rpc_path.rs:8–:13`) |
| `shekyl_curve_tree::Gindex` | `pub type Gindex = GlobalOutputIndex` (RTN-4, landed) | wallet stream key; local assembler already resolves it |

`RAW_TYPE_NEWTYPE_MIGRATION.md` §2 (`:96–:99`) records that
`TreePosition(u64)` still lives in `shekyl-curve-tree` and is the wrong
home. §6 of that file is PR C (hash identity, RTN-7 landed) — there is
**no reserved row** for a `shekyl-types::TreePosition`. If this lane needs
that newtype on `PathStore`, it is the RTN pattern applied: propose a row
on that plan (with disclosure) and land it there; do not mint a family
and do not write the RTN status cell as if this lane owned it.

### 1.5 Stores — LMDB live, redb schema only

**LMDB (production daemon today).** Mapping tables populated and read.
`get_leaf_output_index` / `get_output_leaf_index` work. Path assembly does
not call them. `get_output_key` (S-OUT-KI O1's C++ body) is the live
`(O, C)` read and takes a gindex.

**redb.** `schema.rs:469–:473` declares `OUTPUT_TO_LEAF` and `LEAF_TO_OUTPUT`
(`INTEGERKEY`). No typed reader. S-CURVE (`DAEMON_REDB_STORE.md:628`) is
extraction order **6**, DRS-E3: five methods listed
(`get_curve_tree_depth`, `get_curve_tree_leaf_chunk`,
`get_curve_tree_leaf_count`, `get_curve_tree_root`,
`get_curve_tree_root_at_height`). **`get_leaf_output_index` is not in that
list.** This lane is the future *consumer* of that reader, not its author
(rule 94 §6). A one-line consumer pointer on the S-CURVE / DRS-E3 row is
the right shape after a ruling; a status change in their cell is not.

S-OUT-KI O1 (`ReadSnapshot::output(GlobalOutputIndex)`) is the type that
makes handing a tree position to the output record unrepresentable **once
the resolver exists**. That increment does not itself resolve. DRS-E6 is
`shekyl-chain-rules` (coverage gate, PR #768); this lane does not write it.

### 1.6 PDM-Q-F9 / pruned daemon

F9 as recorded (`ARCHIVAL_PRUNED_DAEMON_MODE.md:1262`; full text
`docs/completed/ARCHIVAL_PRUNED_DAEMON_MODE_ROUND.md:2558–:2572`): silent
**zero-fill** of a missing leaf, landed PR #733 — miss is now
`CORE_RPC_ERROR_CODE_INTERNAL_ERROR`. The path-FFI half this lane owns is
that same fail-closed class applied to a missing `(O, C)` (`rpc_path.rs:32–:35`,
`MissingOutputKey`) **and** SOK-10 (a present but wrong `(O, C)`). F9's
register row stays the PDM lane's; this lane fixes the path-FFI half.

`output_to_leaf` / `leaf_to_output` grade CACHE
(`ARCHIVAL_PRUNED_DAEMON_MODE.md:1424`): "leaf ↔ output mapping on pop and
RPC", rebuildable from insertion order. Under a future prune that discards
them:

- **Today (no resolver):** SOK-10 is silent-wrong as long as
  `output_amounts` still answers `get_output_key(0, pos)`. A discarded
  mapping does not change the bug.
- **After a resolver:** a missing `leaf_to_output` row is the F9 class —
  refuse, name the position, do not assemble. That miss path is owed in
  the same fix; it is not a second product.

This lane does not write the PDM-Q\* status cell. A consumer pointer
naming `SOK_10_PATH_POSITION_RESOLUTION.md` is the right shape if the PDM
lane wants it.

`db_lmdb.h:971` still comments `m_curve_tree_leaves` as
"`global_output_index` → 128 bytes". The write key is `old_leaf_count + i`
(`db_lmdb.cpp:9105`). That comment is the same confusion in the table's
own header (SOK-12).

### 1.7 Lane ownership — this lane is the path-FFI lane

SOK-10's FOLLOWUPS row routes it to "the path-FFI lane (PDM-Q-F9's)"; that
is this lane. So this lane owns: the fix, the `SOK-10` row's resolution in
`DRS_E1_SOUT_KI.md` (continue the `SOK-` numbering for anything new —
findings `SOK-11…`, questions `SOK-Q5…`; do **not** mint a prefix; check
`IMPLEMENTATION_INDEX.md` §2 first per rule 94 §1), the FOLLOWUPS row, this
plan doc, and the path-FFI half of `PDM-Q-F9` (`rpc_path.rs`,
`curve_tree_path_ffi.rs`, `curve_tree_path.cpp`, the `get_curve_tree_path`
handler and its contract prose in `FCMP_PLUS_PLUS.md`). Owner is recorded
in this file's banner so the next reader does not re-derive it.

`IMPLEMENTATION_INDEX.md` §2 already holds `**SOK-1…SOK-N**` (`:222`).
Prefix `SOK-` is unique. Highest finding at this pin is SOK-10; highest
question is SOK-Q4 (RULED). No new family.

Rows this lane still may **not** write without disclosure (rule 94 §6):
S-CURVE / DRS-E3 (the redb `leaf_to_output` reader — this lane is its
future *consumer*, not its author), DRS-E6, the `PDM-Q*` row itself (F9's
path-FFI half is this lane's to fix; the PDM lane's row records that it
landed), and `RTN-` (if a `TreePosition` newtype is needed, propose it to
that family's plan `RAW_TYPE_NEWTYPE_MIGRATION.md` §6 as a row and land it
with disclosure — it is the RTN pattern applied, not a new family).
One-line pointers on those rows naming this consumer are the right shape;
a status change in their cell is not.

---

## 2. Findings opened this sweep (not ruled)

| # | Finding (at `8494f2a27`) | Disposition this round |
| --- | --- | --- |
| **SOK-10** | As recorded and re-verified §1.1. Daemon assembler uses one `pos` for `leaf` (tree position, correct) and `output_oc` (handed to `get_output_key` as gindex, wrong whenever drain order ≠ scan order). | This plan. Design round not started. |
| **SOK-11** | Wire field `output_indices` is unlabeled (`FCMP_PLUS_PLUS.md:383`); the handler implements **tree position** (`core_rpc_server.cpp:1522–:1541`). Production spend does not call this RPC (§1.2). A client following the field name would get (b): the whole path for the wrong leaf. In-tree callers today either send a tree position (spike) or `[0]` on a coinciding fixture (e2e). | Contract prose (and possibly a rename) is this lane's `FCMP_PLUS_PLUS.md` half. Do not fold into SOK-10. Question **SOK-Q5**. |
| **SOK-12** | `db_lmdb.h:971` comments `m_curve_tree_leaves` as keyed by `global_output_index`. The write (`db_lmdb.cpp:9103–:9110`) keys by `old_leaf_count + i` (tree position). Same confusion as SOK-10, in the table header. | Comment is this lane's to correct when the assembler fix lands (file already on the path-FFI touch list via `get_curve_tree_leaf_by_tree_position`). Not a second product. |
| **SOK-Q5** | What does the JSON field *mean* going forward: pin it as tree position (document + keep the name, or rename), or pin it as `GlobalOutputIndex` and have the handler resolve via `get_output_leaf_index` before assembly? Production has no caller to preserve. | Round 1. |
| **SOK-Q6** | Where does `TreePosition → GlobalOutputIndex` resolve: a new `PathStore` method / FFI callback (Rust assembler asks; C++ shim calls `get_leaf_output_index`), or change `output_oc`'s `u64` domain from position to gindex after a Rust-side resolve the assembler cannot perform without a new read? Recorded routing says Rust assembler resolves before `output_oc`. That implies a new store read on the trait, not a silent ABI meaning-change of `pos`. | Round 1. Rule 20: resolution in Rust; C++ remains the LMDB callback. The redb `leaf_to_output` reader stays S-CURVE's; LMDB `get_leaf_output_index` is the callback body until then. |

Stale comments that are not new findings (rule 16, same round as the
touch, not a FOLLOWUPS row): `proof.rs:177–:180` (C++ wallet /
`get_curve_tree_path`); `regtest_e2e.rs:754–:758` ("the call the send path
makes"); `FCMP_PLUS_PLUS.md:380–:381` ("The wallet uses these paths to
construct FCMP++ proofs") — the live wallet does not.

---

## 3. Halt

Round 0 is the sweep. Report is this file. **Stop.**

Do not start Round 1 (design: PathStore shape, wire contract, LMDB callback
vs redb reader timing, test-chain shape) until told. Do not edit production
code, `DRS_E1_SOUT_KI.md`, `FOLLOWUPS.md`, `IMPLEMENTATION_INDEX.md`,
`FCMP_PLUS_PLUS.md`, or any other-lane row from this halt.
