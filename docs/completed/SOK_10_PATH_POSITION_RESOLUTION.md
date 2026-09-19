# SOK-10 — path position resolution

**Status:** CLOSED-as-record (2026-09-18). `SOK-Q7` RULED A by the
maintainer 2026-09-18; the endpoint `get_curve_tree_path`, `shekyl-fcmp::rpc_path`,
the `shekyl-ffi` callback shim and `curve_tree_path.{h,cpp}` are deleted on
this branch (RPC 3.34 — #782 took 3.33 on the same day; chained on merge). `SOK-Q5` / `SOK-Q6` moot under A; `SOK-11` closed with
the interface; `SOK-12` comment corrected; `SOK-13` FOLLOWUPS row removed.
Round 0 sweep confirmed 2026-09-18 with the mechanism sharpened (§1.1a);
Round 1 (§3) and Round 2 wargame (§3.5) closed the same day. Process per
`26-sub-pr-design-discipline.mdc`. **Do not implement from this file**; the
live contract is `FCMP_PLUS_PLUS.md`'s REJECTED line and
`PHASE_2A_SEND_PATH.md` §3.0.1. Every `path:line` below is a records-was
anchor at the pin, most into files this record deleted.

**Owner:** the path-FFI lane (this branch, `feat/sok-10-path-position-resolution`).
FOLLOWUPS routes SOK-10 here as "PDM-Q-F9's"; that is this lane. The next reader
does not re-derive it.

**Pin:** `dev` = `8494f2a27f8b88aecdb11bb9548be5c70f3e9357` (merge of PR #779).
Every code claim below was re-read at this SHA. Line numbers are of this pin.

**Rulings.** §1 is the Round 0 sweep record (confirmed). §3.1 carries the
`SOK-Q7` ruling; §3.2–§3.3 are moot under it and kept as the record of what
a future consumer's design round would have to answer. §3.5 is the Round 2
wargame against the ruled design.

Implements *from* [`DRS_E1_SOUT_KI.md`](DRS_E1_SOUT_KI.md) §3.4 / findings table
SOK-10 (routed off that surface, rule 22), [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md)
the SOK-10 row, [`CT2_DRAIN_ORDER.md`](../design/CT2_DRAIN_ORDER.md),
[`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) `get_curve_tree_path`,
[`ARCHIVAL_PRUNED_DAEMON_MODE.md`](../design/ARCHIVAL_PRUNED_DAEMON_MODE.md) F9,
[`DAEMON_REDB_STORE.md`](../design/DAEMON_REDB_STORE.md) S-CURVE / S-OUT-KI,
[`IMPLEMENTATION_INDEX.md`](../design/IMPLEMENTATION_INDEX.md) §2 `SOK-1…SOK-N`.
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

Recorded fix (not designed in Round 0): Rust assembler resolves
`TreePosition → GlobalOutputIndex` before `output_oc`, via `leaf_to_output`
(S-CURVE's read on redb; `get_leaf_output_index` on LMDB today). Rule 20:
the resolution is Rust; C++ stays a callback shim. Whether that fix is
built at all is `SOK-Q7` (§3.1).

### 1.1a Mechanism, sharpened (maintainer check 2026-09-18, verified at source)

The two indexes diverge on **every chain that has ever carried a
transaction**, not only on a contrived one. The maturity rule is per output
type, on both target variants:

```565:577:src/blockchain_db/blockchain_db.cpp
        if (std::holds_alternative<txout_to_tagged_key>(vout.target))
        {
          output_key = std::get<txout_to_tagged_key>(vout.target).key;
          maturity_raw = is_miner
              ? block_height_raw + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW
              : block_height_raw + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE;
        }
        else if (std::holds_alternative<txout_to_key>(vout.target))
        {
          // ... same rule
```

`CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW = 60`, `CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE
= 10` (`cryptonote_config.h:45`, `:49`). Global index is assigned in scan order,
coinbase first (`this_output{next_output_seq++}` at `:555`;
`CT2_DRAIN_ORDER.md` §2.1). Leaves drain in `(maturity, gindex)`.

So in the first block `h` that carries a transaction: the coinbase holds the
**lower** gindex and matures at `h+60`; the transaction's outputs hold higher
gindexes and mature at `h+10`. The transaction's leaves land at **lower** tree
positions than the coinbase's. From that block on, `pos ≠ gindex` for the
inverted pair and every later leaf shifts with it; the two orderings never
re-coincide under any continuing transaction flow.

`read_output_oc(pos)` therefore pairs the leaf at position `pos` with a
**different output's** `(O, C)` on every real chain. Fail-closed at proof
verification (§1.1), but wrong everywhere.

Why nothing caught it (§1.3, restated with the mechanism): every fixture is
coinbase-only, where one maturity rule applies to every output and the two
orderings coincide exactly. The divergence is unrepresentable in those
fixtures — the same shape as a zero `curve_tree_roots` entry passing on a
chain too short to have a gap.

**The test's own comment is a finding of the same family (maintainer,
2026-09-18).** `regtest_e2e.rs:758` calls `get_curve_tree_path` "the call
the send path makes." The send path has never made it (the wallet assembles
locally, §1.2). So: a green test, a true-looking comment, the wrong subject
— on a fixture whose shape is the exact reason the defect stayed invisible.
Rule 16's "comment that outlived its architecture" had been caught in doc
comments, plan prose and table headers; this is the first instance in a
**test's statement of what it covers**, which is the one layer a reader
trusts to tell them what is verified. Recorded here so the lesson outlives
the test, which is deleted with the endpoint.

Why production is unaffected: the wallet assembles locally
(`assemble.rs:98–:116`) by resolving `gindex` **through the drain-order
stream** — the correct resolution. The daemon assembler is the only site with
the bug, and it has no production consumer (§1.2, §3.1 table).

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

## 2. Findings opened this sweep — all CLOSED by `SOK-Q7` → A (2026-09-18)

| # | Finding (at `8494f2a27`) | Disposition this round |
| --- | --- | --- |
| **SOK-10** | As recorded and re-verified §1.1. Daemon assembler uses one `pos` for `leaf` (tree position, correct) and `output_oc` (handed to `get_output_key` as gindex, wrong whenever drain order ≠ scan order). | This plan. Design round not started. |
| **SOK-11** | Wire field `output_indices` is unlabeled (`FCMP_PLUS_PLUS.md:383`); the handler implements **tree position** (`core_rpc_server.cpp:1522–:1541`). Production spend does not call this RPC (§1.2). A client following the field name would get (b): the whole path for the wrong leaf. In-tree callers today either send a tree position (spike) or `[0]` on a coinciding fixture (e2e). | Contract prose (and possibly a rename) is this lane's `FCMP_PLUS_PLUS.md` half. Do not fold into SOK-10. Question **SOK-Q5**. |
| **SOK-12** | `db_lmdb.h:971` comments `m_curve_tree_leaves` as keyed by `global_output_index`. The write (`db_lmdb.cpp:9103–:9110`) keys by `old_leaf_count + i` (tree position). Same confusion as SOK-10, in the table header. | Comment is this lane's to correct when the assembler fix lands (file already on the path-FFI touch list via `get_curve_tree_leaf_by_tree_position`). Not a second product. |
| **SOK-Q5** | What does the JSON field *mean* going forward: pin it as tree position (document + keep the name, or rename), or pin it as `GlobalOutputIndex` and have the handler resolve via `get_output_leaf_index` before assembly? Production has no caller to preserve. | Round 1. |
| **SOK-Q6** | Where does `TreePosition → GlobalOutputIndex` resolve: a new `PathStore` method / FFI callback (Rust assembler asks; C++ shim calls `get_leaf_output_index`), or change `output_oc`'s `u64` domain from position to gindex after a Rust-side resolve the assembler cannot perform without a new read? Recorded routing says Rust assembler resolves before `output_oc`. That implies a new store read on the trait, not a silent ABI meaning-change of `pos`. | §3.3. **Conditional on Q7 ≠ A.** Rule 20: resolution in Rust; C++ remains the LMDB callback. |
| **SOK-Q7** | **Does the daemon assembler survive at all?** Zero production consumers; forbidden on the send path by a binding ruling; wrong on every real chain. Same question `get_output_histogram` got (SOK-Q3 → B). | §3.1. **Asked first**; Q5/Q6 are moot under arm A. Default **A — delete**. |
| **SOK-13** | `FOLLOWUPS.md:254` "C++ path RPC computes a crypto contract (`hash_to_p3`) inline" is **stale at this pin**: the extraction moved `I = Hp(O)` to Rust (`rpc_path.rs:90` `key_image_generator(&o)`); `curve_tree_path.cpp` and the handler contain no `hash_to_p3`. The row survived the fix that closed it. | Path-FFI FOLLOWUPS row, this lane's. Remove under either Q7 arm (rule 91: resolved items are removed). |

Stale comments that are not new findings (rule 16, same round as the
touch, not a FOLLOWUPS row): `proof.rs:177–:180` (C++ wallet /
`get_curve_tree_path`); `regtest_e2e.rs:754–:758` ("the call the send path
makes"); `FCMP_PLUS_PLUS.md:380–:381` ("The wallet uses these paths to
construct FCMP++ proofs") — the live wallet does not.

---

## 3. Round 1 — design — RULED 2026-09-18 (`SOK-Q7` A; §3.2–§3.3 moot, kept as record)

Short by construction: the correct resolution already exists in the tree
(`assemble.rs:98–:116`), so there is no open design space on *how* to
resolve. The round's two questions are whether the daemon assembler is
kept (Q7) and, only if it is, where the resolution lives (Q6) and what the
wire field means (Q5). Q7 is asked first because its default answer makes
the other two moot.

### 3.1 SOK-Q7 — does `get_curve_tree_path` survive? Default **A — delete**

**Substrate.**

1. **Binding privacy ruling, already on record.** `PHASE_2A_SEND_PATH.md`
   §3.0.1 (`:170`, "Decision (binding): the wallet never reveals which leaf
   it spends"): a per-output path request tells the daemon, before
   broadcast, exactly which output is being spent — "No per-leaf path
   query, full stop." The endpoint's disposition there (`:196–:203`):
   **must not** be used by the wallet send path; "flagged for daemon-side
   Rule-60 / privacy review as a separate C++ PR (acceptable, if at all,
   only for explicitly non-private contexts — debug, or an opt-in
   light-wallet mode that documents the linkability cost)." That review
   was never opened — no FOLLOWUPS row carries it. **This question is that
   review.**
2. **Every consumer, enumerated.**

   | Caller | Repo | Nature | Survives deletion? |
   | --- | --- | --- | --- |
   | Engine spend path | core | uses `CurveTreeClient::assemble_path` locally (`curve_tree_actor.rs:501`) | unaffected |
   | `e2e_get_curve_tree_path_returns_valid_path` (`regtest_e2e.rs:761`) | core | tests that the endpoint is not 404 on the Axum transport; its doc says "the call the send path makes" — false at this pin | deleted with the endpoint |
   | `curve_tree_path_fail_closed.cpp` | core | C++ seam test of the shim | deleted with the shim |
   | `extract_shard.rs` (`shekyl-sp-t3-spike`) | core | **disposable debt, labelled at birth** (`spike/src/lib.rs:6–:7`: "MUST BE DELETED OR FULLY REWRITTEN BEFORE TJ-B"); uses the RPC as a batched leaf source (`fixture.rs:41–:50`) | loses its data source; disclosed to that crate's owner (§3.4), not repaired here |
   | GUI wallet, mobile wallet, web | sibling repos | `rg get_curve_tree_path` → **no match** in any | n/a |
   | `shekyl-daemon-rpc` (Rust daemon RPC) | core | no handler | n/a |
   | Archival personas / fetch side | core | `PDM-Q8` RULED 2026-09-18: "the persona never fetches — its daemon does, episodically" (`ARCHIVAL_PRUNED_DAEMON_MODE.md:1303`); the serve unit is a raw leaf array (`FCMP_SPEND_LINKABILITY_CENSUS.md` S0 `served_frame.rs` row), not this RPC | unaffected |
   | Bulk non-revealing leaf-range RPC (`CURVE_TREE_CLIENT.md:620–:628`, `PHASE_2A` §3.0.2) | core | **not landed** (`core_rpc_ffi.cpp:285–:287` dispatches only `path` / `info` / `checkpoint`); the wallet is block-derived and does not need it | independent |

3. **The data is wrong on every real chain** (§1.1a). An RPC with no
   consumer that returns wrong data is not a thing to repair — the shape
   of `SOK-Q3 → B` (`get_output_histogram`, deleted on privacy grounds as a
   disclosure surface with no consumer). This one is the stronger case: a
   disclosure surface *and* incorrect.
4. **Rule 15 default is delete.** Rule 22: a STAGED surface needs a named
   live-plan consumer; there is none, and the §3.0.1 carve-out names a
   *class* ("debug, or an opt-in light-wallet mode"), not a plan.
   Rule 23: the **name** stays REJECTED in the namespace contract so it is
   not re-minted — the daemon has no method registry analogous to
   `wallet_rpc.yaml` (observed; not this lane's to build), so the entry
   lives in `FCMP_PLUS_PLUS.md`'s RPC section as a one-line
   `get_curve_tree_path — REJECTED (spend-revealing, PHASE_2A §3.0.1; SOK-10)`.

**Arms.**

- **A — delete the endpoint and the daemon assembler.** Default.
- **B — fix (Q6) and keep, for the §3.0.1 carve-out.** Requires naming the
  consumer now. None exists → this is the rule-22 callee-without-caller
  smell wearing a fix. Rejected unless a plan doc names the light-wallet /
  debug consumer with its written linkability disposition **before** the
  fix lands.
- **C — fix and gate (regtest / debug flag).** Same as B with a nettype or
  flag branch on an RPC surface; a consumer-less gate is a gate nobody
  opens. Rejected on B's grounds.

**Ruling — `SOK-Q7` RULED 2026-09-18 (maintainer): A.** Four grounds
converge, each sufficient on its own: (1) spend-revealing under a binding
ruling (`PHASE_2A_SEND_PATH.md:107`, `:184–:190`: `get_outs` went because
FCMP++ needs no ring, and that same absence leaves nothing to hide behind
when a wallet asks for one specific path); (2) no production consumer on any
repo, and `PDM-Q8` forecloses the persona path; (3) wrong data on every real
chain (§1.1a, verified at source by the maintainer independently); (4) under
`00-mission.mdc`'s ordering a privacy surface with no users is removed, not
repaired. B and C rejected: fixing a spend-revealing endpoint so it reveals
spends *accurately* is not an improvement, and gating it mitigates a feature
nobody asked for. Q7 was the daemon-side privacy review §3.0.1 flagged; this
is its answer.

**Reopening criterion (rule 21) — read this before reaching for `git
revert`.** The criterion is **not** "restore this endpoint." §3.0.1 forbids
the **shape** — a per-output path query — not an implementation. A future
light-wallet or debug consumer needs a **bulk, non-revealing leaf-range
service** (`PHASE_2A_SEND_PATH.md:105`, the "only gap"; `CURVE_TREE_CLIENT.md:620–:628`:
takes a position *range*, capped, never per-output; the client assembles
locally). That is a **design round in the consumer's plan**, which inherits
§1 of this file as its substrate read and §3.2/§3.3 as the questions a
per-output shape would have had to answer — and does not answer them,
because it does not ship that shape. Reverting the deletion is the wrong
action under every reopening this document can name.

**Deletion surface (arm A) — enumerated at the pin.**

| Surface | Lines | Action |
| --- | --- | --- |
| `rust/shekyl-fcmp/src/rpc_path.rs` | whole module; `lib.rs:21`, `:28` re-exports | delete |
| `rust/shekyl-ffi/src/curve_tree_path_ffi.rs` | whole; `shekyl_ffi.h:1435–:1444+` prototypes | delete |
| `src/cryptonote_core/curve_tree_path.{h,cpp}` | whole | delete |
| `core_rpc_server.cpp` `on_get_curve_tree_path` | `:1463–:1562`; `core_rpc_server.h:152`; `core_rpc_ffi.cpp:283–:285` dispatch row and its 404 comment | delete |
| `COMMAND_RPC_GET_CURVE_TREE_PATH` | `core_rpc_server_commands_defs.h:1371–:1418` | delete |
| `CORE_RPC_VERSION_MINOR` | `rust/shekyl-rpc-types/src/chain.rs:64` (`32`) + its history comment and `:472` assert | bump — removing a method is a wire change |
| `BlockchainDB::get_curve_tree_layer_hash` | `blockchain_db.h:2719`; `db_lmdb.{h:620,cpp:9637}`; stubs `testdb.h:274`, `chaingen.cpp:165` | delete — the shim was its only caller (`rg` shows no other) |
| `tests/unit_tests/curve_tree_path_fail_closed.cpp` | whole | delete |
| `e2e_get_curve_tree_path_returns_valid_path` | `regtest_e2e.rs:754–:~900` | delete |
| `tree.rs:11`, `:530` comments naming `rpc_path` / `append_layer0` | — | rewrite (`leaf_from_chunk_entry` itself **stays**: archival tests consume it, `gate2_serve_credit_kat.rs:474`, `assembled_path_crosscheck.rs:170`) |
| `hash_trim_selene` / `hash_trim_helios` | — | **stay** — the LMDB trim path uses them (`db_lmdb.cpp:9426`) |
| `db_lmdb.h:971` comment (SOK-12) | — | correct to "tree position" |
| `proof.rs:177–:180` doc | — | rewrite: witness comes from `CurveTreeClient::assemble_path` |
| `FCMP_PLUS_PLUS.md` `:377–:413` | — | replace the section with the REJECTED line + pointer to `PHASE_2A` §3.0.1 and local assembly |
| `DAEMON_RPC_RUST.md:274` | — | remove the bullet |
| `FOLLOWUPS.md:254` (`hash_to_p3`, SOK-13), `:597` ("Historical tree path assembly uses current LMDB state"), `:600` (SOK-10) | — | remove — all three are rows about the deleted surface |
| `DRS_E1_SOUT_KI.md` SOK-10 row (`:414`) and §3.4 | — | resolution recorded: closed by deletion, not by fix |
| `IMPLEMENTATION_INDEX.md` `SOK-1…SOK-N` row (`:222`) | — | `UPDATE` line: SOK-10 closed by deletion (Q7 A), SOK-11/12/13 |

**Other-lane rows — one-line consumer pointers only (rule 94 §6):**
`DAEMON_RPC_KV_CUTOVER.md` RK-9 (`:133`, lists the method);
`FCMP_SPEND_LINKABILITY_CENSUS.md` S0 "RPC path" row (`:136`) and `:46`,
`:402` — deletion **closes** that linkability surface, which the census
lane records; `ARCHIVAL_PRUNED_DAEMON_MODE.md` F9 register row (`:1262`)
— moot once the RPC path is gone; `DRS_E1_SOUT_KI.md` SOK-7 note — O1's
"shaped for the live consumer (returns pubkey **and** commitment)" loses
that consumer; the shape may still be right, but its stated reason is
gone, and that lane decides. `CT4_ROUND1_CLOSEOUT.md` is `docs/completed/`;
left alone.

**Tests under A.** No divergence falsifier is built — there is nothing left
to falsify (rule 22: moot, not deferred). Exit check:
`rg 'get_curve_tree_path|GET_CURVE_TREE_PATH|assemble_curve_tree_path|rpc_path|get_curve_tree_layer_hash' src rust tests --glob '!*.md'`
returns **only** the expected residuals, none of them code that runs against
the deleted surface: the RPC-version history comment and its 3.34 entry
(`rust/shekyl-rpc-types/src/chain.rs`, `tests/rpc_parity.rs` — the record of
*why* the minor bumped), and the disposable `shekyl-sp-t3-spike`'s
records-was header and its JSON string literal (`bins/extract_shard.rs`,
`src/fixture.rs` — marked non-running, §3.4). Every other hit is a defect. `cargo test -p shekyl-fcmp -p shekyl-ffi -p shekyl-rpc-types`
and the C++ unit-test target build clean. The RPC-version assert is
re-pinned.

**Commit shape under A** (rule 90, one PR, ≤ 5 commits): (1) Rust — delete
`rpc_path` + FFI + `CORE_RPC_VERSION` bump; (2) C++ — delete shim, handler,
command struct, `get_curve_tree_layer_hash`, tests; (3) docs — contract
REJECTED line, FOLLOWUPS rows, SOK rows, index `UPDATE`, stale comments
(SOK-12, `proof.rs`), other-lane pointers; (4) `git mv` this file to
`docs/completed/` with `Status: CLOSED-as-record`.

### 3.2 SOK-Q5 — wire meaning (only if Q7 ≠ A)

Default: pin as **tree position**. Rename the field `tree_positions`
(there is no production caller to preserve), bump `CORE_RPC_VERSION_MINOR`,
and write the position semantics into `FCMP_PLUS_PLUS.md` with a pointer to
`:57–:65`. The alternative — accept `GlobalOutputIndex` and resolve with
`get_output_leaf_index` in the handler — moves the resolution into C++,
against rule 20, and makes a spend-revealing query *more* convenient.
Under A this question and SOK-11 close with the interface.

### 3.3 SOK-Q6 — where the resolution lives (only if Q7 ≠ A)

Default **(i)**: a new `PathStore` read, `output_index_at(pos: u64) ->
Result<GlobalOutputIndex, PathAssembleError>` (new variant
`MissingLeafMapping(u64)`, the F9 class), with a fourth C callback whose
LMDB body is `get_leaf_output_index(TreePosition{pos})`; `output_oc` then
takes `GlobalOutputIndex` (`shekyl-fcmp` already depends on `shekyl-types`,
`Cargo.toml:53`). The FFI stays `u64` at the C boundary; the domain is
carried by the callback's name and the Rust trait's types. The redb body
is S-CURVE's when it lands (that lane's row; this lane is its consumer).

Rejected **(ii)**: reconstruct the drain order inside the assembler. The
daemon already holds the mapping as a table; recomputing it needs the
pending/maturity stream, which the daemon has only *as* those tables.

Falsifier: `MapStore` gains a permuted `leaf_to_output` map (position `0`
→ gindex `1`, position `1` → gindex `0`), and
`complete_store_yields_expected_shape` asserts `chunk_outputs[j]` carries
the `(O, C)` of `leaf_to_output[j]`, red before the change; plus the
regtest chain of §1.3 as the daemon-level check. A `TreePosition` newtype
in `shekyl-types`, if wanted, is an `RTN-` row proposed with disclosure to
`RAW_TYPE_NEWTYPE_MIGRATION.md` (§1.4), not minted here.

### 3.4 Interactions disclosed to other lanes (no edits made)

- **`shekyl-sp-t3-spike` owner:** arm A removes `extract_shard.rs`'s data
  source. The crate is labelled disposable and pre-TJ-B; replacement, if
  wanted, is a block-derived rebuild via `shekyl-curve-tree` or a bulk
  leaf-range read the design already names (`CURVE_TREE_CLIENT.md:620`).
- **S-OUT-KI lane:** SOK-7's shaping rationale for O1 loses its live
  consumer under A (above).
- **Census lane (`FCMP_SPEND_LINKABILITY_CENSUS.md`):** S0 "RPC path"
  surface closes under A.
- **PDM lane:** F9 register row becomes moot under A.
- **DAEMON_RPC_KV_CUTOVER (RK-9):** method count drops by one under A.

### 3.5 Round 2 — wargame against the ruled design (closed 2026-09-18)

The Phase 2 attack list was written against a *fix*. Under arm A most
attacks lose their subject; each is still disposed, not skipped, so a
reader can tell "moot by deletion" from "not examined." Dispositions:
**closed by construction** (name the invariant), **closed by test**,
**REJECTED** (reasoning + rule-21 reopening), **DEFERRED** (blocker +
falsifier). No undisposed attacks.

| # | Attack | Disposition |
| --- | --- | --- |
| W1 | **Soundness — a daemon feeds `(O, I, C)` for the wrong output and the proof still verifies.** | Closed by construction, twice. (a) The surface that served `chunk_outputs` is gone; no daemon-supplied prover input remains. (b) The only path source is the wallet's own block-derived stream: `assemble_path` refuses unless its locally recomputed root equals the consensus `curve_tree_root` at the reference height (`assemble.rs:83–:90`, `RootMismatch`) and checks the resolved leaf carries the expected `(O, C)` (`:117–:120`, X3). No trust-in-daemon finding to file: the wallet never took prover inputs from the daemon on the send path (`PHASE_2A` §3.0.1). |
| W2 | **Liveness under reorg — mapping as of reference vs tip; `BoundaryTrim`; a coinbase whose deferral crosses the reference boundary.** | Moot by deletion: `BoundaryTrim` and the reference/tip split were this assembler's. The wallet's equivalent is CT-4's `drained_through(reference.height)` cutoff, KAT-pinned there; not re-audited here (§4). |
| W3 | **Fail-closed vs fail-open — every miss path.** | Moot for the deleted paths. The one *new* behaviour: a client calling `get_curve_tree_path` gets JSON-RPC method-not-found from the Axum dispatch (the row is removed from `get_jsonrpc_table()`), plus `CORE_RPC_VERSION_MINOR` bumped so a client checking `get_version` sees the change. No plausible-looking default remains — the method does not exist. |
| W4 | **Pruned daemon — which resolver tables survive discard.** | Moot: no resolver. Side-effect recorded for the PDM lane: `output_to_leaf` / `leaf_to_output`'s reader list "on pop and RPC" (`ARCHIVAL_PRUNED_DAEMON_MODE.md:1424`) loses the RPC reader; F9's register row (`:1262`) is moot. Pointer only (§3.4). |
| W5 | **Privacy — does the change widen what the RPC reveals.** | Closed by construction: deletion strictly narrows. The endpoint that revealed which indices a wallet asks about no longer exists; `get_curve_tree_info` / `get_curve_tree_checkpoint` take no output index. The census lane's S0 "RPC path" row closes (§3.4). |
| W6 | **Network uniformity (rule 71).** | Closed by construction: no code path remains to branch on nettype. Arm C (a gated endpoint) was the only arm that could have introduced one; rejected. |
| W7 | **Type escape hatches — a `TreePosition` built from a gindex's `u64`.** | Moot for the deleted trait. Residue outside this lane, recorded not fixed (§1.4): `shekyl_types::GlobalOutputIndex`'s doc says "in drain order" (wrong order); `LeafIndex`'s doc names a `shekyl-types::TreePosition` that does not exist. Adjacent rows, not this PR. |
| W8 | **Determinism / KAT — does the assembled byte layout change.** | Moot: no daemon-assembled bytes remain. The wallet's path layout is pinned by CT-4's reconstruct-root KAT (`CT4_ROUND1_CLOSEOUT.md` §6), unchanged by this PR. |
| W9 | **Something still compiles against the deleted symbols.** | Closed by test: the §3.1 exit `rg` returns nothing in `src/ rust/ tests/`; `cargo build`/`clippy` over the workspace lane and the C++ build of `cryptonote_core`, `rpc`, `unit_tests` are the check. `hash_trim_*` (`db_lmdb.cpp:9426`) and `leaf_from_chunk_entry` (archival tests) keep their consumers and stay. |
| W10 | **Something still *calls* the deleted RPC at runtime.** | Closed by enumeration (§3.1 table): the only runtime caller left is `shekyl-sp-t3-spike` `extract_shard.rs`, disposable debt labelled at birth, disclosed to its owner (§3.4). It compiles (the method name is a string literal) and fails loudly at run with the daemon's method-not-found. REJECTED as a blocker: rewriting the spike is that crate's scope; its own header says it must be deleted or rewritten before TJ-B. Reopen if TJ-B's plan names a leaf source and it is not the bulk service. |
| W11 | **The deletion is later reverted as "restoring a missing RPC".** | REJECTED by the reopening criterion (§3.1 "Ruling"): the criterion names a *different shape* (bulk, non-revealing range service) and a *design round*, not a revert. The REJECTED line in `FCMP_PLUS_PLUS.md` is the grep surface that stops a re-mint (rule 23). |
| W12 | **A FOLLOWUPS row is removed whose subject was not this assembler.** | `:600` is SOK-10 by name. `:254` (`hash_to_p3`) names "C++ path RPC" — this endpoint; SOK-13 shows it stale regardless. `:597` "Historical tree path assembly uses current LMDB state": the daemon has exactly one tree-path assembler, and its reference-vs-tip handling (`maybe_trim_boundary`) is what the row describes; closed by deletion. If a reader knows a second subject for `:597`, that is a reopen with the subject named. |
| W13 | **Deleting `get_curve_tree_layer_hash` breaks a store read someone else needs.** | Closed by enumeration: `rg` at the pin lists the shim, the LMDB body, the abstract decl and the two test stubs — no other caller. Grow/trim read `m_curve_tree_layers` through their own cursors (`db_lmdb.cpp:9164`, `:9417`), not this accessor. S-CURVE's five-method list (`DAEMON_REDB_STORE.md:628`) never included it. |

**What this round did not find.** No finding against the wallet's local
assembler beyond the resolve step already read; none against
`get_curve_tree_info` / `get_curve_tree_checkpoint`; none against the
archival serve path (`get_curve_tree_leaf_chunk`, F8), which is a different
read and is not touched. No attack reopened a ruled question; implementation
proceeds.

## 4. What this round did not find

Surfaces examined that yielded nothing: the three sibling wallet repos and
`shekyl-web` (no caller of the RPC); `shekyl-daemon-rpc` (no Rust handler);
`hash_trim_*` (has consumers outside the shim — survives);
`leaf_from_chunk_entry` (archival test consumers — survives); the wallet's
local resolution at `assemble.rs:98–:116` (read for its resolve step only,
not re-audited end to end — CT-4's KAT is that audit). Not examined this
round: whether `get_curve_tree_info` / `get_curve_tree_checkpoint` carry
any per-output surface (they take no output index; out of scope unless a
reviewer names a reason).

## 5. Implementation

`SOK-Q7` ruled A; Round 2 closed with no reopen. The §3.1 commit shape is
the implementation, on this branch. No red-first falsifier is built: there
is no fix to falsify (rule 22 — moot, not deferred; disclosed in §3.1
"Tests under A"). The docs commit records every other-lane pointer it
writes. This file moves to `docs/completed/` as the last commit.
