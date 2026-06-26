# CT-2 — block-derived drain-order replication (design — Round 0)

**Status:** design, Round 0 (enumeration). The CT-2 row of
`CURVE_TREE_CLIENT.md` §9. This doc is the **specification** half (rule
`05-system-thinking.mdc`: spec first, code second); the replicate-and-KAT is
CT-2 implementation. Nothing here is implemented.

**Why it exists.** Under the **block-derived default** (`CURVE_TREE_CLIENT.md`
§6 — the wallet reconstructs the leaf stream from blocks it already syncs rather
than trusting a bulk-leaf RPC), the wallet must replicate the C++ daemon's
drain/index/reorg ordering **bit-exactly**. Any divergence shifts curve-tree
leaf positions, which breaks (a) `R_k` content-addressing (§7 archival
segments), (b) the locally-recomputed root's equality with the consensus
block-header `curve_tree_root`, and (c) every membership proof anchored after
the divergence. The single equality that proves block-derived is sound is the
**reconstruct-root KAT** (§8): wallet-reconstructed root at a reference height
**byte-equals** the C++ block-header `curve_tree_root`.

**Round-0 deliverable.** The enumeration table — for each of the three
divergence surfaces (S1 index assignment, S2 drain trigger + batch order, S3
reorg reordering) the exact C++ rule cited to source, plus the named genesis
corners (empty-tree root, founder-allocation drain order, coinbase leaf
construction). Round 1 turns this into the replication code + KAT.

**Two framing corrections surfaced by the source read** (both load-bearing;
§9 carries the full disposition):

1. **Coinbase matures at `+60`, not `+10`.** The founder allocations are
   genesis **coinbase** outputs (block 0), so they mature at height **60**
   and first appear in the tree at height **61** — a matured leaf enters on
   connection of the *next* block (`drained_through = H − 1`, pinned by the
   CT-2 KAT). The empty-tree window is therefore heights **0..=60**, not 0..9.
   The spike prompt and `CURVE_TREE_CLIENT.md` §8 #/early-height prose said
   "drain at 10 / empty 0..9"; that is wrong for coinbase. (An earlier draft
   of §5 below estimated "first non-empty at 60"; the KAT corrects the
   inclusive/exclusive boundary to 61.) Corrected here and cross-edited.
2. **The empty-tree root is `selene_hash_init`, not `build_layers([])`.** The
   daemon emits the Selene `hash_init` point for an empty tree
   (`db_lmdb.cpp:5909-5921`), **not** the `[[]]` zero-node structure CT-0's
   `empty_tree_is_a_ct2_boundary` left open. CT-2 pins this: the wallet's
   reconstruct path special-cases `leaf_count == 0 → selene_hash_init()`.

---

## 1. The replication contract

The wallet's block-derived reconstruction is a pure function of public block
data. For it to be sound, three sub-functions must each match the daemon
byte-for-byte, composed into the root equality:

```text
blocks ──S1──▶ (global_output_index, leaf bytes) per output
           ──S1-leaf──▶ 128-byte leaf {O.x, I.x, C.x, h_pqc}
           ──S2──▶ drained leaf stream in (maturity, gindex) order
           ──build_layers / build_upper_layers──▶ curve_tree_root
                       ║
                       ╚════ MUST byte-equal ════▶ block-header curve_tree_root
           ──S3──▶ (under reorg) survivors frozen, tail re-drained
```

`build_layers` is the canonical composition CT-0 promoted into
`shekyl-fcmp::tree` and Tier-2-validated against the daemon's incremental
`hash_grow`/`hash_trim`. CT-2 is what proves the **inputs** to `build_layers`
(the ordered leaf stream) are themselves bit-exact against consensus.

---

## 2. S1 — `global_output_index` assignment (intra-block ordering)

Leaf positions follow the global index, so the wallet must assign indices in
the daemon's exact order.

### 2.1 Enumeration

| Question | Rule | Source |
|----------|------|--------|
| Counter scope | Chain-wide **monotonic** `output_id`; `num_outputs() = 1 + max(output_id)` from `m_output_txs` (`MDB_LAST`). Genesis starts at 0. **No persistent counter field** — recomputed from the table. | `db_lmdb.cpp:1159-1196`, `db_lmdb.cpp:3074-3093` |
| Where assigned | `add_block → add_transaction → add_output`; `output_id = m_num_outputs` (the pre-increment count). | `db_lmdb.cpp:1196`, `1214` |
| Coinbase vs tx order | **Coinbase (miner_tx) first**, then block txs. `add_transaction(blk_hash, blk.miner_tx)` precedes the `for (tx : txs)` loop. | `blockchain_db.cpp:296-313` |
| Tx order within block | **`blk.tx_hashes` list order** (the `txs` vector is built by iterating `bl.tx_hashes`, not re-sorted). | `blockchain.cpp:4735-4738` |
| Output order within tx | **`vout[0..n-1]`** ascending; `local_index = i` passed to `add_output`. | `blockchain_db.cpp:242-268` |
| FCMP replay order | Same: `collect_outputs(blk.miner_tx, true)` then `for (tx : txs) collect_outputs(tx, false)`, `next_output_seq++` per vout. | `blockchain_db.cpp:359-361`, `417-420` |
| What "global index" the wallet sees | `m_global_output_index` = `amount_index` in **bucket 0**; under v3 (all `vout.amount == 0`) this **equals `output_id`**. | `wallet2.cpp:2672`, `LMDB_SCHEMA.md:278-279`, `blockchain.cpp:3322` |
| Filtering (indexed set) | **All `vout` entries indexed** (no amount-0 filter in `add_transaction`). v3+ non-coinbase outputs must have `amount == 0` (consensus); coinbase amount forced to 0 at index time; unsupported output target ⇒ block-add **throws**. | `blockchain.cpp:3443-3448`, `db_lmdb.cpp:1167-1169`, `cryptonote_format_utils.cpp:754-763` |
| Index ≠ tree position | `OutputIndex` is **NOT** `TreePosition`; drain reorders by `(maturity, gindex)`. | `shekyl_types.h:94-97`, `FCMP_PLUS_PLUS.md:49-55` |

**Replication rule (byte-exact global index).** Per height: miner outputs
`vout[0..]` first; then each non-miner tx in `block.tx_hashes` order, each
`vout[0..]`; increment one monotonic counter per indexed vout; counter starts 0
at genesis. The Rust scanner already follows this shape
(`rust/shekyl-scanner/src/scan.rs:736-738`, `shekyl-oxide/rpc/src/lib.rs:672-678`).

### 2.2 Divergence surface — leaf-set ⊆ indexed-set (RESOLVED at source)

`collect_outputs` consumes one global index per vout **before** any skip
(`const OutputIndex this_output{next_output_seq++}` at `blockchain_db.cpp:360`,
top of the per-vout loop), then **skips pending-leaf registration** (`continue`,
or the leaf simply not added) when any of:

- (a) output target ∉ {`txout_to_tagged_key`, `txout_to_key`,
  `txout_to_staked_key`} — `else { continue; }` at `:392-393`;
- (b) `i >= tx.rct_signatures.outPk.size()` — `continue` at `:395-396`;
- (c) `shekyl_construct_curve_tree_leaf(...)` returns false — the `if` at
  `:401-403` guards `add_pending_tree_leaf`, so a decompress-failure output is
  silently not a leaf.

**The leaf-skip predicate is therefore: `include iff (a-target-ok) ∧ (b-has-outPk)
∧ (c-construct-ok)`.** `gindex` is assigned to *every* vout regardless of the
predicate, so `global_index → tree_position` is **not surjective** in general: a
skipped output consumes a `gindex` (keeping the index space gap-free) but
produces no leaf, and the surviving leaves carry their (possibly
non-contiguous) `gindex` values as the S2 drain tiebreaker. Source:
`blockchain_db.cpp:355-409`.

**Coinbase is trivially include-all (the Tier-A-relevant case).**
`construct_miner_tx` populates `outPk` with real commitments
(`cryptonote_tx_utils.cpp:156` `outPk.resize`, `:179` `memcpy(...mask...,
od.commitment...)`), and even the explicit-`RCTTypeNull` path does the same
(`:709-743`). So (b) never fires for coinbase; coinbase outputs are
`txout_to_tagged_key`/`txout_to_key` so (a) passes; and (c) is the shared
`construct_leaf`. **A coinbase-only chain produces a leaf per coinbase output —
this is what keeps Tier A non-empty** (and confirms the §5 `C = zG + aH` row: a
coinbase commitment is real, never `zeroCommit`).

**Round-1 disposition.** The wallet's reconstruction **implements the real
predicate (a)∧(b)∧(c), not a hardcoded include-all** — even though Tier A
(coinbase, V3-genesis) under-exercises it (the skip set is empty there). A
hardcoded include-all is exactly the kind of thing Tier B reveals late. No
separate consensus check forces leaf construction to succeed, so (c) is the
surface most likely to bite on a malformed-but-valid output; the
hard-error-vs-skip-match decision for that case stays a reversion (open
question #1), with the default being **skip-match the daemon** (replicate, do
not diverge).

---

## 3. S1-leaf — coinbase / `RCTTypeNull` leaf construction (the sharp sub-surface)

Every block has a coinbase, so a wrong coinbase leaf diverges the tree at every
block. The leaf is `construct_leaf(O, C, h_pqc) → 128 B = {O.x, I.x, C.x,
h_pqc}` where `I = Hp(O)` (key-image generator, Monero biased hash-to-curve),
x-coords are Wei25519 via `ed25519_point_to_selene_scalar`
(`rust/shekyl-fcmp/src/tree.rs:328-353`, `311-325`).

| Question | Rule | Source |
|----------|------|--------|
| Is coinbase a tree leaf? | **Yes** — `collect_outputs(blk.miner_tx, true)`; deferred, maturity `+60`. | `blockchain_db.cpp:417-420`, `372-374` |
| Coinbase commitment `C` | **Real** `C = z*G + amount*H` (`z` from HKDF in `shekyl_construct_output`); `RCTTypeNull` still serializes real `outPk`. | `output.rs:288-293`, `rctTypes.h:207-210`, `cryptonote_tx_utils.cpp:179`,`743` |
| Trivial-commitment rejection | Consensus **rejects** `C == zeroCommit(amount)` (mask=1), `C == identity()`, `C == G` for coinbase. So a coinbase leaf is **never** a zero/identity commitment. | `blockchain.cpp:3402-3425`, `rctOps.cpp:322-333` |
| Coinbase `h_pqc` | **Real per-output hybrid hash**, `Blake2b-512("shekyl-pqc-leaf" ‖ hybrid_pk) wide-reduced`, computed by `shekyl_construct_output` (miner self-KEM, per-output) and stored **on-chain in `tx_extra` tag `0x07`** (`TX_EXTRA_TAG_PQC_LEAF_HASHES`, `N×32` in vout order). | `derivation.rs:53-71`, `cryptonote_tx_utils.cpp:162-192`,`726-755`, `tx_extra.h:45` |
| Where the tree reads `h_pqc` | `extract_leaf_hashes` parses `tx.extra`, finds the **single** `tx_extra_pqc_leaf_hashes` field (one `0x07` field, blob `N×32` in vout order), and returns it **only if** `blob.size() % 32 == 0`; `collect_outputs` then slices `blob + i*32`. **Falls back to 32 zero bytes** when: parse fails, the tag is absent, `blob.size() % 32 != 0` (malformed length → whole field dropped), **or** `i >= num_leaf_hashes` (blob present but shorter than vout count). | `blockchain_db.cpp:341-364` (`extract_leaf_hashes`, `zero_pqc` at `:332`), `tx_extra.h:45,219-228`, `FCMP_PLUS_PLUS.md:222-225` |
| Leaf branch on rct type? | **No.** `collect_outputs` uses one path for miner and normal txs; only `is_miner` changes maturity. | `blockchain_db.cpp:369-407` |
| Accepted rct types | Only `RCTTypeNull = 0` (coinbase) and `RCTTypeFcmpPlusPlusPqc = 7`. | `rctTypes.h:161-166`, `blockchain.cpp:3451-3456`,`1523` |

### 3.1 Replication obligation — `h_pqc` is on-chain, not recomputable

The load-bearing finding: **`h_pqc` cannot be recomputed from the bare public
output** — it is the hash of the *hybrid public key*, carried in `tx_extra`
`0x07`. The wallet's block-derived leaf builder **must parse `tx_extra` `0x07`**
(vout-indexed) for both coinbase and regular outputs, replicating the **exact**
`extract_leaf_hashes` semantics: validate `blob.size() % 32 == 0` (else treat
the whole field as absent → zeros), then per-output `h_pqc = i < num_leaf_hashes
? blob[i*32 .. i*32+32] : zeros`. This is a new S1-leaf input the block-derived
pipeline must thread; it was not in the spike prompt's `{O.x, I.x, C.x, h_pqc}`
description (which read as if `h_pqc` were derivable).

**Parser ownership — RESOLVED: reuse `shekyl_scanner::extra::Extra`.** The Rust
`tx_extra` parser already exists and **already decodes tag `0x07`**:
`ExtraField::PqcLeafHashes(Vec<u8>)` with accessor
`Extra::pqc_leaf_hashes() -> Option<&[u8]>`
(`rust/shekyl-scanner/src/extra.rs:40,60,98-101,146-148,226-233`). The
block-derived leaf builder **reuses this parser** and layers the
`extract_leaf_hashes` *post-parse* validation/slicing (`%32` check,
absent→zeros, per-output `i<N` slice) on top — no new `tx_extra` parser is
written (Shekyl-first reuse; dependency-discipline). One layering nuance for
CT-1: the new curve-tree crate either depends on `shekyl-scanner` for `Extra`
or `Extra`/`ExtraField` is factored to a lower shared crate; decided when the
crate skeleton lands, not pre-provisioned here. One parity nuance parked in Tier
B: the scanner's `Extra::read` breaks on the first unparseable field and returns
the prefix, whereas the daemon's `parse_tx_extra`-returns-false path drops to
zeros; this only diverges on a **crafted/malformed** extra (which needs a spend
to construct), so it rides Tier B's reversion with the malformed-length case.

### 3.2 Torsion in x-extraction — **resolved: not a divergence surface**

The Round-0 review raised a torsion concern (a crypto-careful wallet *adding*
cofactor-clearing the daemon omits, diverging from consensus). The source read
**clears it on two independent grounds**; it is recorded here so it is not
re-raised:

1. **The leaf primitive is shared, not reimplemented.** The daemon builds every
   leaf by FFI into the **same compiled Rust** the wallet uses:
   `shekyl_construct_curve_tree_leaf` (`rust/shekyl-ffi/src/lib.rs:2972,3002`)
   calls `shekyl_fcmp::tree::construct_leaf`, invoked daemon-side at
   `blockchain_db.cpp:401` and `blockchain.cpp:4335`. There is no second leaf
   implementation to diverge: x-extraction (`ed25519_point_to_selene_scalar`,
   `tree.rs:317-326`) runs the identical bytes through the identical code on
   both sides. The wallet's block-derived path is pinned to this primitive
   (`CURVE_TREE_CLIENT.md` §7.7, single-canonical-composition), so there is no
   site at which a "hygienic torsion clear" could be added unilaterally.
2. **`Hp(O)` is already torsion-free.** `construct_leaf` computes `Hp(O)` via
   `shekyl_curve_generators::biased_hash_to_point`, whose Elligator-2 map ends in
   `res.mul_by_cofactor()` — explicitly *"Ensure this point lies within the
   prime-order subgroup"*
   (`rust/shekyl-curve-generators/src/hash_to_point.rs:86`;
   `biased_hash_to_point` at `:111-112`). So `Hp(O)`
   carries no torsion, `O` is `is_torsion_free`-checked at output creation, and
   `C = zG + aH` lies in the prime-order subgroup by construction. No torsion
   enters the leaf, and even if a malformed on-chain `O` carried torsion, ground
   (1) makes daemon and wallet agree on its x byte-for-byte regardless.

**Consequence for the KAT.** There is **no engineered-torsion vector in §8** —
it would test nothing about S1/S2/S3 drain-order agreement (the divergence
surfaces are the *inputs* to `construct_leaf` — which `O`/`C`/`h_pqc`, in which
order — not the hash math inside it, which is shared). Leaf-builder *totality*
on adversarial points (decompress-failure → `None`, no panic) is a **CT-1
leaf-construction unit concern**, already approached by
`node_conversions_are_total`; it is not a CT-2 drain-order obligation. If a
future change ever forks the wallet's leaf construction off the shared primitive
(reversion criterion), the torsion concern reopens and a code-rule + engineered
vector become live.

### 3.3 Minor flag — coinbase type-by-position

`construct_miner_tx` relies on the `transaction` default (`set_null →
RCTTypeNull`) rather than explicitly assigning the type; genesis sets it
explicitly (`cryptonote_tx_utils.cpp:709`). Cosmetic, but the wallet must treat
a coinbase as `RCTTypeNull` by position (it is the miner tx), not by reading a
type field that may be defaulted.

---

## 4. S2 — drain trigger + batch ordering

Leaves enter the tree at maturity; an off-by-one shifts every later position.

| Question | Rule | Source |
|----------|------|--------|
| Drain trigger | **Inclusive** `maturity <= current_height`; the drain cursor breaks on `maturity > current_height`. | `db_lmdb.cpp:4940-4942`, `blockchain_db.h:1977-1984` |
| `current_height` | `prev_height + 1` (the block being connected); `prev_height = height()` before the connect. | `blockchain_db.cpp:290-329`, `414` |
| Stored maturity | `(prev_height+1) + N`. A leaf created at 0-indexed block `h` drains on connect of block **`h + N`** ⇒ `eligible_height = block_height + N`. | `blockchain_db.cpp:372-390` |
| `N` — regular | `CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE = 10`. | `cryptonote_config.h:51`, `transfer.rs:22-24` |
| `N` — **coinbase** | `CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW = 60` (**not 10**). | `cryptonote_config.h:47`, `shekyl_types.h:99-101` |
| `N` — staked | `max(block_height + shekyl_stake_lock_blocks(tier), block_height + 10)`. | `blockchain_db.cpp:387-390`, `FCMP_PLUS_PLUS.md:1025-1027` |
| Drain-then-grow order | Drain matured leaves **before** adding the current block's outputs to pending; then `grow_curve_tree`. | `blockchain_db.cpp:411-420` |
| Batch order (multi-drain) | Strictly **`(maturity ASC, global_output_index ASC)`**, enforced by composite key `BE(maturity) ‖ BE(output)` (16 B) + LMDB byte-order cursor scan. `DUPSORT` removed in DB v7 (was a consensus-nondeterminism bug). | `shekyl_types.h:111`,`137-148`, `db_lmdb.cpp:4937-4965`, `LMDB_SCHEMA.md:491-495` |
| Tree position at drain | `tree_pos = get_curve_tree_leaf_count() + count` (sequential tail append in drain order). | `db_lmdb.cpp:4928-4956` |

**Drain-trigger pin (the off-by-one).** `current_height = prev_height + 1` and
maturity is stored as `(creation_prev_height + 1) + N`, so the `+1` terms cancel:
an output created at 0-indexed block `h` has stored maturity `M`, and drains the
first time a block is connected with `current_height == M` — which is the
connect of 0-indexed block **`h + N`**. The unit tests assert exactly this
boundary: a maturity-50 leaf drains at `drain_pending_tree_leaves(50)` and not at
49 (`tests/unit_tests/deferred_insertion.cpp:95-130`). The wallet must drain
inclusively (`maturity <= height`), never one block early or late.

---

## 5. Genesis corners

| Corner | Rule | Source |
|--------|------|--------|
| Genesis creation | Generated when DB is empty; founder pool = genesis **coinbase** outputs (`build_genesis_coinbase_from_destinations`, `txin_gen`, `version=3`, `RCTTypeNull`, `unlock_time = 60`). | `blockchain.cpp:465-472`, `cryptonote_tx_utils.cpp:683-709`, `GENESIS_TRANSPARENCY.md:122-198` |
| Founder drain height | Height-0 coinbase ⇒ maturity `0 + 60 = 60`. A matured leaf enters the tree on connection of the *next* block (`drained_through = H − 1`), so the **first non-empty tree / first `R_0` material is at height 61**, not 10. (Pinned by the CT-2 KAT, `recon_kat::empty_window_then_first_drain_at_61`; supersedes this row's earlier "60" estimate.) | `blockchain_db.cpp:372-374` + coinbase rule above + CT-2 KAT |
| Empty-tree window | Heights **0..=60** have an empty tree. (No regular tx can exist earlier — spending needs a non-empty tree for FCMP membership, and the first spendable outputs are the founder coinbase maturing at 60, first visible at 61.) | derived from the two rows above + CT-2 KAT |
| **Small-tree root: leaf layer is never the root** | A non-empty tree of `1..=SELENE_CHUNK_WIDTH` leaves roots at the **single-child layer-1 Helios node**, not the layer-0 Selene leaf node: `grow_curve_tree` builds the Helios layer before its root-stop check. The wallet's `build_layers` reproduces this (every non-empty tree is depth ≥ 2). Pinned by the CT-2 KAT at height 61 (one leaf). | `db_lmdb.cpp` `grow_curve_tree`; `shekyl-fcmp::tree::build_upper_layers`; CT-2 KAT |
| **Empty-tree root** | `get_curve_tree_root()` returns **`selene_hash_init`** when no leaves (`MDB_NOTFOUND`); the genesis header is pre-set to `shekyl_curve_tree_selene_hash_init`. Distinguish empty via `get_curve_tree_leaf_count() == 0`. **NOT** `null_hash`, **NOT** all-zeros, **NOT** `build_layers([]) == [[]]`. | `db_lmdb.cpp:5909-5921`, `cryptonote_tx_utils.cpp:821`, `core_rpc_server.cpp:3875-3877` |
| `selene_hash_init` definition | `rejection_sampling_hash_to_curve(b"Monero Selene Hash Initializer")`, compressed (32 B). Computed at runtime via FFI; not inlined in C++. | `rust/shekyl-oxide/.../generators/src/lib.rs:157-159` |
| Genesis root check | Header-root verification is skipped at `new_height == 0` (`blockchain.cpp:4989-4990`). | `blockchain.cpp:4989-4990` |

**Resolution of the CT-0 boundary.** `empty_tree_is_a_ct2_boundary` asked which
of (init-valued node) vs (`build_layers([]) == [[]]` zero-node structure) the
daemon emits. **Answer: neither as a `build_layers` artifact — the daemon emits
the `selene_hash_init` point.** The wallet's reconstruct path therefore must:
`if leaf_count == 0 { root = selene_hash_init() }` and never index
`build_layers([])`. CT-2's KAT pins the **boundary**: `last_empty = 60` and
`first_drain = 61` (`recon_kat::empty_window_then_first_drain_at_61`), both
against `selene_hash_init` and the live header — not interior heights that
leave the off-by-one surface unasserted. Height **61** is the first non-empty
checkpoint (the founder allocation, maturity 60,
enters as tree position 0 — a single leaf wrapped into the layer-1 Helios
root per the small-tree convention above).

---

## 6. S3 — reorg drain reordering

On a tip reorg, orphaned outputs leave and new-chain outputs arrive at the
vacated positions.

| Question | Rule | Source |
|----------|------|--------|
| Index position stability | Global index = monotonic counter; pop removes only the popped block's outputs (`remove_transaction → remove_output` deletes the specific `output_id`), counter rolls back implicitly to the pre-tail value, re-apply **reuses** freed indices. Outputs at/below the fork keep their indices. | `blockchain_db.cpp:458-492`, `db_lmdb.cpp:1263-1298`,`3074-3093` |
| Curve-tree rollback | **Journal-driven**, 6 steps in `pop_block`, all in one write txn: read drain journal; if `drained_count > 0` remove mappings + `trim_curve_tree(drained_count)`; restore drained leaves to pending; remove drain journal; remove block's pending additions via `block_pending_additions` journal. | `blockchain_db.cpp:494-540` |
| Pending-only (never drained) | Removed from `pending_tree_leaves` via the `block_pending_additions` journal; **no tree mutation** (`drained_count == 0` skips trim). | `blockchain_db.cpp:534-540`, `db_lmdb.cpp:4910-4920` |
| Drained leaves | Trimmed via **incremental** `shekyl_curve_tree_hash_trim_selene` on the tail (O(removed·log N), not rebuild); restored to pending for potential re-drain. | `db_lmdb.cpp:5587-5738` |
| Depth split (shallow vs deep) | **No explicit `reorg_depth vs SPENDABLE_AGE` branch in C++.** The split is **emergent from journal membership**: a popped block with an empty drain journal ⇒ pending-only cleanup; a popped block with drain entries ⇒ trim. Equivalent to "deeper than maturity trims," but the wallet should replicate the **per-block-journal** form, not a depth comparison. | `blockchain_db.cpp:494-540`, grep: no depth branch |
| Survivor freeze | Leaves drained at **non-popped** blocks are untouched (frozen); only leaves drained at popped blocks are trimmed (`leaf_count − drained_count + j`). Re-drained leaves get **new tail** `TreePosition`s but the **same** `(maturity, gindex)` canonical order. | `blockchain_db.cpp:516-520`, `db_lmdb.cpp:4928-4956` |

**Carry to the wallet — S3 is not a distinct replication surface.** The freeze
property CT-0 proved at the node-hash layer holds at the index/drain layer: a
reorg churns only the tail. Combined with the **derive-don't-accumulate** rule
(§7), this collapses S3 entirely for the wallet. The journal-driven incremental
trim above is the **daemon's** path; it is the price the daemon pays for an
O(removed·log N) rollback against a persisted LMDB tree, and it is already
covered by CT-0 Tier-2 (the daemon's `hash_trim` ↔ the wallet's `build_layers`
agreement). The wallet has no persisted tree to surgically trim and **must not
replicate the journals**: its reorg is simply *"re-run S1+S2 on the post-reorg
chain and truncate-and-rebuild"* (`build_layers` on the surviving prefix,
`freeze_under_prefix_rebuild`). The surviving prefix is exactly the leaves
drained at non-popped blocks, in unchanged `(maturity, gindex)` order, so the
rebuilt prefix is byte-identical to the pre-reorg prefix and only the tail
changes.

Concretely: a wallet-side journal/trim replica would be **dead complexity** — it
re-derives, at much higher cost, a result that re-running S1+S2 produces for
free. Nobody should implement one. The KAT's reorg case (§8) is therefore not a
new code path under test; it is S1+S2 re-exercised on a different chain, with the
same reconstruct-root equality.

---

## 7. What this changes in the data flow

The block-derived wallet pipeline (Round 1 implementation) is:

1. For each synced block, run **S1** (assign global indices: coinbase-first,
   `tx_hashes` order, vout order).
2. For each indexed output, apply the **leaf-skip predicate** (§2.2:
   target-variant ∧ `i < outPk.size()` ∧ `construct_leaf`-ok); for included
   outputs run the **S1-leaf** builder: `O`, `C` from `outPk[i].mask`, `h_pqc`
   parsed via `shekyl_scanner::extra::Extra` from `tx_extra` `0x07` with the
   `extract_leaf_hashes` validation/slice (§3.1).
3. Register each leaf as pending with maturity `+10`/`+60`/staked.
4. At each connect height, **drain** inclusively (`maturity <= height`) in
   `(maturity, gindex)` order, appending to the leaf array.
5. Compute the root: `leaf_count == 0 → selene_hash_init()`, else
   **`build_layers` over the drained leaves** — the rebuild-from-leaves
   composition is the Round-1 oracle; the cached-`R_k` `build_upper_layers` hot
   path stays CT-1 (open question #5). A few-hundred-leaf coinbase chain rebuilds
   cheaply, so the monolith is the right tool for the KAT; do not build the
   cached hot path before the correctness baseline exists.
6. On reorg: truncate the leaf array to the surviving-drained prefix and rebuild
   (the wallet's pinned strategy; §6 carry).

Step 2's `tx_extra` parse and step 5's empty-root special case are the two new
obligations relative to the bulk-leaf RPC path (where the daemon hands the
wallet finished 128-byte leaves and a leaf count).

### 7.1 The derive-don't-accumulate rule (makes S3 free)

**Rule.** `gindex` (`global_output_index`) is **derived from cumulative chain
position on the current chain**, never carried in a stateful running counter.

This mirrors the daemon, which has **no persistent counter** (§2.1): `output_id`
is recomputed from `m_output_txs`, and a `pop_block` deletes the popped block's
outputs so their `output_id`s are *reused* by the replacement chain
(`blockchain_db.cpp:458-492`). A wallet that instead **accumulates** `gindex`
statefully (incrementing a counter as it scans forward) leaves the counter ahead
of the daemon's rolled-back-and-reused value after any reorg, and **every
post-fork position diverges** — silently, because the prefix still matches.

Deriving instead of accumulating makes the rollback cost nothing: there is no
counter to roll back. The wallet computes `gindex` for any output as a pure
function of (current chain, block height, intra-block position), so re-running
S1 on the post-reorg chain yields the daemon's reused indices by construction.
This is the implementation rule that turns §6's "S3 folds into S1/S2" from an
assertion into a property: with no accumulated state, S1/S2 re-execution *is* the
reorg handler.

---

## 8. The capstone obligation — the reconstruct-root KAT (the actual G2)

CT-2's deliverable is a KAT that runs the §7 replication over a chain exercising
**all three surfaces plus the genesis corner**, and asserts byte-equality at
each reference height:

> wallet-reconstructed `curve_tree_root` at reference height `H`
> **==** the C++ block-header `curve_tree_root` at `H`.

The chain must eventually exercise **all three maturity classes** (§4: `+10` /
`+60` / staked) plus a mixed-maturity collision and a deep reorg. But the cases
**split by a generation dependency** the enumeration did not flag (§8.1): some
need only coinbase blocks, the rest need a working **FCMP++ spend path**. The KAT
therefore lands in two tiers.

That capstone equality is what proves S1+S2+S3 are bit-exact and that
block-derived is sound. It is also where the **empty-tree root** and the
**undeepen drop-model** (CT-0 Tier 2) get pinned against **consensus**, not
self-consistency — closing the `empty_tree_is_a_ct2_boundary` obligation and the
Tier-2 "what Tier 2 does NOT verify" note in `CURVE_TREE_CLIENT.md` §7.7.

### 8.1 The fixture has a generation dependency: spend-path, not staking

A fixture is only as generatable as the chain it records. Two source reads pin
what is drivable **today**:

- **Coinbase outputs need no spend.** A regtest daemon mining empty blocks
  produces the founder coinbase (genesis, matures `+60`) and a coinbase-heavy
  stretch with no wallet involved.
- **Every non-coinbase leaf needs an FCMP++ spend.** A regular (`+10`) output
  exists only as the output of some transaction, and any non-coinbase tx spends
  a prior output — which needs an FCMP++ membership proof. This is the *same*
  structural argument that makes the empty-window 0..=60 structural (§5): no
  non-coinbase leaf can exist until spending works.
- **A staked output is a spend.** `wallet2::create_staking_transaction`
  (`wallet/wallet2.cpp:9974`) routes through `create_transactions_2` — it
  **spends** the staker's existing outputs into a `txout_to_staked_key`
  (`cryptonote_tx_utils.cpp:484`). Cleartext staking is **consensus-live from
  HF1** (`txout_to_staked_key`, tag `0x4`; `cryptonote_config.h:189`), so the
  staked class is **not** gated on Phase 2b — but minting one is gated on the
  spend path exactly like a `+10` output. *(This corrects the Gap-1 framing: the
  staked case is not "deferred pending staking ships"; staking has shipped. It
  is deferred pending the **send path**, in the same tier as Gap 2.)*
- **Reorg.** The production reorg engine (`switch_to_alternative_blockchain`,
  `blockchain.cpp:1316`) works; a regtest daemon can drive competing chains. A
  **coinbase-only** deep reorg (deep pop + alt coinbase chain) trims/re-drains
  `+60` leaves with no spend. A reorg whose churned span contains `+10`/staked
  leaves inherits the spend dependency.
- **In-process chaingen is not the generator.** `chaingen`'s FCMP++ tx
  construction was removed (`tests/core_tests/chaingen_main.cpp:106-110`) and its
  `TestDB` stubs the curve tree to no-ops (`chaingen.cpp:160-171`); the fork
  tests are disabled. So the recommended generator is a **real regtest daemon**
  (§8.3), which sidesteps chaingen entirely and is the only path that can build
  real spends/stakes/reorgs.

### 8.2 The two KAT tiers

**Tier A — coinbase-only, landable in Round 1 (no spend path required):**

- the **empty-window boundary** (`last_empty = 60`, `first_drain = 61`) —
  pins `recon[last_empty] == selene_hash_init` and
  `recon[first_drain] != selene_hash_init`, both consensus-anchored (§5);
- **height 61** — first non-empty checkpoint; the founder allocation (maturity
  60) drains as position `0`, a single leaf wrapped into the layer-1 Helios
  root (the first `R_0`);
- a **coinbase-heavy** stretch — every miner output drains at `+60` with on-chain
  `h_pqc` (§3); confirms coinbase leaf construction and the `+60` rule;
- **both reorg depths**, both coinbase-generatable, because §6's
  journal-membership split has two branches and a coinbase reorg reaches each by
  depth. A popped block `h`'s coinbase (maturity `h + 60`) has drained at tip
  `T` iff `h + 60 ≤ T − 1`, i.e. `h ≤ T − 61`, so:
  - a **deep coinbase reorg (≥ 61)** pops blocks whose coinbase **has drained**
    ⇒ the **trim** branch: tree leaves removed and re-drained, survivors frozen,
    indices position-stable by derive-don't-accumulate;
  - a **shallow coinbase reorg (< 61)** pops blocks whose coinbase is **still
    pending** ⇒ the **no-mutation** branch: `drained_count == 0`, the tree is
    untouched, only pending entries churn.
  The wallet's per-block-journal re-derivation must get **both** right (it folds
  to S1+S2 truncate-and-rebuild either way; §6, §7.1). No wallet journal replica
  under test;
- **enough length to freeze a segment.** Coinbase-only yields one leaf per
  block, so the chain must run far enough past 60 to complete at least one
  **level-0 subtree** (~38 leaves ⇒ ~height 100), ideally into a **level-1**
  segment, or there is no frozen `R_k` to content-address. A few hundred
  coinbase blocks suffice; the **level-2 shard size is not needed** — CT-0
  established the freeze mechanism is level-agnostic and settled on
  `LEVELS = [0,1]`, so the KAT inherits that and does not need the ~26k-block
  shard chain.

Tier A is generatable by a plain regtest daemon and validates the
block-derived path's structural core: empty-root special-case, `+60` coinbase
leaf, drain-trigger off-by-one, **both** S3 branches on coinbase leaves
(trim + no-mutation), and `R_k` content-addressing on a genuinely-frozen
level-0/1 segment. **This is the Round-1 KAT and the TDD oracle.**

**Tier B — spend-dependent, deferred pending the FCMP++ send path (2A):**

- a **multi-tx block** — S1 intra-block ordering (coinbase-first, `tx_hashes`
  order, vout order) and the batch `(maturity, gindex)` drain;
- the **`+10`/`+60` mixed-maturity collision** (Gap 2) — a single drain height
  where a `+10` normal output and a `+60` coinbase **from different source
  blocks** interleave by `gindex` (coinbase from 60 back, lower `gindex`, orders
  ahead of the normal output from 10 back, higher `gindex`). Sustained normal-tx
  activity past ~height 120 produces it; the KAT **asserts the interleaved
  order**. Catches a wallet sorting `gindex`-only or `maturity`-only — both pass
  Tier A and fail exactly here;
- a **staked output** (Gap 1, post-60) — the third maturity class,
  `N = max(block_height + shekyl_stake_lock_blocks(tier), block_height + 10)`
  (§4, `blockchain_db.cpp:387-390`), interleaving with `+10`/`+60` by
  `(maturity, gindex)`;
- a **reorg whose churned span contains `+10`/staked leaves** — S3 on the full
  leaf mix.
- **seam-parity: scanner `Extra` `0x07` extraction == daemon `parse_tx_extra`**
  on adversarial `tx_extra` — duplicate `0x07` tags, malformed/truncated tags,
  and tag ordering. The lean-crate split (CT-1) is faithful to the daemon's own
  two-stage structure: scanner `Extra` owns the **parse** stage (find the `0x07`
  blob), `shekyl-curve-tree::recon::extract_leaf_hashes` owns the **validate**
  stage (absent / `len % 32 != 0` → empty, slice). The validate half is mirrored
  and tested (CT-1); the **parse half's parity is unverified** and is the
  remaining seam obligation — scanner's `Extra::read` must extract the `0x07`
  blob byte-identically to `blockchain_db.cpp`'s `parse_tx_extra` +
  `find_tx_extra_field_by_type` (both return the **first** matching field; the
  parity question is malformed/duplicate/ordering behavior, not the happy path).
  A well-formed coinbase `tx_extra` (Tier A) never exercises it, and a crafted
  duplicate/malformed `tx_extra` needs a spend to construct, so it rides the same
  spend-dependent reversion as the malformed-length validate case (§9 #2). Until
  verified, the parse-stage assumption is: **scanner `Extra` is the sole parser
  and matches the daemon** — a silent divergence here shifts `h_pqc` per output
  and breaks every leaf.

Tier B's assertions are **written now** (the rule is enumerated and correct) but
**`#[ignore]`-gated** pending its fixture, so Gap 1/Gap 2 do not become false
Round-1 blockers. **Reversion criterion (`21-`):** the gate lifts when 2A's send
path can mint a regular (and staked) output on a regtest fixture; **re-evaluation
shape:** the deferred assertions un-ignore and run as a regression net (below).

**Acyclicity is load-bearing, not luck — the bootstrap spend is structurally
coinbase-only.** The founder allocations are coinbase and are the first and only
spendable outputs at height 60 (§5), so 2A's *first* spend necessarily proves
FCMP membership against a **coinbase-only tree**. Tier A is therefore not merely
"what a plain regtest daemon can generate without spends" — it is **exactly the
tree shape the bootstrap spend proves against**. That is why the chain Tier-A →
CT-core → 2A → Tier-B has no hidden cycle: 2A does not need full CT-2, it needs
the coinbase-tree correctness Tier A validates, because the first spend cannot be
anything but a coinbase spend. Once it lands and mints the first non-coinbase
outputs, Tier B becomes both generatable and meaningful. The genesis structure
and the dependency graph are the **same shape** — a sign the split is real and
not engineered.

**Tier B is the regression/completeness net, not what makes 2A work.** 2A
working is already a **coarse** CT-correctness signal on the spend path: a wrong
tree means the daemon **rejects** the spend (the membership proof fails against
the real `curve_tree_root`), so no Tier-B fixture even generates. Tier B is the
**fine-grained root-equality check layered on top of daemon-acceptance** — it
validates *more* (byte-exact per-height roots across the full leaf mix), but its
**absence does not hold 2A hostage**. The deferral is honest in both directions:
Tier B is not a 2A blocker, and 2A is not blocked on Tier B. The deferral is
**bounded by 2A** (when sends mint non-coinbase outputs) yet **not gating** it.

### 8.3 Source of the consensus root — checked-in fixture from a real daemon

Per-height roots are stored by the daemon
(`store_curve_tree_root_at_height(prev_height+1, ct_root)`,
`blockchain_db.cpp:436-437`) and exposed via RPC
(`core_rpc_server.cpp:3875-3877`). The source is a **checked-in fixture chain** —
`{block, header.curve_tree_root}` per height, **generated once from a real
regtest daemon run** and **replayed hermetically** in the KAT.

**Oracle hygiene — the header field is the source of truth.** The
**header-committed `curve_tree_root`** (per-block consensus commitment, what the
wallet's recomputed root must match) is recorded as truth, **cross-checked
against the `get_curve_tree_root` RPC** at generation time so the two are
confirmed equal (the RPC reads the stored per-height root; agreement proves the
fixture captures the consensus value, not an off-by-one). Note **height 0 is an
unverified constant** — the genesis header-root check is *skipped*
(`blockchain.cpp:4989-4990`, §5), so a height-0 assertion would test a
self-asserted value, not consensus. The meaningful empty-window assertion is
the **boundary** at `last_empty = 60` / `first_drain = 61` (both
consensus-verified), which pins the S2 drain trigger without leaving height 60
unasserted. A real daemon
(not in-process `chaingen`, §8.1) is required because only it can build the real
coinbase chain now (Tier A) and, once 2A ships, real spends/stakes/reorgs
(Tier B). This matches the determinism discipline (seeded, Guix-reproducible),
needs no running node in CI, and makes the KAT a **stable regression artifact**
rather than something that flakes on daemon availability. Generation is one-time
and out-of-band; CI only replays the fixture. The fixture is **additive**: the
Tier-A `{block, root}` vector lands in Round 1; the Tier-B heights append to the
same artifact when the send path can generate them.

---

## 9. Disposition of the framing corrections + Round-1 open questions

### Corrections landed (Round 1 close-out, 2026-06-06)

Cross-edits below are **done** — recorded here so §9 does not read as open work.
Authoritative close-out: [`CT2_ROUND1_CLOSEOUT.md`](../completed/CT2_ROUND1_CLOSEOUT.md).

1. **Coinbase `+60` / empty window 0..=60 — LANDED.** Founder coinbase matures at
   `+60` but enters the tree on the *next* block (`drained_through = H − 1`),
   so heights **0..=60** are empty and the first non-empty root is at height
   **61** (pinned by `recon_kat::empty_window_then_first_drain_at_61` at
   `last_empty=60` / `first_drain=61`). The regular-output `+10` rule is
   unchanged and correct. Prose aligned in this doc (§5, §8.2, §8.3) and
   `CURVE_TREE_CLIENT.md` §7.7.
2. **Empty-tree root = `selene_hash_init` — LANDED.** `CURVE_TREE_CLIENT.md`
   §7.7 now records the resolution: daemon emits `selene_hash_init` for
   `leaf_count == 0`; wallet special-cases empty tree; `build_layers([])` is
   **not** indexed for a root. KAT boundary pin at heights 60/61 (not interior
   heights). `empty_tree_is_a_ct2_boundary` in CT-0 remains the executable
   chunk-empty vs tree-empty distinction.
3. **`h_pqc` on-chain — LANDED.** `CURVE_TREE_CLIENT.md` §4.1 (Set A) documents
   block-derived `h_pqc` parsed from `tx_extra` `0x07` (public, parsed input,
   not `TransferDetails`). Parser ownership: `shekyl_scanner::extra::Extra`;
   validate stage: `recon::extract_leaf_hashes`. Scanner `0x07` unit tests
   landed; daemon adversarial parity deferred to Tier B (§8.2).

### Open questions for Round 1

1. **Leaf-skip predicate parity (§2.2) — RESOLVED at source.** The predicate is
   `(target ∈ {tagged_key, key, staked_key}) ∧ (i < outPk.size()) ∧
   (construct_leaf ok)` (`blockchain_db.cpp:355-409`); `gindex` is assigned to
   every vout regardless. Coinbase is trivially include-all (`outPk` populated,
   `cryptonote_tx_utils.cpp:156,179,709-743`), so Tier A under-exercises the
   skip with an empty skip set. The wallet **implements the real predicate**, not
   a hardcoded include-all. Remaining decision (deferred to Tier B): hard-error
   vs skip-match if a consensus-valid output the daemon did not leaf ever
   appears; default **skip-match**. Reversion criterion: a non-empty skip set on
   any real chain.
2. **`tx_extra` `0x07` parser ownership — RESOLVED: reuse
   `shekyl_scanner::extra::Extra`** (§3.1). It already decodes `0x07` →
   `PqcLeafHashes` with a `pqc_leaf_hashes()` accessor; the leaf builder layers
   the `extract_leaf_hashes` validation on top. No new parser (Shekyl-first
   reuse). Layering (curve-tree depends on scanner vs factor `Extra` lower) is a
   CT-1 crate-skeleton decision — **landed lean** (`shekyl-curve-tree` does not
   depend on scanner; the seam is parse-stage = scanner `Extra`, validate-stage =
   `recon::extract_leaf_hashes`, faithful to the daemon's own two-stage
   structure). The **validate** half's parity is mirrored and tested; the
   **parse** half's parity (scanner `Extra` `0x07` extraction == daemon
   `parse_tx_extra` on duplicate/malformed/ordered tags) is the **seam-parity
   Tier-B obligation** recorded in §8.2 — not closed by this resolution. The
   malformed-length / parse-rejection edge needs a crafted extra ⇒ a spend; the
   V3-genesis absent-fallback never fires, so Tier A under-exercises it for
   daemon-parity.
3. **Torsion in x-extraction — RESOLVED (§3.2).** Not a divergence surface: the
   leaf primitive is shared FFI (`construct_leaf`), and `Hp(O)` clears the
   cofactor (`hash_to_point.rs:86`). No engineered-torsion vector in the KAT;
   leaf-builder totality on adversarial points is a CT-1 unit concern. Reopens
   only if the wallet's leaf construction forks off the shared primitive.
4. **KAT root source — RECOMMENDED: checked-in fixture from a real regtest
   daemon (§8.3), NOT in-process `chaingen`** (chaingen lacks FCMP++ tx
   construction and stubs the curve tree — §8.1). Generated once, replayed
   hermetically. The fixture is **additive and two-tier (§8.2)**: Tier A
   (coinbase-only: empty / 60 / coinbase-heavy / coinbase-only reorg) lands in
   Round 1 as the TDD oracle; Tier B (multi-tx, `+10`/`+60` collision, staked,
   mixed reorg) is spend-path-dependent and appends when 2A can mint regular and
   staked outputs. Round 1 confirms the fixture format and the regtest generation
   script for Tier A.
5. **`build_upper_layers` factor (carried from CT-1).** The KAT computes the
   root from leaves via `build_layers`; the wallet's steady-state hot path
   computes it from cached `R_k` via `build_upper_layers`. CT-2 validates the
   from-leaves root; CT-1 must ensure the from-cached-`R_k` path calls the same
   `build_upper_layers` so the KAT's proof transfers.

---

## 10. Round-0 closure

The enumeration is complete: S1 (index assignment), S1-leaf (coinbase/`h_pqc`),
S2 (drain trigger + batch + empty root), S3 (reorg) are each pinned to source
with the genesis corners named. The two framing corrections (coinbase `+60`,
empty root = `selene_hash_init`) and the `h_pqc`-on-chain obligation are the
Round-0 findings that change the implementation shape.

The two Tier-A critical-path items are also resolved at source ahead of
implementation, so they do not surface as mid-build churn: the **leaf-skip
predicate** (§2.2, coinbase include-all confirmed via `outPk` population) and
**`tx_extra` `0x07` parser ownership** (§3.1, reuse `shekyl_scanner`'s `Extra`).
Round 1 implements §7 with `build_layers` and writes the §8 Tier-A KAT against a
real-regtest-daemon fixture; the §9 cross-edits land alongside.
