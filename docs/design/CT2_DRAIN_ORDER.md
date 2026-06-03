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
   genesis **coinbase** outputs, so they drain at height **60**, and the
   empty-tree window is heights **0..59**, not 0..9. The spike prompt and
   `CURVE_TREE_CLIENT.md` §8 #/early-height prose said "drain at 10 / empty
   0..9"; that is wrong for coinbase. Corrected here and to be cross-edited.
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

### 2.2 Divergence surface — leaf-set ⊆ indexed-set (FLAG for Round 1)

`collect_outputs` advances `next_output_seq++` for **every** vout, but **skips
pending-leaf registration** (`continue`) when any of:

- output target ∉ {`txout_to_tagged_key`, `txout_to_key`, `txout_to_staked_key`};
- `i >= tx.rct_signatures.outPk.size()`;
- `shekyl_construct_curve_tree_leaf(...)` returns false.

Source: `blockchain_db.cpp:369-407`. Consequence: a consensus-valid output can
hold a global index **without** a tree leaf, so `global_index → tree_position`
is not surjective in general. Under v3 rules all outputs are tagged/staked keys
with `outPk`, so the skip set is expected empty — **but the wallet's
reconstruction must apply the identical skip predicate, not assume every indexed
output is a leaf.** The KAT (§8) confirms emptiness on the test chain; the
predicate is replicated regardless. No separate consensus check forces leaf
construction to succeed, so this is the surface most likely to bite if the
wallet's leaf builder and the daemon's disagree on a malformed-but-valid output.

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
| Where the tree reads `h_pqc` | `collect_outputs` reads it from the parsed `0x07` blob at `i*32`; **falls back to 32 zero bytes only if the tag is absent** (legacy/pre-tag outputs). | `blockchain_db.cpp:362-364` (`zero_pqc` at `332`), `FCMP_PLUS_PLUS.md:222-225` |
| Leaf branch on rct type? | **No.** `collect_outputs` uses one path for miner and normal txs; only `is_miner` changes maturity. | `blockchain_db.cpp:369-407` |
| Accepted rct types | Only `RCTTypeNull = 0` (coinbase) and `RCTTypeFcmpPlusPlusPqc = 7`. | `rctTypes.h:161-166`, `blockchain.cpp:3451-3456`,`1523` |

### 3.1 Replication obligation — `h_pqc` is on-chain, not recomputable

The load-bearing finding: **`h_pqc` cannot be recomputed from the bare public
output** — it is the hash of the *hybrid public key*, carried in `tx_extra`
`0x07`. The wallet's block-derived leaf builder **must parse `tx_extra` `0x07`**
(vout-indexed) for both coinbase and regular outputs, applying the **exact**
zero-fallback rule when the tag is absent. This is a new S1-leaf input the
block-derived pipeline must thread; it was not in the spike prompt's
`{O.x, I.x, C.x, h_pqc}` description (which read as if `h_pqc` were derivable).

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
   `shekyl_generators::biased_hash_to_point`, whose Elligator-2 map ends in
   `res.mul_by_cofactor()` — explicitly *"Ensure this point lies within the
   prime-order subgroup"*
   (`rust/shekyl-oxide/shekyl-oxide/generators/src/hash_to_point.rs:86`;
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
| Founder drain height | Height-0 coinbase ⇒ maturity `1 + 60 = 61` ⇒ drains on connect of 0-indexed block **60**. **First non-empty tree / first `R_0` material is at height 60**, not 10. | `blockchain_db.cpp:372-374` + coinbase rule above |
| Empty-tree window | Heights **0..59** have an empty tree. (No regular tx can exist earlier — spending needs a non-empty tree for FCMP membership, and the first spendable outputs are the founder coinbase maturing at 60.) | derived from the two rows above |
| **Empty-tree root** | `get_curve_tree_root()` returns **`selene_hash_init`** when no leaves (`MDB_NOTFOUND`); the genesis header is pre-set to `shekyl_curve_tree_selene_hash_init`. Distinguish empty via `get_curve_tree_leaf_count() == 0`. **NOT** `null_hash`, **NOT** all-zeros, **NOT** `build_layers([]) == [[]]`. | `db_lmdb.cpp:5909-5921`, `cryptonote_tx_utils.cpp:821`, `core_rpc_server.cpp:3875-3877` |
| `selene_hash_init` definition | `rejection_sampling_hash_to_curve(b"Monero Selene Hash Initializer")`, compressed (32 B). Computed at runtime via FFI; not inlined in C++. | `rust/shekyl-oxide/.../generators/src/lib.rs:157-159` |
| Genesis root check | Header-root verification is skipped at `new_height == 0` (`blockchain.cpp:4989-4990`). | `blockchain.cpp:4989-4990` |

**Resolution of the CT-0 boundary.** `empty_tree_is_a_ct2_boundary` asked which
of (init-valued node) vs (`build_layers([]) == [[]]` zero-node structure) the
daemon emits. **Answer: neither as a `build_layers` artifact — the daemon emits
the `selene_hash_init` point.** The wallet's reconstruct path therefore must:
`if leaf_count == 0 { root = selene_hash_init() }` and never index
`build_layers([])`. CT-2's KAT hits an early height (e.g. 5 and 59) to pin this
against the live header, and height **60** as the first non-empty checkpoint
(founder allocations drain in `(maturity, gindex)` order as tree positions
`0..N`).

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
2. For each indexed output, run the **S1-leaf** builder: `O`, `C` from
   `outPk[i].mask`, `h_pqc` **parsed from `tx_extra` `0x07`** (zero-fallback if
   absent), applying the **leaf-skip predicate** (§2.2).
3. Register each leaf as pending with maturity `+10`/`+60`/staked.
4. At each connect height, **drain** inclusively (`maturity <= height`) in
   `(maturity, gindex)` order, appending to the leaf array.
5. Compute the root: `leaf_count == 0 → selene_hash_init()`, else
   `build_layers` / `build_upper_layers` over the drained leaves.
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

The test chain must exercise **all three maturity classes** (§4 documents
`+10` / `+60` / staked) and a mixed-maturity drain collision, not just the two
maturity classes the early draft hit. It must include:

- an **early/empty height** (e.g. 5 and 59) — pins the empty-tree root =
  `selene_hash_init` against the live header (§5);
- **height 60** — first non-empty checkpoint; founder allocations drain as
  positions `0..N` (the first `R_0`);
- a **coinbase-heavy** stretch — every block's miner output drains at `+60` with
  on-chain `h_pqc` (§3); confirms coinbase leaf construction and the `+60` rule;
- a **multi-tx block** — confirms S1 intra-block ordering (coinbase-first,
  `tx_hashes` order, vout order) and the batch `(maturity, gindex)` drain;
- **at least one staked output** (post-60, since staking also needs a non-empty
  tree for its membership proof) — exercises the **third maturity class**:
  `N = max(block_height + shekyl_stake_lock_blocks(tier), block_height + 10)`
  (§4, `blockchain_db.cpp:387-390`). The staked leaf drains at a tier-dependent
  height (1,000 / 25,000 / 150,000 blocks) and interleaves with `+10`/`+60` by
  `(maturity, gindex)` like any other leaf. Without this the KAT proves only two
  of three classes the drain path handles;
- a **mixed-maturity drain collision** — the case where *tree-position ≠ gindex*
  actually bites, which "coinbase-heavy" (coinbase-only, no interleaving) and
  "multi-tx block" (intra-block gindex, not cross-source-height order) do **not**
  produce. Engineer a single drain height where a `+10` normal output and a
  `+60` coinbase **from different source blocks** mature together: the coinbase
  from 60 blocks back (lower `gindex`) must order **ahead of** the normal output
  from 10 blocks back (higher `gindex`). Sustained normal-tx activity past
  ~height 120 produces this naturally; the chain must carry a stretch with it and
  the KAT must **assert the interleaved order**. This is the case that catches a
  wallet sorting `gindex`-only (ignores maturity) or `maturity`-only
  (mis-orders within a maturity) — both pass every other bullet and fail exactly
  here;
- a **reorg deeper than `SPENDABLE_AGE`** (and one shallower) — confirms S3
  *folds into S1/S2* (§6, §7.1): survivors frozen, tail re-drained via
  truncate-and-rebuild, indices position-stable by derive-don't-accumulate, and
  the pending-vs-drained split. No wallet journal replica is under test.

That single equality is what proves S1+S2+S3 are bit-exact across all three
maturity classes and that block-derived is sound. It is also where the
**empty-tree root** and the **undeepen drop-model** (CT-0 Tier 2) get pinned
against **consensus**, not self-consistency — closing the
`empty_tree_is_a_ct2_boundary` obligation and the Tier-2 "what Tier 2 does NOT
verify" note in `CURVE_TREE_CLIENT.md` §7.7.

**Source of the consensus root for the KAT — recommendation: a checked-in
fixture chain.** Per-height roots are stored by the daemon
(`store_curve_tree_root_at_height(prev_height+1, ct_root)`,
`blockchain_db.cpp:436-437`) and exposed via RPC
(`core_rpc_server.cpp:3875-3877`). The recommended source is a **checked-in
fixture chain** — `{block, header.curve_tree_root}` per height, **generated once
from a real daemon run** (the chain engineered to carry all three maturity
classes + the §8 collision + a deep reorg) and **replayed hermetically** in the
KAT. This is preferred over a live-daemon/regtest dependency in CI: it matches
the determinism discipline (seeded proptest, Guix-reproducible builds — `30-` /
testing rules), needs no running node, and makes the KAT a **stable regression
artifact** rather than something that flakes on daemon availability. The
generation step is one-time and out-of-band; CI only replays the fixture. (An
in-process `BlockchainDB` over the fixture is a viable generator, but the
checked-in `{block, root}` vector is the artifact CI consumes.)

---

## 9. Disposition of the framing corrections + Round-1 open questions

### Corrections to land (cross-edits, not silent)

1. **Coinbase `+60` / empty window 0..59.** `CURVE_TREE_CLIENT.md`'s
   early-height prose (§8 #7 area and the §7.7 "heights `0..SPENDABLE_AGE`"
   line) says founder allocations drain at `SPENDABLE_AGE = 10`. They are
   coinbase ⇒ `+60`. Cross-edit `CURVE_TREE_CLIENT.md` to "heights 0..59 empty;
   founder drains at 60." (The regular-output `+10` rule is unchanged and
   correct; the error is specifically the founder/coinbase case.)
2. **Empty-tree root = `selene_hash_init`.** Update the
   `empty_tree_is_a_ct2_boundary` resolution in `CURVE_TREE_CLIENT.md` §7.7 from
   "open, verified in CT-2" to "**resolved: daemon emits `selene_hash_init`**;
   wallet special-cases `leaf_count == 0`; KAT confirms at an early height." The
   `build_layers([]) == [[]]` structure is **not** a root and must never be
   indexed for one.
3. **`h_pqc` on-chain.** Add to `CURVE_TREE_CLIENT.md` §4 (Set A) that the
   block-derived path's leaf input includes `h_pqc` parsed from `tx_extra`
   `0x07` — it is public (already on-chain), so it joins Set A, but it is a
   *parsed* input, not a `TransferDetails` field. (Bulk-leaf path is unaffected:
   the daemon hands finished leaves.)

### Open questions for Round 1

1. **Leaf-skip predicate parity (§2.2).** Confirm via the KAT that the skip set
   is empty on a v3 chain, and decide whether the wallet hard-errors or
   skip-matches if it ever sees a consensus-valid output the daemon did not make
   a leaf. Reversion criterion: a non-empty skip set on any real chain.
2. **`tx_extra` `0x07` parser ownership.** Does the block-derived path reuse the
   C++ `tx_extra` parse via FFI, or a Rust `tx_extra` parser
   (`shekyl-oxide`)? Dependency-discipline check at Round 1.
3. **Torsion in x-extraction — RESOLVED (§3.2).** Not a divergence surface: the
   leaf primitive is shared FFI (`construct_leaf`), and `Hp(O)` clears the
   cofactor (`hash_to_point.rs:86`). No engineered-torsion vector in the KAT;
   leaf-builder totality on adversarial points is a CT-1 unit concern. Reopens
   only if the wallet's leaf construction forks off the shared primitive.
4. **KAT root source — RECOMMENDED: checked-in fixture chain (§8).** Generated
   once from a real daemon run, replayed hermetically; no live-daemon CI
   dependency. Round 1 confirms the fixture format and generation script.
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
Round-0 findings that change the implementation shape. Round 1 implements §7 and
writes the §8 KAT; the §9 cross-edits land alongside.
