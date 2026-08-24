# The per-challenge pass record — design round (PC)

**Status:** **RULED 2026-08-24**, opened and ruled in the same sitting because
the ruling was made on the record before the round existed and this document is
its transcription. `PC-D1`…`PC-D7` ruled; implementation lands in this round's
PR, not a later one.

**Process:** [`26-sub-pr-design-discipline`](../../.cursor/rules/26-sub-pr-design-discipline.mdc),
and **[`07-consensus-atomic-cutovers`](../../.cursor/rules/07-consensus-atomic-cutovers.mdc)
is opted into**: this changes an admission path in place, on a genesis-frozen
wire. Disposition IDs **`PC-D1` … `PC-Dn`**, registered at birth per
[`94-tracking-index`](../../.cursor/rules/94-tracking-index.mdc); prefix `PC-`
checked unique against CB/CR/CT/CW/DS/GF/LV/MR/MS/MSW/OA/PF/PR/RF/RP/SA/SH/SO/
SP/TJ/VG/WI/WP/WS.

**Freezes:** the serve-credit vin layout, the leaf-index derivation, and the
admission uniqueness key. All three are pre-genesis-frozen; a wrong byte is
permanent. This is the design-first category by the standing rule, which is why
it is a round rather than a commit.

---

## 1. The finding, and why a counter cannot answer it

2-of-3 settlement needs consensus to know how many of a pair's three challenges
passed. The reflex is a count on the record.

**A count on the record is forgery.** Whoever writes the record chooses the
number: write `3`, settle `Served`, with one read performed or none. That is
`RF-D8`'s criterion word for word — *a value the verifier derives locally must
not be transported, because transporting it lets the prover choose it* — and it
is the identical defect as a supplied `R_k` or a supplied leaf index, which
`RF-D6`/`RF-D8` already refused on exactly these grounds. It is refused here on
the same grounds. **No tally field, ever.**

**But the count was never supposed to be on the record.** Three challenges are
three separate events in three separate blocks, each already in the attestation
path, each nonce-bound to its own block. Consensus counts them by **enumerating
the blocks of the epoch and counting the attestations it finds** — which is what
`SO-D1`'s enumerate-and-write writer already does. Nobody writes a number; the
chain is the number.

That is unforgeable in a way no field can be: to claim three passes you must
produce three blocks each carrying a witness-signed attestation naming you, and
each of those signatures binds to a block you do not control.

### 1.1 The consequence that reverses the record's granularity

If the count cannot be a field, then **the record cannot be per-epoch** — because
"per-epoch" means one artifact standing for three events, and the only way to
express three-in-one is the count just refused. So the record is **per-challenge**.

---

## 2. Verified at source: the current wire cannot express this at all

Grounded on `dev@863a9bf4f`, 2026-08-24.

**The record has no block.** `ArchivalServeCreditResponse` is
`{p_canonical_id, shard_id, settlement_epoch, ed25519_countersignature}`
(`wire.rs:59`). It is structurally keyed per-`(P, s, E)`. There is no way to
represent two distinct challenges for one pair-epoch, and the old-vin dedup
(`blockchain.cpp:5307`) would reject the second as a duplicate of the first.

**The leaf index cannot vary per challenge.** `challenge_leaf_index`'s preimage
is `p_id ‖ shard_id_le ‖ settlement_epoch_le` (`challenge.rs:68`). For a given
`(P, s, E)` the index is a **constant**.

### 2.1 The asymmetry that makes this easy to miss

`RF-D5` already made the attestation nonce
`H(block_hash(h−1) ‖ cb_out_key ‖ P ‖ s ‖ E)` — **block-bound**. The opening is
not.

So three per-challenge records under today's derivation would carry three
**genuinely distinct countersignatures** and three **identical openings**. The
signatures would look like three events; the work would be one. A prover that
fetched one leaf once satisfies all three, and every signature verifies.

That is worse than "proves nothing per-challenge": **it is an artifact that
looks like three tests and contains one.** Half the record varies per block and
half does not, and the varying half is exactly what makes the constant half easy
to miss — **a reviewer checking "do these three records differ?" sees yes and
stops.** That is the hazard this round exists to close, and it is stated first
because it is the one a careful reader would otherwise walk past.

---

## 3. The ruling

### `PC-D1` — no tally field on the wire, ever

Any field a prover populates that consensus then consumes is prover-chosen.
Refused under `RF-D8`'s criterion. Stated as a standing prohibition rather than a
decision about one field, because the next person who needs a number on a record
will reach for the same shape.

**Scope — the wire/local split, stated so the rule is not over-applied.** This
governs **transported** values. It does not reach a value the verifier derives or
counts locally and stores in its own LMDB; that is the *endorsed* side of
`RF-D8`, whose own resolution was "the verifier reads it from its own LMDB".
`SO-D2`'s settlement row keeps `passes` and `issued` for exactly that reason —
node-computed from chain state, never transported, one enforcing writer, the same
argument that makes its `outcome` byte safe. **This round makes that row more
correct, not less: a local materialisation is the only place a count is safe.**

### `PC-D2` — the block is **implicit**: the record rides its own producer's block

**The miner that closes the block issues the challenge.** There is no thundering
herd to arbitrate and never was, so the witness for a challenge is the producer
of the block the challenge belongs to — and the record rides that producer's
block.

That makes the block **unforgeable without carrying it**, the same property the
attestation path already gets for free:

- Nothing goes on the wire. **`ArchivalServeCreditResponse`'s fields do not
  move.**
- There is no claimed block for admission to validate, because there is no
  claim — consensus reads the block it is already validating.
- **There is no path where a record names a block it did not come from.** Not
  "a check rejects it": the state is unrepresentable.

**The alternative was considered and is strictly worse.** Broadcasting records
for any miner to include requires carrying the block, admission verifying the
claim, and a rule for what makes a claimed block legitimate — more wire, more
surface, and a new forgery axis, to buy flexibility the mechanism does not need.
Cheaper *and* more robust is not a trade, so this is ruled rather than balanced.

### `PC-D3` — `challenge_leaf_index` takes `block_hash(h−1)`

The preimage gains the **hash**, not the height.

**Height and hash are not equivalent and the difference is the ruling.** A height
is a *reference* a reorg can silently repoint at a different block; a hash
*names* the block. And the nonce already binds `block_hash(h−1)` and
`cb_out_key` (`RF-D5`), so taking the same term keeps the record with **one**
block reference. A second, weaker reference could disagree with the first — and
a record carrying two references that can diverge is a record with a state
nobody has reasoned about.

Chosen deliberately rather than by picking the field that serializes smaller;
under `PC-D2` nothing serializes at all, so size was never the axis.

**Domain separator bumps** to `shekyl/archival-serve-challenge-leaf-v2` (rule
30). The derivation changed; leaving the label would let two implementations
disagree silently on a value feeding the signature preimage. Pre-genesis there is
no migration — the bump exists so one label never names two functions.

### `PC-D4` — the ledger key widens to `(P, s, E, block)`

This is where consensus stores the enumeration `PC-D5` counts. Under `PC-D2` the
block is the including block, so the key means **one record per producer per
pair-epoch**: a producer cannot submit two for the same pair in one block, and
cannot submit for a block it did not produce.

**The old-vin dedup at `blockchain.cpp:5307` becomes the uniqueness enforcer**
under the widened key. A duplicate is then not a double-count some check must
catch — it is the same key, refused by the structure.

### `PC-D5` — consensus counts by enumeration

`passes(P, s, E)` is the number of admitted records for that pair-epoch, counted
by walking them. No field carries a tally anywhere on the wire.

### `PC-D6` — the four readers must be taught what three rows mean, and the gather explicitly

**This is the round's largest surface and its highest-risk change.** Widening the
key changes a table with four readers — the vin dedup, the slash-window walk, the
fast-path miss check, and the emission gather.

**The gather is the one that cannot be left to infer.** It cursor-walks the table
and pushes one `credit_pairs` entry **per row** (`db_lmdb.cpp:7978`, no
value-byte gate). Three keys where it expects one **triples `credit_pairs` and
inflates `r_market` — silently, with no error and no test failing** unless a test
asserts the fold.

So the gather **folds the enumeration back to one credit per pair-epoch, and the
fold is written explicitly** rather than emerging from the key order. This is the
same shape as `SO-D1`'s enumerate-and-write: consensus counts by enumeration, and
whoever consumes the enumeration states how it collapses.

**This is `CR-D2`'s four-reader problem arriving through the key rather than the
value** — recorded that way because the class is what makes it findable next
time, not the instance.

**Payment stays per-pair-epoch**, which the fold is what preserves. Three passes
credit a pair once. No economic disposition opens — but note it is now preserved
*by the fold* rather than by the key, so the fold is load-bearing and gets a test
that fails if it is removed.

### ~~`PC-D7`~~ — COLLAPSED by `PC-D2`

The opening draft had admission verify that a record's claimed block was a real
assignment. **Under `PC-D2` there is no claimed block**, so there is nothing to
verify and no disposition to hold: the record arrives in the block that produced
it, and consensus reads that block directly.

Recorded as collapsed rather than deleted, because it was carried as a rule-22
blocker against `SO-D8`'s cutover and that dependency is now discharged — the
round no longer waits on the urn for its soundness.

## 4. What this costs — and the cost was already priced

Three openings instead of one, at ~1,920 B each.

**That is the price already on the record.** `ARCHIVAL_SETTLEMENT_WRITER.md`
§2.1 computed block occupancy as `k = 3·D/SEB` — challenges per block, one
record each, at 5,204 B per record. It already assumed per-challenge records.
**The per-epoch reading would have been cheaper than what was priced, not
dearer**: it would have been one record per pair-epoch, a third of the budgeted
volume, because it was doing a third of the testing.

So §2.1's figures stand unchanged — ~10 KB/block at genesis `D ≈ 4,096`, 156 KB
at `D ≈ 100 k`, ~506 KB at `D ≈ 324 k` against a 300 KB penalty threshold. No
re-derivation is owed, and the honest price is the one already carried.

---

## 5. Blast radius — everything this touches

Enumerated at source before implementation, per rule 26's substrate pass.
**`PC-D2` emptied the wire column and `PC-D6` filled the schema one** — the work
moved from serialization to the four readers.

**Does NOT change (and this is the round's main saving):** the vin layout,
`ArchivalServeCreditResponse`'s fields, `canonical_bytes`' length, the pruned
half, `SERVE_CREDIT_PRUNED_MAX_BYTES` and its pinned twin, and — because no
persisted block byte moves — **rule 42 does not fire and no version constant
bumps.** Each was on the opening draft's list and each comes off with the block
going implicit. Recorded so nobody re-adds a schema bump "to be safe": a bump
with no wire change is a false signal that costs the next reader a grounding
pass.

| # | Site | Change |
|---|---|---|
| 1 | `challenge.rs::challenge_leaf_index` | preimage gains `block_hash(h−1)`; separator → `-v2` |
| 2 | `wire.rs::signature_preimage` | binds the index derived from the including block |
| 3 | `serve_credit.rs` (FFI) | derives the index with the block hash it is validating; verifies the opening against it |
| 4 | `shekyl_ffi.h` + `blockchain.cpp:5412` | `shekyl_archival_challenge_leaf_index` signature widens by the hash |
| 5 | **`m_archival_serve_credit` key 48 → 56 B** | `(P, s, E)` → `(P, s, E, block)` — the schema change `PC-D6` is about |
| 6 | `blockchain.cpp:5307` old-vin dedup | becomes the uniqueness enforcer under the widened key |
| 7 | **Emission gather (`db_lmdb.cpp:7978`)** | **folds rows → one `credit_pairs` per pair-epoch, explicitly** — the silent-inflation site |
| 8 | Slash-window walk (`db_lmdb.cpp:5763`) | reads "served" as a count over the widened key, not key-presence |
| 9 | Fast-path miss check (`db_lmdb.cpp:5793`) | same |
| 10 | `delete_archival_serve_credit_before_epoch` | epoch field moves within the key; the prune's offset moves with it |
| 11 | Block-level SCE-1 uniqueness pass | widened key — per-challenge multiplies vins per tx |
| 12 | `gate2_serve_credit_kat.rs` | fixtures gain the block hash in the index derivation |
| 13 | `serve_credit_tx_parity.rs` | **re-anchors only if the preimage changes its bytes** — verify; the vin itself does not move |
| 14 | `failure_window.rs`, `attestation_settlement_window.rs` | confirm they consume the settlement-table shape, not raw record presence |
| 15 | `SO-D1`'s writer | its `passes` is this round's enumeration — the two rounds meet here |
| 16 | `ArchivalServeCreditKey` (`shekyl_types.h`) | 48 → 56 B, and **`SO-D2`'s settlement key rides it** — see §5.2 |

### 5.1 Interaction with `SO-D8`

`SO-D8` (cross-epoch admission: a response naming `E` landing in `E+1`) becomes
**per-challenge rather than per-epoch** — same boundary, finer grain. Under
`PC-D2` it also sharpens: since the record rides its producer's block, a
challenge issued in the epoch's last `W₂` blocks is a record whose *including*
block is past the credit deadline. It does not resolve `SO-D8`; the cutover round
inherits the finer statement.

### 5.2 The consequence for `SO-D2` that must not be missed

`SO-D2` ruled the settlement key **byte-identical to `ArchivalServeCreditKey`**
so one key probes both tables. That key now widens to 56 B — but the settlement
table is **per-pair-epoch by design** (`SO-D1`: one row per pair with
`issued ≥ 1`), so it must **not** widen with it.

So the two keys stop being the same shape, and `SO-D2`'s "one key probes both
tables" rationale expires. That is a **retired justification, not a defect**: the
tables now answer questions at different granularities — evidence per challenge,
verdict per pair-epoch — which is exactly the split `PC-D6` draws. The settlement
key keeps `(P, s, E)` and stops borrowing `ArchivalServeCreditKey`.

**Landed code affected:** `BlockchainLMDB::set_archival_settlement` /
`get_archival_settlement` / `delete_archival_settlement_for_epoch` currently
build `ArchivalServeCreditKey` (PR #554). They need their own 48-byte key type
once that key widens. Flagged here because #554 is open and merges first;
whoever lands this round owns the follow-through.
