# Archival credit wire — TJ-B step 3 (design round, OPENED 2026-08-03)

**Status:** **Round opened.** Framing + grounding + decision structure. No wire
byte-layout is pinned yet; the gating decision (record format + field residence,
§3) is posed, not resolved.

**Scope.** The consensus wire that replaces the leaf-opening serve-credit vin
with the miner-attested, `P`-countersigned whole-shard read ruled across the TJ
round (`ARCHIVAL_TEST_EQUALS_JOB_SEQUENCING.md`; rulings summarised in
`FOLLOWUPS.md` under the seal-deletion / mandate / miss-fact entries). This is
**step 3 of the finalized TJ-B order** (1 = countersignature binding, 2 =
set-size pin, both settled; 3 = deletion surface + credit wire).

**Authority chain.** The mechanism is already ruled; this round only turns
rulings into bytes:

| Ruling (elsewhere) | What it fixes for the wire |
|---|---|
| Miner-chosen set, coinbase-revealed | The attester is the block producer; no schedule, no beacon |
| Block-bound nonce `H(r ‖ cb_out_key ‖ P ‖ s ‖ E)` | The record's authenticity binds to *this* block's coinbase |
| Non-transferable / self-crediting killed | Verify must recompute the nonce, never trust a carried one |
| Miss fact (three-valued) | The record carries a pass/miss discriminant; "neither" is off-wire |
| Coinbase-output-key uniqueness (epoch-windowed) | A consensus check the wire's verify path must invoke |
| Prunable residence | Header kept; 3.43 KB countersignature on the coinbase-tx prunable side |

---

## 1. Two items remain in the whole TJ programme

**Small — the SP-T3 effort ceiling (derivable, not a measurement).** Pin
`(effort_ceiling, give-up→miss semantics)` in a band between "solve-at-ceiling
still fits `r·solve < W`" (the PoW rig measured `solve@67 ≈ 0.19 s`, negligible;
`FOLLOWUPS` SP-T3 entry) and "high enough that ambient `λ_eff ≈ 3`/epoch never
trips it." The give-up state already has a home — it files the
empty-countersignature **miss** record (this wire, §3), and pass-priority
contains it — so this is one afternoon's arithmetic plus a config pin, tracked
but **not** this round.

**Large — this round.** The credit wire. Everything upstream is a ruling about
the mechanism; **none of it is a wire yet.**

---

## 2. What is being deleted, precisely (grounded)

The current credit path is an **FCMP++ leaf-membership proof**: `P` proves it
holds a specific *challenged leaf* in the shard's segment tree.

- **Vin payload** — `ArchivalServeCreditResponse` (`wire.rs`): `p_canonical_id`,
  `shard_id`, `settlement_epoch`, `segment_subroot_rk`, `leaf_index_in_segment`,
  `leaf_bytes[128]`, `path: SegmentPathOpening`, `hybrid_signature`.
- **Verify** — `shekyl_archival_verify_serve_credit_vin` (`archival_ffi.rs:572`):
  checks the path opening against `leaf_layer_scalars` (the Selene leaf-layer
  chunk in the verify ctx) and the signature. Bond posture / market /
  idempotency are C++-side.
- **Deletion surface** (removed in the *same* change that adds the replacement —
  §5): `challenge_leaf_index`, `challenge_fire_height`, `challenge_seal_height`
  (`challenge.rs`); `SegmentPathOpening`, `verify_segment_path`,
  `leaf_bytes_in_layer`, `leaf_layer_scalars` marshalling (`path.rs`); the gate-2
  KATs that exercise them; and the vin type/tag itself.

The old model asks `P` to prove *possession of one leaf at a scheduled index*.
The new model asks a *miner* to attest it *read the whole shard from `P`*, with
`P`'s countersignature proving the read reached `P`'s link. Leaf
parameterisation, the fire schedule, and the path opening all go away
(item 1 of the TJ round already ruled the read is a bulk read with no viable
leaf parameterisation).

---

## 3. THE GATING DECISION — record format + field residence

The scan (§4) and the deletion (§5) both key off *what the record is*, so this
is decided first. **Two standing principles drive the shape to its floor
(maintainer, 2026-08-03): derive rather than store wherever recompute is
possible, and minimise floating stateful objects (each is a crash/dump/
manipulation surface).** Applied hard, they collapse most of a first draft:

- **The settled three-valued bit is NOT stored** — it is a pure fold over epoch
  `E`'s records (pass-priority, §4), recomputable from chain data, so it is not
  a maintained object at all.
- **The `transfer_digest` is NOT a field** — the countersignature covers
  `H(nonce ‖ transfer_digest)`, so the digest lives *inside the signed object*.
  The witness computes it locally to decide whether to sign; consensus never
  sees it; it is not on the wire.
- **The nonce is NOT stored** — `H(r ‖ cb_out_key ‖ P ‖ s ‖ E)` is recomputable
  at the only two moments anything needs it (admission and any later re-check),
  because `r` (coinbase extra) and `cb_out_key` (coinbase output) are kept-side
  and survive the signature prune. Storing it is redundant moving data.

**3.1 Kept side (permanent, coinbase `tx_extra`) — the header.**
`p_id (32) + shard_id (8) + settlement_epoch (8) + sig_commit (32)` ≈ **80 B**,
committed via `prefix_hash` (see the resolution below — the `tx_extra` residence
is what makes the commitment work without a tx-hash change). Nothing else
survives the derive-don't-store collapse above.

*The one field that exists only because pruning destroys what it summarises is
`sig_commit`, and code analysis (2026-08-03) settled it — RESOLVED to
`sig_commit: [u8;32] = H(countersignature)` (zero = miss, nonzero = pass), which
doubles as the pass/miss discriminant (no separate `kind` bit).*

A one-bit `kind` was considered and **rejected at source.** The rejection turns
on a coinbase-hashing fact: the v3 tx-hash is
`cn_fast_hash({prefix_hash, base_rct_hash, pqc_auth_hash, prunable_hash})`, but
`prunable_hash` is **hardcoded to `null_hash` whenever
`rct_signatures.type == CTTypeNull`** (`cryptonote_format_utils.cpp:1236`), and
the coinbase is always `CTTypeNull` (`prevalidate_miner_transaction`:
"FCMP++ signatures not allowed in coinbase"). **So the coinbase commits
`null_hash` for its prunable region regardless of content** — the commitment
slot exists in the tx-hash but is wired to null for the coinbase. The signatures
placed there (§3.2) therefore get **no** commitment from the coinbase's own
`prunable_hash`.

Consequences, and they force `sig_commit`:

- **The kept header is committed unconditionally.** It lives in the coinbase
  `tx_extra`, which is in the prefix, so it rides `prefix_hash` (`hashes[0]`) →
  tx-hash → block-hash. The `CTTypeNull` short-circuit only nulls `hashes[3]`,
  never the prefix. So anything in the header is committed **today, with no
  tx-hash change.**
- **`sig_commit` in the header is the ONLY consensus commitment the pruned
  signatures can get.** Putting `H(sig)` in the header commits the signature via
  `prefix_hash`, sidestepping the null coinbase `prunable_hash` entirely.
- **A bare `kind` bit would leave the signatures uncommitted** — the block would
  attest only a 1-bit flag, with no on-chain evidence the pruned signatures were
  the admitted ones — **or** force a change to `calculate_transaction_hash`
  (un-nulling the coinbase's prunable_hash), the single most consensus-critical
  function in the tree. `sig_commit` avoids both for 32 bytes.

(An earlier draft leaned toward the bit on the argument that prune-integrity was
already carried by the coinbase's collective `txs_prunable_hash`; the
`CTTypeNull` finding shows that hash is null for the coinbase, so it carries
nothing — the lean is retracted.)

*`E` stays explicit (−8 B not taken):* the response window crosses `E`/`E+1`
(a record for `E` may land in a block in `E` or in `E+1`'s grace), so height
does not map to a single `E` and deriving it would reintroduce the boundary
off-by-one the explicit field buys out. Remaining sub-decisions: byte order and
`p_id`/`shard_id` encoding (fixed vs varint).

> **Disambiguation (maintainer, 2026-08-03).** "v3" in this doc is the **Shekyl
> transaction version** (`miner_tx.version ≥ 3`). It is NOT the **Tor onion v3**
> ed25519 address of the step-1 identity ruling. The two never share the bare
> token here.

**3.2 Prunable side — the countersignature, on the miner tx (shape 1, chosen
2026-08-03).** The 3.43 KB hybrid countersignature (Ed25519 64 B + ML-DSA-65
3309 B + framing) over the block-bound nonce, held in **the coinbase tx's own
prunable region** — physically inside the transaction whose `cb_out_key` the
nonce binds. Its commitment is the header's `sig_commit` (§3.1 resolution), NOT
the coinbase's `prunable_hash` (null under `CTTypeNull`); verified at admission
against `sig_commit` + the recomputed nonce, then dropped after depth.

**SHAPE REOPENED (2026-08-03) — the prune-worker confirmation surfaced a
block-blob obstacle that reverses the pruning axis.** Confirmed green: the prune
worker (`prune_worker`) deletes `txs_prunable` by tx_id with **no `txin_gen`
exclusion** (only gate `!is_v1_tx`, which the v3 coinbase passes), keeping the
unprunable prefix. **But** the coinbase is stored *twice*: in
`txs_pruned`/`txs_prunable` (pruned) **and** in the block blob in the `blocks`
table via `block_to_blob(FIELD(miner_tx))` — and **`blocks` is never pruned**.
Non-coinbase tx *bodies* are not in the block blob (only their hashes,
`FIELD(tx_hashes)`). Consequence:
- **Shape 1** — an appendix serialized with `FIELD(miner_tx)` lands in the
  never-pruned block blob, so the signatures persist there *forever* and
  pruning `txs_prunable` leaves them; pruning is defeated unless `block_to_blob`
  is changed to store the coinbase **base-only** — block-format surgery on the
  one tx whose body rides the never-pruned `blocks` table.
- **Shape 2** — a separate attestation tx's body is never in the block blob, so
  it prunes cleanly with the confirmed machinery.
- **Shape 3 (new candidate)** — the attestation blob as its *own* per-block
  prunable LMDB table (keyed by height), committed by `sig_commit` in the
  coinbase `tx_extra` and bound by the nonce's `cb_out_key` term: keeps shape
  1's coherence (commitment in the coinbase, one place to read) with neither
  shape 2's per-tx overhead nor shape 1's block-blob problem.
The pruning axis now favours 2 or 3 over 1. `sig_commit` and the §3.1 header are
unaffected (they are in the kept prefix regardless of where the signature
lives). **Shape decision pending maintainer.** The comparison below is the
pre-finding weighing, retained for the coherence/footprint axes it still scores
correctly:

*Original weighing — 1 (miner-tx prunable region) over 2 (a separate
attestation tx class).* The binding is **physical** in 1 (a future maintainer sees the whole
mechanism in one tx) vs **referential** in 2 (an attestation tx carrying
`cb_out_key` as data, cross-referenced to the coinbase — the class of
replay/mis-association bug the Dandelion++ inheritance is currently costing us).
1 is also smaller on the *permanent* kept side — 2 carries per-tx overhead
(type tag, own tx-hash, own indexing) `k`× per block for the life of the chain,
re-inflating the footprint two rounds just removed. Shape 2's one edge — a
non-coinbase tx gets a real `prunable_hash` for free — **evaporates**, because
`sig_commit` already commits shape 1's signatures via the header. **The audit
shape 1 costs (stated plainly, and bounded — not a tx-hash change):** the
coinbase already has a `txs_prunable` slot and a `txs_prunable_tip` entry
(`add_transaction_data`), empty today, so this fills an existing slot; confirm
the prune worker (`prune_worker`, iterating `txs_prunable_tip`) prunes a
*populated* coinbase region (it participates, pending one walk for a `txin_gen`
skip), and grep for anything asserting the coinbase / `miner_tx` is whole. The
split is *within* the tx: outputs/amounts/supply-relevant fields (the
unprunable prefix) are untouched — only a prunable appendix is added — so the
supply-verification path reads exactly what it read before. Open: how `k`
signatures **pack** in the region (concat + count, or length-prefixed), keyed to
the `k` headers by order.

**3.3 The verify entrypoint that replaces `shekyl_archival_verify_serve_credit_vin`.**
Its contract inverts: instead of a path opening it (a) recomputes the nonce from
`r ‖ cb_out_key ‖ P ‖ s ‖ E`, (b) checks the prunable `HybridSignature` hashes to
the header's `sig_commit` **and** is `P`'s valid countersignature over the nonce,
(c) binds the attester to the block producer (the coinbase authorship *is* the
attestation — no separate witness key), and (d) invokes the **epoch-windowed
coinbase-output-key uniqueness** check (the copy-freeride repair). A **miss**
record carries `sig_commit = 0` and verifies (a) + (c) + (d) with **no**
signature — it proves the challenge was posed (nonce is real) without proving a
response. `sig_commit` binds the kept header to the pruned signature, so the
verdict survives the prune with no reliance on the coinbase's null
`prunable_hash`.

**Gating question for the round — RESOLVED (2026-08-03):** the §3.1 header
(`p_id, shard_id, E, sig_commit` in coinbase `tx_extra`) and the §3.2 residence
(signature in the coinbase prunable region, shape 1) are settled. The scan fold
(§4) now keys off this format.

---

## 4. Settlement-scan fold (depends on §3)

The current scan assumes a beacon fired and writes **one bit per epoch**. Under
miner-chosen records it must fold, **per `(P, s)` per epoch**, the multiset of
records into the three-valued settlement:

```
{≥1 pass}            → served       (serve_credit_bit = 1)
{no pass, ≥1 miss}   → missed        (observation, counts to the m-of-n window)
{neither}            → non-observation (the window never sees it)
```

**Pass-priority** is the rule (any authenticated pass dominates any number of
misses — the fabrication-containment property). Two hazards to carry from the
rulings: (a) the miss record must commit to the challenge nonce or a fabricator
need not even construct a plausible attempt; (b) the **prune path must land on
non-observation, not miss** — the const-assert at `failure_window.rs:178–184`
currently guards "a pruned bit reads as a MISS", and under three-valued
settlement a pruned epoch has a correct value to decay to (non-observation),
which is the one-line credit-wire hazard the miss-fact ruling flagged.

---

## 5. Deletion surface — the atomic consensus swap (the item with teeth)

The old vin is the **only current writer of `serve_credit_bit`**. Delete it
first and there is a block where credit cannot be earned. So the new writer must
be **live before the old one dies, in a single consensus-visible change** —
`shekyl_archival_verify_serve_credit_vin` and its callers, the leaf/path/KAT
surface (§2), and the vin type/tag are removed in the *same* change that lands
§3–§4. The equivalence-KAT pair that pins the old path
(`serve_credit_equivalence_kat_v1.json`, both legs) rides the same change —
it cannot outlive the path it pins (`42-serialization-policy`: a persisted-block
wire change bumps the version constant, CI-enforced).

**This is where to be most careful.** It is a byte-for-byte consensus cutover;
`07-consensus-atomic-cutovers` governs it. Sequencing (writer-live-before-old-dies)
is the property the whole change is organised around.

---

## 6. Decision order for the round

1. **§3.1 header byte layout** + **§3.2 signature packing** — the gating pair.
2. §3.3 verify entrypoint contract (recompute-nonce + countersig + producer bind
   + uniqueness), pass and miss forms.
3. §4 scan fold (pass-priority; prune→non-observation).
4. §5 deletion surface + the atomic-swap sequencing.

Everything downstream is a function of decision 1, which is why it is posed
first and nothing else is pinned in this opening.
