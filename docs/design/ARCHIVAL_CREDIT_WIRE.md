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

**3.1 Kept side (permanent, coinbase `tx_extra`) — the header. RESOLVED under
shape 4.**
`p_id (32) + shard_id (8) + settlement_epoch (8) + kind (1 bit)` ≈ **49 B**,
committed via `prefix_hash`. `sig_commit` is **not** a field — shape 4's
block-level `attestation_root` (§3.2) commits the signature set, so the header
need only carry a per-record pass/miss `kind` bit for the post-prune verdict.

*Why the `kind` bit is committed and sufficient.* It lives in the coinbase
`tx_extra`, which is in the prefix, so it rides `prefix_hash` (`hashes[0]`) →
tx-hash → block-hash. The signatures are committed **separately** by
`attestation_root`. Post-prune (signatures dropped), the `kind` bit gives
per-record pass/miss and the root persists as the set commitment — nothing
depends on the coinbase's own `prunable_hash`.

*Why the coinbase's `prunable_hash` cannot carry the commitment (the finding
that drove the shape search).* The v3 tx-hash is
`cn_fast_hash({prefix_hash, base_rct_hash, pqc_auth_hash, prunable_hash})`, but
`prunable_hash` is **hardcoded to `null_hash` whenever
`rct_signatures.type == CTTypeNull`** (`cryptonote_format_utils.cpp:1236`), and
the coinbase is always `CTTypeNull` (`prevalidate_miner_transaction`: "FCMP++
signatures not allowed in coinbase"). So a signature placed in the coinbase's
prunable region gets **no** commitment from the coinbase itself. Shapes 1/3
therefore needed a `sig_commit: [u8;32] = H(sig)` in the header to commit the
signature via `prefix_hash`; **shape 4 makes that redundant** — the block-level
merkle leaf commits the whole set, so the header drops back to the 1-bit `kind`
(the 32-byte-per-record saving the earlier one-bit reduction was reaching for,
now available because the root, not the coinbase, carries the commitment).

*`E` stays explicit (−8 B not taken):* the response window crosses `E`/`E+1`
(a record for `E` may land in a block in `E` or in `E+1`'s grace), so height
does not map to a single `E` and deriving it would reintroduce the boundary
off-by-one the explicit field buys out. Remaining sub-decisions: byte order and
`p_id`/`shard_id` encoding (fixed vs varint).

> **Disambiguation (maintainer, 2026-08-03).** "v3" in this doc is the **Shekyl
> transaction version** (`miner_tx.version ≥ 3`). It is NOT the **Tor onion v3**
> ed25519 address of the step-1 identity ruling. The two never share the bare
> token here.

**3.2 Prunable side — the countersignature (`HybridSignature`, Ed25519 64 B +
ML-DSA-65 3309 B + framing, over the block-bound nonce). Residence RESOLVED to
shape 4.**

**SHAPE RESOLVED → 4 (2026-08-03, after the merkle walk).** The attestation set
for a block is committed by a single **`attestation_root`** added as one extra
leaf to the block's tx merkle tree, alongside the tx-hashes; the signatures live
in a height-keyed prunable side table. Walk result (verified at source): the
merkle change is **contained** — (i) `tree_branch`/`tree_branch_hash` have **zero
callers** in `src/` (the block tx-tree has no inclusion-proof consumers; the
`tree_path` hits are all the FCMP++ *curve* tree), so a non-tx leaf ripples
nowhere; (ii) every block-hash / PoW path (`get_block_hash`,
`get_block_longhash`, RPC template/submit) flows through the single chokepoint
`get_block_hashing_blob`; (iii) the leaf count in that blob
(`varint(tx_hashes.size()+1)`) is *derived*, not cross-checked, so bumping it to
`+2` stays consistent. The leaf goes last (miner_tx stays leaf 0, tx_hashes
keep 1..n), and mandatory-`k` makes it always present (uniform every block).
**Refinement the walk forced:** `attestation_root` must be a **stored block
field** (32 B, serialized next to `tx_hashes`, kept in the never-pruned block
blob), NOT recomputed from the signatures — `get_tx_tree_hash(b)` is recomputed
at every verification, and a pruned node (signatures gone) must still recompute
the block hash. So the root persists post-prune; the signatures drop from the
side table. It is a block wire-format change (rule 42 version bump) and touches
`get_tx_tree_hash` + `get_block_hashing_blob` + the block struct — bounded, and
it never touches the coinbase.
*Consequences:* `sig_commit` per record is **dropped** — the root now carries
the signature-set commitment, so the header returns to
`p_id(32) + shard_id(8) + E(8) + kind(1 bit) ≈ 49 B`, the `kind` bit committed
via `prefix_hash` (§3.1) and carrying per-record pass/miss post-prune. Concern 1
(totality) **dissolves** — extra-or-missing signatures change the root, block
invalid, self-enforced with no admission loop. Concern 2 (reorg atomicity)
**stands** — the height-keyed side table joins `pop_block`'s atomic set (same
LMDB txn); one schema invariant to pin. The table is structurally parallel to
the serve-credit ledger it replaces (height-keyed, prunable, committed from the
block, dropped after horizon), so the redb-migration template already covers it.

**The principle this settles, and it reframes the round: attestations are
block-level consensus data, NOT transactions.** Shapes 1–3 forced a
non-transaction object into transaction machinery — shape 1 in the coinbase (a
tx), shape 2 as its own txs, shape 3 riding the coinbase's `tx_extra` (a tx
prefix). Shape 4 is the first where an attestation is not a transaction at all:
a sibling to the tx set, committed by the same block via its own merkle leaf,
verified and pruned on its own path. **The transaction set stays pure**
(archival / spend / bond txs), which is the FCMP-purity separation — attestations
never touch a tx, so they cannot perturb the tx-hash or the output-commitment
machinery.

**Do NOT conflate the two "tree roots" (validated at source 2026-08-03).** The
FCMP `tree_root` (`shekyl-fcmp/src/proof.rs`, from `Selene`/`Helios` branch
layers via `get_curve_tree_path`) is the **curve tree** over *outputs* — the
membership structure a spend proof binds to. The block's `tx_tree_hash`
(`format_utils.cpp:1419`) is a **`cn_fast_hash` binary merkle** over *tx hashes*
for the PoW blob. Different data, different hash, different purpose; FCMP binds
the curve root and never references the tx tree. The attestation leaf goes in the
**tx tree**, so it cannot disturb FCMP membership. (Stated so a future maintainer
reading "adding a leaf to the tree root" does not panic about spend proofs.)

**Shape-4 invariants (structural, replacing shape 3's hand-maintained totality):**
1. **Fixed leaf position.** `attestation_root` is always the **last** leaf of
   `get_tx_tree_hash` (miner_tx = leaf 0, `tx_hashes` = 1..n, attestation = n+1),
   and the count varint becomes `+2`. `tree_hash` is order-sensitive and the
   count is committed, so a content-dependent position is a consensus bug — the
   position is a constant.
2. **Defined-empty.** If a block's attestation set is empty, the leaf is the
   **empty-set hash** (a fixed constant), never omitted — omission would desync
   the count. (Mandatory-`k` makes a non-empty set the norm, but the leaf is
   defined for the empty case so the format is total.)
Both are enforced by the merkle root itself rather than by an admission loop,
which is the survives-the-team win: a maintainer cannot get the totality wrong
because the root does not match if they do.

*Shapes 1–3, superseded — one-line lineage (why 4 won).* **1** (appendix on the
miner tx): the coinbase body rides the never-pruned `blocks` table via
`block_to_blob(FIELD(miner_tx))`, so the signatures never prune without
`block_to_blob` surgery. **2** (separate attestation tx): prunes clean but pays
per-tx overhead `k`× per block forever, and binds the coinbase referentially.
**3** (own prunable table, committed by coinbase `sig_commit`): clean prune, but
leaves a hand-maintained totality invariant and still rides the coinbase for the
commitment. **4** dominates all three: the block-level merkle root self-enforces
totality, the coinbase stays a normal coinbase, and attestations are not a
transaction at all.

**3.3 The verify entrypoint that replaces `shekyl_archival_verify_serve_credit_vin`
(shape 4).** Its contract inverts: instead of a path opening, for each of the `k`
records it (a) recomputes the nonce from `r ‖ cb_out_key ‖ P ‖ s ‖ E`,
(b) for a **pass** (`kind = pass`) checks the side-table `HybridSignature` is
`P`'s valid countersignature over the nonce; for a **miss** (`kind = miss`)
requires no signature, (c) binds the attester to the block producer (the
coinbase authorship *is* the attestation — no separate witness key), and
(d) invokes the **epoch-windowed coinbase-output-key uniqueness** check (the
copy-freeride repair). Then it (e) recomputes `attestation_root` over the set and
checks it equals the block's stored root — which is what makes the set **total**
(extra or missing signature ⇒ root mismatch ⇒ block invalid, no per-record
admission loop). Post-prune the root is trusted (committed at admission, in the
block hash) and the `kind` bits carry per-record pass/miss. *(Shapes 1/3 used a
per-record `sig_commit` in the header to bind header→signature; shape 4's block
root subsumes it, so the header drops to the 1-bit `kind`.)*

**Record format + residence — RESOLVED (2026-08-03, shape 4):**
- **Header (kept, coinbase `tx_extra`):** `p_id(32) + shard_id(8) + E(8) +
  kind(1 bit)` ≈ 49 B/record, committed via `prefix_hash`.
- **Signatures (prunable, height-keyed side table):** the `HybridSignature` per
  pass record, pruned after horizon; the side table joins `pop_block`'s atomic
  set.
- **Commitment (block field + merkle leaf):** `attestation_root` (32 B, stored
  in the block blob, appended as the last leaf of `get_tx_tree_hash`, count
  `+2`), self-enforcing set totality; fixed-position and defined-empty invariants.
The scan fold (§4) keys off the kept header; admission keys off the signatures +
root — the two block-lifecycle points on the same records.

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
misses — the fabrication-containment property).

**The admission ↔ settlement seam (the invariant §4 is built around).**
`attestation_root` is **mined over** — it enters `get_block_hashing_blob` via the
tx tree, so the producer commits its attestation set at *mining* time
(unforgeable after the fact; `get_block_longhash` runs the PoW over it). That
fixes two lifecycle points on the same records:

- **Admission (block validation, per-block, PRE-prune).** Recompute
  `attestation_root` over the side-table signatures and check it equals the
  stored block field; for each **pass** recompute the nonce from
  `r ‖ cb_out_key ‖ P ‖ s ‖ E` and verify `P`'s signature; require **miss**
  records carry none; check each `kind` bit matches signature-presence; run the
  coinbase-output-key uniqueness check. A malformed set invalidates the *block*;
  it touches signatures + `r` (present pre-prune) and **never touches settlement
  state**.
- **Settlement (slash-deadline scan, per-epoch, `MAX_CLAIM_AGE_W` later,
  POST-prune).** Fold the **kept headers only** — `p_id, shard_id, E, kind` — into
  `serve_credit_bit` per `(P, s)` per epoch, pass-priority. The signatures and
  `r` are gone by construction; this path must never re-verify a signature or
  re-derive a nonce.

**`r` prunes with the signatures — verified, not assumed.** The nonce's only
consumer is admission: settlement (`r_market_count`, `scarcity_micro`) and claims
(`emission_verify`) read the `serve_credit` **bit**, and the C++ slash scan
operates on `serve_credit_bit` — none derive a challenge or nonce. So `r` lives
in the **prunable side table** (with the signatures), *not* the coinbase
`tx_extra`, and the coinbase extra holds only the kept per-record headers. (The
anti-copy defence is unaffected: it binds `cb_out_key`, which is a kept coinbase
output, not `r`.)

**Make the seam a type, not a discipline.** The settlement fold's input type is
the kept header alone (a `BaselineObservation`-shaped struct carrying `kind`), so
the scan is *structurally incapable* of reaching a signature, an `r`, or a nonce
— the make-bad-states-unrepresentable version of "settlement must not touch
pruned data." A future maintainer cannot accidentally add a signature check at
settlement because the type has no signature to reach.

Two hazards from the rulings, resolved under shape 4: (a) the earlier "miss must
commit to the challenge nonce" concern is **subsumed** — a miss record is a
`kind = miss` header in the coinbase `tx_extra`, which is mined over (committed
by PoW via the coinbase tx-hash), so it is the producer's block-bound assertion
without needing a stored nonce; pass-priority and the `e^−λ` bound contain
fabricated misses. (b) The **prune path must land on non-observation, not miss** —
the const-assert at `failure_window.rs:178–184` currently guards "a pruned bit
reads as a MISS", and under three-valued settlement a pruned epoch decays to
non-observation (the one-line credit-wire hazard the miss-fact ruling flagged).

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
