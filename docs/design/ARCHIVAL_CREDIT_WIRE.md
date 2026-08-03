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

**3.1 Kept side (permanent) — the header, at its floor.**
`p_id (32) + shard_id (8) + settlement_epoch (8) + kind (1 bit)` ≈ **49 B**.
Nothing else survives the collapse above.

*The one field that exists only because pruning destroys what it summarises is
the `kind` bit, and its exact form is the round's sharpest sub-decision.*
Post-prune (the 3.43 KB signature dropped), a pass header and a miss header must
stay distinguishable — and no recompute path avoids a kept discriminator,
because the **nonce is identical for a pass and a miss of the same
`(P, s, E)`** (both derive from the same block's `r`/`cb_out_key`), no other
kept datum distinguishes them, and signature validity — the distinguishing
fact — is pruned before `MAX_CLAIM_AGE_W` (a late claim outlives the sig). So a
discriminator is **forced**. Its form:

- **Candidate A — `sig_commit: [u8;32] = H(countersignature)`** (miss = zeroes).
  Derived-from-the-signature at admission, self-consistent (a pass cannot carry
  a zero hash), survives the prune.
- **Candidate B — a single `kind` bit**, validated at admission
  (`kind = pass ⇒ a valid signature was present`) and committed in the block
  hash alongside the header.

**Provisional lean: B (the bit), 32× smaller — because A's advantages evaporate
exactly post-prune:** (i) once the sig is gone `sig_commit` is no longer
*derived*, it is stored opaque data *exactly as stored* as a bit, so the
derive-don't-store distinction that justified it no longer applies and only
footprint remains; (ii) A's self-consistency is redundant with **admission
validation** — a `kind = pass` in an *admitted* block provably had a valid sig
(a block lacking one was rejected and never prunes), and the bit is committed in
the block hash; (iii) prune-integrity is already provided by the coinbase tx's
**collective `txs_prunable_hash`** over the `k` signatures plus the committed
kept headers, so no *per-record* commitment is needed. The **only** thing A adds
is *which specific* valid signature was admitted (ML-DSA is randomised, so `P`
can produce several for one nonce) — and no post-prune consumer of
signature-*identity* is yet found (disputes settle at admission; light clients
trust the committed bit; pruned-IBD trusts admission either way).
**OPEN — the boundary to test before pinning B:** is there any consumer that
must re-exhibit *the* admitted signature rather than *a* valid one? If yes, A
earns its 32 bytes; if no, B is the floor.

*Further open:* can `E` be derived from block height (−8 B)? Only if the
response-window→epoch map is unambiguous across the boundary — a record for `E`
may land in a block in `E` **or** in `E+1`'s grace, so `E` is not simply "the
block's epoch." Keep it explicit unless that pinning rule comes out clean.
Remaining: byte order and `p_id`/`shard_id` encoding (fixed vs varint).

**3.2 Prunable side (coinbase-tx prunable region) — the countersignature.** The
3.43 KB hybrid countersignature (Ed25519 64 B + ML-DSA-65 3309 B + framing) over
the block-bound nonce. Residence is ruled (`FOLLOWUPS`: the coinbase tx's
`txs_prunable` region, `db_lmdb.cpp:236–240`, keeps it inside the very
transaction whose `cb_out_key` the nonce binds; verify-at-admission,
prune-after-depth). Open: how `k` records' signatures **pack** in that region
(concatenation + count, or length-prefixed), and how the prunable-hash
commitment covers them so a pruned node still validates the block header.

**3.3 The verify entrypoint that replaces `shekyl_archival_verify_serve_credit_vin`.**
Its contract inverts: instead of a path opening it (a) recomputes the nonce from
`r ‖ cb_out_key ‖ P ‖ s ‖ E`, (b) checks `P`'s hybrid countersignature over it,
(c) binds the attester to the block producer (the coinbase authorship *is* the
attestation — no separate witness key), and (d) invokes the **epoch-windowed
coinbase-output-key uniqueness** check (the copy-freeride repair). A **miss**
record verifies (a) + (c) + (d) with an **empty** countersignature field — it
proves the challenge was posed (nonce is real) without proving a response.

**Gating question for the round:** the §3.1 byte layout and the §3.2 packing —
because the scan reads the header and the deletion/KAT rewrite key off both.

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
