# Serve-credit response format — design round (RF)

**Status:** OPEN — `RF-D3`/`RF-D5` resolved and implemented 2026-08-19;
`RF-D1`/`RF-D2`/`RF-D4` **drafted 2026-08-20** (§3.5), implementation pending.
Round opened 2026-08-18.
**Unblocked by:** the carrier round
([`ARCHIVAL_PASS_RECORD_CARRIER.md`](ARCHIVAL_PASS_RECORD_CARRIER.md)) — **RULED
2026-08-18, merged to `dev` in PR #501.**

*(A `⚠️ MERGE ORDER: #501 before #504` note stood here while #501 was open,
because `dev` then still read "Status: OPEN" for the carrier round and this doc
cited a ruling `dev` did not yet record. #501 merged 2026-08-19; the ordering it
enforced is satisfied, so the note is retired rather than left to read as a live
constraint.)*

**Freezes:** a genesis-frozen wire. Everything decided here is impossible to
change after genesis, which is the only reason the round exists as a round.
**Process:** [`26-sub-pr-design-discipline`](../../.cursor/rules/26-sub-pr-design-discipline.mdc).
Disposition IDs **`RF-D1` … `RF-Dn`**, registered at birth per
[`94-tracking-index`](../../.cursor/rules/94-tracking-index.mdc).

**Every input below is pinned, and `RF-D3` is now implemented.** `RF-D5`
(§2.5 — surfaced by grounding the deletion, not by the ruling) is resolved with
it. `RF-D3` was carried as the round's one open test
— *whether `r` survives* — and it **dissolved on grounding** (§2): the ruling had
already settled it on 2026-08-10, by an argument my restatement had replaced with
a weaker one. So the round is **pure transcription of settled rulings into
bytes**, which is a cleaner statement than the one it replaces. Rounds where
everything is open produce prose; this one should produce a wire, and now nothing
stands between it and doing so.

---

## 1. The inputs, and where each was settled

Verified at source on 2026-08-18 against `dev@69e76a7be` — **with one exception,
corrected 2026-08-19 and recorded rather than quietly fixed.** Input 4's
*reasoning* was transcribed from the scoping conversation, not read from the
ruling, and it was wrong in a way that produced a test of the wrong claim. See
§2.

| # | Input | Status | Settled at |
| --- | --- | --- | --- |
| 1 | **Leaf chunk is pruned-side by construction** | RULED | `ARCHIVAL_PASS_RECORD_CARRIER.md` CR-D2 |
| 2 | **Reserved padding field; no padding scheme** | RULED 2026-08-08 (TJ-H) | `ARCHIVAL_CHALLENGE_MECHANISM.md:1065` |
| 3 | **Nonce anchor = `cb_out_key` of block `h`** | RULED 2026-08-10 (fork 2 closed) | `ARCHIVAL_CHALLENGE_MECHANISM.md:40-43` |
| 4 | **`r` deleted**; nonce `H(block_hash(h−1) ‖ cb_out_key ‖ P ‖ s ‖ E)` | **RULED 2026-08-10** — `RF-D3` resolved, see §2 | `ARCHIVAL_CHALLENGE_MECHANISM.md:48`, `:820-850` |
| 5 | **`CR-F2`'s `prefix_hash` / tx-id change** | priced, **lands here** | `ARCHIVAL_PASS_RECORD_CARRIER.md` CR-F2 |

### 1.1 The carrier's answer, which this format must express

Kept, on the vin in the prefix: the record header, `leaf_bytes`, and the 64 B
Ed25519 leg. Pruned, as a **parallel structure keyed to the vin, inside
`serialize_rctsig_prunable`** — ~9,965 B: the ML-DSA leg and `path` including the
leaf chunk.

`CR-D2` sized the kept side at **~278 B ≈ 7.1 GB/yr**. **`RF-D6` (§3.5) refines
that to ~230 B ≈ 5.9 GB/yr** by removing `segment_subroot_rk` and
`leaf_index_in_segment` from the record entirely — they are neither kept nor
pruned, because the verifier derives both and trusting a wire-supplied one is
unsound. The *partition* `CR-D2` ruled is unchanged; what changed is the record's
contents.

**A vin cannot straddle `unprunable_size`** — `tx.vin` serializes wholly inside
the prefix — so the pruned parts are not fields within the vin. And by the
carrier round's §1 the parallel structure lives **inside**
`serialize_rctsig_prunable`, never appended after `ctsig_prunable`: inside, both
paths of `calculate_transaction_prunable_hash` see it by construction; after,
they diverge silently and throw on blob-holding nodes only. That invariant is
guarded by `tests/unit_tests/tx_prunable_region_sole_occupant.cpp`.

### 1.2 `RF-D1` (OPEN) — the constraint whose failure mode is tidiness

**The leaf chunk is pruned-side by construction.** `leaf_bytes` is already
kept-side and the leaf chunk is the same conceptual object in the same
neighbourhood, so grouping them is the obvious, unremarkable move — and it
silently reintroduces **~124 GB/yr**.

A format that groups them for structural neatness **is not disagreeing with
CR-D2; it is not noticing it.** That is why this is recorded as a constraint
rather than left to be re-derived: disagreement gets argued, tidiness just lands.
One field identifies the record, the other proves it, and only the first survives
pruning.

### 1.3 `RF-D2` (OPEN) — `CR-F2`: the tx id moves, and that is genesis-frozen

Today both signature legs sit in one 3,385 B `hybrid_signature` on the vin
(`3385 = 12 framing + 64 Ed25519 + 3309 ML-DSA-65`). Slimming it to the Ed25519
leg alone changes the prefix bytes, therefore `prefix_hash`, therefore **the tx
id for the same logical record**.

**Affordable pre-genesis, impossible after.** It is carried here as a first-class
input rather than a cross-reference to the carrier round, because a fact that
lives only in the round that discovered it is a fact the round that needs it will
not read. `RF-D2` is: does the slimmed field keep the `hybrid_signature` name and
shrink, or become a distinct kept-leg field with the container retired?

---

## 2. `RF-D3` — RESOLVED 2026-08-19: `r` deletes, and the test was of the wrong claim

**The disposition is unchanged — `r` goes — but the round did not settle it. The
2026-08-10 ruling did, and this round had restated its argument incorrectly.**

### 2.1 What the ruling actually argues (`ARCHIVAL_CHALLENGE_MECHANISM.md:820-850`)

Not unpredictability-by-grinding. **Shared chooser, plus an existence bound.**
`attestation_wire.rs:191-195` assigns the roles at source: `cb_out_key` is *"the
copy-freeride bind; kept"*, `r` is *"the producer's revealed randomness"* — whose
only job is nonce unpredictability, stopping `P` pre-signing a countersignature
it hands out without ever being contacted.

> `r` **cannot do that job**: both `r` and `cb_out_key` are chosen by the same
> party, so a producer willing to leak one is equally willing to leak the other —
> *"a second producer-chosen random term does not strengthen a property that fails
> exactly when the producer defects."*

And the substitution is justified by **existence**, not by cost:

> `block_hash(h−1)` *"cannot exist before block h−1 does, **regardless of any
> party's behaviour**"* — collusive pre-signing narrows from unbounded lead time
> to one block.

The ruling states its own residual plainly: **fully-collusive passes remain
possible** (`P` can countersign whatever a colluding producer shows it at block
time) and stay priced by the 2-of-3 quadratic and the outer window. The property
bought is *pre-signing resistance against a colluding producer — which `r` never
provided.*

### 2.2 The error this round made, recorded because the class recurs

This document carried input 4 as *"`block_hash(h−1)` is ungrindable by block
`h`'s producer, so `r` may do no work"*, with the falsifier *"block `h`'s producer
may also have produced `h−1`"*.

**"Not choosable" became "ungrindable", and a test was written for the paraphrase
rather than the ruling.** The ruling never claims ungrindability; it claims a
shared chooser and an existence bound. The falsifier was then aimed at a property
nobody had asserted — and it is *pre-answered* by the ruling's own honest-strength
sentence: a producer of both blocks gets exactly **one block of lead**, which is
the bound the ruling concedes, not a break of it.

This is the third dissolve-on-grounding in this arc — the W₂ floor check, the
Pi-4 device-requirement question, and now `RF-D3` — and the class is identical
each time: **a residual carried into a new round without re-grounding its
reasoning.** The premise travels, the argument behind it does not, and the new
round tests a claim its source never made.

### 2.3 Additionally observed in this round (not part of the 2026-08-10 ruling)

A sharpening, attributed so it is not later read back as the ruling's own:

**Grinding the nonce has no objective.** Grinding requires a target — a value the
ground quantity is compared against. The nonce is a *binding input* to a
countersignature, not a threshold: no nonce value is better for an adversary than
any other, and changing it does not unbind `P`, `shard_id`, `E`, or `cb_out_key`.
Whatever grind-value exists in choosing `block_hash(h−1)` lives on the
**assignment** side — who gets challenged — which is separately priced at
discarded-block cost (`challenge_assignment.rs`: *"Grinding the assignment costs
discarding a valid block"*).

So the falsifier fails for a cleaner reason than the `q²` cost argument would
give: the `q²` precedent prices the *cost* of producing two consecutive blocks,
and here the *benefit* is zero, which makes the cost moot.

### 2.4 The implementation surface, named but not touched

`r` deletes at the format **cut**, not in this document. The surfaces:

| Surface | Location |
| --- | --- |
| Nonce function signature (`r` is its first parameter) | `attestation_wire.rs:199` |
| Per-block `r` field | `attestation_wire.rs:294` |
| Wire side-table field | `shekyl-wire/src/transaction.rs:932` (`pub r: Vec<[u8; 32]>`) |
| Pinned nonce KATs — **regenerate under [rule 30](../../.cursor/rules/30-cryptography.mdc)** | `attestation_wire_kat.rs:48`, `:147`, `:278` |

**The KAT outcome is the payoff for a distinction that looked pedantic.**
Insisting that `r` is **replaced** — same arity, new source — rather than
*deleted* is what let the frozen cross-language vector re-anchor **without
regenerating a signature**. Feed the same 32 bytes through the new term and the
nonce, the countersignature and the `attestation_root` are **byte-identical**;
only the blob changes, losing a prefix it no longer needs to transport.

That matters because **a regenerated vector is a vector nobody can check against
anything.** Its correctness rests on the code that produced it — the code it is
supposed to be testing. Preserving arity turned a rule-30 regeneration ceremony
into rule 30 satisfied **by construction**: the vector still pins exactly what it
always pinned. Had the term been dropped and the preimage reshaped, every pinned
value would have moved and the only available check would have been "the new code
says so."

The structural pins did still move, and were re-anchored rather than deleted:
`WITNESS_PREFIX_LEN` 40 → 8, `MAX_ATTESTATION_WITNESS_BYTES` 866,600 → **866,568**
in **three** places with three different enforcement mechanisms — the C++
transport cap (runtime FFI equality gate against Rust), `shekyl-archival-retention`
(the authority), and `shekyl-levin`'s deliberate duplicate (compile-time
`const _: () = assert!` plus a test), which exists because that crate refuses the
retention stack as a production dependency.

### 2.5 `RF-D5` — RESOLVED 2026-08-19: `r` is **replaced**, not deleted, and the anchor is refused when unpopulated

Found while grounding the deletion surface, and recorded because the ruling's
phrasing (*"the nonce's `r` term DELETES"*) reads as a pure removal and **is not
one**.

`attestation_nonce`'s first term is *replaced* — same arity, new source — and the
new source is **chain state the verifier did not receive**.
`ShekylArchivalAttestationVerifyCtx` carried `attestation_root`, `cb_out_key`,
`headers`, `pairs`, and **no predecessor hash**; Rust has no chain access at that
call site, since admission calls in from C++. So the deletion is one indivisible
change across the surfaces in §2.4 plus an **FFI ABI widening** and a C++
call-site populate.

#### The decision: reject all-zeros, no readability flag

`cb_out_key` sits two fields away with a `cb_out_key_readable` companion, so the
asymmetry would read as an oversight to a later reader and invite a well-meaning
symmetry patch. Stating it as a decision:

**`cb_out_key_readable` models a state that can genuinely occur.** Extracting the
coinbase output key requires parsing the coinbase transaction, and that can fail
on a malformed one. The flag has a real condition behind it.

**`prev_block_hash` is not like that.** It is `prev_id` from the header of the
block being connected — mandatory, and already parsed to have reached attestation
verification at all. There is no path where a verifier holds a block but not its
predecessor's hash, so a readability arm **could never legitimately fire**. This
round has now found three times that a check which never fires is worse than no
check, because it reads as protective: the vacuous KAT arm, `is_floor_datum`
fading open, and the `CTTypeNull`-only test. On a genesis-frozen surface that is
permanent.

**The flag would not buy the property anyway.** The hazard is an *unpopulated*
field, and the flag is itself caller-populated — a caller that forgets the hash
forgets the flag. What makes it fail closed is **zero-initialisation**, and
zero-rejection gets that same property without a second field the caller must get
right.

**All-zeros is a sound sentinel — but only where a record consumes the anchor,
and getting that wrong would have halted the chain.**

The reasoning first recorded here was *"a real block hash under RandomX has
leading zeros, never thirty-two of them"*. **That is wrong, and it is worth
recording why rather than quietly replacing it.** `prev_id` is the block *object*
hash (`get_block_hash`), not the RandomX PoW value — no difficulty target
constrains it, so nothing about mining excludes an all-zero id. The
PoW-difficulty intuition was imported from the wrong hash.

**And the genesis block's `prev_id` is all-zeros, while genesis reaches this
path.** `top_block_hash()` returns `null_hash` on an empty chain, so
`bl.prev_id == get_tail_id()` holds and `add_new_block` routes genesis to
`handle_block_to_main_chain` → `verify_block_attestation`. A ctx-level gate would
have **rejected genesis, and the chain could never have initialised.** The
earlier note that "the genesis edge does not collide" reasoned about *records* at
height 1 and missed that the *block* itself is the case.

**The fix is scoping, not a special-case:** the anchor is checked where it is
**load-bearing** — when at least one pass record will be verified against it.
With no records no nonce is computed, so enforcing it there asserts on a value
nothing reads. Every record-bearing block is at height ≥ 1 with a real
predecessor hash, so within that scope all-zeros is again unreachable except by a
caller that failed to populate the field.

**Pinned by a negative-controlled pair** in `attestation_verify_tests.rs`:
`genesis_all_zero_prev_hash_with_no_records_verifies_ok` goes red if the scope is
removed, and `all_zero_prev_hash_with_a_record_is_refused` goes red if the check
is. The unit suite missed the original defect because no test drives a full
`Blockchain::init`.

**The rejection carries its own verdict code** (`ERR_PREVHASH_UNPOPULATED`)
rather than folding into a generic malformed-ctx path. A distinguishable failure
is what tells the next person the *field* was unpopulated rather than the
*record* bad — the only way that value arises.

#### The empirical half: five call sites forgot it

The disanalogy argument stands on its own, but it was also **tested against real
call sites**. On the first C++ run after the ABI widened, **five tests failed** —
`pinned_valid_vector_verifies_ok`, `flipped_root_is_root_mismatch`,
`absent_bond_is_bond_absent`, `wrong_pair_pid_is_set_mismatch`,
`empty_shape_across_ffi` — every one because it built the ctx without the new
field.

**Under the flag design each of those five would have passed silently**, with a
zeroed flag read either as *"unreadable, skip"* or as *"readable, here are your
zeros"*. Both are silent, on a consensus path. Zero-rejection turned all five
into loud failures at build time.

That is the argument made concrete rather than asserted: the alternative design
was tested against real callers and **five of them would have been wrong**.

#### The predecessor must be *validated*, not merely supplied

Stated on the field itself (`attestation_nonce`'s doc comment and the ctx field),
because call-site ordering is the only thing that currently enforces it:

> The term must be a **validated** predecessor hash, not `prev_id` as supplied.

An unvalidated header field is producer-chosen — exactly the property `r` was
deleted for having. See §2.6 for what the trace found about the two paths.

### 2.6 The ordering trace — bounded, and it settled the constraint's wording

The concern: on the main-chain path `prev_id` is validated against `top_hash`
(`blockchain.cpp:5690`) **before** the attestation call at `:5723`. On the
alt-chain path (`handle_alternative_block`), the call at `:2237` is preceded only
by a height check, an alternative-allowed check, and a hardfork check — **nothing
validates `prev_id`**. Parent existence is established later, inside
`build_alt_chain`.

The discriminating question was not "trace the alt path" (a round) but **"is
`verify_block_attestation` a pure predicate?"** (one function read). It is: only
reads — `parse_archival_attestation_from_extra`, the pure step-1 Rust call,
`get_archival_bond_hybrid_pubkey`, `get_output_public_key` — no DB write, no
member mutation, no cache insert. Its own header says it *"parses nothing
structural and decides nothing."*

**So a losing alt block leaves no residue: this is an ordering smell, not a
soundness hole.** The interesting case is not a fabricated `prev_id` but a *real
but non-tip* one, since alt-chain building on a historical block is legitimate —
but the choice set is bounded by the record's own `E` term (a pass record for
epoch `E` lands in a block within `E`, whose predecessor is in `E`), and to make
any of it land the alt chain must **win**, at which point `prev_id` is a
validated predecessor and the lead time collapses to one block. Winning a reorg
that deep is a majority capability, already outside what this defends against.

**The constraint is written at full strength regardless**, because it is true
under both outcomes and it is what a later implementer needs. **The alt-path
reorder is its own item** — validating `prev_id` before `:2237` rather than
inside `build_alt_chain`. It is filed separately on purpose: the trace showed the
current ordering is *sound but unnamed*, so the reorder is **independent
hardening, not a fix riding a format change**. Bundled, a reviewer would read it
as necessary to the format, which it is not.

### 2.7 Rule 42 — checked, and there is **no instance here**

[Rule 42](../../.cursor/rules/42-serialization-policy.mdc) pairs every persisted
wire-format change with a version-constant bump, CI-enforced. It was checked
rather than assumed, because **a bump performed on the wrong constant is worse
than none — it would read as satisfied**.

Three independent confirmations that it does not reach this change:

1. **The rule's own `globs`** are `rust/shekyl-engine-state/**` and
   `rust/shekyl-engine-file/**`. The attestation witness is in
   `shekyl-archival-retention` — neither.
2. **The CI gate is scoped by construction.** `ci/schema-snapshot`'s
   `assert-snapshots` runs *"the `schema_snapshot` tests in
   `shekyl-engine-state`"*, and `enforce-version-bump` triggers only when *"any
   `.snap` under `rust/shekyl-engine-state/schemas/`"* changed. The workflow does
   not mention this crate.
3. **The purpose does not transfer.** The rule exists so *"a binary can reject a
   file whose wire format it cannot read"* — a wallet-side persisted block read
   later by a possibly-older binary. The witness is a consensus transport blob
   carried alongside the block into a node-side side table, and its integrity
   comes from `attestation_root` being **mined into the block hash**, not from a
   version constant.

**Pre-genesis there is no prior encoding that could coexist with this one.** A
version field exists to let a reader distinguish encodings that coexist; where
none can, the field is ceremony. **No bump is owed**, and this section exists so
the next reader does not re-derive it — or, worse, add one.

---

## 3. `RF-D4` — the reserved padding field, and what "reserved" has to mean in bytes

TJ-H ruled 2026-08-08: **reserve the padding field in the frozen response format;
specify no padding scheme.** The mitigation moves to the Tor layer, because
padding cannot defeat a triggered probe — the adversary receives the padded
response over its own circuit and knows the delivered size.

**The framing constraint is the load-bearing half:** the reserved field sits
**outside the `R_k`-hashed bytes.** A padding scheme adopted later must not
change what the response commits to, or "reserved" bought nothing and the
mitigation it was reserved for cannot be adopted without a second frozen-wire
change.

`RF-D4` is therefore about **bytes, not policy**: what is the field's encoding,
what is its zero/absent form, and what does a verifier do with a non-zero value
it does not understand? A reserved field with no defined handling for unknown
content is reserved in name only.

---

## 3.5 The wire draft — `RF-D1` / `RF-D2` / `RF-D4`

**Two artifacts, not one.** This is a premise correction, made before drafting
because the round's scoping argument had assumed a shared boundary that does not
exist:

| Artifact | Governs | Gated by |
| --- | --- | --- |
| **A — the on-chain record** `txin_archival_serve_credit_response` | `RF-D1`, `RF-D2` | the carrier ruling (§3.1) |
| **B — the served shard payload** (`shekyl-p-serve` → fetcher) | `RF-D4` | TJ-H only |

TJ-H's attack is Tor-observed **response size** — *"the adversary receives the
padded response over its own circuit"*, *"every padded byte crosses two Tor legs
and inflates W₂"* — so the padded thing is the shard payload `P` serves, not the
vin. §9.5's own live-remainder list separates them (*"response wire, pass-record
tx carrier + prunable residence, …"*).

They are still one slice, because they share a **validation surface**: *does each
artifact make its hashed region unambiguous to a verifier?* Same question, same
reviewer, two artifacts.

---

### `RF-D1` / `RF-D2` — artifact A, the on-chain record

**Kept, in the vin (prefix) — ~230 B/record ≈ 5.9 GB/yr**

| Field | Bytes | Note |
| --- | ---: | --- |
| `p_canonical_id` | 32 | identity |
| `shard_id` | varint | identity |
| `settlement_epoch` | varint | identity |
| `leaf_bytes` | 128 | the challenged leaf — the *claim* |
| **`ed25519_countersignature`** | **64** | see `RF-D2` |

**`RF-D6` (ruled here) — `segment_subroot_rk` and `leaf_index_in_segment` come
OFF the wire, and the reason is soundness, not thrift.**

An earlier cut of this table carried both. `CR-D2`'s ruling said the kept side is
*"header + `leaf_bytes` + 64 B Ed25519 — identifies the record, cannot re-verify
the opening"*, and these two are **not identifiers**:

- `segment_subroot_rk` is the **verification target**. `LeafStore::frozen_segment(id)`
  returns a `FrozenSegmentRecord { r_k, .. }`, and one shard is one segment
  (`25,992 × 128 = 3,326,976 B` = `SHARD_BYTES`), so every verifier reads the
  authoritative `R_k` locally.
- `leaf_index_in_segment` is **derived**:
  `challenge_leaf_index(p_id, shard_id, settlement_epoch, segment_leaf_count)`,
  every input of which the verifier already has.

**Carrying them is worse than redundant — a wire-supplied value is unsound if
trusted.** A verifier that checks the path against the *supplied* `R_k` lets the
prover choose its own tree root; one that opens at the *supplied* leaf index lets
the prover choose which leaf to prove. Either **defeats** the challenge — not
degrades it. So the correct verifier must ignore both wire values and use its
own — and **a wire field a correct implementation must ignore is worse than
absent**: it is an invitation, sitting in the record, in the position a reader
trusts.

**The two fail differently, which is why they come off together under one
criterion rather than one at a time.** Supplied-`R_k` is the classic
self-attesting root, and an implementer is likely to spot it. Supplied-leaf-index
is subtler: **the root is right, the opening is valid, and the prover simply
proves the one leaf it kept.** Nothing looks wrong at any step. Someone who
catches the first may well miss the second, so the durable form of this ruling is
the shared test — *is this an identifier, or a verification input?* — not the two
removals.

**What the verifier uses instead, stated because the record no longer declares
it.** With both fields off the wire, a reader of the vin alone cannot see what
the proof is checked against; that dependency is now implicit, and "the fields
were forgotten" is the natural wrong conclusion. It is deliberate, and the
sources are:

| Input | Where the verifier gets it |
| --- | --- |
| `R_k` | `LeafStore::frozen_segment(shard_id)` → `FrozenSegmentRecord { r_k, .. }` |
| leaf index | `challenge_leaf_index(p_id, shard_id, settlement_epoch, segment_leaf_count)` |

Both are chain-derived and identical on every honest node, which is exactly what
makes them unnecessary — and unsafe — to transmit.

That is ~**0.9 GB/yr** saved, and the saving is the lesser half. **There is no
production verifier yet** (`RF-D4` below), so this is pinned before the first one
can read the wrong value.

**A field is kept only if the verifier cannot derive it.** `leaf_bytes` stays
because it is the prover's *claim* — the bytes alleged to sit at the derived
index — which is exactly what nothing else supplies.

**Pruned, keyed to the vin, inside `serialize_rctsig_prunable` — ~9,965 B**

| Field | Bytes |
| --- | ---: |
| leaf-chunk scalars (`4 · 38 · 32`) | 4,864 |
| `c1_layers` / `c2_layers` (`(18 + 38) · 32`) | 1,792 |
| `ml_dsa_countersignature` | 3,309 |

**`RF-D1` — the kept/pruned boundary is structural, and the pairing is stated.**
The boundary is the vin/prunable split itself: `tx.vin` serializes wholly inside
the prefix, so a field's side is a fact of *where it is written*, not a
convention a pruner infers. What must be stated is the **pairing**, because that
is the part an implementation could infer differently: entries appear in
**serve-credit-vin order**, one per serve-credit vin. That mirrors
`pass_signatures[i]` ↔ i-th pass header, whose own doc says the zip must be
"stated, not inferred".

**And stating the pairing is what makes a count field unnecessary.** An earlier
cut wrote `count_le(8) ‖ entry[0..count]` with *"`count` MUST equal the number of
serve-credit vins"* — a `MUST` that is a consistency check on a value the tx
already determines. That is `WITNESS_PREFIX_LEN`'s lesson arriving two paragraphs
after `RF-D2` deletes the same redundant framing from `hybrid_signature`: a
length carried beside data whose length is already known. The length is **implied
by the vin count**, and `serialize_rctsig_prunable` already takes vin-derived
counts (`count_spend_inputs(vin)`), so the precedent for deriving rather than
carrying is in the signature it will be written into.

**The leaf chunk is pruned-side by construction** (`CR-D2`), and the tidiness
hazard is why it is written down: `leaf_bytes` is kept-side and the leaf chunk is
the same conceptual object, so grouping them is the unremarkable move and
reintroduces ~124 GB/yr. One field **identifies** the record; the other **proves**
it. Only the first survives pruning.

**`RF-D2` — the container is renamed and fixed-width, not slimmed in place.**
Today `hybrid_signature: Vec<u8>` holds 3,385 B (`12 framing + 64 Ed25519 + 3309
ML-DSA`) with a length prefix and a `> PQC_HYBRID_SINGLE_SIG_LEN` bound check.
After the split the vin holds **only the Ed25519 leg**.

Keeping the name would be the `WITNESS_PREFIX_LEN` failure *in advance*: a name
asserting contents it does not have, in the declaration a reader trusts most.
So:

- `ed25519_countersignature: [u8; 64]` — **fixed array, not `Vec`**. No length
  prefix on the wire, no bound check to get wrong, and a wrong-length value is
  **unrepresentable** rather than rejected. The framing bytes and the check both
  disappear because the ambiguity they existed to police is gone.
- `ml_dsa_countersignature: [u8; 3309]` on the pruned side, same reasoning.

`CR-F2`'s `prefix_hash`/tx-id change is being paid for the split regardless, so
the rename costs nothing additional — and paying it *without* fixing the name
would be spending the change and keeping the defect.

---

### `RF-D4` — artifact B, the served payload

**Today there is no format.** `shekyl-p-serve` streams a raw `FrozenSegmentBody`
— a flat concatenation of leaf bytes — with `content-length = (end − next) ·
LEAF_BYTES` (`redb_backend.rs:363-365`). No envelope, no fields.

**`content-length` cannot be TJ-H's reserved header**, for three reasons:

1. **It does not locate the split.** One number covers segment *and* padding, so
   a padded response is indistinguishable from a longer segment.
2. **Self-authentication is by reconstruction, not delimiter.**
   `recompute_segment_r_k(&[[u8; 128]])` hashes *what was received*. Any trailing
   byte changes the input, so undeclared padding breaks verification outright
   rather than merely confusing it.
3. **It is a property of this transport, not of the format.** TJ-H reserves a
   field *in the frozen format*; anything living only in HTTP/1.1 headers does
   not survive a transport change.

**Draft: one length field, ahead of the body.**

```text
served response := leaf_count  varint    (≤ leaves_per_segment = 25 992)
                 ‖ padding_len varint
                 ‖ segment_bytes         (leaf_count × LEAF_BYTES, exactly)
                 ‖ padding_bytes         (padding_len, exactly)

hashed against R_k: segment_bytes ONLY
```

The fetcher reads the two lengths, hashes `segment_bytes` via
`recompute_segment_r_k`, and compares to its **local** `R_k`. Padding sits
**outside the bytes hashed against `R_k`** — TJ-H's framing constraint discharged
structurally rather than by prose.

**Both lengths are in a leading header so the response head can go out before any
store read**, preserving the property `remaining_bytes()` exists to give.

**`leaf_count`, not a byte length.** An earlier cut wrote `segment_len_le(8)` — 8
bytes for a quantity with ~25 992 legal values, carrying a *"MUST be a multiple
of `LEAF_BYTES`"* validity rule alongside. A leaf count is 2–3 bytes as a varint
and makes the multiple-of-128 property **structural**: a non-multiple is
unrepresentable rather than rejected. That is the same argument `RF-D2` makes for
the fixed-width signature arrays, applied to a length instead of a payload.

**`padding_len` is explicit, and the format is self-delimiting.** An earlier cut
had no such field while the prose still said *"writers MUST emit
`padding_len == 0`"* — prose and grammar describing different formats. Without
it, padding extent is whatever remains after the segment, i.e. **derived from
`content-length`** — reintroducing precisely the transport dependency this
section spends three reasons rejecting. With it, the frame is complete on its own
terms and survives a transport change.

**The forward-compatibility posture, argued rather than defaulted.** The question
is what a reader does with padding it does not understand:

- **Reject non-zero padding** — safe, and **forecloses the field**. Any future
  scheme needs every fetcher updated first: a flag day, which
  [rule 75](../../.cursor/rules/75-system-autonomy.mdc) exists to avoid. It also
  makes the reservation self-defeating: TJ-H reserved the field precisely so a
  later scheme would *not* need a format change, and this reintroduces one.
- **Ignore padding content** — a future scheme works on deployment. Rollout is
  non-uniform (some serve padded, some not), and **that is the mechanism working,
  not failing**: padding is a privacy measure with no correctness role, so a
  fetcher that receives none is not wronged.

**Ruled: write-zero, read-anything.**

> **Writers** MUST emit `padding_len == 0` until a scheme is specified.
> **Readers** MUST NOT reject on padding **content**, and MUST NOT include
> padding in the `R_k` input.
> **Readers MUST reject `padding_len > leaf_count × LEAF_BYTES` before
> allocating or draining any of it.**

That is the reserved-field posture that permits future use with **no flag day**:
the strictness lives on the write side where it costs nothing to relax, and the
permissiveness on the read side where tightening later would be the breaking
change.

**`RF-D7` (ruled here) — "read-anything" is about content, never about length.**
An earlier cut wrote *"total response length remains bounded by the transport
cap"*, and that was **an unchecked premise**: `shekyl-p-serve` has a request-head
cap (`MAX_REQUEST_BYTES` 8 KB), a concurrency cap (`MAX_INFLIGHT` 64) and a drain
cap (`MAX_DRAIN_BYTES` 8 KB) — **no response-length cap at all**. The fetcher side
has `MAX_RESPONSE_BODY_SIZE` = 256 MB (`shekyl-p-transport`), which is **77× a
segment** and therefore no bound on this format.

`padding_len` is declared by a **potentially adversarial server**, so an unbounded
declaration is a resource-exhaustion path: a fetcher expecting ~3.33 MB drained to
256 MB, once per request, against `MAX_INFLIGHT` concurrent slots.

**The two halves of "read-anything" are separable, and running them together was
the error.** Not rejecting on *content* is what buys forward compatibility — a
future scheme's bytes must not trip a reader written before it. Not bounding
*length* buys nothing and costs the DoS path. A bound is compatible with any
scheme that fits inside it.

**The bound, derived rather than picked:** `padding_len ≤ leaf_count ×
LEAF_BYTES` — at most one segment's worth, so a body never exceeds **2× a
segment** (~6.65 MB). The fetcher already must accept a full segment; this admits
exactly one more. And TJ-H's own third leg against padding is that *"every padded
byte crosses two Tor legs and inflates W₂"* — a scheme wanting more than 100%
overhead is arguing against that cost analysis and should **reopen this cap
deliberately** ([rule 21](../../.cursor/rules/21-reversion-clause-discipline.mdc))
rather than inherit an absent one.

**This is enforceable only because `RF-D4` made `padding_len` explicit.** With
padding extent derived from `content-length`, a reader could not reject an
oversized declaration *before* draining it — the check would arrive after the
bytes did. The self-delimiting frame is what makes the bound a pre-allocation
test rather than a post-hoc complaint.

**`RF-D4` is the more open of the two decisions, and this is why it should be
pinned now.** `recompute_segment_r_k` has **no production consumer** — outside
`shekyl-curve-tree`'s own store operations its only caller is
`p-serve/tests/store_axis.rs:105`, a test. There is no production fetcher, so
content-addressed self-authentication is today a property of the *design*, not of
the tree. **Whatever this round pins is the definition, not a change to a shared
contract**, and the first fetcher will be written against it — one side to
change instead of two.

---

## 4. What this round does not decide

- **The settlement-outcome table schema** (§9.7 item 9) and **`EndpointUpdate`
  on the bond wire** — separate PRs, separate validation surfaces
  ([rule 19](../../.cursor/rules/19-validation-surface-discipline.mdc)).
- **Whether A5/W10 survives overall.** The `RESPONSE_BYTES` correction moved one
  end of it; the arithmetic is pinned by the restated proxy tests and the verdict
  belongs to `ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md`.
- **The prunable structure's own layout beyond its residence.** Its *residence*
  is ruled (inside `serialize_rctsig_prunable`); its field order and framing are
  this round's to draw.
