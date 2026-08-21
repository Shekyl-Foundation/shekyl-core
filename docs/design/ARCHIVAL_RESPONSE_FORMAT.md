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

### `RF-D8` — RULED 2026-08-20: the criterion is one rule, and it takes a third field

**State the rule once, generally.** `segment_subroot_rk`, `leaf_index_in_segment`
and — below — the leaf chunk all come off the wire for a single reason:

> **A value the verifier derives locally must not be transported, because
> transporting it lets the prover choose it.**

Three fields, one criterion. Stating the rule rather than enumerating the
removals is what stops a fourth being added: the next person to propose a field
answers *"can a correct verifier obtain this without the prover?"*, and if the
answer is yes the field is not a saving to be weighed, it is a defect to be
refused.

**And name what stays, so the record looks deliberate rather than whittled.**
The line is **proof versus identifier**:

| Field | Side | Why |
| --- | --- | --- |
| `c1_layers` / `c2_layers` | **kept (pruned region)** | The actual proof — the prover's claim that *its* leaf sits under `R_k`. The verifier cannot derive it, because deriving it would require the very data being proven. |
| `leaf_bytes` | **kept (vin)** | The prover's *claim*: the bytes alleged to sit at the derived index. Nothing else supplies it. |
| `segment_subroot_rk` | **off** | Derived: `LeafStore::frozen_segment(shard_id)`. |
| `leaf_index_in_segment` | **off** | Derived: `challenge_leaf_index(…)`. |
| leaf chunk | **off** | Derived: the verifier reads it from its own store (below). |

#### The leaf chunk — `CR-D2`'s term, and why it is reopened rather than rebuilt

`CR-D2` priced **4,864 B** of leaf chunk as on-wire cost, on the stated basis
that *"a verifier can neither run without it nor derive it, so it is
transmitted."* **That premise is false at source.** The production verifier
derives it:

```text
blockchain.cpp:5421-5428
  chunk bounds  <- shekyl_archival_challenge_leaf_chunk_bounds(shard_id, leaf_index)
  chunk bytes   <- m_db->get_curve_tree_leaf_chunk(chunk_first_leaf, chunk_leaf_count, buf)
  ctx.leaf_layer_scalars_ptr = buf
```

The node reads the chunk from its **own LMDB** and hands it to the FFI through
`ctx.leaf_layer_scalars_ptr`; it is not parsed from the vin, and
`SegmentPathOpening` never had a field for it. The surrounding comment supplies
the soundness argument itself — a frozen segment's leaves are immutable, so the
live rows *are* the as-of-`H_fire` chunk.

**A ruling whose premise is refuted is corrected, not overridden.** The
partition `CR-D2` established is unchanged and remains correct; what moves is one
term inside it. `CR-D2` is not being re-litigated on its merits — its stated
basis simply does not hold against the code.

**How the error entered, recorded because the round has now made it twice.**
The term was priced against the **served payload**, where transmitting leaf bytes
*is* the proof of possession, and carried into the **on-chain record**, where the
verifier reads its own store. Two artifacts, one term. The same
two-artifacts-conflated mistake produced the shared-boundary premise corrected
before §3.5 was drafted — which is why `RF-D4`'s header now says which wire it
governs.

**Building `A` to the uncorrected spec was the alternative, and it was rejected
for a reason stronger than thrift.** A serializer writing 4,864 B that the
verifier at `:5428` ignores is not a suboptimal record — it is precisely the
defect `RF-D6` removed two fields to prevent: a prover-supplied value a correct
verifier must disregard, sitting in the record, inviting use. On a
genesis-frozen surface, landing it to fix later means shipping that invitation
for the duration.

#### The arithmetic, pinned here; the verdict is not this document's

| Term | `CR-D2` | Corrected |
| --- | ---: | ---: |
| leaf chunk | 4,864 | **0** |
| `c1_layers` / `c2_layers` | 1,792 | 1,792 |
| `ml_dsa_countersignature` | 3,309 | 3,309 |
| kept side (vin) | ~278 | ~230 (`RF-D6`) |
| **whole record** | **~10,243 B** | **~5,331 B** |

≈ 262 GB/yr → ≈ **136 GB/yr**, and the pruned side loses its single largest
term. **Whether A5/W10 survives is not decided here** — the arithmetic is pinned
in this table and the verdict belongs to
[`ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md`](ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md),
the same handling the `RESPONSE_BYTES` correction received. A wire round does not
re-rule the economics.



**Pruned, keyed to the vin, inside `serialize_ctsig_prunable` — ~5,101 B**

| Field | Bytes |
| --- | ---: |
| ~~leaf-chunk scalars~~ | ~~4,864~~ → **0** (`RF-D8`: verifier-derived) |
| `c1_layers` / `c2_layers` (`(18 + 38) · 32`) | 1,792 |
| `ml_dsa_countersignature` | 3,309 |

The leaf chunk is struck by [`RF-D8`](#rf-d8--ruled-2026-08-20-the-criterion-is-one-rule-and-it-takes-a-third-field):
the verifier reads it from its own store (`blockchain.cpp:5428`), so
transporting it would let the prover choose the set its leaf is "in" — the same
defect `RF-D6` removed two fields to prevent.

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
counts, so the precedent for deriving rather than carrying is in the signature it
will be written into.

**Corrected 2026-08-20 — the derived count is not one of the four arguments, and
artifact A must widen the signature.** The precedent holds, but the specific
value does not: `serialize_rctsig_prunable(ba, type, count_spend_inputs(vin),
vout.size())` is passed the count of **spend** inputs, and a serve-credit vin is
explicitly *not* a spend input (`blockchain.cpp:3630` skips the whole spend arm
for it — `CR-D1`). So "one entry per serve-credit vin, no count field" gives the
deserializer a length it **cannot** currently see. Artifact A therefore widens
`serialize_rctsig_prunable` by one argument, and every call site widens with it —
including `tx_prunable_region_sole_occupant.cpp`'s
`prunable_reserialized_size`, which reproduces the production call.

Found while checking the #509 tripwire against `RF-D1`'s placement, before
writing artifact A rather than during. **The tripwire itself is better than
merely compatible**: it asserts *tail length equals re-serialized length*, so a
parallel structure added **inside** `serialize_rctsig_prunable` grows both sides
and passes — and its failure message already directs new prunable bytes to
exactly where `RF-D1` puts them. It asserts the equivalence property, not the
three blocks that happened to exist when it was written.

**The leaf chunk is pruned-side by construction** (`CR-D2`), and the tidiness
hazard is why it is written down: `leaf_bytes` is kept-side and the leaf chunk is
the same conceptual object, so grouping them is the unremarkable move and
reintroduces ~124 GB/yr. One field **identifies** the record; the other **proves**
it. Only the first survives pruning.

**`ServeCredit::validate` is deleted, and that is a consequence rather than an
oversight.** After the split every kept-side field is fixed-width — two arrays,
two varints, a `[u8; 64]` — so there is no length a caller could get wrong and
nothing for an in-memory bound check to catch: a value of the type that exists
is one that re-parses. A `validate` returning `Ok(())` unconditionally would be
**worse than absent**, reading as "checked" at every call site while asserting
nothing — [rule 47](../../.cursor/rules/47-gate-subject-assertion.mdc)'s class,
and this instance would have been *created* rather than inherited. The bounds it
used to carry belonged to the branch layers and the signature container; both
moved to `ServeCreditPruned::validate`, where those fields went.

#### Tripwire prediction for the `serialize_ctsig_prunable` widening — written before the run

The remaining C++ work adds the pruned pass-record array to
`serialize_ctsig_prunable` and widens its arity by the serve-credit vin count.
`tests/unit_tests/tx_prunable_region_sole_occupant.cpp` runs against that
change, and **the expected outcome is recorded here in advance**:

> **Expected: GREEN, all three arms.** The new block is written *inside*
> `serialize_ctsig_prunable`, so both paths of
> `calculate_transaction_prunable_hash` see it by construction — the blob path
> hashes the tail wholesale, the re-serialize path emits the same bytes, and
> `tail == reserialized` continues to hold. The serve-credit arm's pinned tail
> grows from **3 bytes** to `3 + Σ record sizes`, so that literal moves *with*
> the change; the equality assertion does not.

**A red result is a stop-and-think, not something to accommodate.** Red would
mean the region's **extent** moved rather than its **contents** — i.e. bytes
landed after `ctsig_prunable` instead of inside it, which is precisely the
divergence the file exists to catch and precisely what `CR-D2`/`RF-D1` ruled
against. The remedy in that case is to move the write, never to adjust the
assertion.

**Why the prediction is written down at all.** Three times this round a check
passed while measuring the wrong thing — the `CTTypeNull`-only tripwire arm, the
serve-credit equivalence test that asserts verdicts rather than bytes, and the
`cargo check` that could not see a clippy-only lint. **A green nobody predicted
is indistinguishable from a vacuous one.** Committing to the outcome first is
what makes the result evidence rather than reassurance.

One measurement hazard already found here and worth carrying: the arm's tail was
first read as 4 bytes, then 3, then 4, because `curve_trees_tree_depth` was
indeterminate in the fixture and the stanza **VARINT-encodes** it — an unset
value changes the tail's *length*, not merely its content. Any fixture used to
pin a byte count must leave no field in the encoded region unset.

#### The preimage keeps its bytes, and that is what makes `RF-D6`/`RF-D8` sound

`segment_subroot_rk` and `leaf_index_in_segment` leave the **wire** and stay in
the **signature preimage**, supplied by the verifier from its own derivation
(`LeafStore::frozen_segment`, `challenge_leaf_index`). The consequence is
stronger than the byte saving:

> A prover that lies about either value cannot produce a signature that
> verifies, because the verifier builds the preimage from what it **derived**,
> not from what it was **told**.

Transporting them would have let a prover choose the values *and* sign them
consistently. Deriving them makes the signature bind the verifier's view — which
is why this is a soundness change rather than a thrift.

**They are parameters of `signature_preimage`, not fields a caller fills in.**
Leaving them on the struct for the caller to populate would recreate exactly the
hazard `RF-D5` rejected when it refused a caller-populated readability flag: a
field someone must remember to set is a field someone will forget — and during
`RF-D5`, five C++ call sites forgot precisely that. As parameters, the compiler
demands them everywhere.

**Which pinned vectors move, and which must not.** The distinction matters
because "regenerate the fixtures" is the instruction that quietly destroys a
KAT's value:

| Vector | Moves? | Why |
| --- | --- | --- |
| `wire_hex` | **yes** | The layout genuinely changed — `RF-D6`/`RF-D8` removed transported fields. A vector describing the old layout is describing a format that no longer exists. |
| `signature_preimage_hex` | **no** | Byte-identical by construction: same terms, same order, different *source* for two of them. |
| the pinned signature | **no** | Follows the preimage. |

So the only regenerated vector is the one whose subject deliberately changed,
and the vectors that would be **unverifiable if regenerated** — the cryptographic
ones, checkable only against the code that produced them — are preserved. That
is the same property preserving `r`'s arity bought in `RF-D5`, and it is worth
checking explicitly on any future field change rather than discovering it after
a bulk regeneration.

**Landed 2026-08-20, and the FFI confirmed the premise before a line changed.**
`shekyl_archival_verify_serve_credit_vin` already received the registry's
`R_k` from C++ (`ctx.registry_segment_subroot_rk`, populated at
`blockchain.cpp:5455`) and **compared the wire value against it**; it likewise
checked the wire leaf index against `challenge_leaf_index`. Both checks could
only ever confirm what the verifier already held — while leaving prover-chosen
copies in the record for a less careful implementation to trust. Now there is
nothing on the wire to compare: the derived values feed path verification and
the preimage directly.

Deleted with the fields, under [rule 15](../../.cursor/rules/15-deletion-and-debt.mdc):
`verify_leaf_index` (its only possible input was the value it would check
against), `VerifyError::LeafIndexMismatch`, and FFI codes **6** and **7** —
retired, not reused, so an old log line cannot be misread as a new condition.

**The fixture split held exactly as predicted.** Regenerating
`gate2_serve_credit_kat_v1.json` moved `wire_hex` (both sections) and added
`segment_subroot_rk_hex` to the integration record; `signature_preimage_hex`
and every signature pin came back **byte-identical**. The one failure the
regen surfaced was a test-authoring error, recorded because it is the class
this section warns about: the integration block's preimage was briefly built
with the *opening* section's `R_k` — a different segment's root that happened
to share the name `rk` — and the signature check failed honestly. Verifier
inputs are now bound under `int_*` names at the point they are derived.

**`leaf_bytes` came off too, and the stronger check it enabled caught a fixture
error the weaker one could not.** The verifier must read the whole leaf chunk to
verify at all (`blockchain.cpp:5428`, and the daemon's LMDB never prunes curve
tree leaves), so it already holds the challenged leaf: `chunk[index − first]`.
Transporting it was a prover-supplied value the verifier had to check against
its own data — `RF-D8`'s class, applied a fourth time. The old check
(`leaf_bytes_in_layer`) only asked whether the supplied bytes matched *some*
leaf in the chunk and **never bound them to the challenged index**; the verifier
now selects by derived offset (`path::challenged_leaf_bytes`), which is strictly
stronger.

Regenerating the gate-2 fixture under that check failed: the integration
substrate's signed `leaf_bytes` was the **founder's** leaf, wherever it sat in
the chunk, not the leaf at the derived challenge index — a latent fixture error
the membership check had accepted for the life of the fixture. The substrate
now derives the challenged leaf from the chunk at the offset. **This is the one
place a signature pin legitimately re-signed**: the preimage input was wrong,
not the construction, and the integration keypair persists in the fixture so the
new signature is verifiable against it. The synthetic wire anchor, signed over a
fixed message, is untouched. Kept side after all four removals: `p_id` 32 ‖
`shard` ‖ `epoch` ‖ Ed25519 64 ≈ **99 B**.

### `RF-D10` — RULED 2026-08-20: the C++ side holds an opaque blob, not a typed struct

**The question that produced it:** *why is this going into C++ instead of
Rust?* The answer is that it should not have been. [Rule 20](../../.cursor/rules/20-rust-vs-cpp-policy.mdc)
and [rule 40](../../.cursor/rules/40-ffi-discipline.mdc) say new code advances
the FFI boundary rather than thickening C++, and the codebase already had the
pattern: `txin_archival_reward_emission` is an **opaque `canonical_bytes`
blob** whose only parser is Rust — C++ never reads inside, and consensus code
that needs fields gets them through an FFI extract. The serve-credit vin
predated that pattern and kept nine typed C++ fields; artifact `A` was about to
widen them *and* add a second typed struct for the pruned half. Since `A`
already changes every byte of this vin, this was the cheapest moment the
migration would ever have.

**What the C++ holds now.**

| Surface | Before | After |
| --- | --- | --- |
| `txin_archival_serve_credit_response` | nine typed fields, C++ codec | `std::vector<uint8_t> canonical_bytes` (tag included), transport guard only |
| pruned half | — | `CtSigPrunable::serve_credit_pruned: vector<vector<uint8_t>>`, one opaque record per serve-credit vin, each length-prefixed |
| `(P, shard, E)` for DB bits, pool keys, block-unique keys | field reads at four sites | one helper, `get_archival_serve_credit_key`, over `shekyl_archival_serve_credit_extract` — given the **tagged blob whole**, as the emission extract is; C++ never slices the tag off, and an empty blob is a wire error, not a null-pointer error (review, 2026-08-21) |
| challenge leaf index | read off the vin | `shekyl_archival_challenge_leaf_index` (RF-D6) |
| admission | C++ path-bound checks + typed re-serialisation into the FFI | `shekyl_archival_verify_serve_credit_vin(kept, pruned, ctx)` — every structural bound is the Rust parser's |
| JSON / boost archives | field-by-field | the blob, as for the emission vin |

**Why each pruned record carries its own byte length, and why that is not the
count field `RF-D1` refused.** C++ must hand the FFI *this vin's* slice of the
pruned region, and it cannot find record boundaries inside bytes it does not
parse. So each record is length-prefixed — the same role `canonical_bytes`'
length plays on the kept side. There is still **no record count** on the wire:
the count is the serve-credit vin count, and `shekyl-wire` checks blobs == vins
structurally. A per-record length is a transport delimiter for an opaque
payload; a count would have been a `MUST`-equal check on a value the
transaction already determines.

**It also deleted a duplication this round had been carrying without noticing.**
`shekyl-wire`'s typed `ServeCredit` and `shekyl-archival-retention`'s
`ArchivalServeCreditResponse` were two codecs of one layout. `shekyl-wire` now
models the C++ *transport* of the blob — tag, length, ceiling — and validates it
by shape, exactly as it does the emission arm; the interior has one parser.

**Pruned weight stays deterministic — conditionally, and the condition is
stated.** `get_pruned_transaction_weight` must reconstruct a tx's full weight on
a pruned node, and for a spend it can because the pruned parts have fixed sizes.
A serve-credit record looked variable — but for a **frozen** segment at
`SEGMENT_LAYER_J = 2` the opening of any leaf is one Helios layer of 18 and one
Selene layer of 38 scalars, so the record is **5,105 B** and **5,107 B** with
its length prefix (`ARCHIVAL_SERVE_CREDIT_PRUNED_RECORD_BYTES`, static-asserted
in C++, pinned in Rust at the constructed production geometry). The determinism
**relies on admission**: `verify_segment_path` checks the record against the
registry's frozen-segment `R_k`, and a record of any other shape cannot hash to
it, so every admitted serve-credit tx carries records of exactly this size.
Recorded because the first Rust pin borrowed the CT-2 *test* substrate — a small
tree whose record is 3,440 B — and would have pinned the wrong number; the test
tree does not exhibit the production invariant, the production rule does.

**The equivalence mirror re-synced, which is what the audit exists to force.**
`serve_credit_decisions` modelled three gate steps that no longer exist: C++
path-bound pre-checks (now the Rust parser's, surfacing as `FfiVerifyFailed`),
the typed-vin re-serialisation and tag pin (gone with the typed vin — the tag is
the serializer guard's, enforced at tx parse), and a wire leaf index (derived).
Two steps joined: the blob parse and the pruned-record ceiling. Fixture vectors
B-02..B-05 now expect the FFI parse failure, B-17 became a zero-geometry
derivation refusal (the only way an out-of-range index remains reachable with
the index derived), B-19..B-21 were retired as unrepresentable, and B-00/B-00b
cover the two new steps. Both legs stayed green.

**The counterparty earned its keep on the first end-to-end run.** `RF-D9` said
the byte-parity work mattered because, unlike `B`, `A` has a counterparty — the
C++ oracle. The first C++ acceptance run failed with `PQC_VERIFY` while every
Rust KAT passed: the FFI computed the challenged leaf's chunk offset as
`leaf_index − first_leaf_position`, subtracting a **global** tree position from
a **segment-relative** index, so it selected leaf 0 of every chunk for every
shard past the first and verified each signature against the wrong leaf. The
Rust KATs had the arithmetic right — locally, each in its own copy. Three copies
of one formula, one wrong, and only the path that crossed the language boundary
could see it. The arithmetic now has one home beside
`challenge_leaf_chunk_bounds` (`challenged_leaf_offset_in_chunk`), used by the
FFI and both KATs.

**Transport ceilings, twinned — and the rule for when a twin is licensed.**
`ARCHIVAL_SERVE_CREDIT_VIN_MAX_BYTES = 117` lives in `cryptonote_config.h` and
`shekyl-wire`; the pruned-record ceiling `1 053 185` lives in
`rct::CtSigPrunable` (where it is **enforced**) and `shekyl-wire`. Each pair is
pinned to the same literal by static/const-assert, so moving one side fails
the other.

Review (2026-08-21) removed a third copy of the pruned ceiling from
`cryptonote_config.h`, and the reason generalises: **a deliberate duplicate is
justified by a boundary that cannot be crossed, not by one that would be
inconvenient to cross.** Rust↔C++ cannot share a header — that twin is
licensed, as `shekyl-levin`'s copy of the witness cap is licensed by a crate
that refuses the dependency. A C++ header declining to include another C++
header is not that kind of boundary; the copy that only *declared* was the one
to delete, and the site that *enforces* keeps the number. The pin is a
tripwire: it makes a duplicate safe, not warranted.

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

### `RF-D9` — FOUND 2026-08-20 while building `A`: the serve-credit tx cannot be serialized by the C++ oracle

**Measured, not read.** The tripwire's new serve-credit arm failed on its first
run — not at its assertion, but because `t_serializable_object_to_blob` returned
`false`. Two experiments isolated it:

```text
empty pqc_auths                 -> serialize = 0   (FAILS)
pqc_auths.size() == vin.size()  -> serialize = 1   blob = 3636  unprunable = 3633  tail = 3
```

**Two requirements that cannot both hold:**

| Site | Requires |
| --- | --- |
| `cryptonote_basic.h:621` (write path) | `pqc_auths.size() == vin.size()` |
| `tx_verification_utils.cpp:118` (verify) | `tx.pqc_auths.empty()` |
| `blockchain.cpp:3746` (verify) | serve-credit `pqc_auths` **must be empty** |

The shape consensus accepts is the shape the serializer refuses to write. C++ can
**parse** a serve-credit tx — the EOF-tolerant branch at `:609` clears
`pqc_auths` — but can never **produce** one; the `if constexpr` guarding that
tolerance is `binary_archive<false>`, read-only.

**Why it survived: the asymmetry is the concealment.** The read direction is
exercised by anything that ingests a block; the write direction had no
exerciser, because nothing in C++ constructs a serve-credit tx. A defect on a
path nobody walks leaves no trace until someone walks it.

**It reframes the divergence rather than adding to it.** The natural reading of
"Rust writes 0 prunable bytes, C++ writes 3" is that Rust drifted from a working
oracle. It did not: the serve-credit wire has **never round-tripped in C++ at
all**. `shekyl-wire`'s own comment — *"the live-oracle byte/hash parity for the
fee-only/serve-credit shape … is validated when those post-genesis blobs are
capturable"* — was pointing straight at this, and deferred to a condition that
would never arrive on its own.

**Only the write direction is claimed.** Whether C++ can read Rust's fee-only
bytes (EOF arriving before the prunable stanza) is untested and is not asserted
here.

**What this means for the byte-parity KAT, which is not what it first appears.**
"Rust and C++ disagree" invites the obvious remedy — take C++ as the reference
and match it. **That remedy is not available**, and the measurement is what rules
it out: C++ can parse but never produce, so there is no C++-authored byte string
of this shape to match *even if matching were wanted*. There is no prior art
here, only an unexercised path.

So the KAT's job is **not to restore agreement but to establish it for the first
time**, and the consequence is worth stating plainly: **the format is genuinely
free.** Nothing about the current bytes is load-bearing — no deployed node has
ever written them, no stored blob contains a C++-authored instance, and the
"compatibility" that normally constrains a wire change has no referent. `A` may
choose the layout on its merits. Recorded because the opposite assumption is the
cheap one, and it would silently import a defect as a constraint.

**Rule 47's third independent instance, and its cleanest.** The class now has
three sightings from unrelated arcs — RandomX T18, the `CTTypeNull` tripwire arm,
and this. A rule drawing instances from independent arcs is one that holds. This
is the sharpest form of it: the gate was **not weak** — it ran, it passed, it
tested something real. It measured a *different quantity than its name implied*.
"Equivalence" named byte agreement; the assertions were verdicts over a JSON
fixture. No amount of strengthening the verdict assertions would ever have
surfaced a byte divergence.

**A third gate, found in review (2026-08-20, PR #522 Copilot), and the defect
underneath it was duplication.** The write fix above landed in the **full**
serializer. `transaction::serialize_base` — the **pruned** form, which is what
LMDB stores (`db_lmdb.cpp:1055/1068`) and what pruned RPC responses carry —
repeated the `pqc_auths` encoding verbatim and kept the `size() != vin.size()`
refusal. So after the fix a serve-credit tx was writable and **still
unstorable**: the node could produce it and could not persist it.

Two copies of one encoding drifted *inside a single change*, which is the
failure mode [rule 15](../../.cursor/rules/15-deletion-and-debt.mdc) names: a
duplicate is not synchronised, it is deleted. Both serializers now call one
member, `serialize_pqc_auths`, and the exemption lives in exactly one place. The
suggested fix — "mirror the typed omission in `serialize_base`" — would have
kept the duplicate and with it the next drift.

**A fourth review finding on the same function, and it is about what a
serializer *is*.** The single-encoding helper cleared `pqc_auths` for the
serve-credit shape on **both** paths. On the loading path that is correct —
nothing is read for this shape, so "read zero elements" is the deserialisation
of an absent array. On the **saving** path it turned the serializer into a
normaliser: a consensus-invalid object (serve-credit vins plus a non-empty
`pqc_auths`) was silently rewritten and emitted as the bytes of a *different,
valid* transaction — through a `const_cast`, so the caller's `const` object was
mutated. The pre-`RF-D9` code refused the mismatch; the refactor lost that. **A
serializer is a faithful encoder, never a validator that rewrites its input**:
save refuses, load clears, and the tripwire's refusal arm asserts the object
comes back untouched from both serializers.

**Prediction for the tripwire's new pruned-round-trip arm, recorded before the
run:** GREEN, with `serialize_base`'s blob **byte-equal to the unprunable prefix
of the full blob**. Both serializers now emit the prefix through the same
helper, so agreement on the boundary is by construction; red would mean the two
paths still diverge somewhere *other* than `pqc_auths`, and would be a stop.

**CLOSED 2026-08-21 — the shape round-trips in C++, and the two languages
agree on its bytes.** Both serializer gates are fixed (typed off the vin), and
the parity RF-D9 said `A` owed now exists as a KAT with **two fixtures, each
owned by its producer**: the gate-2 fixture carries the two blobs (retention
codec), `rust/shekyl-wire/tests/fixtures/serve_credit_tx_parity_v1.json`
carries `shekyl-wire`'s serialization of the whole transaction built around
them (3,585 B) and its tx id, and
`tests/unit_tests/archival_serve_credit_integration.cpp` builds the same
transaction in C++, serializes it, asserts byte-equality with the pin, parses
the pin back, and asserts the tx id agrees. The first C++ acceptance run found
a real cross-language defect before this KAT existed (the chunk-offset
arithmetic, recorded under `RF-D10`); with the KAT in place that class fails at
build time on both sides.

**`A` is the right place to fix it, not a separate slice.** `A` rewrites this
shape entirely — kept side, pruned side, and the serializer's arity. A fix
landed first would be bytes `A` immediately replaces. The cross-language
byte-parity KAT `A` adds is what converts "never exercised" into "cannot
regress".

**The KAT pins the post-`A` format, never an intermediate.** Item 4 (the write
path) is separable on its own validation surface — *can C++ produce a valid
serve-credit tx* is answerable without items 1–3 — but a parity vector captured
against the pre-`A` layout would pin bytes that never ship. It lands with the
finished shape or not at all.

**The general form, because this is the third sighting of the class.** Both
sides identified the serve-credit shape **by absence** — C++ by whether the
`if constexpr` write branch fired, Rust by whether the stream hit EOF after the
base. Both break for one reason: `RF-D1` gives the shape a prunable region, so
*"nothing follows the base"* stops being true.

> **A shape identified by absence becomes unidentifiable the moment the shape
> acquires content.**

That is the same class as `WITNESS_PREFIX_LEN` (a name asserting contents it did
not have) and the `CTTypeNull`-only tripwire arm (a test whose surviving arm
never ran its own assertion): **a property held by circumstance, invisible until
the circumstance changes.**

**Four sightings in this one change**, which is what makes it a form rather than
a coincidence:

| Site | Inferred the shape from | Failed as |
| --- | --- | --- |
| C++ write (`cryptonote_basic.h`) | whether the `if constexpr` branch fired | could not serialize at all |
| C++ parse (`expand_transaction_1`) | `bulletproofs_plus` being absent | *"Failed to expand transaction data"* |
| Rust read (`Ct::read`) | EOF after the base | would misparse `pqc_auths` |
| Rust validate | `Some(prunable)` ⇒ spend/bond-post | *"spend/bond_post has 0 output(s), needs >= 2"* |

**The failures are MISATTRIBUTED, and that is what makes them expensive.** The
general form above says these defects are invisible; it does not convey that
when they finally appear, they appear **wearing someone else's vocabulary**. The
fourth row is the clearest case: a defect in *shape inference* surfaced as a
complaint about *output count*. A reader debugging
*"spend/bond_post has 0 output(s), needs >= 2"* would examine output
construction — reasonably, and for a long time — because nothing in the message
mentions shape, prunable regions, or serve-credit.

An inferred-shape defect surfaces at whatever validation happens to run first
and is described in that validation's terms. So the search starts wherever the
message points, which is never where the defect is.

**A fifth instance landed during this change's own test sweep, and it is the
sharpest of the five for a reason the other four lack.** A test fixture
(`multiple_serve_credits_allowed`) identified the fee-only shape by
`prunable: None` — absence again. Normalizing that fixture for `RF-D2`, the
struct-literal half was updated **because the compiler forced it** (removed
fields fail to compile), while `prunable: None` stayed **well-typed and silently
changed meaning** — from "the fee-only shape" to "a record-count disagreement".
Nothing forced that half, and the passing compile read as confirmation the edit
was complete.

> **Any change that alters what a value means without altering its type has this
> property: the compiler is a collaborator on the visible half and blind to the
> other, and its silence is actively misleading rather than merely unhelpful.**

The other four instances were caught by tests. This one was caught by a test
**after** passing a compile that felt like completion — which is the mechanism
to remember, because "it compiles" is the strongest false signal in a
representation change.

The failure itself was the `RF-D1` coupling working: two serve-credit vins, zero
records, refused by the same check
(`a_record_count_disagreeing_with_the_vin_count_is_refused` asserts the
deliberate form of it). The negative control fired on a real disagreement
introduced by accident — a control demonstrating it *can* fire, which is what
[rule 47](../../.cursor/rules/47-gate-subject-assertion.mdc) asks of a gate and
what three checks this round could not show. The fixture now carries its two
records and is stated as the coupling's positive control.

**That is the argument for the full round-trip test**, and it is not "more
coverage": no unit test of the codec would have produced this failure, because
each unit is individually correct. Only exercising the whole post-`RF-D1` shape
— construct, serialize, parse, validate — puts the inference in contact with the
content that breaks it. The repair on both sides is the same — type the shape
off the **vin**, which is already parsed and is what the shape actually *is*,
rather than off how far a stream has been consumed.

**This is why [`ServeCreditPruned`] is its own type rather than an optional
tail.** An `Option<...>` appended to the prunable region would re-create exactly
the defect: presence would again be a positional fact, inferred from whether
bytes remain. A named type, sized from the serve-credit vin count, makes the
shape **self-identifying** — the reader knows how many records to expect before
it reads a byte of them, and "how many" comes from the transaction rather than
from the stream.

**Prediction, stated before the fix is written.** The expected repair is to let
the write path accept `pqc_auths.empty()` for the serve-credit shape, mirroring
the read path's existing EOF tolerance — i.e. a change to the `if constexpr`
branch **condition**, not to the field layout. If that is what it is,
`unprunable_size` does not move and the #509 tripwire stays **green**.

**If the tripwire goes red, stop rather than accommodate.** Red would mean the
fix changed the prunable region's *extent* instead of its write condition, which
is a different repair with different consequences, and the tripwire saying so is
the whole reason it exists.

The prediction is recorded because of this round's own history: **a green result
nobody predicted is indistinguishable from a vacuous one.** Three times this
round a check passed while measuring the wrong thing — the `CTTypeNull`-only
tripwire arm, the equivalence test above, and the `cargo check` that missed a
clippy-only lint.

**Rule 47, again.** `archival_serve_credit_equivalence.cpp` is a cross-language
equivalence test *for this exact shape* that asserts consensus **verdicts** over
a JSON fixture and never full-tx bytes — so it could not detect a byte
divergence in the thing it is named for. The gate did not assert its own
subject. The byte-parity arm is owed regardless of how the rest of `A` lands.

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

**`varint` names one encoding, and this document has to say which.** It is the
workspace varint — `shekyl_curve_io::{write_varint, read_varint}`, the same
encoder the archival wire modules use: unsigned **little-endian base-128**, seven
payload bits per byte, high bit set on every byte but the last, and **canonical**
(a continuation byte followed by a zero group is refused, so one length has
exactly one encoding). Pinned here rather than left implicit because of the
no-counterparty property this section closes on: the first fetcher is written
from this grammar, and "varint" alone does not determine bytes. Worked example,
which the implementation carries as a hand-derived test vector: a full segment
with no padding is `88 CB 01 00` — `25 992 = 8 + 75·128 + 1·16 384`, then a
single zero byte.

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

**Implemented 2026-08-20 — `shekyl_curve_tree::served_frame::ServedFrameHeader`.**

**Where it lives, and why not with the server.** The encoder is in the serving
path; the decoder will be in a fetcher that does not exist yet. Putting the codec
in `shekyl-p-serve` would make every future fetcher depend on the *server* — the
wrong direction — so the discriminating question is which crate a reader must
already have. A reader cannot verify a response without `recompute_segment_r_k`,
so **`shekyl-curve-tree` is in every fetcher's dependency graph by necessity**;
every other home either adds an edge or declares a second `LEAF_BYTES`. It sits
at the crate root beside `segment.rs` rather than under `store/`, because the
frame is a property of the segment *format* and a fetcher never touches the redb
backend. `LEAF_BYTES` was promoted out of `redb_backend.rs` (where it was a
private `128`) into `segment.rs`, derived as `SCALARS_PER_LEAF · 32` — a leaf
**is** four Selene scalars, so its byte width is that fact, not a second number.

**Write-zero is enforced by construction, not by a rule.** `for_segment` takes no
padding argument at all: it is not that callers must remember to pass `0`, it is
that there is nothing to pass. When a scheme lands, its PR adds the parameter —
that change *is* the reopening criterion ([rule 21](../../.cursor/rules/21-reversion-clause-discipline.mdc)),
rather than a flexibility provisioned ahead of the decision it serves.

**The forward half of the streaming constraint, stated on the field.** The header
is computable without a store read *today* because `leaf_count` comes from the
segment record and `padding_len` is zero. That is a property of the current
implementation, and left there it would die silently with the first padding
scheme. It is therefore written as a constraint on `padding_len` itself: **the
value must be decidable without a store read**, because the field is encoded in
the leading header and a decision needing leaf bytes could not be made in time.
A scheme requiring one is a format change, not an implementation detail — the
same move as the *validated-predecessor* constraint on `RF-D5`'s nonce term, and
for the same reason: an invariant held by circumstance has no name and no test.

**`RF-D7`'s bound is unforgettable rather than merely documented.** Both checks
run inside `ServedFrameHeader::read`, before it returns, so **the only way to
obtain the two lengths is to obtain them already validated** — a caller cannot
allocate against an unchecked `padding_len` because the check is what produces
the value. The leaf-count bound is enforced *first*, which also keeps
`leaf_count × LEAF_BYTES` from overflowing; that ordering dependency is stated at
the site rather than left for a reader to reconstruct.

**What the tests can and cannot prove, given no counterparty.** Round-tripping the
encoder against the serve side's own parser proves internal consistency, not that
an independent implementation can read the format. So the frame carries a
**hand-derived** vector — `88 CB 01 00` for a full unpadded segment, computed from
the grammar rather than from the encoder — which is the only test that checks the
implementation against the *spec*. `p-serve/tests/store_axis.rs` was rewritten to
read the frame the way a fetcher will (`ServedFrameHeader::read`, then slice at
`segment_bytes()`) rather than assuming the body starts at byte zero, making it
the nearest thing to a reference reader that exists. The first real fetcher is
still the actual validation.

**One consequence worth naming: an unframeable body is now unservable.** The frame
declares a leaf count, so bytes that are not a leaf array have no representable
header; `ShardBody::flat` returns `None` for them and the endpoint renders the
ordinary shared 404. Before the frame, a flat body could be any length. That
latitude is what buys "multiple of `LEAF_BYTES`" as a *structural* property
instead of a validity rule written in prose.

**[Rule 42](../../.cursor/rules/42-serialization-policy.mdc) — checked for
artifact B, and again there is no instance.** §2.7 ran this for the attestation
witness blob; the served frame is a *different* artifact and inherits nothing, so
it is checked on its own terms and the answer recorded rather than assumed. The
policy binds a **persisted-block wire change** to a version-constant bump. This
frame is neither persisted nor a block: it is a transport payload, held only for
the life of one response, and its integrity is **content-addressed** — a witness
reconstructs `R_k` from the bytes it received and compares against the
chain-committed record, so a malformed or altered frame fails verification
outright rather than being mis-parsed under the wrong schema version. There is no
stored artifact whose interpretation could drift, which is the hazard the version
constant exists to prevent. No bump is owed; written down so nobody adds one.

**Scope note — superseded 2026-08-20: `A` and `B` land together.** This section
first recorded them as separate validation surfaces
([rule 19](../../.cursor/rules/19-validation-surface-discipline.mdc)) — different
crates, different tests, a C++ serializer `B` never touches. **The maintainer
ruled otherwise, and the reason overrides the rule-19 reading:** the kept/pruned
boundary is the decision under review, and a reviewer can only check it with both
halves visible. A single-artifact PR does not complete the move. Recorded as a
reversal rather than edited away, because the rule-19 argument was correctly
applied to the wrong question — validation surfaces were separable, the *decision*
was not. And the
defect claim here is the narrow one — the served frame **avoids introducing** an
unbounded-padding drain, rather than closing a landed one: `shekyl-p-serve`'s
existing `MAX_DRAIN_BYTES` bounds a peer's unread **request** bytes before close
(`close_gracefully`), which is a different path entirely.

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
