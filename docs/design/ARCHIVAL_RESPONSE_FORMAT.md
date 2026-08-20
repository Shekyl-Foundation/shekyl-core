# Serve-credit response format — design round (RF)

**Status:** OPEN — `RF-D3` and `RF-D5` **resolved and implemented** 2026-08-19;
`RF-D1`, `RF-D2`, `RF-D4` remain (the wire's own layout). Round opened 2026-08-18.
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

Kept, on the vin in the prefix — **278 B/record ≈ 7.1 GB/yr**: the record header,
`leaf_bytes`, and the 64 B Ed25519 leg. Pruned, as a **parallel structure keyed
to the vin, inside `serialize_rctsig_prunable`** — ~9,965 B: the ML-DSA leg and
`path` including the leaf chunk.

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
