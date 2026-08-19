# Serve-credit response format — design round (RF)

**Status:** OPEN. Round opened 2026-08-18.
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

**Every input below is pinned; one implementation question is open** (`RF-D5`,
§2.5 — surfaced by grounding the deletion, not by the ruling). `RF-D3` was
carried as the round's one open test
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

The KAT regeneration is the part to plan for: the nonce preimage changes shape,
so the pinned vectors change, and a pinned vector that changes without its
derivation changing is exactly what those KATs exist to catch.

### 2.5 `RF-D5` (OPEN) — **`r` does not merely delete: `block_hash(h−1)` has to arrive**

Found while grounding the deletion surface, and recorded because the ruling's
phrasing (*"the nonce's `r` term DELETES"*) reads as a pure removal and **is
not one**.

`attestation_nonce`'s first term is *replaced*, not dropped — same arity, new
source — and the new source is **chain state the verifier does not currently
receive**. `ShekylArchivalAttestationVerifyCtx`
(`shekyl-ffi/src/archival_ffi/attestation.rs:81-90`) carries `attestation_root`,
`cb_out_key`, `headers`, and `pairs`. **There is no previous-block hash**, and
Rust has no chain access at that call site — admission calls in from C++.

So the deletion implies, as one indivisible change:

| Surface | Change | Rule |
| --- | --- | --- |
| `ShekylArchivalAttestationVerifyCtx` | gains `prev_block_hash: [u8; 32]` — a `#[repr(C)]` **ABI widening** | [40](../../.cursor/rules/40-ffi-discipline.mdc) |
| The C++ admission call site | must populate it | [20](../../.cursor/rules/20-rust-vs-cpp-policy.mdc) — a boundary advance, not a C++ patch |
| Witness blob | `r ‖ count ‖ sigs` → `count ‖ sigs` | — |
| `cryptonote_config.h:444` | `32 + 8 + MAX·SIG` → `8 + MAX·SIG`, plus the `:429`/`:437` comments | — |
| Persisted-block wire | version-constant bump, CI-enforced | [42](../../.cursor/rules/42-serialization-policy.mdc) |
| Pinned nonce + witness KATs | regenerate | [30](../../.cursor/rules/30-cryptography.mdc) |

**`RF-D5` is: does `cb_out_key`'s existing readability protocol extend to the new
term, or does an unreadable predecessor hash need its own failure code?** The ctx
already models "C++ could not read this" explicitly — `cb_out_key_readable == 0`
→ `ERR_CBKEY_UNREADABLE`, *"never garbage"* — and a new required term inherits
that question rather than the answer. A field added without a readability arm
would be the one input that fails silently.

**Why this belongs in the round rather than the cut.** It is the only part of the
`r` deletion that is *not* transcription: every other surface follows mechanically
from the ruling, and this one asks a question the ruling never reached, because
the ruling was reasoning about a nonce term and not about who hands it across a
boundary.

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
