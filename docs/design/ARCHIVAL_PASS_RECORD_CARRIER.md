# Pass-record carrier — design round (CR)

**Status: RULED 2026-08-18.** Opened 2026-08-17. `CR-D2` resolved — the round is
a **record partition**, not a signature split (`CR-O1` rejected, `CR-O1′`
survives). `CR-D1` resolved by reading — **no tension**; `pqc_auths` is
forbidden, not merely occupied, so the kept leg stays on the vin. The carrier has
a **shape and a placement**; see §3.1.
**Scope:** where the pass record's kept and pruned parts live in the tx wire.
**Blocks:** the response-format round (framing depends on this answer).
**Process:** [`26-sub-pr-design-discipline`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)
— consensus-shaped, genesis-frozen, so design closure precedes any cut.
Disposition IDs in this round are **`CR-D1` … `CR-Dn`**, registered at birth
per [`94-tracking-index`](../../.cursor/rules/94-tracking-index.mdc).

This document **opened** the round on 2026-08-17 and now **carries its ruling**.
The two are kept in one file deliberately: the findings that moved the framing
are what make the ruling checkable, and splitting them would leave a verdict
whose reasoning lives elsewhere.

**Verification stamps are per-section, because the round accreted over three
days and a single stamp would be wrong for two thirds of it.** §0 (`CR-F1`…`F3`)
and §1–§2 were verified at source on **2026-08-17** against **`c92f10ed4`**;
`CR-D2` (§2, the segment arithmetic and the `proxy.rs` correction) and `CR-D1`
(§0) on **2026-08-18** against **`99a2f4f8c`**. Nothing below is transcribed
from discussion.

---

## 0. What changed when the round was grounded

The round was scoped as *"does the pass record's kept header and prunable
countersignature live in one vin-like structure with a defined split, or does
the signature ride a separate prunable container?"* Reading the substrate
answers part of that and invalidates part of the framing. Three findings, in
descending order of how much they move the question.

### CR-F1 — The pass record is **already a live vin**. The question is not *whether*, it is *what moves*

`txin_archival_serve_credit_response` exists, is in the `txin_v` variant with
dense tag `0x02`, and is **read by consensus**:

| Site | What it does |
| --- | --- |
| [`cryptonote_basic.h:278-301`](../../src/cryptonote_basic/cryptonote_basic.h#L278-L301) | the struct + its `BEGIN_SERIALIZE_OBJECT` |
| [`cryptonote_basic.h:334`](../../src/cryptonote_basic/cryptonote_basic.h#L334) | in `txin_v` |
| [`cryptonote_basic.h:989`](../../src/cryptonote_basic/cryptonote_basic.h#L989) *(tag scheme)* | `VARIANT_TAG(binary_archive, …, 0x02)` |
| [`blockchain_db.cpp:265-268`](../../src/blockchain_db/blockchain_db.cpp#L265-L268) | `set_archival_serve_credit_bit(p_canonical_id, shard_id, settlement_epoch)` |
| [`blockchain_db.cpp:816-818`](../../src/blockchain_db/blockchain_db.cpp#L816-L818) | the removal/unwind twin |
| `json_object.cpp:402,460,615,631` | JSON codecs both directions |

So **"is the pass record a vin?" answers *yes, already*** — and the round's
question is not placement but **migration**: what comes *out* of where it is
now, and what that costs.

### CR-F2 — Both legs are **already colocated in one container, inside the prefix**

The vin carries `std::vector<uint8_t> hybrid_signature`, bounded by
[`PQC_HYBRID_SINGLE_SIG_LEN = 3385`](../../src/cryptonote_config.h#L396). That
constant is **not** the ML-DSA leg — the comment at
[`cryptonote_config.h:392`](../../src/cryptonote_config.h#L392) and the Rust
canonical layout at
[`signature.rs:262`](../../rust/shekyl-crypto-pq/src/signature.rs#L262)
decompose it identically:

```text
3385 = 12 framing + 64 Ed25519 + 3309 ML-DSA-65
       (1 + 1 + 2 + 4 + ED25519_SIGNATURE_LENGTH + 4 + ML_DSA_65_SIGNATURE_LENGTH)
```

Both legs, one container, **inside the vin ⇒ inside the prefix ⇒ covered by
`prefix_hash` ⇒ unprunable**.

This is the finding that most changes the round's shape. The proposal is not
"add a block to a region that has no occupant." It is **split an existing
colocated container and migrate ~3.3 KB out of the prefix** — which changes
`prefix_hash`, and therefore the tx id, for the same logical record. Pre-genesis
that is affordable; it is nonetheless a different change than the round was
scoped for, and it must be priced as one.

### CR-F3 — The `pqc_auths` slot is **not free** for a serve-credit tx

The proposal that the kept Ed25519 leg ride `pqc_auths` — *"it's `vin.size()`-
sized, one auth per input, which is what a per-record countersignature is"* —
is the right *shape*, and the slot is nonetheless **carved out** for exactly
this tx class:

- [`blockchain.cpp:3726`](../../src/cryptonote_core/blockchain.cpp#L3726) —
  `if (!is_archival_serve_credit_only && tx.pqc_auths.size() != num_inputs)`.
  A pure serve-credit-response tx is **exempted from the count check**.
- [`cryptonote_basic.h:620-621`](../../src/cryptonote_basic/cryptonote_basic.h#L620-L621)
  — serialization, by contrast, does `PREPARE_CUSTOM_VECTOR_SERIALIZATION(vin.size(),
  pqc_auths); if (pqc_auths.size() != vin.size()) return false;`

### `CR-D1` — RESOLVED 2026-08-18: **no tension**, and this is a finding about reading, not a decision

There is nothing to decide. Twenty lines below the skip, the *same* tx class is
held to a **stricter** rule:

```cpp
// blockchain.cpp:3746-3754
if (is_archival_serve_credit_only) {
  if (!tx.pqc_auths.empty()) {
    MERROR_VER("Archival serve-credit tx " << … <<
      " must not carry pqc_auths (signature is on the vin)");
```

So [`:3726`](../../src/cryptonote_core/blockchain.cpp#L3726) is **not an
exemption from a rule — it is a substitution of a stricter one.** The generic
rule is *one auth per input*; serve-credit's rule is *zero auths, ever*. The
count check is skipped **because** the emptiness check supersedes it.
[`:3630`](../../src/cryptonote_core/blockchain.cpp#L3630) completes the picture,
skipping the whole spend-verification arm for these txs — *"non-spending
archival vins; hybrid signature lives on the vin (gate-2 §5)"*.

The serialization demand at
[`cryptonote_basic.h:620-621`](../../src/cryptonote_basic/cryptonote_basic.h#L620-L621)
is then satisfied trivially: the gate at
[`:605`](../../src/cryptonote_basic/cryptonote_basic.h#L605) means `pqc_auths` is
only read when the region is present, and a serve-credit tx never writes one.

**The appearance of tension came from reading `:3726` alone.** The two sites are
twenty lines apart and only make sense together — which is why this is recorded
as *resolved by reading* rather than as a ruling. Nothing was decided; something
was finished being read.

**What it does to the carrier, which is stronger than "the slot is occupied."**
The slot is **forbidden by an explicit consensus check carrying its own error
message**, and the message states the design intent. Putting the kept Ed25519
leg there means deleting `:3746-3754` and inverting an assertion from *must be
empty* to *must contain exactly one*.

And the rule exists for a reason that survives the edit: `pqc_auths` is
**per-input spend authorization**, and a serve-credit vin does not spend. A
countersignature is a third party attesting to a **read**. Putting it in a
container whose semantic is *this input's spend auth* is a category error even
where the check permits it — so the check is not the obstacle, it is the
symptom.

**Therefore the kept leg stays on the vin, and `CR-F3`'s blast radius
dissolves.** There is no live exemption to remove, because the slot is no longer
wanted. `:3630`, `:3726` and `:3746` all survive unchanged.

**Dissolved:** the coinbase-guard worry
([`:605`](../../src/cryptonote_basic/cryptonote_basic.h#L605), `pqc_auths`
skipped for `txin_gen`) does not apply. Under derived assignment there is no
challenge set in the coinbase — assignments are a pure function of
`block_hash(h−1)` and nothing is recorded — so the pass record rides an
ordinary transaction (§2 step 4) and the guard needs no change.

---

## 1. The invariant this round must not break, which nothing currently protects

[`calculate_transaction_prunable_hash`](../../src/cryptonote_basic/cryptonote_format_utils.cpp#L1135)
computes the prunable-region hash two ways:

- **blob path** — `get_blob_hash(blob->data() + unprunable_size, blob->size() - unprunable_size)`: the whole tail, wholesale.
- **re-serialize path** — `ct_signatures.p.serialize_ctsig_prunable(...)`: only `ct_signatures.p`.

**They agree today only because `ctsig_prunable` is the last thing written** —
[`cryptonote_basic.h:645-648`](../../src/cryptonote_basic/cryptonote_basic.h#L645-L648),
where the object closes immediately after it. The equivalence is **positional,
and it has no name and no test.**

Append anything *after* `ctsig_prunable` and the two paths silently diverge: a
node holding the blob computes one prunable hash, a node re-serializing from
the parsed struct computes another. The failure surfaces at
[`:1166`](../../src/cryptonote_basic/cryptonote_format_utils.cpp#L1166) as
`"tx hash cash integrity failure"` — **a throw, on some nodes and not others,
depending on whether they kept the blob.** A moving split point would at least
be a visible consequence; this is not.

**The inside-versus-after distinction is what makes an option safe.** A block
added *inside* `serialize_ctsig_prunable` does not have this problem: the blob
path hashes the tail, which contains it; the re-serialize path serializes
`ct_signatures.p`, which contains it. Both paths still agree **by construction
rather than by ordering luck** — which is a strictly better property than the
one in force today.

The region is already Shekyl's own — `bulletproofs_plus`, `fcmp_pp_proof`,
`pseudoOuts`, nothing ring-shaped — so a fourth block there is a Shekyl schema
decision, not surgery on inherited Monero structure. (The `rct` *naming* is a
[rule 93](../../.cursor/rules/93-legacy-symbol-migration.mdc) item, not an
argument about contents; see also
[`60-no-monero-legacy`](../../.cursor/rules/60-no-monero-legacy.mdc).)

**The tripwire lands with this round regardless of which option wins** — see §4.

---

## 2. The storage number, and why it is not yet the whole number

At maturity `D ≈ 324k`, `λ = 3` ⇒ ~972k records/epoch, ~26.3 epochs/year.

| Leg | Bytes | Per year, unpruned, on every node |
| --- | ---: | ---: |
| ML-DSA-65 | 3,309 | **~88 GB** |
| Ed25519 + framing | 76 | ~2.0 GB |
| `leaf_bytes` ([fixed 128](../../src/cryptonote_config.h#L413)) | 128 | ~3.4 GB |
| `path` (`c1_layers` + `c2_layers`) | **UNKNOWN** | **UNKNOWN** |

**~88 GB/year of mandatory baseline growth is disqualifying** in a design whose
premise is that every node prunes and archivers carry the bulk — it would dwarf
what the archival system exists to offload. So the `pqc_auths` precedent alone
cannot answer the carrier: **something has to be prunable.** That much is
settled.

### `CR-D2` — RESOLVED 2026-08-18: `path` dominates, and the round is a record partition

The 88 GB above counts the signature only, and it is **the floor of the number,
not the number.** Sizing the whole record was an arithmetic read, not a
measurement: the segment layout fixes it.

`SEGMENT_LAYER_J = 2` ([`segment.rs:18`](../../rust/shekyl-curve-tree/src/segment.rs#L18))
with Selene/Helios widths 38/18
([`fcmps/src/lib.rs:57,59`](../../rust/shekyl-oxide/crypto/fcmps/src/lib.rs#L57))
gives a segment of `38·18·38 = 25,992` leaves. The path assembler loops
`for layer in 1..depth`
([`assemble.rs:164`](../../rust/shekyl-curve-tree/src/assemble.rs#L164)), so the
**leaf layer is excluded** from `c1_layers`/`c2_layers` — depth 3 yields exactly
**two** branch layers, one Helios (≤18) and one Selene (≤38).

**The leaf chunk is on-wire cost even though no struct declares it.**
`SegmentPathOpening` holds only the two layer vectors
([`path.rs:52-55`](../../rust/shekyl-archival-retention/src/path.rs#L52-L55)),
but `verify_segment_path` takes `leaf_layer_scalars` as a **separate parameter**
([`path.rs:116-118`](../../rust/shekyl-archival-retention/src/path.rs#L116-L118)),
and `leaf_bytes_in_layer` requires it be a multiple of `SCALARS_PER_LEAF`
*containing* the challenged leaf ([`path.rs:95-108`](../../rust/shekyl-archival-retention/src/path.rs#L95-L108))
— the full chunk, not one leaf. The verifier cannot run without it and cannot
derive it. **Anything a verifier requires and cannot derive must be transmitted**,
so it is part of the record's cost regardless of which struct names it.

| Component | Bytes | GB/yr |
| --- | ---: | ---: |
| record header (`p_canonical_id`, `shard_id`, `settlement_epoch`, `segment_subroot_rk`, `leaf_index_in_segment`) | 74 | 1.9 |
| `leaf_bytes` (challenged leaf) | 128 | 3.3 |
| Ed25519 leg + framing | 76 | 1.9 |
| **leaf chunk** (`4 · 38 · 32`) | **4,864** | **124.3** |
| **branch layers** (`(18 + 38) · 32`) | **1,792** | **45.8** |
| ML-DSA-65 leg | 3,309 | 84.6 |
| **total per record** | **10,243** | **261.8** |

At maturity `D ≈ 324k`, `λ = 3` ⇒ ~972k records/epoch × ~26.3 epochs/yr ≈ 25.6M
records/yr.

**The ruling: `path` goes on the pruned side with the ML-DSA leg.** Kept ≈
**278 B/record ≈ 7.1 GB/yr**; pruned ≈ 9,965 B.

**`CR-O1` as scoped — split the signature legs — does not solve the problem,
and the verdict is overdetermined.** Keeping `path` leaves ~6,934 B/record ≈
**177 GB/yr**, twice the figure that disqualified doing nothing. It fails at
every reading of the leaf-chunk question, including the smallest (branch layers
only, ~53 GB/yr) — so the partition can be ruled *now*, and the
`proxy.rs` constant corrected separately, without either blocking the other.
The leg split survives as a **sub-decision of the partition**, not as the
partition.

**What survives pruning, stated on the ruling rather than discovered later.**
The kept side is the 64 B Ed25519 leg, `leaf_bytes`, and the record header. That
is enough to **identify the record and check the classical signature**, and
**not** enough to **re-verify the opening** — the leaf chunk and branch layers
are exactly what `verify_segment_path` consumes, and they are gone. A reader who
expects a pruned record's membership proof to be re-checkable later will be
wrong, and that is a property of the design rather than an oversight.

**Sibling finding, corrected IN this PR: `proxy.rs`'s constant was wrong, and
correcting it moves one end of a ratified economics verdict.**
[`RESPONSE_BYTES`](../../rust/shekyl-economics-sim/src/proxy.rs) is
`128 + (38 + 18 + 38)·32 ≈ 3.1 KB` — wrong in *both directions at once*: three
branch layers where the assembler yields two, and the leaf layer as 38 scalars
where it is 152. The correct value is `128 + 4·38·32 + (18 + 38)·32 = 6,784 B`,
a **2.16×** understatement.

Correcting it turns two `shekyl-economics-sim` tests red, and they are right to
go red. The Stage-2 **A5/W10** verdict — *"re-fetch beats holding 4–40×"* — no
longer holds uniformly:

| Fetch price | old re-fetch | new re-fetch | vs storage `0.00519` |
| --- | ---: | ---: | --- |
| bulk transit `1e-11` | 0.000385 | 0.000834 | still cheaper — W10 still fails |
| retail egress `1e-10` | 0.003854 | **0.008336** | **now more expensive** — the proxy attack stops being free |

So a 2.16× correction to one constant flips the retail-egress end of the band.

**Which direction it moves, so its own round starts from the right question.**
The correction makes re-fetching *more* expensive, so the free-riding case the
fetch-price analysis was built to price gets **weaker, not stronger** — it moves
in the **safe direction for the retention argument**. But W10 still fails at
bulk transit, so **the overall verdict may be unchanged even though one end of
it flipped.** That is precisely why it needs reasoning rather than a number
swap: "one band member crossed over" and "the finding is retired" are different
claims, and only the first is established.

**Why it lands here rather than in its own round, correcting an earlier call.**
This was first held out under [rule 19](../../.cursor/rules/19-validation-surface-discipline.mdc)
on the reasoning that an economics re-verdict should not ride in on a
byte-layout review. That over-applied the rule. Rule 19 asks whether a bundle
*collapses* two validation surfaces or *conflates* two under a topic — and the
constant and CR-D2's arithmetic are **the same surface**: both are "did we count
the segment opening correctly?", checked by one reviewer with one body of
knowledge. That is rule 19's **bundle** case. Leaving a known-wrong constant
live in the tree while a doc described it as wrong would have been debt with a
note attached, which is what rules 15/16 say not to ship pre-genesis.

**What is bundled is the arithmetic; the verdict is not settled here.** The two
`shekyl-economics-sim` tests are restated to assert only what the shipped
functions now compute — W10 still fails at bulk transit (`q* ≈ 0.274`), and the
retail-egress end no longer free-rides (`margin > 0` at `q ≈ 0`, `q* = 0`). The
strong form they encoded — *failure at the proxy-unfavourable end implies
failure across the band* — is removed because the implication no longer holds,
not replaced with a new verdict. Whether A5/W10 survives overall belongs to
`ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md`, and the restated tests pin the
arithmetic that round must start from.

**The constant's own caveat is why this travelled.** It read *"the verdict is
robust to it: any KB-scale opening is ≪ the 3.33 MB segment"* — **true for that
use**, where the proxy compares re-fetch against holding and both readings are
≪ a segment. Not true where the opening is the dominant term. A robustness
caveat is a property of the **use**, not of the constant, and it does not travel
when the constant does — so the corrected doc-comment states it per-use rather
than as a blanket claim.

**Note for the format round: the leaf chunk is not on the wire today.**
`txin_archival_serve_credit_response` has no leaf-chunk field, and
`verify_segment_path` has **no production caller** — only
`assembled_path_crosscheck.rs`. So today's record is not verifiable from the
wire at all, and the 261.8 GB figure prices *making it verifiable*. That the
addition lands on the pruned side is the point of ruling now: had the leaf chunk
followed `leaf_bytes` onto the kept side by default, the mandatory baseline
would have been ~130 GB/yr before anyone noticed.

---

## 3. The options, unpriced

Each option is stated with what would decide it. None is chosen.

### CR-O1 — Split the signature legs only — **REJECTED (CR-D2, 2026-08-18)**

Kept Ed25519 leg (64 B) unprunable; pruned ML-DSA leg (3,309 B) as a fourth
block **inside** `serialize_ctsig_prunable`.

*Rejected because it leaves ~6,934 B/record ≈ 177 GB/yr* — `path` is the
dominant term, not the signature. Retained because the leg split itself is
**correct and survives as a sub-decision of `CR-O1′`** — and `CR-D1` has since
settled where the kept leg lands: **on the vin**, in a slimmed
`hybrid_signature`, never `pqc_auths`.

### CR-O1′ — Partition the record — **RULED**

Pruned, inside `serialize_ctsig_prunable` where both hash paths see it by
construction: the **leaf chunk**, the **branch layers**, and the **ML-DSA leg**
(~9,965 B). Kept: the record header, `leaf_bytes`, and the Ed25519 leg (~278 B,
≈7.1 GB/yr).

`CR-D1` supplied the placement: the kept leg stays **on the vin**, in a slimmed
`hybrid_signature`. `pqc_auths` is out — forbidden by consensus and a category
error besides.

## 3.1 The ruling, with the structural consequence `CR-D1` was gating

| | Where | Bytes | GB/yr |
| --- | --- | ---: | ---: |
| **Kept** | the vin, in the prefix — header + `leaf_bytes` + 64 B Ed25519 | 278 | **7.1** |
| **Pruned** | a new block **inside** `serialize_ctsig_prunable` — ML-DSA leg + `path` (incl. leaf chunk) | 9,965 | — |

**A vin cannot have fields on both sides of `unprunable_size`.** `tx.vin`
serializes inside the prefix, wholly. So the pruned parts cannot be *fields
within* the vin — they become a **parallel structure keyed to the vin**, and by
[§1](#1-the-invariant-this-round-must-not-break-which-nothing-currently-protects)
that structure lives **inside `serialize_ctsig_prunable`**, never appended after
`ctsig_prunable`. Inside, both hash paths see it by construction; after, they
diverge silently and throw on blob-holding nodes only — the invariant
`tx_prunable_region_sole_occupant.cpp` now guards.

**What this ruling does not disturb:** `pqc_auths` is untouched;
`blockchain.cpp` `:3630`, `:3726` and `:3746` all survive unchanged; no consensus
assertion is inverted; and the two-path equivalence is preserved by construction
rather than by ordering luck.

**Still priced, not free:** `CR-F2`'s `prefix_hash` change. Slimming
`hybrid_signature` on the vin changes the prefix bytes and therefore the tx id
for the same logical record. Affordable pre-genesis; it is the format round's to
land, not a residual.

### CR-O2 — Whole container prunable

Move all 3,385 B into the prunable block; keep nothing. Simplest split, and it
gives up the ability to verify *anything* about the record from a pruned tx.

*Decided by:* whether any consensus or wallet path must authenticate a pass
record after pruning. If one does, this is dead; if none does, it is cheaper
than `CR-O1` and the kept leg is ceremony.

### CR-O3 — Keep it where it is; solve the volume elsewhere

Rejected pending a reason to revisit, recorded so it is not re-litigated: 88
GB/year of mandatory baseline is the disqualifier, and no proposal to shrink
the record by ~30× is on the table.

*Reopening criterion ([rule 21](../../.cursor/rules/21-reversion-clause-discipline.mdc)):*
a signature scheme with a sub-200 B PQ leg becomes admissible under
[`30-cryptography`](../../.cursor/rules/30-cryptography.mdc), or `D` at
maturity is re-forecast an order of magnitude lower.

---

## 4. Owed regardless — the two-path tripwire

The equivalence in §1 protects a genesis-frozen surface and **nothing would
catch whoever appends next.** The test lands with this round whichever option
wins.

**It is C++, and that is deliberate under
[`20-rust-vs-cpp-policy`](../../.cursor/rules/20-rust-vs-cpp-policy.mdc).** The
invariant is a property of the **C++ serializer's ordering**. A Rust test in
`shekyl-wire` would catch nothing, because a future C++ append is invisible to
it — the test must live where the defect can be introduced. This is a
new-test-in-C++ exception, flagged rather than silent.

**It asserts length equality, not only hash equality.** `serialize_ctsig_prunable(...)`
`.size() == blob.size() - unprunable_size` names the defect directly — *"the
prunable region has a second occupant"* — where a hash mismatch says only
*"different"*, sending the next reader hunting a serialization bug instead of a
layout change.

**It runs across the available tx fixtures, not one hand-built tx.** A future
optional field that a single fixture does not populate makes a one-tx test pass
vacuously ([a seal is not coverage](../../.cursor/rules/50-testing.mdc)).

---

## 5. What this round does not decide

- **The response format — now unblocked, and it is next.** Its framing depended
  on this answer, which §3.1 supplies; it is its own PR ([rule 19](../../.cursor/rules/19-validation-surface-discipline.mdc)
  — hash-equivalence and preimage/domain-separation are independent validation
  surfaces, and "coupled through the framing" is topic adjacency, not a shared
  surface).

  **Constraint it inherits, written down now because the failure mode is
  tidiness rather than disagreement.** The **leaf chunk is pruned-side by
  construction.** `leaf_bytes` is already on the kept side, and the leaf chunk
  is the same conceptual object in the same neighbourhood — so putting them
  together is the obvious, unremarkable move, and it silently reintroduces
  ~124 GB/yr that this ruling exists to avoid. A format that groups them for
  structural neatness is not disagreeing with `CR-D2`; it is **not noticing
  it**, which is why the constraint is recorded here rather than left to be
  re-derived. The two are separated deliberately: one identifies the record,
  the other proves it, and only the first survives pruning.
- **The `r` field's deletion.** Rides the response-format round. Its falsifier
  is *"block `h`'s producer may also have produced `h−1`"* — the same `q²` case
  already ruled on pool grinding, an edge gated behind a discarded-block cost
  and dismissed on the merits. Test it; the disposition is likely the same, and
  citing the precedent keeps it from being re-litigated as novel.
- **The settlement-outcome table schema** (§9.7 item 9) and **`EndpointUpdate`
  on the bond wire** — separate PRs, separate validation surfaces.
