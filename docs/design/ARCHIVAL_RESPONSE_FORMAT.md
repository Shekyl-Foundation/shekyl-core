# Serve-credit response format — design round (RF)

**Status:** OPEN. Round opened 2026-08-18.
**Unblocked by:** the carrier round ([`ARCHIVAL_PASS_RECORD_CARRIER.md`](ARCHIVAL_PASS_RECORD_CARRIER.md)) — RULED.
**Freezes:** a genesis-frozen wire. Everything decided here is impossible to
change after genesis, which is the only reason the round exists as a round.
**Process:** [`26-sub-pr-design-discipline`](../../.cursor/rules/26-sub-pr-design-discipline.mdc).
Disposition IDs **`RF-D1` … `RF-Dn`**, registered at birth per
[`94-tracking-index`](../../.cursor/rules/94-tracking-index.mdc).

**Every input below is pinned except one.** That is unusual and it is the point:
this round is mostly *transcription of settled rulings into bytes*, with a single
genuine test in it — whether `r` survives. Rounds where everything is open
produce prose; this one should produce a wire.

---

## 1. The inputs, and where each was settled

Verified at source on 2026-08-18 against `dev@69e76a7be`. Nothing here is
transcribed from conversation.

| # | Input | Status | Settled at |
| --- | --- | --- | --- |
| 1 | **Leaf chunk is pruned-side by construction** | RULED | `ARCHIVAL_PASS_RECORD_CARRIER.md` CR-D2 |
| 2 | **Reserved padding field; no padding scheme** | RULED 2026-08-08 (TJ-H) | `ARCHIVAL_CHALLENGE_MECHANISM.md:1065` |
| 3 | **Nonce anchor = `cb_out_key` of block `h`** | RULED 2026-08-10 (fork 2 closed) | `ARCHIVAL_CHALLENGE_MECHANISM.md:40-43` |
| 4 | **`r` deleted**; nonce `H(block_hash(h−1) ‖ cb_out_key ‖ P ‖ s ‖ E)` | re-pinned — **the round's one test** | `ARCHIVAL_CHALLENGE_MECHANISM.md:48` |
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

## 2. `RF-D3` — the one genuine test: does `r` survive?

The nonce is re-pinned as `H(block_hash(h−1) ‖ cb_out_key ‖ P ‖ s ‖ E)` with `r`
**deleted**. The reasoning: under derived assignment `block_hash(h−1)` is already
unpredictable to `P` and ungrindable by block `h`'s producer, so `r` may do no
work at all — and a field that does no work on a **genesis-frozen** surface is a
field that can never be removed.

**This must be tested, not assumed.** The claim to falsify is precisely
**"ungrindable by block `h`'s producer"**, and the falsifier is stated:

> Block `h`'s producer **may also have produced `h−1`**.

If it did, it chose `block_hash(h−1)`, and the anchor it is being bound to is
partly of its own making.

**Precedent, cited so the disposition is not re-litigated as novel.** This is the
same `q²` case already ruled on pool grinding — an edge gated behind a
**discarded-block cost**, dismissed on the merits (`ARCHIVAL_CHALLENGE_MECHANISM.md`
§: *"countersigning-as-P harmless (the priced q² case)"*; the success arithmetic
`3q²(1−q)+q³` at `:222`). The disposition is **likely the same**. It is still
tested, because "likely the same" and "the same" differ, and the cost of being
wrong is a field that cannot be added back.

**What a pass and a fail each mean.** Pass ⇒ `r` is deleted and a field
disappears from a genesis-frozen surface, which is worth the check on its own.
Fail ⇒ `r` is retained, and the round must say what it is anchored to — the
falsifier does not by itself supply a replacement.

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
