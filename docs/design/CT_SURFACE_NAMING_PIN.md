# Confidential-transaction surface naming — disposition pin

**Status.** **Pinned** (2026-06-09). No rename PR until `wallet2.cpp` retirement
([`WALLET_REWRITE_PLAN.md`](WALLET_REWRITE_PLAN.md) Phase 5). This document is
the authoritative disposition for inherited `rct::` / `rctSig` / `rctSigs` /
`rct_signatures` naming. Implementation is deferred; **Rust-side vocabulary is
effective now** across the FFI boundary.

**Supersedes (partially).** April 2026 `ct_signatures = rct::rctSig` alias
([`STRUCTURAL_TODO.md`](../STRUCTURAL_TODO.md) §"`rct_signatures` field name is
a Monero-era misnomer") — retained as the C++ type bridge, not as the module or
verifier rename target.

**Tracked in.** [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) §V3.2 — "Rename inherited
`rct::` / `rctSig` / `rctSigs` C++ surface after `wallet2` cutover."

---

## 1. Problem

Shekyl ships FCMP++ confidential transactions from genesis. Inherited names still
say "ring" and "signatures":

| Inherited | Lie |
|-----------|-----|
| `rct` (Ring Confidential Transaction) | No ring; full-chain membership |
| `rctSig` / `rct_signatures` | Container holds commitments, proofs, fees — not ring sigs |
| `rctSigs` module | Verification and semantics checks — not signing |

The April 2026 `ct_signatures` type alias fixes **RCT → CT** (confidential tx, no
ring). It does **not** fix **signatures → semantics/container**. Applying
`ct_signatures` to the verifier module would yield `ct_signatures.cpp` and
re-commit the fossil.

Production FCMP++ proving is Rust (`shekyl_sign_fcmp_transaction`). C++
`rctSigs` retains semantic verification (balance equations, Bulletproof+ batch
verify, fee-only / bond-post variants, `get_tx_prehash`). Deprecated
`genRctFcmpPlusPlus` / `fill_construct_tx_rct_stub` are deletion targets, not
rename targets.

---

## 2. Two artifacts, different rename targets

One inherited module name covers two roles. They diverge at rename time.

| Current (C++) | Role | Target (at cutover) |
|---------------|------|---------------------|
| `rctTypes.h` | Wire blob struct + `RCTType*` enum | `ct_types.h` |
| `rctOps.h`, `rctCryptoOps.h` | Field / point arithmetic | `ct_ops.h` (split TBD) |
| `rctSigs.h` / `.cpp` | **Semantics verification** | `ct_semantics.h` / `.cpp` |
| `rct::rctSig` (field type) | Passive wire container | Keep `ct_signatures` alias for now; de-"sig" the type noun is lower priority |
| `genRctFcmpPlusPlus`, `fill_construct_tx_rct_stub` | Legacy C++ construction | **Delete** with `wallet2` / chaingen migration — do not rename |
| `rctSigBase::pseudoOuts` (base slot) | Dead legacy field — never populated on any live type | **Delete outright — do not rename** (see below) |

**`rctSigBase::pseudoOuts` deletes; renaming it is scope failure.** The rename
sweep's mechanical RCT→CT pass could carry the base-slot field straight
through — renamed container, same dead field — leaving a dead-guarded slot
under a new name in permanence. The accessor is the proof the field is dead:
`get_pseudo_outs()` (`rctTypes.h:430–438`) returns the base slot only for
non-`RCTTypeFcmpPlusPlusPqc` types, the only such type is `RCTTypeNull`
(coinbase), and coinbase never carries pseudo-outs — the slot is a constant
empty vector everywhere it is reachable. Deletion scope (the field and its
guards leave together, none is separable):

- the field itself (`rctTypes.h:174`) and its ctor init (`:194`);
- the `type != RCTTypeFcmpPlusPlusPqc` wire branch (`:288–291`) — note this
  is a **wire change for `RCTTypeNull`** (one varint-0 byte leaves the
  coinbase blob), so it rides the wire-format step (step 3 below) with the
  serialization-version bump per `42-serialization-policy.mdc`, **not** the
  byte-identical rename step (step 2);
- the boost-serialization line (`cryptonote_boost_serialization.h:428`);
- the accessor's base arm — `get_pseudo_outs()` collapses to `p.pseudoOuts`
  (or the accessor deletes with its callers repointed);
- every `rv.pseudoOuts.empty()` dead-field guard (`rctSigs.cpp:212`, `:280`,
  `:348`, `:420`; `tx_verification_utils.cpp:139`, `:158`, `:192`) — these
  exist only to assert the dead slot stayed dead and retire with it.

The sweep's exit check for this row is grep-mechanical: after the sweep, no
identifier for a base-slot pseudo-out container exists under any name.

Verifier entry points already use "semantics" vocabulary:
`verRctSemanticsSimple`, `verRctSemanticsFeeOnly`, `verRctSemanticsBondPost`
(gate-4). Target namespace functions:
`ct::verify_semantics_simple` / `_fee_only` / `_bond_post` (exact spelling at
implementation PR).

---

## 3. Three surfaces — different cost curves

Do not lump these into one "V4 namespace" deferral.

| Surface | Consensus / wire | Pre-genesis cost | Rename PR gate |
|---------|------------------|------------------|----------------|
| **Wire tags** | `ar.tag("rct_signatures")`, `"rctsig_prunable"` in [`cryptonote_basic.h`](../../src/cryptonote_basic/cryptonote_basic.h) | Cheap before genesis — defines genesis format | Intentional format change; update serialization + tx KATs |
| **C++ identifiers** | Invisible if wire tags unchanged | Cheap after `wallet2` gone | Rename-only; byte-identical round-trip required |
| **Rust + FFI** | C ABI strings stable until coordinated cut | **Free now** — use Shekyl-native names in Rust | New exports use `shekyl_ct_*` / semantics vocabulary; legacy `rct_*` only at the C++ glue edge |

PQC binding is identifier-independent:
`serialize(TransactionPrefixV3) || serialize(RctSigningBody) ||
H(serialize(RctSigPrunable))` per [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md).
Renaming C++ functions (`serialize_rctsig_base` → `serialize_ct_base`) is
consensus-safe **iff** emitted bytes are unchanged. The failure mode is a
"while we're here" layout change riding along — not the rename itself.

---

## 4. Rust-side guidance (effective now)

Rust owns signing, increasingly owns verifier fragments across FFI, and will
own more of the wallet path before C++ names change. **Do not propagate Monero
vocabulary into new Rust modules, types, or internal APIs** because C++ still
says `rctSigs` on the other side of the boundary.

### Do

- Name Rust concepts for what they are: **confidential tx body**, **semantics
  verification**, **signing body**, **prunable bundle** — aligned with
  `RctSigningBody` / `RctSigPrunable` *roles* in spec prose, not C++ type names.
- Keep wire-field references in **comments and FFI glue only** when describing
  what C++ will populate (e.g. "`SignedProofs` → C++ `tx.rct_signatures`").
- Prefer new FFI exports like `shekyl_ct_verify_semantics_*` or domain-specific
  names (`shekyl_archival_verify_bond_post_balance`) over mirroring `rctSigs`
  in Rust crate layout.
- When adding cross-boundary helpers, put Shekyl-native types in the owning Rust
  crate; the FFI layer translates bytes into C++ `rct::rctSig` fields.

### Do not

- Add new Rust modules or public types named `rct_sigs`, `RctSig`, or
  `ringct_*`.
- Extend `ct_signatures` as a Rust type name — it inherits the "signatures"
  misnomer.
- Rename C++ or wire tags in feature PRs (gate-4, archival, send path).

### `ct::` vs curve-tree "CT"

Curve-tree work uses **CT-0/1/2/4** and [`CT2_DRAIN_ORDER.md`](CT2_DRAIN_ORDER.md)
(curve-tree gates). Confidential-tx rename targets **`ct::`** for the C++
namespace. No code-level clash (`curve_tree` / `shekyl-fcmp` vs `fcmp/rct*`),
but prose must disambiguate. If the type noun is reopened later,
`confidential_tx_*` spelled out removes ambiguity at a verbosity cost; not
required while the `ct_signatures` alias stands.

---

## 5. Trigger and sequencing

**Trigger:** `wallet2.cpp` retirement (Phase 5). Necessary to shrink the C++
caller surface; sufficient for the mechanical rename PR. Cherry-pick friction
was the April V4 deferral rationale; [`STRUCTURAL_TODO.md`](../STRUCTURAL_TODO.md)
framing note records that cost as largely notional — **wallet2 gone is the
binding trigger**, not upstream cherry-pick calendar.

**Now (pre-cutover):** this pin + Rust vocabulary discipline only.

**At cutover (separate PRs, scoped):**

1. Delete `genRctFcmpPlusPlus` / `fill_construct_tx_rct_stub` (if not already
   gone).
2. C++ namespace/module rename (`rct::` → `ct::`, `rctSigs` → `ct_semantics`,
   etc.) — rename-only, gated on tx blob round-trip / determinism CI. **Scope
   guard:** `rctSigBase::pseudoOuts` is *excluded* from this step — it deletes
   (per §2's deletion row), it does not rename. A renamed base slot surviving
   step 2 is a step-2 review rejection.
3. Wire tag rename (`rct_signatures` → successor) — pre-genesis or coordinated
   hard fork; updates KATs once at genesis definition time. The
   `rctSigBase::pseudoOuts` deletion's wire-visible half (the `RCTTypeNull`
   branch at `rctTypes.h:288–291`) lands here with the serialization-version
   bump; the dead-field guards and the accessor's base arm go with it.

**Log / RPC strings:** internal identifiers may become descriptive; verifier
failure messages stay coarse (no proof-component detail to log observers). Same
guardrail as the `ringct/` → `fcmp/` directory rename.

---

## 6. Reopening criteria

Per [`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc):

- **Accretion:** new production Rust module or C++ surface named `rctSigs` /
  `rct::` after Phase 5 → immediate rename PR, not further deferral.
- **Substrate:** if verifier logic fully migrates to Rust before Phase 5, revisit
  whether C++ rename PR scope shrinks to wire container + consensus glue only
  (design-round amendment to this pin, not silent scope drift).

---

## 7. Cross-references

- [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) — signing body / prunable binding
- [`STRUCTURAL_TODO.md`](../STRUCTURAL_TODO.md) — naming reference + framing note
- [`FOLLOWUPS.md`](../FOLLOWUPS.md) §V3.2 wallet-cutover cluster
- [`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc) — inherited naming drift
