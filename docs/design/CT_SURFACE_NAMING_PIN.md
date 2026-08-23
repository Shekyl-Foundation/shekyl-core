# Confidential-transaction surface naming — disposition pin

**Status.** **CLOSED — the rename landed 2026-08-21** (see the UPDATE below).
Originally **pinned** 2026-06-09 with no rename PR until `wallet2.cpp`
retirement ([`WALLET_REWRITE_PLAN.md`](WALLET_REWRITE_PLAN.md) Phase 5). This
document remains the authoritative disposition for the inherited `rct::` /
`rctSig` / `rctSigs` / `rct_signatures` naming — it is now the record of *what
was renamed to what and why*, and §6's accretion criterion is live.

**UPDATE 2026-07-11 — V3.0 public-API slice pulled forward and landed.** The
later `FOLLOWUPS.md` umbrella entry (flagged 2026-06-22) split the sweep:
public-surface names are free pre-genesis and breaking after, so that slice
does not wait for Phase 5. Landed on the `chore/rct-to-ct-public-api` chain:
the JSON-archive `ar.tag` names (`rct_signatures` → `ct_signatures`,
`rctsig_prunable` → `ctsig_prunable`; JSON output only, binary wire
positional/unchanged), the `RCTType*` enum variants → `CTTypeNull` /
`CTTypeFcmpPlusPlusPqc` (values unchanged), the legacy wallet-RPC
`estimate_tx_size_and_weight` request field `rct` → `ct` (major RPC version
bump 1→2), the cross-language constant chain
(`ct_type_fcmp_plus_plus_pqc` JSON key, `SHEKYL_CT_TYPE_FCMP_PLUS_PLUS_PQC`
macro, Rust `CT_TYPE_FCMP_PLUS_PLUS_PQC`), and Rust-side residue
(`ct_base_blob`). **Everything else in this pin is unchanged**: the `rct::`
namespace, `rctSig*` struct/module/file names, and `serialize_rctsig_*`
function names stay gated on `wallet2` retirement per §5.

**UPDATE 2026-08-21 — §5 step 2 LANDED; this pin is closed.** The trigger
fired early and by a stronger event than the one pinned: `wallet2` was not
*retired*, it was **deleted** — `src/wallet/` no longer exists — so the C++
caller surface the pin wanted shrunk went to zero inside V3.0 rather than
V3.2. The mechanical sweep landed as its own PR:

| Was | Now |
|-----|-----|
| `src/fcmp/rctTypes.{h,cpp}` | `src/fcmp/ct_types.{h,cpp}` |
| `src/fcmp/rctOps.{h,cpp}` | `src/fcmp/ct_ops.{h,cpp}` |
| `src/fcmp/rctCryptoOps.{h,c}` | `src/fcmp/ct_crypto_ops.{h,c}` |
| `src/fcmp/rctSigs.{h,cpp}` | `src/fcmp/ct_semantics.{h,cpp}` |
| `namespace rct` / `rct::` | `namespace ct` / `ct::` |
| `rctSig`, `rctSigBase`, `rctSigPrunable` | `CtSig`, `CtSigBase`, `CtSigPrunable` |
| `transaction.rct_signatures` | `transaction.ct_signatures` |
| `serialize_rctsig_base`, `hash_rctsig_base_component` | `serialize_ctsig_base`, `hash_ctsig_base_component` |
| `verRctSemanticsSimple`, `verRctSemanticsBondPost` | `verCtSemanticsSimple`, `verCtSemanticsBondPost` |
| `is_rct_bulletproof_plus`, `is_rct_fcmp_pp_pqc`, `ver_mixed_rct_semantics` | `is_ct_*`, `ver_mixed_ct_semantics` |

**Byte-invariance** (the §3 requirement) is structural, not merely tested:
`VARIANT_TAG(binary_archive, …)` values are **numeric** (`0x90`–`0xa0`) and
were not touched, so no serialized byte can depend on a renamed C++
identifier. The `json_archive` / `debug_archive` tag *strings* did move with
the type names (`"rct_key"` → `"ct_key"`, `"rct_rctSig"` → `"ct_CtSig"`,
`"rct::key"` → `"ct::key"`, …) — JSON-visible surface, in the same
pre-genesis-free class the 2026-07-11 slice disclosed, affecting
`decode_as_json` / tx-pool JSON only. Those tags follow the inherited
`<namespace>_<typename-as-written>` convention (`rct_keyV` preserved camel),
which is why `ct::CtSig` tags as `ct_CtSig`; the stutter is the convention's,
not new.

**The dead `ct_signatures` alias was deleted with the sweep.** After the
2026-07-11 slice renamed the field itself, `using ct_signatures = rct::rctSig;`
in `cryptonote_basic.h` had no users; post-rename it would have read `using
ct_signatures = ct::CtSig;`, a self-referential no-op. It is gone.

**UPDATE 2026-08-22 — §5 step 1 half landed.** `genRctFcmpPlusPlus` is
**deleted**, together with the legacy prove seam it was the sole C++ end of:
the Rust exports `shekyl_fcmp_prove` and `shekyl_fcmp_proof_len`, and the C++
declarations of those plus `shekyl_fcmp_build_witness_header`,
`SHEKYL_PROVE_WITNESS_HEADER_BYTES`, `ShekylFcmpProveResult` and
`ProveInputFields`. This is the retired C++ → Rust → C++ → Rust round-trip that
`shekyl_sign_fcmp_transaction` replaced with one call; production proving was
never affected, and the Rust prover is untouched.

Two things the grounding corrected, recorded because both were wrong in the
2026-08-21 entry above:

- **The cascade was over-stated.** That entry said the deletion "cascades:
  `SHEKYL_PROVE_WITNESS_HEADER_BYTES` and the legacy `shekyl_fcmp_prove`
  witness path lose their last C++ consumer". Only the two exports actually
  died. The witness *format* — `parse_prove_witness`, its helpers, the byte
  constant, `ProveInputFields`, the `shekyl_fcmp_build_witness_header` writer,
  and the `WITNESS_HEADER.json` round-trip test — is read by the FROST
  coordinator (`shekyl_frost_coordinator_aggregate_and_prove`), a designed
  seam of the multisig lane. Deleting it would have unwired a seam whose
  absence of callers is its design, not its death. It is instead now
  `#[cfg(feature = "multisig")]`, which states the dependency where the
  compiler enforces it.
- **The relocated wire-format spec was wrong and is fixed.** The doc block on
  the deleted `shekyl_fcmp_prove` was the only prose description of the witness
  layout, so it moved to `parse_prove_witness`, which now owns the format. It
  specified a **224-byte, 7-field** header, omitting the commitment mask `z`;
  the real header is **256 bytes, 8 fields**, as the parser, `ProveInputFields`
  and the JSON vectors all agree. Copying it verbatim would have enshrined a
  spec that misaligns every input after the first.

**Still open — the other half of step 1.** `fill_construct_tx_rct_stub` keeps
its name. Its caller `construct_tx_with_tx_key` has no production caller either
(the 2026-08-21 claim that it had one was wrong; corrected in
[`FOLLOWUPS.md`](../FOLLOWUPS.md)), but the `construct_tx*` chain is the C++
consensus oracle's transaction factory, reached from `tests/core_tests/` and
`tests/performance_tests/`. Retiring it is oracle work, not naming work.
Tracked in [`FOLLOWUPS.md`](../FOLLOWUPS.md) (V3.0).

**Surviving `rct`-spelled long tail — outside this pin's scope, and named
here so §6 is not misread.** The sweep's subject was this pin's: the
`src/fcmp/` module, the `rct_signatures` field, and their serializer /
verifier families. A `grep -i rct` across `src/` and `tests/` still returns
matches, and none is a miss:

| Family | Where | Disposition |
|--------|-------|-------------|
| `num_rct_outs`, `bi_cum_rct`, `pre_rct_outkey` | `src/blockchain_db/lmdb` | **Persisted-schema identifiers** — a different validation surface from a C++ rename ([`19-validation-surface-discipline.mdc`](../../.cursor/rules/19-validation-surface-discipline.mdc)); renaming them belongs with the LMDB/blockchain-db port, not here |
| `get_block_cumulative_rct_outputs` | `src/blockchain_db` | Reads the above; moves with them |
| `arg_rct_only` / `opt_rct_only` | `src/blockchain_utilities` | A CLI flag on the export tool — user-visible surface, renamed when that tool is touched |
| `od_rct` | `src/rpc` | Local variable holding an `ct::key`; rule 93 rename-on-touch |
| `_rct_data`, `construct_tx_rct` | `src/cryptonote_core` | Construction path; rename-on-touch, and partly dies with the step-1 deletions |
| `rct_txes`, `RCT_TYPE`, `a_rct`, `rctx` | `tests/` | Test-local helpers and fixtures; rename-on-touch |

§6's accretion criterion is family-scoped to `rctSigs` / `rct::` / `rctSig*` —
the names this pin renamed. It does not assert that the string `rct` is absent
from the tree, and the rows above are not precedent for reintroducing the
renamed families.

**Supersedes (partially).** April 2026 `ct_signatures = rct::rctSig` alias
([`STRUCTURAL_TODO.md`](../STRUCTURAL_TODO.md) §"`rct_signatures` field name is
a Monero-era misnomer") — retained as the C++ type bridge, not as the module or
verifier rename target.

**Tracked in.** [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) — the tracking entry
("Rename inherited `rct::` / `rctSig` / `rctSigs` C++ surface after `wallet2`
cutover") is marked **[Done 2026-08-21]**; the surviving open item is the §5
step-1 deletion of `genRctFcmpPlusPlus` / `fill_construct_tx_rct_stub`.

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

Production FCMP++ proving is Rust (`shekyl_sign_fcmp_transaction`). The C++
module retains semantic verification (balance equations, Bulletproof+ batch
verify, fee-only / bond-post variants, `get_tx_prehash`) — which is why its
rename target was `ct_semantics`, and what it is called since 2026-08-21.
Deprecated `genRctFcmpPlusPlus` / `fill_construct_tx_rct_stub` were deletion
targets, not rename targets; the first was deleted 2026-08-22 and the second
remains (see the UPDATE above).

---

## 2. Two artifacts, different rename targets

One inherited module name covers two roles. They diverge at rename time.

| Current (C++) | Role | Target (at cutover) |
|---------------|------|---------------------|
| `rctTypes.h` | Wire blob struct + type enum (variants already `CTType*`, renamed 2026-07-11) | **Done** — `ct_types.h` |
| `rctOps.h`, `rctCryptoOps.h` | Field / point arithmetic | **Done** — `ct_ops.h` and `ct_crypto_ops.h`; the "split TBD" resolved as *keep the existing split*, since the C shim (`.c`) and the C++ ops are separate translation units |
| `rctSigs.h` / `.cpp` | **Semantics verification** | **Done** — `ct_semantics.h` / `.cpp` |
| `rct::rctSig` (field type) | Passive wire container | **Done** — `ct::CtSig`; the `ct_signatures` alias was deleted (dead after the 2026-07-11 field rename) |
| `genRctFcmpPlusPlus` | Legacy C++ construction | **Done — deleted 2026-08-22** (no caller) |
| `fill_construct_tx_rct_stub` | Legacy C++ construction | **Delete** with the chaingen / test-construction migration — do not rename |
| `rctSigBase::pseudoOuts` (base slot) | Dead legacy field — never populated on any live type | **DELETED (standalone pre-sweep PR)** (see below) |

**`rctSigBase::pseudoOuts` — DELETED in a standalone pre-sweep PR
(2026-07-09), with the two claims below corrected.** The field, its guards,
the accessor's base arm, and the caller-less standalone object serializers
were removed together. The sweep's exit check for this row is now
grep-mechanical and already satisfied: no identifier for a base-slot
pseudo-out container exists under any name.

Two claims in this section's earlier revision were **refuted at source**
during the deletion PR's grounding, and are corrected here so the sweep does
not act on them:

- **The "wire change for `RCTTypeNull`" claim was wrong — the deletion was
  byte-identical.** The `FIELD(pseudoOuts)` branch (old `rctTypes.h:288–291`)
  lived in `rctSigBase`'s standalone `BEGIN_SERIALIZE_OBJECT()` — a second
  serializer with **no production caller** (its only callers were two unit
  tests round-tripping the serializer itself, since repointed to the member
  function), not the wire. Every real byte producer — the
  transaction serializer (`cryptonote_basic.h`), the tx-hash paths
  (`cryptonote_format_utils.cpp`), the FCMP++ pre-hash (`rctSigs.cpp`), the
  PQC payload binding (`tx_pqc_verify.cpp`) — uses the
  `serialize_rctsig_base` **member function**, which never emitted the base
  field (a coinbase's rct tail is exactly
  `type ‖ enc_amounts ‖ enc_labels ‖ outPk`, pinned by
  `tests/unit_tests/serialization.cpp` and the live-oracle coinbase KAT in
  `rust/shekyl-wire`). No coinbase byte changed, no hash changed,
  `GENESIS_TX` is untouched, and no serialization-version bump applies (the
  `42-serialization-policy.mdc` gate governs persisted engine-state blocks,
  none of which embed the rct base). The deletion PR also removed the three
  caller-less standalone object serializers (`rctSigBase`, `rctSigPrunable`,
  `rctSig`) so a second, disagreeing definition of the bytes cannot produce
  this class of phantom finding again.
- **The boost-serialization line (`cryptonote_boost_serialization.h:428`)
  was never part of this deletion — do not touch it in the sweep.** That
  line is the **prunable** field (`x.pseudoOuts` inside
  `serialize(rctSigPrunable&)`), which is live and load-bearing; removing it
  would corrupt the boost wallet-cache format. The boost `rctSigBase`
  serializer never emitted the base slot at all.

Verifier entry points already used "semantics" vocabulary:
`verRctSemanticsSimple`, `verRctSemanticsFeeOnly`, `verRctSemanticsBondPost`
(gate-4). This pin proposed `ct::verify_semantics_simple` / `_fee_only` /
`_bond_post` and delegated the exact spelling to the implementation PR.

**Decided 2026-08-21 — `ct::verCtSemantics*`, superseding the proposed
snake_case.** Not a drift: two members of the family were *already* renamed to
that spelling and merged in PR #522 (`verCtSemanticsFeeOnly`,
`verCtSemanticsEmission`), so snake_case would have created a **third**
convention across five sibling functions rather than one. The sweep instead
converged the family on the landed spelling (`verCtSemanticsSimple`,
`verCtSemanticsBondPost`), which also matches the camelCase of the arithmetic
they sit beside (`addKeys`, `scalarmultH`, `equalKeys`). The pin's substantive
requirement — the module says *semantics*, never *signatures* — is met; only
the casing differs from the proposal.

---

## 3. Three surfaces — different cost curves

Do not lump these into one "V4 namespace" deferral.

| Surface | Consensus / wire | Pre-genesis cost | Rename PR gate |
|---------|------------------|------------------|----------------|
| **Wire tags** | **Renamed 2026-07-11** — `ar.tag("ct_signatures")`, `"ctsig_prunable"` in [`cryptonote_basic.h`](../../src/cryptonote_basic/cryptonote_basic.h). JSON-archive-only (`binary_archive::tag` is a no-op): affects `decode_as_json` / tx-pool JSON, not binary bytes; no KAT pinned the JSON key names | Done pre-genesis | Landed (V3.0 public-API slice) |
| **C++ identifiers** | Invisible if wire tags unchanged | Cheap after `wallet2` gone | **Landed 2026-08-21** — rename-only; byte-identical by construction (binary variant tags are numeric) |
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
  `CtSigningBody` / `CtSigPrunable` *roles* in spec prose. (These prose role
  names were `RctSigningBody` / `RctSigPrunable` until 2026-08-21 and were
  renamed with the sweep, since a `Rct`-spelled role label outliving the
  namespace is exactly the deadweight-masquerading-as-current-naming that
  `STRUCTURAL_TODO.md` flags. **Deliberate consequence:** `CtSigPrunable` is
  now *also* the C++ type name, so this bullet's original role-vs-type
  distinction no longer holds for that one label — the role and the type
  genuinely denote the same thing, and pretending otherwise cost more than it
  bought. `CtSigningBody` remains role-only; the C++ type is `CtSigBase`.)
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
required, since `ct::` now names the confidential-tx namespace outright and
curve-tree work is spelled `curve_tree` / `CT-0..4` with no code-level clash.

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
   gone). **Half landed** — `genRctFcmpPlusPlus` deleted 2026-08-22 (it had no
   caller); `fill_construct_tx_rct_stub` remains, blocked on the C++
   test-construction harness. Step 2 landed before either, which §5 permits;
   see the 2026-08-22 UPDATE.
2. C++ namespace/module rename (`rct::` → `ct::`, `rctSigs` → `ct_semantics`,
   etc.) — rename-only, gated on tx blob round-trip / determinism CI. **Scope
   note:** `rctSigBase::pseudoOuts` no longer exists — it was deleted in the
   standalone pre-sweep PR (§2), byte-identically. The step-2 review check is
   simply that the sweep introduces no new base-slot pseudo-out identifier.
   **LANDED 2026-08-21.** The review check was run and passes: every
   `pseudoOuts` occurrence the sweep touched is prunable-context
   (`rv.p.pseudoOuts` / `tx.ct_signatures.p.pseudoOuts`); no base-slot
   pseudo-out container exists under any name.
3. ~~Wire tag rename (`rct_signatures` → successor)~~ — **landed 2026-07-11**
   pre-genesis as part of the V3.0 public-API slice (`ct_signatures` /
   `ctsig_prunable`; JSON-archive-only, no KAT update was needed — see the
   Status update above). (The earlier claim that the `rctSigBase::pseudoOuts`
   deletion had a wire-visible half landing here was refuted at source and is
   corrected in §2 — the deletion was byte-identical and has already landed;
   nothing from it rides step 3.)

**Log / RPC strings:** internal identifiers may become descriptive; verifier
failure messages stay coarse (no proof-component detail to log observers). Same
guardrail as the `ringct/` → `fcmp/` directory rename.

---

## 6. Reopening criteria

Per [`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc):

- **Accretion (ARMED 2026-08-21).** With the sweep landed there is no
  remaining licence for the old spelling: any new production Rust module or
  C++ surface named `rctSigs` / `rct::` / `rctSig*` is a regression → immediate
  rename PR, not further deferral. The one deliberate survivor is the
  remaining §5 step-1 deletion target, `fill_construct_tx_rct_stub`, and it is
  not precedent.
- **Substrate:** *moot* — this criterion existed to shrink the rename PR's
  scope if verifier logic migrated to Rust before Phase 5. The rename has
  landed, so there is no scope left to shrink. Verifier migration continues on
  its own track ([`20-rust-vs-cpp-policy.mdc`](../../.cursor/rules/20-rust-vs-cpp-policy.mdc));
  it no longer interacts with this pin.

---

## 7. Cross-references

- [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) — signing body / prunable binding
- [`STRUCTURAL_TODO.md`](../STRUCTURAL_TODO.md) — naming reference + framing note
- [`FOLLOWUPS.md`](../FOLLOWUPS.md) §V3.2 wallet-cutover cluster
- [`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc) — inherited naming drift
