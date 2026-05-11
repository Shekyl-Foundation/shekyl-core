# Stage 1 PR 3 — M3c pre-flight investigation

**Status.** **EXECUTED 2026-05-10.** M3c landed on
`feat/stage-1-pr3-m3c` as 6 commits cut off `dev` at `ea1df2539`,
opened as [PR #38](https://github.com/Shekyl-Foundation/shekyl-core/pull/38).
The Phase-2 dispositions in §2 / §5 / §6 below were carried
forward to implementation, with two refinements that surfaced
during execution and are recorded in `STAGE_1_PR_3_MIGRATION_PLAN.md`
§3.3.1 ("Post-implementation cross-reference"):

1. **Trim-1 disposition.** §2.1 step 5(b) was reworked from a
   parallel-`sign_transaction`-with-deterministic-component-byte-
   identity property to a `SpendInput`-byte-identity property
   plus a single engine-path `sign_transaction` call. The
   `SpendInput`-layer property is strictly stronger than the
   signer-output-layer property at lower runtime cost; the
   named coverage gap (legacy `sign_transaction` end-to-end
   execution) is documented in the test docstring and accepted
   given M3d's trajectory.
2. **Runtime-budget reality update.** §2.4 R3 and §6 (c) were
   updated post-implementation when measured runtime came in
   ~17.65 s debug / ~6.87 s release, ~290× over the
   pre-implementation `~60 ms` estimate. The estimate undercounted
   FCMP++ membership-proof cost by ~2 orders of magnitude and the
   sweep-size cost by 3×.

Subsequent maintainers should read the migration plan's M3c
landing notes (§3.3.1) for the actual landed state. This
document is preserved as the audit trail of the Phase-1
investigation; the §1–§7 body below was written before
implementation and is the basis the dispositions above modify.

---

**Original status (preserved for audit).** Read-only investigation.
No code changes proposed yet.
This document re-anchors M3c against its actual structural state on
`dev` post-M3b/PR-#34, and disposes the divergence between the
[`STAGE_1_PR_3_MIGRATION_PLAN.md`](./STAGE_1_PR_3_MIGRATION_PLAN.md)
§3.3 written wording and what is implementable today.

**Branch.** `feat/stage-1-pr3-m3c` off `dev` at `ea1df2539` (post
M3b merge; post PR #35 baseline-zero / capture-guard merge; post
PR #36 runner-bisect workflow merge). Pre-flight commits land here
before implementation begins.

**Cross-references.**

- **Migration plan.**
  [`STAGE_1_PR_3_MIGRATION_PLAN.md`](./STAGE_1_PR_3_MIGRATION_PLAN.md)
  §3.3 (M3c — additive test caller) is the binding scope statement.
  This pre-flight refines its “byte-identical `SignedProofs`”
  language against the actual `tx_builder::sign_transaction` shape
  (which uses `OsRng` internally — strict byte-identity is not a
  reachable property at that surface).
- **Audit.**
  [`STAGE_1_PR_3_MIGRATION_AUDIT.md`](./STAGE_1_PR_3_MIGRATION_AUDIT.md)
  §3.1 (Implication for M3c): "M3c is **additive, not migrational**.
  Non-wallet2-bridged orchestrator callers of
  `tx_builder::sign_transaction`: zero." This pre-flight respects
  the audit framing — M3c introduces a new caller (a test caller),
  it does not migrate an existing one.
- **M3a divergence note.**
  [`STAGE_1_PR_3_MIGRATION_PLAN.md`](./STAGE_1_PR_3_MIGRATION_PLAN.md)
  §3.1 Divergence 3 documents the named-gap status of
  `KeyEngine::sign_transaction`: it returns
  `KeyEngineError::SignTransactionTraitSurfaceIncomplete` because
  `TxToSign`’s `outputs: Vec<TxOutputContext>` and
  `fcmp_plus_plus_context: FcmpPlusPlusContext` are PR-5-pinned
  forward-declared `pub(crate) struct {}` stubs. M3c cannot exercise
  the trait method end-to-end at this point in the migration.
- **M3b precedent.**
  [`STAGE_1_PR_3_M3B_PREFLIGHT.md`](./STAGE_1_PR_3_M3B_PREFLIGHT.md)
  §D5 is the test-placement precedent. M3b D5 (the bundle byte-
  identical test) was specified for
  `tests/byte_identical_derivation.rs` but landed as a unit test in
  `local_keys.rs::tests` because `KeyEngine` and
  `derive_source_secrets_bundle` are `pub(crate)` and integration
  tests run as external crates. M3c-via-C inherits the same
  visibility constraint and the same disposition.

---

## §1 What changed since the migration plan was written

The migration plan’s §3.3 wording predates two structural facts
that landed during M3a/M3b execution:

### §1.1 `KeyEngine::sign_transaction` is non-functional

Per
[`STAGE_1_PR_3_MIGRATION_PLAN.md`](./STAGE_1_PR_3_MIGRATION_PLAN.md)
§3.1 Divergence 3, the trait method’s implementor body
(`local_keys.rs:531–543`) returns
`KeyEngineError::SignTransactionTraitSurfaceIncomplete`
unconditionally. The named-gap signal exists by design — per
[`STAGE_1_PR_3_KEY_ENGINE.md`](./STAGE_1_PR_3_KEY_ENGINE.md) §3.3,
`TxToSign`’s shape is PR-5-pinned because the per-input
on-chain-public data and the FCMP++ tree-branch context belong to
the `PendingTxEngine` build path, not the key-derivation path.

**Implication.** A test that calls
`KeyEngine::sign_transaction(...)` end-to-end can only verify the
named-gap path; it cannot exercise the bridge to
`tx_builder::sign_transaction`. The bridge lands in PR 5.

### §1.2 `KeyEngine` is `pub(crate)`

Per the M3a Round 4a discipline lock recorded in
[`STAGE_1_PR_3_KEY_ENGINE.md`](./STAGE_1_PR_3_KEY_ENGINE.md) §4.4
(trait visibility evolution), `KeyEngine`, `LocalKeys`,
`SourceSecretsBundle`, and `KeyEngineError` are all `pub(crate)`
inside `shekyl-engine-core`. Visibility widens to `pub` only when
a downstream consumer needs the trait — currently scheduled for
the wallet-RPC-server cutover (post-RC1).

**Implication.** A test in `rust/shekyl-engine-core/tests/`
(integration tests, which run as external crates) cannot reach
`KeyEngine` or `SourceSecretsBundle`. M3c’s test caller must live
inside the crate as a unit test in `local_keys.rs::tests` (or a
peer test module under `engine/` with the same visibility), the
same disposition M3b D5 took.

### §1.3 `tx_builder::sign_transaction` is non-deterministic

Audit at `rust/shekyl-tx-builder/src/sign.rs:54–183`:

- Step 5 (pseudo-output blindings, lines 110–117) calls
  `Scalar::random(&mut OsRng)` for each of the first `n_in - 1`
  inputs.
- Step 2 (Bulletproof+ proof, line 80) calls
  `shekyl_bulletproofs::Bulletproof::prove_plus(&mut OsRng, …)`.
- Step 7 (FCMP++ proof, line 164) calls `proof::prove(…)`, which
  also draws from `OsRng` internally.

The function takes no RNG parameter. Two invocations with
byte-identical inputs produce different `SignedProofs.bulletproof_plus`,
different `SignedProofs.fcmp_proof`, and different
`SignedProofs.pseudo_outs` bytes.

**Implication.** The migration plan’s §3.3 success-criterion line
"*Test produces byte-identical `SignedProofs` to the legacy path*"
is unreachable at this surface. The property M3c can pin instead is
**deterministic-component byte-identity plus
verifier-acceptance**:

- `SignedProofs.commitments` (output Pedersen commitments) is
  deterministic in `(mask, amount)`, both of which derive from
  the bundle/output-info inputs. **Pinned byte-wise** against the
  legacy path.
- `SignedProofs.enc_amounts` is a deterministic copy from
  `OutputInfo.enc_amount`. **Pinned byte-wise** against the legacy
  path.
- `SignedProofs.bulletproof_plus`, `.fcmp_proof`, `.pseudo_outs`
  are randomized. **Verified to verify.**

This is a stronger property than the migration plan’s wording: the
deterministic components are pinned, and the randomized components
are pinned not against legacy bytes (which would be brittle and
mostly tautological) but against the verifier (which is the
property that actually matters — that the engine path produces
proofs the verifier accepts).

---

## §2 Disposition: Option C

Three options were considered during the prior audit conversation
(2026-05-09):

- **Option A — Defer M3c.** Treat the migration plan’s §3.3
  literal text as binding; mark M3c as un-implementable until PR 5
  finalizes `TxToSign` and the bridge to `tx_builder::sign_transaction`
  is functional. Rejected: the migration tail (M3d, M3e) depends
  on M3c as a precondition per
  [`STAGE_1_PR_3_MIGRATION_PLAN.md`](./STAGE_1_PR_3_MIGRATION_PLAN.md)
  §3.4 dependencies; deferring M3c blocks M3d/M3e behind PR 5.
- **Option B — Treat M3c as already satisfied by M3b D5.** M3b D5
  pins bundle byte-identicality between engine and legacy
  derivations. Rejected: M3b D5 stops at the bundle (the
  cryptographic-derivation surface). M3c is supposed to validate
  the integration end-to-end through `tx_builder::sign_transaction`
  — i.e., that the bundle’s components are correctly consumed by
  the signing pipeline. M3b D5 does not pin that integration.
- **Option C — Direct call to `tx_builder::sign_transaction` from
  engine-derived bundles** (this disposition). Pin the property
  M3c was designed to validate (engine bundle drives a successful
  signing pipeline) at the surface where it is reachable today
  (`tx_builder::sign_transaction`), bypassing the non-functional
  `KeyEngine::sign_transaction` trait method. The bridge through
  the trait surface lands in PR 5.

**Adopted disposition: Option C.**

### §2.1 What Option C delivers

The new test (working name:
`engine_derived_bundle_signs_through_tx_builder_end_to_end`) sits
inline in `rust/shekyl-engine-core/src/engine/local_keys.rs::tests`
as a peer to M3b D5. It:

1. Constructs a `LocalKeys` from `TEST_SEED` (the same fixture M3b
   D5 uses).
2. For each of *N* synthetic inputs (suggested *N* = 3 — single,
   pair, triple — to exercise the n_in-dependent pseudo-output
   blinding loop):
   - Synthesizes a `(view_secret, source_ciphertext)` pair via the
     same `construct_output` shape M3b D5 uses.
   - Calls `keys.derive_source_secrets_bundle(...)` to obtain
     `SourceSecretsBundle`.
3. Constructs `tx_builder::SpendInput` records using the
   engine-derived bundle’s scalars (`spend_key_x`, `spend_key_y`,
   `mask_z`, plus tree-branch context built from the synthesized
   ciphertext).
4. Constructs matching `OutputInfo` records (recipient
   commitments + encrypted amounts).
5. Asserts that the engine-derived `SpendInput` is byte-identical
   field-by-field to a hand-composed legacy `SpendInput` sourced
   from `scan_output_recover` + hand-composed `(ho + b + m_i)` (the
   same legacy chain M3b D5 uses). Then calls
   `tx_builder::sign_transaction(...)` *once* on the engine-derived
   inputs and asserts:
   - **(a)** Returns `Ok(SignedProofs)`.
   - **(b)** `SpendInput` byte-identical between engine and legacy
     bundle-derivation paths; sign-once on the engine path; verify
     acceptance.
   - **(c)** A verifier (`shekyl_fcmp::proof::verify` and
     `shekyl_bulletproofs::Bulletproof::verify_plus`) accepts the
     proofs.
6. The test asserts these properties for at least 9 distinct
   `(n_in, subaddress_index)` combinations (3 input counts × 3
   subaddress indices) to surface single-axis subaddress-derivation
   regressions, multi-input aggregation regressions, and cross-axis
   interactions between the two.

#### §2.1.1 Trim-1 disposition (post-implementation amendment)

The §2.1 step 5(b) wording above was tightened from "byte-identical
to a parallel call" to "SpendInput byte-identical between engine and
legacy bundle-derivation paths; sign-once on the engine path;
verify acceptance" during implementation, after the parallel-sign-
call structure was measured to dominate the test's runtime
(parallel sign in ~32s debug; sign-once + SpendInput byte-equality
in ~17s debug, ~7s release). The substitution is **strictly
stronger** at the property level:

- **Original (parallel sign).** Engine and legacy
  `SpendInput`s feed the same `tx_builder::sign_transaction`; the
  test asserts the deterministic outputs (`commitments`,
  `enc_amounts`) are byte-equal between the two sign calls. This
  pins the property *both `SpendInput`s arrive at the same
  `OutputInfo` derivations* via the indirect route of
  `OutputInfo`-deterministic signer-output components.
- **Trim 1 (SpendInput byte-equality + sign-once).** Engine and
  legacy `SpendInput`s are byte-compared field-by-field at the
  input layer (`output_key`, `commitment`, `amount`, `spend_key_x`,
  `spend_key_y`, `commitment_mask`, `h_pqc`, `combined_ss`,
  `output_index`, all `leaf_chunk` entries, `c1_layers`,
  `c2_layers`). `sign_transaction` is called once on the engine
  path; verifier acceptance is asserted on the resulting proofs.
  This pins byte-equality at the `SpendInput` layer (the input to
  `sign_transaction`), which combined with the determinism of
  `sign_transaction`'s `OutputInfo → commitments` mapping implies
  the original property as a corollary, AND additionally guards
  against `SpendInput`s that differ in fields irrelevant to
  commitments / enc_amounts but relevant to signature behavior or
  future field additions.

**Named coverage gap.** Trim 1 reduces the workspace's coverage of
`tx_builder::sign_transaction`'s end-to-end success path from 2× to
1× (this test was the workspace's sole such coverage even before
Trim 1; see the test docstring's "Workspace-coverage note"). The
1× reduction is named-and-accepted given M3d removes the legacy
bundle-derivation chain entirely; the engine path is the load-
bearing path going forward and the redundant second exercise of
the same signer would only have decaying value.

**Forward template.** When implementation surfaces a strictly-
stronger test at lower cost than the pre-flight wording specified,
the pre-flight gets amended to reflect the discovered property.
Pre-flight wording is the means; the property tested is the end.
Strengthening a pre-flight property post-implementation requires
the kind of amendment recorded in this section; weakening a
pre-flight property requires explicit revisit of the original
disposition.

### §2.2 Why this is the right validation milestone

The migration plan’s framing of M3c was “the property test the
audit-bounded migration relies on” — i.e., M3c provides the
evidence that allows M3d to remove the legacy
`TransferDetails`-secret-bearing fields and the bridge’s legacy-
fallback path. Option C delivers exactly that evidence:

- The engine’s deterministic bundle derivation reaches a verifier-
  accepting signature when fed through `tx_builder::sign_transaction`.
- The deterministic components match the legacy path byte-wise.
- Since the bundle derivation is the migration’s only secret-flow
  reroute (per
  [`STAGE_1_PR_3_MIGRATION_AUDIT.md`](./STAGE_1_PR_3_MIGRATION_AUDIT.md)
  §1: "Production SpendInput construction outside FFI/`native-sign`:
  zero sites"), and M3b D5 + M3c-via-C together pin the full
  cryptographic-derivation chain end-to-end, the precondition for
  M3d’s removal is satisfied.

---

## §3 Test scope

### §3.1 In-scope

- **One test function** in `local_keys.rs::tests` — see §2.1.
- **Test fixtures** reused from M3b D5 (`TEST_SEED`,
  `TEST_TX_KEY_SECRET`, `construct_output`, `scan_output_recover`,
  `subaddress_derivation_scalar`). No new fixtures introduced.
- **`tx_builder` test helpers.** The existing `dummy_tree()` /
  `dummy_output()` helpers in `shekyl-tx-builder/src/tests.rs` are
  test-only (`#[cfg(test)]`); they are not reachable from
  `shekyl-engine-core` because they live behind a `#[cfg(test)]`
  gate inside a different crate. M3c-via-C must construct the
  `TreeContext` and `OutputInfo` shapes inline. Adapter helpers
  (~30 lines) for the inline constructions land in
  `local_keys.rs::tests` next to the new test function.
- **One verifier call.** The verifier dependency (`shekyl_fcmp` for
  FCMP++ proof verification, `shekyl_bulletproofs` for BP+
  verification) is already a workspace dependency through
  `shekyl-tx-builder`. M3c-via-C imports the verifiers directly in
  `#[cfg(test)] dev-dependencies` if they are not already in scope.

### §3.2 Out-of-scope

- **Calling `KeyEngine::sign_transaction`.** Lands in PR 5 when
  `TxToSign`’s shape is finalized.
- **Integration test in `tests/`.** Blocked by `pub(crate)` lock;
  re-located when `KeyEngine` widens per the FOLLOWUPS V3.0 trigger
  entry. M3b D5 carries the same deferred re-location; M3c-via-C
  will be re-located alongside it under one PR.
- **`sign_pqc_auths` integration.** PQC auth signing is Phase 2 of
  the signing pipeline (per `tx_builder/src/sign.rs:185–245`). It
  consumes `combined_ss` material that flows through the bridge
  shape PR 5 finalizes. Out-of-scope for M3c-via-C; lands when the
  bridge lands.
- **Full transaction assembly.** M3c-via-C exercises
  `sign_transaction`, not the transaction builder’s assembly path.
  Transaction-level integration is wallet-RPC-cutover scope.

---

## §4 Risk register

- **R1 — `tx_builder::tests` private fixtures.** `dummy_tree()`,
  `dummy_output()`, etc. are `#[cfg(test)]`-private to
  `shekyl-tx-builder`. M3c-via-C inlines equivalent constructors
  (~30 LOC). If a future change to `tx_builder` mutates the
  `TreeContext` / `OutputInfo` shape, M3c-via-C’s inline
  constructors require parallel updates. Mitigation: keep the
  inline constructors *minimal* (just enough to drive a 1-input,
  1-output, fee=0 sign call) and document the `tx_builder`
  source-of-truth in the test docstring.
- **R2 — Verifier flake.** BP+ and FCMP++ verification under fresh
  `OsRng` randomness has historically been deterministic-on-success
  (the proof either verifies or doesn’t — there is no statistical
  failure path). The risk is essentially zero, but pinning the
  test as
  *flaky-must-not-flake* is the discipline.
- **R3 — Performance.** Pre-implementation estimate (this section
  as originally drafted): `tx_builder::sign_transaction` end-to-end
  ~20 ms per call, sweep ~3 fixtures × 1 sign call = ~60 ms;
  within the migration plan’s `<1 s` budget. **Measured reality
  (post-Trim-1; see §2.1.1):** the FCMP++ membership-proof
  cost (membership-proof costs ≫ BP+ + signing in this end-to-end
  shape; `transfer_e2e[_iai].rs` benches explicitly elide this
  cost) plus the 9-fixture sweep (3 × 3, not 3 × 1 — see §3.1.1
  for the orthogonal-coverage rationale) push the wall-clock to
  ~17.65 s debug / ~6.87 s release. The pre-implementation
  estimate undercounted the FCMP++ proof cost by ~2 orders of
  magnitude and the sweep by 3× (the actual sweep is the 9-fixture
  orthogonal matrix per §2.1 step 6). The migration-plan `<1 s`
  budget is unmet and revised in §6 (c) below; the runtime is
  named-and-accepted given the property pinned (workspace’s sole
  end-to-end successful-execution coverage of
  `tx_builder::sign_transaction`) is load-bearing for M3d. The
  Trim-1 disposition (§2.1.1) halved the Trim-1-precursor runtime
  (32 s debug / 12 s release) by removing the redundant parallel
  sign call; further reduction (Trim 3 — slow-tests feature gate)
  is held in reserve and not deployed speculatively at the
  post-Trim-1 runtime — see §2.1.1.
- **R4 — `pub(crate)` reach.** All required types
  (`SourceSecretsBundle`, `LocalKeys::derive_source_secrets_bundle`,
  `keys.keys.x25519_pk`, etc.) are reachable from inside
  `local_keys.rs::tests`. Confirmed by M3b D5’s reach into the same
  surface. No visibility widening needed.
- **R5 — Test-vector coverage.** §2.1 specifies 3 fixtures
  covering 1-input / 2-input / 3-input cases (the smallest
  meaningful sweep over `n_in - 1` pseudo-blinding generation).
  The migration plan’s §3.3 says "≥3 existing test vectors" — the
  3-fixture sweep meets the count. Subaddress-index variation
  (PRIMARY + non-PRIMARY) covers the `m_i` injection point that M3b
  D5 also varies.
- **R6 — Migration plan staleness.** §3.3 of the migration plan
  was written before the §1.1–§1.3 facts surfaced. The plan
  document is updated by this pre-flight (peer doc) plus a
  cross-reference paragraph appended to §3.3 in the same M3c PR’s
  doc commit, naming the OptionC disposition and pointing back
  here.

---

## §5 Phase decomposition

Following M3b’s precedent
([`STAGE_1_PR_3_M3B_PREFLIGHT.md`](./STAGE_1_PR_3_M3B_PREFLIGHT.md)
landing notes — 10 commits across pre-flight + implementation +
docs):

- **Phase 0 (this commit).** Pre-flight document; no code.
- **Phase 1 — implementation.**
  1. **Commit 1.** Inline test-fixture helpers (`make_tree_context`,
     `make_output_info` in `local_keys.rs::tests`). ~50 LOC.
  2. **Commit 2.** The M3c-via-C test
     `engine_derived_bundle_signs_through_tx_builder_end_to_end`.
     ~150 LOC.
  3. **Commit 3** *(if needed)*. Verifier-acceptance assertion
     extension (covers §2.1 step 5(c)). May be folded into commit
     2 if the verifier import is one-line.
- **Phase 2 — docs.**
  4. Append cross-reference paragraph to
     [`STAGE_1_PR_3_MIGRATION_PLAN.md`](./STAGE_1_PR_3_MIGRATION_PLAN.md)
     §3.3 naming the Option-C disposition and pointing here. ~10
     LOC.
  5. Update `docs/CHANGELOG.md` under the `### Added` section with
     a one-line note. ~3 LOC.
  6. Close-or-amend the FOLLOWUPS entry covering M3b D5 re-location
     to also cover M3c-via-C re-location at the same trigger
     (`KeyEngine` widens to `pub`). ~5 LOC of trigger-text edit.

**Estimate.** ~210 net code lines + ~20 docs lines; ~5 commits;
1 review round.

---

## §6 Success criteria

Mapped from
[`STAGE_1_PR_3_MIGRATION_PLAN.md`](./STAGE_1_PR_3_MIGRATION_PLAN.md)
§3.3’s original criteria, refined per §1.3:

- [x] **§3.3 (a) revised.** Test passes against ≥9 synthetic
      tx_builder-vector fixtures (3 input counts × 3 subaddress
      indices, orthogonal sweep — see §2.1 step 6 for the cross-
      axis-coverage rationale).
- [x] **§3.3 (b) revised + Trim-1 amended.** Engine-derived
      `SpendInput` is byte-identical field-by-field to a hand-
      composed legacy `SpendInput` at the input layer; sign-once on
      the engine path; randomized components verify (BP+ via
      `Bulletproof::read_plus` + `Bulletproof::verify`; FCMP++ via
      `shekyl_fcmp::proof::verify`). See §2.1.1 for why this is
      strictly stronger than the original signer-output-layer
      byte-identity criterion.
- [x] **§3.3 (c) revised.** Original budget `<1 s` was a pre-
      implementation estimate that undercounted FCMP++ membership-
      proof cost by ~2 orders of magnitude (see R3 above). Revised
      budget: ≤25 s debug / ≤10 s release on the workspace's CI
      runner class. Measured (post-Trim-1): ~17.65 s debug / ~6.87 s
      release — within budget. Named-and-accepted as the cost of
      the workspace's sole end-to-end successful-execution coverage
      of `tx_builder::sign_transaction`; further reduction is
      available behind the Trim-3 slow-tests feature gate (held in
      reserve per §2.1.1). If a future fixture expansion pushes the
      runtime materially past the revised budget (>25 s debug),
      revisit Trim 3 deployment as a complement.
- [x] Cross-reference appended to migration plan §3.3.
- [x] CHANGELOG and FOLLOWUPS updated.

The first criterion in the migration plan ("Test passes against ≥3
existing `tx-builder` test vectors") is interpreted as "≥3
fixtures that look like tx-builder test vectors" — the actual
`tx_builder/src/tests.rs::dummy_*` fixtures are private to that
crate and cannot be reached from `local_keys.rs::tests`, so the
fixtures are inlined per §3.1’s adapter-helper disposition.

---

## §7 What this pre-flight does NOT address

- **PR 5’s `TxToSign` shape.** Pinned independently in PR 5’s
  design rounds (parallel track per
  [`STAGE_1_PR_4_REFRESH_ENGINE.md`](./STAGE_1_PR_4_REFRESH_ENGINE.md)
  and the 2026-05-10 sequencing decision).
- **Bridge from `KeyEngine::sign_transaction` to
  `tx_builder::sign_transaction`.** Lands in PR 5.
- **Integration-test re-location.** Lands at `KeyEngine` `pub`
  trigger; FOLLOWUPS entry tracks.
- **M3d / M3e.** Subsequent migration tail; M3c-via-C is the
  precondition.
