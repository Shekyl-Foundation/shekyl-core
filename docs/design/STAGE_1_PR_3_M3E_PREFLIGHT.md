# Stage 1 PR 3 — M3e pre-flight investigation

**Status.** Pre-Phase-2 (pre-flight commit + open dispositions before
implementation begins). M3e is the documentation-realignment-of-the-whole
that closes the architectural-inheritance migration sequence
(`STAGE_1_PR_3_MIGRATION_PLAN.md` §3.5); it is **doc-only**, with no
code changes and no schema state changes from M3d.

This pre-flight re-anchors M3e against the actual structural state on
`dev` post-M3d (PR #39 merged at `e09c6fc1f` on 2026-05-11), surveys
the stale-reference surface across the workspace's documentation /
rule corpus, and disposes the open scope questions before Phase 2
begins.

**Branch.** `feat/stage-1-pr3-m3e` off `dev` at `e09c6fc1f` (post
M3d/PR #39 merge). Pre-flight commits land here before implementation
begins.

**Cross-references.**

- **Migration plan.**
  [`STAGE_1_PR_3_MIGRATION_PLAN.md`](./STAGE_1_PR_3_MIGRATION_PLAN.md)
  §3.5 (M3e — documentation realignment) is the binding scope statement.
  §4.1 records that M3e delivers no property change (doc-only after the
  M3d activation).
- **M3d landing notes.**
  [`STAGE_1_PR_3_MIGRATION_PLAN.md`](./STAGE_1_PR_3_MIGRATION_PLAN.md)
  §3.4.1 ("Post-implementation cross-reference") records the M3d
  five-commit landing and the load-redistribution refinement.
  [`STAGE_1_PR_3_M3D_PREFLIGHT.md`](./STAGE_1_PR_3_M3D_PREFLIGHT.md)
  §3.2 names the "broader documentation realignment-of-the-whole" that
  was deferred to M3e (this PR) along with a carve-out catalog of what
  M3d's commit 5 already absorbed.
- **Property-delivery framing.**
  [`STAGE_1_PR_3_KEY_ENGINE.md`](./STAGE_1_PR_3_KEY_ENGINE.md) is the
  primary realignment target; §7.10–§7.13 define the engine-confined-
  secrets property M3d activated, framed at authoring time as
  forward-looking. M3e's KEY_ENGINE.md commit past-tenses the
  forward-looking framing where the architecture has landed.
- **Folded-in FOLLOWUP.** The
  [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) entry "Rules realignment:
  `42-serialization-policy.mdc` pre-rename paths" (added in M3d's
  commit 4 per Copilot review of PR #39) is folded into M3e per
  user disposition (2026-05-11). The rule realignment co-lands with
  M3e's documentation pass; the FOLLOWUP entry is closed by the same
  commit that lands the realignment.
- **Audit-trail close-record.** The
  [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) "Recently resolved (audit
  trail)" entry "Stage 1 PR 3 architectural-inheritance migration:
  'secrets confined to engine' property activated at M3d" (added in
  M3d's commit 4) is past-tensed in M3e to reflect M3-series
  completion (M3e is the final PR in the M3a–M3e sequence).

---

## §1 Audit invariants — re-verification on `dev` tip `e09c6fc1f`

The M3d preflight's §1 verified six invariants pre-implementation. M3e
inherits a post-M3d substrate; the audit-relevant invariants to
re-verify pre-Phase-2 are doc-corpus invariants rather than code-state
invariants. The seven verified below bound the realignment's scope.

1. **`TransferDetails` schema is post-M3d.** Five legacy
   `Option<Zeroizing<[u8; N]>>` fields (`combined_shared_secret`,
   `ho`, `y`, `z`, `k_amount`) are absent from
   `rust/shekyl-engine-state/src/transfer.rs`; `source_ciphertext`
   and `output_handle` are the only `Option`-valued secret-source
   fields on the schema (other `Option` fields exist for unrelated
   reasons — `subaddress`, `payment_id`, `spent_height`, `key_image`,
   `fcmp_precomputed_path` — per the M3d round-2 Copilot-finding
   commit `ad7f6ba7a` clarification). **Verified.**

2. **`LEDGER_BLOCK_VERSION` and `WALLET_LEDGER_FORMAT_VERSION` are
   both 4.** Bumped 3 → 4 in M3d's commit 2; the wallet_ledger.rs:67
   docstring is the in-source authoritative statement of the pairing
   rule (per the M3d Copilot-finding redirection commit
   `f82af20b6`). **Verified.**

3. **Snapshots `ledger_block.snap` and `wallet_ledger.snap` are
   post-M3d state.** Regenerated in M3d's commit 2; M3e introduces
   no schema changes that would drift them. **Verified.**

4. **`KeyEngine` trait surface is post-migration.** The trait at
   `rust/shekyl-engine-core/src/engine/traits/key.rs:616` carries the
   M3-introduced API (`account_public_address`, `derive_subaddress`,
   `try_claim_output`, `sign_transaction`). The pre-migration trait
   shape that lived on the design-doc rounds (`sign_with_spend`,
   `view_ecdh`, `ml_kem_decapsulate`, `derive_subaddress_public`) is
   no longer in source. **Verified.**

5. **CHANGELOG has entries for M3a/M3b/M3c/M3d.** Plan §3.5's
   "one entry per merged PR" criterion is satisfied at the M3d-merged
   state: M3a (CHANGELOG `### Added` ~line 1003), M3b
   (line 223), M3c (line 106), M3d (line 6 under `### Removed`).
   M3e's CHANGELOG work is adding the **M3e entry itself** (closes the
   M3-series); it is not backfilling missing prior entries.
   **Verified.**

6. **FOLLOWUPS audit-trail close-record exists for M3d.** Line ~2599
   ("Recently resolved (audit trail)") carries the close-record for
   "Stage 1 PR 3 architectural-inheritance migration: 'secrets
   confined to engine' property activated at M3d". M3e updates this
   entry to reflect M3-series completion (M3e is the final PR);
   plan §3.5's "Add (if not already present)" criterion is
   satisfied by the existing entry. **Verified.**

7. **Pre-rename path residue inventory.** Workspace-wide,
   `shekyl-wallet-state` / `shekyl-wallet-file` references appear in
   20 files (97 occurrences total). Categorized in D5 below; M3e's
   commit-5 disposition scopes to the rule file (per D4) and defers
   the workspace-wide residue per D5. **Verified.**

---

## §2 Dispositions D1–D5

### D1 — `KEY_ENGINE.md` realignment shape: status-banner preface vs. comprehensive past-tense pass

**Plan wording (§3.5).** "Update `docs/design/STAGE_1_PR_3_KEY_ENGINE.md`
to reflect post-migration architecture as the operative design
(Round 3's handle-indirected workflow becomes the sole architecture;
pre-migration framing moves to a 'history' section or is deleted)."

**Substrate state.** `KEY_ENGINE.md` is 4269 lines organized as design
rounds (Round 1 / 2 / 3 / 4) + Phase 0 amendment bundles (Phase 0,
0b, 0c, 0d, 0e) + the post-amendment trait surface (§4) + sequencing
(§5) + implementation scope (§6) + open questions (§7). The doc is
structurally already a design-trajectory record; most sections are
authored in the past tense or in the "Round X proposes…" framing
that reads as historical-context-leading-to-current-architecture.
The genuinely forward-looking framing is concentrated in:

- §1 Scope (Phases 0–0d as prerequisite; Phase 1 as implementation
  ahead).
- §5 Sequencing (the spec-amendment PR sequence + the PR 3 feat
  branch as future work).
- §6 What PR 3 implements (scope) — present-tense framing of the
  work the PR will do.
- §7 Open questions — Round 2+ questions framed as "still open".

**Two candidate shapes.**

- **(α) Status-banner preface + targeted past-tensing.** Add a
  top-of-doc post-migration status note declaring "this design
  landed; the rounds below trace the path to the operative
  architecture at §4." Past-tense the forward-looking framing in
  §1 / §5 / §6 / §7 where the work has shipped. Surgical edits;
  doc-shape unchanged.
- **(β) Comprehensive past-tense pass.** Walk every section and
  past-tense any present-tense statement describing the path to
  the design. Re-titles "Open questions" → "Closed questions
  (with M3-series dispositions)." Substantial rewrite touching
  most sections.

**Disposition.** **(α).** The doc's existing structure is a
trajectory record; (β) risks re-litigating the design rounds and
expanding M3e's scope past the "broader realignment" framing
(plan §3.5 said "M3e can land same-day or next-day after M3d"
which presupposes a bounded scope). The targeted past-tensing in
§1 / §5 / §6 / §7 + the status-banner preface delivers the
"operative design" framing without rewriting the design-history
sections.

The (α) shape mirrors the M3d preflight pattern of preserving
historical content as audit trail while updating active framing.
The carve-out of open questions in §7 to closed-with-disposition
is in-scope where the M3 series resolved them; questions that
remain open beyond M3e (`7.5 AllKeysBlob: Clone derive`,
`7.6 Multisig surface`, `7.7 V3.x full-PQC trait churn`, etc.)
stay open with a status note about which ones remain.

### D2 — `V3_ENGINE_TRAIT_BOUNDARIES.md` `KeyEngine` shape update scope

**Plan wording (§3.5).** "Update `docs/V3_ENGINE_TRAIT_BOUNDARIES.md`
if it references the pre-migration `KeyEngine` shape."

**Substrate state.** The doc has 55 `KeyEngine` references. The trait
listing at line 676 documents the **pre-migration** shape
(`sign_with_spend`, `view_ecdh`, `ml_kem_decapsulate`,
`derive_subaddress_public`); the source-of-truth trait at
`rust/shekyl-engine-core/src/engine/traits/key.rs:616` carries the
post-migration shape (`account_public_address`, `derive_subaddress`,
`try_claim_output`, `sign_transaction`). The doc also references
`KeyEngine` extensively in cross-references that are about its
existence as a trait boundary rather than its method shape — those
references remain valid post-migration.

**Two candidate scopes.**

- **(α) Trait-listing update only.** Update the pre-migration trait
  block at line ~676 to match the source-of-truth post-migration
  trait. Five-method swap; surgical.
- **(β) Trait-listing update + method-name reference sweep.** (α) plus
  grep the doc for `sign_with_spend` / `view_ecdh` /
  `ml_kem_decapsulate` / `derive_subaddress_public` references and
  past-tense them or update to post-migration method names where
  active-reference.

**Disposition.** **(β).** (α) leaves stale method-name references
elsewhere in the doc, which propagates the same staleness Copilot
caught in M3d. The grep sweep is small (the four pre-migration
method names are distinctive; false-positive risk is near zero).

The grep enumeration (run as part of this pre-flight) returned
**0 references** to `sign_with_spend`, `view_ecdh`,
`ml_kem_decapsulate`, or `derive_subaddress_public` outside the trait
block at line ~676. (β) collapses to (α) in practice — the
trait-listing update is the entire change. Disposition recorded as
(β) to make the method-name-reference invariant explicit; the
implementation matches (α) by virtue of the substrate.

### D3 — FOLLOWUPS realignment scope

**Plan wording (§3.5).** "Update `docs/FOLLOWUPS.md`:
(a) Close: any open V3.0 entries that reference the pre-migration
architecture (review §V3.0 entries cross-referencing
`KEY_ENGINE.md` for staleness).
(b) Update: §V3.1 line 259 (`Stage 2 — KeyEngine migration to
actor`) cross-reference to use the post-migration trait surface.
(c) Add (if not already present): 'PR 3 architectural-inheritance
migration complete' close-record per the FOLLOWUPS audit-trail
convention."

**Substrate state.**

- **(a) V3.0 entries citing `KeyEngine`.** The doc has 4 entries
  citing `KeyEngine`:
  - L165 "Stage 1 PR 3 engine-property test re-location (trigger:
    `KeyEngine` widens from `pub(crate)` to `pub`; pre-RC1)." —
    trigger condition unchanged at M3e (KeyEngine remains
    `pub(crate)`). **Open; do not close.**
  - L347 "Stage 1 PR 3 (`KeyEngine`) Round 2 review surfaced…" —
    retroactive observation about a discipline lesson. **Open;
    audit-trail-style retention.**
  - L411 "Before Stage 2 (`KeyEngine` migration) cuts…" —
    V3.1 forward-looking. **Open; do not close.**
  - L2599 "Stage 1 PR 3 architectural-inheritance migration:
    'secrets confined to engine' property activated at M3d" —
    audit-trail close-record. **Update text to reflect M3e
    completion (M3-series done); do not delete.**
  - L814 "`derive_output_handle` Python reference script. Stage 1
    PR 3" — Stage-1-PR-3-related but specific to a sub-task.
    **Open; review for staleness.**
- **(b) Stage 2 actor migration entry.** L492 cites pre-migration
  method names (`sign(payload) -> Signature`, `derive_subaddress`,
  view-key scan ops). M3e updates these to post-migration trait
  surface names (`try_claim_output`, `sign_transaction`,
  `derive_subaddress`, `account_public_address`, …).
- **(c) Close-record.** Already present at L2599 (added in M3d's
  commit 4); M3e past-tenses the wording to reflect M3-series
  completion (M3e is the final PR).

**Disposition.** Three FOLLOWUPS edits:

1. **L492 Stage 2 actor migration entry** — update the actor
   message-protocol surface description to reference the
   post-migration trait methods. Surgical paragraph edit.
2. **L2599 close-record** — past-tense the "M3e remains for the
   documentation-realignment-of-the-whole" wording to "M3-series
   complete (M3e merged YYYY-MM-DD)." Surgical sentence edit.
3. **L763 rule-realignment FOLLOWUP** (the one I added in M3d's
   commit 4) — **close-and-relocate** to "Recently resolved":
   the FOLLOWUP is closed by M3e's rule-realignment commit (per D4
   below); the audit-trail relocation preserves the discipline
   record (`15-deletion-and-debt.mdc` "FOLLOWUPS.md is not a
   graveyard" applied to closed entries).

### D4 — `42-serialization-policy.mdc` rule realignment scope

**Folded-in scope.** User disposition 2026-05-11 to fold the rule
realignment (originally a separate FOLLOWUP added in M3d's commit 4)
into M3e.

**Substrate state.** The rule file carries 15 references to
`shekyl-wallet-state` / `shekyl-wallet-file` across:

- `globs` frontmatter (lines 3–5; controls rule auto-application
  reach).
- Body intro paragraph (line 11).
- "The pairing" table (lines 35–39).
- "Mechanical enforcement → Schema snapshot" subsection
  (lines 89, 92, 95).
- "Mechanical enforcement → Zeroizing-field grep" subsection
  (lines 108, 114).
- "Procedure for an intentional schema change" section
  (lines 132, 134).

The path-rename is purely mechanical:
`s/shekyl-wallet-state/shekyl-engine-state/g`,
`s/shekyl-wallet-file/shekyl-engine-file/g`. Both source and target
paths are workspace-unique strings; sed-and-verify is safe.

**Two candidate scopes.**

- **(α) Rule file only.** Mechanical pass against
  `.cursor/rules/42-serialization-policy.mdc`. Single file; close
  the FOLLOWUP entry I added in M3d's commit 4.
- **(β) Rule file + all citing documents.** (α) plus walk every
  document that cites `42-serialization-policy.mdc` (10 files per
  the M3d Round-1 Copilot-finding grep) and verify each citation's
  context reads correctly against the realigned rule.

**Disposition.** **(α).** (β) expands M3e's scope to chase citation
contexts that aren't on the M3e critical path. Citing docs already
reference the rule by name; the rule's stale paths are the
load-bearing fix. The citing-context review is already partially
absorbed by M3e's other commits (KEY_ENGINE.md, FOLLOWUPS,
CHANGELOG); residual citation contexts that don't fall under those
commits are out-of-scope.

The (α) pass closes the FOLLOWUP entry; the FOLLOWUP-closure is
relocated to FOLLOWUPS' "Recently resolved" per D3.3.

### D5 — Workspace-wide path-rename residue disposition

**Substrate state.** Outside the rule file (D4), 19 files carry
`shekyl-wallet-state` / `shekyl-wallet-file` references (82
occurrences total). Categorized:

| Category | Files | Disposition rationale |
|---|---|---|
| **Active reference docs** | `docs/FOLLOWUPS.md` (6 refs), `docs/V3_WALLET_DECISION_LOG.md` (18 refs), `docs/design/WALLET_REWRITE_PLAN.md` (18 refs) | Mix of historical-state (preserve, e.g. "the pre-rename crate was named X") and current-state references (rename). Per-doc review required; not all references are stale. |
| **Benchmark data artifacts** | `docs/benchmarks/shekyl_rust_v0.json` (10 refs), `.iai.snapshot` (3 refs), `shekyl_rust_v0.manifest.md` (4 refs), `wallet2_baseline_v0.manifest.md` (2 refs), `README.md` (2 refs) | Benchmark baselines may carry the pre-rename name in recorded commands / target paths. Renaming risks invalidating baseline comparisons. **Preserve historical refs; rename current-command refs only.** |
| **Test fixture READMEs** | `rust/shekyl-engine-file/tests/fixtures/adversarial/*.md` (8 files, 1 ref each), `rust/shekyl-engine-state/fuzz/README.md` (2 refs), `rust/shekyl-scanner/README.md` (1 ref) | Likely import-path or package-name strings. Mostly current-state refs; bulk-rename candidate. |
| **Audit-trail (append-only)** | `docs/CHANGELOG.md` (6 refs in historic entries) | Per M3d preflight §3.2 carve-out: "append-only historical entries; previous changelog rows are audit trail, not current-state descriptions." **Preserve as-is.** |

**Two candidate scopes.**

- **(α) Defer all 19 files to a separate path-rename PR.** Rule
  file (D4) is the load-bearing fix; the residue catalog is
  documented in M3e's CHANGELOG entry as a starting point for the
  next pass.
- **(β) Fold all 19 files into M3e.** Single comprehensive
  realignment pass.

**Disposition.** **(α).** Per `15-deletion-and-debt.mdc` "while we're
here is the enemy" and the M3d-precedent of bounded-scope
realignment commits: the rule file is the single high-value target
(it's the cited authority; staleness propagates from there). The 19
residue files are mechanically renamable but each carries its own
historical-vs-current disposition question. Folding them into M3e
expands review surface past what plan §3.5 envisaged.

The residue catalog ships in M3e's CHANGELOG entry as a
"next-realignment-pass starting point" inventory. A FOLLOWUP entry
captures the deferral with a target version
(probable: V3.0 if it pairs with another small mechanical sweep;
V3.1 otherwise).

---

## §3 Scope

### §3.1 In scope (M3e)

- **`STAGE_1_PR_3_KEY_ENGINE.md` post-migration framing** (D1): status-
  banner preface + targeted past-tensing in §1 / §5 / §6 / §7 where
  forward-looking framing has shipped.
- **`V3_ENGINE_TRAIT_BOUNDARIES.md` `KeyEngine` trait listing update**
  (D2): replace pre-migration method block (line ~676) with the
  source-of-truth post-migration trait surface; method-name grep
  pass returned zero residue elsewhere.
- **`STAGE_1_PR_3_MIGRATION_AUDIT.md` snapshot reference refresh**
  (per plan §3.5): update the audit's snapshot reference from the
  M3d cut-base (`e6efaf5b5`) to the M3d-landed state (`e09c6fc1f`)
  where the audit cites a current-substrate snapshot.
- **`FOLLOWUPS.md` realignment** (D3): three surgical edits (L492
  Stage 2 entry method names; L2599 close-record M3-series-complete
  past-tense; L763 rule-realignment FOLLOWUP closure-relocation to
  "Recently resolved").
- **`.cursor/rules/42-serialization-policy.mdc` path realignment**
  (D4 (α)): mechanical
  `s/shekyl-wallet-state/shekyl-engine-state/g`,
  `s/shekyl-wallet-file/shekyl-engine-file/g` against the rule
  body and `globs` frontmatter. Closes the M3d-added FOLLOWUP
  entry.
- **`docs/CHANGELOG.md` M3e entry** (per plan §3.5 +
  `91-documentation-after-plans.mdc`): `### Changed` entry under
  `[Unreleased]` documenting the M3e doc realignment, the rule
  path-realignment, the FOLLOWUPS closures, and the path-rename
  residue catalog (per D5 (α)).

### §3.2 Out of scope (M3e → deferred to a later PR)

- **Workspace-wide path-rename residue** (D5 (α)): 19 files / 82
  occurrences across `docs/FOLLOWUPS.md`, `V3_WALLET_DECISION_LOG.md`,
  `WALLET_REWRITE_PLAN.md`, benchmark artifacts, and test-fixture
  READMEs. Catalogued in the M3e CHANGELOG entry; tracked as a
  FOLLOWUP with target version.
- **`STAGE_1_PR_3_KEY_ENGINE.md` Round-1/2/3 design-history sections**:
  preserved as authored (per D1 (α)). The "history sections" are
  the design-trajectory record; rewriting them would erase the
  audit trail of how the architecture was arrived at.
- **C++-side `transfer_details` consumer migration**: tracked
  separately as the V3.1 FOLLOWUP per the audit-trail close-record;
  not affected by M3e (M3e is Rust-side doc realignment).
- **PR-5 (broader Stage 1 per-trait extraction sequence's
  `PendingTxEngine` PR)**: trait-surface completion; out of M3-series
  scope. Distinct from M3e per the M3d preflight §10 disambiguation.
- **Test-relocation for M3b D5 + M3c-via-C**: triggered by
  `KeyEngine::pub(crate)` → `pub` widening; M3e does not widen
  visibility. Bundled in the existing FOLLOWUPS entry at L165.
- **Any code changes**: M3e is doc-only per plan §3.5 / §4.1.

### §3.3 Property delivery at M3e's merge

**None.** Per plan §4.1, M3e delivers no property change beyond what
M3d activated. M3e's value is **documentation correctness against the
post-migration substrate**: future maintainers reading the design
docs / rules / FOLLOWUPS see a self-consistent picture of the
operative architecture, not a mix of pre- and post-migration framing.

The architectural-inheritance discipline anchor
(`16-architectural-inheritance.mdc`) is the load-bearing rule M3e
operates under: documentation that contradicts the operative
architecture **is** stale-architecture-inheritance even when the code
underneath has migrated.

### §3.4 Property delivery against the three-timeframe framing (`00-system-thinking.mdc` / `05-system-thinking.mdc`)

- **Now (V3 / current protocol).** M3e clears stale framing from the
  authoritative design docs. Discipline integrity for the V3.0
  release.
- **Mining era end (~30 years).** No effect; M3e is documentation.
- **Post-quantum era (V4).** No effect; M3e is documentation.

---

## §4 Commit decomposition

The M3d preflight learned that doc-only PRs allow tighter commit
boundaries than schema-bearing PRs (no per-commit CI compile gate).
M3e's initial decomposition proposal — to be amended in review if
the user prefers a different shape — is **six commits** including
this pre-flight investigation:

| # | Commit | Files touched | Rationale |
|---|---|---|---|
| 1 | `docs(stage-1-pr3-m3e): pre-flight investigation (doc realignment PR)` | `docs/design/STAGE_1_PR_3_M3E_PREFLIGHT.md` (new) | This document. Locks scope before substantive edits begin. |
| 2 | `docs(stage-1-pr3-m3e): KEY_ENGINE.md post-migration framing` | `docs/design/STAGE_1_PR_3_KEY_ENGINE.md` | D1 (α): status-banner preface + §1 / §5 / §6 / §7 past-tensing. Substantive but bounded. |
| 3 | `docs(stage-1-pr3-m3e): V3_ENGINE_TRAIT_BOUNDARIES.md KeyEngine trait surface update` | `docs/V3_ENGINE_TRAIT_BOUNDARIES.md` | D2: trait-listing update at line ~676 to match source-of-truth trait shape. |
| 4 | `docs(stage-1-pr3-m3e): MIGRATION_AUDIT.md snapshot ref refresh` | `docs/design/STAGE_1_PR_3_MIGRATION_AUDIT.md` | Per plan §3.5 bullet 2. Update snapshot reference from `e6efaf5b5` (M3d cut-base) to `e09c6fc1f` (M3d landed). |
| 5 | `docs(stage-1-pr3-m3e): 42-serialization-policy rule realignment + FOLLOWUPS edits` | `.cursor/rules/42-serialization-policy.mdc`, `docs/FOLLOWUPS.md` | D3 + D4 (α): rule path realignment; three FOLLOWUPS edits (L492 Stage 2 entry; L2599 close-record past-tense; L763 rule-realignment FOLLOWUP closure-relocation). |
| 6 | `docs(stage-1-pr3-m3e): CHANGELOG M3e entry + path-rename residue catalog` | `docs/CHANGELOG.md` | `### Changed` entry under `[Unreleased]` per plan §3.5 / `91-documentation-after-plans.mdc`. Includes the D5 residue inventory as a FOLLOWUP starting point. |

**Why six commits, not fewer.** Each substantive doc has its own
audit constraints (KEY_ENGINE.md is the design source-of-truth;
V3_ENGINE_TRAIT_BOUNDARIES.md is the trait-boundary reference;
MIGRATION_AUDIT.md is the discipline-application audit trail);
mixing edits across them complicates review. The rule realignment
+ FOLLOWUPS edits cluster (commit 5) is the only multi-file commit
and is bounded by the rule-realignment FOLLOWUP closure relationship.

**Why six commits, not more.** No per-commit CI compile gate forces
the split that M3d's five-commit decomposition required. Commit 5's
two files have a direct relationship (the rule realignment closes
the FOLLOWUP entry); splitting them would invert the dependency.

---

## §5 Branching

- Branch: `feat/stage-1-pr3-m3e` off `dev` at `e09c6fc1f`
  (post-M3d merge).
- Per `06-branching.mdc`: short-lived branch; ≤ 5 working days from
  branch creation to land-on-dev. Doc-only scope makes that bound
  comfortable.
- No code changes; no schema changes. No fmt / clippy / test gate
  required at per-commit boundaries (markdown / rule-file edits
  only).
- Per `91-documentation-after-plans.mdc`: the M3e CHANGELOG entry
  is the documentation-after-plans deliverable for the M3-series
  conclusion.

---

## §6 Success criteria

- All six commits land cleanly; CI green at every commit boundary.
- No reference to the five removed `TransferDetails` fields exists
  as a current-state description outside git history (per plan
  §3.5; M3d's commit 5 carve-out already handled the primary cases —
  `KEY_ENGINE.md` §3.5, `MIGRATION_AUDIT.md` §2.1 / §2.3,
  `shekyl_rust_v0.manifest.md`).
- `KEY_ENGINE.md`'s status-banner preface declares the doc's
  operative-design framing post-M3d.
- `V3_ENGINE_TRAIT_BOUNDARIES.md`'s `KeyEngine` block matches the
  source-of-truth trait at
  `rust/shekyl-engine-core/src/engine/traits/key.rs:616`.
- `MIGRATION_AUDIT.md`'s snapshot reference cites `e09c6fc1f`
  (M3d-landed) where it cites a current-substrate snapshot.
- `42-serialization-policy.mdc` carries zero `shekyl-wallet-state`
  / `shekyl-wallet-file` references; `globs` frontmatter targets
  the renamed crates so the rule auto-applies on edits to
  `rust/shekyl-engine-state/**` and `rust/shekyl-engine-file/**`.
- `FOLLOWUPS.md` has: (a) updated Stage 2 actor entry method
  names; (b) past-tensed M3d audit-trail entry reflecting
  M3-series completion; (c) the rule-realignment FOLLOWUP closed
  and relocated to "Recently resolved" with cross-reference to the
  M3e commit that landed it.
- `CHANGELOG.md` `[Unreleased]` has a `### Changed` entry for
  M3e enumerating the documentation realignment, the rule
  realignment, the FOLLOWUPS closures, and the D5 path-rename
  residue catalog (as a next-pass starting point).
- No new `#[allow(...)]`, `#[cfg(...)]`, or `TODO/FIXME` comments
  introduced. M3e adds no code changes; the gate is sanity, not
  load-bearing.
- `Cargo.lock` unchanged. M3e touches no deps.
- Test count unchanged (M3e adds no tests).
- `cargo fmt --all -- --check` clean (no code touched, but
  defense-in-depth verification before push).

---

## §7 Out-of-scope reminders

- **No code changes.** If implementation surfaces a doc-vs-code
  divergence that wants a code fix, surface it as a follow-up
  observation rather than expanding M3e's scope. Per
  `15-deletion-and-debt.mdc` "while we're here is the enemy".
- **No schema changes.** Snapshots stay frozen.
  `LEDGER_BLOCK_VERSION` / `WALLET_LEDGER_FORMAT_VERSION` stay at 4.
- **No path-rename outside the rule file** (per D5 (α)). The 19
  residue files are catalogued for a future pass.
- **No FOLLOWUPS additions beyond the path-rename-residue deferral
  and the rule-realignment-closure relocation.** The M3-series'
  forward-template-content observations were already captured in
  the M3d preflight §11 framework-attribution entry; M3e does not
  open new framework-attribution threads.

---

## §8 Open questions for user disposition

1. **D5 (α) acceptance.** The path-rename residue catalog defers 19
   files / 82 occurrences past M3e. Accept the deferral, or fold a
   subset of the categories into M3e? Recommendation: accept (α);
   the load-bearing fix is the rule file.

2. **Commit decomposition.** Six commits including pre-flight. Accept
   as proposed, or prefer consolidation? Two consolidation
   candidates: (a) fold commit 4 (MIGRATION_AUDIT.md snapshot ref)
   into commit 2 (KEY_ENGINE.md) since both are design-doc edits
   under `docs/design/`; (b) fold commit 6 (CHANGELOG) into commit
   5 to land all closure-record work in one commit. Recommendation:
   ship as proposed; the per-commit clarity at review serves the
   M3-series' discipline record.

3. **`KEY_ENGINE.md` §7 (open questions) disposition.** D1 (α)
   proposes a status-banner preface + targeted past-tensing in
   §1 / §5 / §6 / §7. For §7 specifically, the M3-series resolved
   some of the open questions (e.g., §7.4 Cross-trait error type;
   §7.10 Handle-table memory-pressure attack) and not others
   (§7.5 `AllKeysBlob: Clone` derive; §7.7 V3.x full-PQC trait
   churn). M3e commit 2 marks the resolved questions with a
   one-line "[closed at M3<X>; see <ref>]" annotation rather than
   deleting them. Accept this approach, or prefer a different
   handling (delete-and-record, separate "Closed questions"
   section, etc.)?

---

## §9 Phase-2 implementation order

1. Commit 1 (this document) — locks scope.
2. Commit 2 (`KEY_ENGINE.md` realignment) — largest substantive
   commit; surface for spot-review before downstream commits cut.
3. Commit 3 (`V3_ENGINE_TRAIT_BOUNDARIES.md` trait listing) —
   surgical.
4. Commit 4 (`MIGRATION_AUDIT.md` snapshot ref) — surgical.
5. Commit 5 (rule realignment + FOLLOWUPS) — mechanical rule pass
   + three FOLLOWUPS edits.
6. Commit 6 (CHANGELOG M3e entry) — PR closure.

After commit 2, the substantive review surface is settled. Commits
3–6 are mechanical / well-scoped follow-throughs that should land
quickly.

After all six commits land, surface the PR for review per the M3d
precedent (open PR against `dev`; surface for Copilot review;
address findings as a final round; merge when CI + review green).

---

## §10 Framework-attribution observation (FOLLOWUP)

The M3-series' pre-flight pattern surfaces one more framework-attribution
observation at M3e: **post-migration documentation realignment is itself
a recurring template across PR-3-style architectural migrations.** The
plan-vs-state-divergence pattern named in the M3d preflight §11
(plan wording predating substrate changes) extends to its mirror at
PR-series end: **post-migration framing predates the substrate's
landed state at every doc-doc boundary**.

For PR 3 specifically, M3e is the realignment commit; for future
multi-PR architectural migrations following the same M3a–M3e shape,
the realignment commit's structure is now templated:

1. Status-banner preface on the design source-of-truth doc.
2. Trait-boundary doc method-shape update against the source-of-truth
   trait.
3. Migration-audit snapshot ref refresh.
4. FOLLOWUPS realignment (Stage-2-actor-style entries get method-name
   updates; close-records get past-tensing).
5. Workspace-wide path-rename / terminology realignment with explicit
   in-scope vs out-of-scope categorization per the M3d/M3e precedent.
6. CHANGELOG entry per `91-documentation-after-plans.mdc`.

This is forward-template content for future Stage-1-style trait-
extraction migrations. Captured here for the M3-series; not added to
the rules corpus (the rules-queue entry for plan-vs-state-divergence
in `FOLLOWUPS.md` is the canonical workspace-discipline anchor; this
observation lives in the per-migration audit trail rather than as a
separate rule).

---
