# Stage 1 PR 3 — M3e pre-flight investigation

**Status.** Pre-Phase-2 amended (pre-flight commit landed; amendments
applied per user disposition 2026-05-11; ready for implementation).
M3e is the documentation-realignment-of-the-whole that closes the
architectural-inheritance migration sequence
(`STAGE_1_PR_3_MIGRATION_PLAN.md` §3.5); it is **doc-only**, with no
code changes and no schema state changes from M3d.

This pre-flight re-anchors M3e against the actual structural state on
`dev` post-M3d (PR #39 merged at `e09c6fc1f` on 2026-05-11), surveys
the stale-reference surface across the workspace's documentation /
rule corpus, and disposes the open scope questions before Phase 2
begins.

**Amendment cycle (2026-05-11).** The original pre-flight (commit
`82693bab7`) surfaced three open questions (§8); the user's
disposition closes all three and surfaces a calibration framework
shift that applies forward to PR-4 onward. The amendment:

- Closes Q1 by **rejecting D5 deferral** (the 19-file / 82-occurrence
  path-rename sweep folds into M3e per the rule-15 trinary reading
  captured in §11 below; the sweep is mechanical-residue from M3d's
  substrate change, not an out-of-scope tangent).
- Closes Q2 by **consolidating the commit decomposition** from six
  commits (preflight + five substantive) to four commits (preflight +
  three substantive). Pure-docs commits don't carry meaningful
  compile-gate boundaries; granularity beyond review-surface clarity
  doesn't pay back.
- Closes Q3 by **accepting per-question annotation** for KEY_ENGINE
  §7's resolved-vs-open status. Standard pattern.
- Adds §11 (calibration shift framework) capturing the rule-15
  trinary reading, the FOLLOWUPS V3.0/V3.1 queue split, the
  rules-queue consolidation guidance, and forward calibration for
  PR-4 onward.

The amendments apply forward from M3e; M3a–M3d FOLLOWUPS dispositions
stand as authored.

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
   20 files (97 occurrences total). One file is the rule file (D4
   target; 15 occurrences); 19 files / 82 occurrences are the
   workspace-wide residue catalogued in D5. **Per the 2026-05-11
   amendment, the residue folds into M3e per-category** (current-state
   refs renamed; historical / audit-trail / baseline-command refs
   preserved as historical record). **Verified.**

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

**Three candidate scopes.**

- **(α) Defer all 19 files to a separate path-rename PR.** Rule
  file (D4) is the load-bearing fix; the residue catalog is
  documented in M3e's CHANGELOG entry as a starting point for the
  next pass.
- **(β) Fold all 19 files into M3e indiscriminately.** Single
  comprehensive realignment pass with no per-category review.
- **(γ) Fold all 19 files into M3e with per-category disposition.**
  Rename current-state references; preserve historical /
  audit-trail / baseline-command references that document past
  state. Each file reviewed against its category rule.

**Disposition.** **(γ).** _Amended 2026-05-11; original disposition
was (α) — see §11 below for the rule-15 trinary reading that
prompted the shift._ The 19 residue files are mechanically
identifiable, directly traceable to M3d's substrate change, and
surfaced during M3d's review — the qualifying conditions for
"in-scope mechanical-residue" under the trinary reading. Folding
the sweep into M3e closes the migration's natural downhill residue
inside the migration's closing PR rather than deferring it to a
follow-up PR whose per-PR overhead duplicates M3e's.

The per-category disposition applies the four categories from the
table above as rename-vs-preserve rules:

1. **Active reference docs**
   (`docs/FOLLOWUPS.md`, `docs/V3_WALLET_DECISION_LOG.md`,
   `docs/design/WALLET_REWRITE_PLAN.md`): per-doc review.
   Current-state references rename; historical-state references
   (e.g., "the pre-rename crate was named X") preserve with optional
   explanatory note. Each reference is read in context before
   renaming.
2. **Benchmark data artifacts**
   (`docs/benchmarks/*`, baseline `.json` / `.manifest.md` /
   `.iai.snapshot` / `README.md`): **preserve historical refs;
   rename current-command refs only.** Baseline data structurally
   captures the state at recording time; rewriting it would
   invalidate the baseline as a historical comparison point.
   Commands documenting how to reproduce the baseline today get
   renamed; the recorded baseline values stay frozen.
3. **Test fixture READMEs**
   (`rust/shekyl-engine-file/tests/fixtures/adversarial/*.md`,
   `rust/shekyl-engine-state/fuzz/README.md`,
   `rust/shekyl-scanner/README.md`): bulk-rename. References are
   mostly import-path or package-name strings (current-state); 11
   occurrences total across 10 files; no historical preservation
   needed.
4. **Audit-trail (CHANGELOG)**: **preserve as-is** per the M3d
   preflight §3.2 carve-out (append-only historical entries are
   audit trail, not current-state descriptions). Six historic
   `docs/CHANGELOG.md` references stay frozen.

The sweep lands in M3e's commit 3 (path-rename residue sweep +
CHANGELOG) per the consolidated commit decomposition (§4). The
rule file (D4) remains its own load-bearing fix in commit 2 (rule
realignment + FOLLOWUPS closures); the rule file's `globs`
frontmatter is the highest-leverage rename because it controls
the rule's auto-application reach.

The M3d-added FOLLOWUP entry "Rules realignment:
`42-serialization-policy.mdc` pre-rename paths" closes by M3e
commit 2 (rule file rename + entry relocation to "Recently
resolved"). No new FOLLOWUP entry is needed for the residue
sweep — it lands inside M3e rather than deferring.

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
  "Recently resolved"). Plus the **§19 rules-queue entry extensions**
  capturing the rule-15 trinary reading + the rules-queue
  consolidation guidance (per §11 below); plus the **V3.0 / V3.1
  queue split** (section-header re-org separating the two queues
  per §11.2 below).
- **`.cursor/rules/42-serialization-policy.mdc` path realignment**
  (D4 (α)): mechanical
  `s/shekyl-wallet-state/shekyl-engine-state/g`,
  `s/shekyl-wallet-file/shekyl-engine-file/g` against the rule
  body and `globs` frontmatter. Closes the M3d-added FOLLOWUP
  entry.
- **Workspace-wide path-rename residue sweep** (D5 (γ), folded in
  per the 2026-05-11 amendment): 19 files / 82 occurrences, per-
  category disposition (current-state refs renamed; historical /
  audit-trail / baseline-command refs preserved).
- **`docs/CHANGELOG.md` M3e entry** (per plan §3.5 +
  `91-documentation-after-plans.mdc`): `### Changed` entry under
  `[Unreleased]` documenting the M3e doc realignment, the rule
  path-realignment, the FOLLOWUPS realignment + V3.0/V3.1 queue
  split, the path-rename residue sweep with per-category counts,
  and the rule-15 calibration framework shift recorded at M3e's
  boundary.

### §3.2 Out of scope (M3e → deferred to a later PR)

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
- **Rules-queue consolidated landing PR**: V3.1 work per §11.3
  below. M3e captures the calibration guidance in `FOLLOWUPS.md`'s
  §19 entry; the rules-corpus PR itself (1–2 PRs co-landing the
  §18 type-placement + §19 plan-vs-state-divergence + comment-level
  extension + rule-15 trinary refinement + non-`Clone` ban design
  pass as scope allows) is V3.1.
- **Historical-state references in `CHANGELOG.md`**: per the M3d
  preflight §3.2 carve-out (append-only audit trail; previous
  changelog rows are historical state, not current-state
  descriptions). M3e's CHANGELOG entry adds a new `[Unreleased]`
  row; existing rows stay frozen.
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
**Amended 2026-05-11** — the original six-commit decomposition
collapsed to four (preflight + three substantive) per the user's Q2
disposition: pure-docs commits don't have meaningful intermediate
compile boundaries, so granular splits optimize for audit-trail
granularity without bisection benefit; four commits ship the same
scope with cleaner review surface.

| # | Commit | Files touched | Rationale |
|---|---|---|---|
| 1 | `docs(stage-1-pr3-m3e): pre-flight investigation (doc realignment PR)` (landed at `82693bab7`) + the **amendment commit** landing this §11 / §3.1 / §4 / §8 revision | `docs/design/STAGE_1_PR_3_M3E_PREFLIGHT.md` (this file) | Original preflight locks scope; amendment commit records the user's Q1/Q2/Q3 dispositions and the §11 calibration framework shift. |
| 2 | `docs(stage-1-pr3-m3e): post-migration design-doc realignment (KEY_ENGINE + V3_ENGINE_TRAIT_BOUNDARIES + MIGRATION_AUDIT)` | `docs/design/STAGE_1_PR_3_KEY_ENGINE.md`, `docs/V3_ENGINE_TRAIT_BOUNDARIES.md`, `docs/design/STAGE_1_PR_3_MIGRATION_AUDIT.md` | D1 (α) + D2 + plan §3.5 bullet 2: status-banner preface + targeted past-tensing in KEY_ENGINE.md; trait-listing update at V3_ENGINE_TRAIT_BOUNDARIES.md ~L676; MIGRATION_AUDIT.md snapshot ref refresh. All three are the "post-migration design-doc state" logical unit — same review attention; doc-only commits without per-commit compile gates. |
| 3 | `docs(stage-1-pr3-m3e): 42-serialization rule realignment + FOLLOWUPS closures + V3.0/V3.1 queue split` | `.cursor/rules/42-serialization-policy.mdc`, `docs/FOLLOWUPS.md` | D3 + D4 (α): rule path realignment; FOLLOWUPS surgical edits (L492 Stage 2 entry; L2599 close-record past-tense; L763 rule-realignment FOLLOWUP closure-relocation); plus §19 rules-queue entry extensions (rule-15 trinary reading + rules-queue consolidation guidance per §11 below); plus V3.0 / V3.1 queue section-header split per §11.2. |
| 4 | `docs(stage-1-pr3-m3e): workspace-wide path-rename residue sweep + CHANGELOG M3e entry` | 19 files / 82 occurrences across `docs/FOLLOWUPS.md`, `docs/V3_WALLET_DECISION_LOG.md`, `docs/design/WALLET_REWRITE_PLAN.md`, benchmark artifacts, test fixture READMEs; plus `docs/CHANGELOG.md` | D5 (γ): per-category sweep (rename current-state refs; preserve historical / audit-trail / baseline-command refs). Plus the M3e CHANGELOG `### Changed` entry under `[Unreleased]` per plan §3.5 / `91-documentation-after-plans.mdc`, recording the doc realignment, the rule path-realignment, the FOLLOWUPS realignment, the path-rename sweep with per-category counts, and the rule-15 calibration framework shift. |

**Why four commits, not fewer.** The three substantive commits
group by logical-unit-of-work and review-attention boundary: commit
2 is the design-doc-state cluster (post-migration framing across
three docs that share the same trajectory); commit 3 is the
discipline-corpus cluster (rule file + FOLLOWUPS + queue split, all
under the rules / FOLLOWUPS subsystem); commit 4 is the workspace-
wide sweep + closure entry (the residue category and the CHANGELOG
that records it land together because the CHANGELOG cites the
sweep's per-category counts). Folding commit 4 into commit 3 would
mix scope-bounded discipline-corpus edits with workspace-wide
mechanical edits; folding commit 2 into commit 3 would mix design-
doc realignment with rules / FOLLOWUPS work, which are different
review surfaces.

**Why four commits, not six.** The original decomposition split
commit 2 across three sub-commits (one per design doc) and split
the CHANGELOG into its own commit. For docs that all live in the
"post-migration design-doc state" logical unit (D1 + D2 + plan
§3.5 bullet 2), the per-doc split optimizes audit-trail granularity
for changes that share their review attention; the granularity
doesn't pay back at review. Same for the CHANGELOG: it cites the
residue sweep's counts, so co-landing avoids a one-commit lag
between sweep and changelog.

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

- All four commits land cleanly (preflight + amendment + three
  substantive); CI green at every commit boundary.
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
  M3e commit that landed it; (d) §19 rules-queue entry extended
  with rule-15 trinary reading + rules-queue consolidation
  guidance per §11; (e) V3.0 / V3.1 queue section headers
  separating the two queues per §11.2.
- **Workspace-wide path-rename sweep applied per D5 (γ):**
  - Active reference docs: current-state refs renamed; historical
    refs preserved with context. Per-doc-grep verified each
    reference's category disposition.
  - Benchmark data artifacts: historical baseline refs preserved;
    current-command refs renamed.
  - Test fixture READMEs: bulk-renamed.
  - `CHANGELOG.md` historic entries: preserved as-is.
- `CHANGELOG.md` `[Unreleased]` has a `### Changed` entry for
  M3e enumerating: the documentation realignment, the rule
  realignment, the FOLLOWUPS realignment + V3.0/V3.1 queue split,
  the path-rename sweep with per-category counts, and the
  rule-15 calibration framework shift recorded at M3e's boundary.
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
  observation rather than expanding M3e's scope. The rule-15
  trinary reading (§11) applies: in-scope mechanical-residue is
  doc-level renames / past-tensing / FOLLOWUPS closure work
  directly tied to M3d's substrate change; code fixes that surface
  during implementation are out-of-scope structural-tangents
  unless they're explicitly mechanical-residue of M3d.
- **No schema changes.** Snapshots stay frozen.
  `LEDGER_BLOCK_VERSION` / `WALLET_LEDGER_FORMAT_VERSION` stay at 4.
- **No path-rename outside the workspace-wide residue scope** (per
  D5 (γ)). The 19-file / 82-occurrence inventory is the closed
  scope; new references that surface during implementation get
  per-category disposition before merging.
- **No FOLLOWUPS additions beyond the M3-series closure work.**
  The §19 rules-queue entry extension (rule-15 trinary +
  consolidation guidance) is in-scope per §11; the
  rule-realignment FOLLOWUP closure-relocation is in-scope per
  D3.3; the V3.0/V3.1 section-header split is in-scope per §11.2.
  Other new framework-attribution entries are out-of-scope; if
  M3e implementation surfaces a new pattern, capture it in a
  separate FOLLOWUP after M3e merges per the forward calibration
  in §11.4.
- **No re-litigation of M3a–M3d dispositions.** Per §11.5: the
  rule-15 trinary recalibration applies forward from M3e; prior
  PRs' FOLLOWUPS dispositions stand as authored.

---

## §8 Open questions for user disposition

_Per Q3's per-question-annotation pattern: closed questions are
marked inline with `[closed at <ref>]`; original framing is
preserved as the design-rounds history._

1. **D5 (α) acceptance.** The path-rename residue catalog defers 19
   files / 82 occurrences past M3e. Accept the deferral, or fold a
   subset of the categories into M3e? Recommendation: accept (α);
   the load-bearing fix is the rule file.
   **[closed at preflight amendment (2026-05-11); see §2 D5 (γ)
   and §11.1 — rule-15 trinary reading reclassifies the residue
   as in-scope mechanical-residue; the sweep folds into M3e with
   per-category disposition rather than deferring.]**

2. **Commit decomposition.** Six commits including pre-flight. Accept
   as proposed, or prefer consolidation? Two consolidation
   candidates: (a) fold commit 4 (MIGRATION_AUDIT.md snapshot ref)
   into commit 2 (KEY_ENGINE.md) since both are design-doc edits
   under `docs/design/`; (b) fold commit 6 (CHANGELOG) into commit
   5 to land all closure-record work in one commit. Recommendation:
   ship as proposed; the per-commit clarity at review serves the
   M3-series' discipline record.
   **[closed at preflight amendment (2026-05-11); see §4 — the
   decomposition collapses to four commits (preflight + three
   substantive). Commit 2 absorbs the three design-doc realignments
   (KEY_ENGINE + V3_ENGINE_TRAIT_BOUNDARIES + MIGRATION_AUDIT) as
   one logical "post-migration design-doc state" unit; commit 3
   carries rule + FOLLOWUPS work; commit 4 carries the path-rename
   sweep + CHANGELOG (CHANGELOG co-lands with the sweep because it
   cites the sweep's per-category counts).]**

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
   **[closed at preflight amendment (2026-05-11); see D1 (α) +
   §11 — per-question annotation accepted. Closed questions get
   `[closed at M3<X>; see <ref>]` inline; open questions stay
   open with their original framing. Preserves the design-rounds
   history (the α-vs-β iteration trail) while making
   resolved/unresolved state grep-able for future readers.]**

---

## §9 Phase-2 implementation order

1. Pre-flight (`82693bab7`) + amendment commit (this revision) —
   locks scope.
2. Commit 2 (post-migration design-doc realignment cluster:
   `KEY_ENGINE.md` + `V3_ENGINE_TRAIT_BOUNDARIES.md` +
   `MIGRATION_AUDIT.md`) — largest substantive commit;
   `KEY_ENGINE.md` carries the most edit volume (status-banner
   preface + §1/§5/§6/§7 past-tensing + §7 per-question
   annotation). Surface for spot-review before downstream commits
   cut.
3. Commit 3 (rule realignment + FOLLOWUPS closures + V3.0/V3.1
   queue split + §19 rules-queue entry extensions) — mechanical
   rule pass + four FOLLOWUPS edits + queue section-header
   re-org + §19 extension capturing the rule-15 trinary reading
   and rules-queue consolidation guidance from §11.
4. Commit 4 (workspace-wide path-rename residue sweep + CHANGELOG
   M3e entry) — D5 (γ) per-category sweep across 19 files + the
   M3e CHANGELOG entry recording it. CHANGELOG co-lands with the
   sweep so it can cite the sweep's per-category counts.

After commit 2, the substantive review surface is settled. Commits
3 and 4 are mechanical / well-scoped follow-throughs that should
land quickly.

After all three substantive commits land, surface the PR for
review per the M3d precedent (open PR against `dev`; surface for
Copilot review; address findings as a final round; merge when
CI + review green).

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
   updates; close-records get past-tensing; queue-split section
   headers separating V3.0 / V3.1+ per §11.2 if not already present).
5. Workspace-wide path-rename / terminology realignment per the
   rule-15 trinary reading (§11.1): per-category disposition with
   current-state refs renamed, historical / audit-trail / baseline-
   command refs preserved. Mechanical-residue of the substrate
   change folds inline rather than deferring.
6. CHANGELOG entry per `91-documentation-after-plans.mdc`.

This is forward-template content for future Stage-1-style trait-
extraction migrations. Captured here for the M3-series; not added to
the rules corpus (the rules-queue entry for plan-vs-state-divergence
in `FOLLOWUPS.md` is the canonical workspace-discipline anchor; this
observation lives in the per-migration audit trail rather than as a
separate rule).

---

## §11 Calibration shift recorded at M3e boundary

The user's amendment-cycle observations (2026-05-11) surfaced a
calibration framework shift that applies forward from M3e to PR-4
onward. The shift is not a framework rewrite — it operates at the
calibration layer of the existing rules (`15-deletion-and-debt.mdc`
"while we're here is the enemy"; `16-architectural-inheritance.mdc`
"what does this deliver against the threat model?"; the per-PR
pre-flight discipline). What recalibrates is **what counts as
in-scope mechanical-residue vs out-of-scope tangent**.

The discipline-application discovery: under the binary reading
("in-scope or not in-scope"), `15-deletion-and-debt.mdc` was firing
against mechanical residue directly traceable to the just-finished
substrate change. That generated accumulation pressure on the V3.0
FOLLOWUPS queue — each "defer to FOLLOWUP" disposition added work
to a queue whose items must land before genesis. The shift names a
third mode and reroutes mode-2 work into the closing PR.

### §11.1 Rule-15 trinary reading

`15-deletion-and-debt.mdc` "while we're here is the enemy" reads,
under the binary, as: any change outside the PR's stated scope is
"while we're here" and gets deferred. That binary reading collapses
two qualitatively different cases. The trinary reading distinguishes
three modes:

| Mode | Definition | Disposition |
|---|---|---|
| **1. In-scope substantive** | Work the PR was authored to do. | Land in the PR's substantive commits. |
| **2. In-scope mechanical-residue** | Mechanically derivable consequence of the substrate change the PR just made; bounded; directly traceable; surfaced inside the PR's review window. | **Fold into the closing PR.** |
| **3. Out-of-scope structural-tangent** | Unrelated design changes; scope expansion; new features; premature gold-plating of public material. | Defer per `15-deletion-and-debt.mdc`. |

The binary reading treats mode 2 as mode 3. That generates exactly
the accumulation pattern observed on the V3.0 FOLLOWUPS queue at
M3d's merge: 19 files / 82 occurrences of path-rename residue were
deferred to a separate PR despite being mechanically derivable from
M3d's substrate change.

**M3e's D5 is the clearest instance of mode 2:** the workspace-wide
path-rename residue is mechanically identifiable (the source paths
and target paths are workspace-unique strings); directly traceable
(`shekyl-wallet-state` / `shekyl-wallet-file` → `shekyl-engine-state`
/ `shekyl-engine-file` happened pre-M3 sub-PRs but the doc residue
was first surfaced inside M3d's Copilot review); bounded (the
inventory is closed at 19 files / 82 occurrences); and the closing
PR's natural target (M3e is the migration's closing PR, where
"closing" includes closing the migration's mechanical residue). Per
the trinary reading, M3e is the right landing site.

When the §19 / rule-15-refinement artifact lands in V3.1, this
distinction belongs in the rule text directly:

> _"Mechanical residue of the just-finished substrate change folds
> inline; structural design passes get their own pre-flight."_

The pattern that catches the right mode: ask whether the work is
**a downhill of the substrate change the PR just made**. If yes
and the work is bounded and identifiable, it's mode 2 and folds in.
If the work is a separate substrate change, a separate design
review, or unrelated improvement, it's mode 3 and defers.

### §11.2 FOLLOWUPS V3.0 / V3.1 queue split

`docs/FOLLOWUPS.md` currently mixes two queues into one chronological
list:

- **V3.0 pre-genesis queue.** Items must land before genesis. Each
  item carries fixed per-PR overhead (pre-flight + review + CI).
  Accumulation compounds the pre-genesis trajectory cost. Growth
  rate against resolution rate determines whether the pattern is
  sustainable.
- **V3.1+ post-genesis queue.** Items have no near-term deadline.
  Items are well-anchored to precedent PRs. Re-derivation cost is
  low. The queue can grow indefinitely without compounding
  pre-genesis cost.

If the two queues aren't separated explicitly, V3.0 items hide in
a long V3.x list and the accumulation looks manageable when it
isn't. M3e's commit 3 introduces section-header structure that
separates the two queues:

```markdown
### V3.0 pre-genesis queue (load-bearing; must land before genesis)
…items…

### V3.1+ post-genesis queue (sustainable; coherent backlog)
…items…

### Recently resolved (audit trail)
…items…
```

The split is mechanical (re-sort the existing entries by `Target:
V3.0` / `Target: V3.1` markers). No content changes; the structure
makes the load-bearing queue's growth rate visible.

### §11.3 Rules-queue consolidation

The rules-queue is now ~5 distinct topics across the FOLLOWUP
entries (the user characterized it as "~6 deep" — same order of
magnitude):

1. `18-type-placement.mdc` (existing FOLLOWUP entry; in-queue draft).
2. Stateless-actor preference (existing FOLLOWUP entry).
3. `19-plan-vs-state-divergence.mdc` plus the comment-level
   extension (rationale-rot per Finding 5) and the enumeration-
   claim brittle-shape discipline (per Finding 4). Three sub-topics
   under one FOLLOWUP entry — extended in commit `4b931b1b5`.
4. Rule-15 trinary refinement (mode-1 / mode-2 / mode-3 reading per
   §11.1). Captured in M3e commit 3 as a §19 entry extension.
5. Non-`Clone` ban re-evaluation design pass (added in commit
   `4b931b1b5` as a separate FOLLOWUP entry per its design-pass
   character).

Five queued rule artifacts shipping as five PRs is 5× the per-PR
overhead. For pure-documentation work, consolidation:

- **Preserves bisection** (no compile gates between rule files; no
  cross-rule dependency that requires sequencing).
- **Reduces context-switching across reviews** (rule corpus PRs
  benefit from a single review attention pass).
- **Ships the rules as a coherent artifact** (the rules co-evolve
  on the same audit cycle; co-landing makes their relationships
  reviewable in one pass).

**Pin V3.1's rules-queue to land as 1 consolidated rules-corpus PR
(possibly 2 if the non-`Clone` ban re-evaluation warrants its own
design pass per scope). Not 6.**

The §19 entry extension landing in M3e commit 3 captures this
consolidation guidance directly in the rules-queue entry so the
V3.1 landing PR(s) can cite the precedent rather than re-deriving.

### §11.4 Forward calibration for PR-4 and beyond

Apply the trinary rule-15 reading at each PR's pre-flight. When a PR
is closing out (last commit in a migration series; substrate-change
PR with downstream residue), identify mechanical-residue from the
substrate change — path renames, comment-level rationale rewrites
under the §19 extension, enumeration-claim brittleness fixes,
doc-string past-tensing, FOLLOWUPS closure relocations — and **fold
it in** rather than deferring.

Reserve V3.0 FOLLOWUPS for items that genuinely don't fit the
closing PR's scope:

- Independent substrate-change PRs (e.g., the `AllKeysBlob` /
  `ml_kem_dk` newtype wrappers — a separate substrate from M3d's
  `TransferDetails` work, properly its own chore PR).
- Structural design passes that warrant their own pre-flight (e.g.,
  the non-`Clone` ban re-evaluation per the new FOLLOWUP entry
  "Non-`Clone` ban on `TransferDetails` — post-M3d structural
  re-evaluation" in `docs/FOLLOWUPS.md`).
- Cross-component coordination that breaks the project's discipline
  budget (multi-quarter scope, etc.).

Reserve V3.1 FOLLOWUPS for:

- Rules-queue work (consolidate as 1–2 PRs per §11.3).
- Post-genesis architecture work (wallet-RPC cutover, KeyImage
  `Option`-promotion, `transfer_details` Rust migration).
- Structural design passes that don't fit V3.0's pre-genesis
  scope.

The net effect: the V3.0 queue shrinks toward "genuinely structural
items that don't fit closing PRs"; the V3.1 queue stays coherent
rather than diffusing into many small PRs. Each PR genuinely takes
its hill and clears its immediate downhill residue; what defers is
genuinely a different hill.

### §11.5 Application to M3a–M3d dispositions

The calibration shift applies **forward from M3e**. M3a–M3d
FOLLOWUPS dispositions stand as authored — they were correct under
the prevailing binary reading at the time of authoring, and
re-litigating them would expand M3e's scope without proportional
benefit. The shift is recorded at M3e's boundary because M3e is the
M3-series' closing PR; recording the recalibration here lets it
apply forward to PR-4 onward as the per-PR pre-flight discipline
absorbs it.

The pre-flight discipline still applies. Rule 15 still applies.
Rule 16 still applies. The recalibration operates at the
calibration layer, not the framework layer.

---
