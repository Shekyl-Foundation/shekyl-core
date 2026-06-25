# shekyl-oxide Un-vendor — Restructure Plan (slice 2)

**Status:** Design draft (2026-06-20). **This is the second slice of the
`shekyl-oxide` un-vendor.** Slice 1 is the genesis wire-format extraction
([`GENESIS_TX_WIRE_FORMAT.md`](GENESIS_TX_WIRE_FORMAT.md) Decision 4): it stands
up the clean wire crate, retires `shekyl-oxide`'s `block`/`transaction`/`fcmp`
serializer, and migrates the ~58 `shekyl_oxide::{block,transaction}` sites. This
doc covers everything the wire slice *leaves behind*: making the kept crypto
crates genuinely pristine, relocating + renaming the residual application-layer
support crates, and reconciling the tracking machinery to one honest story.
**Process:** the crypto-pristine track is genesis-gate-adjacent (it protects a
Q6-frozen surface and feeds the divisor EC-membership external review); the
residual-move track is a **reversible code reorg**, not a consensus decision.
**Parents:** [`GENESIS_TX_WIRE_FORMAT.md`](GENESIS_TX_WIRE_FORMAT.md) (slice 1),
[`CONSENSUS_PORT_SEQUENCE.md`](CONSENSUS_PORT_SEQUENCE.md),
[`TRACK2_REGTEST_PARITY.md`](TRACK2_REGTEST_PARITY.md).

## 0. Posture — legibility, not ownership

`shekyl-oxide` is no longer a vendored dependency in any meaningful sense; even
maintaining the crypto primitives against upstream is a cherry-picking
expedition. The fork concentrates in the application layer but has tendrils into
the primitives, and the tracking machinery built for "code we sync" is being
applied to "code we've decided to permanently diverge" — fighting reality and
encoding confusion into the metadata.

"Is it ours?" is the wrong test, because *everything* is ours. The only thing
the vendoring machinery buys is the ability to pull upstream fixes, and it earns
its overhead **only where we genuinely intend to do that.** So the per-crate
test is:

> **Do we realistically expect to ever re-vendor an upstream change into this?**

- **Yes → keep vendored.** Keep it diffable against the upstream fork, keep the
  divergence CI. This is the FCMP++ research crypto: security-critical, headed
  for the divisor EC-membership external review (a genesis gate), and now also
  carrying **genesis-frozen format by reference** (slice-1 Q6 freezes
  `crypto/fcmps/src/lib.rs` and `fcmp/bulletproofs/src/lib.rs`). A reviewer's job
  is vastly easier against a clean, bounded subtree they can diff against the
  upstream FCMP++ research than against a tree with Shekyl consensus code
  interleaved. The split *serves* the genesis-critical review.
- **No → it's forked.** Move it into a normal `shekyl-*` crate, drop the
  tracking machinery, stamp it with its monero-oxide provenance, stop pretending.

The end state must be **unambiguous**: *vendored* means "pristine, tracked,
external-review-scoped"; *`shekyl-*` crate* means "ours, no upstream." A lingering
half-modified application crate in the `-oxide` tree reproduces the whole
confusion at lower volume. Don't half-do it.

Why now, not later: this is the cheapest the restructure will ever be. Post-
genesis the crypto subtree is frozen-by-audit and the consensus crates are
load-bearing under a live chain — moving them then is a far bigger deal. And
unlike the wire format, the downside here is bounded and reversible if a boundary
turns out wrong ([`00-mission`]: this is hygiene in service of security/privacy
legibility, not a consensus commitment).

## 1. Decisions (locked 2026-06-20)

1. **Scope by the upstream-relationship test (§0), not a "primitives"
   heuristic.** The kept-vendored set is exactly the crypto research crates we
   expect to re-vendor from; everything else moves out.
2. **`divisors` drift goes upstream into the fork** (not patch-overlaid in
   place, not moved out). Re-pin and re-sync so the local copy is a genuinely
   pristine mirror again — restoring diffability for the EC-membership review,
   which is *itself* the review target.
3. **The residual support crates are renamed to final Shekyl names during the
   move** (one churn, full legibility) — but the names are settled against the
   *post-sweep* residual (§7), because slice 1 changes what remains and how it
   connects.
4. **This slice is sequenced strictly after slice 1.** Block/tx is slice-1
   territory; touching it here would rename the ~58-site surface only for slice 1
   to delete it — the double-handling Decision 4 of
   [`GENESIS_TX_WIRE_FORMAT.md`](GENESIS_TX_WIRE_FORMAT.md) explicitly rules out.
   The crypto-pristine track (§6 Track A) is *decoupled* and may run in parallel.

## 2. Triage — is the kept crypto set actually pristine?

Authoritative method: **diff each crypto crate against the pinned commit**
(`3933664d0851871c976f07298b862373d1c6fec0`, sync 2026-04-25, recorded in
`rust/shekyl-oxide/UPSTREAM_MONERO_OXIDE_COMMIT`), extracted via `git archive`.
The live `monero-oxide` working checkout is dirty and ahead of the pin — diffing
against *it* produces false "FORKED" findings; that contamination was the first
trap and is why the pin, not the checkout, is the baseline.

Two framing corrections fell out of this:

- **The Shekyl-stamp scan is the wrong instrument.** It over-counts (12 stamped
  files, all cosmetic or inherited) *and* under-counts (the two real `divisors`
  changes are in **unstamped** files). Diff-against-pin is the only reliable
  signal.
- **The pin is itself a Shekyl fork of Monero's monero-oxide**, not pristine
  Monero. The PQC extra-leaf machinery (`[H(pqc_pk)]`) and the `ShekylCurves`
  test type already exist *in the pin*. So "vendored = pristine upstream" already
  isn't literally true; the honest baseline is "pristine mirror of
  `Shekyl-Foundation/monero-oxide@fcmp++`."

### 2.1 Per-crate verdict (against the pin)

| Crate | Verdict | Evidence |
|---|---|---|
| `helioselene` | **PRISTINE** | hex constants, generators, `b"Helios"`/`b"Selene"`, to/from-bytes identical; rustfmt reflow only. |
| `generalized-bulletproofs` | **PRISTINE** | `commit()` bound, index math, transcript labels/keying byte-identical at pin. |
| `fcmps` (+ `ec-gadgets`, `circuit-abstraction`) | **PRISTINE (not forked)** | `tree.rs` (root/leaf hashing) and `lib.rs::transcript()` token-identical to pin; only an inert `params.rs` API change (`new() -> Option<Self>`). PQC `[H(pqc_pk)]` + `ShekylCurves` are inherited from the pin, unchanged. |
| `divisors` | **FORKED (minor)** | Two genuine logic changes, both in **unstamped** files (so the stamp scan misses them) — see §2.2. |

**Decisive answer:** the hypothesis that `fcmps` is functionally forked (recon /
root-hash-convention / PQC leaf hashing) is **refuted**. `divisors` is the one
forked crate.

### 2.2 The `divisors` divergence (the cut that must heal)

- `crypto/divisors/src/barycentric.rs` — `interpolate()` sizes the output
  polynomial by `self.lagrange_polys.len()` instead of upstream's `evals.len()`.
  When `evals.len() > lagrange_polys.len()` the two produce **different-length
  output vectors** — a real computed-output divergence, not formatting.
- `crypto/divisors/src/divisor.rs` — `Divisor::div()` gains two
  `assert!(self.a.degree >= rhs.degree, …)` / `self.b.degree` underflow guards
  before the `degree -= rhs.degree` subtraction (silent `usize` wrap → panic).

Both read as correctness hardening. They reached the vendored subtree **without
going through the fork** — i.e. they bypassed step 1 of the documented vendoring
workflow (`docs/SHEKYL_OXIDE_VENDORING.md`: "cherry-pick the fix into the fork
*first*"). The fix is to apply that workflow retroactively (§6 Track A).

### 2.3 The genesis-freeze cross-link (raises the bar)

Slice-1 **Q6** freezes the canonical proof/Bp+ interiors *by reference* to
`rust/shekyl-oxide/crypto/fcmps/src/lib.rs` (FCMP++) and
`rust/shekyl-oxide/shekyl-oxide/fcmp/bulletproofs/src/lib.rs` (Bp+). So the
kept-vendored crypto now carries **genesis-frozen format**, and the Bp+ wrapper
in the *application* layer is genesis-load-bearing too. The pristine gate (§6 A1)
is therefore not hygiene — it protects a frozen surface ([`42-serialization-policy`],
[`30-cryptography`]).

**The pin is not just stale — it is proof-format-buggy.** Re-baselining at the
upstream tip (§6 A0) surfaced two genesis-relevant corrections sitting *above* the
pin: an `fcmps` proof-sizing fix (`ni = 2 + 2*(c/2)` → `ni = 2 + 2*c`) and an IETF
constant-`c` alignment — both change the proof structure Q6 freezes. **Round 1 must
therefore freeze on the post-fix tip, not the pin (`3933664d`)**, or genesis freezes
a known-buggy proof size. Our PQC extra-leaf work reapplies cleanly onto the fix and
the `fcmps` suite is green on it, so the correction and our delta are compatible.

## 3. The manifest — three buckets, with the slice-1 boundary

| Bucket | Crates | Owner / fate |
|---|---|---|
| **KEEP-VENDORED** — pristine mirror of fork@pin; tracked; EC-review + Q6-freeze scoped | `crypto/{divisors, helioselene, generalized-bulletproofs, fcmps, fcmps/ec-gadgets, fcmps/circuit-abstraction}` | stays vendored; fixes go upstream → fork → re-pin → re-sync |
| **SLICE-1 OWNED** — *not this doc's scope* | main `shekyl-oxide` crate: `block.rs`, `transaction.rs`, `merkle.rs`, `fcmp.rs` → new wire crate; **crate dissolves** | wire-format slice; ~58 sites |
| **RESIDUAL MOVE-OUT** — this slice, post-sweep | `shekyl-io`, `shekyl-primitives`, `shekyl-generators`, `shekyl-bulletproofs` (`fcmp/bulletproofs`), `shekyl-fcmp-plus-plus` (`fcmp/fcmp++`), `shekyl-rpc`, `shekyl-simple-request-rpc` | rename to final names + drop tracking machinery + provenance-stamp |

**Note — the main crate *dissolves*, it doesn't shrink.** Its four modules are
*all* wire/consensus (`merkle` = the block's tx-tree root; `fcmp.rs` = the
length-prefixed proof wire framing), so slice 1 absorbs the whole crate. Confirm
at slice-1 land that nothing non-wire is stranded in it.

**Consumer-surface reconciliation.** The "~58 sites" figure is the
`{block,transaction}` surface — **slice 1's** migration, not ours. The
workspace-wide total across *all* move-out crates is ~198 sites / 11 consumer
crates. Subtract the slice-1 surface and the RPC crates (delete candidates, §7),
and this slice's rename surface is **~75 sites** on io/primitives/generators/
bulletproofs/fcmp++. The number firms up only once slice 1 lands and we know
what's left. (`shekyl-cli` is *not* a direct consumer — transitive through
`shekyl-engine-rpc` → `shekyl-engine-core`; drop it from the consumer list.)

## 4. Dependency-DAG pre-flight

**Verdict: clean DAG.** No KEEP-VENDORED crypto crate depends — directly or
transitively — on any MOVE-OUT application crate. The flow is strictly
**app → crypto**. The only cross-cut edges are `shekyl-generators` and
`shekyl-fcmp-plus-plus` → crypto crates; that is the boundary surface the move
makes explicit (normal-crate → vendored-crate), and it is fine.

Caveat that *reinforces* the un-vendor rather than blocking it: the main
`shekyl-oxide` crate already depends on first-party `shekyl-archival-retention`
(`rust/shekyl-oxide/shekyl-oxide/Cargo.toml:30`) — it is **already not
pure-vendored**, so the move-out is overdue, not speculative. (This edge belongs
to the dissolving crate, so slice 1 absorbs it; noted for completeness.)

## 5. The machinery & metadata reality being cleaned up

What exists today, and why it's misleading:

- **The divergence CI doesn't check what people assume.**
  `.github/workflows/shekyl-oxide-divergence.yml` is a **weekly staleness canary**
  (Mondays; not on push/PR). It compares the *pinned commit hash* in
  `UPSTREAM_MONERO_OXIDE_COMMIT` against the live fork-branch tip via
  `git ls-remote`. It does **not** diff file contents and does **not** cover any
  `rust/shekyl-oxide/` path. So **there is no automated check that the local
  vendored copy matches the pin** — which is exactly why the `divisors` drift
  went undetected. The gate everyone assumes exists (local copy == pin) does not.
  *(Addressed by A1 — a content-integrity gate now runs on push/PR; see §6 Track A.
  Drift-from-snapshot today, byte-exact-vs-pin after A0.)*
- **Three "upstreams" are named in one tree:**
  - all 14 crate `repository` fields → `Shekyl-Foundation/shekyl-oxide`;
  - the vendoring doc + pin file + CI → `Shekyl-Foundation/monero-oxide@fcmp++`;
  - `docs/MONERO_OXIDE_VENDOR_STATUS.md` → the *original* `monero-oxide/monero-oxide`
    (formerly `kayabaNerve/monero-oxide`).
  The CI never reads the `repository` fields, so the mismatch is silent.
- **No git-subtree / submodule.** The doc's "sync the subtree" step is a manual,
  unscripted copy.

**Target end state (resolved in §6 Track B):**

- *Kept crypto:* `repository` → the fork (`Shekyl-Foundation/monero-oxide@fcmp++`)
  — the single source of truth for "where fixes go." A real **local-vs-pin
  content gate** runs on push/PR; the staleness canary is scoped to these crates.
- *Moved crates:* `repository` → `Shekyl-Foundation/shekyl-core` (they're ours);
  tracking machinery dropped; each moved file carries a monero-oxide provenance
  stamp (origin path + the descended-from commit) so the Phase-9 audit doesn't
  need git archaeology to tell Shekyl-original from Shekyl-derived
  ([`92-copyright-header`], [`93-legacy-symbol-migration`]).
- `docs/SHEKYL_OXIDE_VENDORING.md` rewritten to cover **only** the crypto crates;
  `MONERO_OXIDE_VENDOR_STATUS.md` + `docs/CI_BASELINE.md` collapsed to one
  lineage: pristine Monero research → Shekyl `monero-oxide@fcmp++` fork (adds PQC
  + divisor hardening) → pinned crypto subtree in shekyl-core; application layer
  forked off, untracked.

## 6. The plan — two tracks

### Track A — Crypto pristine (decoupled from slice 1; can start now)

Touches only kept-vendored crates, which neither slice 1 nor Track B otherwise
moves. It is a genesis-gate dependency (Q6 + EC review), so it is the higher-
priority track.

- **A0 — re-baseline the crypto subtree at the upstream tip [EXECUTED on the fork; shekyl-core re-pin gated].**
  The original plan (cherry-pick the divisor patches onto the pin) was overtaken by
  what the fork actually held: an in-flight per-commit upstream sync
  (`chore/upstream-sync-2026-05`) stalled ~8-of-49 commits in, on a *non-compiling*
  intermediate (an out-of-order cherry-pick left a `ConditionallySelectable` use
  without its import). Hand-replaying 49 commits is the cherry-pick expedition §0
  names as the core problem, so we did the reset the posture implies — take upstream
  wholesale, reapply our small delta:
  - New branch **`chore/crypto-resync-from-tip`** off the real upstream `fcmp++`
    tip (`06622980`), pushed to `Shekyl-Foundation/monero-oxide`; the stalled branch
    is preserved as a record.
  - Reapplied the **entire** Shekyl crypto delta as two documented commits: PQC
    extra-leaf scalar support (reapply of `87acb57` onto the fixed `fcmps` — clean
    3-way, **fcmps 7/7**) and the `divisors` `div`/`interpolate` hardening (sourced
    from the vendored copy, the only place it lived — **divisors 6/6**).
    `helioselene`/`gbp` carry upstream's formal-verification + WCG fixes *natively*,
    zero Shekyl delta — the clean, bounded, diff-against-upstream set the EC review
    wants. The crypto `Cargo.toml` metadata is kept upstream-minimal (the Shekyl
    `repository` stamping happens at re-pin per §5).
  - **shekyl-core re-pin — EXECUTED (PR #181):** `UPSTREAM_MONERO_OXIDE_COMMIT` →
    the resync branch tip `2753111c50`, vendored crypto subtree re-synced, A1
    manifest regenerated, and the one consumer break (`FcmpParams::new` became
    infallible) adapted in `shekyl-fcmp-plus-plus`. The `ni` proof-structure change
    rippled cleanly (`proof_size()` delegates to upstream — no KAT regen).
    **Correction to the byte-exact-vs-pin expectation below:** the fork formats with
    nightly-only rustfmt options Shekyl's stable toolchain can't reproduce, and
    `cargo fmt --all` formats path-deps regardless of `exclude`, so the vendored copy
    is reformatted to the workspace rustfmt style (as it always was) — the manifest
    pins *that* tree (catches silent edits; not byte-identical to the fork). The clean
    upstream-formatted mirror is the fork. **Re-vetting Q6 against the moved proof
    structure is DONE (2026-06-25):** Q6 is ratified frozen on `2753111c50` — the wire
    framing is opaque/structural, `proof_len == proof_size` is reconciled (engine KAT
    `0dcef1081` + `kat_fcmp_proof_size_depth1_row` to the real proof), and `fcmps` is
    7/7 green on the new pin. See `GENESIS_TX_WIRE_FORMAT.md` §6 Q6.
- **A1 — add the gate everyone assumed existed. [content gate landed; canary
  re-scoped]** A content-integrity gate now runs on push/PR
  (`.github/workflows/vendored-crypto-content.yml` →
  `scripts/ci/check_vendored_crypto_manifest.sh`): the vendored crypto subtree is
  verified byte-for-byte against a checked-in manifest
  (`rust/shekyl-oxide/CRYPTO_CONTENT_MANIFEST.sha256`), so an in-place edit that
  bypasses the fork workflow — the `divisors` failure mode — fails CI. The weekly
  staleness canary is re-scoped/clarified (`shekyl-oxide-divergence.yml`, now
  "vendored crypto staleness"): commit-hash staleness only, explicitly distinct from
  the content gate.
  - **Snapshot form, not byte-exact-to-fork (resolved post-A0).** The gate verifies
    the working tree against a checked-in manifest of the *vendored* tree — it catches
    silent local edits (the `divisors` failure mode), which is its job. It is NOT a
    byte-comparison against the fork: A0 reformats the subtree to Shekyl's stable
    rustfmt style (the fork's nightly rustfmt options don't reproduce on stable, and
    `cargo fmt --all` formats the path-dep crypto regardless of `exclude`), so the
    manifest pins the reformatted tree. Diffability against upstream lives on the fork,
    not here.
  - **Fmt: `exclude` does NOT isolate the subtree from `cargo fmt` (mistaken
    premise, corrected by A0).** `cargo fmt --all` formats workspace members *and
    their local path-dependencies*, so the crypto (a path-dep of the consumers) is
    formatted regardless of `exclude` (rustfmt's per-path `ignore` is nightly-only).
    The `exclude` does its real job for **clippy/lints** — upstream code isn't subject
    to Shekyl's `-D warnings` gate. For fmt, A0 reformats the subtree to the workspace
    rustfmt style and the manifest pins it; a toolchain bump that reflows it
    regenerates the manifest in the same PR.

### Track B — Residual un-vendor + rename (gated after slice 1)

- **B0 — re-inventory the residual.** Once slice 1 dissolves the main crate,
  confirm what io / primitives / generators / bulletproofs / fcmp++ / rpc
  actually remain and what the wire crate absorbed (esp. the Q10 varint, today in
  `shekyl-oxide/io/src/lib.rs`). The residual also includes the **wallet-domain
  types** `shekyl-scanner` still imports from `shekyl_oxide::transaction`
  (`Timelock`, `StakingMeta`) and `primitives`/`io` (`Commitment`,
  `CompressedPoint`); B1 names their native home. When `Timelock` is brought
  native, define it **block-height-only** (drop the CryptoNote `Time` variant) —
  the scan/refresh slice already maps the timestamp form to `None` and rejects it
  at ingestion, so the variant is dead on chain data; this plus a pruned-safe
  context-free ingestion validator and daemon-side enforcement are tracked
  together in [`../FOLLOWUPS.md`](../FOLLOWUPS.md) ("Block-height-only
  `unlock_time`").
- **B1 — settle the final names** against the post-sweep namespace (§7), per
  [`25-rust-architecture`].
- **B2 — relocate + rename** the residual support crates; provenance-stamp each
  moved file; drop their tracking machinery. Because the crates already carry
  `shekyl-*` names, the directory move alone changes no import sites — the rename
  is the deliberate churn we *chose* (Decision 3) for legibility.
- **B3 — reconcile metadata + docs** to the §5 target end state (free while in
  the files).
- **B4 — verify + land.** `cargo fmt --check`, `cargo clippy --all-targets -- -D
  warnings`, `cargo test --workspace`, `ninja shekyld`, plus the A1 content gate
  green; land as a deliberate restructure off `dev` ([`06-branching`];
  [`45-rust-lint-checks`], [`50-testing`]).

## 7. Open decisions (resolve against the *post-sweep* residual)

Finalizing these before slice 1 lands risks naming a crate slice 1 merges or
empties — the same double-handling trap one level down. Each is a B1 input.

- **`shekyl-io`** — slice-1 Q10 pins the canonical varint to *its* `lib.rs`, and
  the new wire crate is its primary consumer. Slice 1 may **absorb** varint into
  the wire crate, shrinking or eliminating `shekyl-io`. (Fold candidate:
  `shekyl-encoding`.)
- **`shekyl-primitives`** — overlaps the existing `shekyl-types`; fold vs rename
  needs its src inventory.
- **`shekyl-fcmp-plus-plus`** — name-collides with the existing `shekyl-fcmp`;
  resolve the relationship before naming (fold vs distinct).
- **`shekyl-generators`** — crypto-adjacent (depends on kept crypto crates); it
  is the app→crypto boundary surface; name to make that boundary legible.
- **`shekyl-rpc` / `shekyl-simple-request-rpc`** — `shekyl-daemon-rpc` already
  exists as the successor and the AXUM cutover is in motion; these are likely
  **delete candidates, not rename candidates.** Decide by the same upstream-
  relationship test.
- **`shekyl-bulletproofs`** (`fcmp/bulletproofs`) — genesis-frozen by reference
  (Q6); already a clean name; likely kept as-is, but confirm placement relative
  to the kept-vendored crypto vs the wire crate.

## 8. Sequencing

1. **Track A — A0 executed on the fork; shekyl-core re-pin gated.** The crypto
   subtree is re-baselined at the upstream tip (`chore/crypto-resync-from-tip`,
   pushed) with the two-commit Shekyl delta reapplied and green; A1's content gate
   runs on push/PR. The remaining step — re-pin shekyl-core to the new tip + re-vet Q6 —
   is a genesis-format change, sequenced with slice 1 (step 2).
2. **Slice 1 lands** (wire-format extraction; main crate dissolves; ~58 sites
   migrated) — out of this doc's scope, tracked in
   [`GENESIS_TX_WIRE_FORMAT.md`](GENESIS_TX_WIRE_FORMAT.md).
3. **Track B begins** once slice 1 is on `dev`: B0 re-inventory → B1 names → B2
   relocate+rename → B3 metadata → B4 verify+land.

On approval, append a binding entry to
[`../V3_WALLET_DECISION_LOG.md`](../V3_WALLET_DECISION_LOG.md) recording the
upstream-relationship test, the keep/move split, and the `divisors`-to-fork
decision — mirroring how slice-1 Decision 4 was logged.

---

*Triage evidence (this slice's findings): the kept-crypto diff is against pin
`3933664d`; `divisors` is the sole forked crate (`barycentric.rs`,
`divisor.rs`); `fcmps` is pristine. The stamp scan is unreliable in both
directions. The divergence CI checks commit-hash staleness, not local content.
Three upstreams are named across the tree's metadata. The cut is a clean
app→crypto DAG.*
