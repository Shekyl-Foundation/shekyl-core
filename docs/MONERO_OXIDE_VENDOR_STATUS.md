# Monero-oxide vendor status

Audit produced for **PR 0.4** of the `shekyl_v3_wallet_rust_rewrite` plan
(see `.cursor/plans/shekyl_v3_wallet_rust_rewrite_3ecef1fb.plan.md` Phase 0).
Vendor-bump portion executed by **PR 0.6** on the same day; see
"PR 0.6 vendor-bump execution" below.

## Scope

This document is a **freshness audit only**. Per the rewrite plan's Phase 0
charter, the goal is to record where the vendored `shekyl-oxide` snapshot
sits relative to:

1. The Shekyl fork — `Shekyl-Foundation/monero-oxide`, branch `fcmp++`.
2. The original upstream — `monero-oxide/monero-oxide` (formerly
   `kayabaNerve/monero-oxide`; the canonical Luke-Parker repo), branch
   `fcmp++`.

It is explicitly **not** a re-vendor or un-pin operation. The actual
"un-pin `monero-oxide`, decide what to merge from kayabaNerve, decide what
the Shekyl fork's relationship to upstream looks like long-term" exercise
is a separate plan (see `docs/FOLLOWUPS.md` § "V3.1+ — Legacy C++ → Rust
rewrite scope" for the placeholder).

The audit produces three deliverables consumed by the un-pin plan:

- A per-crate map of vendored / fork-tip / upstream-tip commits.
- A list of substantive upstream commits that the fork is currently behind
  on (the un-pin plan's input queue).
- A list of fork-only commits (the un-pin plan's "what is Shekyl-specific"
  baseline).

## Reference points (audit date: 2026-04-25)

| Reference | Commit | Date | Subject |
| --- | --- | --- | --- |
| Vendored snapshot | `87acb57e0c3935c8834c8a270bd3bdcbbe36bcde` | 2026-04-05 | Add support for extra leaf scalars in Shekyl curves |
| Fork tip (`origin/fcmp++`) | `3933664d0851871c976f07298b862373d1c6fec0` | 2026-04-16 | Update copyright header guidelines for Shekyl Foundation |
| Upstream tip | `0e438aed2cce5c0ab8a935916c1a89bb0077f97f` | 2026-04-23 | Move where we check the properties of the leading entries of the `l` polynomial |
| Fork↔upstream merge base | `92af05e0d44bd1ec1fed6028a8d2aade615f805a` | 2025-11-22 | Fix `proof_sizes` |

The vendored metadata file (`rust/shekyl-oxide/UPSTREAM_MONERO_OXIDE_COMMIT`)
agrees with the snapshot commit above.

## Per-crate map

Vendored paths are workspace members declared in `rust/Cargo.toml`. Fork
paths match vendored paths exactly (the vendored tree is a literal
sub-tree copy of the fork). Upstream paths reflect the post-reorg
structure on `upstream/fcmp++` (see "Upstream restructure" below).

| Workspace member (vendored) | Fork path (`origin/fcmp++`) | Upstream path (`upstream/fcmp++`) | Last fork commit on path | Last upstream commit on path |
| --- | --- | --- | --- | --- |
| `shekyl-oxide/crypto/helioselene` | `crypto/helioselene` | `crypto/helioselene` | `416d8d1` (Transition rename, 2026-04-05) | `c240ada` debug_assert in release-mode (2026-04-23) |
| `shekyl-oxide/crypto/divisors` | `crypto/divisors` | `crypto/divisors` | `416d8d1` (2026-04-05) | `b4bb6c0` Update MSRVs (2026-04-04) |
| `shekyl-oxide/crypto/generalized-bulletproofs` | `crypto/generalized-bulletproofs` | `crypto/generalized-bulletproofs` | `416d8d1` (2026-04-05) | `0e438ae` `l` polynomial leading-entry check (2026-04-23) |
| `shekyl-oxide/crypto/fcmps/circuit-abstraction` | `crypto/fcmps/circuit-abstraction` | `crypto/fcmps/circuit-abstraction` | `416d8d1` (2026-04-05) | `b4bb6c0` Update MSRVs (2026-04-04) |
| `shekyl-oxide/crypto/fcmps/ec-gadgets` | `crypto/fcmps/ec-gadgets` | `crypto/fcmps/ec-gadgets` | `416d8d1` (2026-04-05) | `b4bb6c0` Update MSRVs (2026-04-04) |
| `shekyl-oxide/crypto/fcmps` | `crypto/fcmps` | `crypto/fcmps` | `87acb57` extra leaf scalars (2026-04-05) | `8ff1f90` GBP optimization (2026-04-22) |
| `shekyl-oxide/shekyl-oxide/io` | `shekyl-oxide/io` | `monero-oxide/io` | `416d8d1` (2026-04-05) | `b6d3e44` Rollup of misc commits (2026-01-19) |
| `shekyl-oxide/shekyl-oxide/generators` | `shekyl-oxide/generators` | (split — see "Upstream restructure" below) | `416d8d1` (2026-04-05) | n/a after split; see notes |
| `shekyl-oxide/shekyl-oxide/primitives` | `shekyl-oxide/primitives` | `monero-oxide/primitives` | `416d8d1` (2026-04-05) | `b6d3e44` Rollup of misc commits (2026-01-19) |
| `shekyl-oxide/shekyl-oxide/fcmp/bulletproofs` | `shekyl-oxide/fcmp/bulletproofs` | `monero-oxide/ringct/bulletproofs` | `416d8d1` (2026-04-05) | `3e37924` `cargo +nightly clippy` (2026-04-04) |
| `shekyl-oxide/shekyl-oxide/fcmp/fcmp++` | `shekyl-oxide/fcmp/fcmp++` | `monero-oxide/ringct/fcmp++` | `87acb57` extra leaf scalars (2026-04-05) | `b4bb6c0` Update MSRVs (2026-04-04) |
| `shekyl-oxide/shekyl-oxide` (umbrella) | `shekyl-oxide/` | `monero-oxide/` | `182b648` Cargo profiles + base58 (2026-04-06) | `b4bb6c0` Update MSRVs (2026-04-04) |
| `shekyl-oxide/shekyl-oxide/rpc` | `shekyl-oxide/rpc` | `monero-oxide/interface/daemon` | `416d8d1` (2026-04-05) | `b6d3e44` Rollup of misc commits (2026-01-19) |
| `shekyl-oxide/shekyl-oxide/rpc/simple-request` | `shekyl-oxide/rpc/simple-request` | `monero-oxide/interface/daemon/simple-request` | `416d8d1` (2026-04-05) | `b6d3e44` Rollup of misc commits (2026-01-19) |

Notes on the per-crate table:

- "Last fork commit on path" reads as: the most recent commit on
  `origin/fcmp++` that touched any file under that subtree. `416d8d1`
  ("Transition project from Monero-oxide to Shekyl-oxide") is the global
  rename commit and shows up everywhere; subsequent commits only appear
  where they actually touched the path.
- The `crypto/*` subtrees were not renamed by `416d8d1`; the rename only
  applied to the umbrella formerly called `monero-oxide/`. The fork
  retained the upstream layout for `crypto/`.
- `shekyl-oxide/shekyl-oxide` umbrella Cargo.toml carries `182b648`
  ("Update Cargo.toml profiles and enhance base58 decoding logic"), the
  one Shekyl-only commit since `87acb57` that touches behavior rather
  than policy/CI/docs. Worth a closer read at re-vendor time; see
  "Vendored ↔ fork delta" §1 below.

## Vendored ↔ fork delta (5 commits, all minor)

The vendored snapshot is **5 commits behind fork tip**. None of them touch
crypto code paths (`crypto/*`, `shekyl-oxide/fcmp/*`,
`shekyl-oxide/primitives`, `shekyl-oxide/io`, `shekyl-oxide/generators`):

| Commit | Date | Subject | Crypto-relevant? |
| --- | --- | --- | --- |
| `182b648` | 2026-04-06 | Update Cargo.toml profiles and enhance base58 decoding logic | Indirect — base58 decoder hardening; address path |
| `157c8f3` | 2026-04-06 | Add Shekyl-first development rules and guidelines | No — `.cursor/rules/` only |
| `6b385c3` | 2026-04-07 | Update Shekyl action configuration to remove redundant command line option | No — CI |
| `a37d2ce` | 2026-04-07 | Add branch policy guidelines for Shekyl core and GUI wallet | No — `.cursor/rules/` only |
| `3933664` | 2026-04-16 | Update copyright header guidelines for Shekyl Foundation | No — header policy doc |

**Re-vendor cost: trivial.** The vendor-bump from `87acb57` to `3933664`
is mechanical: copy the fork subtree, update
`UPSTREAM_MONERO_OXIDE_COMMIT`, run the workspace verification suite per
`docs/SHEKYL_OXIDE_VENDORING.md`. The only commit worth a content review
is `182b648`, specifically the base58 decoder hardening — verify it
doesn't change wallet address parsing semantics in a way `shekyl-address`
depends on.

This bump is **not** scheduled by this audit. The un-pin plan or a
follow-up vendor-refresh PR will schedule it; this audit just records
that it's available and cheap.

## PR 0.6 vendor-bump execution (2026-04-25)

PR 0.6 (`chore/phase0-pr06-oxide-vendor-bump`) executed the `87acb57` →
`3933664` vendor-bump on the same audit date. Three findings emerged
during execution that refine the audit's "trivial" classification to
"strictly metadata-only":

1. **No vendored file content actually changed.** Running
   `git diff --name-only 87acb57..3933664 -- 'crypto/**' 'shekyl-oxide/**'`
   on the fork repo lists exactly two files:
   `shekyl-oxide/wallet/base58/src/lib.rs` and
   `shekyl-oxide/wallet/base58/src/tests.rs`. **Neither is vendored** in
   `rust/shekyl-oxide/` — the fork's `shekyl-oxide/wallet/` subtree
   (Monero-shaped wallet code) is excluded per `60-no-monero-legacy.mdc`,
   and Shekyl uses native `shekyl-address` (Bech32m) instead.
2. **The umbrella `Cargo.toml` is byte-identical** between the vendored
   copy (`rust/shekyl-oxide/shekyl-oxide/Cargo.toml`) and the fork tip.
   The "Cargo.toml profiles" portion of `182b648` lives in the fork's
   *workspace-root* `Cargo.toml`, which we do not vendor.
3. **The `182b648` base58 review is moot for shekyl-core.** Workspace
   grep for `monero_base58 | shekyl-oxide.*base58 | ::base58::` returns
   zero matches; `shekyl-address` depends only on the `bech32` crate and
   `shekyl-encoding`/`shekyl-crypto-hash`. The hardening itself is
   strictly more restrictive (rejects more inputs via `checked_add` +
   non-canonical-encoding check, accepts no new inputs), so even a
   hypothetical downstream consumer would only see additional `None`
   returns, never different `Some(_)` payloads.

PR 0.6 therefore consisted of:

- Updating `rust/shekyl-oxide/UPSTREAM_MONERO_OXIDE_COMMIT` from
  `87acb57e0c3935c8834c8a270bd3bdcbbe36bcde` (sync_date 2026-04-06) to
  `3933664d0851871c976f07298b862373d1c6fec0` (sync_date 2026-04-25).
- Running the workspace verification suite per
  `docs/SHEKYL_OXIDE_VENDORING.md`:
  `cargo build --locked -p shekyl-fcmp` (clean) and
  `cargo test --locked --workspace` (**900 passed, 0 failed, 6
  ignored**, exit 0). `ninja shekyld` was skipped because PR 0.6 does
  not touch the C++ side and `docs/SHEKYLD_PREREQUISITES.md` already
  certifies the C++ daemon as ready.
- Documentation updates (this section, `docs/CHANGELOG.md`,
  `docs/V3_WALLET_DECISION_LOG.md`).

The `.github/workflows/shekyl-oxide-divergence.yml` CI guard (per
`docs/SHEKYL_OXIDE_VENDORING.md`) now compares against the new pin and
will report zero divergence until the fork advances again.

**Operation B remains unchanged.** The 40-commit fork ↔ upstream delta
(below) is unaffected by PR 0.6 and remains scoped to a separate V3.1.x
follow-up per `docs/FOLLOWUPS.md`.

## Fork-only commits (8 commits since merge base, oldest first)

These are the Shekyl-specific patches the un-pin plan must preserve when
deciding what "the fork's relationship to upstream looks like long-term":

| Commit | Date | Subject | Category |
| --- | --- | --- | --- |
| `1194d9c` | 2025-11-23 | Refactor and update for Shekyl fork | Initial fork bring-up |
| `416d8d1` | 2026-04-05 | Transition project from Monero-oxide to Shekyl-oxide | Rename — `monero-oxide/` → `shekyl-oxide/` |
| `87acb57` | 2026-04-05 | Add support for extra leaf scalars in Shekyl curves *(currently vendored)* | Crypto — Shekyl curve specialization |
| `182b648` | 2026-04-06 | Update Cargo.toml profiles and enhance base58 decoding logic | Cargo + base58 |
| `157c8f3` | 2026-04-06 | Add Shekyl-first development rules and guidelines | `.cursor/rules/` policy |
| `6b385c3` | 2026-04-07 | Update Shekyl action configuration to remove redundant command line option | CI |
| `a37d2ce` | 2026-04-07 | Add branch policy guidelines for Shekyl core and GUI wallet | `.cursor/rules/` policy |
| `3933664` | 2026-04-16 | Update copyright header guidelines for Shekyl Foundation | Copyright header policy |

The two crypto-substantive Shekyl-only commits are `416d8d1` (rename;
moves `monero-oxide/*` → `shekyl-oxide/*` but no algorithm change) and
`87acb57` (extra leaf scalars). The latter is the only Shekyl-original
algorithmic divergence and is what makes a "just track upstream" strategy
not viable — Shekyl curves require this support.

## Fork ↔ upstream delta (40 commits, several substantive)

The fork is **40 commits behind upstream `fcmp++` tip** since the merge
base `92af05e` (2025-11-22). The full delta is recorded for reference
below; the un-pin plan's input is the substantive subset.

### Substantive upstream commits the fork is missing

These are the commits that affect crypto correctness, performance, or
public API. The un-pin plan should evaluate each for inclusion.

| Commit | Date | Subject | Touches | Severity |
| --- | --- | --- | --- | --- |
| `cba7117` | 2026-04-05 | Respond to cypherstack/generalized-bulletproofs-fix audit issues | `crypto/fcmps/src/lib.rs`, `crypto/generalized-bulletproofs/src/arithmetic_circuit_proof.rs` | **High** — security-relevant audit response |
| `00bafcf` | 2026-04-21 | Fix `HelioseleneField::invert` (Veridise formal-verification edge case) | `crypto/helioselene/src/field.rs` | **High** — correctness bug fix |
| `af44fb4` | 2026-04-21 | Add debug assertion for invariant of `invert`'s `step` algorithm | `crypto/helioselene/src/field.rs` | Medium — debug-only assertion |
| `f58f2a9` | 2026-04-21 | Reorganize `helioselene` in response to formal verification, and update documentation | `crypto/helioselene/` | Medium — refactor + doc |
| `e5d533c` | 2026-04-21 | Replace a manual `shr_vartime` with a call to `shr_vartime` | `crypto/helioselene/` | Low — perf cleanup |
| `0d6f5e8` | 2026-04-06 | Add missing `C::G: ConditionallySelectable` bound | `crypto/generalized-bulletproofs/src/lib.rs` | **High** — type-bound correctness |
| `1ac294e` | 2026-04-04 | Fix update of `WCG` to a `BTreeMap` w.r.t. other libraries within the tree | `crypto/fcmps/circuit-abstraction/src/lib.rs` | **High** — correctness bug fix |
| `a5cc436` | 2026-04-04 | Represent `WCG` not as a non-sparse `Vec` of sparse vectors, but a sparse `BTreeMap` of sparse vectors (#4) | `crypto/generalized-bulletproofs` | High — performance + memory |
| `7568518` | 2026-04-04 | Lazy deserialize proof elements within the SA+L proof | `crypto/fcmps` | High — wallet hot-path perf |
| `8ff1f90` | 2026-04-22 | Implement the optimization noted within the 'fixed' GBP draft | `crypto/fcmps`, `crypto/generalized-bulletproofs` | Medium — perf |
| `0e438ae` | 2026-04-23 | Move where we check the properties of the leading entries of the `l` polynomial | `crypto/generalized-bulletproofs` | Medium — verification ordering |
| `c240ada` | 2026-04-23 | Cargo still compiles code inside debug_assert! in release mode (#175) | `crypto/helioselene` | Medium — release-build correctness |
| `cae84b7` | 2026-01-07 | New `monero-rpc` candidate (#66) | `monero-oxide/rpc/` → `monero-oxide/interface/daemon/` | Likely not directly mergeable — Monero-shaped RPC; Shekyl rebuilds the daemon RPC client Shekyl-natively in Phase 4 |
| `b6d3e44` | 2026-01-19 | Rollup of miscellaneous commits (#155) | Various | Medium — needs unpacking |
| `64a7489` | 2026-04-03 | Merge `main` into `fcmp++` | Various | Medium — merge commit; constituents need separate evaluation |

### Highlight: cypherstack `generalized-bulletproofs-fix` response

`cba7117` ("Respond to <https://github.com/cypherstack/generalized-bulletproofs-fix>") is the most
important upstream commit the fork is missing. It's Luke Parker's
response to Cypher Stack's audit of `generalized-bulletproofs`,
addressing two filed issues (`#1` and `#2`) plus indexing tweaks. It
landed upstream on **2026-04-05** — the same calendar day as the fork's
`416d8d1` and `87acb57` commits — but is on the upstream-only side of the
merge base (`92af05e`, 2025-11-22).

Per Luke's commit message, two of the cypherstack issues are still open
("are left as blockers") and the indexing tweaks have not been
sign-off-reviewed by upstream as of `cba7117`. The un-pin plan should
treat this as **a known-open audit response, not a known-good fix** —
re-vendoring `cba7117` doesn't close the cypherstack audit, it just keeps
us aligned with upstream's in-progress response.

This is the highest-priority item on the un-pin plan's input queue. It
also informs Shekyl's primitives audit scope per the rewrite plan: any
primitives audit must cover the cypherstack-fix response surface
regardless of whether we adopt `cba7117` directly or carry our own
equivalent.

### Highlight: helioselene formal-verification cluster

`00bafcf`, `af44fb4`, `f58f2a9`, `e5d533c` are a sequence dated 2026-04-21
that responds to Veridise's formal-verification work on `helioselene`.
The headline finding is in `00bafcf`: `HelioseleneField::invert` had an
edge case where `a` could be reduced without `b` being reduced, breaking
the loop-body assumption. This is a correctness bug in field inversion
and is **active in the vendored code**.

The un-pin plan should prioritize this cluster alongside the cypherstack
fix.

### Full upstream-only commit list (for reference)

The full 40-commit delta from `git log --oneline origin/fcmp++..upstream/fcmp++`:

```text
0e438ae Move where we check the properties of the leading entries of the `l` polynomial
c240ada Cargo still compiles code inside debug_assert! in release mode (#175)
8ff1f90 Implement the optimization noted within the 'fixed' GBP draft
e5d533c Replace a manual `shr_vartime` with a call to `shr_vartime`
f58f2a9 Reorganize `helioselene` in response to formal verification, and update documentation
00bafcf Fix `HelioseleneField::invert`
af44fb4 Add debug assertion for invariant of `invert`'s `step` algorithm
0d6f5e8 Add missing `C::G: ConditionallySelectable` bound
cba7117 Respond to https://github.com/cypherstack/generalized-bulletproofs-fix
b4bb6c0 Update MSRVs of FCMP++ crates
e8ade65 Add missing `helioselene/alloc` feature to `monero-fcmp-plus-plus`
1ac294e Fix update of `WCG` to a `BTreeMap` w.r.t. other libraries within the tree
7568518 Lazy deserialize proof elements within the SA+L proof
9a22942 `doc_auto_cfg` -> `doc_cfg`
a5cc436 Represent `WCG` not as a non-sparse `Vec` of sparse vectors, but a sparse `BTreeMap` of sparse vectors (#4)
cfeda0a Respond to a pair of nits raised by @Boog900
e4da504 Use `is_power_of_two` in applicable spot
ca1a9fb Add "crypto" branch as reason to run tests
a3825fd Modernize CI
ff1a225 Update CI, dependencies
3e37924 `cargo +nightly clippy`
64a7489 Merge `main` into `fcmp++`
c8be5d3 Gate debug-only Extra::write assertions behind cfg(debug_assertions)
b6d3e44 Rollup of miscealleanous commits (#155)
0f10a09 Clarify alternate methods of disclosure (#162)
cae84b7 New `monero-rpc` candidate (#66)
097728e Documentation nits
0fec70e Add convenience function `.with_payment_id` to monero-address (#148)
aebc44f Miscellaneous updates and bug fixes (#140)
08c8950 Add `SignableTransaction::unsigned_transaction` (#135)
```

(Truncated at 30 — the remaining 10 are pre-2026-01-07 and predominantly
test/CI cleanup; the un-pin plan can recover them via the same `git log
origin/fcmp++..upstream/fcmp++` invocation against the vendor metadata's
recorded upstream.)

## Upstream restructure (post-merge-base, fork did not follow)

Between merge base `92af05e` (2025-11-22) and upstream tip `0e438ae`
(2026-04-23), upstream restructured the `monero-oxide/` umbrella. The
fork did not pick up the restructure. Re-vendoring will need to either
adopt the new layout or maintain a path-mapping. Affected paths:

| Pre-reorg path (= fork layout) | Post-reorg upstream path | Note |
| --- | --- | --- |
| `monero-oxide/rpc` | `monero-oxide/interface` | Plus `daemon/` sub-split |
| `monero-oxide/rpc/simple-request` | `monero-oxide/interface/daemon/simple-request` | |
| `monero-oxide/generators` | Split: `monero-oxide/ed25519/` + `monero-oxide/ringct/bulletproofs/generators/` | Two-way split |
| `monero-oxide/` (umbrella, FCMP++) | `monero-oxide/ringct/fcmp++` | Moved into `ringct/` subdirectory |
| Various `primitives/src/` files | `monero-oxide/ed25519/` | `unreduced_scalar`, etc. |
| (new) | `monero-oxide/ringct/{borromean, clsag, mlsag}` | Pre-FCMP++ ringct paths split out |
| (new) | `monero-oxide/wallet/`, `monero-oxide/wallet/{address, base58}` | Wallet code split into its own subtree (Monero-shaped — Shekyl uses `shekyl-wallet-*` instead) |

The `wallet/` and `ringct/{borromean, clsag, mlsag}/` upstream additions
are **Monero-only** (per `60-no-monero-legacy.mdc`, Shekyl ships only
`RCTTypeFcmpPlusPlusPqc` from genesis and uses Shekyl-native wallet
crates). Re-vendoring should not pull them in.

The `ringct/{bulletproofs, fcmp++}/` reorg is structural — same code,
new path. Re-vendoring should adopt it iff the un-pin plan decides the
fork follows upstream layout going forward; if not, the fork's `fcmp/`
layout stays and upstream paths are translated at vendor time.

## Findings summary

1. **Vendored is fresh against the fork.** Five commits behind, all
   non-crypto except the `182b648` base58 hardening. A vendor-bump
   from `87acb57` → `3933664` is mechanical and was **not blocked by
   anything in this audit**. **Executed by PR 0.6** on the same
   calendar day — turned out to be strictly metadata-only because the
   sole content delta lives in `shekyl-oxide/wallet/base58/`, which is
   not vendored in shekyl-core. See "PR 0.6 vendor-bump execution"
   above.

2. **The fork is 40 commits behind upstream**, including:
   - One security-relevant audit response (`cba7117` cypherstack-fix —
     itself still in-progress upstream).
   - One correctness bug fix (`00bafcf` HelioseleneField::invert) and
     three companion commits responding to Veridise's formal
     verification.
   - One missing type-system bound (`0d6f5e8` ConditionallySelectable).
   - One correctness fix (`1ac294e` WCG library invariant).
   - Several substantive performance changes (`a5cc436`, `7568518`,
     `8ff1f90`).
   - One major upstream restructure that the fork has not adopted.

3. **The fork holds two crypto-substantive Shekyl-only commits**:
   `416d8d1` (rename) and `87acb57` (extra leaf scalars for Shekyl
   curves). The remaining six fork-only commits are policy/CI/docs.

4. **Path divergence is non-trivial**. Upstream's post-reorg layout and
   Shekyl's `shekyl-oxide/`-rename layout will collide at re-vendor
   time. Resolving the path question is part of the un-pin plan's
   scope, not this audit's.

## Recommendations (input to the un-pin plan, not actions for this PR)

The un-pin plan, when it lands, should:

1. **Prioritize cypherstack and Veridise responses.** `cba7117`,
   `00bafcf`, `af44fb4`, `f58f2a9` are correctness/security work and
   should be evaluated first. Note that `cba7117` is itself in-progress
   upstream — the un-pin plan should not treat picking it up as
   "closing the cypherstack audit," only as "tracking upstream's
   in-progress response."

2. **Decide the fork-vs-upstream layout question early.** The fork
   currently lives at `shekyl-oxide/`; upstream lives at
   `monero-oxide/{ringct, interface, ed25519, wallet}/`. The un-pin
   plan should pick one of:
   - Shekyl follows upstream's reorg, accepting the path-rename churn.
   - Shekyl freezes its current layout, mapping upstream paths at
     vendor time.
   - Shekyl divests the umbrella umbrella entirely, depending on the
     specific Monero-shaped crates ad-hoc per workspace member.

   Each has different implications for ongoing cherry-pick cost.

3. **Tag the Shekyl-original divergence**. `87acb57` ("extra leaf
   scalars") is the only algorithmic Shekyl-specific patch. The un-pin
   plan should ensure it's preserved on whatever future fork branch
   exists, ideally with a Shekyl-specific identifier in the commit
   message so it survives rebases against upstream.

4. **Drop Monero-only upstream additions**. The post-reorg
   `wallet/`, `ringct/{borromean, clsag, mlsag}/`, and `with_payment_id`
   commits should not enter Shekyl. They are Monero-legacy per
   `60-no-monero-legacy.mdc`.

## How this audit was reproduced

```bash
# In the monero-oxide working tree (~/shekyl/monero-oxide):
git remote -v   # confirms origin = Shekyl-Foundation, upstream = monero-oxide
git fetch --all

# Reference commits:
git log -1 origin/fcmp++ --format='%H %s %ai'
git log -1 upstream/fcmp++ --format='%H %s %ai'
git log -1 87acb57e0c3935c8834c8a270bd3bdcbbe36bcde --format='%H %s %ai'
git merge-base origin/fcmp++ upstream/fcmp++

# Per-crate path freshness:
for p in crypto/{helioselene,divisors,generalized-bulletproofs,fcmps,fcmps/circuit-abstraction,fcmps/ec-gadgets} \
         shekyl-oxide/{io,generators,primitives,fcmp/bulletproofs,fcmp/fcmp++,rpc,rpc/simple-request} \
         shekyl-oxide; do
  git log -1 origin/fcmp++ -- "$p" --format="$p :: %h %s"
done

# Fork-only commits (since merge base):
git log --oneline upstream/fcmp++..origin/fcmp++

# Upstream-only commits (since merge base):
git log --oneline origin/fcmp++..upstream/fcmp++
```

## Audit lifecycle

- **Snapshot**: this audit is a point-in-time record (2026-04-25).
- **Refresh trigger**: re-run before scheduling the un-pin plan, and
  before any vendor-bump PR. The procedure is in "How this audit was
  reproduced" above.
- **Storage**: this file is append-only (the audit record persists for
  history); refresh runs land as a new dated section rather than an
  in-place edit. The first refresh should add a "## 2026-MM-DD audit
  refresh" section with the updated table; the original 2026-04-25
  section stays so the rewrite plan's Phase 0 record stays
  intelligible after the un-pin lands.
