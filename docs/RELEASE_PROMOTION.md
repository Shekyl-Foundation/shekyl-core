# Release Promotion & Rehearsal Runbook

This runbook governs how a frozen point on `dev` is promoted to `main` as a
tagged release. **It is dual-purpose:** pre-genesis, every release is a
*rehearsal* whose job is to validate the chain **and** the release machinery
itself. The steps below are written so this testnet runbook becomes the mainnet
runbook by substitution (see §7), and so each guardrail is *actively attacked*
during rehearsal to confirm it holds (see §5).

Governing posture: get it right, not get it now. A release is a deliberate,
gated act — never a merge to keep diffs small.

Companion docs: `RELEASING.md` (tag → CI → artifact mechanics),
`RELEASE_CHECKLIST.md` (feature-readiness gates), `GENESIS_STRATEGY.md` (frozen
launch tuple), `TESTNET_REHEARSAL_CHECKLIST.md` (network go/no-go),
`UPGRADE_POLICY.md` (feature-driven cadence).

---

## 1. Invariants

- `dev` is trunk and is **always releasable** (green CI, no half-landed
  consensus changes). Review happens at the `feature → dev` boundary.
- `main` advances **only** by promoting a tagged release. No feature work, no
  independent commits land on `main`.
- Each release is cut on a `release-vX.Y` branch off a **frozen `dev` SHA**.
  After the cut, only critical fixes are backported to the release branch.
- The `dev → main` diff size is irrelevant: every commit in it was reviewed when
  it landed on `dev`. Promotion is a release event, not a re-review.
- Cadence is **feature-driven**, mapped to testnet milestones, not a calendar
  (mirrors `UPGRADE_POLICY.md`). Do not promote "periodically to stay small."

---

## 2. One-time setup (before the first rehearsal)

- [ ] **Remote layout is settled** — one remote, `origin` →
      `Shekyl-Foundation/shekyl-core`, default branch `main` (`origin/HEAD`
      tracks `main`). The old personal `origin/ng` is retired. `RELEASING.md` is
      stale on this point: it still pushes to a `foundation` remote and a dead
      `ng` branch. Correct it to the single-remote flow in §4.
- [ ] **Reconcile `main` vs `dev` before the first promotion.** They have
      diverged (`main` at `34b2b3c`, `dev` at `62a6cdd`). `git log origin/main
      ^origin/dev` MUST be empty — confirm `main` holds nothing that isn't also
      on `dev`, or reconcile first, so the first signed merge doesn't strand or
      conflict with unique `main` commits.
- [ ] **Signing key handling.** The dedicated `main` key signs (a) the promotion
      commit/merge to `main` and (b) the release tag. It is **hardware-backed
      and unreachable by any coding agent**. Signing is a deliberate human step,
      never automated into the agent loop.
- [ ] **Publish the key fingerprint** in-repo (`KEYS` / `RELEASING.md`) and on
      `shekyl.org`, alongside `hashes.txt.sig`. The release key is part of the
      user-facing trust root.
- [ ] **Branch protection on `main`:** require signed commits, require the tag
      signature to verify, restrict who/what can push. An unsigned promotion
      must be *mechanically* rejected, not caught by review.
- [ ] **Fix `RELEASING.md` tag step** from `git tag -a` to `git tag -s` so the
      documented path actually uses the key.
- [ ] **Resolve `CONTRIBUTING.md`** — it still mandates the inherited C4
      single-`master`, no-topic-branch model, which contradicts this runbook.
      Replace it or it will mislead contributors.

---

## 3. Versioning of rehearsal releases

Pre-genesis releases use **pre-release suffixes** so they cannot be mistaken for
the genesis release (`RELEASING.md` already auto-marks `RC`/`alpha`/`beta` as
pre-releases). Recommended: `v3.0.0-RC1`, `-RC2`, … for rehearsals. **The first
non-pre-release tag is reserved for the genesis mainnet release.** This uses the
existing machinery and keeps the trust boundary legible to anyone verifying.

Three version axes stay distinct and live in one authority doc:
- **Software semver** (`v3.x`) — MAJOR bumps only on consensus-incompatible
  releases.
- **Transaction format** (`TransactionV3`) — unrelated to software semver.
- **Hard-fork / consensus version** — must be reconciled to a single genesis
  number *before* the genesis freeze (see §7). Not yet load-bearing on testnet.

---

## 4. Promotion sequence

Single remote: `origin` → `Shekyl-Foundation/shekyl-core`, default branch
`main`. The tag must point at a commit already on `main`, so **promote first,
then tag** (avoids the "tag not on the default branch" trap that
`RELEASING.md` warns about).

1. **Quiesce `dev`.** Halt agent landings. Record the frozen SHA:
   `git rev-parse origin/dev`. Everything below references this SHA.
2. **Pre-flight at the frozen SHA:**
   - [ ] CI green on the SHA (fmt + clippy `-D warnings` + full test suite).
   - [ ] `Cargo.lock` and vendored-dep state are exactly the green-on-`dev`
         state (reproducible-build inputs must match what was reviewed).
   - [ ] **Frozen-tuple diff-check** (highest severity — see §6).
3. **Cut the release branch:** `git switch -c release-v3.0 <frozen-SHA>`.
4. **Stabilize on the release branch.** Run `RELEASE_CHECKLIST.md` gates
   applicable to a testnet rehearsal (PQC spec frozen, reproducible-build inputs
   documented, testnet fork + verification, etc.). Only critical fixes land here.
5. **Promote to `main`** via **signed merge** of `release-v3.0` into `main`, so
   `main`'s history shows discrete, signed release points. Do not fast-forward
   away the merge record.
6. **Sign the tag** on the `main` HEAD with the `main` key:
   `git tag -s v3.0.0-RC1 -m "Shekyl v3.0.0-RC1 (rehearsal)"`.
7. **Push `main`, then the tag,** to `origin`. Before pushing the tag, confirm
   its commit is an ancestor of `origin/main`:
   `git merge-base --is-ancestor v3.0.0-RC1 origin/main`.
8. **Reproducible build.** Tag push triggers CI/Gitian/Guix; confirm the hashes
   match a second independent build (see §5).
9. **Sign artifacts** (`SHA256SUMS`, `hashes.txt.sig`).
10. **Post-promotion verification:** tag resolves on `origin`; published artifact
    hashes match the signed sums; `main` HEAD is signed and verifies.

---

## 5. Adversarial guardrail tests (the point of rehearsing)

For each rehearsal, **actively attempt the violation and confirm it is blocked.**
A guardrail that has never been tested is a guardrail you don't have.

- [ ] **Unsigned tag** pushed to `main` → branch protection **rejects** it.
- [ ] **Tag off a non-ancestor commit** (not on `main`) → push **fails**.
- [ ] **Mutated frozen-tuple constant** on the release branch → the §6
      diff-check **catches** it and forces a re-rehearsal.
- [ ] **Agent attempts to invoke the signing key** → **impossible** (key is
      out of every agent-reachable environment).
- [ ] **Two independent reproducible builds** → hashes **match** byte-for-byte.
- [ ] **Commit landed mid-cut** (moving target) → the §4.1 quiescence gate
      **prevents** tagging a shifting SHA.

Record pass/fail for each in the deployment record. A failed guardrail test is a
release blocker, not a footnote.

---

## 6. Frozen-tuple gate (highest severity)

The moment a release tag is used to stand up a seed, this tuple is **frozen for
that network**; if any element later changes on `dev` and is promoted without
re-running the rehearsal, you silently fork your own network
(`GENESIS_STRATEGY.md`). Diff every element between the previous released tag and
the candidate SHA:

- [ ] `config::testnet::GENESIS_TX`
- [ ] `config::testnet::GENESIS_NONCE`
- [ ] `config::testnet::NETWORK_ID`
- [ ] testnet hardfork table (including the genesis HF height)
- [ ] generated economics constants from `config/economics_params.json`

If **any** changed → re-run the rehearsal from clean datadirs per
`TESTNET_REHEARSAL_CHECKLIST.md` before this candidate can become a release.

Also pin the deterministic artifacts per `GENESIS_STRATEGY.md`: block 0 hash,
block 0 blob, block 0 miner-tx hash, daemon version + git commit, startup tuple.
All three seeds must compare byte-for-byte.

---

## 7. testnet → mainnet substitution

When this runbook becomes the mainnet runbook, the following change. **Resolve
each before the genesis freeze — after it, these are immutable.**

| Item | testnet rehearsal | mainnet genesis |
|---|---|---|
| Tag | `v3.0.0-RCn` (pre-release) | first non-pre-release tag |
| Frozen tuple | `config::testnet::*` | `config::mainnet::*` |
| **Genesis HF number** | testnet artifact (`HF_VERSION_SHEKYL_NG = 17`) | **one canonical number, reconciled across code + `UPGRADE_POLICY.md` + HF table** |
| Lead time before activation | accelerated | ≥ 4 weeks (`UPGRADE_POLICY.md`); 72 h floor for emergency forks |
| Snapshot allocation | none | per `GENESIS_STRATEGY.md` decision |

**Pre-freeze blocker:** the genesis HF number must be made canonical in one
authority doc and every `hf_version >=` gate before mainnet. It is currently
ambiguous (`UPGRADE_POLICY.md` says HF1; code uses 17). This is the one item
with a hard, irreversible deadline.

---

## 8. Failure / rollback

If a rehearsal release is bad, move the tag per the `RELEASING.md` procedure
(`git tag -d`, delete on `origin`, recreate on the corrected commit, re-push
`main` then tag). If a frozen-tuple element was wrong, the network must be
re-rehearsed from clean datadirs — a moved tag does not unfork a started network.

Post-mortem any guardrail that failed to hold, within the rehearsal record, so
the mainnet process inherits the fix rather than rediscovering the gap.
