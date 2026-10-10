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
`RELEASE_CHECKLIST.md` (feature-readiness gates), `GENESIS_TRANSPARENCY.md`
(frozen launch tuple; ops narrative in shekyl-dev),
`TESTNET_REHEARSAL_CHECKLIST.md` (network go/no-go),
`UPGRADE_POLICY.md` (feature-driven cadence).

---

## 1. Invariants

- `dev` is trunk and is **always releasable** (green CI, no half-landed
  consensus changes). Review happens at the `feature → dev` boundary.
- `main` advances **only** by promoting a tagged release. No feature work, no
  independent commits land on `main`.
- Each release is cut from a **frozen `dev` SHA**. Through `beta.N` the
  promotion is a pull request from `dev` to `main` (§4): a pre-release is
  superseded by the next incompatibility on `dev`, so the next pre-release is
  cheaper than a backport to this one. A `release-vX.Y` branch, with only
  critical fixes backported to it, starts at `rc.1`, when backports become
  plausible.
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
   `git rev-parse origin/dev`. Everything below references this SHA. The
   promotion pull request's head is the `dev` branch, so a merge into `dev`
   after this point moves the candidate; the changelog cut (`RELEASING.md`
   step 1) is the last merge, and its merge commit is the frozen SHA.
2. **Pre-flight at the frozen SHA:**
   - [ ] CI green on the SHA (fmt + clippy `-D warnings` + full test suite).
   - [ ] `Cargo.lock` and vendored-dep state are exactly the green-on-`dev`
         state (reproducible-build inputs must match what was reviewed).
   - [ ] **Frozen-tuple diff-check** (highest severity — see §6).
   - [ ] **Gitian dry-run gate** — dispatch the gitian workflow against the
         frozen SHA and confirm **all four platforms** (Linux/Windows/FreeBSD/macOS)
         build green *before* the cut/promote/tag:
         `gh workflow run gitian.yml --ref <dev-or-release-branch> -f tag=<frozen-SHA>`.
         The `tag` value **must be a commit SHA** (or a slash-free tag): gitian-builder's
         `gbuild sanitize` rejects any ref containing `/`, so passing a branch
         name like `fix/…` aborts every platform at ref-parse with `unsanitary
         string` before the build even starts. A frozen SHA is hex, so it passes.
         Gitian builds the checked-out ref, not a tag object, so this runs with
         **no tag pushed** — it catches release-only build breakage that the
         normal PR CI never exercises (the depends cross-build and the container's
         rustup/toolchain setup) *before* a signed tag exists, instead of after.
         This gate is why `v3.1.0-alpha.6`'s post-tag gitian failure (a rustup
         toolchain race in the descriptors) forced a bump to `alpha.7`; running it
         here would have caught it pre-tag. Only proceed once green.
         Dispatch it with `package_dry_run` checked. The four platform builds
         then feed the package job, which builds the `.deb`, the `.rpm`, the
         Windows installer, the source archive and `SHA256SUMS`, checks the
         Tor bundle inside each unpacked package, and stops before
         publishing. Without that input the package job is skipped on a
         dispatch, and packaging is first exercised by the real tag.
3. **Open the promotion pull request** from `dev` to `main`, titled
   `Release: vX.Y.Z`. The build and test workflows run on pull requests and on
   pushes to `main`, not on pushes to `dev`, so this pull request is the first
   full run on the frozen SHA. (From `rc.1`: cut `release-vX.Y` from the frozen
   SHA and promote that branch instead.)
4. **Stabilize.** Run the `RELEASE_CHECKLIST.md` gates applicable to a testnet
   rehearsal (PQC spec frozen, reproducible-build inputs documented, testnet
   fork + verification, etc.). A fix lands on `dev` through its own pull
   request, and its merge is the new frozen SHA: repeat step 2 on it.
5. **Promote to `main`** by merging that pull request with a **merge commit**,
   so `main`'s history shows discrete release points. Never squash, rebase or
   fast-forward: the merge commit is the branch-topology release marker. Its
   tree must equal the frozen SHA's tree.
6. **Sign the tag** on that merge commit with the Foundation signing subkey
   (`6914D74823DDA8DC`), by the ceremony in `SIGNING.md`
   §"Release-tag signing ceremony". The merge happened on the remote, so the
   ceremony fetches first and names the commit it tags; a local `main` or a
   stale `origin/main` is the previous release's commit. `git verify-tag`
   before anything is pushed.
7. **Push the tag** to `origin` (`main` is already there: the merge happened on
   the remote). Before pushing, confirm the tag's commit is an ancestor of
   `origin/main`: `git merge-base --is-ancestor vX.Y.Z origin/main`.
8. **Reproducible build.** Tag push triggers CI/Gitian/Guix; confirm the hashes
   match a second independent build (see §5).
9. **Sign artifacts** (`SHA256SUMS`, `hashes.txt.sig`): the manifest ceremony
   in `SIGNING.md`, run by the release owner once the release job has
   published.
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
(`GENESIS_TRANSPARENCY.md`). Diff every element between the previous released tag and
the candidate SHA:

- [ ] `config::testnet::GENESIS_TX`
- [ ] `config::testnet::GENESIS_NONCE`
- [ ] handshake id: `shekyl_network_id(TESTNET)`, derived from the genesis block hash (`cSHAKE256`, domain `shekyl/p2p-network-id-v1`). The header does not carry the bytes. Diff the genesis tx and nonce above, and confirm the recorded testnet KAT.
- [ ] generated economics constants from `config/economics_params.json`

If **any** changed → re-run the rehearsal from clean datadirs per
`TESTNET_REHEARSAL_CHECKLIST.md` before this candidate can become a release.

**The other direction is a gate, and it is scripted:**

```bash
python3 scripts/release/check_frozen_tuple.py <previous-tag> <frozen-SHA>
```

It fails when the consensus surface moved since the previous tag and the
testnet genesis hash did not. Two builds with one genesis share a network id:
they find each other, connect, reject each other's blocks and ban each other.
That is what a cut from `dev` after `v3.1.0-alpha.9` would have shipped: the
rule that reserved the header's minor version made every block the alpha.9
fleet had mined invalid, and the genesis, and so the id, was unchanged.

The remedy is one integer. Move `config::testnet::GENESIS_NONCE` and re-record
what follows from it, in one change:

- [ ] the nonce in `src/cryptonote_config.h`;
- [ ] the block id, from `cargo run -p shekyl-genesis-tool -- block-id --network testnet`,
      in `rust/shekyl-rpc-types/src/identity.rs` (`TESTNET_GENESIS`),
      `rust/shekyl-chain-rules/src/anchors.rs` (`ReleaseAnchors::TESTNET`, a
      byte array, so a search for the hex string does not find it),
      `tests/unit_tests/mining_parity.cpp` and `docs/GENESIS_ALLOCATIONS.md`;
- [ ] the id and prefix in `rust/shekyl-ffi/src/network_id_ffi.rs`'s KAT, which
      fails and prints the new bytes until they are recorded, and the same
      two values in the table in `docs/design/SHEKYL_P2P_PROTOCOL.md`.

Each of these is held by a test, so a pin left behind fails: run
`cargo test --workspace --no-fail-fast` to see all of them at once, since a
plain run stops at the first crate that fails.

The genesis transaction, the recipients files and the other networks do not
change. "The consensus surface moved" is read from the reviewed constants
digest and from the captured replay chains; either moving is enough, and the
script's header says why both are read.

A rotated id partitions the old fleet from the new at the handshake. It does
not remove the reason to stop the whole fleet before starting any of it on
the new build: an old node that keeps dialing a new one is scored and banned
for a day, as the `v3.1.0-alpha.9` changelog records.

Also pin the deterministic artifacts per `GENESIS_TRANSPARENCY.md`: block 0 hash,
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
| Block version | `CURRENT_BLOCK_MAJOR_VERSION` 1 and `CURRENT_BLOCK_MINOR_VERSION` 0 | the same constants. There is no per-network fork number |
| Snapshot allocation | none | per `GENESIS_TRANSPARENCY.md` decision |

Block version is the constant 1.0 on every network. The hard-fork table is
deleted, so there is no fork number, vote, or activation height to freeze.
A later consensus change is a design document before any code
(`design/CXX_VERSION_GATES.md` §5, `UPGRADE_POLICY.md`).

---

## 8. Failure / rollback

If a rehearsal release is bad, move the tag per the `RELEASING.md` procedure
(`git tag -d`, delete on `origin`, fetch, recreate on the corrected merge
commit, push the tag). If a frozen-tuple element was wrong, the network must be
re-rehearsed from clean datadirs — a moved tag does not unfork a started network.

Post-mortem any guardrail that failed to hold, within the rehearsal record, so
the mainnet process inherits the fix rather than rediscovering the gap.
