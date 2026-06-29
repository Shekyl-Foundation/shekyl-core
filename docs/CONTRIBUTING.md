# Contributing to Shekyl

Shekyl is a privacy-maximalist, consensus-critical cryptocurrency. Contributions
are welcome, but the bar is high and deliberate. Testing and bug reports are
genuinely valuable — see
[How to Report Bugs Effectively](https://www.chiark.greenend.org.uk/~sgtatham/bugs.html).

## Priorities

The project's standing priority order is **privacy > security > correctness >
performance > features**, and its posture is **get it right, not get it now**.
A patch that trades a higher priority for a lower one will be rejected no matter
how much it improves the lower one. We build systems that make sense, not patches
that paper over a problem.

## Branching model

- **`dev` is the integration trunk.** It must always build and stay releasable
  (green CI). All day-to-day development targets `dev`.
- **`main` is for releases only.** It advances solely through the gated, signed
  promotion in [`RELEASE_PROMOTION.md`](RELEASE_PROMOTION.md). No feature work
  and no direct commits land on `main`.
- **All changes reach `dev` through feature branches and pull requests** — never
  direct pushes. (This replaces the project's former single-branch model.)

There is **one remote**: `origin` → `github.com/Shekyl-Foundation/shekyl-core`,
default branch `main`. Maintainers push feature branches to `origin`; outside
contributors fork and open PRs from their fork.

Branch naming is scoped to one logical change: `feat/...`, `fix/...`,
`chore/...`, `docs/...`.

## Submitting a change

- **One PR = one logical change.** "While we're here" is the enemy: no unrelated
  refactors, whitespace churn, reindentation, or drive-by renames bundled in.
  Use `git add -p` to keep commits clean.
- **Rebase on current `dev`** before opening or updating a PR. No merge commits,
  no stray commits from others in your branch. You may be asked to rebase even
  for trivially resolvable conflicts.
- **Squash fix-ups.** A buggy patch plus its later fix should be one clean commit.
- **Commit messages:** a subject line under ~50 characters summarizing the
  change, an optional blank line, then a body with rationale and details. If you
  change documented behavior, update the Doxygen header / docs in the same patch.
- **Tests:** new functionality needs real-path tests (no mocks). Cryptographic
  and consensus-frozen boundaries require known-answer-test (KAT) pins.

## What it takes to merge to `dev`

Branch protection enforces all of the following. None are bypassable by direct
push:

1. **An open pull request** — no direct pushes to `dev`.
2. **Maintainer approval on the PR.** With a single maintainer this is still an
   explicit approval step (never a direct push); as the maintainer set grows,
   approval for consensus- or cryptography-touching changes MUST come from
   someone other than the patch author.
3. **Green CI:** `fmt`, `clippy -D warnings`, and the full test suite across the
   required platform matrix.
4. **Signed commits that verify** (see *Commit signing*).
5. **Rebased on `dev`** with conflicts resolved.

## What it takes to reach `main`

Nothing reaches `main` except through
[`RELEASE_PROMOTION.md`](RELEASE_PROMOTION.md): a frozen `dev` SHA, a release
branch, the frozen-tuple gate, a signed promotion merge, and a signed tag. The
`main` release signing key is never used for routine development and is never
reachable by automated tooling.

## Code review standards

Review is **adversarial and source-anchored**. Reviewers:

- Verify claims against actual source at `file:line`, not against design docs
  (which may be stale) or memory.
- Apply extra scrutiny to anything touching consensus, cryptography, wire
  formats, or funds-bearing state. Prefer making bad states unrepresentable in
  the type system over guarding against them at runtime.
- Enforce **single source of truth**: no reimplementation of canonical
  arithmetic, no parallel definitions of consensus constants.
- Treat any change to the frozen genesis tuple (see `GENESIS_STRATEGY.md`) as
  requiring a re-run of the testnet rehearsal — it is not a routine merge.
- Require **named reopen criteria for every deferral**. Absence of a claim is
  not a claim of absence.

## Automated and agent-generated contributions

Patches produced by autonomous tooling are welcome but receive **no special
trust**. They pass through the identical PR → review → approval → signed-CI gate
as human patches, and a human maintainer is accountable for every merge.

Automated tooling MUST NOT hold the `main` release signing key, nor any
credential that can push directly to `dev` or `main`. Agent-authored PRs SHOULD
be labeled as such so reviewers calibrate scrutiny accordingly.

## Security and responsible disclosure

Do **not** open public issues for security vulnerabilities. Report privately to
the Foundation disclosure contact: **Rick Dawson, dawsora@gmail.com** (canonical
contact; mirror in `SECURITY.md` where present). Given the privacy-first threat
model, err toward private disclosure for anything affecting unlinkability, key
handling, or fund safety.

## Commit signing

Signed commits are **required**, not merely encouraged. Branch protection on
`dev` and `main` requires signature verification. The release/promotion signing
key for `main` is distinct from routine commit-signing keys, is hardware-backed,
and is operated only by a human; its fingerprint is published in-repo and on
`shekyl.org` so anyone can verify releases.

## Conduct

Be respectful and constructive. Maintainers may, after public discussion,
remove contributors who repeatedly disrupt the project or ignore its process.

## License

Shekyl is free software under the GNU General Public License v3, or (at your
option) any later version, distributed in the hope that it will be useful but
WITHOUT ANY WARRANTY. All contributions are made under this license. There is no
copyright-assignment process; contributors retain copyright in their own
patches, owned collectively by the project's contributors.

Copyright (c) 2024+, The Shekyl Project.

## Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in RFC 2119.
