# Shekyl Core — Claude Code Context

**Repo:** https://github.com/Shekyl-Foundation/shekyl-core
**Org:** https://github.com/Shekyl-Foundation
**Copyright:** © 2025–2026, The Shekyl Foundation (some inherited files
additionally carry Monero/CryptoNote
copyright — see [`92-copyright-header`](.cursor/rules/92-copyright-header.mdc))

Shekyl is privacy-preserving, quantum-resistant money designed to last:
hybrid post-quantum cryptography from genesis, FCMP++ membership-proof
privacy, and a PoW chain with staking as an economic primitive. Everything
Shekyl ships is Rust under `rust/`: the node daemon `shekyld` and the wallet
stack (`shekyl-cli`, `shekyl-wallet-rpc`, `shekyl-engine-core` and
siblings). The tree holds no first-party C or C++; the only C/C++ is
vendored under `external/` (the RandomX references). How the workspace is
laid out, and the gate that holds that end state, is
[`125-rust-architecture`](.cursor/rules/125-rust-architecture.mdc).

---

## ⚠️ The rules live in `.cursor/rules/`, and they are canonical

**`.cursor/rules/*.mdc` is the single source of truth for how we develop.**
This file is orientation only — a map to the rules and the codebase. It does
**not** restate the rules, because a second copy drifts and then lies. When
this file and a rule disagree, **the rule wins**; when two rules disagree,
[`00-mission`](.cursor/rules/00-mission.mdc) wins.

Before non-trivial work, read the rules relevant to what you're touching.
[`00-mission`](.cursor/rules/00-mission.mdc) and
[`06-branching`](.cursor/rules/06-branching.mdc) apply to *everything*.

### Mission priority hierarchy (from `00-mission`, the tie-breaker for conflicts)

1. **Security & quantum resilience are preconditions** — hybrid PQC ships from
   genesis; nothing trades it away.
2. **Privacy is the product** — same guarantees for everyone, never a setting.
3. **The system must outlast the team** — written for an unknown future
   maintainer, evaluated against now / end-of-mining-era / the V4
   lattice-only transition.

When you invoke the hierarchy, name which commitment is binding and why.

---

## Rule index

Two series. **Estate rules (00–99)** are canonical here and copied verbatim
into `shekyl-gui-wallet` and `shekyl-prism`; each carries `scope: estate` and
the `repos:` it governs. **shekyl-core's own rules (101–199)** carry
`scope: core`; an estate rule's core-only part is its companion `1NN`
(06 → 106). The GUI's series is 201–299 and prism's 901–999. A vacated
number is never reused or cited
([`vacated-numbers.tsv`](.cursor/rules/vacated-numbers.tsv)); the estate
files' hashes are in [`ESTATE_MANIFEST`](.cursor/rules/ESTATE_MANIFEST), which
the GUI and prism check their copies against.

Foundations & process

- [`00-mission`](.cursor/rules/00-mission.mdc) — mission + priority hierarchy (always applies)
- [`05-system-thinking`](.cursor/rules/05-system-thinking.mdc) — system-level design discipline
- [`06-branching`](.cursor/rules/06-branching.mdc) — branch policy (always applies): `main`=stable, `dev`=integration; short-lived branches off `dev`; each push is separately authorized
  - core part: [`106-branching-core`](.cursor/rules/106-branching-core.mdc) — the consensus-cutover exception and how CI tests merges into `dev`
- [`107-consensus-atomic-cutovers`](.cursor/rules/107-consensus-atomic-cutovers.mdc) — named, opt-in exception to `06` for consensus-boundary PRs
- [`08-worktree-hygiene`](.cursor/rules/08-worktree-hygiene.mdc) — the tested tree is the shipped tree (always applies): stage explicit paths, never `-A`/`-a`; verify from a fresh checkout of the pushed SHA; read back anything published (a PR body, a comment) rather than trusting the send's exit status
- [`37-internal-information-boundary`](.cursor/rules/37-internal-information-boundary.mdc) — `shekyl-core`, `shekyl-gui-wallet` and `shekyl-prism` are public (always applies): write the role, never the host; host identities, operational state and local paths live in `shekyl-dev`
  - core part: [`137-internal-information-boundary-core`](.cursor/rules/137-internal-information-boundary-core.mdc) — the gate for host identities and local paths
- [`38-shared-estate-coordination`](.cursor/rules/38-shared-estate-coordination.mdc) — Foundation hosts are shared (always applies): read and claim in `shekyl-dev`'s `infrastructure/USAGE.md` before using one; a long-running test is a `quiet` claim nobody else disturbs
- [`90-commits`](.cursor/rules/90-commits.mdc) — commit message & PR discipline
- [`91-documentation-after-plans`](.cursor/rules/91-documentation-after-plans.mdc) — docs update is the final task of a plan
- [`194-tracking-index`](.cursor/rules/194-tracking-index.mdc) — `docs/design/IMPLEMENTATION_INDEX.md` is load-bearing; identifier families register at birth; Phase 3+ / Stage 3+ items start with an index row
- [`95-documentation-lifecycle`](.cursor/rules/95-documentation-lifecycle.mdc) — document classes, status banners, archive-or-contract, FOLLOWUPS one-liners, CHANGELOG scope, three work-item targets
  - core part: [`195-documentation-lifecycle-core`](.cursor/rules/195-documentation-lifecycle-core.mdc) — front door, archive checklist, the FOLLOWUPS `Owner:` gate, `changelog.d`, document gates
- [`126-sub-pr-design-discipline`](.cursor/rules/126-sub-pr-design-discipline.mdc) — a new crate or consensus-boundary change is its own change (always); opt-in design-round process for multi-round/consensus/reference-port sub-PRs

Architecture & scope

- [`110-shekyl-first`](.cursor/rules/110-shekyl-first.mdc) — shekyl-core is primary; the `shekyl-oxide` fork is a disposable downstream consumer
- [`15-deletion-and-debt`](.cursor/rules/15-deletion-and-debt.mdc) — when to delete vs. defer; migration-code lifecycle
- [`16-architectural-inheritance`](.cursor/rules/16-architectural-inheritance.mdc) — inherited code is not inherited architecture; migrate flows that contradict the threat model
- [`119-validation-surface-discipline`](.cursor/rules/119-validation-surface-discipline.mdc) — bundle work by validation surface, not feature topic
- [`21-reversion-clause-discipline`](.cursor/rules/21-reversion-clause-discipline.mdc) — reject-now-with-reopening-criteria over pre-provisioned flexibility
- [`22-no-lazy-deferral`](.cursor/rules/22-no-lazy-deferral.mdc) — scoped work lands where scoped (always applies); deferral needs a named blocker, disclosed in the deferring commit
  - core part: [`122-no-lazy-deferral-core`](.cursor/rules/122-no-lazy-deferral-core.mdc) — a FOLLOWUPS `Owner:` may be an identifier family; the cell is gated
- [`23-disposition-visibility`](.cursor/rules/23-disposition-visibility.mdc) — REJECTED / DEFERRED / STAGED / RESERVED each has a defined grep surface; zero code symbols unless staged; refused names stay in namespace contracts as structured statuses
- [`60-no-monero-legacy`](.cursor/rules/60-no-monero-legacy.mdc) — v3-from-genesis, no Monero chain history; remove dead pre-genesis code
- [`170-modular-consensus`](.cursor/rules/170-modular-consensus.mdc) — PoW consensus; staking is economic; no speculative consensus scaffolding
- [`171-network-uniformity`](.cursor/rules/171-network-uniformity.mdc) — nettype selects data, never control flow, on the consensus surface; a behavioral divergence must be named, ratified, and loud
- [`175-system-autonomy`](.cursor/rules/175-system-autonomy.mdc) — self-regulating design; minimize coordinated upgrades
- [`176-device-provisioning-floor`](.cursor/rules/176-device-provisioning-floor.mdc) — stated minimum supported device (Pi 4); constants derived from work time are provisioned at the floor, never at the machine that was handy

Rust

- [`125-rust-architecture`](.cursor/rules/125-rust-architecture.mdc) — workspace layout, no first-party C and no C ABI, dependency rules, decoding untrusted bytes
- [`17-dependency-discipline`](.cursor/rules/17-dependency-discipline.mdc) — verify deps at source before adding
- [`118-type-placement`](.cursor/rules/118-type-placement.mdc) — transform- vs state-shaped types; byte-layout discipline
- [`142-serialization-policy`](.cursor/rules/142-serialization-policy.mdc) — persisted-block wire change ⇒ version-constant bump (CI-enforced)
- [`45-rust-lint-checks`](.cursor/rules/45-rust-lint-checks.mdc) — `cargo fmt` + `cargo clippy --all-targets -- -D warnings` before any Rust commit
  - core part: [`145-rust-lint-checks-core`](.cursor/rules/145-rust-lint-checks-core.mdc) — the two crates allowed `unsafe_code` at their root
- [`46-shell-gate-exits`](.cursor/rules/46-shell-gate-exits.mdc) — gate verdicts never travel through a pipe; `PIPESTATUS`/unpiped exits; the pipefail SIGPIPE trap; `pgrep -f` matches the caller
- [`47-gate-subject-assertion`](.cursor/rules/47-gate-subject-assertion.mdc) — a gate must assert its own subject exists; absence of signal is first evidence the subject is absent
- [`43-absence-is-not-a-value`](.cursor/rules/43-absence-is-not-a-value.mdc) — zero is a value; "no result" is `None` / `null`, never an in-band sentinel
  - core part: [`143-absence-is-not-a-value-core`](.cursor/rules/143-absence-is-not-a-value-core.mdc) — the required-nullable reply wrapper and the sentinel record
- [`93-legacy-symbol-migration`](.cursor/rules/93-legacy-symbol-migration.mdc) — never introduce a `MONERO_*` identifier; frozen domain separators stay

Cryptography & secrets

- [`30-cryptography`](.cursor/rules/30-cryptography.mdc) — crypto implementation discipline (hybrid PQC, domain separators, pinned test vectors)
  - core part: [`130-cryptography-core`](.cursor/rules/130-cryptography-core.mdc) — per-output PQC keys, the vector path, the domain registry
- [`35-secure-memory`](.cursor/rules/35-secure-memory.mdc) — structural secret wiping (`Zeroizing` / `ZeroizeOnDrop`)
  - core part: [`135-secure-memory-core`](.cursor/rules/135-secure-memory-core.mdc) — process hardening and locked storage as core implements them
- [`36-secret-locality`](.cursor/rules/36-secret-locality.mdc) — secret bytes are clamped, reduced and combined only in the crypto-owning crates (gated)
  - core part: [`136-secret-locality-core`](.cursor/rules/136-secret-locality-core.mdc) — the crypto-crate list, the gate and its inventory
- [`65-address-format-discipline`](.cursor/rules/65-address-format-discipline.mdc) — address format rules
- [`92-copyright-header`](.cursor/rules/92-copyright-header.mdc) — Shekyl Foundation header; never add Monero copyright to a file that lacks one

Testing

- [`50-testing`](.cursor/rules/50-testing.mdc) — test-gate & diagnostic-output discipline
  - core part: [`150-testing-core`](.cursor/rules/150-testing-core.mdc) — where the chain witness lives; flaky-test retry, report and quarantine

UX (end-user-facing surfaces)

- [`80-usability`](.cursor/rules/80-usability.mdc) — usability-first design
- [`81-no-protocol-knowledge`](.cursor/rules/81-no-protocol-knowledge.mdc) — users never need to understand the protocol
- [`82-failure-mode-ux`](.cursor/rules/82-failure-mode-ux.mdc) — failure modes are first-class design scope
- [`83-input-grammar`](.cursor/rules/83-input-grammar.mdc) — the input grammar (always applies): one tree glossary, names as paths, no negation, no aliases, syntax kinds, one table per binary, typed diagnostics, no environment input

---

## Lineage (so the framing is right)

Shekyl is **v3-from-genesis with no Monero chain history**. Some files are
inherited from the Monero/CryptoNote lineage and keep their original
copyright, but **Monero is not an upstream to track** — the codebases are
siblings, and inherited data flows that contradict Shekyl's threat model are
*migrated, not rationalized* ([`16`](.cursor/rules/16-architectural-inheritance.mdc),
[`60`](.cursor/rules/60-no-monero-legacy.mdc)). The vendored
`rust/shekyl-oxide/` is a **disposable downstream consumer**, used for its
crypto primitives; the rest of that tree's application/protocol code is ours
([`110`](.cursor/rules/110-shekyl-first.mdc)).

---

## Repository orientation

```text
shekyl-core/
├── rust/       # Rust workspace: daemon, wallet stack, crypto/consensus crates
├── config/     # Economics/consensus parameters (build-script source of truth)
├── docs/       # Design docs, decision log, FOLLOWUPS, test vectors
├── external/   # Vendored third-party C/C++ (the RandomX v2 reference)
├── tests/      # the depends refusal test and the stressnet harness (Rust tests live in rust/)
└── CLAUDE.md   # this file
```

Key Rust crates: `shekyl-engine-*` (wallet orchestrator/state/file), `shekyl-scanner`,
`shekyl-tx-builder`, `shekyl-crypto-pq`, `shekyl-proofs`, `shekyl-fcmp`,
`shekyl-curve-tree`, `shekyl-consensus`, `shekyl-economics`, `shekyl-staking`,
`shekyl-chain-store` / `shekyl-chain-rules` (daemon store and the consensus
validator that alone mints what it connects — the two share no code), and
`shekyl-units` / `shekyl-types` (foundational newtypes). See
[`125-rust-architecture`](.cursor/rules/125-rust-architecture.mdc).

Documentation starts at [`docs/README.md`](docs/README.md). Binding
history: [`docs/V3_WALLET_DECISION_LOG.md`](docs/V3_WALLET_DECISION_LOG.md).
Identifier map: [`docs/design/IMPLEMENTATION_INDEX.md`](docs/design/IMPLEMENTATION_INDEX.md).
Open residue: [`docs/FOLLOWUPS.md`](docs/FOLLOWUPS.md).

---

## Build & test (practical orientation, not policy)

**Checkout hygiene.** Clone with `git clone --recursive`. After a
non-recursive clone or a new worktree, run
`git submodule update --init --recursive` — never `--exclude`
`shekyl-randomx-differential` / `external/randomx-v2`. Worktrees inherit
gitlinks, not submodule working trees. The release build does not
need `external/randomx-v2`; the C library is opt-in:

```bash
scripts/build_randomx_v2_ref.sh "$PWD/build/randomx-v2" "$PWD/build/randomx-v2-install"
export RANDOMX_V2_INSTALL_DIR="$PWD/build/randomx-v2-install"
```

That script builds the C library
for the differential harness and the out-of-process miner reference only;
it never links into `shekyld`, whose PoW is the Rust verifier
(`RANDOMX_V2_RUST.md` §2; gate: `scripts/ci/check_randomx_symbol_isolation.sh`).
The workspace `cargo test` lane **unconditionally** excludes
`shekyl-randomx-differential` (`.github/workflows/rust-audit-test.yml`);
setting `RANDOMX_V2_INSTALL_DIR` does not re-include it. The dedicated
`randomx-v2-differential` workflow is the gate for T13/T14/T15.

The release binaries through `cargo xtask` (it runs cargo from
`rust/xtask/matrix.toml` and stages `shekyld`, `shekyl-cli`,
`shekyl-wallet-rpc` and `shekyl-rpc-tunnel` in `build/bin/`; a release
host's cross build is `cargo xtask dist --host <host>`):

```bash
cd rust && cargo xtask build
```

Rust (workspace under `rust/`; gates per [`45`](.cursor/rules/45-rust-lint-checks.mdc), tests per [`50`](.cursor/rules/50-testing.mdc)):

```bash
cd rust
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace --exclude shekyl-randomx-differential
```

CI mirrors these plus `cargo audit` on `Cargo.lock` changes and the
persisted-schema snapshot check ([`142`](.cursor/rules/142-serialization-policy.mdc)). Run them locally before
claiming a change is done — "fix CI later" is not the workflow.
