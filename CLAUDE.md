# Shekyl Core — Claude Code Context

**Repo:** https://github.com/Shekyl-Foundation/shekyl-core
**Org:** https://github.com/Shekyl-Foundation
**Copyright:** © 2025–2026, The Shekyl Foundation (some inherited C++ under
`src/` additionally carries Monero/CryptoNote copyright — see
[`92-copyright-header`](.cursor/rules/92-copyright-header.mdc))

Shekyl is privacy-preserving, quantum-resistant money designed to last:
hybrid post-quantum cryptography from genesis, FCMP++ membership-proof
privacy, and a PoW chain with staking as an economic primitive. The node
daemon and legacy wallet live in C++ under `src/`; the wallet stack is being
actively rewritten as a native Rust workspace under `rust/`, and the rest of
the codebase will follow. The long-term goal is an all-Rust stack, so editing
C++ is the exception, not the default: new code **and bug fixes** belong in
Rust (with proper types), advancing the FFI boundary rather than thickening the
C++ — patching C++ just re-creates debt the Rust rewrite must pay down again,
and the inherited C++ carries enough accumulated glitches and workarounds that
"fix it in place" is rarely the right call. This is the canonical policy in
[`20-rust-vs-cpp-policy`](.cursor/rules/20-rust-vs-cpp-policy.mdc) (when to
choose Rust) and [`40-ffi-discipline`](.cursor/rules/40-ffi-discipline.mdc) /
[`25-rust-architecture`](.cursor/rules/25-rust-architecture.mdc) (how to move
the boundary).

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

Foundations & process

- [`00-mission`](.cursor/rules/00-mission.mdc) — mission + priority hierarchy (always applies)
- [`05-system-thinking`](.cursor/rules/05-system-thinking.mdc) — system-level design discipline
- [`06-branching`](.cursor/rules/06-branching.mdc) — branch policy (always applies): `main`=stable, `dev`=integration; short-lived branches off `dev`; each push is separately authorized
- [`07-consensus-atomic-cutovers`](.cursor/rules/07-consensus-atomic-cutovers.mdc) — named, opt-in exception to `06` for consensus-boundary PRs
- [`90-commits`](.cursor/rules/90-commits.mdc) — commit message & PR discipline
- [`91-documentation-after-plans`](.cursor/rules/91-documentation-after-plans.mdc) — docs update is the final task of a plan
- [`94-tracking-index`](.cursor/rules/94-tracking-index.mdc) — `docs/design/IMPLEMENTATION_INDEX.md` is load-bearing; identifier families register at birth; Phase 3+ / Stage 3+ items start with an index row
- [`26-sub-pr-design-discipline`](.cursor/rules/26-sub-pr-design-discipline.mdc) — opt-in design-round process for multi-round/consensus/FFI sub-PRs

Architecture & scope

- [`10-shekyl-first`](.cursor/rules/10-shekyl-first.mdc) — shekyl-core is primary; the `shekyl-oxide` fork is a disposable downstream consumer
- [`15-deletion-and-debt`](.cursor/rules/15-deletion-and-debt.mdc) — when to delete vs. defer; migration-code lifecycle
- [`16-architectural-inheritance`](.cursor/rules/16-architectural-inheritance.mdc) — inherited code is not inherited architecture; migrate flows that contradict the threat model
- [`19-validation-surface-discipline`](.cursor/rules/19-validation-surface-discipline.mdc) — bundle work by validation surface, not feature topic
- [`21-reversion-clause-discipline`](.cursor/rules/21-reversion-clause-discipline.mdc) — reject-now-with-reopening-criteria over pre-provisioned flexibility
- [`60-no-monero-legacy`](.cursor/rules/60-no-monero-legacy.mdc) — v3-from-genesis, no Monero chain history; remove dead pre-genesis code
- [`70-modular-consensus`](.cursor/rules/70-modular-consensus.mdc) — PoW consensus; staking is economic; no speculative consensus scaffolding
- [`75-system-autonomy`](.cursor/rules/75-system-autonomy.mdc) — self-regulating design; minimize coordinated upgrades

Rust & FFI

- [`20-rust-vs-cpp-policy`](.cursor/rules/20-rust-vs-cpp-policy.mdc) — when to use Rust vs. C++
- [`25-rust-architecture`](.cursor/rules/25-rust-architecture.mdc) — workspace layout, the single `shekyl-ffi` crate, dependency rules
- [`17-dependency-discipline`](.cursor/rules/17-dependency-discipline.mdc) — verify deps at source before adding
- [`18-type-placement`](.cursor/rules/18-type-placement.mdc) — transform- vs state-shaped types; byte-layout discipline
- [`40-ffi-discipline`](.cursor/rules/40-ffi-discipline.mdc) — FFI surface management
- [`42-serialization-policy`](.cursor/rules/42-serialization-policy.mdc) — persisted-block wire change ⇒ version-constant bump (CI-enforced)
- [`45-rust-lint-checks`](.cursor/rules/45-rust-lint-checks.mdc) — `cargo fmt` + `cargo clippy --all-targets -- -D warnings` before any Rust commit
- [`93-legacy-symbol-migration`](.cursor/rules/93-legacy-symbol-migration.mdc) — rename `MONERO_*` → `SHEKYL_*` when touching code

Cryptography & secrets

- [`30-cryptography`](.cursor/rules/30-cryptography.mdc) — crypto implementation discipline (hybrid PQC, domain separators, pinned test vectors)
- [`35-secure-memory`](.cursor/rules/35-secure-memory.mdc) — structural secret wiping (`Zeroizing` / `ZeroizeOnDrop`)
- [`36-secret-locality`](.cursor/rules/36-secret-locality.mdc) — Rust owns secrets; C++ holds opaque bytes only
- [`65-address-format-discipline`](.cursor/rules/65-address-format-discipline.mdc) — address format rules
- [`92-copyright-header`](.cursor/rules/92-copyright-header.mdc) — Shekyl Foundation header; never add Monero copyright to a file that lacks one

Testing

- [`50-testing`](.cursor/rules/50-testing.mdc) — test-gate & diagnostic-output discipline

UX (end-user-facing surfaces)

- [`80-usability`](.cursor/rules/80-usability.mdc) — usability-first design
- [`81-no-protocol-knowledge`](.cursor/rules/81-no-protocol-knowledge.mdc) — users never need to understand the protocol
- [`82-failure-mode-ux`](.cursor/rules/82-failure-mode-ux.mdc) — failure modes are first-class design scope

---

## Lineage (so the framing is right)

Shekyl is **v3-from-genesis with no Monero chain history**. Some C++ under
`src/` is inherited from the Monero/CryptoNote lineage and keeps its original
copyright, but **Monero is not an upstream to track** — the codebases are
siblings, and inherited data flows that contradict Shekyl's threat model are
*migrated, not rationalized* ([`16`](.cursor/rules/16-architectural-inheritance.mdc),
[`60`](.cursor/rules/60-no-monero-legacy.mdc)). The vendored
`rust/shekyl-oxide/` is a **disposable downstream consumer**, used for its
crypto primitives; the rest of that tree's application/protocol code is ours
([`10`](.cursor/rules/10-shekyl-first.mdc)).

---

## Repository orientation

```text
shekyl-core/
├── src/        # C++ core: daemon, wallet (legacy), p2p, crypto, rpc
├── rust/       # Rust workspace: wallet stack rewrite + crypto/consensus crates
├── cmake/      # CMake modules and the Rust build bridge (BuildRust.cmake)
├── config/     # Economics/consensus parameters (build-script source of truth)
├── docs/       # Design docs, decision log, FOLLOWUPS, test vectors
├── external/   # Vendored third-party C/C++ deps (submodules)
├── tests/      # C++ unit/integration + functional tests
├── CMakeLists.txt / Makefile   # C++ build entry points
└── CLAUDE.md   # this file
```

Key Rust crates: `shekyl-engine-*` (wallet orchestrator/state/file), `shekyl-scanner`,
`shekyl-tx-builder`, `shekyl-crypto-pq`, `shekyl-proofs`, `shekyl-fcmp`,
`shekyl-curve-tree`, `shekyl-consensus`, `shekyl-economics`, `shekyl-staking`,
`shekyl-units` / `shekyl-types` (foundational newtypes), and the single FFI
crate `shekyl-ffi`. See [`25-rust-architecture`](.cursor/rules/25-rust-architecture.mdc).

Design history worth knowing: [`docs/V3_WALLET_DECISION_LOG.md`](docs/V3_WALLET_DECISION_LOG.md)
(append-only binding decisions), [`docs/design/`](docs/design/), and
[`docs/FOLLOWUPS.md`](docs/FOLLOWUPS.md).

---

## Build & test (practical orientation, not policy)

C++ (Monero-lineage toolchain):

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j$(nproc)
cd build && ctest --output-on-failure          # C++ tests
```

Rust (workspace under `rust/`; gates per [`45`](.cursor/rules/45-rust-lint-checks.mdc), tests per [`50`](.cursor/rules/50-testing.mdc)):

```bash
cd rust
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace
```

CI mirrors these plus `cargo audit` on `Cargo.lock` changes and the
persisted-schema snapshot check ([`42`](.cursor/rules/42-serialization-policy.mdc)). Run them locally before
claiming a change is done — "fix CI later" is not the workflow.
