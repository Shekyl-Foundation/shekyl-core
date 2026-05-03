# Shekyl-Oxide Vendoring Workflow

This document defines the required maintenance workflow for vendored
`shekyl-oxide` crates in `shekyl-core`.

## Vendored source location

The vendored crates live under:

- `rust/shekyl-oxide/`

Upstream tracking reference:

- `https://github.com/Shekyl-Foundation/monero-oxide` (`fcmp++` branch)

Vendored snapshot metadata file:

- `rust/shekyl-oxide/UPSTREAM_MONERO_OXIDE_COMMIT`

## Required update workflow

When upstream ships a fix, use this sequence:

1. Cherry-pick or merge the upstream fix into the Shekyl fork
   (`Shekyl-Foundation/monero-oxide`).
2. Run the fork's tests in isolation in the fork repository.
3. Sync the updated crate subtree into `shekyl-core/rust/shekyl-oxide/`.
4. Update `rust/shekyl-oxide/UPSTREAM_MONERO_OXIDE_COMMIT`.
5. Run the full `shekyl-core` verification suite:
   - `cd rust && cargo build --locked -p shekyl-fcmp`
   - `cd rust && cargo test --locked --workspace`
   - `ninja shekyld` from the build directory
6. Commit in `shekyl-core` with the upstream commit reference in the message.

Do not do blind direct merges from upstream into consensus-critical code.

## CI support

- `.github/workflows/shekyl-oxide-divergence.yml` compares the vendored snapshot
  commit to the fork tip and fails when they diverge.
- `.github/workflows/build.yml` contains a portability guard that fails if
  Cargo manifests include absolute local paths.

## Integration patches (post-2026-05-02 re-sync)

The 2026-05-02 wholesale re-sync of `rust/shekyl-oxide/` from
`Shekyl-Foundation/monero-oxide@2618f22` exposed two integration gaps that
required surgical patches in the vendored copy. Each patch is intentionally
narrow and is tracked for upstream promotion so future re-syncs restore
byte-equality without further intervention.

### Patch 1: `shekyl-address` package rename

**Files affected (vendored copy only):**

- `rust/shekyl-oxide/shekyl-oxide/wallet/address/Cargo.toml` — `name` changed
  from `shekyl-address` to `shekyl-oxide-address`.
- `rust/shekyl-oxide/shekyl-oxide/wallet/Cargo.toml` — dep updated with
  `package = "shekyl-oxide-address"`.
- `rust/shekyl-oxide/shekyl-oxide/rpc/Cargo.toml` — same.
- `rust/shekyl-oxide/shekyl-oxide/rpc/simple-request/Cargo.toml` — same.

**Rationale:** shekyl-core's first-party `shekyl-address` crate (Bech32m
network-aware addresses) collides with the fork's CryptoNote-style
`shekyl-address` crate by package name. Per the Shekyl-First rule
(`.cursor/rules/10-shekyl-first.mdc`), the fork adapts. Source-level imports
remain `shekyl_address::...` because the cargo `package` directive aliases
the rename at the dep declaration, leaving Rust source unchanged.

**Upstream promotion target:** open a follow-up fork PR titled
`chore: rename wallet/address package to shekyl-oxide-address` against
`Shekyl-Foundation/monero-oxide`. Once merged and re-synced, this patch
becomes a no-op divergence and the byte-equality guard is restored.

### Patch 2: `RerandomizedOutput::with_commitment_blind`

**File affected (vendored copy only):**

- `rust/shekyl-oxide/shekyl-oxide/fcmp/fcmp++/src/sal/mod.rs` — restored the
  caller-supplied-commitment-blind constructor.

**Rationale:** `shekyl-fcmp` requires the FCMP++ prover to bind the
pseudo-output commitment to a wallet-derived `r_c = a − z` (where `a` is the
pseudo-out blind and `z` is the original commitment mask) so the rerandomized
`C̃` matches the pre-committed `pseudo_out` used elsewhere in the proof. The
fork's `RerandomizedOutput::new` only emits a fully random `r_c`. The
constructor was a Shekyl extension in the prior vendored copy that the
re-sync overwrote; it should have been promoted to the fork as part of the
2026-05-02 consensus-extensions PR (`Shekyl-Foundation/monero-oxide#2`) but
was missed.

**Upstream promotion target:** open a follow-up fork PR titled
`feat(sal): add RerandomizedOutput::with_commitment_blind for caller-supplied r_c`.
Once merged and re-synced, this patch becomes a no-op divergence.

### Divergence-guard interaction

Both patches are flagged by `oxide-tree-equality`. The guard remains in
**observe-only** mode (Step 4a) and reports the divergence as a workflow
warning rather than failing the build. Promoting the guard to a required
check (Step 4b) is gated on these two follow-up fork PRs landing — restoring
byte-equality is a precondition for the `required` flip.
