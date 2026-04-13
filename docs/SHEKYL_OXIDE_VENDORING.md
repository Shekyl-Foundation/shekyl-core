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
