# Vendored FCMP++ Crypto — Maintenance Workflow

This document defines the maintenance workflow for the **only** code still
vendored from the `monero-oxide` fork: the FCMP++ research crypto crates.

> **Scope narrowed (un-vendor slice-2, 2026-06-25).** The application/support
> layer that used to live under `rust/shekyl-oxide/shekyl-oxide/` — `io`,
> `generators`, `primitives`, `bulletproofs`, `fcmp++`, `rpc`, the main crate —
> has been **forked out** into first-party `shekyl-*` crates and is no longer
> upstream-tracked (see [`design/SHEKYL_OXIDE_UNVENDOR.md`](design/SHEKYL_OXIDE_UNVENDOR.md)).
> "Vendored" now means exactly the crypto subtree below; everything else is ours.

## Vendored source location

Only the FCMP++ research crypto remains vendored, under:

- `rust/shekyl-oxide/crypto/{helioselene, divisors, generalized-bulletproofs,
  fcmps, fcmps/ec-gadgets, fcmps/circuit-abstraction}`

These are **workspace-excluded** (so upstream code is not subject to Shekyl's
`-D warnings` clippy gate) and consumed by the first-party crates by path.

Upstream tracking reference (the single source of truth for "where fixes go"):

- `https://github.com/Shekyl-Foundation/monero-oxide` (`fcmp++` lineage)

Vendored snapshot metadata + integrity:

- `rust/shekyl-oxide/UPSTREAM_MONERO_OXIDE_COMMIT` — pinned commit
  (`2753111c50abe04395102e060fb4dc0b57e8d278`, synced 2026-06-24).
- `rust/shekyl-oxide/CRYPTO_CONTENT_MANIFEST.sha256` — the A1 content gate: the
  vendored crypto subtree is verified byte-for-byte against this manifest on
  push/PR (`scripts/ci/check_vendored_crypto_manifest.sh`), so an in-place edit
  that bypasses the fork workflow fails CI.

## Required update workflow

When upstream ships a fix to the crypto crates, use this sequence (do **not** do
blind direct merges from upstream into consensus-critical crypto):

1. Cherry-pick or merge the upstream fix into the Shekyl fork
   (`Shekyl-Foundation/monero-oxide`).
2. Run the fork's tests in isolation in the fork repository.
3. Sync the updated crypto subtree into `shekyl-core/rust/shekyl-oxide/crypto/`.
4. Update `rust/shekyl-oxide/UPSTREAM_MONERO_OXIDE_COMMIT` and regenerate
   `CRYPTO_CONTENT_MANIFEST.sha256`.
5. Run the verification suite:
   - `cd rust && cargo test --locked -p shekyl-fcmp`
   - `cd rust && cargo clippy --workspace --all-targets -- -D warnings`
   - `bash scripts/ci/check_vendored_crypto_manifest.sh`
   - a crypto subtree re-vendor that changes the genesis proof/Bp+ interiors is
     a **genesis-format change** — re-vet the Q6 freeze
     ([`design/GENESIS_TX_WIRE_FORMAT.md`](design/GENESIS_TX_WIRE_FORMAT.md) §6).
6. Commit with the upstream commit reference in the message.

## CI support

- `.github/workflows/vendored-crypto-content.yml` — the **content gate** (A1):
  verifies the local subtree byte-for-byte against the checked-in manifest on
  push/PR. This is the gate that catches the `divisors`-style in-place drift.
- `.github/workflows/shekyl-oxide-divergence.yml` — the weekly **staleness
  canary**: compares the pinned commit hash to the fork tip (commit-hash
  staleness only; explicitly distinct from the content gate). Scoped to the
  crypto crates.

## History

The former "local patches applied ahead of the fork" list (the RPC
`Content-Type` / JSON-RPC 2.0 client fixes) is retired: those crates are now the
first-party `shekyl-rpc-client` / `shekyl-rpc-transport`, maintained here, not
upstreamed. The `divisors` `div`/`interpolate` hardening and the PQC extra-leaf
delta were re-based onto the upstream tip and re-pinned at `2753111c50`
(slice-2 Track A); the vendored copy is a pristine mirror of the fork at that pin
(reformatted to the workspace rustfmt style — see
[`design/SHEKYL_OXIDE_UNVENDOR.md`](design/SHEKYL_OXIDE_UNVENDOR.md) §6 A0/A1).
