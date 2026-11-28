# Vendored FCMP++ Crypto — Maintenance Workflow

This document defines the maintenance workflow for the **only** code still
vendored from the `monero-oxide` fork: the FCMP++ research crypto crates.

> **Scope narrowed (un-vendor slice-2, 2026-06-25).** The application/support
> layer that used to live under `rust/shekyl-oxide/shekyl-oxide/` — `io`,
> `generators`, `primitives`, `bulletproofs`, `fcmp++`, `rpc`, the main crate —
> has been **forked out** into first-party `shekyl-*` crates and is no longer
> upstream-tracked (see [`completed/SHEKYL_OXIDE_UNVENDOR.md`](completed/SHEKYL_OXIDE_UNVENDOR.md)).
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
  (`6b73e4d5df6059a8df9a55e1c0c70e766b8729dd`, the head of fork PR #12: upstream
  `fcmp++`'s eight commits of 2026-11-26 (`cc4812f`..`63e7e7d`), which remove the
  Barycentric divisor calculator, compute divisors with the rewritten `Poly`, make
  the blind constructors return `Option`, make blinds single-use and zeroize the
  SAL multisig. Below it, `dae42d0` (fork PR #11, `Fcmp::proof_size` a `const fn`)
  and `c753b3475f`, the merge of fork PR #10,
  `LinComb::evaluate`'s row sum statically dispatched, on top of the merge of fork PR #9 (`6bf40e5118`):
  `generalized-bulletproofs` correct in every build. Its inner-product prover
  takes no opening point; its vector lengths hold in every build; its prover is
  formed from commitments made from their openings and checks every length and
  constraint in every build; `circuit-abstraction`'s circuit has a role
  (proving, verifying). Before it, `4ea2c03215` (fork PR #8: upstream
  `497f60b`'s multiexp hunks, multiexp 0.5 for a constant-time prover, MSRV
  1.81), whose parent `3abb123` carries the crypto tree of `2485a176`, the
  tip named in the Q6 re-vet. Synced 2026-11-28.)
- `rust/shekyl-oxide/CRYPTO_CONTENT_MANIFEST.sha256` — the A1 content gate: the
  vendored crypto subtree is verified byte-for-byte against this manifest on
  push/PR (`scripts/ci/check_vendored_crypto_manifest.sh`), so an in-place edit
  that bypasses the fork workflow fails CI.

## What the pin covers

The pin names the fork commit the subtree was taken from; it is not a claim that
the subtree is byte-identical to that commit. Verified 2026-09-29 by reformatting
the fork's `crypto/` at the pin with the workspace `rustfmt.toml` and diffing:

- `helioselene`, `divisors`, `generalized-bulletproofs`, `fcmps/ec-gadgets`,
  `fcmps/circuit-abstraction` are **mirrors** of the pin. The only differences
  are the workspace formatting, the dropped `[lints] workspace = true` (these
  crates are workspace-excluded, so there is no workspace to inherit from), and
  the Shekyl `A5-12` soundness note appended to the Bulletproofs README.
- `fcmps` (the crate itself) is **Shekyl's PL-D3 fork**, not a mirror. Its leaf
  is the `K`-point commitment shape (`output_cm`, `leaves_cm_x`); the fork's
  `fcmps` still carries the June `EXTRA_LEAF_SCALARS` shape. Upstream `fcmps`
  fixes are ported by hand into this crate and re-vetted against the Q6 freeze;
  a wholesale copy from the fork would delete PL-D3. Upstream's 2026-11-26
  commits are its first `fcmps` change since `0662298`, and are ported: the blind
  constructors return `Option` (`None` when a divisor cannot be normalized), blinds,
  paths and branches lose `Clone` and blinds are documented single-use, the tape
  stores `Box`, and tests take `recursion_limit = "256"`. PL-D3's `KBlind` takes
  the `Option` and documents why its scalar, the opening of the output's on-chain
  commitment, is the one blind reused on every spend. Fork PR #11's
  `Fcmp::proof_size` `const fn` is ported by shekyl-core #1543. Of `497f60b`'s dependency reconciliation,
  the multiexp hunks are ported (multiexp 0.5 and `subtle`, with the MSRV 1.81
  multiexp 0.5 needs); the rest of that commit (the `zeroize_derive` floors,
  `tap`, and the edits to `helioselene`, `divisors` and the gadget crates) is not
  taken. Fork PR #9's `fcmps` changes are ported: the tape yields its vector
  commitments' openings (`VectorCommitmentTape::openings`, a branch's opening
  without its zero padding), committed once through `Openings::commit`, in place
  of `VectorCommitmentTape::commit`; the circuit wrapper and its gadgets are
  generic over the circuit's role.

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
[`completed/SHEKYL_OXIDE_UNVENDOR.md`](completed/SHEKYL_OXIDE_UNVENDOR.md) §6 A0/A1).
