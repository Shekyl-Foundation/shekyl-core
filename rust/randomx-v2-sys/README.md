# `randomx-v2-sys`

Hand-written `extern "C"` bindings for [`external/randomx-v2`](../../external/randomx-v2/)
(the RandomX v2 C reference), introduced by Phase 2g per the R1-D2
option (c) close in
[`docs/design/RANDOMX_V2_PHASE2G_PLAN.md`](../../docs/design/RANDOMX_V2_PHASE2G_PLAN.md).

## Sole consumer

This crate's only consumer is
[`shekyl-randomx-differential`](../shekyl-randomx-differential/),
which lands at C4 of the Phase 2g implementation sequence. T14
(§6.6) asserts the sole-consumer invariant via `cargo metadata`
at per-PR cadence; any additional consumer is a precedent
violation per the §5.2.5 + §5.7 + R1-D13 disposition and fails
CI.

## Pattern C invariant exemption

The Phase 2F crate-invariant grep gate
([`scripts/ci/check_randomx_crate_invariants.sh`](../../scripts/ci/check_randomx_crate_invariants.sh))
treats `extern "C"` declarations as a precedent-violation pattern
in `shekyl-pow-randomx`. This crate is **exempt** from Pattern C
per R1-D13 because its raison d'être is to be the localized FFI
boundary; T13 (§6.6) asserts the script's exempt-list correctness
per-PR.

## Fork-pin coupling

The 7-signature surface in [`src/lib.rs`](src/lib.rs) is pinned
against `external/randomx-v2/src/randomx.h` at fork commit
`aaafe71322df6602c21a5c72937ac284724ae561`. The
`[package.metadata.shekyl]` `fork-pin-coupled = true` +
`fork-pin-sha = "aaafe71..."` markers in [`Cargo.toml`](Cargo.toml)
are the audit-trail anchors per §1.7 maintenance discipline.

T15 (§6.7) asserts the metadata SHA matches `external/randomx-v2`'s
HEAD at per-PR cadence. Any advance of the fork pin must re-verify
the 7 declarations against the new pin's `randomx.h` and update
the `fork-pin-sha` metadata in the same PR (R1-D2 reopening
criterion).

## Build prerequisites (lands at C3)

The crate's `build.rs` (not present at C1; lands at C3 per §5.2.2
and R4-D2 / R4-D3) requires the `RANDOMX_V2_INSTALL_DIR`
environment variable to point at the CMake install prefix
containing `lib/librandomx.a`. The Shekyl CMake build sets this
via the `BUILD_RANDOMX_V2_DIFFERENTIAL_HARNESS=ON` option per
§5.4.1 / T12.

At C1 the crate is declarations-only; `cargo build -p
randomx-v2-sys` succeeds without any C link step because no
caller invokes the declared functions inside this crate. The
build-clean invariant is the §8.1 C1 bisection-invariant.

## Discipline references

- [Phase 2g plan](../../docs/design/RANDOMX_V2_PHASE2G_PLAN.md)
  §3.5 (R1-D2), §3.16 (R4-D2/R4-D3/R4-D4), §5.2, §5.7, §8.1.
- [`90-commits.mdc`](../../.cursor/rules/90-commits.mdc) scope
  per commit.
- [`17-dependency-discipline.mdc`](../../.cursor/rules/17-dependency-discipline.mdc)
  recommended-against-bindgen rationale (R1-D2 substrate-anchored).
- [`20-rust-vs-cpp-policy.mdc`](../../.cursor/rules/20-rust-vs-cpp-policy.mdc)
  Rust-side localization of unsafe.
