# shekyl-randomx-differential

Phase 2g Rust/C differential test harness comparing
[`shekyl-pow-randomx`](../shekyl-pow-randomx/) (the Rust verifier) against
[`external/randomx-v2`](../../external/randomx-v2/) (the C reference)
via the [`randomx-v2-sys`](../randomx-v2-sys/) `extern "C"` wrapper.

This crate is the third leg of the Phase 2c/2d/2f verification posture
per [`RANDOMX_V2_PHASE2G_PLAN.md`](../../docs/design/RANDOMX_V2_PHASE2G_PLAN.md)
§2.5: spec-faithful implementation (leg 1) + property tests (leg 2) +
this differential harness as the catch-of-last-resort backstop (leg 3).

## Status (C4 skeleton)

This is the **C4 skeleton** per §8.1: argument parsing and
`--mode=<MODE>` dispatch are wired, but the actual mode implementations
land at C5–C9. Invoking any mode at C4 returns a clear "corpus modules
not yet wired" diagnostic per the §8.2 C4 → C5 bisection boundary
invariant.

```text
$ cargo run --bin shekyl-randomx-differential -- --help
shekyl-randomx-differential — Phase 2g Rust/C differential test harness
...

$ cargo run --bin shekyl-randomx-differential -- --mode=correctness
error: shekyl-randomx-differential is at the C4 skeleton (per
RANDOMX_V2_PHASE2G_PLAN.md §8.1); mode 'correctness' dispatch requires
the corpus modules (§5.1.5, §5.1.6) and the C oracle / Rust subject /
cache-precondition modules (§5.1.7–§5.1.9), which land at C5–C6.
Re-run after the corresponding commits land on this branch.
```

The C4 → C9 commit sequence per §8.1 fills in:

| Commit | Surface |
|---|---|
| **C5** | `corpus_random.rs` + `adversarial_corpus.rs` + `canonical_outputs.rs` + `gen-canonical-outputs` binary |
| **C6** | `cache_precondition.rs` + `c_oracle.rs` + `rust_subject.rs` (consumes `PreparedCache::cache_block_bytes_for_testing` under `test-internals`) |
| **C7** | `mode_correctness.rs` + `failure_output.rs` + `invocation_banner.rs` |
| **C8** | `mode_worst_case.rs` + `mode_latency.rs` |
| **C9** | `mode_concurrent.rs` + `tests/perf/per_hash_latency.rs` deletion + `main.rs` dispatch wire-up |

## Build prerequisites

The harness links statically against `librandomx.a` produced by
`external/randomx-v2`'s `ExternalProject_Add` (gated on
`-DBUILD_RANDOMX_V2_DIFFERENTIAL_HARNESS=ON` at CMake configure time
per §5.4.1). The `randomx-v2-sys` build script discovers the
install prefix via the `RANDOMX_V2_INSTALL_DIR` environment variable.

```bash
# From the repository root:
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_RANDOMX_V2_DIFFERENTIAL_HARNESS=ON
cmake --build build --target shekyl_randomx_v2

# Then build the harness:
export RANDOMX_V2_INSTALL_DIR="$(pwd)/build/external/randomx-v2-install"
cargo build --bin shekyl-randomx-differential
```

When `RANDOMX_V2_INSTALL_DIR` is unset, `randomx-v2-sys`'s `build.rs`
emits a `cargo:warning=…` and returns cleanly (the rlib still compiles
so `cargo check --workspace` succeeds; only binaries that link against
the cache + VM symbols fail at link time). See
[`RANDOMX_V2_PHASE2G_PLAN.md`](../../docs/design/RANDOMX_V2_PHASE2G_PLAN.md)
§3.16 R4-D3 + §3.17 R5-D2 + §5.2.2 for the soft-fail rationale.

## Sole-consumer invariants

Per §5.6 + R1-D13 the following invariants are mechanically asserted
(T14 §6.6) and reviewer-enforced:

- `randomx-v2-sys` has exactly **one** consumer:
  `shekyl-randomx-differential`. No other workspace member may
  depend on it.
- The `shekyl-pow-randomx` `test-internals` feature
  (§3.17 R5-D1 + §5.3.3) is enabled by **exactly one** consumer:
  this crate. Production builds never enable the feature.

Any extension of either invariant requires a plan-doc round per
§5.7's drift-prevention discipline; it is not a PR-author decision.

## Authoritative spec

`docs/design/RANDOMX_V2_PHASE2G_PLAN.md` is the authoritative spec.
Discrepancies between this README and the plan-doc are README bugs;
file an issue or open a doc PR.
