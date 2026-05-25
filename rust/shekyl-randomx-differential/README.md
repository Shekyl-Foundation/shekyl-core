# shekyl-randomx-differential

Phase 2g Rust/C differential test harness comparing
[`shekyl-pow-randomx`](../shekyl-pow-randomx/) (the Rust verifier) against
[`external/randomx-v2`](../../external/randomx-v2/) (the C reference)
via the [`randomx-v2-sys`](../randomx-v2-sys/) `extern "C"` wrapper.

This crate is the third leg of the Phase 2c/2d/2f verification posture
per [`RANDOMX_V2_PHASE2G_PLAN.md`](../../docs/design/RANDOMX_V2_PHASE2G_PLAN.md)
§2.5: spec-faithful implementation (leg 1) + property tests (leg 2) +
this differential harness as the catch-of-last-resort backstop (leg 3).

## Status (C6 landed; mode implementations land at C7+)

Per §8.1 the C4 skeleton (argparse + `--mode=<MODE>` dispatch shell),
the C5a corpora + canonical outputs, the C5b Round 7 substrate
amendment, and the C6 cache-precondition + Rust/C oracle wrappers
have landed on this branch. Mode dispatch is still gated behind the
"corpus modules wired; mode implementations not yet" diagnostic
until the C7 + C8 mode-module commits land per the §8.2 C4 → C5
bisection boundary invariant (carried forward through C6).

```text
$ cargo run --bin shekyl-randomx-differential -- --help
shekyl-randomx-differential — Phase 2g Rust/C differential test harness
...

$ cargo run --bin shekyl-randomx-differential -- --mode=correctness
error: shekyl-randomx-differential is at the C6 boundary (per
RANDOMX_V2_PHASE2G_PLAN.md §8.1); mode 'correctness' dispatch requires
the mode modules (§§5.1.10, 5.1.12, 5.1.13), which land at C7–C9.
Re-run after the corresponding commits land on this branch.
```

The C4 → C9 commit sequence per §8.1 fills in:

| Commit | Surface |
|---|---|
| **C5a** | `corpus_random.rs` (populated per R6-D1) + `adversarial_corpus.rs` (scaffolded-empty per R6-D2; arrays populated per R7-D4 deferral to post-2g) + `canonical_outputs.rs` (1024 random-corpus hashes + 32 cache-SHA-256 fingerprints) + `gen-canonical-outputs` binary |
| **C5b** | Round 7 substrate-completeness amendment (per §3.19 R7-D1 through R7-D5): R1-D5 + R1-D6 disposition reopening, adversarial-corpus methodology deferred to a post-2g design round, `adversarial_corpus.rs` doc-comment refresh. No new code surface. |
| **C6** | `cache_precondition.rs` + `c_oracle.rs` + `rust_subject.rs` (consumes `PreparedCache::cache_block_bytes_for_testing` under `test-internals`) + `--debug-cache-divergence` flag wired into argparse |
| **C7** | `mode_correctness.rs` + `mode_latency.rs` (`mode_worst_case` deferred per §3.19 R7-D4 to the post-2g adversarial-corpus design round) |
| **C8** | `mode_concurrent.rs` + RSS-bound assertion (T7 + T8) |
| **C9** | `failure_output.rs` + `invocation_banner.rs` + `rust/shekyl-pow-randomx/tests/perf/per_hash_latency.rs` deletion |

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
