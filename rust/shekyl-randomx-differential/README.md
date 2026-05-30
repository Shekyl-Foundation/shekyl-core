# shekyl-randomx-differential

Phase 2g Rust/C differential test harness comparing
[`shekyl-pow-randomx`](../shekyl-pow-randomx/) (the Rust verifier) against
[`external/randomx-v2`](../../external/randomx-v2/) (the C reference)
via the [`randomx-v2-sys`](../randomx-v2-sys/) `extern "C"` wrapper.

This crate is the third leg of the Phase 2c/2d/2f verification posture
per [`RANDOMX_V2_PHASE2G_PLAN.md`](../../docs/design/RANDOMX_V2_PHASE2G_PLAN.md)
§2.5: spec-faithful implementation (leg 1) + property tests (leg 2) +
this differential harness as the catch-of-last-resort backstop (leg 3).

## Status (C4 → C10 landed; harness is feature-complete pending V3.0 follow-ups)

Per §8.1 the full C4 → C10 commit sequence has landed: argparse skeleton,
C5a corpora + canonical outputs, C5b Round 7 substrate amendment, C6
cache-precondition + Rust/C oracle wrappers, C7 correctness + latency
modes, C8 concurrent mode + RSS-bound assertion, C9 failure-output JSON
schema + invocation banner, and C10 CI gates + crate-invariant script
extension + cargo-mutants config + PR template.

`mode_worst_case` is deferred per §3.19 R7-D4 to a post-2g
adversarial-corpus design round; `--mode=worst-case` emits a clean
deferred-mode diagnostic per §5.1.11. The known `compute_hash`
divergence on large random-corpus inputs is tracked in
`docs/FOLLOWUPS.md` (V3.0 target); once that closes, the runtime
modes in `.github/workflows/randomx-v2-differential.yml` move from
the queued state into the merge-blocking gates per §6.8 cadence.

```text
$ cargo run --bin shekyl-randomx-differential -- --help
shekyl-randomx-differential — Phase 2g Rust/C differential test harness
...

$ cargo run --bin shekyl-randomx-differential -- --mode=worst-case
error: --mode=worst-case is deferred per RANDOMX_V2_PHASE2G_PLAN.md
§3.19 R7-D4 (adversarial-corpus methodology design round deferred to
post-2g per V3.0 pre-genesis queue in docs/FOLLOWUPS.md); the mode
dispatch is retained in the CLI surface for forward-compatibility
but produces no output until the post-2g design round resolves R1-D5
+ R1-D6.
```

The C4 → C10 commit sequence per §8.1:

| Commit | Surface |
|---|---|
| **C5a** | `corpus_random.rs` (populated per R6-D1) + `adversarial_corpus.rs` (scaffolded-empty per R6-D2; arrays populated per R7-D4 deferral to post-2g) + `canonical_outputs.rs` (1024 random-corpus hashes + 32 cache-SHA-256 fingerprints) + `gen-canonical-outputs` binary |
| **C5b** | Round 7 substrate-completeness amendment (per §3.19 R7-D1 through R7-D5): R1-D5 + R1-D6 disposition reopening, adversarial-corpus methodology deferred to a post-2g design round, `adversarial_corpus.rs` doc-comment refresh. No new code surface. |
| **C6** | `cache_precondition.rs` + `c_oracle.rs` + `rust_subject.rs` (consumes `PreparedCache::cache_block_bytes_for_testing` under `test-internals`) + `--debug-cache-divergence` flag wired into argparse |
| **C7** | `mode_correctness.rs` + `mode_latency.rs` (`mode_worst_case` deferred per §3.19 R7-D4 to the post-2g adversarial-corpus design round) |
| **C8** | `mode_concurrent.rs` + RSS-bound assertion (T7 + T8) |
| **C9** | `failure_output.rs` + `invocation_banner.rs` + `rust/shekyl-pow-randomx/tests/perf/per_hash_latency.rs` deletion |
| **C10** | `.github/workflows/randomx-v2-differential.yml` (per-PR structural + nightly + weekly mutants) + `.cargo/mutants.toml` (skip-list discipline) + `.github/pull_request_template.md` (harness/verifier modification checklist) + `scripts/ci/check_randomx_crate_invariants.sh` extension (T13 + T14 + T15) + `tests/crate_invariants.rs` integration tests |

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
