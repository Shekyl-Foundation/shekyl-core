# tests/wallet_bench

Google Benchmark harness capturing the wallet2 C++ baseline for the
mid-rewire hardening pass. See
[`docs/MID_REWIRE_HARDENING.md`](../../docs/MID_REWIRE_HARDENING.md)
§3.1 for the full motivation and commit boundary.

## Scope

Of the Five hot paths from §3.1, three are registered in this harness:

- `BM_balance_compute` (N ∈ {100, 1000, 10000}) — **live on this tree**.
- `BM_open_cold` — scaffolded but `SkipWithError`-gated (see "Known
  gaps" below).
- `BM_cache_roundtrip` (N ∈ {1000, 10000}) — scaffolded but
  `SkipWithError`-gated (same blocker).

Two of the Five (`scan_block_K`, `transfer_e2e_1in_2out`) are Rust-only
in commit 3.2. The reason is architectural: wallet2's scanner and
FCMP++ proof paths are daemon-coupled and have no hermetic provisioning
path. Reimplementing the daemon-side synthetic fixture inside this
directory would be ~1000 lines of code that is deleted in `2m-cache`,
measuring a proxy for the real daemon path rather than the real path.
See `docs/MID_REWIRE_HARDENING.md` §3.1 and §4.3 for the full
rationale.

## Building

The harness is opt-in via the `BUILD_SHEKYL_WALLET_BENCH` CMake option
(OFF by default). Normal contributors do not pay the cost of the
Google Benchmark FetchContent step unless they want to run the
benchmarks locally.

```bash
# From the repo root:
cmake -S . -B build/bench \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTS=ON \
  -DBUILD_SHEKYL_WALLET_BENCH=ON \
  -GNinja

cmake --build build/bench --target shekyl-wallet-bench --parallel
```

The first configure downloads Google Benchmark v1.9.1 under
`build/bench/_deps/googlebenchmark-*`. If a system package is
installed (`find_package(benchmark)` succeeds), the FetchContent step
is skipped.

## Running

Console output:

```bash
./build/bench/tests/wallet_bench/shekyl-wallet-bench
```

JSON output (what the CI workflow consumes):

```bash
./build/bench/tests/wallet_bench/shekyl-wallet-bench \
  --benchmark_format=json \
  --benchmark_repetitions=5 \
  --benchmark_report_aggregates_only=false \
  --benchmark_min_time=1.0s \
  > /tmp/wallet2_bench.json
```

To capture an authoritative baseline (what
`docs/benchmarks/wallet2_baseline_v0.json` is produced from), run the
capture script:

```bash
./scripts/bench/capture_cpp_baseline.sh
```

See [`docs/benchmarks/README.md`](../../docs/benchmarks/README.md)
for the baseline-capture procedure and baseline-update policy.

## Fixtures

All fixtures use a pinned seed (`shekyl_bench::kBenchSeed`) so two
runs on the same machine produce byte-identical inputs. See
`bench_fixtures.h` for the fixture API and
`docs/benchmarks/wallet2_baseline_v0.manifest.md` for the
per-benchmark operation lists.

**Important: none of the fixture transfers are cryptographically
valid.** They are populated with seeded-pseudorandom bytes in the
32-byte slots that `balance()` and cache serialization read or write
but do not dereference. Do not point a real wallet at these fixture
files.

## Known gaps

- **`BM_open_cold` and `BM_cache_roundtrip` skip on this tree.** Both
  rely on a freshly generated wallet round-tripping through
  `wallet2::generate` → `store_to` → `load`. That round-trip is
  broken on this tree: `load_keys_buf`'s final
  `hwdev.verify_keys(spend_secret, spend_public)` returns false and
  `load_keys_buf` raises `wallet_files_doesnt_correspond`. The
  already-failing unit test `wallet_storage.store_to_mem2file` in
  `tests/unit_tests/wallet_storage.cpp` reproduces the regression
  one-for-one. Root-causing it is the scope of hardening-pass commits
  `2l` / `2m-keys` / `2m-cache`; patching it here would collide with
  that scope. The benches therefore `state.SkipWithError(...)` with a
  message that names the blocker. When `2l` / `2m` land, un-skipping
  is a one-line change in `bench_wallet2.cpp`. See
  `docs/benchmarks/wallet2_baseline_v0.manifest.md` sections for the
  two skipped paths.
- **`scan_block_K`, `transfer_e2e_1in_2out`**: Rust-only in commit
  3.2 by design, no C++ counterpart here. See scope section above.
- **`kdf_rounds=1`**: the harness pins this to 1 wherever Argon2id
  appears (once the open path un-skips) so the `open_cold` number is
  the minimum achievable Argon2id cost. Production wallets may set
  higher rounds; those numbers scale linearly and can be extrapolated
  from the baseline.

## Cross-references

- [`docs/MID_REWIRE_HARDENING.md`](../../docs/MID_REWIRE_HARDENING.md) §3.1 — this commit's scope and exit criteria.
- [`docs/benchmarks/wallet2_baseline_v0.manifest.md`](../../docs/benchmarks/wallet2_baseline_v0.manifest.md) — prose manifest of operation lists + fixture shapes.
- [`docs/benchmarks/README.md`](../../docs/benchmarks/README.md) — baseline-capture procedure.
