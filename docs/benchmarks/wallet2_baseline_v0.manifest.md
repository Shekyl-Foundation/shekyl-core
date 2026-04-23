# wallet2 baseline v0 — benchmark manifest

**Status.** Pinned prose specification for the C++ benchmarks captured
by `tests/wallet_bench/bench_wallet2.cpp`. This manifest is
load-bearing: the Rust harness in commit 3.2 mirrors these operation
lists, and the bench-comparison script (commit 3.3) emits both manifest
lines side by side in the PR comment against every regression signal.

**Scope.** Of the Five hot paths identified in §3.1 of
`docs/MID_REWIRE_HARDENING.md`, **one ships with a live C++ baseline on
this tree** (`BM_balance_compute`). Two others (`BM_open_cold`,
`BM_cache_roundtrip`) are scaffolded but `SkipWithError`-gated because a
pre-existing regression in `wallet2::generate`/`store_to`/`load` prevents
any freshly generated wallet from round-tripping through disk — see the
**Known gaps** section below. The two Rust-only benchmarks
(`scan_block_K`, `transfer_e2e_1in_2out`) have no C++ entry at all; see
§3.1 and §4.3 of the hardening document for the daemon-coupling
rationale.

**Schema version.** `wallet2_baseline_v0`. A schema bump is required
whenever any benchmark's operation list, argument set, or measurement
boundary changes, or whenever a previously skipped bench un-skips. The
schema version is part of every JSON output and is checked by the
bench-comparison script before any delta is computed.

## BM_balance_compute

**What it measures.** `wallet2::balance(subaddr_index_major=0,
strict=true)` over `N ∈ {100, 1000, 10000}` synthetic transfers.
Exercises the O(n) summation loop with both branches of the
`is_transfer_unlocked` + spent/frozen filters.

**Operation list — every step exercised in the hot loop.**

1. `w.balance(0, true)`:
   - Iterate `m_transfers`.
   - For each entry, test `m_spent`, `m_frozen`,
     `m_subaddr_index.major == 0`, and `is_transfer_unlocked(td)`.
   - Accumulate `td.amount()` into the per-major-account total.
   - Return the total.

**Fixture shape — controlled by seed `0xBEEFF00DCAFEBABE`.**

- Transfer count: Google Benchmark `Arg(N)` → `state.range(0)`.
- Half spent (`m_spent = (i & 1) != 0`), half unspent. Forces both
  branches of the spent-filter short-circuit.
- Single major account (`subaddr_index.major = 0`); minor spread
  across `i % 8` to keep the subaddress filter non-degenerate.
- Block heights drawn uniformly in `[0, 1_000_000)` so
  `is_transfer_unlocked` has a mix of unlock statuses against the
  synthetic `chain_tip_height=1_000_000`.
- Amounts drawn uniformly in `[1, 2^40)` so no trivial short-circuit
  on zero amounts.
- All other fields (`m_key_image`, `m_mask`, `m_y`, `m_k_amount`,
  `m_txid`) are filled with seeded-pseudorandom bytes. Not
  cryptographically valid; `balance()` does not dereference them.

**Measurement boundary.** The `DoNotOptimize` sink is an `xor`-reduced
accumulator of balance return values across iterations. Without this,
the inner loop is dead-code-eliminated to nothing.

**Counters.**

- `items_processed = iterations * N` — Google Benchmark's standard
  per-element rate counter.
- `per_transfer_ns` — inverse of items-per-second, i.e. nanoseconds
  per transfer. This is the number that regression thresholds care
  about; wall-clock scales trivially with N.
- `transfers` — the `N` argument, echoed for correlation in the CSV.

**Apples-to-oranges against Rust.** The Rust `balance_compute_N`
benchmark iterates the same `TransferDetails`-equivalent structure
with `Zeroize`-on-drop semantics and `#[inline]` hints from
`shekyl-wallet-state`. The Rust path additionally calls
`WalletLedger::check_invariants()` on the input fixture once (outside
the hot loop). The per-transfer costs are expected to be comparable.

## BM_open_cold (SKIPPED on this tree)

**Intended measurement.** End-to-end wallet open from on-disk fixture —
filesystem read of `.keys` + cache, Argon2id password-derive under
`kdf_rounds=1`, XChaCha20 decrypt, keys JSON parse, v1 master-seed
rederivation, binary-archive cache parse, XChaCha20 cache decrypt,
inner cache deserialize. Wall-clock `ms`, real-time; this is the wait
the user actually sees between double-click and usable wallet.

**Skip reason.** `wallet2::generate(path, password)` (and the
`generate("", password)` + `store_to(path, password)` variant used by
the existing unit tests) does not produce an on-disk fixture that
`wallet2::load(path, password)` will re-open on this tree: the final
`hwdev.verify_keys(spend_secret, spend_public)` call inside
`load_keys_buf` returns false and `load_keys_buf` throws
`tools::error::wallet_files_doesnt_correspond`. The existing unit test
`wallet_storage.store_to_mem2file` in
`tests/unit_tests/wallet_storage.cpp` reproduces the regression
one-for-one, and `wallet_storage.change_password_*` tests are already
guarded with `GTEST_SKIP()` referencing the missing fixture dance.
Root-causing the regression is the exact work scope of hardening-pass
commits `2l` (cache rewire) and `2m-keys` (keys rewire); fixing it
here would collide with that scope. The bench therefore carries a
`state.SkipWithError(...)` message that names the blocking issue and
points at the un-skip commits.

**Un-skip criterion.** One-line change: remove the `SkipWithError` call
and restore the `OpenColdFixture` + `w.load(fx.wallet_base, password)`
loop, plus flip the table row in `docs/MID_REWIRE_HARDENING.md` §3.1
from `no (blocked)` to `yes`. The scaffolding (`TempWalletDir`,
`generate_fresh_wallet_to_disk`) stays in `bench_fixtures.{h,cpp}`
precisely so that re-enabling is mechanical.

## BM_cache_roundtrip (SKIPPED on this tree)

**Intended measurement.** `get_cache_file_data` (inner serialize of
`m_transfers` + XChaCha20 encrypt) + `binary_archive` serialize of the
encrypted blob + `load_wallet_cache` (archive parse + XChaCha20
decrypt + inner deserialize) on a wallet holding `N ∈ {1000, 10000}`
transfers. Disk I/O excluded; this is the format-layer regression
canary.

**Skip reason.** Depends on `wallet2::load` succeeding against a
freshly generated wallet, which fails for the same reason as
`BM_open_cold`. The alternative — writing a raw cache blob from
scratch without ever going through `wallet2` — would bypass
`get_cache_file_data` entirely and would therefore only measure Boost's
serialization framing, which is not the signal this bench is supposed
to capture (a regression in `cache_file_data` framing, XChaCha20 cache
encryption, or the per-transfer inner serialization pass). The hollow
measurement is worse than no measurement, so the bench skips.

**Un-skip criterion.** Same as `BM_open_cold`: lands with
`2l` / `2m-cache`.

## Known gaps

The one-bench v0 baseline is honest about what it does not measure:

1. **Cold-open Argon2id / KDF cost**: not captured on this tree in
   C++. The Rust harness in commit 3.2 captures it directly via the
   `shekyl-wallet-file` AEAD open path.
2. **Cache-format regressions**: not captured on this tree in C++.
   The Rust harness captures these through the postcard ledger roundtrip
   plus the wallet-file AEAD roundtrip.
3. **Scanner and transfer end-to-end**: not captured in C++ at all by
   design — see §3.1 "Why `scan_block_K` and `transfer_e2e_1in_2out`
   are Rust-only".

Because the Rust side covers all three above, the overall hardening
pass still produces a complete Five-path baseline; it just lives
asymmetrically. This is the "apples-to-oranges manifest discipline"
the hardening document prescribes (§4.3): the regression-comparison
script refuses to compute a C++-vs-Rust delta for paths where one side
is missing, and instead emits a one-liner explaining the asymmetry.

## Change log for this manifest

- `v0` (commit 1 of the mid-rewire hardening pass): initial baseline.
  Live measurement: `BM_balance_compute`. Scaffolded-but-skipped:
  `BM_open_cold`, `BM_cache_roundtrip` (blocked on the pre-existing
  `wallet2::generate`/`load` round-trip regression; un-skips with
  commits `2l` / `2m-keys` / `2m-cache`). The two Rust-only benchmarks
  from the Five (`scan_block_K`, `transfer_e2e_1in_2out`) are
  documented only in the Rust-side
  `wallet_state_baseline_v0.manifest.md` that commit 3.2 introduces.
