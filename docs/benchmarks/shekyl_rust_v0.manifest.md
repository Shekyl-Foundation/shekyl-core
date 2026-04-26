# shekyl_rust_v0 — Rust benchmark manifest

**Status.** Pinned prose specification for the Rust criterion +
iai-callgrind benchmarks introduced by hardening-pass commit 2 (see
`docs/MID_REWIRE_HARDENING.md` §3.2). The five harnesses in this
manifest mirror the Five hot paths captured — or scoped — on the C++
side by `wallet2_baseline_v0.manifest.md`. This file is load-bearing:
the bench-comparison script (commit 3.3) emits both manifests side by
side in PR comments against every regression signal, and the
"apples-to-oranges" discipline in `docs/MID_REWIRE_HARDENING.md` §4.3
refuses to compute a delta when the two sides measure meaningfully
different work.

**Scope.** All five hot paths ship with live measurement on the Rust
side. Three are Rust-only by design (`scan_block_K`,
`transfer_e2e_1in_2out`, and `open_cold` while the C++ regression
stands); one (`balance_compute`) has a directly comparable C++
baseline today; one (`ledger_postcard_roundtrip`) is the canonical
canary for the format-layer regression the C++ `BM_cache_roundtrip`
was designed to catch before it was skipped.

**Schema version.** `shekyl_rust_v0`. A schema bump is required
whenever any benchmark's operation list, argument set, or measurement
boundary changes; whenever a KAT profile (e.g. the iai-callgrind
Argon2 profile in `crypto_bench_wallet_open_cold`) is adjusted;
whenever a new bench is added or an existing one is removed. The
schema version is present in every JSON envelope emitted by
`scripts/bench/capture_rust_baseline.sh` and is checked by the
bench-comparison script before any delta is computed.

**Tool split (recap from `MID_REWIRE_HARDENING.md` §3.2).** Every hot
path ships *two* benchmark binaries:

- A `criterion` harness (`<name>.rs`) for wall-clock metrics. Non-
  deterministic on shared runners; used locally and for future
  Tier-2 CI enforcement on a dedicated runner.
- An `iai-callgrind` harness (`<name>_iai.rs`) for instruction-count
  and cache-miss metrics. Deterministic (±0 variance under Valgrind);
  this is the Tier-1 metric the CI gate in commit 3 enforces.

Naming convention:

- `crypto_bench_*` — bidirectional threshold (±5% warn, ±15% fail).
  A speedup is as suspicious as a slowdown because it usually means a
  constant-time property drifted.
- `hot_path_bench_*` — slowdown-only threshold (+5% warn, +15% fail).
  Speedups are unambiguously good.

## 1. `hot_path_bench_ledger_postcard_roundtrip`

**Crate.** `shekyl-wallet-state`.
**Binaries.** `benches/ledger.rs` (criterion), `benches/ledger_iai.rs`
(iai-callgrind).

**What it measures.** Serialize + deserialize round-trip of
`WalletLedger` through `to_postcard_bytes` and `from_postcard_bytes`
over `N ∈ {100, 1000, 10000}` synthetic transfers. The two bench
entries (`serialize/N` and `deserialize/N`) are split so a regression
in one direction is obvious at a glance; both are tagged with
`Throughput::Elements(N)` so the `ns/transfer` rate counter is
directly comparable across N.

**Operation list — every step exercised in the measured region.**

- `serialize/N`:
  - Build a fresh `postcard::to_allocvec` payload for the entire
    `WalletLedger` (all four blocks: Ledger, Bookkeeping, TxMeta,
    SyncState).
  - Inside Ledger, iterate `transfers` and emit each `TransferDetails`
    field-by-field (postcard varint + tagged enum framing).
  - Emit the terminal `crc32c` suffix that `WalletLedger` carries for
    integrity.
- `deserialize/N`:
  - `postcard::from_bytes` over the entire buffer.
  - Version-tag gate: reject payloads whose `block_version` is not in
    the supported set.
  - Per-block CRC verification before handing the block to the typed
    deserializer.

**Fixture shape.** Deterministic synthetic transfers via
`synthetic_transfer(seed, height)`:

- `N` generated as `seed ∈ [0, N)`, `height = 1_000 + seed`.
- `tx_hash[0..8]` carries `seed.to_le_bytes()`; the rest is zero.
- `key` is `seed · 0x9E37_79B9_7F4A_7C15 mod L` multiplied against the
  Ed25519 basepoint table. Golden-ratio-derived stride so adjacent
  seeds do not alias.
- `commitment = Commitment::new(Scalar::ONE, 1_000 + seed)`.
- All optional `Zeroizing`/HKDF fields (`combined_shared_secret`,
  `ho`, `y`, `z`, `k_amount`, `fcmp_precomputed_path`, `subaddress`,
  `payment_id`, `spent_height`, `key_image`) are `None`. See
  **Known gaps** §1 below for the reasoning and the delta-against-C++
  implication.
- `spent = false`, `staked = (seed & 0b11) == 0`,
  `stake_tier = (seed & 0x3) as u8`,
  `stake_lock_until = height + 100`,
  `eligible_height = height + SPENDABLE_AGE`.

**Measurement boundary.** The criterion inner closure wraps each
full round-trip half in `black_box(...)` to prevent dead-code
elimination of both the serialize buffer and the deserialized
`WalletLedger`. The iai-callgrind sibling uses `#[library_benchmark]`
with `setup = build_ledger(N)` / `build_bytes(N)`; setup is excluded
from the measured region as iai-callgrind pins the counter start at
the annotated function boundary.

**Counters.**

- criterion: `ns/transfer = time / N` via `Throughput::Elements(N)`.
- iai-callgrind: `instructions`, `l1_hits`, `ll_hits`, `ram_hits`,
  `total_read+write`, `estimated_cycles`. Per-transfer rate is
  computed downstream by the bench-comparison script from the N
  encoded in the `with_setup_K:build_ledger(N)` label.

**Apples-to-oranges against C++.** No direct C++ counterpart ships on
this tree: `BM_cache_roundtrip` in the C++ harness is `SkipWithError`
-gated behind the pre-existing `wallet2::generate`/`load` regression
(see `wallet2_baseline_v0.manifest.md` §`BM_cache_roundtrip`). Once
that regression is fixed (commits `2l` / `2m-cache`) the Rust
postcard round-trip and the C++ Boost serialization round-trip become
comparable at the per-transfer cost level. The Rust path additionally
runs a `crc32c` over each block; the C++ path does not — this is
documented work that the Rust side does and the C++ side did not, and
the bench-comparison script surfaces it in the PR comment whenever a
cross-stack delta is attempted.

## 2. `hot_path_bench_balance_compute`

**Crate.** `shekyl-wallet-state` (criterion + iai), with
`shekyl-scanner` as a dev-dep.
**Binaries.** `benches/balance.rs`, `benches/balance_iai.rs`.

**What it measures.** `BalanceSummary::compute(&transfers,
current_height)` over `N ∈ {100, 1000, 10000}`. The canonical
balance implementation lives in `shekyl-scanner`; the bench is hosted
in `shekyl-wallet-state` because the `TransferDetails` fixture
builder is already there and duplicating it would split the
source-of-truth for the synthetic transfer shape.

**Operation list — every step exercised in the hot loop.**

- Iterate `&[TransferDetails]`.
- For each transfer, classify into exactly one of:
  `unlocked` | `locked_by_timelock` | `spent` | `frozen` |
  `staked_total` | `staked_matured` | `staked_locked`.
- Predicate evaluation per transfer:
  - `td.spent` short-circuit.
  - `td.frozen` short-circuit.
  - `td.eligible_height <= current_height` (timelock).
  - `td.staked` branch + `td.stake_lock_until` comparison.
- Accumulate per-class running totals into `BalanceSummary` fields.
- Return the summary.

**Fixture shape.** Same `synthetic_transfer(seed, height)` builder as
§1, with the following differences:

- `spent = (seed & 0x7) == 0` — forces ~12.5% of entries through the
  spent short-circuit.
- `frozen = (seed & 0xf) == 0` — forces ~6.25% through the frozen
  short-circuit, and has overlap with `spent` (by design) so the
  predicate ordering inside `compute` is exercised.
- `staked = (seed & 0b11) == 0` — 25% staked.
- `current_height = 1_000 + N/2` so roughly half of `eligible_height`
  comparisons fall on either side of the cutoff. This mirrors the
  "balanced classification spread" that `BM_balance_compute` in the
  C++ harness uses (`wallet2_baseline_v0.manifest.md`
  §`BM_balance_compute`).

**Measurement boundary.** The inner closure is
`BalanceSummary::compute(black_box(transfers), current_height)` with
the return value swallowed by `black_box(...)`. For iai-callgrind,
`build_transfers(N)` is the annotated `setup` and the measured region
is `compute(&transfers, current_height)` only; the setup's
allocations and key-scalar multiplications do not count toward the
reported instruction counts.

**Counters.** Same as §1 — `Throughput::Elements(N)` plus the
iai-callgrind six-metric block.

**Apples-to-oranges against C++.** Direct counterpart:
`BM_balance_compute` in the C++ harness. Both measure an O(N) walk
over the same logical transfer shape. **Documented asymmetries:**

- The Rust path evaluates a richer classification (six-way;
  `unlocked`/`locked`/`spent`/`frozen`/`staked_*`). The C++ path
  evaluates a narrower spent/frozen/unlocked split. The Rust
  per-transfer cost is therefore expected to be modestly higher at
  equal `N`.
- The Rust path has `#[inline]` hints on the predicate helpers; the
  C++ path relies on the compiler. This typically nets out in the
  wall-clock metric and is invisible in the instruction-count metric.
- The Rust fixture includes a per-transfer `Scalar` key derived via
  multiplication against the basepoint table *inside* the setup, not
  the measured region — same as the C++ fixture's
  `DoNotOptimize`-fenced accumulator. No apples-to-oranges drift.

## 3. `crypto_bench_wallet_open_cold`

**Crate.** `shekyl-wallet-file`.
**Binaries.** `benches/open.rs` (criterion, production KDF),
`benches/open_iai.rs` (iai-callgrind, KAT KDF).

**What it measures.** `WalletFile::open(base_path, password,
network, SafetyOverrides::none())` of a freshly created wallet pair.
This is the UI-visible wait the user experiences between "clicked
Open" and "ledger is ready": Argon2id password wrap → keys-file AEAD
decrypt → capability decode → state-file AEAD decrypt → postcard
deserialization of the empty `WalletLedger` → version-tag gate →
advisory-lock reacquire.

**Operation list — every step exercised in the measured region.**

- Read `<base>.keys` from disk, parse the envelope framing.
- Argon2id(`password`, `salt`, `m_log2`, `t`, `p`) → 32-byte master
  key. See **Fixture shape** for the profile split.
- Unwrap the keys-file payload through ChaCha20-Poly1305
  (`aead::Aead::decrypt`).
- Parse the v1 `CapabilityContent::ViewOnly` structure.
- Read `<base>` from disk, parse the envelope framing.
- Unwrap the state-file payload through ChaCha20-Poly1305.
- `WalletLedger::from_postcard_bytes` over the inner payload.
- Re-acquire the advisory lock on `<base>` (fcntl-level; no kernel
  round-trip on re-entry in this bench because `prepared_wallet`
  drops its handle before the measured region).

**Fixture shape.** `prepared_wallet(kdf: KdfParams)` builds a wallet
in a `tempfile::tempdir()` with:

- `base = <dir>/bench.wallet`.
- `capability = ViewOnly { view_sk = [0x11; 32],
                            ml_kem_dk = [0x22; ML_KEM_768_DK_LEN],
                            spend_pk = [0x33; 32] }`.
- `expected_classical_address = [0x01, 0, 0, ...]`
  (`EXPECTED_CLASSICAL_ADDRESS_BYTES` long; only the first byte is
  set so the bench is not accidentally benchmarking a decode of the
  zero-address edge case).
- `creation_timestamp = 0x6000_0000`, `restore_height_hint = 0`.
- `initial_ledger = WalletLedger::empty()` — no transfers. The
  ledger-walk cost is already covered by §1 / §2; `open_cold` is
  specifically the "what does the user see before any ledger state is
  present" metric.
- `password = b"correct horse battery staple"`.
- `network = Network::Testnet`.

The fixture builder creates, drops the handle (releasing the
advisory lock), and hands `(TempDir, base_path)` to the bench
closure. The `TempDir` is held alive through the measured region so
the filesystem does not yank the files mid-bench; criterion's
`iter_batched(.., BatchSize::PerIteration)` guarantees a fresh pair
per iteration.

**KDF profile split.**

- **criterion (`open.rs`) — `KdfParams::default()`**: `m_log2 = 0x10`
  (64 MiB), `t = 3`, `p = 1`. Production cost. The criterion group is
  configured with `sample_size(10)` and
  `measurement_time(30s)` to stay tractable.
- **iai-callgrind (`open_iai.rs`) — KAT profile**: `m_log2 = 0x08`
  (256 KiB), `t = 1`, `p = 1`. Valgrind's ~10× instruction overhead
  makes the production profile run for tens of minutes per iteration.
  The instruction-count metric scales linearly with Argon2id's
  `m · t · p` so the KAT numbers are a faithful proxy; the bench
  label (`kat_kdf:prepared_wallet()`) encodes the profile so
  bench-comparison cannot accidentally compare KAT numbers against a
  production-profile baseline on the same machine.

**Measurement boundary.** Criterion wraps `WalletFile::open(..)`
in `black_box(..)` at both the argument and return-value boundary.
iai-callgrind's `#[library_benchmark]` has the annotated function
body contain the `::open` call only; `prepared_wallet(kdf)` is the
`setup` and is excluded.

**Apples-to-oranges against C++.** Direct counterpart is
`BM_open_cold` in the C++ harness, currently `SkipWithError`-gated
(see `wallet2_baseline_v0.manifest.md` §`BM_open_cold`). The Rust
harness is therefore the authoritative "open stayed snappy" gate for
this tree; the C++ un-skip criterion (commits `2l` / `2m-keys` /
`2m-cache`) is tracked in the C++ manifest. **Documented
asymmetries** to emit in the PR comment once the C++ side un-skips:

- Rust runs a second postcard parse (the `WalletLedger`) against a
  freshly AEAD-decrypted payload; C++ runs a Boost binary-archive
  parse against `m_transfers`. Both have per-byte, non-crypto cost
  only.
- Rust goes through two envelope framings (`.keys` + `.wallet`); C++
  goes through one monolithic file. The Rust path therefore has an
  additional file `open` + read + header-parse that the C++ path
  does not; this is intentional (see `docs/WALLET_FILE_FORMAT_V1.md`)
  and the expected delta is in the tens-of-µs range, not the
  Argon2id-dominated ms range.

## 4. `hot_path_bench_scan_block`

**Crate.** `shekyl-scanner`.
**Binaries.** `benches/scan_block.rs`, `benches/scan_block_iai.rs`.

**What it measures.**
`LedgerIndexes::process_scanned_outputs(&mut LedgerBlock,
block_height, block_hash, outputs)` for `K ∈ {0, 5, 50}` owned
`RecoveredWalletOutput`s per block. This is the non-crypto
bookkeeping half of the scanner pipeline (the bench operates on a
fresh `(LedgerBlock, LedgerIndexes)` pair). The cryptographic half —
`scan_output_recover` (X25519 view-tag pre-filter, ML-KEM-768 decap,
HKDF, leaf-hash rederivation) — lives in
`shekyl-crypto-pq/benches/pqc_rederivation.rs` and is **explicitly
out of scope** for this bench. The two together span the "owned
output lands in wallet state" pipeline; splitting them lets a
regression in one half be attributed correctly.

**Operation list — every step exercised in the measured region.**

- Update `ledger.tip` (height + hash) to the new block.
- For each `RecoveredWalletOutput` in the input `Timelocked`:
  - Consume the wrapper, extract the inner `WalletOutput` and its
    `eligible_height`.
  - Convert the `WalletOutput` into a `TransferDetails` via
    `TransferDetailsExt::from_wallet_output`.
  - Burning-bug guard: skip if `pub_keys` already maps the output
    public key.
  - Push into `ledger.transfers`; update `indexes.pub_keys` (and
    `indexes.key_images` when the transfer carries one).
  - Update the per-subaddress running totals in
    `ledger.bookkeeping`.
- Append `(block_height, block_hash)` to `ledger.reorg_blocks`.

**Fixture shape.** `build_owned_outputs(K)` synthesizes:

- One common `tx_hash = [0x42; 32]` for all outputs in the block
  (mirrors a single-tx multi-output layout, the common fan-out case).
- For each `i ∈ [0, K)`:
  - `WalletOutput::new_for_test(tx_hash, i, global_index = 1_000+i,
    key = unique_point(1_000+i), key_offset = ZERO,
    commitment = Commitment::new(ONE, 1_000+i), subaddress = None)`.
  - `RecoveredWalletOutput::new_for_test(wo, eligible_height =
    1_000+i)`.
- `unique_point(seed)` is `seed · G` (Ed25519 basepoint) with `seed`
  placed in the low 8 bytes of a 32-byte buffer; distinct seeds yield
  distinct curve points.

The `new_for_test` helpers are behind the `shekyl-scanner`
`test-utils` feature, activated for this crate's benches via a
self-referential dev-dep (`shekyl-scanner = { path = ".", features =
["test-utils"] }`). They populate the PQC secret fields with
deterministic zeros; the measured path does not depend on the values.

**Measurement boundary.** Criterion wraps `process_scanned_outputs(..)`
in `black_box(..)` and swallows the return value. The inputs
(`(LedgerBlock::empty(), LedgerIndexes::empty())` + `build_owned_outputs(K)`)
are built per-iteration via `iter_batched(.., BatchSize::SmallInput)`.
iai-callgrind sets the same call as the annotated region with
`with_setup_K:build_state_and_outputs(K)` as the setup label.

**K = 0 case.** Deliberately included because the
"block-arrived-no-owned-outputs" path is the overwhelmingly common
case in wallet scanning (most blocks are not for us). The iai-
callgrind K=0 number (~545 instructions on the baseline host) is the
per-block overhead floor; any regression here is almost certainly an
accidental O(1) → O(log N) lookup on an inner map.

**Counters.**

- criterion: `Throughput::Elements(K.max(1))`. K=0 is reported at
  N=1 for the rate counter because criterion rejects Elements(0);
  downstream the bench-comparison script reads the
  `value_str`/`param` axis for the real K.
- iai-callgrind: six-metric block per K.

**Apples-to-oranges against C++.** No C++ counterpart. The C++
scanner path (`wallet2::scan`) is daemon-coupled: the C++ harness
cannot synthesize a single-block ingestion without running a
real daemon (see `docs/MID_REWIRE_HARDENING.md` §3.1 "Why
`scan_block_K` is Rust-only"). This bench is unilaterally the
"scanner stayed fast across the rewire" gate.

## 5. `crypto_bench_transfer_e2e_1in_2out`

**Crate.** `shekyl-tx-builder`.
**Binaries.** `benches/transfer_e2e.rs`, `benches/transfer_e2e_iai.rs`.

**What it measures.** The two cryptographic components of a 1-input /
2-output transfer that can be exercised hermetically on this tree:

- `bulletproofs_plus_2_outputs`: `Bulletproof::prove_plus(rng,
  commitments)` over two random Pedersen commitments.
- `hybrid_sign_1_input`: `HybridEd25519MlDsa.sign(&sk, &message)`
  against a pre-generated hybrid secret key.

Both entries live under the same criterion `benchmark_group` so the
bench-comparison script can read them as a single "1-in/2-out
transfer crypto cost" line when summing for the PR comment.

**Operation list — every step exercised in the measured region.**

- `bulletproofs_plus_2_outputs`:
  - `Bulletproof::prove_plus(rng, [c0, c1])`:
    - Inner-product argument over two commitments (rangeproof
      size fixed to `log2(64) + log2(2) = 7` rounds).
    - Fiat-Shamir transcript operations (Blake2b).
    - Final proof serialization.
- `hybrid_sign_1_input`:
  - Ed25519 classical sign over a 32-byte sighash-shaped buffer.
  - ML-DSA-65 post-quantum sign over the same buffer.
  - Serialize the combined hybrid signature.

**Fixture shape.**

- `fresh_2out_commitments()`:
  - `recipient = Commitment::new(Scalar::random(OsRng),
    OsRng.next_u64())`.
  - `change = Commitment::new(Scalar::random(OsRng),
    OsRng.next_u64())`.
  - Fresh blindings per iteration so the bench cannot cheat by
    reusing a proof transcript. `iter_batched(.., SmallInput)`.
- `fresh_hybrid_secret_key()` (hoisted out of the measured region):
  - One Ed25519 keypair + one ML-DSA-65 keypair.
  - Pre-generated once at `benchmark_group` setup time; keygen cost
    is not on the per-transfer hot path.
- Message under sign: `[0xA5; 32]`. Fixed-length random-ish buffer
  keeping the ML-DSA-65 input shape realistic without coupling this
  bench to the tx-sighash construction. Real sigs are over the
  32-byte sighash of the tx; ML-DSA-65 is not input-content-sensitive
  at the instruction-count level.

**Measurement boundary.** Criterion wraps the proof/signature output
in `black_box(..)` to prevent elimination. iai-callgrind annotates
each `#[library_benchmark]` with `setup = fresh_2out_commitments()`
or `seeded_signing_state()` respectively; keygen and commitment
generation are excluded from the measured region.

**Determinism deviation (iai-callgrind only).** The iai bench
**bypasses `HybridEd25519MlDsa::sign`** and inlines the two sign
steps with deterministic RNG sources:

- Ed25519 uses `SigningKey::from_bytes(..).sign(..)`, already
  deterministic by construction (RFC 8032 §5.1.6 derives the nonce
  from SHA-512 of the secret key + message, no RNG draw).
- ML-DSA-65 uses `try_sign_with_seed(&BENCH_SEED, ..)` instead of
  `try_sign(..)` (which draws from `OsRng` for the rejection-sampling
  loop). Without this, observed instruction-count variance across
  back-to-back runs was ~16%, violating the §3.2 exit criterion
  ("two runs agree to the instruction").
- ML-DSA-65 keygen uses `try_keygen_with_rng(&mut seeded)` so the
  `s1, s2` secret vectors — which influence the rejection-sampling
  trajectory — are also pinned. Without this, instruction-count
  variance remained ~66% even with a seeded sign RNG.
- BP+ `prove_plus` also uses the seeded `StdRng` (defense in depth;
  BP+ is not rejection-sampling so variance was already near zero).

The criterion sibling keeps the production path (`scheme.sign(..)`,
`keypair_generate()`, `OsRng` for BP+) because wall-clock averaging
absorbs the rejection-sampling variance at the per-iteration level;
only the instruction-count metric needs determinism. Both halves of
the split are documented as §6.3 "known gap" because neither fully
exercises the production hedged-randomized sign path in a stable
way — the criterion half measures it but with variance, the iai
half measures a fips204-compliant deterministic variant.

**Known gap: FCMP++ membership proof.** A full `sign_transaction`
additionally runs a **full-chain membership proof** over the
consensus curve tree — proving the spent output is a leaf of the
tree whose root the daemon published. Shipping a checked-in
curve-tree fixture is its own scope of work (the tree root is
chain-dependent; synthesizing a valid fixture from scratch requires
either a snapshot from the live daemon or a deterministic regtest
chain of useful depth, neither of which is cheap). It is tracked as
**§6.1 below**. In the interim, a delta in this bench is
interpretable as a regression in **Bulletproofs+ or ML-DSA-65 only**;
membership-proof cost is tracked separately once the fixture lands.

**Apples-to-oranges against C++.** No C++ counterpart. The C++
`wallet2::transfer_selected` path is daemon-coupled on input
selection (asks a running daemon for decoy outputs and block heights
for the ring). See `docs/MID_REWIRE_HARDENING.md` §3.1 for the full
rationale. This bench is unilaterally the "transfer crypto stayed
fast across the rewire" gate — FCMP++ excluded, with both directions
of the bidirectional `crypto_bench_*` threshold enforced once the CI
wiring lands in commit 3.

## 6. Known gaps

The v0 baseline is explicit about what it does not measure:

1. **FCMP++ membership proof.** `crypto_bench_transfer_e2e_1in_2out`
   covers BP+ and hybrid-sign only. Expected median-cost contribution
   of the membership proof on a 1-input tx is large (the proof
   dominates `sign_transaction` wall-clock). The un-gap work:
   check in a deterministic curve-tree path fixture under
   `rust/shekyl-tx-builder/benches/fixtures/` keyed to a synthetic
   tree of realistic depth, add a third sub-bench
   `fcmp_plus_plus_membership_proof`, bump the manifest to
   `shekyl_rust_v1`. Not blocking the hardening pass; tracked as a
   follow-up in the commit-2 changelog entry.
2. **Zeroizing/HKDF secret fields in the ledger postcard.**
   `hot_path_bench_ledger_postcard_roundtrip` sets all optional
   `combined_shared_secret` / `ho` / `y` / `z` / `k_amount` /
   `fcmp_precomputed_path` fields to `None`, so the measured cost is
   the "cold-sync transfer" shape (newly scanned, secrets not yet
   hydrated). The "hot-spend transfer" shape with all secret fields
   `Some(..)` adds ~3× bytes per transfer and a matching postcard
   cost; deferring to a follow-up bench is acceptable because the
   hot-spend shape is rare (only transfers actively being spent are
   in that state) and the cold-sync shape is what dominates wallet
   startup.
3. **ML-DSA-65 hedged-randomized production sign path.** The iai-
   callgrind half of `crypto_bench_transfer_e2e_1in_2out` measures
   the FIPS 204 `try_sign_with_seed` + `try_keygen_with_rng`
   deterministic variants rather than the production
   `HybridEd25519MlDsa::sign` path, which draws from `OsRng` inside
   both keygen and the rejection-sampling loop. This was necessary
   to meet the §3.2 exit criterion ("two runs agree to the
   instruction"); back-to-back variance in the production path was
   ~16% on instruction count, ~66% once keygen randomness was also
   accounted for. The deterministic variant is FIPS-204-compliant
   and exercises the identical signing primitives (same NTT, same
   rejection predicates, same packing) — the only differences are
   (a) the `rho_prime` input to expand-A/expand-s1/s2 comes from a
   seed rather than `OsRng`, and (b) the nonce for the signing loop
   comes from a seed rather than `OsRng`. Neither affects
   instruction-count semantics. The criterion sibling preserves the
   production randomized path so the human-facing wall-clock number
   is honest; the bench-comparison script (commit 3) treats a
   regression in either the criterion or iai half as the same
   alert.
4. **Argon2id production profile under iai-callgrind.**
   `crypto_bench_wallet_open_cold`'s iai-callgrind sibling uses the
   KAT profile (`m_log2 = 0x08`, `t = 1`, `p = 1`). Valgrind
   instruction-count overhead on the production profile
   (`m_log2 = 0x10`, `t = 3`, `p = 1`) is tens of minutes per
   iteration; the KAT numbers are a faithful linear proxy and are
   sufficient for the constant-time-property-drift signal that
   `crypto_bench_*` actually gates on. The criterion sibling runs
   the production profile so the human-facing wall-clock number is
   preserved.
5. **`scan_output_recover` (PQC-side of scanning).** Out of scope
   for `hot_path_bench_scan_block` by design — covered by
   `shekyl-crypto-pq/benches/pqc_rederivation.rs`. The bench-
   comparison script treats the two as paired siblings when
   reporting a "scanner regressed" signal.
6. **AEAD framing in isolation.** Out of scope for
   `hot_path_bench_ledger_postcard_roundtrip` by design — covered
   by `crypto_bench_wallet_open_cold`. An AEAD-only regression
   surfaces under `open_cold`; a postcard-only regression surfaces
   under the ledger round-trip.

Because the three C++-missing paths (`open_cold`, `scan_block_K`,
`transfer_e2e`) are all covered on the Rust side, and
`balance_compute` and `ledger_postcard_roundtrip` have live numbers
here, the overall
hardening pass produces a complete Five-path baseline. The coverage
lives asymmetrically between the two stacks — this is the
apples-to-oranges manifest discipline the hardening document
prescribes (`docs/MID_REWIRE_HARDENING.md` §4.3).

## 7. Cross-references

- `docs/MID_REWIRE_HARDENING.md` §3.1 — C++ scope, Five-path list,
  daemon-coupling rationale.
- `docs/MID_REWIRE_HARDENING.md` §3.2 — Rust scope, tool split,
  naming conventions, exit criteria (this commit).
- `docs/MID_REWIRE_HARDENING.md` §3.3 — CI integration, threshold
  table, rolling baseline, profile-on-fail (upcoming commit 3).
- `docs/MID_REWIRE_HARDENING.md` §4.3 — apples-to-oranges manifest
  discipline.
- `docs/benchmarks/wallet2_baseline_v0.manifest.md` — C++ sibling
  manifest.
- `scripts/bench/capture_rust_baseline.sh` — authoritative local
  runner. Emits `shekyl_rust_v0.json` and
  `shekyl_rust_v0.iai.snapshot` into this directory.

## 8. Change log for this manifest

- `v0` (commit 2 of the mid-rewire hardening pass, a.k.a.
  `bench(wallet-state)`): initial Rust baseline. Live measurements:
  all five hot paths (`ledger_postcard_roundtrip`, `balance_compute`,
  `wallet_open_cold`, `scan_block`, `transfer_e2e_1in_2out`). Known
  gaps documented in §6 (FCMP++ membership proof, hot-spend ledger
  shape, Argon2id production profile under Valgrind).
