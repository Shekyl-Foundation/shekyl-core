# RandomX v2 — Rust verifier + C miner

**Status.** **DRAFT — Round 0 (initial draft, 2026-05-16).** Phase 0
deliverable for the RandomX v2 Rust port. Companion:
[`RANDOMX_V1_FALLBACK.md`](./RANDOMX_V1_FALLBACK.md). Both documents
must pass the Phase 0 review cycle before any code lands.

**Scope.** Shekyl's target proof-of-work is RandomX v2 from the
Shekyl-Foundation RandomX fork. Verification is a Rust pure-software
interpreter; mining keeps the fork's C/JIT implementation as a
miner-only artifact. No backward compatibility is preserved: no
CryptoNight, no RandomX v1 dispatch, and no `RX_BLOCK_VERSION` gate.

---

## 1. Why RandomX v2

The RandomX v2 fork is a Shekyl-controlled divergence from upstream
RandomX v1. Phase 1 adds it as `external/randomx-v2` rather than
repointing `external/randomx`; the rename is load-bearing because it
makes the fork boundary and pin discipline visible in the tree.

The v2 specification source is the fork's `doc/design_v2.md` at the
commit pinned during Phase 1. This document intentionally leaves the
exact commit as a Phase 0 review item:

- **Pinned fork commit:** TBD after v2 algorithm review.
- **Spec section citations:** TBD after the pinned commit is selected.
- **v2 deployers besides Shekyl:** TBD during review.

Phase 0 must answer two questions before Phase 2 begins:

1. What concrete problem does v2 solve that RandomX v1 does not?
2. Who, besides Shekyl, is reviewing or deploying this v2 algorithm?

If Shekyl is the only deployer, Shekyl owns the full review burden for
the v2 algorithm, the v2 spec, the C reference, and the Rust port.
That makes [`RANDOMX_V1_FALLBACK.md`](./RANDOMX_V1_FALLBACK.md) a real
contingency, not paperwork.

## 2. Permanent C/Rust Split

The split is permanent:

- **C/JIT stays miner-only.**
- **Rust interpreter owns daemon verification.**

The JIT is not a good Rust migration target. Any JIT is structurally
unsafe: it allocates executable memory, emits raw instruction bytes,
manages W^X transitions, and trusts an encoder. Rust would not remove
that risk; it would wrap it in large `unsafe` regions while replacing a
production-exposed C emitter with new code.

Cranelift is also the wrong abstraction. RandomX's ASIC-resistance
properties depend on the generated instruction mix. An optimizing IR can
change the shape the algorithm relies on. The miner wants a near-1:1
bytecode-to-native emitter, which is what the fork's C implementation
already provides.

The mining ecosystem also consumes the C ABI. Forcing miners to adopt a
Rust crate would raise the integration bar for hobbyist miners, which
cuts against the accessibility goal RandomX is supposed to serve.

The daemon verification path does not need a JIT. It verifies one hash
per block, not millions of hashes per second. The C JIT is retained for
mining throughput and structurally isolated from daemon verification by
CI (§7).

## 3. Spec Is the Source of Truth

The Rust verifier is implemented from the v2 spec, not from the C
implementation. The C reference is a cross-check. If the spec and C
reference disagree, the spec wins and the C fork receives a bug report.

This avoids the failure mode where the Rust port matches the C library
while both diverge from the specification.

Phase 2 test hierarchy:

- Spec vectors are required for every primitive and opcode family.
- Differential tests compare Rust and C over a corpus of
  `(seedhash, data)` inputs.
- Differential success is necessary but not sufficient; spec-vector
  success remains the canonical correctness condition.

Test-vector provenance is recorded per primitive in Phase 2:

- If the v2 spec ships canonical vectors, those are the vectors checked
  in and committed under `rust/shekyl-pow-randomx/tests/vectors/spec/`.
  Each vector file records the spec section it derives from.
- If the spec defines a primitive but ships no vectors, vectors are
  generated from the C reference at the pinned fork commit, checked in
  under `rust/shekyl-pow-randomx/tests/vectors/reference/`, and labelled
  as derived. A derived vector that disagrees with a later spec update
  is treated as a C-reference bug, not a Rust-port bug.
- The differential corpus in
  `rust/shekyl-pow-randomx-difftest/` is generated, not checked in, so
  its inputs are reproducible from a fixed RNG seed.

This split keeps the "spec wins over C" rule mechanical: spec vectors
fail loudly if the Rust port matches the C reference but diverges from
the spec.

## 4. Derived-First Design

Per [`18-type-placement.mdc`](../../.cursor/rules/18-type-placement.mdc),
RandomX verification values are transform-shaped:

- `Cache::derive(seedhash) -> Cache`
- `Dataset::derive(cache) -> Dataset` (miner-only)
- `Vm::new(cache)` and `Vm::compute(data) -> Hash`
- `compute_hash(cache, data) -> Hash`

The canonical definition is the function. Storing the result is a memo,
not protocol state.

The inherited C code uses process-global caches, thread-local VMs, and
an async cache-rebuild state machine. That shape is appropriate for a
miner trying to sustain high throughput, but it is not the architecture
Shekyl wants on the verifier path. Per
[`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc),
inheriting code is not inheriting architecture.

The Rust verifier crate, `shekyl-pow-randomx`, therefore exposes pure
derivations and opt-in memoization helpers. It does not instantiate
module-level mutable state.

## 5. FFI Surface

The committed FFI surface is one function:

```c
int32_t shekyl_pow_randomx_v2_hash(
    const uint8_t* seedhash32,
    const uint8_t* data,
    size_t data_len,
    uint8_t* out_hash32);
```

Semantics:

- `seedhash32` is exactly 32 bytes.
- `out_hash32` receives exactly 32 bytes on success.
- Return codes follow `40-ffi-discipline.mdc`: `0` success, negative
  values for distinct failure modes.
- `shekyl-ffi` may memoize derived caches internally across calls.
  `shekyl-pow-randomx` itself does not hold module-level state.

`seedheight(height) -> u64` is discretionary. Phase 3 may add it only if
the C++ caller survey proves the call cannot be eliminated or moved to a
Rust caller cleanly.

Explicitly not exported:

- `prewarm`
- `set_main_seedhash`
- `set_miner_thread`
- `get_miner_thread`
- `allocate_state`
- `free_state`

Those functions manage inherited state that does not exist in the
derived-first verifier design.

## 6. No Prewarm

Prewarm is deliberately omitted. Cache derivation is paid lazily on the
first hash for a new seedhash.

Current budget assumptions:

- `SEEDHASH_EPOCH_BLOCKS = 2048`
- `DIFFICULTY_TARGET_V2 = 120` seconds
- One cache miss per epoch is about once every 2.84 days.
- A cache miss budget of 150-200 ms is acceptable for a one-off event.
- During a 600k-block initial sync, about 293 epoch transitions add
  roughly 44 seconds of cache-derivation overhead.

That overhead is noise relative to per-hash verification time. The
inherited async cache-rebuild state machine would add scheduling logic,
reorg edge cases, background threads, and lifecycle calls for a cost
that is below the user-visible threshold.

There is no supported fake-prewarm pattern. With a capacity-2 LRU, a
dummy hash can be evicted before the real use. If a future design needs
prewarm, it must propose a new design doc that revisits this decision.

## 7. Isolation Invariants

Two invariants are load-bearing.

### 7.1 C library absent from daemon verification

Daemon binaries built with `BUILD_RANDOMX_V2_MINER_LIB=OFF` must contain
zero symbols from the C v2 library:

- `randomx_alloc_cache`
- `randomx_alloc_dataset`
- `randomx_create_vm`
- `randomx_init_cache`
- `randomx_init_dataset`
- `randomx_destroy_vm`
- `randomx_vm_set_cache`
- `randomx_calculate_hash`
- `randomx_dataset_item_count`
- `randomx_get_flags`

Linux/macOS CI uses `nm` against that explicit list. Windows CI uses the
equivalent `dumpbin /symbols` check. The check must not become a broad
`randomx_*` grep because Rust-internal symbol names may contain
`randomx` without linking the C library.

### 7.2 `shekyl-pow-randomx` has no C ABI

All C ABI lives in `shekyl-ffi` and uses the
`shekyl_pow_randomx_v2_*` prefix. The verifier crate never defines
`#[no_mangle]`, `#[unsafe(no_mangle)]`, or exported `extern "C"` Rust
functions.

The verifier crate also forbids module-level runtime-mutable state.
Immutable tables are allowed; `static mut`, `Mutex`, `RwLock`, `OnceCell`,
`OnceLock`, `Lazy`, and atomics at module scope are not.

## 8. Performance Targets

The C baseline is the current light-VM-JIT path described by
`src/crypto/rx-slow-hash.c` comments: roughly 10-15 ms per hash.

Phase 2 targets:

- Rust interpreter median per-hash latency must be at most 3.0x the C
  light-VM-JIT median on the same hardware.
- Cache derivation must be at most 200 ms.
- Per-call `Vm` allocation must be at most 100 us. If it exceeds that,
  Phase 2 adds an opt-in `VmPool` type; the pool is caller-owned and
  not module-level state.

At the 3.0x ratio, a 600k-block sync adds about four hours of PoW
verification time over the C light-VM-JIT baseline:

- C baseline midpoint: 12 ms/hash.
- Rust target ceiling: 36 ms/hash.
- Delta: 24 ms/hash.
- 600,000 blocks x 24 ms ~= 4 hours.

That four-hour delta is the Phase 0 review question. If review rejects
it, the target tightens before Phase 2 starts.

Per-PR CI uses a synthetic benchmark of 1024 hashes at fixed seedhashes
and fixed inputs, checking the median Rust/C ratio. Full 600k-block sync
timing is a release-gate test, not per-PR CI.

Pre-genesis, the 600k-block release-gate test cannot run against a real
Shekyl chain because that chain does not yet exist. Phase 0 records the
substitute used until genesis:

- A synthetic chain harness deterministically generates 600,000 block
  headers with valid seedhash transitions every 2048 blocks, fixed
  hashing-blob sizes, and a fixed RNG seed.
- The harness lives under `tests/release_gates/randomx_v2_sync/` and
  reuses the same FFI entry point the daemon uses.
- The harness replaces the real chain for the release-gate metric;
  once a Shekyl stressnet or mainnet of comparable length exists, the
  release-gate switches to that and the synthetic harness becomes a
  regression test only.

The release-gate threshold is wall-time-over-baseline, not absolute
wall time, so the synthetic harness comparison stays valid across
hardware changes.

## 9. Environment and Consensus Constants

No Monero-era RandomX env vars carry forward.

- `MONERO_RANDOMX_UMASK` becomes an explicit verifier configuration
  parameter if needed; no env var.
- `MONERO_RANDOMX_FULL_MEM` is miner-only; verifier code does not use
  the full 2 GiB dataset.
- `SEEDHASH_EPOCH_BLOCKS` becomes a typed constant.
- `SEEDHASH_EPOCH_LAG` becomes a typed constant.

Operator overrides of consensus-critical constants are deleted, not
renamed to `SHEKYL_*`. That follows `60-no-monero-legacy.mdc` and the
system-autonomy rule: consensus defaults must be documented and stable,
not controlled by local environment variables.

## 10. Grover Bound and V4

RandomX output is 256 bits. Quantum Grover search gives a square-root
speedup for unstructured preimage search. For a target threshold `T`,
classical expected work is approximately `2^256 / T`; Grover reduces
the exponent by half for the same threshold search.

For any realistic Shekyl difficulty target, the target remains far below
the point where Grover changes network economics during the V3/V4
planning horizon. The relevant V4 risk is not that RandomX's 256-bit
output collapses; it is whether quantum miners become economically
available and materially shift mining centralization. That is monitored
as an economics/deployment question, not a reason to reject RandomX v2
from genesis.

Phase 0 review must fill this section with the concrete target-range
calculation used by the release checklist.

## 11. `cncrypto` PUBLIC Link Survey

Current `src/crypto/CMakeLists.txt` links `randomx` as a `PUBLIC`
dependency of `cncrypto`. That means downstream consumers can receive
`randomx_*` symbols transitively.

Known direct `cncrypto` consumers from the Phase 0 survey:

- `src/crypto/wallet/CMakeLists.txt` (`wallet-crypto`)
- `tests/crypto/CMakeLists.txt` (`cncrypto-tests`)
- `src/device_trezor/CMakeLists.txt` (`device_trezor`)
- `tests/CMakeLists.txt` (`shekyl-wallet-crypto-bench`)

Phase 3c may drop the C `randomx` link from `cncrypto` only after these
consumers are confirmed not to use `randomx_*` directly or are rewired
to the new FFI path.

## 12. What Stays State

The irreducible state is narrow and owned by its semantic owner:

- `shekyl-ffi` owns its internal `CacheStore` memo because C callers
  need cross-call memoization and C ABI state belongs at the boundary.
- Chain state owns the seedhash selection for a given height.
- `SEEDHASH_EPOCH_BLOCKS` and `SEEDHASH_EPOCH_LAG` are protocol
  constants in `shekyl-pow-randomx`.

Everything else is transform-shaped and derived on demand.

## 13. Explicit Non-Goals

- No RandomX v1 compatibility.
- No CryptoNight fallback.
- No `RX_BLOCK_VERSION`.
- No `major_version` or `hf_version` dispatch in PoW selection.
- No runtime env-var overrides of consensus constants.
- No Rust JIT.
- No `prewarm` FFI.
- No C ABI exports from `shekyl-pow-randomx`.
- No module-level runtime-mutable state in `shekyl-pow-randomx`.

## 14. Wallet V3.2 Gate

Track B starts only after wallet V3.2 (`wallet_rpc_server` Rust cutover)
has landed on `dev` and the FFI mega-header has been quiet for one to
two weeks. Phase 0 and Phase 1 can proceed in parallel with wallet work;
Phase 3 cannot.

## 15. RPC Payments Disposition — Delete

**Phase 0 decision: delete the RPC-payments feature in its entirety.**
This is recorded as a deliberate Shekyl-choice, not deferred to Phase 4
implementation discretion.

### 15.1 What RPC payments was

Monero's RPC-payments feature (shipped ~0.17, 2020-2021) allowed a
daemon operator to require RPC clients to submit RandomX work as
"payment" before serving requests. The intended use case was making
public-node operation economically rational: instead of free-riders
DDoS'ing public daemons, clients would pay via PoW, with credits
tracked per-client per-session. Wallets calling a payment-enabled
remote daemon had to compute RandomX themselves to pay for their
queries, which is why `src/wallet/wallet_rpc_payments.cpp` imports the
PoW machinery into the wallet tree.

### 15.2 Evidence the wallet-tree PoW touchpoint is unique

A targeted grep across `src/wallet/` for `rx_*`, `randomx_*`,
`cn_slow_hash`, `rx_slow_hash`, and `RX_BLOCK_VERSION` returns exactly
one file:

- `src/wallet/wallet_rpc_payments.cpp:156` (`if (major_version >= RX_BLOCK_VERSION)`)
- `src/wallet/wallet_rpc_payments.cpp:158` (`crypto::rx_slow_hash(...)`)
- `src/wallet/wallet_rpc_payments.cpp:163` (`crypto::cn_slow_hash(...)`)

Deleting RPC payments removes the entire wallet-tree PoW surface in a
single sweep. The grep above is rerun in Track B's gate check as
mechanical evidence that no new wallet-tree PoW touchpoint has
appeared in the meantime.

### 15.3 Why delete (rather than rewrite)

1. **Pre-genesis, there are no users.** Per `60-no-monero-legacy.mdc`
   the default is delete and there is no transitional concern.
2. **The feature shipped and saw essentially zero production adoption
   in Monero.** Reasons that carry forward to Shekyl: most users run
   their own daemon and never hit the payment path; public-node
   operators who want monetization prefer other mechanisms (Tor hidden
   services with donations, rate limiting, or accepting load); client-
   side friction is real (PoW capability now required) while the
   client benefit is zero (work done for the operator's privilege of
   serving); light and mobile wallets struggle to support it; credits
   don't survive session boundaries cleanly; the threat model — "I
   want to charge non-mining clients" — conflicts with the audience
   most likely to be running a privacy-preserving public node.
3. **If Shekyl ever wants a public-RPC monetization story, it is
   better designed fresh than inherited.** The space has changed since
   2020 — Lightning-style payment channels, Tor hidden services with
   built-in rate limiting, OAuth-style API keys, and pay-per-call HTTP
   services all exist now. Carrying a barely-used 2020 design forward
   forecloses better options without buying anything.

### 15.4 Concrete deletion surface

Phase 4 inherits this checklist. Files that exist solely to support
RPC payments and are deleted whole:

- `src/rpc/rpc_payment.h`
- `src/rpc/rpc_payment.cpp`
- `src/rpc/rpc_payment_signature.h`
- `src/rpc/rpc_payment_signature.cpp`
- `src/rpc/rpc_payment_costs.h`
- `src/wallet/wallet_rpc_payments.cpp` (the wallet PoW touchpoint)
- `tests/functional_tests/rpc_payment.py`

Files that touch RPC payments but stay; surgical edits remove the
payment hooks, types, RPC endpoints, CLI commands, and config fields:

- `src/rpc/CMakeLists.txt` — drop the `rpc_payment*` translation units.
- `src/rpc/core_rpc_server.{h,cpp}` — remove `GET_RPC_PAYMENT_*` /
  `RPC_ACCESS_*` endpoints and their dispatch entries.
- `src/rpc/bootstrap_daemon.{h,cpp}` — drop client-side payment
  handling for upstream bootstrap daemons.
- `src/cryptonote_config.h` — drop RPC-payment-related constants.
- `src/daemon/rpc_command_executor.{h,cpp}`,
  `src/daemon/command_parser_executor.{h,cpp}`,
  `src/daemon/command_server.cpp` — remove `rpc_payments`,
  `change_rpc_pay`, and related daemon CLI commands.
- `src/wallet/CMakeLists.txt` — drop `wallet_rpc_payments.cpp` from
  the wallet library.
- `src/wallet/wallet2.{h,cpp}`, `src/wallet/wallet_args.{h,cpp}`,
  `src/wallet/wallet_errors.h`,
  `src/wallet/wallet_rpc_helpers.h`,
  `src/wallet/wallet_rpc_server.cpp`,
  `src/wallet/node_rpc_proxy.{h,cpp}` — remove client-id /
  payment-secret fields, `--rpc-payment-*` CLI flags, payment error
  types, and the proxy's payment-credit accounting.

Phase 0 review confirms this list against the tree before Phase 4
begins; new daemon or wallet code merged in the interim is added here.

### 15.5 Phase 4 scope implication

The original "rewrite or delete" framing left Phase 4 with the larger
scope (rewrite the file to call the v2 verifier, update its tests,
maintain a feature with no users). The delete decision tightens Phase
4 to: drop the files above, drop the dispatch entries, drop the CLI
flags, done. No v2 verifier wiring is needed for the wallet tree;
Phase 3's FFI export is consumed by daemon-side block verification
only.

A future RPC-monetization design — if Shekyl ever wants one — gets
its own design doc and is reviewed on its own merits, against 2026+
options rather than 2020 ones.

## 16. Genesis-Block Seedhash Handling

Inherited C `rx_seedheight(height)` returns `0` for any
`height <= SEEDHASH_EPOCH_BLOCKS + SEEDHASH_EPOCH_LAG` (≤ 2112 at
defaults `2048 + 64`); the C++ caller then resolves seed_height 0 to
`block_hash(0)`, the genesis block hash. The verifier does not see a
"genesis special case"; it sees a 32-byte seedhash that happens to be
the genesis block hash for the first 2113 blocks.

This means:

- The FFI contract is unchanged. `shekyl_pow_randomx_v2_hash` accepts
  any 32 bytes as seedhash. Early-block correctness is the caller's
  responsibility.
- The optional `seedheight(height) -> u64` helper, if exported in
  Phase 3 (see §5), must reproduce the early-block branch exactly:

  ```rust
  pub fn seedheight(height: u64) -> u64 {
      if height <= SEEDHASH_EPOCH_BLOCKS + SEEDHASH_EPOCH_LAG {
          0
      } else {
          (height - SEEDHASH_EPOCH_LAG - 1) & !(SEEDHASH_EPOCH_BLOCKS - 1)
      }
  }
  ```

  A spec-vector test for `seedheight` is required across the
  boundaries `0`, `SEEDHASH_EPOCH_BLOCKS`,
  `SEEDHASH_EPOCH_BLOCKS + SEEDHASH_EPOCH_LAG`,
  `SEEDHASH_EPOCH_BLOCKS + SEEDHASH_EPOCH_LAG + 1`, and the first two
  epoch transitions after the early-block window closes. Off-by-one
  errors in this function are consensus errors.

- If the C++ caller is deleted in a future migration (call-site moves
  to Rust), the early-block branch above is the only correct mapping.
  The helper is not a "convenience"; it is the protocol rule.

`SEEDHASH_EPOCH_BLOCKS` and `SEEDHASH_EPOCH_LAG` are typed constants in
`shekyl-pow-randomx::consensus`. They are not env-var-overridable per
§9.

## 17. FFI Error-Code Taxonomy

`shekyl_pow_randomx_v2_hash` returns `i32`. Codes are stable across
versions; new codes append, existing codes never re-mean.

```c
#define SHEKYL_POW_RANDOMX_V2_OK                      0
#define SHEKYL_POW_RANDOMX_V2_ERR_NULL_PTR           -1
#define SHEKYL_POW_RANDOMX_V2_ERR_DATA_TOO_LARGE     -2
#define SHEKYL_POW_RANDOMX_V2_ERR_CACHE_DERIVE_FAILED -3
#define SHEKYL_POW_RANDOMX_V2_ERR_INTERNAL           -4
```

Semantics:

- `OK (0)`: `out_hash32` was written; caller must use it.
- `ERR_NULL_PTR (-1)`: any of `seedhash32`, `data` (when `data_len > 0`),
  or `out_hash32` is null. `out_hash32` is **not** written.
- `ERR_DATA_TOO_LARGE (-2)`: `data_len` exceeds the verifier's
  hashing-blob bound. `out_hash32` is **not** written.
- `ERR_CACHE_DERIVE_FAILED (-3)`: cache derivation could not complete
  (allocation failure or panic caught in the FFI shim). `out_hash32` is
  **not** written.
- `ERR_INTERNAL (-4)`: a Rust panic crossed the FFI boundary and was
  caught. `out_hash32` is **not** written. This code is a CI failure
  signal during development; in release it returns the code and logs
  via the standard FFI logging hook.

Failure discipline:

- All failure paths run in time independent of `seedhash32` and `data`
  contents.
- On any non-zero return, `out_hash32` is untouched; callers must not
  use it (in particular, must not treat zeroed memory as the hash).
- No error code maps to "fall back to a different algorithm." There is
  no other algorithm.

The constants are emitted alongside the function prototype in
`src/shekyl/shekyl_ffi.h`. Adding a code is a Phase-3-or-later change
that requires a doc update here.

## 18. Thread-Safety Contract

`shekyl_pow_randomx_v2_hash` is callable concurrently from multiple
threads. The contract is:

- The function is reentrant. Two concurrent calls with disjoint
  `out_hash32` buffers and disjoint `data` buffers must produce the
  same results they would produce serially.
- Concurrent calls must not race on internal caches. The internal
  `CacheStore` in `shekyl-ffi` is `Send + Sync` and synchronizes
  access; a concurrent cache miss for the same seedhash deduplicates
  to a single derivation under lock.
- Callers must not pass overlapping `data` and `out_hash32`. Passing
  the same `out_hash32` from two threads is undefined.
- The function does not block on I/O, does not take Rust async
  futures, and does not call back into C++ during execution.

Consequence for the daemon caller: block-verification threads may call
the function in parallel without external locking. The first call on a
new seedhash pays the derivation cost; subsequent concurrent calls on
the same seedhash wait briefly behind the in-flight derivation and
then proceed.

`shekyl-pow-randomx` itself is trivially `Sync` because it has no
module-level state (§7.2). Thread-safety lives at the `shekyl-ffi`
boundary where the memo lives.

## 19. `block.major_version` After PoW Dispatch Deletion

Deleting `IPowSchema`/`pow_registry` removes `block.major_version`
from the PoW dispatch path, but the field itself stays — it is the
consensus hard-fork version and is used by non-PoW subsystems.

Survey of `block.major_version` consumers as of Phase 0:

- Block-header serialization and difficulty selection.
- Consensus-rule selection in `Blockchain::validate_block` and
  transaction-version checks.
- RPC responses that surface the active hard-fork version.

None of these is a PoW dispatch. The Phase 4 deletion is narrow:

- Delete every read of `block.major_version` that selects between
  CryptoNight, RandomX v1, and RandomX v2 paths.
- Delete every read that gates on `RX_BLOCK_VERSION`.
- Keep every read that participates in hard-fork rule selection.

Phase 3b's deleted-call audit
(`docs/design/RANDOMX_V2_PHASE3B_AUDIT.md`, created in Phase 3b)
records each `block.major_version` reference as either "kept (hard-fork
rule)" or "deleted (PoW dispatch)" with the file and line.

The field is not renamed in this work. A `block.major_version` →
`block.hf_version` rename is a separate scope-limited PR if the
working group wants it.

## 20. License and Attribution

`shekyl-pow-randomx` is licensed BSD-3-Clause, matching the
workspace-wide license decision for Shekyl-authored Rust crates. The
crate-level `//!` doc header records:

- Copyright notice per `92-copyright-header.mdc`.
- A short paragraph naming the RandomX v2 fork the code derives its
  algorithm from and the commit pinned in Phase 1.
- A pointer to `docs/design/RANDOMX_V2_RUST.md` and the v2 spec.

The Rust code is an independent re-implementation, not a translation of
the C source, so it carries Shekyl copyright. The Phase 0 review checks
this section for accuracy against the fork's actual license before any
code lands.

If the v2 fork's license is incompatible with BSD-3-Clause distribution
of a clean-room re-implementation (no copied code, only algorithm),
Phase 0 review flags it and the plan returns to algorithm-review gate
before Phase 2 begins.

## 21. MSRV

`rust/Cargo.toml` currently declares no `rust-version`, and the
repository has no `rust-toolchain.toml`. Before Phase 2 begins, the
workspace pins an MSRV in one of those two locations.

Phase 0 proposal:

- Pin MSRV to the version that lets the symbol-isolation CI grep be
  written against `#[unsafe(no_mangle)]` rather than the older
  `#[no_mangle]` form, so the grep cannot be defeated by renaming the
  attribute syntax.
- Track the workspace edition decision. If the workspace upgrades
  from edition 2021 to edition 2024 before Phase 2,
  `shekyl-pow-randomx` adopts edition 2024 in the same PR so that
  `unsafe(no_mangle)` is enforced rather than merely linted.

The MSRV bump itself is a separate workspace-scoped PR per
`06-branching.mdc`; this design doc does not perform it. The §7.2
invariant grep must cover both `#[no_mangle]` and `#[unsafe(no_mangle)]`
forms until the MSRV bump lands.

## 22. Guix Reproducible-Build Impact

There is no `contrib/guix/` manifest in the repository today, and no
file matching `*guix*` exists in the tree. Reproducible-build via Guix
is not present-day infrastructure; it is forward work.

When Guix infrastructure lands, the v2 work creates these obligations:

- `external/randomx-v2` needs a pinned source hash in the Guix manifest
  alongside its commit pin.
- The `BUILD_RANDOMX_V2_MINER_LIB` flag becomes a reproducible build
  variant — daemon-only builds and miner-bundle builds are separate
  reproducible artifacts.
- `shekyl-pow-randomx` Rust dependencies are vendored or pinned in the
  same manifest, with no network access at build time.

The Guix-integration design doc is the right place to encode this; this
section exists so the v2 plan does not silently break a future Guix
integration. If Guix integration lands during the lifetime of Track A
or Track B, this section is rewritten to point at the actual manifest.

## 23. Reviewer Discipline Under Solo-Architect Reality

This section acknowledges the project's review reality. Shekyl pre-launch
operates with a small core team; the formal "at least one reviewer who
is not the author" rule is aspirational for some rounds and binding for
others.

Discipline applied to this work:

- Phase 0 review rounds may be self-review when an external reviewer
  is unavailable. Self-review rounds use a written, dated review note
  in `docs/design/RANDOMX_V2_REVIEW_LOG.md` and a minimum 24-hour
  sleep-on-it gap between the review note and the resulting edits.
- The algorithm-review gate before Phase 2 is **not** waivable to
  self-review. External cryptographic review of the v2 algorithm is a
  hard precondition for Phase 2 per `00-mission.mdc` commitment #1.
  If no external reviewer is available, the plan falls back to
  `RANDOMX_V1_FALLBACK.md`.
- The differential-test harness gate before Phase 3 requires an
  external reviewer for the test design itself, because a
  self-reviewed differential harness against a self-implemented
  verifier reduces to a self-consistency check.
- Phase 4 (legacy deletion) requires an external reviewer because the
  deletion is irreversible at branch level and touches consensus
  surface.

The review log records which rounds had external reviewers and which
did not, so the audit trail is honest rather than performative.
