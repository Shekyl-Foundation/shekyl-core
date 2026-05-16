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

## 15. `wallet_rpc_payments.cpp` Disposition

`src/wallet/wallet_rpc_payments.cpp` is the one wallet-tree file known
to touch PoW-era hashing. Phase 0 review must decide whether the feature
is still part of Shekyl's roadmap:

- If yes, Phase 4 rewrites it to call the v2 verifier.
- If no, Phase 4 deletes the feature along with the legacy PoW surface.

This is not deferred to implementation; the answer is recorded before
Track B begins.
