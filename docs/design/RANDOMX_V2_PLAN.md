---
name: RandomX v2 Rust port
overview: "Port Shekyl's PoW from Monero's RandomX v1 (C) to RandomX v2 (Rust pure-software verifier + C library compiled only as the miner) via the Shekyl-Foundation fork (non-divergent from upstream tevador/RandomX at pin aaafe71; Monero is the parallel production deployer and v1->v2 delta audit funder per RANDOMX_V2_RUST.md \u00a71.4). No backward compatibility. The C-for-mining / Rust-for-verification split is permanent. Per 18-type-placement.mdc, Cache/Dataset/Hash are transform-shaped (defined by their derivation function); memoization is a transparent function-level memo inside shekyl-ffi, invisible to C++ callers. No prewarm \u2014 lazy derivation on first use is honest about the cost (~150ms hit once per ~2.8 days; above Nielsen's 100ms 'feels instant' threshold by ~50ms but well below the 1s 'continuous flow' threshold, and invisible in practical RPC-round-trip context). Phase 0 produces both the primary design doc and a pre-vetted v1 fallback. Track A (design + submodule + isolated Rust verifier crate) starts now and proceeds in parallel with Monero's audit; Phase 2 is NOT gated on external algorithm review (the algorithm-review gate is release-time, not Phase-2 time, per RANDOMX_V2_RUST.md \u00a71.4). Track B (FFI wiring + legacy deletion) is gated on wallet V3.2 cutover. Phase 3 (cutover, likely split 3a/3b/3c) replaces all C implementation files; Phase 4 deletes the C++ IPowSchema/pow_registry and the entire shekyl-consensus crate to remove speculative-scaffolding rule violations on both sides. Release gate \u2014 Monero deployment-experience window plus completed delta audit without contraindicating findings; v1 unpin-and-revert (default 102f8acf) is the late-binding fallback."
todos:
  - id: phase0-design
    content: "Track A / Phase 0: Write docs/design/RANDOMX_V2_RUST.md AND docs/design/RANDOMX_V1_FALLBACK.md. Cover: (a) permanent C-JIT-for-mining / Rust-interpreter-for-verification split; (b) derived-first design per 18-type-placement.mdc; (c) memoization inside shekyl-ffi only (no prewarm; lazy derivation with documented perception-threshold rationale); (d) 1-function FFI surface (hash), with seedheight as discretionary Phase 3 addition; (e) v2 algorithm review prerequisites and spec-as-source-of-truth doctrine; (f) interpreter performance target (≤3.0× C light-VM-JIT) + concrete initial-sync wall-time delta (~4 hours per current math) for review ratification; (g) structural isolation invariants with specific v2 C library export symbol list AND companion 'shekyl-pow-randomx never uses #[no_mangle]' invariant; (h) consensus constants become typed const, env-var overrides deleted entirely; (i) Grover-bound argument for PoW surviving lattice transition; (j) v1 fallback (depth calibrated to algorithm-review confidence; honest framing, not theater); (k) cncrypto PUBLIC link survey results; (l) what irreducibly stays state and where. Pass 4-6 review rounds before any code lands."
    status: pending
  - id: phase1-submodule
    content: "Track A / Phase 1: Add external/randomx-v2 submodule pointing at Shekyl-Foundation/RandomX v2 fork at a pinned commit (added alongside, not as a rename of, external/randomx; v1 retirement is Phase 5); add BUILD_RANDOMX_V2_MINER_LIB CMake option (default OFF; will flip to ON for miner consumers in Phase 3) and ExternalProject_Add wiring producing the shekyl_randomx_v2 IMPORTED static-library target out-of-tree under ${CMAKE_BINARY_DIR}/external/randomx-v2-build/; no Shekyl C++ consumer links the target in Phase 1 (first consumer is Phase 2 cross-check tests in rust/shekyl-pow-randomx/). Detailed plan at docs/design/RANDOMX_V2_PHASE1_PLAN.md; target-collision disposition at §2 (ExternalProject_Add not add_subdirectory; v1 and v2 both declare project(RandomX) + add_library(randomx ...) so the global-target-name pool would collide). Proceeds in parallel with v2 algorithm review (release-time gate per §1.4)."
    status: completed
  - id: algorithm-review-gate
    content: "Track A release-time gate (NOT a Phase 2 blocker): the Monero-funded v1->v2 delta audit completes without contraindicating findings AND Monero's parallel production deployment has had meaningful observation-window exposure. Per RANDOMX_V2_RUST.md §1.4, Phase 2 implementation proceeds in parallel — the verifier is faithful spec implementation, not an algorithm-soundness decision, and Shekyl inherits Monero's audit byte-for-byte via the non-divergent fork pin (§1.1). If the audit surfaces a blocker before Shekyl's release, unpin to pre-PR-#317 (default 102f8acf, already in external/randomx) and ship v1 per RANDOMX_V1_FALLBACK.md §1's late-binding trigger criteria."
    status: pending
  - id: phase2a-argon2d
    content: "Track A / Phase 2a: Add rust/shekyl-pow-randomx crate scaffold to rust/Cargo.toml; implement Argon2d primitive used by Cache::derive; vector parity against spec test vectors."
    status: completed
  - id: phase2b-aes-sshash
    content: "Track A / Phase 2b: Implement AES round + SuperScalarHash primitives from the v2 spec; spec-vector parity tests."
    status: completed
  - id: phase2c-vm-and-cache
    content: "Track A / Phase 2c: Implement Cache (with `pub fn derive(seedhash)` constructor + `pub(crate)` `from_raw` / `derive_item(item_number)` / `item_bytes` accessors; 256 MB cache memory + 8 SuperscalarHash programs) AND `pub fn compute_hash(&Cache, &[u8; 32], &[u8]) -> [u8; 32]` public transform (with `VmState` as a `pub(crate)` private struct internal to vm.rs; scratchpad allocated via Box::new_zeroed_slice or Vec::into_boxed_slice to avoid stack overflow on the 2 MB buffer; execution loop calls a private `fn dispatch_instruction(&Instruction, &mut VmState)` whose body is a Phase 2c NOP stub and is replaced in place by Phase 2d with real table-driven per-opcode dispatch — no trait, no impl swap, no signature change to compute_hash). Structural-parity spec vectors (T1–T8 per docs/design/RANDOMX_V2_PHASE2C_PLAN.md §6): cache derivation, dataset-item derivation, scratchpad init, register init, program parse, spAddr derivation, F/E AES mix, end-to-end stub-NOP hash. Cache-derivation latency benchmark (≤200 ms per Phase 0 budget) + per-call compute_hash allocation benchmark (≤100 µs per Phase 0 budget; budget binds the VmState allocation portion under stub-NOP dispatch); BENCH_RESULTS.md baseline artifact committed at PR-merge. Phase 2c absorbs Cache::derive from the originally-scoped Phase 2e (see RANDOMX_V2_PHASE2C_PLAN.md §5 F4 for absorption rationale); 2e is removed from the sub-PR sequence. Round 2 substrate-finding pass collapsed the public surface to compute_hash (with VmState private) and the dispatch shape to a free function with body replacement (per docs/design/RANDOMX_V2_PHASE2C_PLAN.md §14 Round 2 entry)."
    status: pending
  - id: phase2d-bytecode-v2
    content: "Track A / Phase 2d: Implement RandomX v2 bytecode opcode set (delta from v1) as table-driven dispatch from the v2 spec, landed as a body replacement of Phase 2c's private `dispatch_instruction` free function (no trait wiring, no impl swap, no signature change to compute_hash — per docs/design/RANDOMX_V2_PHASE2C_PLAN.md §5 F1 R2-D1); FPU rounding-mode plumbing for fprc register (deferred from 2c per F2c — 2c uses host-default rounding mode under stub-NOP dispatch; 2d adds the rounding-mode setter alongside CFROUND); byte-equality tests against spec vectors with end-to-end real-hash parity. F128 newtype extraction decision (if needed) lands here per F3a deferral."
    status: pending
  - id: phase2f-store-and-invariants
    content: "Track A / Phase 2f: Implement CacheStore utility type (LruCache<Seedhash, Arc<Cache>> behind a Mutex; default capacity 2). The crate exports it as a generic helper for any Rust caller; shekyl-pow-randomx instantiates none. PR includes TWO crate-level invariant tests on shekyl-pow-randomx: (1) no module-level static/OnceCell/lazy_static other than const data; (2) no #[no_mangle] or extern \"C\" exports. Both CI-enforced via grep on the crate source tree. Benchmark per-call VmState allocation cost inside compute_hash (extending the Phase 2c BENCH_RESULTS.md baseline); if it dominates per-hash time, internalize a VmState pool inside compute_hash (private to vm.rs, invisible to consumers — same shape as Phase 2c R2-D1's dispatch-function-body-replacement discipline; no public VmPool type). Per Decision #7 (Round 2 substrate-shift form): per-call allocation is the default; pooling, if needed, is internal to compute_hash."
    status: pending
  - id: phase2g-differential-harness
    content: "Track A / Phase 2g: Create a separate test-only artifact (NOT a dev-dependency of shekyl-pow-randomx) that links both the Rust verifier and the v2 fork's C reference and asserts byte equality across a corpus of (seedhash, data) inputs. Concurrent-call test verifies CacheStore thread-safety. C-side state-machine scenarios (epoch transition, secondary cache, async rebuild) are explicitly out of scope. CI job runs the harness; failure fails CI."
    status: pending
  - id: trackb-gate-check
    content: "Track B gate: confirm wallet V3.2 (wallet_rpc_server Rust cutover) has landed on dev per docs/FOLLOWUPS.md; verify rust/shekyl-ffi/src/lib.rs and src/shekyl/shekyl_ffi.h are in a quiet 1-2 week window before starting Phase 3."
    status: pending
  - id: phase3-cutover
    content: "Track B / Phase 3 (likely split 3a/3b/3c per 06-branching.mdc size limits): Export the 1-2 function FFI surface from rust/shekyl-ffi (with shekyl-ffi holding the internal CacheStore as a transparent memo); add matching declarations in src/shekyl/shekyl_ffi.h; rewire all 6 C++ callers; ship a versioned docs/design/RANDOMX_V2_PHASE_3B_DELETED_CALL_AUDIT.md naming each deleted lifecycle call (rx_set_main_seedhash, rx_set_miner_thread, rx_get_miner_thread, rx_slow_hash_allocate_state, rx_slow_hash_free_state) with original intent and new-flow disposition; delete src/crypto/rx-slow-hash.c AND src/crypto/pow_cryptonight.cpp AND src/crypto/slow-hash.c together (tangled implementation); drop randomx C linkage from cncrypto per Phase 0 PUBLIC-link survey; add CI symbol-isolation invariant against the specific v2 C library export list; add per-PR CI per-hash benchmark (N=1024 hashes, ≤3.0× ratio); add 600k-block initial-sync wall-time test to release-gate suite. Phase 3a's build flag exists only between 3a-merge and 3b-merge (days), not across releases."
    status: pending
  - id: phase4-delete-abstractions
    content: "Track B / Phase 4: Pure abstraction cleanup (no implementation files left to delete; Phase 3 handled those). Delete pow_schema.h (IPowSchema), pow_registry.{h,cpp}, the RX_BLOCK_VERSION constant, and any major_version branching in PoW selection (the switch itself, not just its branches); delete the entire rust/shekyl-consensus crate per 70-modular-consensus.mdc, folding BlockHeader/ChainState/Difficulty/ConsensusError into shekyl-pow-randomx, deleting ConsensusProof trait + ConsensusRegistry, removing the CONSENSUS_REGISTRY static and shekyl_rust_init consensus registration from shekyl-ffi; resolve wallet_rpc_payments.cpp PoW touchpoint per Phase 0 decision; update unit tests."
    status: pending
  - id: phase5-docs
    content: "Track B / Phase 5: Update USER_GUIDE, SHEKYLD_PREREQUISITES, DOCUMENTATION_TODOS_AND_PQC, DESIGN_CONCEPTS, CHANGELOG, FOLLOWUPS per 91-documentation-after-plans.mdc. Close any RandomX v2 follow-ups this plan introduces along the way. This plan is primarily fresh debt clearance — IPowSchema/pow_registry, shekyl-consensus, RPC payments, and the rx-slow-hash.c stateful core were not previously tracked in FOLLOWUPS — so Phase 5 is mostly forward-looking close-records and any forward obligations the plan creates (notably the §22 Guix forward-looking entry), not closure of a pre-existing queue."
    status: pending
isProject: false
---


# RandomX v2 Rust port (Track A / Track B)

## Sequencing rationale

Three independent gates govern when phases land.

**Wallet-migration gate (Track B).** The wallet migration is actively churning `rust/shekyl-ffi/src/lib.rs`, [src/shekyl/shekyl_ffi.h](../../src/shekyl/shekyl_ffi.h), `rust/Cargo.toml` and [rust/Cargo.lock](../../rust/Cargo.lock) (43 lockfile commits in 30 days). The wallet does not compute PoW. Conceptually orthogonal; the contention is FFI/Cargo.lock plumbing and reviewer bandwidth.

**Algorithm-review gate (release-time, not intra-track).** Per `RANDOMX_V2_RUST.md` §1.4, the v2 algorithm-review gate is **release-time**, not before Phase 2. Phase 2 is faithful spec implementation against a stable spec — not an algorithm-soundness decision — so gating it on external review would either delay or duplicate effort. Monero is the parallel v2 deployer and v1→v2 delta audit funder, and the Shekyl-Foundation fork is non-divergent from upstream (§1.1), so Monero's audit covers Shekyl's pinned code byte-for-byte without coordination. Implementation work (Phases 1-4) proceeds in parallel; the gate fires before genesis release (§1.4: Monero production-deployment observation window plus completed delta audit without contraindicating findings). If the gate fails, the fork pin is bumped to a pre-PR-#317 commit (default `102f8acf`, already in `external/randomx`) and v1 ships per `RANDOMX_V1_FALLBACK.md` §1's late-binding triggers.

**Performance-target gate (Track A intra-track).** Phase 2 benchmarks must hit Phase 0 budgets before Phase 3 starts. The C library's light-VM-JIT path is what daemons use today; the Rust pure-software interpreter will be ~2-3× slower per hash. Per-hash slowdown dominates initial-sync wall-time delta (~4 hours over 600k blocks at 3× ratio); cache-derivation overhead is noise (~44s).

```mermaid
flowchart LR
  subgraph TrackA [Track A - parallel with Monero audit]
    P0[Phase 0: Two design docs<br/>RANDOMX_V2_RUST.md<br/>RANDOMX_V1_FALLBACK.md]
    P1[Phase 1: external/randomx-v2 submodule<br/>+ BUILD_RANDOMX_V2_MINER_LIB gate]
    P2[Phase 2: shekyl-pow-randomx<br/>transform-shaped Cache/Vm/Hash<br/>CacheStore utility type<br/>two crate-level invariants<br/>sub-PRs 2a-2g]
    PG{Perf targets met?}
  end
  subgraph TrackB [Track B - gated on wallet V3.2]
    P3[Phase 3 (likely 3a/3b/3c)<br/>Wire 1-2 fn FFI surface<br/>rewire C++ callers<br/>delete lifecycle calls<br/>delete C implementation files<br/>CI invariants]
    P4[Phase 4: Delete abstractions<br/>IPowSchema/pow_registry<br/>shekyl-consensus crate<br/>version-gate switch]
    P5[Phase 5: Docs + CHANGELOG]
  end
  subgraph Release [Release gate - external dependencies]
    MonAudit[Monero-funded v1->v2 delta audit:<br/>completed, no contraindicating findings]
    MonDeploy[Monero v2 production deployment:<br/>observation window elapsed]
    AR{Release gate satisfied?}
    FB[Unpin to 102f8acf<br/>ship v1 per RANDOMX_V1_FALLBACK.md]
    REL[Genesis release]
  end
  P0 --> P1 --> P2 --> PG
  PG -- no --> P2
  WG{Wallet V3.2 landed on dev?}
  PG -- yes --> WG
  WG -- yes --> P3 --> P4 --> P5 --> AR
  MonAudit --> AR
  MonDeploy --> AR
  AR -- yes --> REL
  AR -- no --> FB
```

Note that `MonAudit` and `MonDeploy` are external to Shekyl's control;
they run in parallel with the entire Phase 0→Phase 5 sequence.
Shekyl's implementation work never blocks waiting for them.

## Permanent architectural decisions

These decisions are made now and locked. Any future proposal to reverse them must start with a new design doc that addresses the rationale below.

### 1. C JIT for mining, Rust interpreter for verification — permanent

The `20-rust-vs-cpp-policy.mdc` "Rust by default" pressure exists to put Rust on consensus paths and untrusted-input parsing. A RandomX JIT for mining is neither: it's a code generator that the daemon's verification path does not touch and that consumes only data the miner produced.

Any JIT is structurally an `unsafe` operation: W^X pages, raw instruction-byte emission, `mprotect` transitions, trust in the encoder. The fork's C JIT has years of production exposure; reimplementing it in Rust trades that hardening for a fresh codegen surface, which is the wrong direction for `00-mission.mdc` commitment #1.

Cranelift is the wrong tool: RandomX's ASIC resistance depends on the *specific instruction mix* the bytecode dispatch produces.

Ecosystem argument: xmrig, SRBMiner, and every stratum pool consume the C ABI. A Rust-port either ships a C-ABI-wrapped Rust JIT (no gain) or diverges from the ecosystem and forces every miner to integrate a Rust crate (hostile to decentralization).

Concrete data point: the MSVC PDB type-server ICE from `CryptonightR_JIT.c` is evidence that a heavy C JIT in the daemon build path causes real cross-platform pain. The hybrid model isolates that pain to a separate artifact that MSVC and Guix reproducible-build pipelines can skip entirely.

**Verifiers don't need JITs.** Verification is one-shot per block at the cache mode that daemons actually use. There is no FOLLOWUPS entry to "Rust-port the JIT later" — the split is the answer, permanently.

### 2. `external/randomx-v2` is a rename, not a reuse of `external/randomx`

The v2 fork is added as a new submodule at `external/randomx-v2`. Makes the discontinuity visible, prevents accidental upstream-tracking updates, signals Shekyl-controlled fork. `external/randomx` is removed only when Phase 3 deletes its last consumer.

### 3. Spec is the source of truth, C reference is the cross-check

The Rust verifier is implemented from the v2 specification document. The v2 fork's C implementation is treated as a cross-check, not as the source of truth. If they disagree, the spec wins and a bug is filed against the C fork.

### 4. Cache, Dataset, and Hash are transform-shaped per `18-type-placement.mdc`

The rule: *"Transform-shaped types. Defined by a function. The canonical definition is the function; storage of the value is a memo of the function's output. Anyone with the function's inputs can recompute the value."*

A RandomX cache fits exactly: `Cache::derive(seedhash) -> Cache` is a pure function (~10-100ms, ~256 MB output). Same for `Dataset::derive(cache) -> Dataset` (~30s, ~2 GiB, miner-only) and `compute_hash(cache, data) -> Hash` (~10-30ms per hash).

The C code's process-global cache + thread-local VMs + async epoch-transition state machine is a *miner-side performance optimization* inherited from Monero. Per `16-architectural-inheritance.mdc`, "inheriting code is not inheriting architecture" — carrying the miner-shape state into a verifier-only Rust implementation is the inheritance anti-pattern the rule names.

Types are defined by their derivation functions:

```rust
pub struct Cache(Box<[u8; CACHE_SIZE]>);
impl Cache {
    /// Pure derivation. The canonical definition of a Cache.
    pub fn derive(seedhash: &Seedhash) -> Self { /* ~10-100ms */ }
}

/// Pure derivation. No memoization, no internal state.
/// VmState is a `pub(crate)` implementation detail of vm.rs — never
/// exposed at the public crate surface. Pooling, if needed, is
/// internal to compute_hash per Decision #7's Round 2 substrate-shift
/// form.
pub fn compute_hash(cache: &Cache, seedhash: &Seedhash, data: &[u8]) -> Hash {
    let mut state = VmState::new();           // private to vm.rs
    state.initialize(seedhash, data, cache);  // private to vm.rs
    state.run(cache);                          // private to vm.rs
    state.finalize()                           // private to vm.rs
}
```

### 5. Memoization is transparent inside `shekyl-ffi`, not exposed to C++

The daemon's hash-call shape is identical to today: `hash(seedhash, data) -> hash`. Caching of derived `Cache` values across calls is a function-level memo internal to `shekyl-ffi`. The load-bearing argument: `shekyl-ffi` *is* the C-ABI boundary, and module-level state at the C-ABI boundary is structurally unavoidable — C has no other way to hold cross-call state than process-globals, and FFI tracks C's reality. Other Rust crates (`shekyl-pow-randomx` included) are not at this boundary and do not get the same allowance.

The verifier crate `shekyl-pow-randomx` exports `CacheStore` as a generic utility type (`LruCache<Seedhash, Arc<Cache>>` wrapper). It **instantiates no module-level instance** — `shekyl-ffi` constructs one as part of its FFI bridge's lifecycle, hidden from C++ callers.

The two-crate split keeps the "no hidden state" property where it matters (the verifier crate that other Rust callers depend on) while permitting the necessary state at the FFI boundary.

### 6. No prewarm, no async cache rebuild — lazy derivation is the design

The C library moves cache derivation off the hot path via a background thread triggered by an explicit `rx_set_main_seedhash` call. That's a state machine. The Rust verifier doesn't have one.

The cost analysis:

- Per cache miss: ~150 ms one-time latency.
- Frequency on the verifier path: one per `SEEDHASH_EPOCH_BLOCKS` (2048) blocks = one per ~2.84 days at 120s block time.
- Perceptibility framing: ~150 ms exceeds Nielsen's 100 ms "feels instant" threshold by ~50 ms but sits an order of magnitude below the 1 s "continuous flow" / "stay focused" threshold. For a one-off event on the verifier path (not in any user-input feedback loop), 150 ms is invisible in practical RPC-call contexts where network round-trip already adds tens to hundreds of ms.
- Block propagation impact: 150 ms / 2048 blocks = 0.073 ms average. Below the variance floor of normal network propagation (~500 ms - 1 s).
- Initial sync impact: ~293 transitions × 150 ms ≈ 44 s of derivation overhead across a 600k-block sync. The canonical per-hash figures from `RANDOMX_V2_RUST.md` §8 are: C light-VM-JIT baseline ~12 ms/hash × 600,000 ≈ 2 hours of baseline PoW verification work; Rust target ceiling at 3.0× ratio (36 ms/hash) × 600,000 ≈ 6 hours of Rust-side PoW verification work; the **delta** is ~4 hours of additional verification time (the figure §8 ratifies for review). Against the Rust-side total of ~6 hours, the 44 s cache-derivation overhead is < 0.25% of total — noise relative to either baseline or Rust-target wall time.

What we trade away:

- Async-state-machine complexity. The C library's reader/writer locks + background-thread lifecycle were correct but not free. They cost test surface, cost reviewer attention, and embodied exactly the inherited-state pattern `16-architectural-inheritance.mdc` warns against.
- A `prewarm` FFI export that would need daemon-side scheduling logic ("a few blocks before transition," "not during a reorg," "wait for completion before validating," etc.). Non-trivial C++ logic we don't have to write.

No escape hatch is provided. With a capacity-2 LRU, any "fake prewarm" pattern (call `hash(upcoming_seedhash, dummy_data)`, discard the result, hope the cache stays warm) is unreliable: if any other seedhash is hashed in the interval before the real use, the warmed cache gets evicted. If a future caller genuinely needs prewarm semantics, the disposition is to propose a new design doc that revisits Decision #6, not to pretend the current API can simulate one.

**Phase 0 includes a "Why no prewarm" section** so future contributors who propose adding it back find the recorded reasoning instead of having to re-litigate it.

### 7. Per-call `VmState` allocation inside `compute_hash` is the default; pooling, if needed, is internal to `compute_hash`

Per-hash VM state (the 2 MB scratchpad plus the register file) is a `VmState` value created inside `compute_hash` for each invocation and dropped at return. Per-call construction is ~µs with thread-local arena allocators. If Phase 2f benchmarks show allocation cost dominates per-hash time on the verifier path, the disposition is to **internalize a `VmState` pool inside `compute_hash`** (private to `vm.rs`, invisible to consumers) rather than expose a public `VmPool` type. This matches the dispatch-function-body-replacement discipline established in `docs/design/RANDOMX_V2_PHASE2C_PLAN.md` §5 F1 R2-D1: implementation-detail optimizations stay inside the transform function; the public API stays minimal.

Decision-shape note: the substance of this decision is unchanged from its pre-Round-2 form (per-call allocation is the default; pool only if needed). The implementation shape (internal pool inside `compute_hash` vs. public `VmPool` type) tracks the Round 2 substrate shift to `compute_hash`-as-public-transform per `21-reversion-clause-discipline.mdc`'s reopening-criterion shape — when the substrate (which surface is public) changes, the disposition tracking that substrate re-anchors without changing the decision itself. No thread-local globals in either form.

### 8. What irreducibly stays state, and where

Three things cannot be derived and must be remembered. Each lives in its semantic owner per `18-type-placement.mdc`:

- **`shekyl-ffi`'s internal `CacheStore` entries.** Function-level memo state. Lives in `shekyl-ffi`. Hidden from C++.
- **The chain's current `Seedhash` at any height.** State-shaped (chain progression). Computed as `block_hash(seed_block(height))`. Lives in the chain-state-owning crate (`shekyl-engine-state`).
- **`SEEDHASH_EPOCH_BLOCKS` / `SEEDHASH_EPOCH_LAG`.** Protocol constants, typed `const` in `shekyl-pow-randomx`. Not runtime-configurable; operator overrides of consensus-critical constants are a Monero-era anti-pattern per `60-no-monero-legacy.mdc`.

Everything else (caches, datasets, VMs, hashes) is transform-shaped and derived on demand.

## Track A — Phase 0 (start now)

Two design documents, **both** required before Phase 1.

### `docs/design/RANDOMX_V2_RUST.md`

1. **Why Shekyl-Foundation RandomX v2 fork.** Cite `RANDOMX_FLAG_V2` and `doc/design_v2.md` from the fork. Document the delta from v1.

2. **Hybrid architecture and the C/Rust split.** Cite Decision #1. No FOLLOWUP entry for porting the JIT to Rust later.

3. **v2 algorithm review status and release-gate framing.** Records (a) the algorithm-review situation — **Monero is funding the v1→v2 delta audit** and is the other production deployer of upstream RandomX v2 (PR #317); the Shekyl-Foundation fork is non-divergent (`RANDOMX_V2_RUST.md` §1.1) so the audit's scope covers Shekyl's pinned code byte-for-byte; and (b) the **release-time** (not Phase-2-time) framing of the algorithm-review gate. Phase 2 is faithful spec implementation against a stable spec, not an algorithm-soundness decision; gating Phase 2 on external review would either delay implementation behind work Shekyl does not control or duplicate Monero's audit for no security gain. Per `RANDOMX_V2_RUST.md` §1.4 the gate fires before genesis release (Monero deployment-experience window plus completed audit without contraindicating findings). Reference `RANDOMX_V1_FALLBACK.md` for the late-binding unpin-and-revert fallback if the release-time gate fails.

4. **Spec-as-source-of-truth doctrine.** Rust verifier implemented from spec; C reference is cross-check; spec wins on disagreement.

5. **FFI surface scope (1 function, plus 1 discretionary).** Decisions #4, #5, #6:
   - **Committed:** `shekyl_pow_randomx_v2_hash(seedhash[32], data, len, out[32]) -> i32`. The pure derivation. Caller passes seedhash + data; receives hash. Internal `shekyl-ffi` `CacheStore` memoizes derived caches across calls, transparently.
   - **Discretionary (Phase 3 may add):** `shekyl_pow_randomx_v2_seedheight(height: u64, out_seedheight: *mut u64) -> i32` — pure function with the same out-parameter-plus-`i32`-error-code shape as the hash export. Returns `OK (0)` on success with the computed seed height written through `out_seedheight`, or `ERR_NULL_PTR (-1)` if `out_seedheight` is null. The shape matches `40-ffi-discipline.mdc`'s "all exports return `i32` error codes" rule. Added only if the Phase 3 survey of C++ callers identifies sites that genuinely cannot be rewritten in Rust. If the survey finds none, the FFI surface is one function.
   - **Explicitly not exported, with rationale documented:** `set_main_seedhash`, `set_miner_thread`, `get_miner_thread`, `allocate_state`, `free_state`, **and `prewarm`**. The first five manage state that doesn't exist in the derived-first design. `prewarm` is excluded per Decision #6.
   - All exports return `i32` error codes per `40-ffi-discipline.mdc`; values computed by the export reach the caller via out-parameters.

6. **Performance targets** (concrete numbers, not "set in review"):
   - **Per-hash latency:** Rust interpreter / C light-VM-JIT ≤ 3.0× on the cache mode daemons actually run in. Benchmarked in Phase 2g (consumes the differential harness binary that 2g produces); CI-enforced in Phase 3.
   - **Cache derivation latency:** ≤ 200 ms (C reference is ~10-100 ms; slack for pure-Rust). Benchmarked in Phase 2c (which absorbs `Cache::derive` from the originally-scoped Phase 2e per `RANDOMX_V2_PHASE2C_PLAN.md` §5 F4).
   - **Per-call `VmState` allocation inside `compute_hash`:** ≤ 100 µs (jemalloc/mimalloc thread-local arena typical). If exceeded, internalize a `VmState` pool inside `compute_hash` per Decision #7 (no public `VmPool` type).
   - **First-hash-after-epoch-transition latency hit:** ≤ 200 ms (~once per 2.84 days). Sits between Nielsen's 100 ms ("feels instant") and 1 s ("continuous flow") thresholds; in practical RPC-round-trip context where network already adds tens-to-hundreds of ms, the hit is invisible. **Accepted as design choice per Decision #6, not budgeted.**
   - **Initial-sync wall-time delta:** at 3.0× per-hash ratio over 600k blocks at ~12 ms C baseline, the delta is **~4 hours of additional PoW verification time**. Cache derivation overhead (~44 s across ~293 epoch transitions) is < 0.25% of the per-hash cost and treated as noise. Phase 0 review ratifies whether 4 hours additional PoW work in initial sync is acceptable. If not, the per-hash target tightens (e.g., to 1.5×, which requires platform-specific Rust tuning and re-scopes Phase 2 accordingly).
   - **CI enforcement mechanism for the per-hash target** (per-PR): synthetic benchmark of N = 1024 hashes against a fixed seedhash + fixed inputs, asserting the median Rust-interpreter latency is ≤ 3.0× the corresponding C-reference median on the same hardware. <30s of CI wall time, deterministic, and validates the load-bearing ratio that drives the 4-hour figure. The full 600k-block sync is a release-gate test (run before each release tag, not per-PR), so a single PR can't smuggle in a regression that the synthetic benchmark catches.

7. **Structural isolation invariants** (CI-enforced, two of them):
   - **Symbol-isolation invariant.** Daemon binaries built with `BUILD_RANDOMX_V2_MINER_LIB=OFF` contain zero symbols from the v2 C library's export list: `randomx_alloc_cache`, `randomx_alloc_dataset`, `randomx_create_vm`, `randomx_init_cache`, `randomx_init_dataset`, `randomx_destroy_vm`, `randomx_vm_set_cache`, `randomx_calculate_hash`, `randomx_dataset_item_count`, `randomx_get_flags`. CI runs `nm shekyld | rg -q '^.* (T|U) (randomx_alloc_cache|...)'` and fails on match.
   - **Companion invariant: `shekyl-pow-randomx` never uses `#[no_mangle]` or `extern "C"`.** All C-ABI exports live in `shekyl-ffi` with the `shekyl_pow_randomx_v2_*` prefix. Without this, a future contributor adding a Rust function named `randomx_calculate_hash` for "test parity" reasons silently weakens the symbol-isolation grep. CI greps the crate source for `#[no_mangle]` and `extern "C"`; presence of either fails CI.
   - Differential test harness (Phase 2g) is a separate artifact, not a dev-dependency of `shekyl-pow-randomx`.

8. **Environment-configuration disposition.** Per Decision #8 and `93-legacy-symbol-migration.mdc`:
   - `MONERO_RANDOMX_UMASK` → explicit parameter on `compute_hash` (or an args struct passed to it) — caller's choice, not an env var. (Pre-Round-2 framing surfaced this as a `Vm::new` constructor parameter; post-Round-2, `Vm`/`VmState` is internal and the parameter rides on `compute_hash`'s signature.)
   - `MONERO_RANDOMX_FULL_MEM` → only relevant if daemon constructs a `Dataset` (very rare). Becomes an explicit call site decision. Not an env var.
   - `SEEDHASH_EPOCH_LAG`, `SEEDHASH_EPOCH_BLOCKS` → typed `const` in `shekyl-pow-randomx`. Env-var overrides removed entirely.
   - Net: zero `MONERO_*` carried forward, zero new `SHEKYL_*` env vars introduced, consensus constants are typed instead of runtime-tunable.

9. **Grover-bound argument for the lattice transition.** Grover gives a square-root speedup against unstructured preimage search — for 256-bit output the idealized work drops from ~2²⁵⁶ to ~2¹²⁸, i.e., the search-effort exponent halves. For 256-bit output and difficulty target T ≪ 2²⁵⁶, the classical bound on finding a hash below T is still ahead of Grover. Cite the specific calculation; audit reviewers will ask. (Mirrors `RANDOMX_V2_RUST.md` §10's framing; the canonical statement lives there.)

10. **`cncrypto` PUBLIC link survey.** [src/crypto/CMakeLists.txt](../../src/crypto/CMakeLists.txt) links `randomx` PUBLIC into `cncrypto`. Phase 0 surveys cncrypto's transitive consumers and documents which subsystems silently depend on `randomx` through the PUBLIC link. Phase 3 cannot drop the link until those consumers are resolved.

11. **What stays state, named explicitly.** Per Decision #8: `shekyl-ffi`'s internal `CacheStore` entries, chain's current `Seedhash`, protocol constants. Auditors can grep this section against the crate's public surface to confirm no hidden state in `shekyl-pow-randomx`.

12. **Why no prewarm.** Per Decision #6, with the full reasoning: 150 ms per ~2.84 days is below human perception threshold; 44 s of derivation overhead during initial sync is < 0.25% of total PoW work; the async-state-machine alternative was inherited Monero shape that violates `16-architectural-inheritance.mdc`. Documented here so future contributors find the recorded reasoning before proposing prewarm.

13. **Explicit non-goals** (per `60-no-monero-legacy.mdc`): no v1 compatibility, no CryptoNight fallback, no `RX_BLOCK_VERSION` gate, no version-dispatch switch in PoW selection, no env-var overrides of consensus constants, no prewarm.

14. **Wallet V3.2 dependency** for Track B start.

15. **`wallet_rpc_payments.cpp` disposition — resolved to delete.** Phase 0 decision recorded in `RANDOMX_V2_RUST.md` §15: delete the RPC-payments feature in its entirety. The earlier "rewrite or delete" framing is closed; Phase 4 inherits the deletion checklist in §15.4 and does not re-litigate. This list item exists so the plan's Phase 0 contents include the resolved disposition rather than reopening the question.

### `docs/design/RANDOMX_V1_FALLBACK.md`

Real insurance, not theater. The cost is 4-6 review rounds on a doc we hope never to invoke; the expected value is justified by the asymmetric cost of crisis-replanning if v2 review fails. **Depth calibrated to Phase 0 §3's algorithm-review confidence assessment:** if confidence is very high (multiple independent reviewers, deployment elsewhere, etc.), this doc is a placeholder with trigger criteria and a high-level recovery sketch; if confidence is low, it gets the full 4-6 round treatment.

Sections required regardless of depth:

1. **Trigger criteria.** What findings from v2 algorithm review invoke this doc?
2. **What "ship v1" means for the rest of the plan.** Phase 1 changes (pin v1 fork); Phase 2 changes (v1 bytecode; transform-shaped design unchanged); Track B unchanged in shape, smaller in delta.
3. **v1's track record.** Trail of Bits review, Monero mainnet exposure, threat-model fit.
4. **What we lose by reverting to v1.** What v2 was supposed to fix that v1 doesn't.
5. **Re-evaluation trigger.** Under what conditions does Shekyl revisit v2 (or v3) post-launch?

Pass review rounds calibrated to confidence assessment. Markdown only — zero merge surface against wallet work.

## Track A — Phase 1 (parallel with Monero audit)

**Status.** Landed on `dev` as PR #54 (merge commit `c0c4a11e5`, 2026-05-19); detailed plan and reviewer-map are in [`docs/design/RANDOMX_V2_PHASE1_PLAN.md`](./RANDOMX_V2_PHASE1_PLAN.md). The merge was a non-fast-forward merge commit per `06-branching.mdc` rule 1 (`dev → main` is the only release path, but `feat/* → dev` follows the same merge-commit convention here for visible release-boundary topology). Phase 1 landed in 5 commits (3 implementation-close + 2 Copilot-fix layers) on the `feat/randomx-v2-phase1` short-lived branch (cut 2026-05-18, merged 2026-05-19; under the ≤5-working-day window from `06-branching.mdc` rule 2).

- Add [external/randomx-v2](../../external/randomx-v2) as a new submodule pointing at Shekyl-Foundation/RandomX v2 fork at a pinned commit (`aaafe71`, v2.0.1; identical to `tevador:master` per RANDOMX_V2_PHASE1_PLAN.md §1.3). Do not repoint `external/randomx`; the two coexist until Phase 3.
- Add `BUILD_RANDOMX_V2_MINER_LIB` CMake option (default `OFF`; will flip to `ON` for miner consumers in Phase 3). Default-OFF means daemon builds are byte-identical to a no-flag build per the byte-equivalence test in RANDOMX_V2_PHASE1_PLAN.md §4.1.
- Add the `ExternalProject_Add` block in `external/CMakeLists.txt` that, when the option is `ON`, builds the v2 fork out-of-tree under `${CMAKE_BINARY_DIR}/external/randomx-v2-build/` and exposes a Shekyl-side `IMPORTED` static-library target `shekyl_randomx_v2`. No Shekyl C++ consumer links the target in Phase 1; first consumer is Phase 2 cross-check tests. Target-collision disposition (v1 and v2 both declare `project(RandomX)` and `add_library(randomx ...)`) at RANDOMX_V2_PHASE1_PLAN.md §2.
- One PR, scoped to submodule add + CMake option + `ExternalProject_Add` wiring. Diff envelope ≤250 lines, ≤5 commits, per the plan's §"Scope envelope."

Reversibility: if the release-time algorithm-review gate fails (Monero's audit or production deployment surfaces a blocker before Shekyl's release), Phase 1 is **not** reverted — the fallback per `RANDOMX_V1_FALLBACK.md` §1 keeps the submodule infrastructure in place and bumps the fork pin to a pre-PR-#317 commit (default `102f8acf`, already reachable in the existing `external/randomx` history). If Phase 1 needs to be undone for a different reason (e.g., the fork URL changes), removing the submodule and CMake option is mechanical (RANDOMX_V2_PHASE1_PLAN.md §5).

## Release-time algorithm-review gate (runs in parallel with all implementation phases)

Per `RANDOMX_V2_RUST.md` §1.4 the v2 algorithm-review gate is **release-time**, not before Phase 2. It fires before genesis release with two release-checklist conditions:

1. **Monero-funded v1→v2 delta audit completed without contraindicating findings.** Shekyl inherits this audit via fork non-divergence (§1.1); no Shekyl-direct audit coordination is required.
2. **Monero's parallel production deployment has had meaningful observation-window exposure** (specific duration recorded in the release checklist before genesis; target: at least one full epoch transition cycle plus a conservative incident-detection window).

Both conditions run **in parallel** with Phases 0–5. Shekyl's implementation never blocks waiting for them. If either condition fails before release, **unpin to a pre-PR-#317 commit** (default `102f8acf`, already in `external/randomx`) and ship v1 per `RANDOMX_V1_FALLBACK.md` §1's late-binding triggers. The unpin is a submodule SHA change plus a verifier toggle, not a re-implementation.

## Track A — Phase 2 (parallel with Monero audit; spec-stable)

Add `rust/shekyl-pow-randomx/` as a new workspace member in [rust/Cargo.toml](../../rust/Cargo.toml). Crate is not yet wired to `shekyl-ffi` or C++.

Sub-PRs per `06-branching.mdc` (≤5 working days, ≤10 commits):

- **2a:** Argon2d primitive used by `Cache::derive`; spec-vector parity.
- **2b:** AES round / SuperScalarHash primitives from the v2 spec; spec-vector parity.
- **2c:** `Cache` (with `pub fn derive(seedhash)` constructor + `pub(crate)` `from_raw` / `derive_item(item_number)` / `item_bytes` accessors; 256 MB cache memory + 8 SuperscalarHash programs) and `pub fn compute_hash(&Cache, &[u8; 32], &[u8]) -> [u8; 32]` public transform (with `VmState` as a `pub(crate)` private struct internal to `vm.rs`; scratchpad allocated via `Box::new_zeroed_slice` or `Vec::into_boxed_slice` to avoid stack overflow on the 2 MB buffer; execution loop calls a private `fn dispatch_instruction(&Instruction, &mut VmState)` whose body is a Phase 2c NOP stub and is replaced in place by Phase 2d with real table-driven per-opcode dispatch — no trait, no impl swap, no signature change to `compute_hash`, per [`RANDOMX_V2_PHASE2C_PLAN.md`](./RANDOMX_V2_PHASE2C_PLAN.md) §5 F1 R2-D1). Structural-parity spec vectors (T1–T8 enumerated in [`RANDOMX_V2_PHASE2C_PLAN.md`](./RANDOMX_V2_PHASE2C_PLAN.md) §6): cache derivation, dataset-item derivation, scratchpad init, register init, program parse, spAddr derivation, F/E AES mix, end-to-end stub-NOP hash. Cache-derivation latency benchmark (≤200 ms per Phase 0 budget) + per-call `compute_hash` allocation benchmark (≤100 µs per Phase 0 budget; budget binds the `VmState` allocation portion under stub-NOP dispatch); `BENCH_RESULTS.md` baseline artifact committed at PR-merge. 256 MB cache buffer constructed via `Box::new_zeroed_slice(CACHE_SIZE).assume_init()` (unsafe but standard for large boxes; documented with `// SAFETY:` per `45-rust-lint-checks.mdc`) or `vec![0u8; CACHE_SIZE].into_boxed_slice()` — **never** `Box::new([0u8; CACHE_SIZE])`, which stack-constructs first and overflows default thread stacks. Both `Box::new_zeroed_slice` and `vec![]` are **infallible** allocation APIs: on OOM they call `handle_alloc_error` and abort the process rather than return an error. This is consistent with `RANDOMX_V2_RUST.md` §17's error taxonomy: `ERR_CACHE_DERIVE_FAILED` covers **structured VM-level failures the derivation deliberately returns** (e.g., a `debug_assert` caught at the shim), `ERR_INTERNAL` covers **uncaught Rust panics that cross the FFI boundary via `catch_unwind`**, and neither covers allocation failure (which aborts via `handle_alloc_error`). The two codes are disjoint at the shim by construction. If a future caller needs OOM-recoverable cache derivation (e.g., a wallet-side cold path), the disposition is V3.x work: rewrite the derivation to use `Box::try_new_zeroed_slice`/`Vec::try_reserve_exact` and add an `ERR_CACHE_ALLOC_FAILED` taxonomy entry. Until then, OOM at cache derivation aborts. **Phase 2c absorbs `Cache::derive` from the originally-scoped Phase 2e** — the work is small composition of existing 2a+2b primitives (Argon2d fill + 8× SuperscalarHash program generation), and the absorbed scope eliminates the `DatasetReader` trait abstraction the 2c-without-Cache shape would have required (see [`RANDOMX_V2_PHASE2C_PLAN.md`](./RANDOMX_V2_PHASE2C_PLAN.md) §5 F4 for the absorption rationale). 2e is removed from the sub-PR sequence; the sub-PR count drops from 7 (2a-2g) to 6 (2a-2g minus 2e). Per-hash latency benchmark (≤3.0× ratio against C reference) deferred to 2g where the differential harness lives. **PR cannot merge if either Phase 2c benchmark (cache-derive ≤200 ms, compute_hash-alloc ≤100 µs) fails the target.**
- **2d:** v2 bytecode opcode set (delta from v1) as table-driven dispatch from the v2 spec, landed as a body replacement of Phase 2c's private `dispatch_instruction` free function (no trait wiring, no impl swap, no signature change to `compute_hash` — per [`RANDOMX_V2_PHASE2C_PLAN.md`](./RANDOMX_V2_PHASE2C_PLAN.md) §5 F1 R2-D1); FPU rounding-mode plumbing for `fprc` register (deferred from 2c per F2c — 2c uses host-default rounding mode under stub-NOP dispatch; 2d adds the rounding-mode setter alongside CFROUND); byte-equality tests against spec vectors with end-to-end real-hash parity. `F128` newtype extraction decision (if needed) lands here per F3a deferral. The v2-only simplification table inherited from `RANDOMX_V2_PHASE2C_PLAN.md` §5 F5 includes a CFROUND throttling forward-pointer ensuring no v1 per-iteration-rounding-mode shim is constructed.
- **2f:** `CacheStore` utility type (`LruCache<Seedhash, Arc<Cache>>` behind a `Mutex`; default capacity 2). The crate exports it; instantiates none. **Two crate-level invariant tests, both CI-enforced**, with regex shapes calibrated to avoid false positives/negatives:
  1. **No module-level runtime-mutable state.** Test greps the crate source for the specific shapes that indicate runtime-mutable globals: `static\s+mut\s+\w+`, or `static\s+\w+\s*:\s*.*(?:Mutex|RwLock|Lazy|OnceCell|OnceLock|AtomicU|AtomicI|AtomicBool|AtomicPtr)`. Plain immutable data statics (`static FOO: &str = "..."`, `static TABLE: [u32; N] = [...]`) are explicitly permitted — they're effectively `const` and don't carry runtime state. Any hit on the mutable-shape patterns fails CI.
  2. **No C-ABI exports.** Three patterns checked, each failing CI on any hit:
     - **`#[no_mangle]` attribute, both spellings.** Pattern `#\[(?:unsafe\(\s*)?no_mangle(?:\s*\))?\]` covers both bare `#[no_mangle]` (older Rust) and `#[unsafe(no_mangle)]` (Rust 1.82+).
     - **`extern "C" fn` function declarations.** Pattern `\bextern\s+"C"\s+fn\b` catches `pub extern "C" fn foo()`, `pub unsafe extern "C" fn foo()`, and the private/internal forms. The `fn` token after the ABI string distinguishes function declarations from `extern "C" {` blocks. Catching this independent of `#[no_mangle]` is deliberate: a `pub extern "C" fn` without `#[no_mangle]` is Rust-mangled in its symbol and therefore not C-callable today, but the shape signals intent to be C-callable and a future `#[no_mangle]` would make it real — forbidding the shape now closes the door.
     - **`#[export_name = "..."]` attribute, both spellings.** Pattern `#\[(?:unsafe\(\s*)?export_name\b` covers both bare `#[export_name = "..."]` (older Rust / edition 2021) and `#[unsafe(export_name = "...")]` (edition 2024 / `unsafe-attributes` lint regime). Catches the rarer case where an export bypasses `#[no_mangle]` by naming the symbol directly. Without this check the shape would slip through both previous patterns. The double-spelling treatment mirrors the `#[no_mangle]` pattern above so the two attribute families have symmetrical coverage.
     - **Note:** `extern "C" { ... }` blocks (foreign imports) are explicitly NOT forbidden because the verifier crate is pure-Rust and the patterns above never match them. If a future contributor needs a foreign import for benchmarking or instrumentation, the import has no overlap with the exports the invariant guards.

     All C-ABI exports must live in `shekyl-ffi`.
  
  Benchmark per-call `VmState` allocation cost inside `compute_hash` (extending the Phase 2c BENCH_RESULTS.md baseline); if it exceeds the Phase 0 budget (100 µs), internalize a `VmState` pool inside `compute_hash` (private to `vm.rs`, invisible to consumers — no public `VmPool` type, no module-level state). Per Decision #7's Round 2 substrate-shift form: the pool is an implementation-detail optimization inside the transform function, not a public API surface.
  
- **2g:** Differential-test harness as a separate test-only artifact (not a dev-dependency of `shekyl-pow-randomx`). Links both the Rust verifier and the v2 fork's C reference; asserts byte equality across a corpus of `(seedhash, data)` inputs plus a concurrent-call thread-safety test. C-side state-machine scenarios (epoch transition, secondary cache, async rebuild) are explicitly out of scope. The `shekyl-pow-randomx` crate's own `cargo test` succeeds without the C library present.

**Track A end state:** `shekyl-pow-randomx` exists, passes spec-vector parity, is cross-checked against the C reference via a separate CI harness, hits Phase 0 performance budgets, and is not consumed by anything in shipping binaries. Zero behavior change in shipping binaries.

## Track B — gated on wallet V3.2 cutover

**Gating signal:** wallet V3.2 has landed on `dev`; FFI mega-header in a quiet 1-2 week window before starting Phase 3.

### Phase 3: Cutover (likely split 3a/3b/3c)

Six C++ files form the **daemon-side `rx_*` caller set** Phase 3 must rewire onto the v2 FFI: `pow_randomx.cpp`, `blockchain.cpp`, `slow-hash.c`, `core_rpc_server.cpp`, `hash-ops.h`, `cryptonote_tx_utils.cpp`. Plus implementation files to delete (`rx-slow-hash.c`, `pow_cryptonight.cpp`, `slow-hash.c`), the `cncrypto` PUBLIC link to drop, and two CI invariants to add.

A repo-wide grep for `rx_` returns additional files (`src/cryptonote_basic/miner.cpp`, `src/cryptonote_basic/cryptonote_format_utils.cpp`, `src/rpc/rpc_payment.cpp`, `src/wallet/wallet_rpc_payments.cpp`) which are intentionally **not** in the Phase 3 caller-rewire set because they are handled by other plan steps that run in the same window or earlier:

- `src/rpc/rpc_payment.cpp` and `src/wallet/wallet_rpc_payments.cpp` are **deleted in full** by the RPC-payments removal recorded in `RANDOMX_V2_RUST.md` §15. The deletion removes the only PoW touchpoint in the wallet tree and the only RPC-payments call sites of `rx_*`.
- `src/cryptonote_basic/miner.cpp` and `src/cryptonote_basic/cryptonote_format_utils.cpp` are handled by Phase 4's **version-gate deletion** and `IPowSchema`/`pow_registry` removal. Their `rx_*` references are either inside `IPowSchema`-mediated dispatch (deleted with the registry) or inside `block.major_version` PoW-selection branches (deleted with the version gate). See Phase 4 §"Version-gate deletion" and §"C++ side."

Net: Phase 3 rewires six daemon files; the remaining four `rx_*`-touching files are deleted or surgically edited by §15 (RPC payments) and Phase 4 (version gate + IPowSchema), not by Phase 3. The Phase 3b deleted-call audit (next sub-section) confirms the per-site disposition for each call.

This exceeds `06-branching.mdc`'s 5-day / 10-commit limit; **the plan acknowledges the split with proposed phasing, finalized in Phase 3 planning:**

- **Phase 3a — FFI export + flagged swap.** Export `shekyl_pow_randomx_v2_hash` from `shekyl-ffi` (with internal `CacheStore`). Add header declaration. In [src/crypto/pow_randomx.cpp](../../src/crypto/pow_randomx.cpp), swap `crypto::rx_slow_hash` → `shekyl_pow_randomx_v2_hash` behind a build flag (default ON; legacy path still buildable for the duration of 3a review so reviewers can A/B the implementations and rollback is mechanical if Phase 3a's PR is bisected against a problem). **The flag does not survive Phase 3b.** Pre-genesis there are no shipped users to maintain a rollback story for; the flag is purely a developer-side knob between 3a-merge and 3b-merge — a span of days, not releases.

- **Phase 3b — Rewire remaining callers + delete lifecycle calls.** Rewire `blockchain.cpp`, `core_rpc_server.cpp`, `hash-ops.h`, `cryptonote_tx_utils.cpp`. Delete every call site for `rx_set_main_seedhash`, `rx_set_miner_thread`, `rx_get_miner_thread`, `rx_slow_hash_allocate_state`, `rx_slow_hash_free_state`. **A new versioned markdown file ships with the PR: [docs/design/RANDOMX_V2_PHASE_3B_DELETED_CALL_AUDIT.md](../../docs/design/RANDOMX_V2_PHASE_3B_DELETED_CALL_AUDIT.md).** It is a permanent record, not a PR-description summary. The PR description summarizes and links to it. Required shape:

  | Deleted call site (file:line) | Original intent | New flow disposition |
  |---|---|---|
  | `rx_set_main_seedhash` in `blockchain.cpp:NNN` | Trigger async cache rebuild when daemon learns new seedhash | Lazy derivation on first `hash` call for new seedhash. ~150 ms one-time latency once per ~2.84 days, accepted per Decision #6. |
  | `rx_set_miner_thread` in `miner.cpp:NNN` | Register thread index to control `RANDOMX_FLAG_SECURE` for JIT mode | Irrelevant in Rust interpreter (no JIT, no SECURE flag). Deletion is correct; nothing to cover. |
  | ... (one row per deleted call site) | ... | ... |
  
  Each row's "new flow disposition" must be a positive statement of what covers the original intent, or an explicit "intent no longer applies in derived-first design" with rationale. The file is grep-able six months later, gets the same review rigor as code, and serves as audit evidence for the "things still compile, but is startup behavior the same?" question that the differential harness cannot answer.
  
  Build flag from 3a is removed; Rust path is the only path.

- **Phase 3c — Implementation deletions + cncrypto link drop + CI invariants.** **Ordering precondition:** Phase 3c assumes that every remaining `rx_slow_hash` / `cn_slow_hash` / `slow_hash_allocate_state` / `slow_hash_free_state` call site has already been rewired or deleted by the preceding steps in this plan window. Specifically, before 3c lands: §15 (RPC payments delete) must have removed `src/wallet/wallet_rpc_payments.cpp` and `src/rpc/rpc_payment*`; **and** Phase 4's version-gate + `IPowSchema` deletion must have removed `src/cryptonote_basic/miner.cpp`'s `slow_hash_allocate_state()` / `slow_hash_free_state()` `extern "C"` declarations and calls, plus `src/cryptonote_basic/cryptonote_format_utils.cpp`'s `crypto::rx_slow_hash` and `crypto::cn_slow_hash` call sites. (The KDF `cn_slow_hash` calls in `cryptonote_format_utils.cpp` at lines 1465/1473 are non-PoW and must move to a Rust-side KDF replacement before 3c; this is a Phase 4 deliverable.) If any caller remains at the time 3c is opened, the order is: pull that caller's removal forward into the 3c PR, or land 3c after the Phase 4 deletion lands. Without this ordering, the build's intermediate state has unresolved `slow_hash_*` / `rx_slow_hash` references. Then: delete [src/crypto/rx-slow-hash.c](../../src/crypto/rx-slow-hash.c), [src/crypto/pow_cryptonight.cpp](../../src/crypto/pow_cryptonight.cpp), [src/crypto/slow-hash.c](../../src/crypto/slow-hash.c) together — they are tangled implementation (CryptoNight code references the rx-slow-hash dispatch), deleting separately leaves intermediate states broken. Drop randomx C linkage from `cncrypto` per `RANDOMX_V2_RUST.md` §11 PUBLIC-link survey. Add CI symbol-isolation invariant (`RANDOMX_V2_RUST.md` §7). Add CI per-hash benchmark (`RANDOMX_V2_RUST.md` §8 mechanism: N=1024 hashes, median ratio ≤ 3.0×, deterministic, <30s wall time). Full 600k-block initial-sync wall-time test is added to the release-gate suite (not per-PR).

If during Phase 3 planning the work fits in one PR within `06-branching.mdc` limits, the split can be skipped. The default expectation is the split.

### Phase 4: Delete abstractions (no implementation churn)

Pure abstraction cleanup. Phase 3 handled the implementation files; Phase 4 deletes the rule-violating speculative scaffolding on both sides.

Per `60-no-monero-legacy.mdc`, `15-deletion-and-debt.mdc`, and `70-modular-consensus.mdc`.

**C++ side:**

- Delete [src/crypto/pow_schema.h](../../src/crypto/pow_schema.h) (the `IPowSchema` interface).
- Delete [src/crypto/pow_registry.h](../../src/crypto/pow_registry.h) and [src/crypto/pow_registry.cpp](../../src/crypto/pow_registry.cpp).
- Update call sites in [src/cryptonote_core/cryptonote_tx_utils.cpp](../../src/cryptonote_core/cryptonote_tx_utils.cpp), [src/cryptonote_basic/miner.cpp](../../src/cryptonote_basic/miner.cpp), [src/daemon/rpc_command_executor.cpp](../../src/daemon/rpc_command_executor.cpp), [src/rpc/core_rpc_server.cpp](../../src/rpc/core_rpc_server.cpp), [src/rpc/core_rpc_server_commands_defs.h](../../src/rpc/core_rpc_server_commands_defs.h) to call the single RandomX v2 verifier directly via FFI.

**Rust side (per `70-modular-consensus.mdc`):**

The `shekyl-consensus` crate has the same prohibited shape as `IPowSchema`. The crate's own doc-comment confirms it: *"Provides a pluggable proof mechanism supporting PoW, PoS, and hybrid consensus modes."*

- Delete [rust/shekyl-consensus/](../../rust/shekyl-consensus/) (proof.rs, registry.rs, randomx.rs, types.rs, error.rs, lib.rs, Cargo.toml).
- Remove `shekyl-consensus` from [rust/Cargo.toml](../../rust/Cargo.toml) `members`.
- Fold remaining real types into `shekyl-pow-randomx`:
  - `BlockHeader`, `ChainState`, `Difficulty` — currently only used by `RandomXProof`. Per `70-modular-consensus.mdc`: do not pre-extract to `shekyl-consensus-types`; if a second consensus algorithm is ever proposed, that algorithm extracts them then.
  - `ConsensusError` — fold into `shekyl-pow-randomx`'s error type.
- Replace structural-stub `RandomXProof` with concrete `RandomXVerifier` in `shekyl-pow-randomx`.
- Update [rust/shekyl-ffi/Cargo.toml](../../rust/shekyl-ffi/Cargo.toml): remove `shekyl-consensus`; add `shekyl-pow-randomx`.
- Update [rust/shekyl-ffi/src/lib.rs](../../rust/shekyl-ffi/src/lib.rs):
  - Delete `static CONSENSUS_REGISTRY: Mutex<Option<shekyl_consensus::ConsensusRegistry>>`.
  - Delete `shekyl_rust_init` consensus-registry construction.
  - Delete `shekyl_active_consensus_module()` (answer is permanently `"RandomX"`).
- Update doc-comment reference in [rust/shekyl-engine-state/src/safety_constants.rs](../../rust/shekyl-engine-state/src/safety_constants.rs).
- Update any C++ caller of `shekyl_rust_init` / `shekyl_active_consensus_module`.

**Version-gate deletion (mandatory):**

- Delete `RX_BLOCK_VERSION` constant and every reference.
- Delete any `if (major_version >= X)` / `if (hf_version >= X)` switch in PoW selection. The switch itself is the failure; even dead branches imply "we might dispatch differently someday."
- Applies to [src/cryptonote_basic/cryptonote_format_utils.cpp](../../src/cryptonote_basic/cryptonote_format_utils.cpp) and any other site discovered.

**Misc cleanup:**

- Resolve [src/wallet/wallet_rpc_payments.cpp](../../src/wallet/wallet_rpc_payments.cpp) PoW touchpoint per Phase 0 decision.
- Update PoW unit tests under [tests/unit_tests/](../../tests/unit_tests/) to v2-only.

### Phase 5: Docs

Update:

- [docs/USER_GUIDE.md](../../docs/USER_GUIDE.md) (PoW description; mining instructions referencing the miner-only C build flag; note that former `MONERO_RANDOMX_*` env vars are gone, replaced by constructor parameters or removed entirely).
- [docs/SHEKYLD_PREREQUISITES.md](../../docs/SHEKYLD_PREREQUISITES.md) (Rust toolchain version if bumped).
- [docs/DOCUMENTATION_TODOS_AND_PQC.md](../../docs/DOCUMENTATION_TODOS_AND_PQC.md) (close RandomX v2 row).
- [docs/DESIGN_CONCEPTS.md](../../docs/DESIGN_CONCEPTS.md) (cite the permanent architectural decisions; note `shekyl-consensus` crate deletion; cite `18-type-placement.mdc` as the rule that shaped the verifier API; cite Decision #6 for why no prewarm).
- [docs/CHANGELOG.md](../../docs/CHANGELOG.md).
- [docs/FOLLOWUPS.md](../../docs/FOLLOWUPS.md) — close any RandomX v2 follow-ups this plan introduces along the way (notably: confirm the §22 Guix forward-looking entry was filed at Phase 0 close, and amend or close it once Guix integration lands). **Note this plan is primarily fresh debt clearance**: `IPowSchema`/`pow_registry`, `shekyl-consensus`, RPC payments, and the `rx-slow-hash.c` stateful core were not previously tracked in FOLLOWUPS, so the queue's pre-existing accumulation/resolution trajectory is unaffected by this work. The Phase 5 FOLLOWUPS pass is therefore mostly forward-looking close-records of obligations the plan itself creates, not closure of pre-existing items. **Do not** add a "Rust-port the JIT later" item — Decision #1 is permanent; **do not** add a "consider prewarm" item — Decision #6 is permanent.

## Risk acknowledgments

- **Consensus-critical.** A bug here is a hard-fork crisis. Every Track B PR needs differential-test green, both CI invariants green, initial-sync wall-time CI green, and at least one reviewer who is not the author.
- **v2 algorithm posture is the largest external dependency.** Mitigated by (a) fork non-divergence inheriting Monero's audit byte-for-byte, (b) Monero deploying v2 in parallel as the other production network, and (c) the release-time gate (not Phase-2 gate, per `RANDOMX_V2_RUST.md` §1.4) that fires before genesis with explicit unpin-and-revert fallback to v1 at `102f8acf` if either Monero's audit or its production deployment surfaces a blocker.
- **Per-call `VmState` allocation cost inside `compute_hash`** is empirically untested at plan creation time. Phase 2c BENCH_RESULTS.md baseline + Phase 2f follow-on benchmark gate Phase 3; if allocation dominates, an internal `VmState` pool lands inside `compute_hash` per Decision #7 (no public `VmPool` type).
- **State-statelessness and ABI-cleanliness invariants are load-bearing.** Phase 2f's two crate-level invariant tests are mechanical enforcement of Decisions #4–#6. If a future contributor removes, weakens, or marks them allow-failure, the principles silently revert to honor-system. Treat any PR that touches them as architectural.
- **Long-running work.** Track A alone is multi-PR over weeks; Track B starts months out. Each sub-PR within `06-branching.mdc` limits; Phase 3's 3a/3b/3c split is the explicit acknowledgement.
- **FFI contention if Track B starts too early.** Re-confirm gating signal immediately before Phase 3.
- **`cncrypto` PUBLIC link is wider than one file.** Phase 3c cannot drop the link until `RANDOMX_V2_RUST.md` §11 PUBLIC-link survey confirms no direct consumer (currently 13+ targets in production `src/` plus 6+ test executables, per the §11 expansion) and no transitive consumer (via `common` etc.) uses any `randomx_*` symbol.
- **Phase 3b's per-site audit doc is a versioned markdown file, not a PR-description summary.** Lives at `docs/design/RANDOMX_V2_PHASE_3B_DELETED_CALL_AUDIT.md`. Without a permanent grep-able record, lifecycle-call deletion risks a "things compile, but startup behavior is subtly different" regression the differential harness won't catch — and a PR-description audit isn't a record six months later.
- **Cargo.lock conflicts during Track A.** Mechanical; resolve by regenerating after rebase.
- **Symbol-isolation invariant is load-bearing.** If Phase 3c's CI job is removed or weakened, the "C JIT off the verification path" property reverts to honor-system. Consensus-critical PR.
