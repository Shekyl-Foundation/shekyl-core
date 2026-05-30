// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `--mode=concurrent` orchestrator (§5.1.13, T7, T8).
//!
//! Per `docs/design/RANDOMX_V2_PHASE2G_PLAN.md` §5.1.13 + §3.15.4
//! orchestration lifecycle, this module runs the harness's
//! multi-worker concurrent correctness + RSS-bound assertion against
//! the per-PR-size random corpus (§5.1.5 + R1-D9).
//!
//! ## What this mode tests (per R1-D9 close + §6.3 T7/T8)
//!
//! - **T7 — Concurrent byte-equality.** 4 production + 1 reserve
//!   workers, 256 hashes each, share a [`CacheStore`] of capacity 2
//!   (per Phase 2F R3-D4). Each worker iterates the per-PR-size
//!   random corpus cyclically (128 distinct pairs × 2 = 256
//!   iterations per worker). Each worker's `(seedhash, data)`
//!   sequence must produce byte-identical Rust hashes (cross-worker
//!   determinism) and byte-equal the pre-computed C-reference hash
//!   (Rust/C parity).
//! - **T8 — RSS bound.** During concurrent execution, resident-set
//!   size measured via Linux `/proc/self/statm` field 2 (resident
//!   pages × page size) must satisfy
//!   `max(steady_state_samples) - baseline ≤ 640 MiB × 1.10`
//!   per R1-D9 F4. `steady_state_samples` = samples taken at t > 5 s
//!   after worker spawn ("after worker scheduling warms up").
//!
//! ## R1-D9 amendment mode-scoping pin
//!
//! Per Round 2 T3 (the R1-D9 amendment), the RSS-sampler thread is
//! spawned **only** inside this module's [`run`]; the
//! [`crate::mode_correctness`] / [`crate::mode_latency`] paths do
//! not spawn it and do not assert against the 640 MiB ceiling.
//! Inheritance-by-default is rejected: a future mode addition that
//! needs RSS-bound enforcement must explicitly extend its dispatch
//! to spawn the sampler.
//!
//! ## C-side reference pre-computation
//!
//! The harness's [`crate::c_oracle::COracleSession`] is `!Send +
//! !Sync` (it holds raw `randomx_cache` / `randomx_vm` pointers and
//! the C reference's internal state is not designed for concurrent
//! mutation). Rather than wrap the C oracle in a `Mutex` and
//! serialize all five workers' C-side calls (which would inflate
//! wall-clock by >5× and confound the T8 RSS measurement with
//! single-threaded C-side cache footprint), this module
//! **pre-computes** the C-reference hash for every `(seedhash,
//! data)` pair single-threadedly before the workers start. The
//! workers then run only the Rust hot path (`CacheStore`-driven
//! `compute_hash`) and assert their output against the pre-computed
//! C hashes after join.
//!
//! Pre-computation is **dropped** before the RSS baseline is taken:
//! each per-seedhash [`COracleSession`] is constructed, all of that
//! seedhash's data values are hashed, the session is dropped (C
//! cache + VM released), and the loop advances to the next
//! seedhash. No C-side allocations survive the pre-computation
//! phase. This keeps the baseline RSS measurement attributable to
//! the Rust harness's steady state and prevents the C-side
//! transient memory from masking a Rust-side leak.
//!
//! ## Pre-seeded canonical
//!
//! Per R1-D9 F4 ("baseline taken at test entry after `PreparedCache`
//! initialization but before worker spawn") the [`CacheStore`]'s
//! canonical slot is pre-seeded with the first corpus seedhash's
//! [`PreparedCache`]. The baseline RSS therefore captures the
//! single-canonical state; the steady-state delta captures the
//! transient-slot rotation + worker-thread overhead that the
//! concurrent phase adds. This mirrors the daemon's chain-tip
//! pre-seeded shape: at steady state the daemon holds one canonical
//! cache (the chain-tip seedhash) and rotates the transient slot
//! across alt-tip / probe seedhashes.
//!
//! ## Linux-only RSS sampling
//!
//! Per R1-D9 F4 "cross-platform disposition", the RSS-bound
//! assertion runs on Linux only. On macOS / Windows the worker
//! spawn + byte-equality assertion (T7) still run; the RSS sampler
//! is a no-op and T8 is reported as `rss_assertion_evaluated =
//! false`. The CI matrix is `ubuntu-latest` (per F5), so the
//! cross-platform skip is a portability artifact, not a coverage
//! gap.
//!
//! ## Failure surfacing
//!
//! At C8 the failure path emits a human-readable diagnostic via
//! [`std::fmt::Display`] and exits non-zero through `main.rs`'s
//! `ExitCode`. The §5.1.14 structured-JSON failure schema lands at
//! C9; each [`ConcurrentError`] variant carries enough context
//! (worker indices, iteration index, seedhash, hash pair) for the
//! C9 schema to populate without re-running the failing test.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use shekyl_pow_randomx::{compute_hash, CacheStore, PreparedCache, Seedhash};

use crate::c_oracle::{COracleError, COracleSession, RANDOMX_HASH_SIZE};
use crate::corpus_random::{
    generate_random_corpus, RandomCorpusPair, PER_PR_DATA_PER_SEEDHASH, PER_PR_SEEDHASH_COUNT,
};

/// Per R1-D9 close: 4 production + 1 reserve workers = 5 total.
///
/// Matches Phase 2F R1-D5's daemon parallel-verification fanout
/// formula `min(get_max_concurrency(), m_max_prepare_blocks_threads)
/// + 1` on the GitHub Actions `ubuntu-latest` runner class (4
/// vCPU; per F5 R1-D12 close). The §3.15.3 `--workers=<N>` flag's
///   default mirrors this constant.
pub const DEFAULT_WORKER_COUNT: usize = 5;

/// Per R1-D9 close: 256 hashes per worker × 5 workers = 1280
/// total hashes. The product exercises [`CacheStore`]'s capacity-2
/// invariant multiple times under contention.
pub const HASHES_PER_WORKER: usize = 256;

/// Per R1-D9 F4: 640 MiB ceiling = 2 × 256 MiB CacheStore
/// derived-cache holdings + ~10 MiB worker working-set + ~118 MiB
/// OS/allocator overhead headroom. Asserted as
/// `max(steady_state) - baseline ≤ ceiling × (numerator /
/// denominator)`.
pub const RSS_CEILING_BYTES: u64 = 640 * 1024 * 1024;

/// Per R1-D9 F4: ±10% tolerance band numerator (1.10).
pub const RSS_TOLERANCE_NUMERATOR: u64 = 11;

/// Per R1-D9 F4: ±10% tolerance band denominator (1.10 = 11/10).
pub const RSS_TOLERANCE_DENOMINATOR: u64 = 10;

/// Per R1-D9 F4: 100 ms sample interval.
pub const RSS_SAMPLE_INTERVAL: Duration = Duration::from_millis(100);

/// Per R1-D9 F4: steady-state samples = samples taken at t > 5 s
/// after worker spawn ("after worker scheduling warms up").
pub const STEADY_STATE_WARMUP: Duration = Duration::from_secs(5);

/// Per T7 (ii): wall-clock budget = "4× single-thread bound". The
/// estimated single-thread bound is `1280 hashes × ~300 ms ≈ 384
/// s ≈ 6.4 min` per the R1-D9 close worker-count rationale, giving
/// `4× ≈ 25.6 min`. Rounded up to a generous 30-minute ceiling so
/// the assertion functions as a deadlock-detector rather than a
/// performance check; the actual T7 release-mode runtime on the
/// 4-vCPU CI runner is ~1.5 min (per R1-D9 close: `5 workers × 256
/// hashes × ~300 ms × (1 / parallelism) ≈ 1.5 min`).
pub const WALL_CLOCK_BUDGET: Duration = Duration::from_secs(30 * 60);

/// Linux page size assumption for `/proc/self/statm` field 2
/// conversion (`resident_pages × PAGE_SIZE_BYTES = RSS bytes`).
/// The CI runner class per F5 R1-D12 is `ubuntu-latest` (amd64),
/// which uses 4 KiB pages by default; aarch64 / Apple Silicon
/// Linux variants may use 16 KiB pages, which would under-report
/// RSS by 4× and produce a silent false-pass on T8. A future port
/// to non-4 KiB Linux CI must replace this constant with a runtime
/// `sysconf(_SC_PAGESIZE)` (via `libc::sysconf`); the harness
/// would gain a new direct dep on `libc` per
/// `17-dependency-discipline.mdc` review at that point.
const PAGE_SIZE_BYTES: u64 = 4096;

/// Successful run summary surfaced on the stdout report path.
///
/// On non-Linux platforms `baseline_rss_bytes` /
/// `max_steady_state_rss_bytes` / `rss_delta_bytes` are `None` and
/// `rss_assertion_evaluated == false`; the worker counts and wall
/// clock are still populated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConcurrentReport {
    /// Number of worker threads spawned (per [`DEFAULT_WORKER_COUNT`]
    /// or the `--workers=<N>` override).
    pub workers: usize,
    /// Constant [`HASHES_PER_WORKER`] = 256; reported for
    /// reviewer convenience.
    pub hashes_per_worker: usize,
    /// `workers × hashes_per_worker`.
    pub total_hashes: usize,
    /// Wall-clock elapsed from baseline-RSS capture through worker
    /// join + sampler stop. T7 (ii) asserts this against
    /// [`WALL_CLOCK_BUDGET`].
    pub wall_clock_ms: u64,
    /// `/proc/self/statm` field 2 × [`PAGE_SIZE_BYTES`] captured
    /// after canonical pre-seed but before worker spawn (Linux
    /// only).
    pub baseline_rss_bytes: Option<u64>,
    /// Max RSS sample taken at `t > STEADY_STATE_WARMUP` after
    /// worker spawn (Linux only).
    pub max_steady_state_rss_bytes: Option<u64>,
    /// `max_steady_state_rss_bytes - baseline_rss_bytes` (Linux
    /// only; `None` if either component is `None` or the
    /// subtraction would saturate to zero on a noisy runner).
    pub rss_delta_bytes: Option<u64>,
    /// Constant [`RSS_CEILING_BYTES`] = 640 MiB; reported for
    /// `BENCH_RESULTS.md` traceability per R1-D9 F4 "max sample
    /// reported in `BENCH_RESULTS.md`".
    pub rss_ceiling_bytes: u64,
    /// `true` on Linux when the sampler ran and the bound was
    /// evaluated; `false` on macOS / Windows (T8 skipped).
    pub rss_assertion_evaluated: bool,
}

impl fmt::Display for ConcurrentReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.rss_assertion_evaluated {
            write!(
                f,
                "concurrent mode: workers={}, hashes_per_worker={}, \
                 total_hashes={}, wall_clock_ms={}, \
                 baseline_rss={} bytes, max_steady_state_rss={} bytes, \
                 rss_delta={} bytes (ceiling {} bytes ±10%)",
                self.workers,
                self.hashes_per_worker,
                self.total_hashes,
                self.wall_clock_ms,
                self.baseline_rss_bytes.unwrap_or_default(),
                self.max_steady_state_rss_bytes.unwrap_or_default(),
                self.rss_delta_bytes.unwrap_or_default(),
                self.rss_ceiling_bytes,
            )
        } else {
            write!(
                f,
                "concurrent mode: workers={}, hashes_per_worker={}, \
                 total_hashes={}, wall_clock_ms={} \
                 (RSS-bound assertion skipped per Linux-only methodology pin)",
                self.workers, self.hashes_per_worker, self.total_hashes, self.wall_clock_ms,
            )
        }
    }
}

/// All failure modes the concurrent orchestrator can surface. Each
/// variant carries enough context for the C9 §5.1.14 JSON schema
/// to attribute the failure without re-running the test.
#[derive(Debug)]
pub enum ConcurrentError {
    /// C oracle resource allocation failed during the pre-
    /// computation phase. Wraps the [`COracleError`] from
    /// [`COracleSession::new`].
    COracle(COracleError),
    /// T7 (i): a worker thread panicked. The panic payload is
    /// dropped (Rust's `Box<dyn Any>` is not portable into the
    /// failure-output schema); the worker index is sufficient
    /// attribution for a local re-run.
    WorkerPanicked { worker_index: usize },
    /// T7 (iii) leg 1: two workers produced different Rust hashes
    /// for the same iteration. Indicates a determinism break
    /// somewhere in the `compute_hash` path under contention
    /// (e.g., shared-state mutation, allocator nondeterminism
    /// leaking into the hash output).
    WorkerHashDivergence {
        /// Index of the worker chosen as the reference (always 0
        /// at C8 — every other worker is compared against worker
        /// 0).
        worker_a: usize,
        /// Index of the worker whose hash diverged from `worker_a`.
        worker_b: usize,
        /// Iteration index `i ∈ [0, HASHES_PER_WORKER)` at which
        /// the divergence first surfaced.
        iteration_index: usize,
        /// `worker_a`'s hash output at iteration `iteration_index`.
        hash_a: [u8; 32],
        /// `worker_b`'s hash output at iteration `iteration_index`.
        hash_b: [u8; 32],
    },
    /// T7 (iii) leg 2: a worker's Rust hash disagrees with the
    /// pre-computed C-reference hash for the same `(seedhash,
    /// data)` pair. This is the same divergence shape that C7's
    /// [`crate::mode_correctness::CorrectnessError::HashMismatch`]
    /// surfaces; T7 catches it under concurrent load.
    RustVsCMismatch {
        /// Worker that surfaced the mismatch (always 0 at C8 —
        /// the cross-worker leg runs first and would have caught
        /// any worker divergence before this leg runs).
        worker_index: usize,
        /// Iteration index `i ∈ [0, HASHES_PER_WORKER)` at which
        /// the mismatch surfaced.
        iteration_index: usize,
        /// Seedhash that `corpus[i % corpus.len()]` resolves to.
        seedhash: Seedhash,
        /// Worker's Rust hash output.
        rust_hash: [u8; 32],
        /// C reference's hash output (pre-computed before worker
        /// spawn).
        c_hash: [u8; 32],
    },
    /// T7 (ii): test wall-clock exceeded [`WALL_CLOCK_BUDGET`].
    /// Indicates a deadlock or pathological scheduling pattern
    /// (the deadlock-detector interpretation of "no deadlock").
    WallClockExceeded { elapsed_ms: u64, budget_ms: u64 },
    /// T8: `max(steady_state_samples) - baseline > ceiling × (11/10)`.
    /// Indicates a Rust-side memory regression (most likely an
    /// `Arc<PreparedCache>` retention leak past the
    /// `CacheStore::lookup_or_derive` hand-off boundary).
    RssBoundExceeded {
        /// RSS in bytes at test entry (after canonical pre-seed).
        baseline_bytes: u64,
        /// Max RSS sample taken at `t > STEADY_STATE_WARMUP`.
        max_steady_state_bytes: u64,
        /// `max_steady_state_bytes - baseline_bytes`.
        delta_bytes: u64,
        /// `RSS_CEILING_BYTES × (RSS_TOLERANCE_NUMERATOR /
        /// RSS_TOLERANCE_DENOMINATOR)` = 640 MiB × 1.10.
        ceiling_with_tolerance_bytes: u64,
    },
}

impl fmt::Display for ConcurrentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::COracle(e) => write!(f, "c-oracle setup failed: {e}"),
            Self::WorkerPanicked { worker_index } => {
                write!(f, "worker {worker_index} panicked during concurrent run")
            }
            Self::WorkerHashDivergence {
                worker_a,
                worker_b,
                iteration_index,
                hash_a,
                hash_b,
            } => write!(
                f,
                "cross-worker hash divergence at iteration {iteration_index}: \
                 worker {worker_a}: hash_a={}; worker {worker_b}: hash_b={}",
                hex_lower(hash_a),
                hex_lower(hash_b)
            ),
            Self::RustVsCMismatch {
                worker_index,
                iteration_index,
                seedhash,
                rust_hash,
                c_hash,
            } => write!(
                f,
                "rust vs C mismatch at worker {worker_index} iteration \
                 {iteration_index} for seedhash {seedhash}: rust_hash={}, \
                 c_hash={}",
                hex_lower(rust_hash),
                hex_lower(c_hash)
            ),
            Self::WallClockExceeded {
                elapsed_ms,
                budget_ms,
            } => write!(
                f,
                "concurrent test exceeded wall-clock budget: elapsed_ms={elapsed_ms}, \
                 budget_ms={budget_ms} (T7 (ii) deadlock-detector)"
            ),
            Self::RssBoundExceeded {
                baseline_bytes,
                max_steady_state_bytes,
                delta_bytes,
                ceiling_with_tolerance_bytes,
            } => write!(
                f,
                "RSS bound exceeded (T8): baseline={baseline_bytes} bytes, \
                 max_steady_state={max_steady_state_bytes} bytes, delta={delta_bytes} \
                 bytes > ceiling_with_tolerance={ceiling_with_tolerance_bytes} bytes \
                 (640 MiB × 1.10 per R1-D9 F4)"
            ),
        }
    }
}

impl std::error::Error for ConcurrentError {}

impl From<COracleError> for ConcurrentError {
    fn from(e: COracleError) -> Self {
        Self::COracle(e)
    }
}

/// Run `--mode=concurrent` per §5.1.13 + §3.15.4.
///
/// Returns [`ConcurrentReport`] on success; the first failure
/// short-circuits the run per the §3.15.4 + R1-D11 fail-fast
/// discipline (the worker join order is deterministic; the
/// cross-worker check then the rust-vs-C check then the RSS check
/// run in that order).
///
/// # Errors
///
/// Surfaces the first [`ConcurrentError`] across the pre-
/// computation + concurrent-execution + post-join assertion flow.
pub fn run(workers: usize) -> Result<ConcurrentReport, ConcurrentError> {
    // 1. Generate per-PR random corpus (16 × 8 = 128 pairs).
    let corpus = generate_random_corpus(PER_PR_SEEDHASH_COUNT, PER_PR_DATA_PER_SEEDHASH);

    // 2. Pre-compute C-reference hashes for each (seedhash, data)
    //    pair. The corpus is generated row-major over (i, j) so
    //    each seedhash's pairs arrive contiguously; one
    //    COracleSession per seedhash; the session is dropped (C
    //    cache + VM released) before the next seedhash to keep
    //    the C-side allocator footprint bounded.
    let c_hashes = precompute_c_reference_hashes(&corpus)?;

    // 3. Pre-seed CacheStore canonical with the first seedhash's
    //    PreparedCache. Per R1-D9 F4 the baseline RSS is taken
    //    "after PreparedCache initialization but before worker
    //    spawn"; pre-seeding satisfies the post-init precondition
    //    and matches the daemon's chain-tip canonical-loaded
    //    steady state.
    let cache_store = Arc::new(CacheStore::new());
    let first_seedhash = corpus[0].seedhash;
    let first_prepared = Arc::new(PreparedCache::derive(first_seedhash));
    cache_store.set_canonical(first_prepared);

    // 4. Take RSS baseline (Linux only).
    let baseline_rss = read_baseline_rss();

    // 5. Spawn RSS sampler + worker threads.
    let corpus_shared = Arc::new(corpus);
    let stop_sampler = Arc::new(AtomicBool::new(false));
    let samples = Arc::new(Mutex::new(Vec::<(Duration, u64)>::new()));
    let test_start = Instant::now();
    let sampler_handle =
        spawn_rss_sampler(Arc::clone(&stop_sampler), Arc::clone(&samples), test_start);

    let mut worker_handles: Vec<JoinHandle<Vec<[u8; RANDOMX_HASH_SIZE]>>> =
        Vec::with_capacity(workers);
    for worker_idx in 0..workers {
        let corpus_c = Arc::clone(&corpus_shared);
        let store_c = Arc::clone(&cache_store);
        worker_handles.push(thread::spawn(move || {
            worker_loop(worker_idx, &corpus_c, &store_c)
        }));
    }

    // 6. Join workers; the panic-from-worker case surfaces as
    //    JoinHandle::join Err. We unconditionally stop the sampler
    //    after worker join (whether they succeeded or panicked)
    //    so the sampler thread doesn't outlive the test.
    let mut worker_hashes: Vec<Vec<[u8; RANDOMX_HASH_SIZE]>> = Vec::with_capacity(workers);
    let mut worker_panic: Option<usize> = None;
    for (idx, handle) in worker_handles.into_iter().enumerate() {
        match handle.join() {
            Ok(hashes) => worker_hashes.push(hashes),
            Err(_) => {
                worker_panic = Some(idx);
                // Continue draining remaining handles so they don't
                // leak; their results are discarded.
            }
        }
    }
    stop_sampler.store(true, Ordering::Release);
    if let Some(h) = sampler_handle {
        // Drop the JoinHandle's Result explicitly; the sampler
        // thread can't fail meaningfully (its body is bounded by
        // the stop flag), so we don't propagate its `Result`.
        drop(h.join());
    }
    let elapsed = test_start.elapsed();

    if let Some(idx) = worker_panic {
        return Err(ConcurrentError::WorkerPanicked { worker_index: idx });
    }

    // 7. Wall-clock bound (T7 ii). Saturating cast: 30-min budget
    //    fits comfortably in u64 milliseconds.
    let elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
    let budget_ms = u64::try_from(WALL_CLOCK_BUDGET.as_millis()).unwrap_or(u64::MAX);
    if elapsed > WALL_CLOCK_BUDGET {
        return Err(ConcurrentError::WallClockExceeded {
            elapsed_ms,
            budget_ms,
        });
    }

    // 8. Cross-worker byte-equality (T7 iii leg 1). Worker 0 is
    //    the reference; workers 1..N are checked against it. The
    //    nested-index shape is the natural expression for a 2D
    //    [worker][iteration] grid; iterator-style would require
    //    `.iter().zip(...)` plumbing without clarity gain.
    #[allow(clippy::needless_range_loop)]
    for i in 0..HASHES_PER_WORKER {
        let reference = worker_hashes[0][i];
        #[allow(clippy::needless_range_loop)]
        for w in 1..workers {
            if worker_hashes[w][i] != reference {
                return Err(ConcurrentError::WorkerHashDivergence {
                    worker_a: 0,
                    worker_b: w,
                    iteration_index: i,
                    hash_a: reference,
                    hash_b: worker_hashes[w][i],
                });
            }
        }
    }

    // 9. Rust vs C parity (T7 iii leg 2). All workers agreed by
    //    leg 1, so worker 0's hashes suffice as the Rust side.
    let corpus_len = corpus_shared.len();
    #[allow(clippy::needless_range_loop)]
    for i in 0..HASHES_PER_WORKER {
        let rust_hash = worker_hashes[0][i];
        let corpus_idx = i % corpus_len;
        let c_hash = c_hashes[corpus_idx];
        if rust_hash != c_hash {
            return Err(ConcurrentError::RustVsCMismatch {
                worker_index: 0,
                iteration_index: i,
                seedhash: corpus_shared[corpus_idx].seedhash,
                rust_hash,
                c_hash,
            });
        }
    }

    // 10. RSS-bound assertion (T8; Linux only).
    let (max_steady_state, rss_delta, rss_assertion_evaluated) =
        evaluate_rss(baseline_rss, &samples)?;

    Ok(ConcurrentReport {
        workers,
        hashes_per_worker: HASHES_PER_WORKER,
        total_hashes: workers * HASHES_PER_WORKER,
        wall_clock_ms: elapsed_ms,
        baseline_rss_bytes: baseline_rss,
        max_steady_state_rss_bytes: max_steady_state,
        rss_delta_bytes: rss_delta,
        rss_ceiling_bytes: RSS_CEILING_BYTES,
        rss_assertion_evaluated,
    })
}

/// Worker thread body: iterate [`HASHES_PER_WORKER`] times,
/// `corpus[i % corpus.len()]`-driven; look up the cache via
/// [`CacheStore::lookup_or_derive`]; compute the hash; drop the
/// `Arc<PreparedCache>` immediately (per Phase 2F §3.1 caller hand-
/// off Arc-lifetime discipline). Returns the per-iteration Rust
/// hash vector for the post-join cross-worker + rust-vs-C
/// assertions.
///
/// The `Arc<Vec<…>>` / `Arc<CacheStore>` are taken by reference
/// because the spawning closure owns the cloned `Arc` for the
/// thread's lifetime; passing the `Arc` by value into `worker_loop`
/// would move ownership across an additional function boundary
/// with no benefit (the function does not re-clone the `Arc` to
/// further consumers).
fn worker_loop(
    worker_idx: usize,
    corpus: &Arc<Vec<RandomCorpusPair>>,
    cache_store: &Arc<CacheStore>,
) -> Vec<[u8; RANDOMX_HASH_SIZE]> {
    let _ = worker_idx; // reserved for future per-worker diagnostics
    let corpus_len = corpus.len();
    let mut out = Vec::with_capacity(HASHES_PER_WORKER);
    for i in 0..HASHES_PER_WORKER {
        let pair = &corpus[i % corpus_len];
        let prepared = cache_store.lookup_or_derive(&pair.seedhash);
        let hash = compute_hash(&prepared, &pair.data);
        // Drop the Arc immediately per Phase 2F's caller hand-off
        // discipline; long-lived holds extend cache memory residency
        // past CacheStore's capacity-2 bound and break the RSS
        // assertion.
        drop(prepared);
        out.push(hash);
    }
    out
}

/// Single-threaded C-reference pre-computation. For each unique
/// seedhash in `corpus`, allocate one [`COracleSession`], hash
/// every data value for that seedhash, then drop the session
/// (releasing the C-side 256-MiB cache + VM before the next
/// seedhash). Returns the hash vector in the same order as
/// `corpus`.
///
/// Cost: `N_seedhashes × (~5–10 s release Argon2d fill + cache
/// init)` plus `corpus.len() × per-hash time`. The per-seedhash
/// session pattern keeps the C-side peak RSS bounded to ~256 MiB
/// throughout pre-computation, matching the harness's RSS-bound
/// methodology.
fn precompute_c_reference_hashes(
    corpus: &[RandomCorpusPair],
) -> Result<Vec<[u8; RANDOMX_HASH_SIZE]>, ConcurrentError> {
    let mut out = Vec::with_capacity(corpus.len());
    let mut i = 0;
    while i < corpus.len() {
        let seedhash = corpus[i].seedhash;
        let oracle = COracleSession::new(seedhash)?;
        while i < corpus.len() && corpus[i].seedhash == seedhash {
            out.push(oracle.calculate_hash(&corpus[i].data));
            i += 1;
        }
        // `oracle` drops here: C-side cache + VM released before
        // the next seedhash. No C-side allocations survive across
        // seedhashes during pre-computation.
    }
    Ok(out)
}

// ---------- RSS sampling (Linux only) ----------

#[cfg(target_os = "linux")]
// The `Option` wrapper is structurally necessary so that the
// signature is uniform across platforms: the non-Linux stub
// returns `None` because `/proc/self/statm` is Linux-specific.
// Clippy sees only the Linux branch and reports the wrap as
// unnecessary; the cross-platform contract is the reason.
#[allow(clippy::unnecessary_wraps)]
fn spawn_rss_sampler(
    stop: Arc<AtomicBool>,
    samples: Arc<Mutex<Vec<(Duration, u64)>>>,
    start: Instant,
) -> Option<JoinHandle<()>> {
    Some(thread::spawn(move || {
        while !stop.load(Ordering::Acquire) {
            if let Ok(rss) = read_statm_resident() {
                if let Ok(mut guard) = samples.lock() {
                    guard.push((start.elapsed(), rss));
                }
            }
            thread::sleep(RSS_SAMPLE_INTERVAL);
        }
    }))
}

#[cfg(not(target_os = "linux"))]
fn spawn_rss_sampler(
    _: Arc<AtomicBool>,
    _: Arc<Mutex<Vec<(Duration, u64)>>>,
    _: Instant,
) -> Option<JoinHandle<()>> {
    None
}

#[cfg(target_os = "linux")]
fn read_statm_resident() -> std::io::Result<u64> {
    let s = std::fs::read_to_string("/proc/self/statm")?;
    let mut fields = s.split_ascii_whitespace();
    let _size = fields.next();
    let resident = fields.next().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "/proc/self/statm missing field 2 (resident)",
        )
    })?;
    let pages: u64 = resident.parse().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("parse resident field: {e}"),
        )
    })?;
    Ok(pages.saturating_mul(PAGE_SIZE_BYTES))
}

#[cfg(target_os = "linux")]
fn read_baseline_rss() -> Option<u64> {
    read_statm_resident().ok()
}

#[cfg(not(target_os = "linux"))]
fn read_baseline_rss() -> Option<u64> {
    None
}

/// Compute the steady-state max RSS sample, the delta against
/// baseline, and assert the bound. Returns
/// `(max_steady_state_bytes, delta_bytes, rss_assertion_evaluated)`.
///
/// On Linux: filter `samples` to those with `elapsed >
/// STEADY_STATE_WARMUP`, take `max`, subtract baseline, assert
/// `delta ≤ 640 MiB × 1.10`. If no steady-state samples were
/// collected (test finished before 5 s) the assertion is skipped
/// and the function returns `(None, None, false)` to surface this
/// transparently rather than silently pass.
///
/// On non-Linux: returns `(None, None, false)` unconditionally.
fn evaluate_rss(
    baseline: Option<u64>,
    samples: &Arc<Mutex<Vec<(Duration, u64)>>>,
) -> Result<(Option<u64>, Option<u64>, bool), ConcurrentError> {
    let Some(baseline) = baseline else {
        return Ok((None, None, false));
    };
    let max_steady_state = max_steady_state_sample(samples);
    let Some(max_steady_state) = max_steady_state else {
        // Linux but no steady-state samples (test finished before
        // STEADY_STATE_WARMUP). Surface as "not evaluated" rather
        // than as a silent pass; smoke tests + tiny corpora can
        // legitimately finish under 5 s.
        return Ok((None, None, false));
    };
    let delta = max_steady_state.saturating_sub(baseline);
    let ceiling_with_tolerance =
        RSS_CEILING_BYTES.saturating_mul(RSS_TOLERANCE_NUMERATOR) / RSS_TOLERANCE_DENOMINATOR;
    if delta > ceiling_with_tolerance {
        return Err(ConcurrentError::RssBoundExceeded {
            baseline_bytes: baseline,
            max_steady_state_bytes: max_steady_state,
            delta_bytes: delta,
            ceiling_with_tolerance_bytes: ceiling_with_tolerance,
        });
    }
    Ok((Some(max_steady_state), Some(delta), true))
}

fn max_steady_state_sample(samples: &Arc<Mutex<Vec<(Duration, u64)>>>) -> Option<u64> {
    let guard = samples.lock().ok()?;
    guard
        .iter()
        .filter(|(t, _)| *t > STEADY_STATE_WARMUP)
        .map(|(_, rss)| *rss)
        .max()
}

/// Lower-case hex string formatter for 32-byte arrays. Duplicated
/// across mode modules per the same rationale documented in
/// [`crate::mode_correctness::hex_lower`].
fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ConcurrentError::Display` surfaces the worker indices,
    /// iteration index, seedhash, and hex bytes for the diagnosis-
    /// relevant variants. Substring checks keep the test resilient
    /// against minor format-string reshapes.
    #[test]
    fn concurrent_error_display_includes_attribution() {
        let seedhash = Seedhash::from_bytes([0x42; 32]);

        let e = ConcurrentError::WorkerHashDivergence {
            worker_a: 0,
            worker_b: 3,
            iteration_index: 17,
            hash_a: [0xaa; 32],
            hash_b: [0xbb; 32],
        };
        let s = format!("{e}");
        assert!(s.contains("worker 0"), "got: {s}");
        assert!(s.contains("worker 3"), "got: {s}");
        assert!(s.contains("iteration 17"), "got: {s}");
        assert!(s.contains("aaaaaaaa"), "got: {s}");
        assert!(s.contains("bbbbbbbb"), "got: {s}");

        let e = ConcurrentError::RustVsCMismatch {
            worker_index: 2,
            iteration_index: 5,
            seedhash,
            rust_hash: [0xcc; 32],
            c_hash: [0xdd; 32],
        };
        let s = format!("{e}");
        assert!(s.contains("rust vs C mismatch"), "got: {s}");
        assert!(s.contains("worker 2"), "got: {s}");
        assert!(s.contains("iteration 5"), "got: {s}");

        let e = ConcurrentError::WallClockExceeded {
            elapsed_ms: 99_999,
            budget_ms: 1_800_000,
        };
        let s = format!("{e}");
        assert!(s.contains("wall-clock"), "got: {s}");
        assert!(s.contains("elapsed_ms=99999"), "got: {s}");

        let e = ConcurrentError::RssBoundExceeded {
            baseline_bytes: 100_000_000,
            max_steady_state_bytes: 900_000_000,
            delta_bytes: 800_000_000,
            ceiling_with_tolerance_bytes: RSS_CEILING_BYTES * 11 / 10,
        };
        let s = format!("{e}");
        assert!(s.contains("RSS bound exceeded"), "got: {s}");
        assert!(s.contains("delta=800000000"), "got: {s}");

        let e = ConcurrentError::WorkerPanicked { worker_index: 4 };
        let s = format!("{e}");
        assert!(s.contains("worker 4 panicked"), "got: {s}");
    }

    /// The constants in this module match the R1-D9 close pins.
    /// A drift would break the §4.6 T-A4 assertion-tampering catch
    /// at the §5.7 + §8.3 PR-review-time discipline level; this
    /// test catches the drift at `cargo test` time too.
    #[test]
    fn r1_d9_constants_match_plan_doc_pins() {
        assert_eq!(DEFAULT_WORKER_COUNT, 5);
        assert_eq!(HASHES_PER_WORKER, 256);
        assert_eq!(RSS_CEILING_BYTES, 640 * 1024 * 1024);
        assert_eq!(RSS_TOLERANCE_NUMERATOR, 11);
        assert_eq!(RSS_TOLERANCE_DENOMINATOR, 10);
        assert_eq!(RSS_SAMPLE_INTERVAL, Duration::from_millis(100));
        assert_eq!(STEADY_STATE_WARMUP, Duration::from_secs(5));
    }

    /// The ceiling-with-tolerance computation matches the
    /// `640 MiB × 1.10` literal value (within integer rounding).
    /// Pins the arithmetic shape that
    /// [`ConcurrentError::RssBoundExceeded`]'s
    /// `ceiling_with_tolerance_bytes` field carries.
    #[test]
    fn ceiling_with_tolerance_matches_640_mib_times_1_10() {
        let cwt =
            RSS_CEILING_BYTES.saturating_mul(RSS_TOLERANCE_NUMERATOR) / RSS_TOLERANCE_DENOMINATOR;
        // 640 × 1024 × 1024 × 11 / 10 = 738_197_504
        assert_eq!(cwt, 738_197_504);
        // The bound is the headroom plus the ceiling; rounded to
        // MiB it is 704 MiB (= 640 + 64).
        let cwt_mib = cwt / (1024 * 1024);
        assert_eq!(cwt_mib, 704);
    }

    /// `max_steady_state_sample` filters samples by elapsed time
    /// and returns the max of the steady-state subset. Samples at
    /// or before `STEADY_STATE_WARMUP` are excluded.
    #[test]
    fn max_steady_state_sample_filters_warmup_window() {
        let samples = Arc::new(Mutex::new(vec![
            (Duration::from_secs(1), 100), // pre-warmup; ignored
            (Duration::from_secs(5), 999), // boundary; excluded (> not >=)
            (Duration::from_secs(6), 200), // steady; counted
            (Duration::from_secs(7), 300), // steady; counted (this is max)
            (Duration::from_secs(8), 250), // steady; counted
        ]));
        let max = max_steady_state_sample(&samples);
        assert_eq!(max, Some(300));
    }

    /// With no steady-state samples (all samples ≤ warmup), the
    /// helper returns `None`. `evaluate_rss` then reports the
    /// assertion as not-evaluated rather than silently passing.
    #[test]
    fn max_steady_state_sample_empty_when_all_in_warmup() {
        let samples = Arc::new(Mutex::new(vec![
            (Duration::from_secs(1), 100),
            (Duration::from_secs(2), 200),
            (Duration::from_secs(5), 300),
        ]));
        let max = max_steady_state_sample(&samples);
        assert_eq!(max, None);
    }

    /// `evaluate_rss` with no Linux baseline returns `(None, None,
    /// false)` cleanly. This is the non-Linux path's signature.
    #[test]
    fn evaluate_rss_no_baseline_skips() {
        let samples: Arc<Mutex<Vec<(Duration, u64)>>> = Arc::new(Mutex::new(Vec::new()));
        let (max, delta, evaluated) = evaluate_rss(None, &samples).expect("no error path");
        assert_eq!(max, None);
        assert_eq!(delta, None);
        assert!(!evaluated);
    }

    /// `evaluate_rss` with a baseline + steady-state samples below
    /// the ceiling returns `(Some(max), Some(delta), true)`. Pins
    /// the success-path return shape.
    #[test]
    fn evaluate_rss_within_bound() {
        let baseline = 100_000_000;
        // delta = 50 MiB; well under the 640 MiB ceiling
        let max_ss = baseline + 50 * 1024 * 1024;
        let samples = Arc::new(Mutex::new(vec![
            (Duration::from_secs(1), baseline),
            (Duration::from_secs(6), max_ss),
            (Duration::from_secs(7), max_ss - 1024 * 1024),
        ]));
        let (max, delta, evaluated) =
            evaluate_rss(Some(baseline), &samples).expect("within-bound path");
        assert_eq!(max, Some(max_ss));
        assert_eq!(delta, Some(50 * 1024 * 1024));
        assert!(evaluated);
    }

    /// `evaluate_rss` with a delta over the ceiling-with-tolerance
    /// surfaces `RssBoundExceeded`. Pins T8's failure path.
    #[test]
    fn evaluate_rss_exceeds_bound() {
        let baseline = 100_000_000;
        // delta = 800 MiB; well over the 704 MiB ceiling-with-tolerance
        let max_ss = baseline + 800 * 1024 * 1024;
        let samples = Arc::new(Mutex::new(vec![(Duration::from_secs(6), max_ss)]));
        let err = evaluate_rss(Some(baseline), &samples)
            .expect_err("over-ceiling path should surface error");
        match err {
            ConcurrentError::RssBoundExceeded {
                baseline_bytes,
                max_steady_state_bytes,
                delta_bytes,
                ceiling_with_tolerance_bytes,
            } => {
                assert_eq!(baseline_bytes, baseline);
                assert_eq!(max_steady_state_bytes, max_ss);
                assert_eq!(delta_bytes, 800 * 1024 * 1024);
                assert_eq!(ceiling_with_tolerance_bytes, 738_197_504);
            }
            other => panic!("expected RssBoundExceeded, got {other:?}"),
        }
    }

    /// On Linux, `/proc/self/statm` is readable and returns a
    /// plausible (non-zero) RSS in bytes. The test runs only on
    /// Linux per the cfg gate; on other platforms the function
    /// itself doesn't exist.
    #[cfg(target_os = "linux")]
    #[test]
    fn read_statm_resident_returns_plausible_value() {
        let rss = read_statm_resident().expect("statm read");
        // The test process's RSS is non-zero (we're running it).
        // Pinned to a small lower bound — any working Rust process
        // is well above 100 KiB resident. Upper bound is left
        // unpinned because debug builds with shared dependencies
        // can easily exceed 100 MiB at the time we sample.
        assert!(rss > 100 * 1024, "rss too small: {rss}");
    }

    /// On Linux the baseline-RSS helper succeeds.
    #[cfg(target_os = "linux")]
    #[test]
    fn read_baseline_rss_succeeds_on_linux() {
        let baseline = read_baseline_rss();
        assert!(baseline.is_some(), "baseline read should succeed on linux");
    }

    /// On non-Linux platforms the baseline-RSS helper returns
    /// `None` and the spawn helper returns `None` (no sampler
    /// thread).
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn rss_helpers_no_op_on_non_linux() {
        assert!(read_baseline_rss().is_none());
        let stop = Arc::new(AtomicBool::new(false));
        let samples = Arc::new(Mutex::new(Vec::new()));
        let handle = spawn_rss_sampler(stop, samples, Instant::now());
        assert!(handle.is_none());
    }

    /// `hex_lower` produces a 64-char lowercase hex string. Pins
    /// the display format used by [`ConcurrentError::Display`].
    #[test]
    fn hex_lower_round_trips() {
        let bytes: [u8; 32] = [
            0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45,
            0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01,
            0x23, 0x45, 0x67, 0x89,
        ];
        let s = hex_lower(&bytes);
        assert_eq!(s.len(), 64);
        assert!(s.starts_with("abcdef01"));
        assert!(s.ends_with("23456789"));
    }
}
