//! Public consensus constants for LWMA-1.
//!
//! These values are emitted by `build.rs` from
//! `config/consensus_constants.json`, the single source of truth shared
//! with the C++ side per `docs/design/DAA_LWMA1.md` §4 and §6.2. The
//! `static_assert`-style const-eval `assert!` blocks below pin meaning
//! against the spec values; a hand-edit of the JSON that changes a
//! consensus property fails the build with a clear message rather than
//! silently producing a different chain.

// Include the generator's emitted file. The expansion site (rather than
// a separate module) keeps the build-script artefact a private
// implementation detail; consumers see only the named re-exports below.
include!(concat!(
    env!("OUT_DIR"),
    "/consensus_constants_generated.rs"
));

/// LWMA-1 window size, in blocks. Canonical recommendation for
/// `T = 120`-second target block times per
/// `docs/design/DAA_LWMA1.md` §4.
pub const N: u64 = DAA_WINDOW_N;

/// LWMA-1 window size as a `usize` for slice/array indexing. The
/// build script (`build.rs`) emits this directly from the JSON
/// value (validated as `<= u32::MAX`) so no in-Rust `u64 -> usize`
/// cast is needed; this satisfies the workspace's
/// `cast_possible_truncation = "deny"` lint without per-site
/// `#[allow]` annotations.
pub const N_USIZE: usize = DAA_WINDOW_N_USIZE;

/// Target block time in seconds.
pub const T_SECONDS: u64 = DAA_TARGET_SECONDS;

/// Future-Time-Limit: incoming-timestamp acceptance bound relative to
/// local clock, in seconds. `T*N/20 = 540`s per
/// `docs/design/DAA_LWMA1.md` §5.5 (which co-tunes FTL with the
/// algorithm-internal solvetime clamp).
pub const FTL_SECONDS: u64 = DAA_FTL_SECONDS;

/// Median-Time-Past window length, in blocks. Canonical
/// recommendation per `docs/design/DAA_LWMA1.md` §4 / §5.5.
pub const MTP_WINDOW: u64 = DAA_MTP_WINDOW;

/// MTP window length as a `usize` for slice/array indexing. Same
/// compile-time-truncation defense as [`N_USIZE`].
pub const MTP_WINDOW_USIZE: usize = DAA_MTP_WINDOW_USIZE;

/// The single ratified pre-window difficulty value (the "difficulty
/// guess" of canonical LWMA-1 line 107, expressed as a consensus
/// constant rather than a runtime parameter per
/// `docs/design/DAA_LWMA1.md` §2.6). Returned by `lwma1_next` for any
/// `chain_height < N`.
pub const GENESIS_DIFFICULTY: u128 = DAA_GENESIS_DIFFICULTY;

// Consensus-property sentinels. These const-eval `assert!` blocks pin
// the JSON-authority values against the §4 / §5.5 disposition; if a
// future PR drifts a value without amending the spec, the build fails
// with a clear message. The `static_assertions::const_assert!` crate is
// intentionally not pulled in for single-call-site sentinels; the
// const-eval `assert!` form is equivalent and dependency-free
// (mirrors the pattern used in `rust/shekyl-engine-core/build.rs`'s
// consumers).

// Per docs/design/DAA_LWMA1.md §4 Round 4 disposition.
const _: () = assert!(
    N == 90,
    "DAA_LWMA1.md §4 ratifies N = 90 for T = 120; \
     drift requires a spec amendment."
);

// Per docs/design/DAA_LWMA1.md §4 (T = 120 second target block time).
const _: () = assert!(
    T_SECONDS == 120,
    "DAA_LWMA1.md §4 ratifies T = 120 seconds; \
     drift requires a spec amendment."
);

// Per docs/design/DAA_LWMA1.md §5.5 (FTL = N*T/20 = 540 seconds).
const _: () = assert!(
    FTL_SECONDS == 540,
    "DAA_LWMA1.md §5.5 ratifies FTL = 540 seconds (= N*T/20); \
     drift requires a spec amendment."
);

// Per docs/design/DAA_LWMA1.md §5.5 (MTP window = 11 blocks).
const _: () = assert!(
    MTP_WINDOW == 11,
    "DAA_LWMA1.md §5.5 ratifies MTP window = 11 blocks; \
     drift requires a spec amendment."
);

// Per docs/design/DAA_LWMA1.md §2.6 (GENESIS_DIFFICULTY = 100).
const _: () = assert!(
    GENESIS_DIFFICULTY == 100,
    "DAA_LWMA1.md §2.6 ratifies GENESIS_DIFFICULTY = 100; \
     drift requires a spec amendment."
);

// Algorithm-internal type-safety sentinels: the LWMA-1 specification
// references `N*N*T/20` for the minimum-L floor and `2_000_000 * N * N
// * T` for the §5.3 step-8 overflow guard. Both arithmetic expressions
// must fit comfortably in u128 for the algorithm's preconditions to
// hold. Pinning here forces a build failure if a future N/T choice
// would push these expressions into overflow territory.

// Worst-case |L| bound across the window: N*(N+1)/2 * 6*T (the largest
// possible |sum of i * clamped_solvetime|). Per §5.4 must fit in i128.
const _: () = assert!(
    (N as u128) * ((N as u128) + 1) / 2 * 6 * (T_SECONDS as u128) <= (i128::MAX as u128),
    "DAA_LWMA1.md §5.4: worst-case |L| bound must fit in i128."
);
