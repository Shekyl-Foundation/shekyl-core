// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Phase 2F §3.3 Round 3 component-floor benches (B-2 + B-3).
//!
//! Per
//! [`docs/design/RANDOMX_V2_PHASE2F_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2F_PLAN.md)
//! §3.4 R1-D4 + §6.3 Round 3, the per-call allocation cost in
//! [`shekyl_pow_randomx::compute_hash`] decomposes into two
//! independently measurable heap allocations performed by
//! `VmState::new` (the only allocator-visible work the per-call
//! pre-pool path performs):
//!
//! - **B-2 — `vmstate_alloc_scratchpad_zeroed`.** The 2 MiB
//!   zero-initialized scratchpad is the dominant per-call
//!   allocation by size (2_097_152 bytes vs. ~3 KiB for the
//!   register-file `Box<Program>`). The bench mirrors
//!   `crate::vm::alloc_zeroed_scratchpad`'s exact pattern:
//!   `Box::new_zeroed_slice(N)` followed by `assume_init`. Both
//!   bench and production resolve to the global allocator's
//!   `alloc_zeroed` call.
//! - **B-3 — `vmstate_alloc_register_file`.** The `Box<Program>`
//!   allocation backs the per-program parsed bytecode. Sized at
//!   `PROGRAM_SIZE * INSTRUCTION_SIZE = 384 * 8 = 3072` bytes plus
//!   the `cbranch_table` (PROGRAM_SIZE * 2 = 768 bytes). Total ~3.8
//!   KiB. The bench measures `Box::new(Program::default())`.
//!
//! The component-floor sum (B-2 median + B-3 median) is the §3.4
//! R1-D4 lower bound — the per-call cost the no-pool path cannot
//! undercut. The §3.4 R1-D4 disposition table (Round 3) decides the
//! Branch A / Branch B / Branch C disposition based on the A/B
//! delta from `compute_hash_alloc`'s `with_no_pool` vs. `with_pool`
//! benches; these component benches survive Round 3 as a sanity
//! cross-check (the no-pool A/B median should not undercut the
//! component-floor sum, which would indicate bench misconfiguration).
//!
//! # Why these benches don't reach into `crate::vm`
//!
//! The Phase 2F discipline is "don't expose internals just for
//! benches." The two component allocations are textbook
//! `Box::<[u8]>::new_zeroed_slice` / `Box::new(...)` calls — the
//! cost is the global allocator's, not Shekyl-specific code. Since
//! the bench measures the standard library's allocator path against
//! a freshly-shaped allocation, re-implementing the allocation
//! inline in the bench file produces a measurement equivalent to
//! `crate::vm::VmState::new`'s per-call alloc cost. The
//! `crate::vm::alloc_zeroed_scratchpad` carve-out adds no measurable
//! work above the global allocator (it's a thin wrapper that exists
//! to scope the Phase 2c `unsafe` block).
//!
//! # Status: informational (always runs)
//!
//! Both benches always run — no feature gate. Phase 2F's `cargo
//! bench --bench per_call_alloc` produces the medians without any
//! flags. The `BENCH_RESULTS.md` Phase 2F section records them;
//! Phase 3a may re-run them on the FFI-shim deployment hardware to
//! confirm the §3.4 R1-D4 disposition still holds against the
//! deployed allocator.

use std::mem::MaybeUninit;

use criterion::{black_box, criterion_group, criterion_main, Criterion};

/// Scratchpad size in bytes, mirrored from
/// `shekyl_pow_randomx::vm::RANDOMX_SCRATCHPAD_L3` (2 MiB).
///
/// The bench file is an external cargo target and cannot reach
/// `pub(crate)` constants directly. The literal is duplicated here
/// rather than gated behind a `#[doc(hidden)] pub` re-export per
/// the module rustdoc's "don't expose internals just for benches"
/// discipline. A divergence between this literal and the constant
/// would be caught by the criterion bench's wall-clock differing
/// from the production path; the value is stable per spec.
const RANDOMX_SCRATCHPAD_L3: usize = 2_097_152;

/// Program-instruction count, mirrored from
/// `shekyl_pow_randomx::vm::PROGRAM_SIZE` (384). Same rationale as
/// [`RANDOMX_SCRATCHPAD_L3`].
const PROGRAM_SIZE: usize = 384;

/// Per-instruction wire size in bytes, mirrored from
/// `shekyl_pow_randomx::vm::INSTRUCTION_SIZE` (8). Same rationale.
const INSTRUCTION_SIZE: usize = 8;

/// 8-byte instruction layout matching `shekyl_pow_randomx`'s
/// internal `Instruction` struct.
///
/// Re-implemented here (rather than re-exported via
/// `#[doc(hidden)] pub`) per the module rustdoc's "don't expose
/// internals just for benches" discipline. The struct's per-field
/// memory layout is the bench's measurement target — what's being
/// timed is `Box::new(Program::default())`'s allocation + zero-init
/// cost, which depends only on the struct's *size* (8 bytes per
/// instruction, 384 instructions, plus the 2-byte cbranch_table).
/// The struct's field semantics are irrelevant to the bench.
#[derive(Default)]
#[allow(dead_code)] // Fields are never read; only the alloc + zero-init cost is measured.
struct Instruction {
    opcode: u8,
    dst: u8,
    src: u8,
    mod_: u8,
    imm32: u32,
}

/// Program block matching `shekyl_pow_randomx::vm::Program`'s
/// layout.
///
/// Same "bench-side mirror, not bench-side re-export" rationale as
/// [`Instruction`]. The struct's role is to be `Box::new`'d on the
/// heap; what's timed is the heap allocation + zero-init, not any
/// field access.
#[allow(dead_code)] // Fields are never read; only the alloc + zero-init cost is measured.
struct Program {
    instructions: [Instruction; PROGRAM_SIZE],
    cbranch_table: [u16; PROGRAM_SIZE],
}

impl Default for Program {
    fn default() -> Self {
        Self {
            instructions: core::array::from_fn(|_| Instruction::default()),
            cbranch_table: [u16::MAX; PROGRAM_SIZE],
        }
    }
}

/// B-2: per-call cost of the 2 MiB zero-initialized scratchpad
/// allocation that `VmState::new` performs via
/// `crate::vm::alloc_zeroed_scratchpad`.
///
/// The bench mirrors the production allocation pattern exactly:
/// `Box::new_zeroed_slice(N)` followed by `assume_init`, which is
/// what `crate::vm::alloc_zeroed_scratchpad` does. Both paths
/// route through the global allocator's `alloc_zeroed` (per the
/// Rust 1.82+ stabilization of `Box::new_zeroed_slice`); on
/// contemporary x86-64 allocators (system glibc, mimalloc,
/// jemalloc) the cost is dominated by the kernel's
/// zero-page-mapping `mmap` path on cold allocations and the
/// per-thread cache hit on warm allocations.
///
/// Earlier drafts used `vec![0u8; N].into_boxed_slice()`. On
/// current `rustc` releases the `IsZero` specialization in
/// `Vec::from_elem` does fold this to the same `alloc_zeroed`
/// call, so the timing is observably equivalent on the reference
/// hardware — but the equivalence is a stdlib-implementation
/// property rather than a contract. Mirroring the production call
/// exactly removes the dependency on that specialization holding
/// across future stdlib versions.
fn bench_vmstate_alloc_scratchpad_zeroed(c: &mut Criterion) {
    let mut group = c.benchmark_group("per_call_alloc");
    // `sample_size = 200` reflects the per-call cost being well
    // under criterion's default measurement-time budget; B-2 is
    // sub-millisecond, so 200 samples produce a tight CI without
    // over-running the developer-loop time budget. Match B-3's
    // shape so the two component medians are directly comparable.
    group.sample_size(200);
    group.bench_function("vmstate_alloc_scratchpad_zeroed", |b| {
        b.iter(|| {
            // `Box::new_zeroed_slice(N)` + `assume_init` is the
            // exact pattern `crate::vm::alloc_zeroed_scratchpad`
            // uses (stable since Rust 1.82; the crate's MSRV is
            // 1.85). The unsafe block is the bench-side mirror of
            // the production carve-out's unsafe block — same
            // safety reasoning applies (every `u8` bit pattern is
            // valid; `Box::new_zeroed_slice(len)` zero-initializes
            // per its stabilized contract).
            let uninit: Box<[MaybeUninit<u8>]> =
                Box::new_zeroed_slice(black_box(RANDOMX_SCRATCHPAD_L3));
            // SAFETY:
            // `u8`'s all-zeros bit pattern is a valid `u8` value (every
            // value 0..=255 is in range; 0 is trivially valid).
            // `Box::new_zeroed_slice(len)` allocates `len` contiguous
            // `MaybeUninit<u8>` cells and zero-initializes them per its
            // stabilized contract (Rust 1.82+; MSRV 1.85). Converting
            // `Box<[MaybeUninit<u8>]>` to `Box<[u8]>` via `assume_init`
            // is therefore sound. Mirrors the SAFETY comment on
            // `crate::vm::alloc_zeroed_scratchpad` per the
            // module-rustdoc "bench-side mirror" discipline.
            #[allow(unsafe_code)]
            let buf: Box<[u8]> = unsafe { uninit.assume_init() };
            black_box(buf)
        });
    });
    group.finish();
}

/// B-3: per-call cost of the `Box<Program>` allocation that
/// `VmState::new` performs.
///
/// The bench measures `Box::new(Program::default())` — the same
/// allocation path the production code takes. Cost is the heap
/// allocation of `size_of::<Program>()` bytes (~3.8 KiB) plus the
/// zero-init the struct's `Default` impl performs (`from_fn` over
/// 384 instructions plus a 768-byte `cbranch_table` fill).
fn bench_vmstate_alloc_register_file(c: &mut Criterion) {
    // Sanity check: the bench-side mirror's size must equal the
    // production type's size. A mismatch would mean the bench is
    // not measuring the right allocation. The constant comparison
    // is compile-time-evaluable; assert at runtime here so the
    // bench output flags it before the criterion timing loop runs.
    let expected_program_size = PROGRAM_SIZE * INSTRUCTION_SIZE + PROGRAM_SIZE * 2;
    let actual_program_size = core::mem::size_of::<Program>();
    assert_eq!(
        actual_program_size, expected_program_size,
        "bench-side `Program` size ({actual_program_size}) must equal \
         PROGRAM_SIZE * INSTRUCTION_SIZE + PROGRAM_SIZE * 2 = \
         {expected_program_size}; if this assertion fires, the bench \
         is not measuring the production allocation cost.",
    );

    let mut group = c.benchmark_group("per_call_alloc");
    group.sample_size(200);
    group.bench_function("vmstate_alloc_register_file", |b| {
        b.iter(|| {
            // `Box::new(Program::default())` matches the production
            // allocation pattern in `crate::vm::VmState::new`'s
            // `Box::new(Program::default())` line. Clippy's
            // `box_default` lint suggests `Box::<Program>::default()`
            // as the idiomatic equivalent, but the bench's purpose
            // is to mirror the production cost; allowing the lint
            // here keeps the measured shape literal-equivalent to
            // the production site.
            #[allow(clippy::box_default)]
            let prog: Box<Program> = Box::new(Program::default());
            black_box(prog)
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_vmstate_alloc_scratchpad_zeroed,
    bench_vmstate_alloc_register_file,
);
criterion_main!(benches);
