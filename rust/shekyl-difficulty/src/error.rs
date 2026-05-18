//! Error taxonomy for the LWMA-1 algorithm.
//!
//! The variants mirror the FFI error codes documented in
//! `docs/design/DAA_LWMA1.md` §6.1 (ERR_NULL_PTR / ERR_INVALID_COUNT /
//! ERR_OVERFLOW / ERR_INTERNAL) modulo the Rust-safe-API boundary:
//! - `ERR_NULL_PTR` is structurally absent in safe Rust (slices cannot
//!   be null).
//! - `ERR_INTERNAL` (panic catch) is the FFI shim's responsibility in
//!   Phase 3; the Rust-side API surfaces panics as panics.
//!
//! This crate is `#![no_std]`, so the variants do not carry messages —
//! the `Display` impl produces the same short string the FFI shim
//! will log. Consumers wanting structured error reporting reconstruct
//! it from the variant.

/// Errors returned by [`crate::lwma1::lwma1_next`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// `chain_height >= N` but the input window does not contain
    /// exactly `N + 1` entries (or the two slices disagree in length).
    /// Maps to `ERR_INVALID_COUNT` (-2) at the FFI boundary per
    /// `docs/design/DAA_LWMA1.md` §6.1.
    InvalidCount,
    /// A consensus invariant was violated by the inputs — typically a
    /// non-monotonic cumulative-difficulty sequence, or arithmetic
    /// that would wrap `u128` despite the §5.3 step-8 overflow guard
    /// (which can only happen on attacker-controlled inputs that
    /// would themselves be rejected at the consumer's invariant
    /// checks). Maps to `ERR_OVERFLOW` (-3) at the FFI boundary.
    Overflow,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Self::InvalidCount => "invalid input count for the given chain_height",
            Self::Overflow => "consensus invariant violation (arithmetic overflow)",
        };
        f.write_str(s)
    }
}

// `core::error::Error` requires Rust 1.81; the Shekyl workspace MSRV
// permits it, but a `no_std` crate with no `std` feature still cannot
// implement it before 1.81. The workspace toolchain is current, and
// every other no_std-leaning crate in the workspace implements it. We
// follow suit for parity at the API surface.
impl core::error::Error for Error {}
