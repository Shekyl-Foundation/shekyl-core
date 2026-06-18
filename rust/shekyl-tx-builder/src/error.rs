//! Structured error types for transaction signing.
//!
//! Every failure mode in [`crate::sign_transaction`] maps to a variant of
//! [`TxBuilderError`]. Errors are returned *before* any cryptographic work
//! begins when possible (validation errors) or after a proof operation fails
//! (crypto errors).

use crate::{MAX_INPUTS, MAX_OUTPUTS};
use shekyl_fcmp::MAX_TREE_DEPTH;

/// Structured error covering every failure mode in transaction signing.
///
/// Validation errors (`NoInputs` through `BranchLayerMismatch`) are checked
/// exhaustively at the top of [`crate::sign_transaction`] before any
/// expensive cryptographic operations begin.
///
/// Crypto errors (`BulletproofError`, `FcmpProveError`, `PqcSignError`)
/// wrap downstream crate errors with additional context.
#[derive(Debug, thiserror::Error)]
pub enum TxBuilderError {
    /// The caller provided an empty `inputs` slice.
    #[error("no inputs provided")]
    NoInputs,

    /// The number of inputs exceeds the consensus limit.
    #[error("too many inputs: {0} exceeds limit {MAX_INPUTS}")]
    TooManyInputs(usize),

    /// The caller provided an empty `outputs` slice.
    #[error("no outputs provided")]
    NoOutputs,

    /// The number of outputs exceeds the consensus limit.
    #[error("too many outputs: {0} exceeds limit {MAX_OUTPUTS}")]
    TooManyOutputs(usize),

    /// An input has a zero amount, which is not spendable.
    #[error("input {index} has zero amount")]
    ZeroInputAmount { index: usize },

    /// An output has a zero amount, which is economically meaningless.
    #[error("output {index} has zero amount")]
    ZeroOutputAmount { index: usize },

    /// Summing the input-side amounts (inputs plus any input-side cleartext
    /// balance terms, `extra_inputs`) would overflow `u64`.
    #[error("total input-side amount overflows u64")]
    InputAmountOverflow,

    /// Summing the output-side amounts (outputs, fee, and any output-side
    /// cleartext balance terms, `extra_outputs`) would overflow `u64`.
    #[error("total output-side amount overflows u64")]
    OutputAmountOverflow,

    /// The value available (inputs + input-side cleartext terms) is less than
    /// the value required (outputs + fee + output-side cleartext terms), so the
    /// transaction cannot balance.
    #[error("available total {available_total} less than required total {required_total}")]
    InsufficientFunds {
        /// Inputs plus input-side cleartext terms (`extra_inputs`).
        available_total: u64,
        /// Outputs plus fee plus output-side cleartext terms (`extra_outputs`).
        required_total: u64,
    },

    /// An input's leaf chunk is empty (must contain at least the input itself).
    #[error("input {index} has empty leaf chunk")]
    EmptyLeafChunk { index: usize },

    /// An input's leaf chunk exceeds the Selene chunk width.
    #[error("input {index} leaf chunk has {count} entries, exceeds SELENE_CHUNK_WIDTH ({max})")]
    LeafChunkTooLarge {
        index: usize,
        count: usize,
        max: usize,
    },

    /// The tree depth must be at least 1.
    #[error("tree depth is 0")]
    ZeroTreeDepth,

    /// The tree depth exceeds the protocol maximum.
    #[error("tree depth {0} exceeds maximum {MAX_TREE_DEPTH}")]
    TreeDepthTooLarge(u8),

    /// The number of C1/C2 branch layers is inconsistent with the tree depth.
    ///
    /// For a tree of depth `d`, each input must have `c1 + c2 == d - 1` total
    /// branch layers (the leaf hash at layer 0 needs no branch entry).
    /// The FCMP++ tower alternates Selene (C1) at even indices and Helios (C2)
    /// at odd indices, so `c1 == c2` (odd branch count) or `c1 == c2 + 1`
    /// (even branch count).
    #[error(
        "input {index} has {c1} C1 layers and {c2} C2 layers, inconsistent with tree depth {depth}"
    )]
    BranchLayerMismatch {
        index: usize,
        c1: usize,
        c2: usize,
        depth: u8,
    },

    /// The combined_ss field has the wrong length (expected 64 bytes).
    #[error("input {index} combined_ss has wrong length: {len} (expected 64)")]
    InvalidCombinedSsLength { index: usize, len: usize },

    /// Bulletproof+ range proof generation failed.
    #[error("Bulletproof+ proving failed: {0}")]
    BulletproofError(String),

    /// FCMP++ membership proof generation failed.
    #[error("FCMP++ proving failed: {0}")]
    FcmpProveError(String),

    /// PQC (hybrid Ed25519 + ML-DSA-65) signing failed for a specific input.
    #[error("PQC signing failed for input {index}: {reason}")]
    PqcSignError { index: usize, reason: String },

    /// Wire encoding / phase-1 payload construction failed.
    #[error("wire encoding failed: {0}")]
    WireError(String),
}
