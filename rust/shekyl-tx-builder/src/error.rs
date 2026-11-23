//! Structured error types for transaction signing.
//!
//! Every failure mode in [`crate::sign_transaction`] maps to a variant of
//! [`TxBuilderError`]. Errors are returned *before* any cryptographic work
//! begins when possible (validation errors) or after a proof operation fails
//! (crypto errors).

use crate::{MAX_INPUTS, MAX_OUTPUTS};
use shekyl_fcmp::MAX_TREE_DEPTH;
use shekyl_wire::transaction::MIN_NON_COINBASE_OUTPUTS;

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

    /// Fewer outputs than consensus admits on a non-coinbase transaction
    /// (CEN-I1, [`MIN_NON_COINBASE_OUTPUTS`]), but at least one.
    #[error("too few outputs: {0} is below the minimum {MIN_NON_COINBASE_OUTPUTS}")]
    TooFewOutputs(usize),

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

    /// The input's own entry is not in its leaf chunk (matched on the
    /// `(output_key, commitment)` pair), so there is no leaf to prove against.
    #[error("input {index}: the assembled leaf chunk does not contain the spent output")]
    SpentOutputNotInLeafChunk { index: usize },

    /// The PQC leaf commitment the signer re-derives for this input (`PL-D3`:
    /// `CM = k·G_k + r·J` from the output's `combined_ss` and index) does not
    /// match the leaf the chain holds for it — the output was created with a
    /// `0x07` entry that is not the honest derivation. The funds were
    /// received but **cannot be spent**: no opening of the chain's leaf is
    /// known to this wallet. Surfaced here, before proving, as the typed
    /// received-but-unspendable condition rather than as a proof failure
    /// (`FCMP_SPEND_LINKABILITY.md` §6.2, rule 82).
    #[error(
        "input {index}: the chain's leaf commitment for this output is not the wallet's \
         derivation — received but unspendable (creator published a non-honest 0x07 entry)"
    )]
    PqcLeafMismatch { index: usize },

    /// The exceptional-value guard exhausted its counter while re-deriving
    /// the input's leaf blind (a ~2⁻²⁵² event per step; effectively unreachable).
    #[error("input {index}: PQC leaf blind derivation failed: {detail}")]
    PqcLeafDerivation { index: usize, detail: String },

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

    /// The FCMP++ layer count is below the spendable minimum. A spend needs at
    /// least 2 layers so the on-chain `curve_trees_tree_depth` (layers − 1) is
    /// ≥ 1; the daemon rejects `curve_trees_tree_depth == 0` as out of range.
    #[error("FCMP++ layer count {layers} is below the spendable minimum of 2")]
    TreeTooShallow {
        /// The provided FCMP++ layer count (`< 2`).
        layers: u8,
    },

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

    /// The constructed transaction failed the construct-side CT balance
    /// self-check: the built pseudo-outputs + output masks do not satisfy the
    /// commitment-sum balance equation the daemon verifies. This is a local,
    /// fail-fast catch for a construction/masking bug that the cleartext
    /// funds-sufficiency check in `validate_inputs` cannot see (amounts correct,
    /// blinding factors don't balance on the curve) — caught before sign +
    /// broadcast rather than as a daemon rejection.
    #[error("construct-side CT balance self-check failed: {0}")]
    BalanceSelfCheck(#[from] shekyl_ct_balance::CtBalanceError),
}

/// What a [`TxBuilderError`] means to a wallet, bounded: the variant's
/// identity and its counts or input position, never the inner text a
/// crypto variant carries (which a caller logs locally). `Copy`, so it
/// crosses an actor boundary and reaches the wire as it is.
///
/// Four variants are the user's to act on; every other is an internal
/// invariant the build path should have made unreachable, named by
/// [`InternalSignFault::keyword`] so a report says which one failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SignFault {
    /// More inputs than one transaction may spend ([`MAX_INPUTS`]).
    #[error("{count} inputs exceed the limit of {MAX_INPUTS} per transaction")]
    TooManyInputs {
        /// How many inputs the build carried.
        count: usize,
    },
    /// More outputs than one transaction may carry ([`MAX_OUTPUTS`],
    /// the change output included).
    #[error("{count} outputs exceed the limit of {MAX_OUTPUTS} per transaction")]
    TooManyOutputs {
        /// How many outputs the build carried, change included.
        count: usize,
    },
    /// An input's assembled tree path does not hold the output it spends.
    #[error("input {input}: its tree path does not hold the output it spends")]
    SpentOutputNotInLeafChunk {
        /// The input's position in the transaction.
        input: usize,
    },
    /// An input's leaf on chain does not open to this wallet's keys: the
    /// output was received but can never be spent.
    #[error("input {input}: received but unspendable (its leaf is not this wallet's)")]
    PqcLeafMismatch {
        /// The input's position in the transaction.
        input: usize,
    },
    /// An internal invariant failed; [`InternalSignFault`] names which.
    #[error("internal signing fault: {}", .0.keyword())]
    Internal(InternalSignFault),
}

/// The [`TxBuilderError`] variants a build that passed the wallet's own
/// checks cannot reach: each is a bug, named and nothing more.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InternalSignFault {
    NoInputs,
    NoOutputs,
    TooFewOutputs,
    ZeroInputAmount,
    ZeroOutputAmount,
    InputAmountOverflow,
    OutputAmountOverflow,
    InsufficientFunds,
    EmptyLeafChunk,
    PqcLeafDerivation,
    LeafChunkTooLarge,
    ZeroTreeDepth,
    TreeTooShallow,
    TreeDepthTooLarge,
    BranchLayerMismatch,
    InvalidCombinedSsLength,
    BulletproofError,
    FcmpProveError,
    PqcSignError,
    WireError,
    BalanceSelfCheck,
}

impl InternalSignFault {
    /// Every internal fault, in declaration order.
    pub const ALL: [Self; 21] = [
        Self::NoInputs,
        Self::NoOutputs,
        Self::TooFewOutputs,
        Self::ZeroInputAmount,
        Self::ZeroOutputAmount,
        Self::InputAmountOverflow,
        Self::OutputAmountOverflow,
        Self::InsufficientFunds,
        Self::EmptyLeafChunk,
        Self::PqcLeafDerivation,
        Self::LeafChunkTooLarge,
        Self::ZeroTreeDepth,
        Self::TreeTooShallow,
        Self::TreeDepthTooLarge,
        Self::BranchLayerMismatch,
        Self::InvalidCombinedSsLength,
        Self::BulletproofError,
        Self::FcmpProveError,
        Self::PqcSignError,
        Self::WireError,
        Self::BalanceSelfCheck,
    ];

    /// The variant's name as one keyword, the closed set a report and the
    /// wire carry (`data.fault` on the wallet RPC's `-29119`).
    #[must_use]
    pub const fn keyword(self) -> &'static str {
        match self {
            Self::NoInputs => "no-inputs",
            Self::NoOutputs => "no-outputs",
            Self::TooFewOutputs => "too-few-outputs",
            Self::ZeroInputAmount => "zero-input-amount",
            Self::ZeroOutputAmount => "zero-output-amount",
            Self::InputAmountOverflow => "input-amount-overflow",
            Self::OutputAmountOverflow => "output-amount-overflow",
            Self::InsufficientFunds => "insufficient-funds",
            Self::EmptyLeafChunk => "empty-leaf-chunk",
            Self::PqcLeafDerivation => "pqc-leaf-derivation",
            Self::LeafChunkTooLarge => "leaf-chunk-too-large",
            Self::ZeroTreeDepth => "zero-tree-depth",
            Self::TreeTooShallow => "tree-too-shallow",
            Self::TreeDepthTooLarge => "tree-depth-too-large",
            Self::BranchLayerMismatch => "branch-layer-mismatch",
            Self::InvalidCombinedSsLength => "invalid-combined-ss-length",
            Self::BulletproofError => "bulletproof",
            Self::FcmpProveError => "fcmp-prove",
            Self::PqcSignError => "pqc-sign",
            Self::WireError => "wire",
            Self::BalanceSelfCheck => "balance-self-check",
        }
    }
}

impl TxBuilderError {
    /// This error's [`SignFault`]: its identity, bounded. Exhaustive, so a
    /// new variant decides here whether the user can act on it.
    #[must_use]
    pub const fn fault(&self) -> SignFault {
        use InternalSignFault as I;
        let internal = match self {
            Self::TooManyInputs(count) => return SignFault::TooManyInputs { count: *count },
            Self::TooManyOutputs(count) => return SignFault::TooManyOutputs { count: *count },
            Self::SpentOutputNotInLeafChunk { index } => {
                return SignFault::SpentOutputNotInLeafChunk { input: *index }
            }
            Self::PqcLeafMismatch { index } => return SignFault::PqcLeafMismatch { input: *index },
            Self::NoInputs => I::NoInputs,
            Self::NoOutputs => I::NoOutputs,
            Self::TooFewOutputs(_) => I::TooFewOutputs,
            Self::ZeroInputAmount { .. } => I::ZeroInputAmount,
            Self::ZeroOutputAmount { .. } => I::ZeroOutputAmount,
            Self::InputAmountOverflow => I::InputAmountOverflow,
            Self::OutputAmountOverflow => I::OutputAmountOverflow,
            Self::InsufficientFunds { .. } => I::InsufficientFunds,
            Self::EmptyLeafChunk { .. } => I::EmptyLeafChunk,
            Self::PqcLeafDerivation { .. } => I::PqcLeafDerivation,
            Self::LeafChunkTooLarge { .. } => I::LeafChunkTooLarge,
            Self::ZeroTreeDepth => I::ZeroTreeDepth,
            Self::TreeTooShallow { .. } => I::TreeTooShallow,
            Self::TreeDepthTooLarge(_) => I::TreeDepthTooLarge,
            Self::BranchLayerMismatch { .. } => I::BranchLayerMismatch,
            Self::InvalidCombinedSsLength { .. } => I::InvalidCombinedSsLength,
            Self::BulletproofError(_) => I::BulletproofError,
            Self::FcmpProveError(_) => I::FcmpProveError,
            Self::PqcSignError { .. } => I::PqcSignError,
            Self::WireError(_) => I::WireError,
            Self::BalanceSelfCheck(_) => I::BalanceSelfCheck,
        };
        SignFault::Internal(internal)
    }
}
