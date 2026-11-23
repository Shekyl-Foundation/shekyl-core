// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The bond-assembly path's error vocabulary (§3.6, rule 82), the `#[path]`
//! sibling of `bond_assembly.rs`, which re-exports it: carved out so the
//! assembly file stays under the decomposition ratchet's `NEW_FILE_CAP`
//! (`scripts/ci/engine_decomposition_ratchet.conf`).

use crate::engine::error::{CarriedFailure, ClassifiedFailure, PipelineFailure};

/// Failure surface of the bond-assembly path (`ARCHIVAL_BOND_WI2_ASSEMBLY.md`
/// §3.6). Every arm names its operator-facing disposition: refusals are
/// caller-recoverable states, defects are fail-closed build errors.
#[derive(Debug, thiserror::Error)]
pub(crate) enum BondAssemblyError {
    /// The persona's spendable funding set (unreserved, scan-discovered
    /// outputs) sums below the bond floor + fee. Fund-from-earnings ramp
    /// (`ARCHIVAL_TIMING_CONSTANTS.md` §7): the caller waits for more
    /// earnings; there is **no** reach-across to principal outputs (that
    /// reach-across is the funding-seam linkage the architecture firewalls).
    #[error(
        "insufficient P-side funding: {available} available < {required} required; \
         the persona funds bonds from its own earnings — wait for further accrual"
    )]
    InsufficientFunding {
        /// Sum of the unreserved spendable records.
        available: u64,
        /// `bond_floor(holdings) + fee`.
        required: u64,
    },

    /// The persona's eligible funding set is **empty** at the sweep's
    /// reference height: nothing discovered, or everything is immature or
    /// reserved by in-flight posts. Structurally distinct from
    /// [`Self::InsufficientFunding`] (records exist but sum short —
    /// including all-zero-amount records, a representable CT state): the
    /// remedies differ, and the claim path maps only *this* arm to its
    /// structural no-fee-input refusal.
    #[error(
        "no spendable P-side funding outputs at the reference height: none discovered, \
         or all are immature or reserved by in-flight posts; fund the persona or wait \
         for maturity/confirmation"
    )]
    NoSpendableFunding,

    /// The eligible funding set exceeds the per-transaction vin headroom
    /// ([`MAX_RETENTION_FUNDING_INPUTS`](super::MAX_RETENTION_FUNDING_INPUTS):
    /// the consensus vin cap minus the one non-funding vin this transaction
    /// carries) and the caller's sweep semantics forbid a silent subset
    /// ([`SweepOverflowPolicy::RefuseTooMany`](super::SweepOverflowPolicy::RefuseTooMany)).
    /// Raised BEFORE assembly, so a transaction every public network would
    /// reject is never built —
    /// FAKECHAIN does not enforce the cap, so an e2e cannot catch this. The
    /// funding is intact and spendable; what does not exist yet is a
    /// consolidation path for a pool this fragmented (the drain lane
    /// consolidates `P`-funding in capped passes).
    #[error(
        "too many spendable funding outputs for one transaction: {count} eligible, \
         max {max} (the transaction carries one non-funding input of its own); \
         the funding is intact — consolidate before retrying"
    )]
    TooManyFundingInputs {
        /// How many records were eligible at the reference height.
        count: usize,
        /// The per-transaction funding-input headroom.
        max: usize,
    },

    /// The presented input set carries **no funding input at all** — a
    /// structural shape refusal, not a shortfall. The rule belongs to
    /// [`bond_post_funding_floor_met`](shekyl_archival_retention::bond_post::bond_post_funding_floor_met):
    /// a bond post carries at least one real `txin_to_key` spend input, checked
    /// before any amount rule. This arm is what the producer raises when that
    /// predicate says no — the condition is not restated here.
    ///
    /// Distinct from [`Self::NoSpendableFunding`], which names what the *sweep*
    /// found eligible at its reference height. This arm is about the set a
    /// caller actually presented — and it is the exit path that needs it,
    /// because there the amount rules cannot see the difference: released
    /// collateral alone covers the fee, so both the sufficiency check and the
    /// balance equation close with an empty funding vector.
    #[error(
        "the transaction carries no funding input: consensus requires at least one \
         txin_to_key spend input on a bond post"
    )]
    FundingInputsRequired,

    /// A live pending post already exists for this persona. JoinMarket-only
    /// at genesis: one live post per persona (§3.5); the caller waits for the
    /// pending post to confirm or fail before re-assembling.
    #[error("a pending bond post already exists for this persona; one live post per persona")]
    PendingPostExists,

    /// This post's funding inputs are no longer selectable, for either of the
    /// two reasons the seal-time re-check can find:
    ///
    /// - a concurrent **claim or drain** now reserves one of them
    ///   (`SealAdmission::InputRaced`); or
    /// - a reservation was **released** between the pre-assembly snapshot and
    ///   the seal (`SealAdmission::Stale`), so the set this assembly selected
    ///   against no longer describes the wallet — the released record may have
    ///   confirmed and spent an input this post still believes is fundable.
    ///
    /// Both refuse **before** sealing, so no doomed record is left behind, and
    /// both take the same remedy: retry against a current snapshot. One variant
    /// because one remedy; the message names both causes because naming only
    /// one sends a caller looking for a collision that may not exist.
    #[error(
        "this post's funding inputs are no longer current — another live record \
         holds one, or a reservation was released mid-assembly; retry"
    )]
    InputRaced,

    /// The post's seal was saved, but the save was not confirmed on disk,
    /// so the seal was removed: nothing will be sent, and the stake is
    /// retried once the save's cause is fixed (Rick, 2026-11-19).
    #[error("the bond post was not sealed: {0}")]
    SealNotSaved(#[source] crate::engine::error::PersistenceError),

    /// The curve-tree / ledger anchoring procedure could not produce a
    /// submittable [`ReferenceBlock`](shekyl_curve_tree::ReferenceBlock)
    /// (tree too far behind, ingest missing, ledger hash missing, chain too
    /// short). Loud resync — never a silent path fail (WI-2 F-6).
    #[error("bond reference unavailable: {detail}; resync")]
    ReferenceResyncing {
        /// Operator-facing detail naming which arm of the anchoring gate fired.
        detail: &'static str,
    },

    /// A swept record cleared the spendability filter but has no drained
    /// leaf in the REFERENCE tree yet (the reference lags tip by
    /// `REF_ANCHOR_AGE`, so a freshly-matured output can be spendable at
    /// tip and absent at the reference) — the one path-assembly refusal
    /// that is wait-and-retry, not a defect. Typed so retry policy (the
    /// regtest harness today, production retry logic later) matches on the
    /// variant instead of substring-scanning a rendered
    /// `ClientError::OutputNotDrained`.
    #[error(
        "funding output (gindex {gindex}) is not yet drained into the reference tree; \
         wait for the tree to catch up and retry"
    )]
    OutputNotYetDrained {
        /// The global output index the reference tree has no leaf for.
        gindex: u64,
    },

    /// The funding arithmetic (`floor + fee`, change split, balance rule)
    /// overflowed u64 — unreachable with consensus-bounded amounts; fail
    /// closed rather than wrap.
    #[error("funding amount arithmetic overflowed")]
    AmountOverflow,

    /// `bond_floor(holdings)` is zero — structurally invalid holdings (empty
    /// / zero-count descriptor). Same refusal the wire builder and retention
    /// verifier raise (`BondBuildError::BondFloorZero`); refuse before sweep
    /// so a zero-`required` never reaches `assemble_tx` as an empty path set.
    #[error("bond_floor(holdings) is zero; holdings are structurally invalid")]
    BondFloorZero,

    /// A cryptographic step of the assemble pipeline failed (spend-bundle
    /// derivation, output construction, proving, PQC auth signing, or wire
    /// encoding). `stage` names the pipeline step; `detail` is the wrapped
    /// error's rendering (public error text — never key material). Nothing
    /// was persisted (§3.6: no partial state, funding never reserved).
    #[error("bond assembly failed at {stage}: {detail}")]
    Build {
        /// Pipeline step that failed.
        stage: &'static str,
        /// Rendered cause.
        detail: String,
    },

    /// The signer refused the spend, with its own bounded fault, which
    /// reaches the wallet RPC as it does for a transfer. Nothing was
    /// persisted (§3.6).
    #[error("the signer refused the spend: {0}")]
    Signer(shekyl_tx_builder::SignFault),
}

impl BondAssemblyError {
    /// The one constructor for a step that failed. A signer refusal keeps its
    /// [`SignFault`](shekyl_tx_builder::SignFault); every other failure is the
    /// [`Build`](Self::Build) arm. The type of `err` decides which
    /// ([`PipelineFailure`](crate::engine::error::PipelineFailure)), so a
    /// [`TxBuilderError`](shekyl_tx_builder::TxBuilderError) cannot be
    /// stringified into an internal fault.
    pub(crate) fn build(stage: &'static str, err: impl PipelineFailure) -> Self {
        match err.carry().classify(stage, "bond") {
            ClassifiedFailure::Signer(fault) => Self::Signer(fault),
            ClassifiedFailure::Pipeline { stage, detail } => Self::Build { stage, detail },
        }
    }
}

// Store and wire errors the bond pipeline renders. They are not signer
// faults. Named here, beside the constructor, so the error module does not
// depend on the stores that already depend on it.
crate::engine::error::pipeline_detail!(
    crate::engine::pscan::start::WalletFilePendingStoreError,
    crate::engine::pscan::start::WalletFilePScanStoreError,
    crate::engine::pscan::block_source::BlockSourceError,
    shekyl_archival_retention::EmissionWireError,
);

impl PipelineFailure for BondAssemblyError {
    fn carry(self) -> CarriedFailure {
        match self {
            Self::Signer(fault) => CarriedFailure {
                fault: Some(fault),
                detail: fault.to_string(),
            },
            other => CarriedFailure {
                fault: None,
                detail: other.to_string(),
            },
        }
    }
}
