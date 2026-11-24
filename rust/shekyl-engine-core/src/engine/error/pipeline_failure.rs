// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! How an assembly pipeline carries a failure.
//!
//! [`BondAssemblyError::build`](crate::engine::bond_assembly::BondAssemblyError::build)
//! and [`DrainAssemblyError::build`](crate::engine::drain_assembly::DrainAssemblyError::build)
//! are the one constructor each pipeline calls. A type that can be a signer's
//! refusal says so here. Every other failure is a rendered pipeline detail.
//! There is no `impl<T: Display>`: that blanket is how a [`TxBuilderError`]
//! became an internal `-32603` again, the compiler unable to prefer the
//! signer's fault over `to_string()`.

use shekyl_tx_builder::{SignFault, TxBuilderError};

use super::key::KeyEngineError;

/// A failure split into the signer's fault, when it is one, and the text a
/// log or a pipeline-detail arm carries. The text is public error wording,
/// never key material.
pub(crate) struct CarriedFailure {
    /// Set when this failure is the signer's bounded fault.
    pub fault: Option<SignFault>,
    /// The failure's own rendering.
    pub detail: String,
}

/// What an assembly step's error is, to the bond and drain pipelines.
pub(crate) trait PipelineFailure {
    /// Split `self` into a signer fault or a pipeline detail.
    fn carry(self) -> CarriedFailure;
}

impl CarriedFailure {
    /// `Signer` keeps the fault. `Pipeline` is the detail arm's stage and text.
    /// A signer fault is logged here, once, for both pipelines.
    pub(crate) fn classify(self, stage: &'static str, family: &'static str) -> ClassifiedFailure {
        match self.fault {
            Some(fault) => {
                tracing::debug!(
                    stage,
                    family,
                    error = %self.detail,
                    "the signer refused the spend"
                );
                ClassifiedFailure::Signer(fault)
            }
            None => ClassifiedFailure::Pipeline {
                stage,
                detail: self.detail,
            },
        }
    }
}

/// [`CarriedFailure::classify`]'s result: the arm an assembly error stores.
pub(crate) enum ClassifiedFailure {
    /// The signer refused. The fault reaches the wallet RPC unchanged.
    Signer(SignFault),
    /// A pipeline step failed. `detail` is its rendering.
    Pipeline {
        /// The step that failed.
        stage: &'static str,
        /// Rendered cause.
        detail: String,
    },
}

impl PipelineFailure for TxBuilderError {
    fn carry(self) -> CarriedFailure {
        let detail = self.to_string();
        CarriedFailure {
            fault: Some(self.fault()),
            detail,
        }
    }
}

impl PipelineFailure for KeyEngineError {
    fn carry(self) -> CarriedFailure {
        match self {
            Self::Sign(fault) => CarriedFailure {
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

/// A failure that is never the signer's. Naming it here is what lets it cross
/// [`PipelineFailure`]; a type with no impl cannot be
/// stringified by accident, and a type that *is* a signer fault must not be
/// added to this list.
macro_rules! pipeline_detail {
    ($($ty:ty),+ $(,)?) => {$(
        impl crate::engine::error::PipelineFailure for $ty {
            fn carry(self) -> crate::engine::error::CarriedFailure {
                crate::engine::error::CarriedFailure {
                    fault: None,
                    detail: self.to_string(),
                }
            }
        }
    )+};
}
pub(crate) use pipeline_detail;

pipeline_detail!(
    String,
    &str,
    shekyl_crypto_pq::CryptoError,
    shekyl_crypto_pq::tx_key::RandomnessUnavailable,
    shekyl_tx_builder::outputs::BuildSpendError,
    tokio::task::JoinError,
);
