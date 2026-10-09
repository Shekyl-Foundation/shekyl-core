// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The basis a derived timing value rests on.
//!
//! Ruling B (`docs/design/DAEMON_RELAY_PRIVACY.md` §97, 2026-10-08): nothing
//! derived while C++ is in the path is valid for Rust. A derivation consumes
//! one of three bases, weakest first, and the value carries the weakest of
//! its inputs:
//!
//! - [`AdmissibleBasis::Assumption`] — written down, never measured;
//! - [`AdmissibleBasis::Model`] — a property of a rule the conformance suite
//!   measured;
//! - [`AdmissibleBasis::RustPath`] — measured on the Rust path.
//!
//! A C++-path reading is not a variant. [`DerivationMs`] has nowhere to put
//! it, and naming one does not compile:
//!
//! ```compile_fail,E0599
//! use shekyl_relay_privacy::basis::AdmissibleBasis;
//! let _ = AdmissibleBasis::CppPath;
//! ```
//!
//! The shipped hop's scheduling term is a C++-path claim of 0. It stays an
//! omission in [`crate::verify_cost::adopted_hop_ms`], not an input: this
//! type has no way to carry it, and the register says so.
//!
//! Outside this crate a value is built only by [`DerivationMs::assumption`],
//! [`DerivationMs::model`], or [`DerivationMs::rust_path`].
//! [`DerivationMs::derive`] is crate-private, so a caller cannot take an
//! admitted basis and attach it to some other number:
//!
//! ```compile_fail,E0624
//! use shekyl_relay_privacy::basis::DerivationMs;
//! let transit = DerivationMs::assumption(50);
//! let _ = transit.derived(715);
//! ```
//!
//! ```
//! use shekyl_relay_privacy::basis::{AdmissibleBasis, DerivationMs};
//! assert_eq!(DerivationMs::model(3_250).basis(), AdmissibleBasis::Model);
//! assert_eq!(DerivationMs::rust_path(40).ms(), 40);
//! assert_eq!(
//!     DerivationMs::assumption(50).basis(),
//!     AdmissibleBasis::Assumption
//! );
//! ```

/// Where a derived timing value's number came from.
///
/// Declared weakest first. [`Self::weaker`] is that order: an assumption
/// beside a measurement is an assumption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AdmissibleBasis {
    /// Never measured. Written down, and labelled as written down.
    Assumption,
    /// A conformance output: a property of a rule, not of an implementation.
    /// It transfers to Rust when a conformance test shows the Rust code
    /// implements that rule. It is not re-run.
    Model,
    /// Measured on the Rust path.
    RustPath,
}

impl AdmissibleBasis {
    /// The register's spelling of this basis.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Assumption => "Assumption",
            Self::Model => "Model",
            Self::RustPath => "RustPath",
        }
    }

    /// Weakest first: an assumption, then a model result, then a Rust-path
    /// measurement.
    const fn rank(self) -> u8 {
        match self {
            Self::Assumption => 0,
            Self::Model => 1,
            Self::RustPath => 2,
        }
    }

    /// The weaker of two bases.
    #[must_use]
    pub const fn weaker(self, other: Self) -> Self {
        if self.rank() <= other.rank() {
            self
        } else {
            other
        }
    }
}

/// Whole milliseconds a privacy-constant derivation may consume, with the
/// basis those milliseconds rest on.
///
/// Built outside this crate by [`Self::assumption`], [`Self::model`], or
/// [`Self::rust_path`]. Inside the crate a derivation builds one with
/// [`Self::derive`], which takes the weakest basis of its inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DerivationMs {
    ms: u32,
    basis: AdmissibleBasis,
}

impl DerivationMs {
    /// A labelled whole-millisecond value.
    #[must_use]
    pub const fn new(ms: u32, basis: AdmissibleBasis) -> Self {
        Self { ms, basis }
    }

    /// Written down, never measured.
    #[must_use]
    pub const fn assumption(ms: u32) -> Self {
        Self::new(ms, AdmissibleBasis::Assumption)
    }

    /// A model result.
    #[must_use]
    pub const fn model(ms: u32) -> Self {
        Self::new(ms, AdmissibleBasis::Model)
    }

    /// Measured on the Rust path.
    #[must_use]
    pub const fn rust_path(ms: u32) -> Self {
        Self::new(ms, AdmissibleBasis::RustPath)
    }

    /// The milliseconds.
    #[must_use]
    pub const fn ms(self) -> u32 {
        self.ms
    }

    /// The basis the value was built with.
    #[must_use]
    pub const fn basis(self) -> AdmissibleBasis {
        self.basis
    }

    /// A value a derivation inside this crate produced from `inputs`. It
    /// takes the weakest of them ([`AdmissibleBasis::weaker`]): the hop is a
    /// Rust-path verification floor plus an assumed transit, and it reads as
    /// an assumption.
    ///
    /// Crate-private on purpose. A public version would attach any admissible
    /// basis to any number.
    ///
    /// # Panics
    ///
    /// With no inputs. A derivation names what it rests on.
    #[must_use]
    pub(crate) const fn derive(ms: u32, inputs: &[AdmissibleBasis]) -> Self {
        assert!(!inputs.is_empty(), "a derived value names its inputs");
        let mut basis = inputs[0];
        let mut i = 1;
        while i < inputs.len() {
            basis = basis.weaker(inputs[i]);
            i += 1;
        }
        Self::new(ms, basis)
    }

    /// This basis on a new number. Its only callers are the sensitivity
    /// probes below, so it is built with them; a shipped build derives
    /// through [`Self::derive`] alone.
    #[cfg(any(test, feature = "conformance"))]
    #[must_use]
    pub(crate) const fn derived(self, ms: u32) -> Self {
        Self::derive(ms, &[self.basis])
    }

    /// `self` plus `extra` milliseconds, with the same basis, or `None` on
    /// overflow. For the sensitivity probes only: the conformance instrument
    /// steps a derived value to find the next embargo step. Not in a shipped
    /// build.
    #[cfg(any(test, feature = "conformance"))]
    #[must_use]
    pub(crate) const fn checked_add_ms(self, extra: u32) -> Option<Self> {
        match self.ms.checked_add(extra) {
            Some(ms) => Some(self.derived(ms)),
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_labels_are_the_register_spellings() {
        assert_eq!(AdmissibleBasis::Assumption.label(), "Assumption");
        assert_eq!(AdmissibleBasis::Model.label(), "Model");
        assert_eq!(AdmissibleBasis::RustPath.label(), "RustPath");
    }

    #[test]
    fn a_value_keeps_the_number_and_the_basis_it_was_built_with() {
        let assumed = DerivationMs::assumption(1_625);
        assert_eq!(assumed.ms(), 1_625);
        assert_eq!(assumed.basis(), AdmissibleBasis::Assumption);
        assert_eq!(DerivationMs::model(3_250).basis(), AdmissibleBasis::Model);
        assert_eq!(DerivationMs::rust_path(40).ms(), 40);
    }

    #[test]
    fn a_probe_keeps_its_basis_when_the_number_moves() {
        let transit = DerivationMs::rust_path(40);
        let hop = transit.derived(165);
        assert_eq!((hop.ms(), hop.basis()), (165, AdmissibleBasis::RustPath));
        assert_eq!(hop.checked_add_ms(10), Some(transit.derived(175)));
        assert_eq!(hop.checked_add_ms(u32::MAX), None);
    }

    #[test]
    fn a_derived_value_takes_the_weakest_basis_of_its_inputs() {
        use AdmissibleBasis::{Assumption, Model, RustPath};
        assert_eq!(
            DerivationMs::derive(1, &[RustPath, Assumption]).basis(),
            Assumption
        );
        assert_eq!(
            DerivationMs::derive(1, &[Assumption, RustPath]).basis(),
            Assumption
        );
        assert_eq!(DerivationMs::derive(1, &[RustPath, Model]).basis(), Model);
        assert_eq!(
            DerivationMs::derive(1, &[Model, Assumption]).basis(),
            Assumption
        );
        assert_eq!(DerivationMs::derive(1, &[RustPath]).basis(), RustPath);
        assert_eq!(RustPath.weaker(Model), Model);
        assert_eq!(Model.weaker(Assumption), Assumption);
    }
}
