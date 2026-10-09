// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Where a timing value's number came from.
//!
//! Ruling B (`docs/design/DAEMON_RELAY_PRIVACY.md` §97, 2026-10-08): nothing
//! derived while C++ is in the path is valid for Rust. A timing value is one
//! of four things, and the register in that section lists every value this
//! crate and `shekyl-transport-layer` carry, with its basis:
//!
//! - a **model** result, a property of a rule the conformance suite measured;
//! - a value measured or derived on the **C++ path**, which is re-measured on
//!   the Rust path before anything is derived from it;
//! - a value measured on the **Rust path**;
//! - an **assumption** nobody has measured, written down and labelled as one.
//!
//! [`crate::verify_cost::Provenance`] and [`crate::verify_cost::TreeBasis`]
//! already label where a verification cost came from (§81.2). This module is
//! the same idea for time, with one addition: a privacy-constant derivation
//! consumes [`DerivationMs`], and that type is built only from a
//! [`Timing`] whose basis implements [`DerivationInput`]. [`CppPath`] does
//! not. The refusal is the compiler's, not a comment's:
//!
//! ```compile_fail
//! use shekyl_relay_privacy::basis::{CppPath, DerivationMs, Timing};
//! let measured_on_cpp: Timing<CppPath> = Timing::new(715.0);
//! let _ = DerivationMs::admit(measured_on_cpp);
//! ```
//!
//! and the admissible three compile:
//!
//! ```
//! use shekyl_relay_privacy::basis::{Assumption, DerivationMs, Model, RustPath, Timing, TimingBasis};
//! assert_eq!(DerivationMs::admit(Timing::<Model>::new(3_250.0)).basis(), TimingBasis::Model);
//! assert_eq!(DerivationMs::admit(Timing::<RustPath>::new(40.0)).ms(), 40);
//! assert_eq!(DerivationMs::admit(Timing::<Assumption>::new(50.0)).basis(), TimingBasis::Assumption);
//! ```

use core::marker::PhantomData;

/// Where a timing value's number came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimingBasis {
    /// A conformance output: a property of a rule, not of an implementation.
    /// It transfers to Rust when a conformance test shows the Rust code
    /// implements that rule. It is not re-run.
    Model,
    /// Measured, or derived from a measurement, with C++ in the path. The C++
    /// carries defects that distort timing (dials on the two-worker io pool;
    /// the post-handshake cause race), so this is not a reference. It is
    /// re-measured on the Rust path, and nothing is derived from it until
    /// then.
    CppPath,
    /// Measured on the Rust path.
    RustPath,
    /// Never measured. Written down, and labelled as written down.
    Assumption,
}

impl TimingBasis {
    /// The register's spelling of this basis.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Model => "Model",
            Self::CppPath => "CppPath",
            Self::RustPath => "RustPath",
            Self::Assumption => "Assumption",
        }
    }

    /// Whether a privacy-constant derivation may consume a value with this
    /// basis. The same answer as the type system gives through
    /// [`DerivationInput`], for a reader holding the enum.
    #[must_use]
    pub const fn admissible(self) -> bool {
        !matches!(self, Self::CppPath)
    }
}

/// A basis at the type level, so a function's bound can name it.
pub trait Basis: Copy {
    /// The enum value this marker stands for.
    const BASIS: TimingBasis;
}

/// A basis a privacy-constant derivation may consume.
///
/// [`Model`], [`RustPath`] and [`Assumption`] implement it. [`CppPath`]
/// does not, and that absence is the mechanism: a `Timing<CppPath>` has no
/// path into [`DerivationMs`].
pub trait DerivationInput: Basis {}

/// [`TimingBasis::Model`] as a type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Model;
/// [`TimingBasis::CppPath`] as a type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct CppPath;
/// [`TimingBasis::RustPath`] as a type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct RustPath;
/// [`TimingBasis::Assumption`] as a type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Assumption;

impl Basis for Model {
    const BASIS: TimingBasis = TimingBasis::Model;
}
impl Basis for CppPath {
    const BASIS: TimingBasis = TimingBasis::CppPath;
}
impl Basis for RustPath {
    const BASIS: TimingBasis = TimingBasis::RustPath;
}
impl Basis for Assumption {
    const BASIS: TimingBasis = TimingBasis::Assumption;
}

impl DerivationInput for Model {}
impl DerivationInput for RustPath {}
impl DerivationInput for Assumption {}

/// Milliseconds with their basis in the type.
///
/// This is what a constant is declared as. The number is the number; the
/// type parameter says where it came from, so a reader at the use site sees
/// the basis without opening the doc comment.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Timing<B: Basis> {
    ms: f64,
    basis: PhantomData<B>,
}

impl<B: Basis> Timing<B> {
    /// A labelled value.
    #[must_use]
    pub const fn new(ms: f64) -> Self {
        Self {
            ms,
            basis: PhantomData,
        }
    }

    /// The milliseconds.
    #[must_use]
    pub const fn ms(self) -> f64 {
        self.ms
    }

    /// The basis, as the enum.
    #[must_use]
    pub const fn basis(self) -> TimingBasis {
        B::BASIS
    }
}

/// Whole milliseconds a privacy-constant derivation may consume.
///
/// Built only by [`DerivationMs::admit`], whose bound excludes
/// [`CppPath`]. The basis travels with the value so the derivation's output
/// can say what it rests on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DerivationMs {
    ms: u32,
    basis: TimingBasis,
}

impl DerivationMs {
    /// Admit a labelled value to derivation.
    ///
    /// Only a `Timing<B>` with `B: DerivationInput` is accepted; passing a
    /// `Timing<CppPath>` does not compile.
    ///
    /// # Panics
    ///
    /// When `ms` is not a whole number of milliseconds representable as
    /// `u32`. The embargo tables are keyed by whole milliseconds, and no
    /// shipped transit has been fractional; a fractional value here is a
    /// new constant that needs its own row, not a rounding.
    #[must_use]
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        clippy::cast_lossless,
        clippy::float_cmp
    )]
    pub const fn admit<B: DerivationInput>(timing: Timing<B>) -> Self {
        let whole = timing.ms as u32;
        assert!(
            timing.ms == whole as f64,
            "a derivation input is a whole number of milliseconds"
        );
        Self {
            ms: whole,
            basis: B::BASIS,
        }
    }

    /// The milliseconds.
    #[must_use]
    pub const fn ms(self) -> u32 {
        self.ms
    }

    /// The basis the value was admitted with.
    #[must_use]
    pub const fn basis(self) -> TimingBasis {
        self.basis
    }

    /// A value derived from this one, carrying the basis this one was
    /// admitted with. The derivation that produced `ms` consumed an admitted
    /// input, so the result rests on nothing a derivation may not consume;
    /// this is how `time_between_hop_ms` keeps the transit's basis.
    #[must_use]
    pub const fn derived(self, ms: u32) -> Self {
        Self {
            ms,
            basis: self.basis,
        }
    }

    /// `self` plus `extra` milliseconds, with the same basis, or `None` on
    /// overflow. For sensitivity probes that step a derived value.
    #[must_use]
    pub const fn checked_add_ms(self, extra: u32) -> Option<Self> {
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
    fn the_enum_and_the_markers_agree_on_which_bases_derive() {
        assert_eq!(Model::BASIS, TimingBasis::Model);
        assert_eq!(CppPath::BASIS, TimingBasis::CppPath);
        assert_eq!(RustPath::BASIS, TimingBasis::RustPath);
        assert_eq!(Assumption::BASIS, TimingBasis::Assumption);
        for basis in [
            TimingBasis::Model,
            TimingBasis::RustPath,
            TimingBasis::Assumption,
        ] {
            assert!(
                basis.admissible(),
                "{} is a derivation input",
                basis.label()
            );
        }
        assert!(!TimingBasis::CppPath.admissible());
    }

    #[test]
    fn an_admitted_value_keeps_its_number_and_its_basis() {
        let admitted = DerivationMs::admit(Timing::<Assumption>::new(1_625.0));
        assert_eq!(admitted.ms(), 1_625);
        assert_eq!(admitted.basis(), TimingBasis::Assumption);
        assert_eq!(Timing::<Model>::new(3_250.0).basis(), TimingBasis::Model);
    }

    #[test]
    fn a_derived_value_carries_the_basis_it_was_derived_from() {
        let transit = DerivationMs::admit(Timing::<RustPath>::new(40.0));
        let hop = transit.derived(165);
        assert_eq!((hop.ms(), hop.basis()), (165, TimingBasis::RustPath));
        assert_eq!(hop.checked_add_ms(10), Some(transit.derived(175)));
        assert_eq!(hop.checked_add_ms(u32::MAX), None);
    }

    #[test]
    #[should_panic(expected = "whole number of milliseconds")]
    fn a_fractional_input_is_refused_rather_than_rounded() {
        let admitted = DerivationMs::admit(Timing::<Model>::new(49.5));
        unreachable!("49.5 ms was admitted as {} ms", admitted.ms());
    }
}
