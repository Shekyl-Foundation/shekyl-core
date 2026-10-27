// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The staged admission rows, CEN-J29 through CEN-J37 (`SO-D12` increment 4a).
//!
//! Each type names the refusal the verifier already raises
//! ([`BundleInvalid::row`], [`SectionRefused::row`]). None adds a check, and
//! none is bound in the census registry: the rows stay `pending` until
//! increment 4b runs them from `validate`. The connect-path falsifier fails
//! if that call lands without the registry moving with it.

use crate::census::CenRow;
use crate::rules::Rule;

macro_rules! staged_row {
    ($name:ident, $row:ident) => {
        /// The staged type for this census row. Unbound until increment 4b.
        pub(crate) struct $name;

        impl Rule for $name {
            const ROW: CenRow = CenRow::$row;
        }
    };
}

staged_row!(J29, J29);
staged_row!(J30, J30);
staged_row!(J31, J31);
staged_row!(J32, J32);
staged_row!(J33, J33);
staged_row!(J34, J34);
staged_row!(J35, J35);
staged_row!(J36, J36);
staged_row!(J37, J37);

/// The nine types exist while unbound. The census names them; `validate`
/// does not construct them until increment 4b.
const _: (J29, J30, J31, J32, J33, J34, J35, J36, J37) =
    (J29, J30, J31, J32, J33, J34, J35, J36, J37);
