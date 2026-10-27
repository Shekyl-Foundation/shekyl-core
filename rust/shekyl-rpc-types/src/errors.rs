// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The error registry (`RPC_WIRE.md` RW-Q3).
//!
//! A failure is only ever the JSON-RPC error object. Its numeric code is a
//! class a client branches on, and its `data` carries one typed diagnostic:
//! a stable dotted code, its parameters, and one English rendering (IG-11).
//!
//! The registry is closed: a code not here is not one this daemon sends.
//! Bad params and internal faults take JSON-RPC's own reserved codes; the
//! other classes sit in its server-error range. The codes the C++ server
//! carried (`-1` … `-26`) remain on the methods that still answer through
//! it, until the rename at `CORE_RPC_VERSION` 4.0 (RW-Q8).

use serde::{Deserialize, Serialize};

/// What kind of failure an error is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorClass {
    /// The request's parameters do not parse, or name nothing.
    BadParams,
    /// The method understood the request and declines it.
    RefusedByMethod,
    /// The caller's grant does not cover the method, or the method is an
    /// armed lever the daemon was not started armed for.
    OutsideTheGrant,
    /// The request asks for more than one request may.
    OverResourceBound,
    /// The node cannot answer yet; asking again later may succeed.
    NotReady,
    /// The node's store faulted while answering.
    StoreFault,
    /// Anything else: a defect in the node.
    Internal,
}

impl ErrorClass {
    /// Every class, in registry order.
    pub const ALL: [Self; 7] = [
        Self::BadParams,
        Self::RefusedByMethod,
        Self::OutsideTheGrant,
        Self::OverResourceBound,
        Self::NotReady,
        Self::StoreFault,
        Self::Internal,
    ];

    /// The class's code on the wire.
    #[must_use]
    pub const fn code(self) -> i64 {
        match self {
            Self::BadParams => -32_602,
            Self::RefusedByMethod => -32_001,
            Self::OutsideTheGrant => -32_002,
            Self::OverResourceBound => -32_003,
            Self::NotReady => -32_004,
            Self::StoreFault => -32_005,
            Self::Internal => -32_603,
        }
    }

    /// The class a wire code names, if it names one.
    #[must_use]
    pub fn of_code(code: i64) -> Option<Self> {
        Self::ALL.into_iter().find(|class| class.code() == code)
    }
}

/// The typed diagnostic an error's `data` carries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Diagnostic {
    /// The stable dotted code, such as `mine.no_address`.
    pub code: String,
    /// The named facts the message is built from, in a stable order.
    pub params: Vec<(String, String)>,
    /// The one English rendering.
    pub message: String,
}

impl Diagnostic {
    /// A diagnostic with no parameters yet.
    #[must_use]
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            params: Vec::new(),
            message: message.into(),
        }
    }

    /// Adds a named parameter.
    #[must_use]
    pub fn param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.params.push((key.into(), value.into()));
        self
    }
}

/// A failure as the wire carries it: the class, and the diagnostic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpcError {
    /// The class: the error object's `code`.
    pub class: ErrorClass,
    /// The diagnostic: the error object's `data`, and its `message`.
    pub diagnostic: Diagnostic,
}

impl RpcError {
    /// A failure of `class` with `diagnostic`.
    #[must_use]
    pub const fn new(class: ErrorClass, diagnostic: Diagnostic) -> Self {
        Self { class, diagnostic }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_class_has_its_own_code_and_reads_back() {
        let mut codes = std::collections::BTreeSet::new();
        for class in ErrorClass::ALL {
            assert!(codes.insert(class.code()), "{class:?} shares a code");
            assert_eq!(ErrorClass::of_code(class.code()), Some(class));
        }
        assert_eq!(
            ErrorClass::of_code(-26),
            None,
            "the C++ codes are not classes"
        );
    }

    /// JSON-RPC 2.0 reserves -32602 and -32603 for these two meanings, and
    /// -32000 to -32099 for the server's own.
    #[test]
    fn the_codes_sit_where_json_rpc_reserves_them() {
        assert_eq!(ErrorClass::BadParams.code(), -32_602);
        assert_eq!(ErrorClass::Internal.code(), -32_603);
        for class in [
            ErrorClass::RefusedByMethod,
            ErrorClass::OutsideTheGrant,
            ErrorClass::OverResourceBound,
            ErrorClass::NotReady,
            ErrorClass::StoreFault,
        ] {
            assert!((-32_099..=-32_000).contains(&class.code()), "{class:?}");
        }
    }
}
