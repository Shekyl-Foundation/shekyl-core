// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The error registry (`RPC_WIRE.md` RW-Q3).
//!
//! A failure is only ever the JSON-RPC error object. Its numeric code is a
//! class a client branches on, and its `data` carries one typed diagnostic
//! (a stable dotted code, its parameters, and one English rendering, IG-11)
//! or, for a configuration refusal, the list of those diagnostics.
//!
//! The registry is closed: a code not here is not one this daemon sends.
//! Bad params and internal faults take JSON-RPC's own reserved codes; the
//! other classes sit in its server-error range. A name that is no method is
//! JSON-RPC's own method-not-found ([`METHOD_NOT_FOUND`]), which is not a
//! class: the call never reached a method.
//!
//! Each refusal's diagnostic code is dotted (`INPUT_GRAMMAR.md` IG-Q86): its
//! first segment names what refused, a glossary subject, or `grant` or
//! `bound` for the two classes no method owns. A client branches on the
//! class and the code, never on the English.

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

    /// The name a person reads. This is the contract; [`Debug`] is not.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::BadParams => "BadParams",
            Self::RefusedByMethod => "RefusedByMethod",
            Self::OutsideTheGrant => "OutsideTheGrant",
            Self::OverResourceBound => "OverResourceBound",
            Self::NotReady => "NotReady",
            Self::StoreFault => "StoreFault",
            Self::Internal => "Internal",
        }
    }
}

/// JSON-RPC's own code for a name that is no method (an old name, an
/// alias, a path). Not an [`ErrorClass`]: the call never reached a method.
pub use crate::endpoint::METHOD_NOT_FOUND;

/// The typed diagnostic an error's `data` carries (IG-11), and a reply's
/// `cause` where a state is explained (`mine_status`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Diagnostic {
    /// The stable dotted code, such as `mine.address.unset`.
    pub code: String,
    /// The named facts the message is built from (IG-F20: a map, each name
    /// once).
    pub parameter: std::collections::BTreeMap<String, String>,
    /// The one English rendering.
    pub message: String,
}

impl crate::schema::Schema for Diagnostic {
    fn shape() -> crate::schema::Shape {
        use crate::schema::{Field, Shape};
        let field = |name, shape| Field {
            name,
            under: None,
            shape,
        };
        Shape::Object {
            holder: "diagnostic",
            fields: vec![
                field("code", Shape::Scalar("text")),
                field(
                    "parameter",
                    Shape::Map {
                        keys: None,
                        value: Box::new(Shape::Scalar("text")),
                    },
                ),
                field("message", Shape::Scalar("text")),
            ],
            parts: Vec::new(),
            choice: Vec::new(),
        }
    }
}

impl Diagnostic {
    /// A diagnostic with no parameters yet.
    #[must_use]
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            parameter: std::collections::BTreeMap::new(),
            message: message.into(),
        }
    }

    /// Adds a named parameter. A name given twice keeps the last value.
    #[must_use]
    pub fn param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.parameter.insert(key.into(), value.into());
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

    /// The line a person reads: the class's name and the diagnostic's code.
    ///
    /// The English rendering stays on [`Diagnostic::message`]. It is for a
    /// log, never for this line, and never what a caller matches.
    #[must_use]
    pub fn report(&self) -> String {
        format!("{} {}", self.class.name(), self.diagnostic.code)
    }
}

/// Read a JSON-RPC `error` object.
///
/// The class comes from the numeric code ([`ErrorClass::of_code`]), and
/// `data` is a [`Diagnostic`] or a list of configuration
/// [`crate::options::Refusal`]s. An object with no class, or no readable
/// diagnostic, is not one this daemon sends: `None`.
#[must_use]
pub fn read_error_object(error: &serde_json::Value) -> Option<RpcError> {
    let class = ErrorClass::of_code(error.get("code")?.as_i64()?)?;
    let diagnostic = diagnostic_from_data(error.get("data")?)?;
    Some(RpcError { class, diagnostic })
}

/// Whether a JSON-RPC `error` object is method-not-found.
#[must_use]
pub fn is_method_not_found(error: &serde_json::Value) -> bool {
    error.get("code").and_then(serde_json::Value::as_i64) == Some(METHOD_NOT_FOUND)
}

/// One diagnostic, or the configuration-refusal list `option_set` carries
/// in `data`. Every code in the list is kept: a reader that takes only the
/// object's `message` loses the stable codes.
fn diagnostic_from_data(data: &serde_json::Value) -> Option<Diagnostic> {
    if let Ok(one) = serde_json::from_value::<Diagnostic>(data.clone()) {
        return Some(one);
    }
    let refusals = serde_json::from_value::<Vec<crate::options::Refusal>>(data.clone()).ok()?;
    if refusals.is_empty() {
        return None;
    }
    let code = refusals
        .iter()
        .map(|refusal| refusal.code.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let message = refusals
        .iter()
        .map(|refusal| refusal.message.as_str())
        .collect::<Vec<_>>()
        .join("; ");
    let mut diagnostic = Diagnostic::new(code, message);
    diagnostic.parameter.clone_from(&refusals[0].parameter);
    Some(diagnostic)
}

/// The refusal in a JSON body, when the body is a JSON-RPC error object.
#[must_use]
pub fn read_refusal(body: &[u8]) -> Option<RpcError> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    read_error_object(value.get("error")?)
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
        for retired in [-1, -2, -5, -9, -19, -22, -24, -25, -26] {
            assert_eq!(
                ErrorClass::of_code(retired),
                None,
                "{retired} is not a class"
            );
        }
        assert_eq!(ErrorClass::of_code(METHOD_NOT_FOUND), None);
    }

    /// The operator line is the class name and the code. The English
    /// rendering is not part of it, so a caller cannot match on prose.
    #[test]
    fn the_operator_line_is_the_class_and_the_code() {
        let refusal = RpcError::new(
            ErrorClass::OutsideTheGrant,
            Diagnostic::new("rpc.grant", "english the operator must not see"),
        );
        assert_eq!(refusal.report(), "OutsideTheGrant rpc.grant");
        assert_eq!(refusal.class.name(), "OutsideTheGrant");
    }

    /// `option_set` carries `data` as a list of configuration refusals.
    /// Reading that list as one diagnostic loses every stable code.
    #[test]
    fn a_configuration_refusal_list_keeps_every_code() {
        let error = serde_json::json!({
            "code": ErrorClass::RefusedByMethod.code(),
            "message": "english the caller must not match",
            "data": [{
                "code": "config.value.range",
                "option": "data-dir",
                "source": "runtime",
                "parameter": {"name": "data-dir"},
                "message": "data-dir cannot change while running"
            }]
        });
        let read = read_error_object(&error).expect("a refusal list is a diagnostic");
        assert_eq!(read.class, ErrorClass::RefusedByMethod);
        assert_eq!(read.diagnostic.code, "config.value.range");
        assert_eq!(
            read.diagnostic.message,
            "data-dir cannot change while running"
        );
        assert_eq!(
            read.diagnostic.parameter,
            [("name".to_owned(), "data-dir".to_owned())].into()
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
