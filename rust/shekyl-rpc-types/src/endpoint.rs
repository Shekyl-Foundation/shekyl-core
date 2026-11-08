// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Where a JSON-RPC call is posted, and the answer to a path no route serves.
//!
//! The daemon and the wallet RPC take JSON-RPC calls at one path,
//! [`JSON_RPC_PATH`], spelled the same on both (rule 83: one spelling, no
//! alias). A request to any path a server does not route gets HTTP 404 with
//! [`unrouted_path`]'s body instead of an empty one, so a script posting to
//! the wrong path is told which path the server answers on.
//!
//! The body is built here, beside the error registry, and each server mounts
//! it as its router's fallback. This crate has no HTTP framework, so the
//! status and the handler stay in the servers; the answer is this module's.

use crate::errors::Diagnostic;

/// The path a JSON-RPC call is posted to, on the daemon and the wallet RPC.
pub const JSON_RPC_PATH: &str = "/json_rpc";

/// The JSON-RPC code of a name a server does not serve.
///
/// Both servers already answer a method that is not in their table with
/// it; a path that is not in the route table is the same answer one level
/// up.
pub const METHOD_NOT_FOUND: i64 = -32_601;

/// The diagnostic code of a request to a path the server does not route.
pub const UNROUTED_PATH: &str = "rpc.path.unrouted";

/// The body a server sends, under HTTP 404, for a request to `path` when
/// no route serves it.
///
/// A JSON-RPC 2.0 error object with a null `id` (no request was read). Its
/// `data` is a [`Diagnostic`] naming the path asked for and
/// [`JSON_RPC_PATH`].
#[must_use]
pub fn unrouted_path(path: &str) -> serde_json::Value {
    let diagnostic = Diagnostic::new(
        UNROUTED_PATH,
        format!("no RPC is served at {path}; this server takes JSON-RPC calls at {JSON_RPC_PATH}"),
    )
    .param("path", path)
    .param("json_rpc", JSON_RPC_PATH);
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": null,
        "error": {
            "code": METHOD_NOT_FOUND,
            "message": diagnostic.message.clone(),
            "data": diagnostic,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::read_error_object;

    #[test]
    fn the_body_names_the_path_asked_for_and_the_one_served() {
        let body = unrouted_path("/");
        assert_eq!(body["jsonrpc"], "2.0");
        assert!(body["id"].is_null());
        assert_eq!(body["error"]["code"], -32_601);
        assert_eq!(body["error"]["data"]["code"], "rpc.path.unrouted");
        let params = &body["error"]["data"]["params"];
        assert_eq!(params[0], serde_json::json!(["path", "/"]));
        assert_eq!(params[1], serde_json::json!(["json_rpc", "/json_rpc"]));
        assert_eq!(
            body["error"]["message"],
            "no RPC is served at /; this server takes JSON-RPC calls at /json_rpc"
        );
    }

    /// The data round-trips as the typed diagnostic every other refusal
    /// carries, so a client reads it with the code it already has.
    #[test]
    fn the_data_is_a_diagnostic() {
        let body = unrouted_path("/wallet");
        let diagnostic: Diagnostic =
            serde_json::from_value(body["error"]["data"].clone()).expect("a Diagnostic");
        assert_eq!(diagnostic.code, UNROUTED_PATH);
        // -32601 is JSON-RPC's own "method not found", not an RW-Q3 class:
        // the registry reader does not claim it.
        assert!(read_error_object(&body["error"]).is_none());
    }
}
