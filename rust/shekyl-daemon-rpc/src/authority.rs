// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A connection's authority (`docs/design/RPC_CHANNEL.md` §6.1, §6.2, §6.3;
//! RT-O32).
//!
//! What a connection may ask for is its grant set; whether it is the host's
//! administrator decides host-only data and the armed levers; whether it is
//! bounded is what the handlers' caps read. All three are one value,
//! [`Authority`], stamped on every request as a request extension
//! ([`stamp`]), and every gate reads it:
//!
//! - a REST path that has a row is admitted by [`stamp`] itself, against
//!   that row, before the handler runs; a path with no row is not a method,
//!   and the router answers 404;
//! - a JSON-RPC method is admitted by the `/json_rpc` handler against its
//!   own row ([`Authority::admit`]); a name with no row is method-not-found;
//! - a handler that shapes its reply by grant reads [`Authority::disclosure`].
//!
//! A refusal is the JSON-RPC error object on every surface (`RPC_WIRE.md`
//! RW-Q3): the class is the code, and `data` is the typed diagnostic.
//!
//! **Today's two plaintext listeners** stamp a fixed authority each
//! ([`Authority::admin_listener`], [`Authority::VIEW_LISTENER`]). The view
//! listener keeps its method set until RT-W12 moves its clients (RT-O33).

use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use shekyl_rpc_types::errors::{Diagnostic, ErrorClass, RpcError};
use shekyl_rpc_types::methods::{
    admit_armed, caller_bounded, rest_path, Grant, GrantSet, Method, Policy, Preset,
};

use crate::info::Disclosure;
use crate::types::JsonRpcResponse;

/// The diagnostic codes a refusal carries.
pub mod codes {
    /// The method needs a grant the connection does not hold.
    pub const OUTSIDE_THE_GRANT: &str = "rpc.grant.outside";
    /// The method is served only to the host's administrator.
    pub const HOST_ONLY: &str = "rpc.grant.host_only";
}

/// What one connection may do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Authority {
    grants: GrantSet,
    host: bool,
    armed: bool,
}

/// The view listener's grants: the `view` preset, plus `submit` and
/// `mining-work`, which the plaintext view listener serves today and keeps
/// until RT-W12 moves its clients to the same-user socket (RT-O33, ruled
/// 2026-10-25). The GUI submits and mines through it.
const VIEW_LISTENER_GRANTS: GrantSet = Preset::View
    .grants()
    .union(GrantSet::of(&[Grant::Submit, Grant::MiningWork]));

impl Authority {
    /// The plaintext admin listener: every grant, and the host's
    /// administrator. It binds loopback only, which stands in for a host
    /// identity until the same-user socket exists. `armed` is the node's
    /// armed-lever switch.
    #[must_use]
    pub const fn admin_listener(armed: bool) -> Self {
        Self {
            grants: GrantSet::ALL,
            host: true,
            armed,
        }
    }

    /// The plaintext view listener (RT-O33).
    pub const VIEW_LISTENER: Self = Self {
        grants: VIEW_LISTENER_GRANTS,
        host: false,
        armed: false,
    };

    /// The grants this connection holds.
    #[must_use]
    pub const fn grants(self) -> GrantSet {
        self.grants
    }

    /// Whether this connection is the host's administrator.
    #[must_use]
    pub const fn host(self) -> bool {
        self.host
    }

    /// The node's armed-lever switch, as stamped on this connection.
    #[must_use]
    pub const fn armed_switch(self) -> bool {
        self.armed
    }

    /// Whether this connection's requests are bounded (§6.3): every
    /// connection except the host's administrator, whatever its grant.
    #[must_use]
    pub const fn bounded(self) -> bool {
        caller_bounded(self.host)
    }

    /// What this connection is shown on a reply filled by grant.
    #[must_use]
    pub const fn disclosure(self) -> Disclosure {
        Disclosure::of(self.grants, self.host)
    }

    /// Admit a call of `row`.
    ///
    /// # Errors
    ///
    /// - [`ErrorClass::OutsideTheGrant`] when the row's grant is not held,
    ///   when host-only data or an armed lever is asked for by anyone but the
    ///   host's administrator, or when an armed lever is asked for with the
    ///   switch off.
    ///
    /// A request over a handler's bound is that handler's refusal. Admit
    /// decides who may call the row.
    pub fn admit(self, row: &Method) -> Result<(), RpcError> {
        let host_only = || {
            RpcError::new(
                ErrorClass::OutsideTheGrant,
                Diagnostic::new(
                    codes::HOST_ONLY,
                    format!(
                        "{} is served only on the node's own computer, to its administrator",
                        row.name
                    ),
                )
                .param("method", row.name),
            )
        };
        match row.policy {
            Policy::Endpoint => {}
            Policy::Grant(grant) => {
                if !self.grants.holds(grant) {
                    return Err(RpcError::new(
                        ErrorClass::OutsideTheGrant,
                        Diagnostic::new(
                            codes::OUTSIDE_THE_GRANT,
                            format!(
                                "{} needs the {} grant, which this connection does not hold",
                                row.name,
                                grant.name()
                            ),
                        )
                        .param("method", row.name)
                        .param("grant", grant.name()),
                    ));
                }
            }
            Policy::HostOnly => {
                if !self.host {
                    return Err(host_only());
                }
            }
            Policy::Armed => {
                if !self.host {
                    return Err(host_only());
                }
                admit_armed(row, self.armed)?;
            }
        }
        Ok(())
    }
}

/// The JSON-RPC error object a refusal is on every surface (RW-Q3).
#[must_use]
pub fn refusal(id: serde_json::Value, error: &RpcError) -> JsonRpcResponse {
    crate::methods::RpcRefusal::of_error(error).to_json_rpc(id)
}

/// The message of a grant refusal, when `raw` is that envelope.
///
/// The stamp answers a gated path with the JSON-RPC error object on HTTP
/// 200 (RW-Q3). A remote console recognizes that envelope by its class.
/// Any other body, including another error class, is not a grant refusal.
#[must_use]
pub fn grant_refusal_message(raw: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(raw).ok()?;
    let error = value.get("error")?;
    if error.get("code")?.as_i64()? != ErrorClass::OutsideTheGrant.code() {
        return None;
    }
    error.get("message")?.as_str().map(str::to_owned)
}

/// Record that `row` was admitted, on an armed daemon only.
///
/// The line is `row.name`: a REST path today, a JSON-RPC method name
/// otherwise. The `/json_rpc` endpoint is not a method and is not
/// recorded. Params and the body are not.
pub(crate) fn note_admitted(authority: Authority, row: &Method) {
    if !authority.armed_switch() || matches!(row.policy, Policy::Endpoint) {
        return;
    }
    tracing::info!(target: "global", "rpc request: {}", row.name);
}

/// The layer that stamps `authority` on a request whose path is a method,
/// and admits that row before the handler runs.
///
/// A path with no row is not a method. The layer does not admit it and does
/// not stamp an authority on it, so a handler that asks for the extension
/// fails closed, and an unrouted path is the router's 404. The gate that
/// every route is a row keeps a served path off that arm.
pub async fn stamp(authority: Authority, mut request: Request, next: Next) -> Response {
    let Some(row) = rest_path(request.uri().path()) else {
        return next.run(request).await;
    };
    if let Err(error) = authority.admit(row) {
        return (
            StatusCode::OK,
            Json(refusal(serde_json::Value::Null, &error)),
        )
            .into_response();
    }
    // Armed daemons (`--dev-rpc`) record the method-table row that was
    // admitted, and not the body or the params. A REST row's name is its
    // path today; a JSON-RPC row's name is the method. The `/json_rpc`
    // endpoint itself is not a method, so it is not recorded here — the
    // handler records the method it admits.
    note_admitted(authority, row);
    request.extensions_mut().insert(authority);
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_rpc_types::methods::{json_rpc, METHODS};

    fn row(name: &str) -> &'static Method {
        json_rpc(name)
            .or_else(|| rest_path(name))
            .unwrap_or_else(|| panic!("{name} has no row"))
    }

    #[test]
    fn the_view_listener_is_refused_every_grant_it_does_not_hold() {
        let view = Authority::VIEW_LISTENER;
        let refused = view.admit(row("/stop_daemon")).expect_err("node");
        assert_eq!(refused.class, ErrorClass::OutsideTheGrant);
        assert_eq!(refused.diagnostic.code, codes::OUTSIDE_THE_GRANT);
        assert!(view.admit(row("get_connections")).is_err(), "peers");
        assert!(view.admit(row("/get_alt_blocks_hashes")).is_err(), "status");
        assert!(view.admit(row("get_block_count")).is_ok(), "chain");
        assert!(view.admit(row("/submit_transaction")).is_ok(), "submit");
        assert!(view.admit(row("get_block_template")).is_ok(), "mining-work");
    }

    #[test]
    fn host_only_data_and_the_armed_levers_are_the_hosts_alone() {
        let view = Authority::VIEW_LISTENER;
        for name in ["/get_stem_tallies", "generateblocks", "/pop_blocks"] {
            let refused = view.admit(row(name)).expect_err(name);
            assert_eq!(refused.diagnostic.code, codes::HOST_ONLY, "{name}");
        }
        assert!(Authority::admin_listener(false)
            .admit(row("/get_stem_tallies"))
            .is_ok());
    }

    #[test]
    fn an_armed_lever_needs_the_switch_even_for_the_host() {
        let unarmed = Authority::admin_listener(false);
        let armed = Authority::admin_listener(true);
        for name in ["generateblocks", "/pop_blocks"] {
            let refused = unarmed.admit(row(name)).expect_err(name);
            assert_eq!(refused.class, ErrorClass::OutsideTheGrant, "{name}");
            assert_eq!(
                refused.diagnostic.code,
                shekyl_rpc_types::methods::UNARMED,
                "{name}"
            );
            assert!(armed.admit(row(name)).is_ok(), "{name}");
        }
    }

    #[test]
    fn calc_pow_and_the_coinbase_sum_are_admitted_on_the_view_listener() {
        let view = Authority::VIEW_LISTENER;
        for name in ["calc_pow", "get_coinbase_tx_sum"] {
            assert!(view.admit(row(name)).is_ok(), "{name}");
        }
    }

    /// Every row is admitted for the host's administrator with the switch
    /// on: the admin listener's method set is the whole table.
    #[test]
    fn the_admin_listener_is_admitted_every_row() {
        let armed = Authority::admin_listener(true);
        for row in METHODS {
            assert!(armed.admit(row).is_ok(), "{}", row.name);
        }
    }

    /// The view listener's method set, written out (RT-O33: it keeps today's
    /// set, less `/get_alt_blocks_hashes`, which §6.1 moves to `status`).
    /// `calc_pow` and `get_coinbase_tx_sum` are on it: they are bounded
    /// reads, paid from the hash budget and the coinbase permit, not
    /// admin-gated. Written from the specification, not from the table.
    #[test]
    fn the_view_listener_serves_exactly_its_specified_set() {
        let specified: &[&str] = &[
            "get_version",
            "get_block_count",
            "on_get_block_hash",
            "get_block_header_by_height",
            "get_block",
            "get_last_block_header",
            "get_block_header_by_hash",
            "get_block_headers_range",
            "calc_pow",
            "get_coinbase_tx_sum",
            "get_fee_estimate",
            "option_show",
            "get_info",
            "submit_block",
            "get_block_template",
            "get_miner_data",
            "get_txpool_backlog",
            "get_curve_tree_info",
            "get_curve_tree_checkpoint",
            "get_archival_emission_claim_source",
            "get_archival_shard_coverage",
            "/json_rpc",
            "/get_height",
            "/get_transactions",
            "/is_key_image_spent",
            "/submit_transaction",
            "/get_transaction_pool",
            "/get_transaction_pool_hashes",
            "/get_transaction_pool_stats",
            "/get_info",
            "/get_blocks_by_height.bin",
            "/get_o_indexes.bin",
        ];
        let served: Vec<&str> = METHODS
            .iter()
            .filter(|row| Authority::VIEW_LISTENER.admit(row).is_ok())
            .map(|row| row.name)
            .collect();
        let mut want = specified.to_vec();
        let mut got = served.clone();
        want.sort_unstable();
        got.sort_unstable();
        assert_eq!(got, want);
    }

    #[test]
    fn a_refusal_is_the_json_rpc_error_object_with_its_diagnostic() {
        let error = Authority::VIEW_LISTENER
            .admit(row("/stop_daemon"))
            .expect_err("node");
        let body = serde_json::to_value(refusal(serde_json::Value::Null, &error)).unwrap();
        assert_eq!(body["error"]["code"], -32_002);
        assert_eq!(body["error"]["data"]["code"], codes::OUTSIDE_THE_GRANT);
        assert_eq!(body["error"]["data"]["params"][1][1], "node");
        assert_eq!(
            grant_refusal_message(&body.to_string()).as_deref(),
            Some(error.diagnostic.message.as_str())
        );
        assert_eq!(grant_refusal_message(r#"{"status":"OK"}"#), None);
        assert_eq!(
            grant_refusal_message(r#"{"error":{"code":-32603,"message":"boom"}}"#),
            None
        );
    }
}
