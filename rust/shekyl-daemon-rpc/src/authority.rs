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
//! - every method is JSON-RPC on `/json_rpc` (RW-Q1, RW-Q2), and the handler
//!   admits it against its own row ([`Authority::admit`]); a name with no
//!   row is method-not-found; a path that is not `/json_rpc` is the router's
//!   404;
//! - a handler that shapes its reply by grant reads [`Authority::disclosure`].
//!
//! A refusal is the JSON-RPC error object on every surface (`RPC_WIRE.md`
//! RW-Q3): the class is the code, and `data` is the typed diagnostic.
//!
//! **Today's two plaintext listeners** stamp a fixed authority each
//! ([`Authority::admin_listener`], [`Authority::VIEW_LISTENER`]). The view
//! listener keeps its method set until RT-W12 moves its clients (RT-O33).

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use shekyl_rpc_types::errors::{Diagnostic, ErrorClass, RpcError};
use shekyl_rpc_types::method::{
    admit_armed, caller_bounded, Grant, GrantSet, Policy, Preset, Row as Method,
};

use crate::info::Disclosure;
use crate::types::JsonRpcResponse;

/// The diagnostic codes a refusal carries.
pub mod codes {
    /// The method needs a grant the connection does not hold.
    pub const OUTSIDE_THE_GRANT: &str = "grant.outside";
    /// The method is served only to the host's administrator.
    pub const HOST_ONLY: &str = "grant.host-only";
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
            // A connection that reaches dispatch has authenticated, or came
            // in on a plaintext loopback listener (RT-O33).
            Policy::Endpoint | Policy::Authenticated => {}
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

/// The JSON-RPC error object a refusal is (RW-Q3): the class is the code,
/// and `data` is the typed diagnostic.
#[must_use]
pub fn refusal(id: serde_json::Value, error: &RpcError) -> JsonRpcResponse {
    JsonRpcResponse::error_with_data(
        id,
        error.class.code(),
        error.diagnostic.message.clone(),
        serde_json::to_value(&error.diagnostic).ok(),
    )
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
/// The line is the method's name. Params and the body are not recorded.
pub(crate) fn note_admitted(authority: Authority, row: &Method) {
    if !authority.armed_switch() || matches!(row.policy, Policy::Endpoint) {
        return;
    }
    tracing::info!(target: "global", "rpc request: {}", row.name);
}

/// The layer that stamps `authority` on every request. The `/json_rpc`
/// handler admits each call against its method's row; no path is a method
/// of its own (RW-Q1).
pub async fn stamp(authority: Authority, mut request: Request, next: Next) -> Response {
    request.extensions_mut().insert(authority);
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_rpc_types::method::{RpcMethod, UNARMED};
    use shekyl_rpc_types::wire::{self, TABLE};

    fn row<M: RpcMethod>() -> Method {
        Method::of::<M>()
    }

    /// The version read is under no grant (RW-Q6): a key that holds
    /// `submit` alone runs the skew check, and is still refused
    /// `daemon_status`. Red edit: give `version` the `health` grant.
    #[test]
    fn a_submit_only_key_reads_the_version() {
        let submit_only = Authority {
            grants: GrantSet::of(&[Grant::Submit]),
            host: false,
            armed: false,
        };
        assert!(submit_only.admit(&row::<wire::Version>()).is_ok());
        assert!(submit_only.admit(&row::<wire::TxSubmit>()).is_ok());
        let refused = submit_only
            .admit(&row::<wire::DaemonStatus>())
            .expect_err("health");
        assert_eq!(refused.class, ErrorClass::OutsideTheGrant);
    }

    #[test]
    fn the_view_listener_is_refused_every_grant_it_does_not_hold() {
        let view = Authority::VIEW_LISTENER;
        let refused = view.admit(&row::<wire::DaemonStop>()).expect_err("node");
        assert_eq!(refused.class, ErrorClass::OutsideTheGrant);
        assert_eq!(refused.diagnostic.code, codes::OUTSIDE_THE_GRANT);
        assert_eq!(refused.diagnostic.parameter["grant"], "node");
        assert!(
            view.admit(&row::<wire::PeerConnections>()).is_err(),
            "peers"
        );
        assert!(view.admit(&row::<wire::ChainAlt>()).is_err(), "status");
        assert!(view.admit(&row::<wire::ChainHeight>()).is_ok(), "chain");
        assert!(view.admit(&row::<wire::TxSubmit>()).is_ok(), "submit");
        assert!(
            view.admit(&row::<wire::BlockTemplate>()).is_ok(),
            "mining-work"
        );
    }

    #[test]
    fn host_only_data_and_the_armed_levers_are_the_hosts_alone() {
        let view = Authority::VIEW_LISTENER;
        for row in [
            row::<wire::RelayStats>(),
            row::<wire::DevBlockGenerate>(),
            row::<wire::DevChainPop>(),
        ] {
            let refused = view.admit(&row).expect_err(row.name);
            assert_eq!(refused.diagnostic.code, codes::HOST_ONLY, "{}", row.name);
        }
        assert!(Authority::admin_listener(false)
            .admit(&row::<wire::RelayStats>())
            .is_ok());
    }

    #[test]
    fn an_armed_lever_needs_the_switch_even_for_the_host() {
        let unarmed = Authority::admin_listener(false);
        let armed = Authority::admin_listener(true);
        for row in [row::<wire::DevBlockGenerate>(), row::<wire::DevChainPop>()] {
            let refused = unarmed.admit(&row).expect_err(row.name);
            assert_eq!(refused.class, ErrorClass::OutsideTheGrant, "{}", row.name);
            assert_eq!(refused.diagnostic.code, UNARMED, "{}", row.name);
            assert!(armed.admit(&row).is_ok(), "{}", row.name);
        }
    }

    /// `pow` and the coinbase sum are bounded reads, paid from the hash
    /// budget and the coinbase permit, and are admitted on the view
    /// listener.
    #[test]
    fn pow_and_the_coinbase_sum_are_admitted_on_the_view_listener() {
        let view = Authority::VIEW_LISTENER;
        assert!(view.admit(&row::<wire::Pow>()).is_ok());
        assert!(view.admit(&row::<wire::ChainCoinbaseSum>()).is_ok());
    }

    /// Every row is admitted for the host with the switch on: the admin
    /// listener's method set is the whole table.
    #[test]
    fn the_admin_listener_is_admitted_every_row() {
        let armed = Authority::admin_listener(true);
        for row in TABLE {
            assert!(armed.admit(row).is_ok(), "{}", row.name);
        }
    }

    /// The view listener's method set, written out from the grants it holds
    /// (`view` plus `submit` and `mining-work`, RT-O33), not from the
    /// table: a row that moves grant moves this list by hand.
    #[test]
    fn the_view_listener_serves_exactly_its_specified_set() {
        let specified = [
            row::<wire::Version>(),
            row::<wire::ChainHeight>(),
            row::<wire::BlockHeaderShow>(),
            row::<wire::BlockHeaderList>(),
            row::<wire::BlockShow>(),
            row::<wire::BlockList>(),
            row::<wire::TxShow>(),
            row::<wire::TxList>(),
            row::<wire::ChainSpent>(),
            row::<wire::Fee>(),
            row::<wire::ChainCoinbaseSum>(),
            row::<wire::CurveShow>(),
            row::<wire::ArchivalClaimShow>(),
            row::<wire::ShardCoverage>(),
            row::<wire::ShardFetch>(),
            row::<wire::DaemonStatus>(),
            row::<wire::OptionShow>(),
            row::<wire::TxpoolList>(),
            row::<wire::TxpoolStats>(),
            row::<wire::TxSubmit>(),
            row::<wire::BlockTemplate>(),
            row::<wire::BlockSubmit>(),
            row::<wire::Pow>(),
        ];
        let mut want: Vec<&str> = specified.iter().map(|row| row.name).collect();
        let mut got: Vec<&str> = TABLE
            .iter()
            .filter(|row| Authority::VIEW_LISTENER.admit(row).is_ok())
            .map(|row| row.name)
            .collect();
        want.sort_unstable();
        got.sort_unstable();
        assert_eq!(got, want);
    }

    #[test]
    fn a_refusal_is_the_json_rpc_error_object_with_its_diagnostic() {
        let error = Authority::VIEW_LISTENER
            .admit(&row::<wire::DaemonStop>())
            .expect_err("node");
        let body = serde_json::to_value(refusal(serde_json::Value::Null, &error)).unwrap();
        assert_eq!(body["error"]["code"], -32_002);
        assert_eq!(body["error"]["data"]["code"], codes::OUTSIDE_THE_GRANT);
        assert_eq!(body["error"]["data"]["parameter"]["grant"], "node");
        assert_eq!(body["error"]["data"]["parameter"]["method"], "daemon_stop");
        assert_eq!(
            grant_refusal_message(&body.to_string()).as_deref(),
            Some(error.diagnostic.message.as_str())
        );
        assert_eq!(grant_refusal_message(r#"{"result":{}}"#), None);
        assert_eq!(
            grant_refusal_message(r#"{"error":{"code":-32603,"message":"boom"}}"#),
            None
        );
    }
}
