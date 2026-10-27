// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The ban methods' wire, at today's names (`DRS_X_STORE_FLIP.md` DX-Q3,
//! Q11; the rename is RW-Q8's).
//!
//! A ban names a host (`203.0.113.7`, `2001:db8::1`) or an IPv4 subnet
//! (`203.0.113.0/24`) in `host`. C++'s numeric `ip` duplicated `host` for
//! IPv4 and is not on this wire. A ban with no `seconds` lasts until it is
//! lifted (the ban file's kind); `get_bans` and `banned` say so in
//! `permanent`. Each difference is a row in the divergence register.

use serde::{Deserialize, Serialize};

use crate::chain::RpcStatus;

/// One entry of `set_bans`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetBan {
    /// A host, or an IPv4 subnet as `address/prefix`.
    pub host: String,
    /// `true` bans; `false` lifts.
    pub ban: bool,
    /// How long, in seconds; absent is until lifted. Ignored on a lift.
    #[serde(default)]
    pub seconds: Option<u64>,
}

/// `set_bans`' request.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetBansRequest {
    pub bans: Vec<SetBan>,
}

/// One ban in force.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetBan {
    pub host: String,
    /// Whole seconds left, rounded up; `0` when permanent.
    pub seconds: u64,
    /// Until it is lifted.
    pub permanent: bool,
}

/// `get_bans`' reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetBansResponse {
    pub status: RpcStatus,
    pub bans: Vec<GetBan>,
}

/// `banned`'s request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BannedRequest {
    /// A host address.
    pub address: String,
}

/// `banned`'s reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BannedResponse {
    pub status: RpcStatus,
    pub banned: bool,
    /// Whole seconds left, rounded up; `0` when permanent or not banned.
    pub seconds: u64,
    pub permanent: bool,
}
