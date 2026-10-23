// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The ban methods (`DRS_X_STORE_FLIP.md` DX-Q3, Q11), host only, over the
//! node's [`BansFacts`]. **Built and not routed**, like
//! [`crate::mining_methods`].

use std::net::{IpAddr, Ipv4Addr};

use shekyl_rpc_types::bans::{
    BannedRequest, BannedResponse, GetBan, GetBansResponse, SetBansRequest,
};
use shekyl_rpc_types::errors::{Diagnostic, ErrorClass, RpcError};
use shekyl_rpc_types::mining::StatusOnlyResponse;
use shekyl_rpc_types::RpcStatus;

use crate::handles::{BanLeftFacts, BanTargetFacts, BansFacts};

/// The ban methods' diagnostic codes.
pub mod codes {
    /// Not a host address or an IPv4 subnet.
    pub const BAD_HOST: &str = "ban.bad_host";
    /// A deadline the clock cannot hold.
    pub const TOO_LONG: &str = "ban.too_long";
}

fn bad_host(text: &str) -> RpcError {
    RpcError::new(
        ErrorClass::BadParams,
        Diagnostic::new(
            codes::BAD_HOST,
            format!("`{text}` is not a host address or an IPv4 subnet as address/prefix"),
        )
        .param("host", text),
    )
}

/// A host or an IPv4 subnet, as the wire writes one.
fn target_of(text: &str) -> Result<BanTargetFacts, RpcError> {
    match text.split_once('/') {
        Some((network, prefix)) => {
            let network: Ipv4Addr = network.parse().map_err(|_| bad_host(text))?;
            let prefix: u8 = prefix.parse().map_err(|_| bad_host(text))?;
            if prefix > 32 {
                return Err(bad_host(text));
            }
            Ok(BanTargetFacts::Subnet { network, prefix })
        }
        None => text
            .parse::<IpAddr>()
            .map(BanTargetFacts::Host)
            .map_err(|_| bad_host(text)),
    }
}

fn text_of(target: BanTargetFacts) -> String {
    match target {
        BanTargetFacts::Host(host) => host.to_string(),
        BanTargetFacts::Subnet { network, prefix } => format!("{network}/{prefix}"),
    }
}

const fn seconds_of(left: BanLeftFacts) -> (u64, bool) {
    match left {
        BanLeftFacts::Permanent => (0, true),
        BanLeftFacts::Seconds(seconds) => (seconds, false),
    }
}

/// `set_bans { bans }`: each entry bans or lifts a host or a subnet, in
/// order. Every entry is read, and every deadline checked against the
/// clock, before any is applied, so a malformed entry or a deadline the
/// clock cannot hold changes nothing.
///
/// # Errors
///
/// `BadParams` for a host that is not one, or a deadline the clock cannot
/// hold; the handle's fault.
pub fn set_bans(
    bans: &dyn BansFacts,
    request: &SetBansRequest,
) -> Result<StatusOnlyResponse, RpcError> {
    let too_long = |entry: &shekyl_rpc_types::bans::SetBan| {
        RpcError::new(
            ErrorClass::BadParams,
            Diagnostic::new(
                codes::TOO_LONG,
                format!(
                    "a ban of {:?} seconds does not fit the clock",
                    entry.seconds
                ),
            )
            .param("host", entry.host.clone()),
        )
    };
    let entries = request
        .bans
        .iter()
        .map(|entry| target_of(&entry.host).map(|target| (target, entry)))
        .collect::<Result<Vec<_>, _>>()?;
    for (_, entry) in &entries {
        if let (true, Some(seconds)) = (entry.ban, entry.seconds) {
            if !bans.fits(seconds)? {
                return Err(too_long(entry));
            }
        }
    }
    for (target, entry) in entries {
        if entry.ban {
            if !bans.ban(target, entry.seconds)? {
                return Err(too_long(entry));
            }
        } else {
            let _lifted = bans.lift(target)?;
        }
    }
    Ok(StatusOnlyResponse {
        status: RpcStatus::ok(),
    })
}

/// `get_bans`: every ban in force, with its time left.
///
/// # Errors
///
/// The handle's fault.
pub fn get_bans(bans: &dyn BansFacts) -> Result<GetBansResponse, RpcError> {
    Ok(GetBansResponse {
        status: RpcStatus::ok(),
        bans: bans
            .list()?
            .into_iter()
            .map(|row| {
                let (seconds, permanent) = seconds_of(row.left);
                GetBan {
                    host: text_of(row.target),
                    seconds,
                    permanent,
                }
            })
            .collect(),
    })
}

/// `banned { address }`: whether a host is banned, and for how long.
///
/// # Errors
///
/// `BadParams` for an address that is not one; the handle's fault.
pub fn banned(bans: &dyn BansFacts, request: &BannedRequest) -> Result<BannedResponse, RpcError> {
    let host: IpAddr = request
        .address
        .parse()
        .map_err(|_| bad_host(&request.address))?;
    let left = bans.remaining(host)?;
    let (seconds, permanent) = left.map_or((0, false), seconds_of);
    Ok(BannedResponse {
        status: RpcStatus::ok(),
        banned: left.is_some(),
        seconds,
        permanent,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use shekyl_rpc_types::bans::SetBan;

    use super::*;
    use crate::chain_facts::FactsFault;
    use crate::handles::BanRow;

    /// A table whose clock holds a ban of at most a day, recording bans.
    struct Table {
        banned: Mutex<Vec<BanTargetFacts>>,
    }

    impl BansFacts for Table {
        fn ban(&self, target: BanTargetFacts, seconds: Option<u64>) -> Result<bool, FactsFault> {
            if seconds.is_some_and(|seconds| seconds > 86_400) {
                return Ok(false);
            }
            self.banned.lock().expect("lock").push(target);
            Ok(true)
        }

        fn fits(&self, seconds: u64) -> Result<bool, FactsFault> {
            Ok(seconds <= 86_400)
        }

        fn lift(&self, _target: BanTargetFacts) -> Result<bool, FactsFault> {
            Ok(false)
        }

        fn remaining(&self, _host: IpAddr) -> Result<Option<BanLeftFacts>, FactsFault> {
            Ok(None)
        }

        fn list(&self) -> Result<Vec<BanRow>, FactsFault> {
            Ok(Vec::new())
        }
    }

    /// A request whose second ban the clock cannot hold bans nothing: every
    /// deadline is checked before any entry is applied (the review of
    /// #1165). Red edit: check each deadline as its entry is applied.
    #[test]
    fn a_ban_the_clock_cannot_hold_leaves_the_whole_request_unapplied() {
        let table = Table {
            banned: Mutex::new(Vec::new()),
        };
        let entry = |host: &str, seconds: u64| SetBan {
            host: host.to_owned(),
            ban: true,
            seconds: Some(seconds),
        };
        let refused = set_bans(
            &table,
            &SetBansRequest {
                bans: vec![entry("203.0.113.1", 60), entry("203.0.113.2", u64::MAX)],
            },
        )
        .expect_err("too long");
        assert_eq!(refused.class, ErrorClass::BadParams);
        assert_eq!(refused.diagnostic.code, codes::TOO_LONG);
        assert!(
            table.banned.lock().expect("lock").is_empty(),
            "the first entry was not applied"
        );
    }
}
