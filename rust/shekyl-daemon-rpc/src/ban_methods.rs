// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The ban methods (`DRS_X_STORE_FLIP.md` DX-Q3, Q11), host only, over the
//! node's [`BansFacts`]. JSON-RPC dispatches here, like
//! [`crate::mining_methods`].

use std::net::{IpAddr, Ipv4Addr};

use shekyl_rpc_types::errors::{Diagnostic, ErrorClass, RpcError};
use shekyl_rpc_types::kinds::{Done, Duration, Text};
use shekyl_rpc_types::nullable::Nullable;
use shekyl_rpc_types::wire::node;

use crate::handles::{BanLeftFacts, BanTargetFacts, BansFacts};

/// The ban methods' diagnostic codes.
pub mod codes {
    /// Not a host address or an IPv4 subnet.
    pub const BAD_HOST: &str = "ban.host";
    /// A deadline the clock cannot hold.
    pub const TOO_LONG: &str = "ban.duration-over-clock";
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

fn ban_of(target: BanTargetFacts, left: BanLeftFacts) -> node::Ban {
    match left {
        BanLeftFacts::Permanent => node::Ban {
            host: Text(text_of(target)),
            duration: Nullable(None),
            permanent: true,
        },
        BanLeftFacts::Seconds(seconds) => node::Ban {
            host: Text(text_of(target)),
            duration: Nullable(Some(Duration(seconds))),
            permanent: false,
        },
    }
}

/// `ban_add { host, duration }`: ban a host or an IPv4 subnet, for
/// `duration`, or for good when it is left out (IG-Q44).
///
/// # Errors
///
/// `BadParams` for a host that is not one, or a duration the clock cannot
/// hold; the handle's fault.
pub fn ban_add(bans: &dyn BansFacts, request: &node::BanAdd) -> Result<Done, RpcError> {
    let target = target_of(&request.host.0)?;
    let seconds = request.duration.map(|duration| duration.0);
    let too_long = || {
        RpcError::new(
            ErrorClass::BadParams,
            Diagnostic::new(
                codes::TOO_LONG,
                format!("a ban of {seconds:?} seconds does not fit the clock"),
            )
            .param("host", request.host.0.clone()),
        )
    };
    if let Some(seconds) = seconds {
        if !bans.fits(seconds)? {
            return Err(too_long());
        }
    }
    if !bans.ban(target, seconds)? {
        return Err(too_long());
    }
    Ok(Done)
}

/// `ban_remove { host }`: lift a ban. A host not banned is lifted too: the
/// state asked for holds.
///
/// # Errors
///
/// `BadParams` for a host that is not one; the handle's fault.
pub fn ban_remove(bans: &dyn BansFacts, request: &node::BanHost) -> Result<Done, RpcError> {
    let _lifted = bans.lift(target_of(&request.host.0)?)?;
    Ok(Done)
}

/// `ban_list`: every ban in force, with its time left.
///
/// # Errors
///
/// The handle's fault.
pub fn ban_list(bans: &dyn BansFacts) -> Result<Vec<node::Ban>, RpcError> {
    Ok(bans
        .list()?
        .into_iter()
        .map(|row| ban_of(row.target, row.left))
        .collect())
}

/// `ban_show { host }`: one host's ban, or `null` when it is not banned
/// (§18).
///
/// # Errors
///
/// `BadParams` for a host that is not an address; the handle's fault.
pub fn ban_show(
    bans: &dyn BansFacts,
    request: &node::BanHost,
) -> Result<Nullable<node::Ban>, RpcError> {
    let host: IpAddr = request
        .host
        .0
        .parse()
        .map_err(|_| bad_host(&request.host.0))?;
    Ok(bans
        .remaining(host)?
        .map(|left| ban_of(BanTargetFacts::Host(host), left))
        .into())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

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

    fn table() -> Table {
        Table {
            banned: Mutex::new(Vec::new()),
        }
    }

    /// A ban the clock cannot hold is refused before anything is applied:
    /// the deadline is checked before the ban (the review of #1165). Red
    /// edit: apply the ban, then check the deadline.
    #[test]
    fn a_ban_the_clock_cannot_hold_is_refused_and_bans_nothing() {
        let table = table();
        let refused = ban_add(
            &table,
            &node::BanAdd {
                host: Text("203.0.113.2".to_owned()),
                duration: Some(shekyl_rpc_types::kinds::Duration(u64::MAX)),
            },
        )
        .expect_err("too long");
        assert_eq!(refused.class, ErrorClass::BadParams);
        assert_eq!(refused.diagnostic.code, codes::TOO_LONG);
        assert!(table.banned.lock().expect("lock").is_empty());

        ban_add(
            &table,
            &node::BanAdd {
                host: Text("203.0.113.1".to_owned()),
                duration: Some(shekyl_rpc_types::kinds::Duration(60)),
            },
        )
        .expect("a minute fits");
        assert_eq!(table.banned.lock().expect("lock").len(), 1);
    }

    /// A host that is not one is `ban.host` (BadParams) on every ban
    /// method; a host not banned shows `null`, not an error.
    #[test]
    fn a_host_that_is_not_one_is_refused_and_an_unbanned_host_shows_null() {
        let table = table();
        let bad = node::BanHost {
            host: Text("not a host".to_owned()),
        };
        for refused in [
            ban_remove(&table, &bad).expect_err("bad host"),
            ban_show(&table, &bad).expect_err("bad host"),
            ban_add(
                &table,
                &node::BanAdd {
                    host: bad.host.clone(),
                    duration: None,
                },
            )
            .expect_err("bad host"),
        ] {
            assert_eq!(refused.class, ErrorClass::BadParams);
            assert_eq!(refused.diagnostic.code, codes::BAD_HOST);
        }
        let shown = ban_show(
            &table,
            &node::BanHost {
                host: Text("203.0.113.9".to_owned()),
            },
        )
        .expect("an answer");
        assert_eq!(shown, Nullable(None));
        assert!(ban_list(&table).expect("a list").is_empty());
    }
}
