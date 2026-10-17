// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Derived defaults, written into the resolved map before any section reads.
//!
//! [`resolve`](crate::resolve::resolve) stores a row whose default is a
//! literal. A derived row stays absent until its path or its port can be
//! named. This module names those values, with source `default`, so the
//! announcement and `option show` read the value the process uses. A section
//! then only reads the map.
//!
//! `tor-file` is a search: absence means discovery, and this module does not
//! invent a path. `config-file` is named by the announcement itself.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use shekyl_options::{Diagnostic, Source, Value};

use crate::network::Network;
use crate::paths;
use crate::platform::{Platform, RunMode};
use crate::resolve::Resolved;

/// The default clearnet bind: every IPv4 interface.
const CLEARNET_BIND: Ipv4Addr = Ipv4Addr::UNSPECIFIED;
/// The default admin bind: this host only.
const ADMIN_BIND: Ipv4Addr = Ipv4Addr::LOCALHOST;

/// When a listen default is written.
#[derive(Clone, Copy)]
enum When {
    /// Whenever the operator left the row unset.
    Always,
    /// Whenever the operator left the row unset and did not turn clearnet off.
    /// A missing or unreadable clearnet word still runs the on path, so the
    /// listen it would use is named here too.
    ClearnetNotOff,
}

/// One derived row and how its default is built.
enum Derived {
    /// A path under the daemon's root. No home is one fault on this row,
    /// and the row stays absent: the reader does not report it again.
    Path {
        name: &'static str,
        at: fn(&Path, Network) -> PathBuf,
    },
    /// One IPv4 listen endpoint.
    Listen {
        name: &'static str,
        addr: Ipv4Addr,
        port: fn(Network) -> u16,
        when: When,
    },
}

/// The derived rows a start fills. `tor-file` is not among them.
const DERIVED: &[Derived] = &[
    Derived::Path {
        name: "data-dir",
        at: paths::data_dir_default,
    },
    Derived::Path {
        name: "log-file",
        at: paths::log_file_default,
    },
    Derived::Listen {
        name: "rpc-admin-listen",
        addr: ADMIN_BIND,
        port: Network::rpc_port,
        when: When::Always,
    },
    Derived::Listen {
        name: "clearnet-listen",
        addr: CLEARNET_BIND,
        port: Network::p2p_port,
        when: When::ClearnetNotOff,
    },
];

/// Writes each derived default the operator left unset.
///
/// An explicit value, including an empty list (`none`), is left as the
/// operator gave it. A path whose root cannot be named adds one fault and
/// stays absent.
pub(super) fn fill(
    resolved: &mut Resolved,
    network: Network,
    run_mode: RunMode,
    platform: &Platform,
) -> Vec<Diagnostic> {
    let mut faults = Vec::new();
    for row in DERIVED {
        match *row {
            Derived::Path { name, at } => {
                fill_path(resolved, platform, run_mode, network, name, at, &mut faults);
            }
            Derived::Listen {
                name,
                addr,
                port,
                when,
            } => {
                if applies(resolved, when) {
                    fill_listen(resolved, name, addr, port(network));
                }
            }
        }
    }
    faults
}

fn applies(resolved: &Resolved, when: When) -> bool {
    match when {
        When::Always => true,
        When::ClearnetNotOff => !matches!(resolved.get("clearnet"), Some(Value::Word("off"))),
    }
}

fn fill_path(
    resolved: &mut Resolved,
    platform: &Platform,
    run_mode: RunMode,
    network: Network,
    name: &'static str,
    at: fn(&Path, Network) -> PathBuf,
    faults: &mut Vec<Diagnostic>,
) {
    if resolved.values.contains_key(name) {
        return;
    }
    match paths::root(platform, run_mode, name) {
        Ok(root) => {
            resolved
                .values
                .insert(name, (Value::Path(at(&root, network)), Source::Default));
        }
        Err(diagnostic) => faults.push(diagnostic),
    }
}

fn fill_listen(resolved: &mut Resolved, name: &'static str, addr: Ipv4Addr, port: u16) {
    if resolved.values.contains_key(name) {
        return;
    }
    let value = Value::List(vec![Value::Endpoint(SocketAddr::new(
        IpAddr::V4(addr),
        port,
    ))]);
    resolved.values.insert(name, (value, Source::Default));
}
