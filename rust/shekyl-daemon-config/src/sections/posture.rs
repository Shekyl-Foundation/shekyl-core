// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The clearnet and Tor postures, and the one rule that a child row needs
//! its parent to be the posture that row belongs to.
//!
//! The rule is a table, not a copied loop: each child names the parent
//! posture that refuses it, and the sentence the refusal prints.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use shekyl_options::{Code, Diagnostic, PeerEndpoint};

use super::read::Reader;
use super::{Clearnet, Onion, Socks, Tor};
use crate::network::Network;

/// A parent posture under which a child row is a conflict.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Parent {
    /// `clearnet` is `off`.
    ClearnetOff,
    /// `tor` is `off`.
    TorOff,
    /// `tor` is `managed`, which has its own Tor and onion.
    TorManaged,
    /// `tor` is set, and it is not `managed`.
    TorNotManaged,
}

/// One child row, the parent that refuses it, and the conflict text.
struct Child {
    option: &'static str,
    parent: Parent,
    because: &'static str,
}

/// The sentence each parent prints. One place, so the three postures cannot
/// drift apart.
const CLEARNET_OFF: &str = "`clearnet` is `off`";
const TOR_OFF: &str = "`tor` is `off`";
const TOR_MANAGED: &str = "`tor` is `managed`, which has its own Tor and onion";
const TOR_NOT_MANAGED: &str = "`tor` is not `managed`";

const CHILDREN: &[Child] = &[
    Child {
        option: "clearnet-listen",
        parent: Parent::ClearnetOff,
        because: CLEARNET_OFF,
    },
    Child {
        option: "clearnet-advertise",
        parent: Parent::ClearnetOff,
        because: CLEARNET_OFF,
    },
    Child {
        option: "clearnet-socks",
        parent: Parent::ClearnetOff,
        because: CLEARNET_OFF,
    },
    Child {
        option: "clearnet-socks-username",
        parent: Parent::ClearnetOff,
        because: CLEARNET_OFF,
    },
    Child {
        option: "clearnet-socks-password",
        parent: Parent::ClearnetOff,
        because: CLEARNET_OFF,
    },
    Child {
        option: "tor-socks",
        parent: Parent::TorOff,
        because: TOR_OFF,
    },
    Child {
        option: "tor-socks-username",
        parent: Parent::TorOff,
        because: TOR_OFF,
    },
    Child {
        option: "tor-socks-password",
        parent: Parent::TorOff,
        because: TOR_OFF,
    },
    Child {
        option: "tor-onion",
        parent: Parent::TorOff,
        because: TOR_OFF,
    },
    Child {
        option: "tor-onion-listen",
        parent: Parent::TorOff,
        because: TOR_OFF,
    },
    Child {
        option: "tor-file",
        parent: Parent::TorOff,
        because: TOR_OFF,
    },
    Child {
        option: "tor-file",
        parent: Parent::TorNotManaged,
        because: TOR_NOT_MANAGED,
    },
    Child {
        option: "tor-socks",
        parent: Parent::TorManaged,
        because: TOR_MANAGED,
    },
    Child {
        option: "tor-socks-username",
        parent: Parent::TorManaged,
        because: TOR_MANAGED,
    },
    Child {
        option: "tor-socks-password",
        parent: Parent::TorManaged,
        because: TOR_MANAGED,
    },
    Child {
        option: "tor-onion",
        parent: Parent::TorManaged,
        because: TOR_MANAGED,
    },
    Child {
        option: "tor-onion-listen",
        parent: Parent::TorManaged,
        because: TOR_MANAGED,
    },
];

fn refuse_children(r: &mut Reader<'_>, parent: Parent) {
    for child in CHILDREN {
        if child.parent == parent && r.given(child.option) {
            r.conflict(child.option, child.because);
        }
    }
}

/// The clearnet connector. A word other than `on` or `off` is a fault; the
/// children are still read, so a bad word does not hide a bad endpoint.
pub(super) fn clearnet(r: &mut Reader<'_>, network: Network) -> Clearnet {
    match r.required_word("clearnet") {
        Some("off") => {
            refuse_children(r, Parent::ClearnetOff);
            Clearnet::Off
        }
        // `on`, and a word that could not be read (the fault is already
        // recorded): the children are still built.
        Some("on") | None => clearnet_on(r, network),
        Some(other) => {
            r.word_choice("clearnet", other, "on, off");
            clearnet_on(r, network)
        }
    }
}

fn clearnet_on(r: &mut Reader<'_>, network: Network) -> Clearnet {
    let listen = if r.given("clearnet-listen") {
        r.endpoint_list("clearnet-listen", false)
    } else {
        vec![SocketAddr::new(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            network.p2p_port(),
        )]
    };
    let advertise = r.endpoint_list("clearnet-advertise", false);
    let v4 = advertise
        .iter()
        .filter(|endpoint| endpoint.is_ipv4())
        .count();
    let v6 = advertise
        .iter()
        .filter(|endpoint| endpoint.is_ipv6())
        .count();
    if v4 > 1 || v6 > 1 {
        r.faults.push(
            Diagnostic::new(Code::ValueRange, r.source("clearnet-advertise"))
                .option("clearnet-advertise")
                .param(
                    "value",
                    advertise
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(" "),
                )
                .param("rule", "at most one endpoint per address family"),
        );
    }
    Clearnet::On {
        listen,
        socks: socks(r, "clearnet-socks"),
        advertise,
    }
}

/// The Tor connector.
pub(super) fn tor(r: &mut Reader<'_>) -> Tor {
    match r.required_word("tor") {
        Some("off") => {
            refuse_children(r, Parent::TorOff);
            Tor::Off
        }
        Some("managed") => managed(r),
        Some("operator") => operator(r),
        Some(other) => {
            r.word_choice("tor", other, "managed, operator, off");
            managed_binary(r)
        }
        None => managed_binary(r),
    }
}

fn managed(r: &mut Reader<'_>) -> Tor {
    refuse_children(r, Parent::TorManaged);
    managed_binary(r)
}

fn managed_binary(r: &mut Reader<'_>) -> Tor {
    Tor::Managed {
        binary: r.optional_path("tor-file").present(),
    }
}

fn operator(r: &mut Reader<'_>) -> Tor {
    refuse_children(r, Parent::TorNotManaged);
    let socks = socks(r, "tor-socks");
    let onion = onion(r);
    match socks {
        Some(socks) => Tor::Operator { socks, onion },
        None => {
            r.requires("tor", "`tor-socks` when it is `operator`");
            Tor::Off
        }
    }
}

fn onion(r: &mut Reader<'_>) -> Option<Onion> {
    let service = r.onion("tor-onion");
    let listen = r.optional_endpoint("tor-onion-listen");
    match (service, listen) {
        (super::read::Read::Present((host, virtual_port)), super::read::Read::Present(listen)) => {
            Some(Onion {
                host,
                virtual_port,
                listen,
            })
        }
        (super::read::Read::Present(_), _) => {
            r.requires("tor-onion", "`tor-onion-listen`");
            None
        }
        (_, super::read::Read::Present(_)) => {
            r.requires("tor-onion-listen", "`tor-onion`");
            None
        }
        _ => None,
    }
}

/// A SOCKS proxy. The dial sends no credentials, so a username or a
/// password is refused until a dial carries them: with the endpoint, the
/// refusal names that fact; without it, the refusal names the missing
/// endpoint. The secret's text is never copied onto the success type.
fn socks(r: &mut Reader<'_>, prefix: &str) -> Option<Socks> {
    let endpoint = r.optional_endpoint(prefix).present();
    let missing = format!("`{prefix}` is not set");
    let because = match endpoint {
        Some(_) => {
            "the SOCKS dial sends no credentials; the proxy must accept an unauthenticated connection"
        }
        None => missing.as_str(),
    };
    for suffix in ["username", "password"] {
        let key = format!("{prefix}-{suffix}");
        if r.given(&key) {
            r.conflict(&key, because);
        }
    }
    endpoint.map(|endpoint| Socks { endpoint })
}

/// An IP peer needs clearnet; an onion peer needs Tor. The refusal names
/// the peer, so this is not a static child row.
pub(super) fn peers_follow(
    r: &mut Reader<'_>,
    key: &str,
    peers: &[PeerEndpoint],
    clearnet_on: bool,
    tor_on: bool,
) {
    for peer in peers {
        match peer {
            PeerEndpoint::Ip(_) if !clearnet_on => {
                r.conflict(
                    key,
                    &format!("`clearnet` is `off` and {peer} is a clearnet peer"),
                );
            }
            PeerEndpoint::Onion { .. } if !tor_on => {
                r.conflict(key, &format!("`tor` is `off` and {peer} is an onion"));
            }
            _ => {}
        }
    }
}
