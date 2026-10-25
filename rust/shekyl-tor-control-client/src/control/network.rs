// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Tor's own view of its network (`TOR_SUPERVISOR.md` §1 `TSR-Q14`, §4.2):
//! `GETINFO network-liveness` and `GETINFO status/circuit-established`.
//! The driver asks while the managed Tor is Running. A missing or
//! unrecognized value is unknown, never a negative.

use super::framing::ControlReply;

/// One `GETINFO` fact. Unknown is a missing or unrecognized value, and it
/// is not a negative: the supervisor does not invent a statement Tor did
/// not make.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Reported {
    /// The reply had no such key, or a value this parser does not know.
    #[default]
    Unknown,
    /// The key's affirmative value (`up`, `1`).
    Yes,
    /// The key's negative value (`down`, `0`).
    No,
}

/// Tor's sampled view of its network. Each field is one key.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NetworkView {
    /// `network-liveness`.
    pub liveness: Reported,
    /// `status/circuit-established`.
    pub circuits: Reported,
}

impl NetworkView {
    /// Either key answered in the negative. Unknown is not a negative, so
    /// one unknown key does not name a blocked link by itself.
    #[must_use]
    pub const fn reports_blocked(self) -> bool {
        matches!(self.liveness, Reported::No) || matches!(self.circuits, Reported::No)
    }

    /// Both keys answered in the affirmative: Tor says it reaches its network.
    #[must_use]
    pub const fn reports_reachable(self) -> bool {
        matches!(
            (self.liveness, self.circuits),
            (Reported::Yes, Reported::Yes)
        )
    }
}

/// Both keys from one sample reply. A key that is absent or unrecognized
/// is [`Reported::Unknown`].
#[must_use]
pub fn parse_network_view(reply: &ControlReply) -> NetworkView {
    NetworkView {
        liveness: reported(value(reply, "network-liveness="), "up", "down"),
        circuits: reported(value(reply, "status/circuit-established="), "1", "0"),
    }
}

fn reported(got: Option<&str>, yes: &str, no: &str) -> Reported {
    match got {
        Some(text) if text == yes => Reported::Yes,
        Some(text) if text == no => Reported::No,
        _ => Reported::Unknown,
    }
}

fn value<'a>(reply: &'a ControlReply, key: &str) -> Option<&'a str> {
    reply
        .lines()
        .iter()
        .find_map(|line| line.strip_prefix(key))
        .map(str::trim)
}

#[cfg(test)]
mod tests {
    use super::super::framing::ReplyFramer;
    use super::*;

    fn reply_from(payload: &str) -> ControlReply {
        let mut framer = ReplyFramer::new();
        framer.push_bytes(format!("{payload}250 OK\r\n").as_bytes());
        framer
            .next_reply()
            .expect("well-formed")
            .expect("one reply")
    }

    #[test]
    fn both_keys_parse_among_the_other_sample_keys() {
        let reply = reply_from(
            "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"\r\n\
             250-traffic/read=17274230\r\n\
             250-network-liveness=down\r\n\
             250-status/circuit-established=1\r\n",
        );
        assert_eq!(
            parse_network_view(&reply),
            NetworkView {
                liveness: Reported::No,
                circuits: Reported::Yes,
            }
        );
        let reply = reply_from("250-network-liveness=up\r\n250-status/circuit-established=0\r\n");
        assert_eq!(
            parse_network_view(&reply),
            NetworkView {
                liveness: Reported::Yes,
                circuits: Reported::No,
            }
        );
    }

    #[test]
    fn a_missing_or_unknown_value_is_unknown_not_down() {
        let none = reply_from("250-traffic/read=1\r\n");
        assert_eq!(parse_network_view(&none), NetworkView::default());
        let odd =
            reply_from("250-network-liveness=maybe\r\n250-status/circuit-established=yes\r\n");
        assert_eq!(
            parse_network_view(&odd),
            NetworkView {
                liveness: Reported::Unknown,
                circuits: Reported::Unknown,
            }
        );
    }
}
