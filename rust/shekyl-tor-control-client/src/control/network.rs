// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Tor's own view of its network, read with every supervisor sample
//! (`TOR_SUPERVISOR.md` §1 `TSR-Q14`, §4.2): `GETINFO network-liveness` and
//! `GETINFO status/circuit-established`. Tor decides whether it can build
//! circuits; the supervisor reads what it concludes, even when Tor sends
//! no event.

use super::framing::ControlReply;

/// `network-liveness`: `Some(true)` for `up`, `Some(false)` for `down`.
/// `None` when the reply carries no such line or a value this module does
/// not know: unknown, never down.
#[must_use]
pub fn parse_network_liveness(reply: &ControlReply) -> Option<bool> {
    match value(reply, "network-liveness=")? {
        "up" => Some(true),
        "down" => Some(false),
        _ => None,
    }
}

/// `status/circuit-established`: `Some(true)` for `1`, `Some(false)` for
/// `0`. `None` when absent or malformed: unknown, never down.
#[must_use]
pub fn parse_circuit_established(reply: &ControlReply) -> Option<bool> {
    match value(reply, "status/circuit-established=")? {
        "1" => Some(true),
        "0" => Some(false),
        _ => None,
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
        assert_eq!(parse_network_liveness(&reply), Some(false));
        assert_eq!(parse_circuit_established(&reply), Some(true));
        let reply = reply_from("250-network-liveness=up\r\n250-status/circuit-established=0\r\n");
        assert_eq!(parse_network_liveness(&reply), Some(true));
        assert_eq!(parse_circuit_established(&reply), Some(false));
    }

    #[test]
    fn a_missing_or_unknown_value_is_unknown_not_down() {
        let none = reply_from("250-traffic/read=1\r\n");
        assert_eq!(parse_network_liveness(&none), None);
        assert_eq!(parse_circuit_established(&none), None);
        let odd =
            reply_from("250-network-liveness=maybe\r\n250-status/circuit-established=yes\r\n");
        assert_eq!(parse_network_liveness(&odd), None);
        assert_eq!(parse_circuit_established(&odd), None);
    }
}
