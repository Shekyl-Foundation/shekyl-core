// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `GETINFO traffic/read` reply parsing: the bytes Tor has read from the
//! network since it started (Tor's control-spec `traffic/read`).
//!
//! The supervisor asks it with every sample. During a bootstrap it tells a
//! slow directory mirror (bytes moving, the percent held) from one that is
//! not answering (nothing moving), which the bootstrap percent alone cannot:
//! Tor counts descriptors only as each batch completes (`TOR_SUPERVISOR.md`
//! §5, §10 `TSR-M1`).

use super::framing::ControlReply;

/// Extract the byte count from a `GETINFO traffic/read` reply. `None` when
/// the reply carries no such line or its value is not a decimal count:
/// unknown, never zero, so a malformed reply is not read as a stall.
#[must_use]
pub fn parse_traffic_read(reply: &ControlReply) -> Option<u64> {
    reply
        .lines()
        .iter()
        .find_map(|line| line.strip_prefix("traffic/read="))
        .and_then(|value| value.trim().parse::<u64>().ok())
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
    fn traffic_read_parses_among_the_other_keys() {
        let reply = reply_from(
            "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=55 TAG=loading_descriptors SUMMARY=\"Loading relay descriptors\"\r\n\
             250-net/listeners/socks=\"127.0.0.1:43529\"\r\n\
             250-traffic/read=17274230\r\n",
        );
        assert_eq!(parse_traffic_read(&reply), Some(17_274_230));
    }

    #[test]
    fn a_missing_or_malformed_count_is_unknown_not_zero() {
        assert_eq!(
            parse_traffic_read(&reply_from("250-net/listeners/socks=\"127.0.0.1:1\"\r\n")),
            None
        );
        assert_eq!(
            parse_traffic_read(&reply_from("250-traffic/read=-1\r\n")),
            None
        );
        assert_eq!(
            parse_traffic_read(&reply_from("250-traffic/read=12kB\r\n")),
            None
        );
    }
}
