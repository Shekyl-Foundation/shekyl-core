// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The p2p conformance harness.
//!
//! One scripted peer, one seam host, and a comparator. The epee host is a
//! separate C++ binary that writes the same transcript. This crate does
//! not link epee. Before cutover the comparator diffs the two hosts.
//! At cutover the epee transcripts for the parity fields become goldens.
//! A golden changes only with a ruling, in that ruling's pull request.

#![deny(unsafe_code)]

mod compare;
mod handshake;
mod peer;
mod script;
mod seam_host;
mod transcript;

pub use compare::{
    diff, is_expected_divergence, is_parity_field, run_agrees, Finding, Run, EXPECTED_DIVERGENCES,
};
pub use handshake::{handshake, Handshake, HANDSHAKE_SEED};
pub use peer::run_peer;
pub use script::{known_seed, script, whole_message_count, SEED_CONCURRENT};
pub use seam_host::{serve_seam_once, SeamHost};
pub use transcript::{End, Event, Role, Transcript};

/// A harness failure. The seed, when there is one, stays on the transcript.
#[derive(Debug)]
pub struct Error {
    message: String,
}

impl Error {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::new(err.to_string())
    }
}

impl From<shekyl_levin::Error> for Error {
    fn from(err: shekyl_levin::Error) -> Self {
        Self::new(err.to_string())
    }
}

/// Run seed 1 against the seam host. The epee host is not in this process.
pub fn run_seam(seed: u64) -> Result<Run, Error> {
    let host = serve_seam_once(seed)?;
    let peer = run_peer(host.addr(), seed)?;
    let host = host.finish()?;
    Ok(Run { peer, host })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_transcript_round_trips_and_keeps_the_seed() {
        let transcript = Transcript {
            version: 1,
            seed: HANDSHAKE_SEED,
            role: Role::Peer,
            sent: vec![1, 2, 255],
            recv: vec![],
            end: End::Established,
            events: vec![],
        };
        let decoded = Transcript::decode(&transcript.encode()).expect("decode");
        assert_eq!(decoded, transcript);
    }

    #[test]
    fn parity_fields_are_not_expected_divergences() {
        for field in [
            "peer-sent",
            "peer-recv",
            "peer-end",
            "host-delivered",
            "host-sent",
            "host-session",
        ] {
            assert!(is_parity_field(field), "{field}");
            assert!(!is_expected_divergence(field), "{field}");
        }
        assert_eq!(EXPECTED_DIVERGENCES.len(), 7);
    }

    #[test]
    fn the_same_seed_replays_against_the_seam_host() {
        let first = run_seam(HANDSHAKE_SEED).expect("first");
        let second = run_seam(HANDSHAKE_SEED).expect("second");
        assert!(
            super::run_agrees(&first),
            "peer sent {} recv {} {:?} host sent {} recv {} {:?}",
            first.peer.sent.len(),
            first.peer.recv.len(),
            first.peer.end,
            first.host.sent.len(),
            first.host.recv.len(),
            first.host.end
        );
        assert_eq!(first.peer.end, End::Established);
        assert!(diff(&first, &second).is_empty());
        let mut broken = second;
        broken.peer.recv.push(0);
        let findings = diff(&first, &broken);
        assert_eq!(
            findings,
            vec![Finding {
                seed: HANDSHAKE_SEED,
                field: "peer-recv",
            }]
        );
    }

    #[test]
    fn each_leg_agrees_on_the_seam_host() {
        for seed in [1, 2, 3, 10, 11, 20, 30, 31, 32, 40, 100, 107] {
            let run = run_seam(seed).unwrap_or_else(|err| panic!("seed {seed}: {err}"));
            assert!(
                run_agrees(&run),
                "seed {seed} peer sent {} recv {} {:?} host sent {} recv {} {:?}",
                run.peer.sent.len(),
                run.peer.recv.len(),
                run.peer.end,
                run.host.sent.len(),
                run.host.recv.len(),
                run.host.end
            );
        }
        let concurrent = run_seam(SEED_CONCURRENT).expect("concurrent");
        assert_eq!(whole_message_count(&concurrent.peer.recv), Some(2));
        let stalled = run_seam(40).expect("backpressure");
        assert!(
            stalled
                .peer
                .events
                .iter()
                .any(|event| event.kind() == "stalled"),
            "peer events {:?}",
            stalled
                .peer
                .events
                .iter()
                .map(Event::kind)
                .collect::<Vec<_>>()
        );
    }
}
