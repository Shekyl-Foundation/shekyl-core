// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The p2p conformance harness.
//!
//! One scripted peer, one seam host, a comparator, and a driver that
//! runs every seed against both stacks. The epee host is a separate C++
//! recording binary: it takes [`script::AfterHandshake`] on the command
//! line and does not own the seed table. This crate does not link epee.
//! Before cutover the comparator diffs the two hosts. At cutover the
//! epee transcripts for the parity fields become goldens. After cutover
//! the same peer stays as the CI check on the Rust transport;
//! [`compare::DeferredInvariant`] is the vocabulary those later checks
//! use. A golden changes only with a ruling, in that ruling's pull request.

#![deny(unsafe_code)]

mod compare;
mod driver;
mod handshake;
mod peer;
mod script;
mod seam_host;
mod transcript;

pub use compare::{diff, run_agrees, run_matches_script, DeferredInvariant, Field, Finding, Run};
pub use driver::{epee_cli_args, host_wait_ms, run_all};
pub use handshake::{handshake, Handshake};
pub use peer::run_peer;
pub use script::{
    all_seeds, known_seed, script, whole_message_count, AfterHandshake, NamedSeed, Script,
    PROPERTY_SEEDS, READ_PAUSE, SEND_QUEUE_BYTES,
};
pub use seam_host::{serve_seam_once, SeamHost};
pub use transcript::{End, Event, Role, Transcript, TranscriptVersion};

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

/// Run a seed against the seam host. The epee host is not in this process.
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
            version: TranscriptVersion::V1,
            seed: NamedSeed::Handshake.as_u64(),
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
    fn the_same_seed_replays_against_the_seam_host() {
        let seed = NamedSeed::Handshake.as_u64();
        let first = run_seam(seed).expect("first");
        let second = run_seam(seed).expect("second");
        let plan = script(seed).expect("script");
        assert!(
            run_matches_script(&first, &plan),
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
        assert!(findings.iter().any(|finding| finding.field == Field::Run));
        assert!(findings
            .iter()
            .any(|finding| finding.field == Field::PeerRecv));
    }

    #[test]
    fn each_leg_matches_the_script_on_the_seam_host() {
        for seed in all_seeds() {
            let plan = script(seed).unwrap_or_else(|err| panic!("script {seed}: {err}"));
            let run = run_seam(seed).unwrap_or_else(|err| panic!("seed {seed}: {err}"));
            assert!(
                run_matches_script(&run, &plan),
                "seed {seed} peer sent {} recv {} {:?} host sent {} recv {} {:?}",
                run.peer.sent.len(),
                run.peer.recv.len(),
                run.peer.end,
                run.host.sent.len(),
                run.host.recv.len(),
                run.host.end
            );
            assert_eq!(run.peer.end, plan.end, "seed {seed} end");
        }
        let concurrent = run_seam(NamedSeed::Concurrent.as_u64()).expect("concurrent");
        assert_eq!(whole_message_count(&concurrent.peer.recv), Some(2));
        let stalled = run_seam(NamedSeed::Backpressure.as_u64()).expect("backpressure");
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
