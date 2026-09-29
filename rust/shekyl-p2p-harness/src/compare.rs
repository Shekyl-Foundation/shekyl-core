// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Diff two runs of one seed.
//!
//! A difference in the parity fields is a finding. A difference named in
//! [`EXPECTED_DIVERGENCES`] is not: those are the places the seam is not
//! epee, and the harness does not "fix" them toward epee.

use crate::transcript::{Role, Transcript};

/// Named in `P2P_DIFFERENTIAL_HARNESS.md`. A parity field is not in this list.
pub const EXPECTED_DIVERGENCES: &[&str] = &[
    "fin-after-zero-bytes",
    "typed-cause-first-wins",
    "admission-reservation",
    "derived-deadline",
    "no-timer-split",
    "no-tos",
    "byte-bounds",
];

/// Wire bytes and the session outcome. Goldens keep these.
const PARITY: &[&str] = &[
    "peer-sent",
    "peer-recv",
    "peer-end",
    "host-delivered",
    "host-sent",
    "host-session",
];

/// One mismatch. `seed` is the replay key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub seed: u64,
    pub field: &'static str,
}

/// Two hosts, each with the peer's transcript and the host's transcript.
pub struct Run {
    pub peer: Transcript,
    pub host: Transcript,
}

/// Parity differences. Expected divergences are not returned.
pub fn diff(left: &Run, right: &Run) -> Vec<Finding> {
    let seed = left.peer.seed;
    let mut findings = Vec::new();
    if left.peer.seed != right.peer.seed || left.host.seed != seed || right.host.seed != seed {
        findings.push(Finding {
            seed,
            field: "seed",
        });
    }
    push_bytes(
        &mut findings,
        seed,
        "peer-sent",
        &left.peer.sent,
        &right.peer.sent,
    );
    push_bytes(
        &mut findings,
        seed,
        "peer-recv",
        &left.peer.recv,
        &right.peer.recv,
    );
    if left.peer.end != right.peer.end {
        findings.push(Finding {
            seed,
            field: "peer-end",
        });
    }
    push_bytes(
        &mut findings,
        seed,
        "host-delivered",
        &left.host.recv,
        &right.host.recv,
    );
    push_bytes(
        &mut findings,
        seed,
        "host-sent",
        &left.host.sent,
        &right.host.sent,
    );
    if left.host.end != right.host.end {
        findings.push(Finding {
            seed,
            field: "host-session",
        });
    }
    findings
        .into_iter()
        .filter(|finding| !is_expected_divergence(finding.field))
        .collect()
}

pub fn is_expected_divergence(field: &str) -> bool {
    EXPECTED_DIVERGENCES.contains(&field)
}

pub fn is_parity_field(field: &str) -> bool {
    PARITY.contains(&field) || field == "seed"
}

fn push_bytes(
    findings: &mut Vec<Finding>,
    seed: u64,
    field: &'static str,
    left: &[u8],
    right: &[u8],
) {
    if left != right {
        findings.push(Finding { seed, field });
    }
}

/// The peer and the host of one run agree on the bytes and the outcome.
pub fn run_agrees(run: &Run) -> bool {
    run.peer.role == Role::Peer
        && run.host.role == Role::Host
        && run.peer.seed == run.host.seed
        && run.peer.sent == run.host.recv
        && run.peer.recv == run.host.sent
        && run.peer.end == run.host.end
}
