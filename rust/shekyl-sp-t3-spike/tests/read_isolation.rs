// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `SF-D3`: does tor give each read its own rendezvous circuit?
//!
//! `shekyl-p-fetch`'s own tests show the client presents SOCKS credentials
//! that differ between reads and repeat inside one. They cannot show what
//! tor does with them, and the ruling rests on that. This asks tor: it reads
//! the client tor's control port and compares the circuits it attached the
//! streams to.
//!
//! Two parts, on opposite sides of one seam:
//!
//! - **The reading of control events** is pure and is unit-tested here, with
//!   no tor.
//! - **The live run** is `#[ignore]`d. It needs the pinned tor binary and the
//!   network, publishes an onion and fetches from it over real rendezvous
//!   circuits.
//!
//! Run with:
//! ```text
//! SHEKYL_SPIKE_TOR=/path/to/pinned/tor \
//!   cargo test -p shekyl-sp-t3-spike --test read_isolation -- --ignored --nocapture
//! ```
//!
//! The live run also reports, without asserting, whether a read under new
//! credentials made tor fetch the onion's descriptor again (`BA-T31`).

use std::collections::{BTreeMap, HashMap};

use shekyl_tor_control_client::control::{parse_stream_event, CircId, ControlReply};

/// What the client tor reported while reads were made.
#[derive(Debug, Default)]
struct Observed {
    /// The circuits tor attached a stream to, by the SOCKS username the
    /// stream's dial presented, in the order tor reported them.
    circuits_by_username: BTreeMap<String, Vec<CircId>>,
    /// The purpose tor gave each circuit it reported.
    purpose_by_circuit: HashMap<CircId, String>,
    /// Descriptor fetches tor started.
    descriptor_requests: usize,
}

impl Observed {
    /// Fold one async control reply in. Replies that are not a `STREAM`,
    /// `CIRC`, `CIRC_MINOR` or `HS_DESC` event are ignored.
    fn fold(&mut self, reply: &ControlReply) {
        let Some(line) = reply.lines().first() else {
            return;
        };
        if let Some(event) = parse_stream_event(reply) {
            // A stream is on circuit 0 until tor attaches it.
            if event.circ_id() != CircId::new(0) {
                if let Some(username) = event.socks_username() {
                    let seen = self
                        .circuits_by_username
                        .entry(username.to_owned())
                        .or_default();
                    if seen.last() != Some(&event.circ_id()) {
                        seen.push(event.circ_id());
                    }
                }
            }
            return;
        }
        let mut fields = line.split_ascii_whitespace();
        match fields.next() {
            // `CIRC` reports a circuit's purpose as it is built. A circuit tor
            // had built ahead and then put to use changes purpose afterwards,
            // and that change is a `CIRC_MINOR` event. The later one wins.
            Some("CIRC" | "CIRC_MINOR") => {
                let id = fields.next().and_then(|id| id.parse().ok());
                if let (Some(id), Some(purpose)) = (id, bare_field(line, "PURPOSE")) {
                    self.purpose_by_circuit.insert(CircId::new(id), purpose);
                }
            }
            Some("HS_DESC") if fields.next() == Some("REQUESTED") => {
                self.descriptor_requests += 1;
            }
            _ => {}
        }
    }

    /// The circuits tor attached to streams that presented `username`, in the
    /// order it reported the attachments. The same circuit reported again is
    /// one attachment.
    ///
    /// # Panics
    ///
    /// If tor reported no attachment for `username`. A missing observation is
    /// not an empty set a caller could read as isolation. More than one
    /// circuit is an answer, not a panic: a read whose circuit Tor replaces
    /// is still that read.
    fn circuits_of(&self, username: &str) -> &[CircId] {
        match self.circuits_by_username.get(username) {
            Some(circuits) if !circuits.is_empty() => circuits.as_slice(),
            // Which of the two it was says where to look: a tor that reports
            // no credentials on any stream, or a read that never attached.
            // Nothing about the streams themselves goes into the message.
            None if self.circuits_by_username.is_empty() => {
                panic!("tor reported no attached stream for this read, or for any other")
            }
            _ => panic!("tor reported no attached stream for this read, only for others"),
        }
    }
}

/// No circuit of `read` is a circuit of `other`.
///
/// A read that rode two circuits because Tor replaced the first is isolated
/// from another read exactly when the other rode neither. Sharing either one
/// is the isolation failure.
fn isolated(read: &[CircId], other: &[CircId]) -> bool {
    other.iter().all(|circuit| !read.contains(circuit))
}

/// `KEY=value` in a control event line, the value up to the next space.
fn bare_field(line: &str, key: &str) -> Option<String> {
    line.split_ascii_whitespace()
        .find_map(|field| field.strip_prefix(&format!("{key}=")))
        .map(str::to_owned)
}

#[cfg(test)]
mod reading {
    use super::*;
    use shekyl_tor_control_client::control::ReplyFramer;

    fn event(wire: &str) -> ControlReply {
        let mut framer = ReplyFramer::default();
        framer.push_bytes(wire.as_bytes());
        framer.next_reply().expect("frames").expect("one reply")
    }

    fn observed(lines: &[&str]) -> Observed {
        let mut o = Observed::default();
        for line in lines {
            o.fold(&event(line));
        }
        o
    }

    #[test]
    fn a_stream_is_filed_under_its_username_once_it_has_a_circuit() {
        let o = observed(&[
            "650 STREAM 7 NEW 0 abc.onion:80 SOCKS_USERNAME=\"aa\" SOCKS_PASSWORD=\"p\"\r\n",
            "650 STREAM 7 SENTCONNECT 12 abc.onion:80 SOCKS_USERNAME=\"aa\" SOCKS_PASSWORD=\"p\"\r\n",
            "650 STREAM 7 SUCCEEDED 12 abc.onion:80 SOCKS_USERNAME=\"aa\" SOCKS_PASSWORD=\"p\"\r\n",
            "650 STREAM 9 SUCCEEDED 15 abc.onion:80 SOCKS_USERNAME=\"bb\" SOCKS_PASSWORD=\"p\"\r\n",
        ]);
        assert_eq!(o.circuits_of("aa"), &[CircId::new(12)]);
        assert_eq!(o.circuits_of("bb"), &[CircId::new(15)]);
    }

    #[test]
    fn two_streams_under_one_username_on_one_circuit_are_one_circuit() {
        let o = observed(&[
            "650 STREAM 7 SUCCEEDED 12 abc.onion:80 SOCKS_USERNAME=\"aa\"\r\n",
            "650 STREAM 8 SUCCEEDED 12 abc.onion:80 SOCKS_USERNAME=\"aa\"\r\n",
        ]);
        assert_eq!(o.circuits_of("aa"), &[CircId::new(12)]);
    }

    #[test]
    fn two_circuits_under_one_username_are_kept_in_order() {
        // A replacement under the same credentials is still this read. The
        // fold keeps both attachments; isolation is decided across reads.
        let o = observed(&[
            "650 STREAM 7 SUCCEEDED 12 abc.onion:80 SOCKS_USERNAME=\"aa\"\r\n",
            "650 STREAM 8 SUCCEEDED 13 abc.onion:80 SOCKS_USERNAME=\"aa\"\r\n",
        ]);
        assert_eq!(o.circuits_of("aa"), &[CircId::new(12), CircId::new(13)]);
    }

    #[test]
    fn isolation_holds_across_a_replacement_and_fails_when_a_circuit_is_shared() {
        let read_a = [CircId::new(12), CircId::new(13)];
        assert!(isolated(&read_a, &[CircId::new(20)]));
        assert!(!isolated(&read_a, &[CircId::new(13)]));
    }

    #[test]
    #[should_panic(expected = "no attached stream")]
    fn a_stream_with_no_username_is_not_filed() {
        // A tor too old to report the field, or a dial with no credentials:
        // the read is then not found, and the run fails rather than passing
        // on an empty comparison.
        let o = observed(&["650 STREAM 7 SUCCEEDED 12 abc.onion:80\r\n"]);
        let _ = o.circuits_of("aa");
    }

    #[test]
    fn a_purpose_change_replaces_the_purpose_the_circuit_was_built_with() {
        // What the first run on a real tor showed: a read's circuit was
        // built ahead as `HS_VANGUARDS` and became the rendezvous later.
        let o = observed(&[
            "650 CIRC 15 BUILT $A~a,$B~b PURPOSE=HS_VANGUARDS\r\n",
            "650 CIRC_MINOR 15 PURPOSE_CHANGED $A~a,$B~b PURPOSE=HS_CLIENT_REND HS_STATE=HSCR_CONNECTING OLD_PURPOSE=HS_VANGUARDS\r\n",
        ]);
        assert_eq!(o.purpose_by_circuit[&CircId::new(15)], "HS_CLIENT_REND");
    }

    #[test]
    fn circuit_purposes_and_descriptor_requests_are_counted() {
        let o = observed(&[
            "650 CIRC 12 BUILT $A~a,$B~b BUILD_FLAGS=IS_INTERNAL PURPOSE=HS_CLIENT_REND HS_STATE=HSCR_JOINED\r\n",
            "650 CIRC 14 BUILT $A~a PURPOSE=GENERAL\r\n",
            "650 HS_DESC REQUESTED abc NO_AUTH $F~f descid\r\n",
            "650 HS_DESC RECEIVED abc NO_AUTH $F~f descid\r\n",
        ]);
        assert_eq!(o.purpose_by_circuit[&CircId::new(12)], "HS_CLIENT_REND");
        assert_eq!(o.purpose_by_circuit[&CircId::new(14)], "GENERAL");
        assert_eq!(o.descriptor_requests, 1);
    }
}

/// The live run. Everything that waits on a socket or a network is here.
mod live {
    use super::{isolated, Observed};
    use std::sync::Arc;
    use std::time::Duration;

    use shekyl_p_fetch::{FetchError, RequestHeader, Stall, Timeouts};
    use shekyl_sp_t3_spike::harness::{Apparatus, APPARATUS_ANCHOR_HASH, APPARATUS_ANCHOR_HEIGHT};
    use shekyl_tor_control_client::control::{CircId, ControlReply};
    use shekyl_types::BlockHeight;
    use tokio::sync::mpsc::UnboundedReceiver;

    /// `SF-D6`'s stall-retry budget inside one read.
    const STALL_RETRIES: u32 = 2;

    /// The pinned tor binary. Hard-fails rather than skipping, so a lane
    /// that is not set up is loud.
    fn tor_binary() -> std::path::PathBuf {
        std::env::var_os("SHEKYL_SPIKE_TOR")
            .map(std::path::PathBuf::from)
            .expect("SHEKYL_SPIKE_TOR must point at the pinned Tor Expert Bundle binary")
    }

    fn fresh_header() -> RequestHeader {
        RequestHeader::fresh(
            BlockHeight::from_raw(APPARATUS_ANCHOR_HEIGHT),
            APPARATUS_ANCHOR_HASH,
        )
        .expect("OS entropy")
    }

    /// The SOCKS username a read under `header` presents: its nonce in
    /// lowercase hex. Written out here, not taken from the client, so the
    /// run fails if the client stops presenting it.
    fn username_of(header: &RequestHeader) -> String {
        header.nonce().iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Take what tor has reported so far, and what it reports in the next
    /// moment: a stream's last events trail the fetch that caused them.
    async fn drain(rx: &mut UnboundedReceiver<ControlReply>, into: &mut Observed) {
        while let Ok(Some(reply)) = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await {
            into.fold(&reply);
        }
    }

    /// Fetch under `header` until it completes, repeating the header on a
    /// stall as the caller does, within `SF-D6`'s budget of
    /// [`STALL_RETRIES`]. `already` is how many stall retries this read has
    /// used before the call. Returns the retries used in all.
    ///
    /// A retry can itself stall on a real network, and so can a first
    /// attempt. Neither is what this run is asking about.
    async fn complete(app: &Apparatus, shard: u64, header: &RequestHeader, already: u32) -> u32 {
        let mut retries = already;
        loop {
            match app.fetch_with(0, shard, header, Timeouts::DEFAULT).await {
                Ok(_) => return retries,
                Err(FetchError::Stall(stall)) if retries < STALL_RETRIES => {
                    retries += 1;
                    println!("a fetch stalled ({stall}); stall retry {retries} of this read");
                }
                Err(other) => panic!("a read did not complete within its retries: {other}"),
            }
        }
    }

    /// Two reads of one shard ride no circuit in common.
    ///
    /// The first read stalls and retries on the same header. A replacement
    /// circuit under those credentials is printed and does not fail the run.
    /// The run fails when a circuit one read rode is a circuit the other
    /// rode, or when a circuit's purpose is not the rendezvous.
    #[tokio::test]
    #[ignore = "requires the pinned Tor binary via SHEKYL_SPIKE_TOR (bootstraps, publishes an onion, network)"]
    async fn reads_ride_disjoint_rendezvous_circuits() {
        let payload: Vec<u8> = (0..64_000u32).map(|i| (i % 251) as u8).collect();
        let dir = tempfile::tempdir().expect("tempdir");
        let app = Apparatus::bring_up(
            tor_binary(),
            dir.path().join("tor-data"),
            1,
            Arc::from(payload.into_boxed_slice()),
        )
        .await
        .expect("apparatus comes up");
        app.await_reachable().await.expect("the persona answers");

        let mut events = app
            .observe_client(&["STREAM", "CIRC", "CIRC_MINOR", "HS_DESC"])
            .await
            .expect("the client tor reports its streams");
        let shard = 0;

        // Read A, first attempt: bounded so that it stalls after the dial.
        // The dial keeps its full budget, so the stream is attached to a
        // circuit before the head timeout ends the attempt.
        let read_a = fresh_header();
        let stalling = Timeouts {
            head: Duration::from_millis(1),
            ..Timeouts::DEFAULT
        };
        let first = app.fetch_with(0, shard, &read_a, stalling).await;
        assert!(
            matches!(first, Err(FetchError::Stall(Stall::HeadTimeout))),
            "the first attempt was meant to stall on the head, got {first:?}"
        );
        let mut after_stall = Observed::default();
        drain(&mut events, &mut after_stall).await;
        let username_a = username_of(&read_a);
        let stalled_on = after_stall.circuits_of(&username_a);

        // Read A, the stall retries: the same header, as `SF-D6` has it.
        let mut during_a = Observed::default();
        let retries = complete(&app, shard, &read_a, 1).await;
        println!("read A: completed on stall retry {retries}");
        drain(&mut events, &mut during_a).await;
        let retried_on = during_a.circuits_of(&username_a);

        // Read B: a new read of the same shard from the same persona.
        let read_b = fresh_header();
        let mut during_b = Observed::default();
        let attempts = complete(&app, shard, &read_b, 0).await + 1;
        println!("read B: completed on attempt {attempts}");
        drain(&mut events, &mut during_b).await;
        let b_on = during_b.circuits_of(&username_of(&read_b));

        // Circuit ids are not printed: the control crate keeps them out of
        // every log, and the verdict needs only whether the reads share one.
        // A circuit's purpose is the last one tor reported for it, in
        // whichever window that fell: tor builds circuits ahead, so a read's
        // circuit can first appear, under another purpose, while an earlier
        // read is in progress. Newest window first.
        let purpose = |circuit: CircId| {
            [&during_b, &during_a, &after_stall]
                .iter()
                .find_map(|o| o.purpose_by_circuit.get(&circuit).cloned())
        };
        // Same credentials keep the retry in this read's isolation domain.
        // They do not promise the circuit id. A replacement is Tor retiring
        // a circuit, and it is reported on its own so it is not read as the
        // two reads sharing one.
        let retry_replaced = retried_on
            .iter()
            .any(|circuit| !stalled_on.contains(circuit));
        println!(
            "read A: the stall retry {} (purpose {:?})",
            if retry_replaced {
                "built a replacement circuit under the same credentials"
            } else {
                "rode a circuit the stalled attempt already used"
            },
            purpose(retried_on[retried_on.len() - 1])
        );
        let mut read_a_circuits = Vec::with_capacity(stalled_on.len() + retried_on.len());
        read_a_circuits.extend_from_slice(stalled_on);
        read_a_circuits.extend_from_slice(retried_on);
        let shared = !isolated(&read_a_circuits, b_on);
        println!(
            "read B: {} a circuit with read A (purpose {:?})",
            if shared { "shared" } else { "did not share" },
            purpose(b_on[b_on.len() - 1])
        );
        println!(
            "descriptor fetches tor started: {} during read A's retry, {} during read B",
            during_a.descriptor_requests, during_b.descriptor_requests
        );

        assert!(!shared, "two reads shared a circuit");
        // Every circuit either read rode to the onion. Each was put to use
        // after the subscription, so tor reported its purpose; a circuit
        // with none on record is a run that did not see what it compared.
        for circuit in read_a_circuits.iter().chain(b_on.iter()).copied() {
            assert_eq!(
                purpose(circuit).as_deref(),
                Some("HS_CLIENT_REND"),
                "a read's circuit is not a rendezvous circuit"
            );
        }

        app.shutdown().await;
    }
}
