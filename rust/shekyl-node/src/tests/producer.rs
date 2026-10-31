// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Which configurations run the bundle producer, and the descriptors its
//! reads hold.

use shekyl_daemon_config::sections::{Socks, Tor};

use super::*;

/// The producer runs when the node mines and has a Tor, managed or the
/// operator's, and then holds at most one SOCKS stream per slot of its
/// fetch client. A node that does not mine, or has Tor off, runs none and
/// holds none. Reserving the reads under only one Tor, or for a node that
/// does not mine, fails this.
#[test]
fn the_producer_holds_its_reads_descriptors_only_when_it_runs() {
    let dir = tempfile::tempdir().expect("temp");
    let address = mining_address(shekyl_address::Network::Mainnet);
    let reads = u64::try_from(shekyl_bundle_producer::read::READS_AT_ONCE.get()).expect("small");
    assert_eq!(
        reads,
        u64::try_from(shekyl_archival_fetch_sched::MAX_INFLIGHT).expect("small"),
        "one stream per slot of the client"
    );
    let with = |config: &DaemonConfig, tor: Tor| {
        let mut config = config.clone();
        config.tor = tor;
        config
    };
    let managed = Tor::Managed { binary: None };
    let operator = Tor::Operator {
        socks: Socks {
            endpoint: "127.0.0.1:9050".parse().expect("endpoint"),
            credential: None,
        },
        onion: None,
    };

    let mining = dev_config(dir.path(), &["--mine-address", &address]);
    assert_eq!(producer_descriptors(&with(&mining, managed.clone())), reads);
    assert_eq!(
        producer_descriptors(&with(&mining, operator.clone())),
        reads
    );
    assert_eq!(producer_descriptors(&with(&mining, Tor::Off)), 0, "Tor off");

    let idle = dev_config(dir.path(), &[]);
    assert_eq!(producer_descriptors(&with(&idle, managed)), 0, "not mining");
    assert_eq!(
        producer_descriptors(&with(&idle, operator)),
        0,
        "not mining"
    );
}
