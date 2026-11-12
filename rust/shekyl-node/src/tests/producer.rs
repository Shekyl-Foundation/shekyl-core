// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Which configurations build the fetch scheduler and run the bundle
//! producer, the descriptors the fetch client holds, and what
//! `shard_fetch` answers with and without a Tor.

use shekyl_daemon_config::sections::{Socks, Tor};
use shekyl_daemon_rpc::shard_view::{codes, shard_fetch};
use shekyl_rpc_types::errors::ErrorClass;
use shekyl_rpc_types::kinds::Integer;
use shekyl_rpc_types::wire::archival::ShardId;

use super::*;

fn operator_tor() -> Tor {
    Tor::Operator {
        socks: Socks {
            // Nothing listens here: a fetch would stall, and these tests
            // open none.
            endpoint: "127.0.0.1:9".parse().expect("endpoint"),
            credential: None,
        },
        onion: None,
    }
}

fn with_tor(config: &DaemonConfig, tor: Tor) -> DaemonConfig {
    let mut config = config.clone();
    config.tor = tor;
    config
}

/// The fetch client holds one SOCKS stream per slot and has exactly the
/// slots its lanes use: a node with a Tor, managed or the operator's,
/// holds the view lane's [`VIEW_SLOTS`], and the producer's
/// [`READS_AT_ONCE`] beside them when it mines. Tor off builds no client
/// and holds none.
///
/// Red edits: size a mining node's client without the view lane; reserve
/// the producer's reads for a node that does not mine.
///
/// [`VIEW_SLOTS`]: shekyl_archival_fetch_sched::VIEW_SLOTS
/// [`READS_AT_ONCE`]: shekyl_bundle_producer::read::READS_AT_ONCE
#[test]
fn the_fetch_client_holds_its_lanes_descriptors_only_under_a_tor() {
    let dir = tempfile::tempdir().expect("temp");
    let address = mining_address(shekyl_address::Network::Regtest);
    let reads = u64::try_from(shekyl_bundle_producer::read::READS_AT_ONCE.get()).expect("small");
    let views = u64::try_from(shekyl_archival_fetch_sched::VIEW_SLOTS.get()).expect("small");
    let managed = Tor::Managed { binary: None };

    let mining = dev_config(dir.path(), &["--mine-address", &address]);
    for tor in [managed.clone(), operator_tor()] {
        assert_eq!(
            fetch_descriptors(&with_tor(&mining, tor.clone())),
            reads + views,
            "{tor:?}: the producer's reads and the view lane"
        );
    }
    assert_eq!(
        fetch_descriptors(&with_tor(&mining, Tor::Off)),
        0,
        "Tor off"
    );

    let idle = dev_config(dir.path(), &[]);
    for tor in [managed, operator_tor()] {
        assert_eq!(
            fetch_descriptors(&with_tor(&idle, tor.clone())),
            views,
            "{tor:?}: the view lane alone"
        );
    }
    assert_eq!(fetch_descriptors(&with_tor(&idle, Tor::Off)), 0, "Tor off");
}

/// A node with Tor off has no client to read a shard through: its
/// `shard_fetch` refuses as Tor off, for the host and a bounded caller,
/// never as a fault (IG-Q90).
///
/// Red edit: hand the RPC the absent handle when there is no scheduler.
#[test]
fn a_node_with_tor_off_refuses_a_shard_fetch_as_tor_off() {
    let dir = tempfile::tempdir().expect("temp");
    let node = open_posted(dir.path(), &[]);
    let handles = node.handles(std::sync::Arc::new(shekyl_daemon_rpc::tor_facts::TorAbsent));
    let answers: Vec<_> = [false, true]
        .into_iter()
        .map(|bounded| {
            a_runtime().block_on(shard_fetch(
                &*handles.shard_view,
                ShardId { id: Integer(3) },
                bounded,
            ))
        })
        .collect();
    node.stop();
    for answer in answers {
        let error = answer.expect_err("Tor is off").into_error();
        assert_eq!(
            (error.class, error.diagnostic.code.as_str()),
            (ErrorClass::RefusedByMethod, codes::TOR_OFF)
        );
    }
}

/// A node with a Tor answers `shard_fetch` through its view desk, over its
/// own store: a shard past the genesis chain's tip is still open, which
/// the desk says before any dial. A node that does not mine builds the
/// desk too.
///
/// Red edit: build the scheduler only for a mining node.
#[test]
fn a_node_with_a_tor_answers_a_shard_fetch_through_its_desk() {
    let dir = tempfile::tempdir().expect("temp");
    std::fs::create_dir_all(dir.path()).expect("dir");
    let config = with_tor(&dev_config(dir.path(), &[]), operator_tor());
    let node = Node::open(OpenArgs {
        config: &config,
        version: "test".to_owned(),
        protocol_version: 1,
        release_build: false,
        supervisor: None,
        request_stop: Arc::new(|| {}),
        plan: test_plan(&config),
    })
    .expect("node");
    let handles = node.handles(std::sync::Arc::new(shekyl_daemon_rpc::tor_facts::TorAbsent));
    let answer = a_runtime().block_on(shard_fetch(
        &*handles.shard_view,
        ShardId { id: Integer(3) },
        true,
    ));
    node.stop();
    let error = answer.expect_err("no shard has closed").into_error();
    assert_eq!(
        (error.class, error.diagnostic.code.as_str()),
        (ErrorClass::RefusedByMethod, codes::OPEN)
    );
}
