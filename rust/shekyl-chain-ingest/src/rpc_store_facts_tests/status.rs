// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `daemon_status` over the store facts: the chain from the snapshot, and
//! the hasher's live-cache count in the part shown to `status`.

use super::*;

/// `daemon_status` over the store: the chain part from the snapshot and the
/// rules' derivations, everything else from the node's inputs.
#[tokio::test]
async fn daemon_status_reads_the_chain_from_the_store_and_the_rest_from_the_node() {
    let mut s = Scenario::open("rpc-store-facts-info");
    let mined = s.mine(5).await;
    let last = mined.last().expect("tip").clone();
    // The wire's `tx_count` excludes coinbases: every listed body, and
    // nothing else.
    let listed: u64 = mined
        .iter()
        .map(|m| u64::try_from(m.template.transactions.len()).expect("fits"))
        .sum();
    s.reopen(|path| {
        let store = Arc::new(open_store(path));
        let facts = facts_over(Arc::clone(&store), path, RULES);
        let info = daemon_status(
            &facts,
            &facts,
            Disclosure::FULL,
            0,
            tor_read(Disclosure::FULL),
        )
        .unwrap_or_else(|_| panic!("daemon_status"));
        assert_eq!(info.height.0, last.height.to_raw(), "the tip's height");
        assert_eq!(info.hash, hex(last.hash));
        assert!(info.synchronized);
        assert!(!info.degraded);
        assert_eq!(
            info.tx_count.shown().expect("the chain part is shown").0,
            listed,
            "every listed body, coinbases excluded"
        );
        assert_eq!(
            info.emission
                .shown()
                .expect("the chain part is shown")
                .to_atomic_units(),
            last.emission.coins_generated,
            "the accumulator through the tip"
        );
        // The scenario's fixed difficulty is the next block's too.
        assert_eq!(
            info.difficulty.shown().expect("the chain part is shown").0,
            1
        );
        assert_eq!(
            info.block_weight_max
                .shown()
                .expect("the chain part is shown")
                .0,
            2 * info
                .block_weight_median
                .shown()
                .expect("the chain part is shown")
                .0,
            "the limit is twice the effective median (CEN-G6b)"
        );
        assert_eq!(
            info.txpool_count
                .shown()
                .expect("the pool part is shown")
                .0
                .map(|count| count.0),
            Some(3),
            "the pool's broadcast count is the node's"
        );
        assert_eq!(
            info.alt_count.shown().map(|count| count.0),
            Some(0),
            "a full disclosure shows Status"
        );
        let restricted = daemon_status(
            &facts,
            &facts,
            Disclosure::VIEW,
            0,
            tor_read(Disclosure::VIEW),
        )
        .unwrap_or_else(|_| panic!("daemon_status"));
        assert!(restricted.alt_count.is_withheld(), "Status is withheld");
        assert!(restricted.connector.is_withheld(), "Peers is withheld");
        drop(facts);
        drop(store);
    })
    .await;
    s.close().await;
}

/// `daemon_status` reports the hasher's live caches (4.4,
/// `RANDOMX_CACHE_ACTOR.md` §5.6): the count is the length of the
/// hasher's published `Resident::caches` when the call is made, in the
/// part shown to `status`. A caller without that grant gets no part:
/// absent, never zero (RK-D23).
///
/// The facts here ask a hasher of the test's own, ranked with two seeds:
/// the status says two. The driver's chain is over the free longhash; the
/// count is the hasher's and not the chain's.
///
/// Red edits: in `StoreFacts::status`, report `0`, or count only warm
/// caches while one is building; in `info::daemon_status`, show the field
/// under `on_chain` instead of `on`: the restricted caller is shown it.
#[tokio::test]
async fn daemon_status_reports_the_hashers_live_caches_to_status_alone() {
    let mut s = Scenario::open("rpc-store-facts-caches");
    s.mine(2).await;
    let own = crate::test_support::own_hasher();
    let seed = |fill: u8| shekyl_pow_randomx::Seedhash::from_bytes([fill; 32]);
    own.hasher
        .rank(shekyl_hasher::Ranked::new(seed(0xc1), Some(seed(0xc2)), None).expect("two seeds"));
    assert_eq!(
        shekyl_hasher::quiet::seeds(&own.hasher.resident()).len(),
        2,
        "the hasher holds the two ranked seeds' caches"
    );
    s.reopen(|path| {
        let store = Arc::new(open_store(path));
        let facts = facts_with_hasher(Arc::clone(&store), path, RULES, own.hasher.clone());
        let full = daemon_status(
            &facts,
            &facts,
            Disclosure::FULL,
            0,
            tor_read(Disclosure::FULL),
        )
        .unwrap_or_else(|_| panic!("daemon_status"));
        assert_eq!(
            full.randomx_caches.shown().map(|count| count.0),
            Some(2),
            "a status call while the hasher holds two caches reports 2"
        );
        let restricted = daemon_status(
            &facts,
            &facts,
            Disclosure::VIEW,
            0,
            tor_read(Disclosure::VIEW),
        )
        .unwrap_or_else(|_| panic!("daemon_status"));
        assert!(
            restricted.randomx_caches.is_withheld(),
            "a caller without `status` gets no part"
        );
        drop(facts);
        drop(store);
    })
    .await;
    s.close().await;
}

/// What the daemon's Tor supervisor answers `disclosure`, which a store
/// test does not run: a Tor-off node's `hiding`, and its status only for a
/// caller shown Status, as the handler asks it.
fn tor_read(disclosure: Disclosure) -> shekyl_daemon_rpc::tor_facts::TorRead {
    use shekyl_tor_status::{Clearnet, Origination, Posture, TorSetting, TorStatus};
    shekyl_daemon_rpc::tor_facts::TorRead {
        hiding: false,
        status: disclosure.status().then(|| TorStatus {
            posture: Posture {
                tor: TorSetting::Off,
                clearnet: Clearnet::On,
            },
            origination: Origination::ClearnetOnly,
            sync_connector: vec![],
            tor_quiet: None,
            tor: None,
        }),
    }
}
