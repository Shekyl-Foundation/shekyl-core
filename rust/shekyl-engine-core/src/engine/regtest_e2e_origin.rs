// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Origin-guard rig and the live `daemon_status` gates.
//!
//! A `#[path]` child of the regtest harness, so `regtest_e2e` stays the shared
//! daemon lifecycle. The stem/sink pair holds a transaction un-broadcast for
//! longer than one assertion, which one daemon cannot do. The restricted-listener
//! and console gates that read `daemon_status` live here with it.
//! The embargo walks are [`embargo`].

// The production debug-macro lint treats a file as test code only when the
// file itself carries this attribute. The parent harness is already
// test-only; this sibling has to say so on its own.
#![cfg(test)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use shekyl_rpc_client::{wire, Rpc};
use shekyl_rpc_transport::HttpRpc;
use shekyl_rpc_types::hash::HashHex;
use shekyl_rpc_types::kinds::NoParams;
use shekyl_rpc_types::wire::daemon::{DaemonStatus, GrantName};
use shekyl_rpc_types::wire::shared::{Slot, SlotState};
use shekyl_types::TxHash;
use tokio::sync::RwLock;

use super::*;

/// Two linked regtest daemons: an **origin** a wallet submits to, and a
/// **sink** that drops what it is sent.
///
/// This is the rig that holds a transaction un-broadcast for longer than an
/// assertion takes, which one daemon cannot do. An `--offline` daemon has no
/// route, so it broadcast-records a submitted transaction within
/// milliseconds; the single-node form of the test this rig serves found that
/// window already shut on one run in three
/// (`DAEMON_RPC_KV_CUTOVER.md` §7, 2026-08-27).
///
/// **What holds the transaction.** The origin's only outbound peer is the
/// sink. A transaction the origin's own wallet submits is a local origin, and
/// a local origin takes the stem slot whatever the epoch draw
/// (`Relay::plan_relay`), so the origin sends it to the sink on the stem and
/// records it `stem`, embargoed. The sink admits it
/// (`restricted_listener_hides_a_transaction_this_node_has_not_broadcast`
/// asserts that) and has nowhere to send it. Its only session is the
/// origin's, the one the stem arrived on: a stem goes out on an outbound
/// session other than its source, and a fluff to every peer but its source.
/// The sink's closed peer is an unanswered port on `127.0.0.1`
/// (`Peering::Listening`). Once the origin's session is up, that host is
/// held and the sink does not dial it again (Rick, 2026-11-09), so the
/// pair holds one session, the origin's. A sink that dialed the origin
/// first would take that session and leave the origin no stem successor.
/// The transaction stays `stem` on the origin until the origin's own
/// embargo expires. A second
/// session between the two would carry the stem straight back, the origin
/// would take the second arrival as a fluff, and the hold would be over in
/// seconds. The sink also runs `--dev-sync off`: it requests nothing and
/// follows the origin by announcements alone, which still keeps it at the
/// origin's tip.
///
/// **What the rig does not fix.** The embargo is a draw (geometric, mean
/// 190 s on clearnet) with no lever, so a short one can end mid-assertion.
/// The rig does not pretend otherwise: [`StemSinkPair::stem_held`] reads the
/// state back, and a caller brackets its assertions with it.
pub(super) struct StemSinkPair {
    origin: RegtestDaemon,
    /// The origin's one peer, a second daemon; the stems it receives are
    /// read from its own pool.
    sink: RegtestDaemon,
}

/// `tx_list` for one id, as `rpc`'s caller is answered.
async fn tx_slot(rpc: &HttpRpc, txid: TxHash) -> Slot<wire::tx::TxEntry> {
    rpc.call::<wire::TxList>(wire::tx::TxListQuery {
        id: vec![HashHex::from_bytes(txid.to_bytes())],
        prune: true,
    })
    .await
    .expect("tx_list")
    .pop()
    .expect("one slot for one id")
}

/// Whether `rpc`'s caller is shown `txid` in the pool's list.
async fn pool_lists(rpc: &HttpRpc, txid: TxHash) -> bool {
    rpc.call::<wire::TxpoolList>(NoParams)
        .await
        .expect("txpool_list")
        .iter()
        .any(|entry| entry.id.to_bytes() == txid.to_bytes())
}

/// Where the origin holds a transaction, read from its unrestricted listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StemHold {
    /// In its stem phase: admitted and not shown, whether the stem send has
    /// gone out or not (the wire does not say which).
    Stem,
    /// Broadcast: the embargo ended, or the transaction came back fluffed.
    Broadcast,
    /// Not in the pool at all.
    Absent,
}

impl StemSinkPair {
    /// Spawn the sink, then the origin with a restricted listener, and wait
    /// until the origin holds an outbound session to the sink and reports
    /// itself synchronized. The two must link **before** anything is mined:
    /// a node becomes synchronized from a handshake with a peer at its own
    /// height, and an unsynchronized node withholds a local origin instead
    /// of stemming it.
    /// Spawn the pair mining coinbase to `seed`'s primary address (N2).
    pub(super) async fn start_for_seed(
        seed: &[u8; shekyl_crypto_pq::account::SEED_BYTES],
    ) -> StemSinkPair {
        let serial = serial_lock().lock_owned().await;
        let origin_p2p = RegtestDaemon::free_port();
        let sink_p2p = RegtestDaemon::free_port_excluding(&[origin_p2p]);
        let mine_address = mine_address_from_seed(seed, shekyl_address::Network::Regtest);
        let sink = RegtestDaemon::spawn(
            RegtestSpawn::new(None)
                .with_ports_taken([origin_p2p])
                .with_peering(Peering::Listening {
                    p2p_port: sink_p2p,
                    requests: false,
                }),
        )
        .await;
        let origin = RegtestDaemon::spawn(
            RegtestSpawn::new(Some(serial))
                .with_restricted_listener()
                .with_mine_address(mine_address)
                .with_peering(Peering::Linked {
                    p2p_port: origin_p2p,
                    peer_p2p_port: sink_p2p,
                }),
        )
        .await;
        let pair = StemSinkPair { origin, sink };
        pair.await_linked().await;
        pair
    }

    /// The daemon a wallet submits to. It carries both listeners.
    pub(super) fn sink(&self) -> &RegtestDaemon {
        &self.sink
    }

    pub(super) fn origin(&self) -> &RegtestDaemon {
        &self.origin
    }

    async fn await_linked(&self) {
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut last = String::new();
        while Instant::now() < deadline {
            let connections = self
                .origin
                .rpc
                .call::<wire::PeerConnections>(NoParams)
                .await
                .expect("origin peer_connections");
            let outbound = connections.iter().filter(|c| !c.inbound).count();
            let synchronized = self.origin.status().await.synchronized;
            if outbound >= 1 && synchronized {
                return;
            }
            last = format!("outbound sessions {outbound}, synchronized {synchronized}");
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        self.origin.panic_with_log(
            "the origin never linked to the sink",
            format!("after 60s: {last}"),
        );
    }

    /// Where the origin holds `txid` now.
    ///
    /// Read from the host's `tx_list`, whose pool entry carries the relay
    /// state as the pool's one bit (IG-Q57): `public` is whether the node
    /// shows the entry, `false` through its stem phase.
    pub(super) async fn stem_held(&self, txid: TxHash) -> StemHold {
        match tx_slot(&self.origin.rpc, txid).await {
            Slot::Item(entry) if entry.pooled && entry.public.0 == Some(false) => StemHold::Stem,
            Slot::Item(entry) if entry.pooled => StemHold::Broadcast,
            _ => StemHold::Absent,
        }
    }
}

/// The restricted listener's posture reaches the handlers.
///
/// The listener a request arrives on decides what the handler discloses
/// and whether it is bounded. Two legs:
///
/// - `daemon_status`: the listener's grants become the reply's parts. The
///   view listener holds no `status` or `peers` grant and is not the host,
///   so its reply carries no Status, Peers or host-only part, and its
///   `grant` list says so; the admin listener's carries all three, with
///   real values (RK-D23).
/// - `block_header_list` over `RESTRICTED_BLOCK_COUNT` hashes is refused on
///   the view listener (`bound.block`).
///
/// Admin-only method gating is
/// `admin_methods_are_refused_only_on_the_restricted_listener` in
/// `shekyl-daemon-rpc`. The histogram deletion gate is
/// `get_output_histogram_stays_unrouted`.
///
/// Both listeners come from one daemon, so the postures are compared against
/// the same chain in the same process, and the admin rows are the
/// blast-radius check: the restricted posture must not narrow the admin
/// listener.
#[tokio::test]
#[ignore = "Track-2 regtest: requires SHEKYLD_BIN; spawns a live daemon"]
async fn restricted_listener_is_withheld_status_and_capped_by_native_handlers() {
    use shekyl_rpc_client::ErrorClass;
    /// `RESTRICTED_BLOCK_COUNT`, the cap on `block_header_list` by hash.
    const BLOCK_CAP: usize = 1000;

    let daemon = RegtestDaemon::start_with_restricted_listener().await;
    let restricted = HttpRpc::new(daemon.restricted_url().to_owned())
        .await
        .expect("restricted rpc client");
    let unrestricted = HttpRpc::new(format!("http://127.0.0.1:{}", daemon.rpc_port()))
        .await
        .expect("unrestricted rpc client");

    // ── daemon_status: the listener decides the disclosure ──────────────
    let admin_info: DaemonStatus = unrestricted
        .call::<wire::DaemonStatus>(NoParams)
        .await
        .expect("admin daemon_status");
    let restricted_info: DaemonStatus = restricted
        .call::<wire::DaemonStatus>(NoParams)
        .await
        .expect("restricted daemon_status");
    assert!(
        admin_info.grant.contains(&GrantName::Status)
            && !restricted_info.grant.contains(&GrantName::Status),
        "each listener must say which it is: admin {:?}, restricted {:?}",
        admin_info.grant,
        restricted_info.grant
    );
    // A caller without the `status` and `peers` grants is not shown those
    // parts, and the reply does not carry them. If either part is here, the
    // handler answered the view listener as it answers the host.
    assert!(
        restricted_info.started.is_withheld() && restricted_info.revision.is_withheld(),
        "a restricted listener must not disclose Status: the start time, free \
         space, the store's size, the build's revision, the connection counts"
    );
    assert!(
        restricted_info.connector.is_withheld(),
        "a restricted listener must not disclose Peers: the connectors' counts"
    );
    assert!(
        restricted_info.txpool_private_count.is_withheld(),
        "a restricted listener is not the host"
    );
    assert!(
        !admin_info.connector.is_withheld(),
        "the admin listener is shown Peers"
    );
    let started = admin_info.started.shown().expect("admin is shown Status");
    let revision = admin_info
        .revision
        .clone()
        .shown()
        .expect("admin is shown Status");
    let disk_free = admin_info.disk_free.shown().expect("admin is shown Status");
    assert!(
        started.0 > 0 && !revision.0.is_empty(),
        "the admin listener must still report the start time and the revision — \
         otherwise the assertions above would hold for a daemon that reports \
         nothing to anyone"
    );
    assert_ne!(
        disk_free.0,
        u64::MAX,
        "the admin listener must report the volume's real free space"
    );
    // The two listeners describe the same chain.
    assert_eq!(restricted_info.height, admin_info.height);
    // Health is told to both. This daemon runs `--offline`, which binds no
    // p2p hub at all. It still answers, and says it is offline, with
    // `peered: null` beside it (Rick, 2026-10-14).
    for (listener, info) in [("restricted", &restricted_info), ("admin", &admin_info)] {
        assert!(
            info.offline && info.peered.0.is_none(),
            "{listener}: the harness starts this daemon offline, and it says so"
        );
    }

    // ── the header cap ──────────────────────────────────────────────────
    let hashes: Vec<HashHex> = (0..=BLOCK_CAP)
        .map(|i| {
            let mut bytes = [0u8; 32];
            bytes[24..].copy_from_slice(&(i as u64).to_be_bytes());
            HashHex::from_bytes(bytes)
        })
        .collect();
    let refused = restricted
        .call_or_refusal::<wire::BlockHeaderList>(wire::block::HeaderRange {
            select: wire::block::HeaderRangeSelect::Hash(hashes),
            pow: false,
        })
        .await
        .expect("block_header_list answers")
        .expect_err("a bounded listener refuses more than the cap");
    assert_eq!(refused.class, ErrorClass::OverResourceBound, "{refused:?}");
    assert_eq!(refused.diagnostic.code, "bound.block", "{refused:?}");
    assert_eq!(
        refused
            .diagnostic
            .parameter
            .get("bound")
            .map(String::as_str),
        Some("1000"),
        "the refusal names the cap: {refused:?}"
    );
}

/// A restricted listener does not disclose a transaction this node has not
/// broadcast.
///
/// This is the origin guard anchored on the property it protects — the
/// pool scope a caller reads with (`scope_for`, RT-O9.3) — and not on a
/// symptom of it. A caller that is not the host must read the broadcast set
/// only.
///
/// **Four reads take the scope, and all four are here:** `txpool_list`,
/// `txpool_stats`, `daemon_status`'s `txpool_count`, and `tx_list` by id.
/// `chain_spent` reads the scope too, and answers `unspent` for a spend the
/// caller may not see.
///
/// **The verdict is deterministic, and the state is not.** The transaction
/// is held un-broadcast by [`StemSinkPair`], for as long as the origin's
/// embargo runs — a draw with no lever. So the restricted reads are
/// bracketed: [`StemSinkPair::stem_held`] must say `Held` immediately before
/// them and immediately after. The relay state only moves forward, so `Held`
/// on both sides means held throughout, and the reads are judged. A bracket
/// that does not close proves nothing about the reads either way, so that
/// attempt is discarded whatever they returned and the next one submits a
/// new transaction. Running out of attempts is its own failure, and says the
/// subject was never established — it is not a pass.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "Track-2 regtest: requires SHEKYLD_BIN; spawns two live daemons"]
async fn restricted_listener_hides_a_transaction_this_node_has_not_broadcast() {
    use shekyl_units::AtomicUnits;

    /// Embargo draws at or under the bracket's width are rare (about one in
    /// sixty at a mean of 190 s and a bracket of a few seconds), so three
    /// independent attempts all failing to hold is about one run in 200,000.
    const ATTEMPTS: usize = 3;
    const MINE_BATCH_BLOCKS: u64 = 10;
    const MAX_MINE_BATCHES: usize = 24;

    let seed = [0x5eu8; shekyl_crypto_pq::account::SEED_BYTES];
    let pair = StemSinkPair::start_for_seed(&seed).await;
    let origin = pair.origin();
    let restricted = HttpRpc::new(origin.restricted_url().to_owned())
        .await
        .expect("restricted rpc client");
    let admin = HttpRpc::new(format!("http://127.0.0.1:{}", origin.rpc_port()))
        .await
        .expect("unrestricted rpc client");

    // RK-D14, on a live node. The origin holds a handshaken session to the
    // sink. Its restricted listener withholds Status, so it reports no
    // connection counts, and it still says the node has peers, because
    // Health is told to every caller.
    let restricted_info = restricted
        .call::<wire::DaemonStatus>(NoParams)
        .await
        .expect("restricted daemon_status");
    let admin_info = admin
        .call::<wire::DaemonStatus>(NoParams)
        .await
        .expect("admin daemon_status");
    assert!(
        restricted_info.peered.0 == Some(true) && admin_info.peered.0 == Some(true),
        "a node with a handshaken session has peers, on both listeners"
    );
    assert!(
        restricted_info.peer_outbound_count.is_withheld(),
        "the restricted listener's reply carries no connection counts at all, \
         so `peered` above did not come from them"
    );
    assert!(
        matches!(
            admin_info
                .peer_outbound_count
                .shown()
                .expect("the admin listener is shown Status")
                .0,
            Some(outbound) if outbound.0 >= 1
        ),
        "the admin listener reports the session the pair was started with"
    );

    let (wallet, _tmp, address) = mainnet_wallet(origin.rpc_port(), 0x5e).await;
    let arc = Arc::new(RwLock::new(wallet));
    mine_until_spendable(origin, &arc, MINE_BATCH_BLOCKS, MAX_MINE_BATCHES).await;

    for attempt in 1..=ATTEMPTS {
        let amount = AtomicUnits::from_raw(unlocked_balance(&arc).await.to_raw() / 4);
        let txid = submit_transfer(
            origin,
            &arc,
            crate::engine::pending::TxDestination::Address(address.clone()),
            amount,
            MINE_BATCH_BLOCKS,
            MAX_MINE_BATCHES,
        )
        .await;
        let hex_id = hex::encode(txid.as_bytes());

        // The bracket is on the stem phase: `public: false` before and after
        // the reads, whether or not the stem send has gone out (the wire
        // does not say which; the restricted listener must hide the entry
        // in either case).
        let before = pair.stem_held(txid).await;

        let restricted_listed = pool_lists(&restricted, txid).await;
        let restricted_stats = restricted
            .call::<wire::TxpoolStats>(NoParams)
            .await
            .expect("restricted txpool_stats");
        let restricted_status = restricted
            .call::<wire::DaemonStatus>(NoParams)
            .await
            .expect("restricted daemon_status");
        let restricted_tx = tx_slot(&restricted, txid).await;

        let admin_listed = pool_lists(&admin, txid).await;
        let admin_stats = admin
            .call::<wire::TxpoolStats>(NoParams)
            .await
            .expect("admin txpool_stats");
        let admin_tx = tx_slot(&admin, txid).await;

        let after = pair.stem_held(txid).await;
        if before != StemHold::Stem || after != StemHold::Stem {
            eprintln!(
                "attempt {attempt}: the transaction was not in its stem phase across the reads \
                 ({before:?} before, {after:?} after); discarding the attempt"
            );
            // Clear the pool so the next attempt's counts are its own.
            origin.generate_blocks(1).await;
            assert_eq!(
                origin.tx_pool_size().await,
                0,
                "the discarded attempt's transaction must be mined out of the pool"
            );
            refresh(&arc).await;
            continue;
        }

        // Held on both sides of the reads: they are judged. Every read is
        // judged before any verdict, so one run names every route that
        // disclosed and not only the first.
        let mut disclosed = Vec::new();
        if restricted_listed {
            disclosed.push("txpool_list listed it");
        }
        if restricted_stats.count.0 != 0 {
            disclosed.push("txpool_stats counted it");
        }
        if restricted_status.txpool_count.0.map(|count| count.0) != Some(0) {
            disclosed.push("daemon_status counted it");
        }
        if !matches!(restricted_tx, Slot::State(SlotState::Missing(_))) {
            disclosed.push("tx_list returned it by id");
        }
        assert!(
            disclosed.is_empty(),
            "a restricted listener must not disclose a transaction this node has \
             not broadcast, and it did for {hex_id}: {disclosed:?}. A read named \
             here used the host's scope — its handler lost the caller's \
             authority, or stopped deriving the scope from it"
        );

        // Blast radius, and the subject's own existence: the host is shown
        // the same transaction on the same reads. Without these, everything
        // above holds for a daemon with an empty pool.
        let mut withheld = Vec::new();
        if !admin_listed {
            withheld.push("txpool_list");
        }
        if admin_stats.count.0 != 1 {
            withheld.push("txpool_stats");
        }
        if !matches!(admin_tx, Slot::Item(_)) {
            withheld.push("tx_list");
        }
        assert!(
            withheld.is_empty(),
            "the host must be shown the held transaction {hex_id} on every pool \
             read, and was not on: {withheld:?}"
        );
        eprintln!("attempt {attempt}: held across the reads; hidden on four, shown on four");

        // The stem reached the sink, a second daemon, over p2p after the
        // handshake: it admitted the peer-delivered transaction to its own
        // pool (brief §5, "admitted and relayed after the handshake").
        let sink = pair.sink();
        let admitted_by = Instant::now() + Duration::from_secs(20);
        loop {
            if matches!(tx_slot(&sink.rpc, txid).await, Slot::Item(_)) {
                break;
            }
            if Instant::now() >= admitted_by {
                sink.panic_with_log(
                    "the sink did not admit the transaction its peer stemmed to it",
                    format!("{hex_id} not in its pool after 20 s"),
                );
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        eprintln!("attempt {attempt}: the sink admitted the stemmed transaction");

        // The other half, that a restricted listener names what the node
        // shows, is `restricted_listener_names_a_transaction_this_node_shows`
        // below: the C++ rig mined this transaction and popped the block so
        // it came back carried, which is public, but the Rust template lists
        // only what the node shows (criterion 2), so a stem-phase entry is
        // not mined and that lever is gone. The entry joins the broadcast
        // set when an embargo ends, which is the relay owner's (the record,
        // "Stem, fluff, embargo and arrival connector are the relay
        // owner's"); on the flip binary neither this node's nor the sink's
        // ended within 600 s of the stem (2026-10-29), a finding carried in
        // FOLLOWUPS, so this test does not wait on it.
        return;
    }
    origin.panic_with_log(
        "no transaction stayed held across the reads",
        format!(
            "{ATTEMPTS} attempts each lost their hold. That is not a short embargo \
             {ATTEMPTS} times running; the rig is not holding"
        ),
    );
}

/// The positive control for the test above: a restricted listener names a
/// transaction the node shows. An offline node has no route, so its own
/// transaction is shown the moment it is admitted (RD's NoRoute fluff at
/// the origin), and every pool read on the restricted listener carries it:
/// the hiding above is the flag, not the listener hiding the pool
/// wholesale.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "Track-2 regtest: requires SHEKYLD_BIN; spawns a live daemon"]
async fn restricted_listener_names_a_transaction_this_node_shows() {
    use shekyl_units::AtomicUnits;

    const MINE_BATCH_BLOCKS: u64 = 10;
    const MAX_MINE_BATCHES: usize = 24;

    let seed = [0x5fu8; shekyl_crypto_pq::account::SEED_BYTES];
    let daemon = RegtestDaemon::start_for_seed_with_restricted_listener(&seed).await;
    let restricted = HttpRpc::new(daemon.restricted_url().to_owned())
        .await
        .expect("restricted rpc client");
    let (wallet, _tmp, address) = mainnet_wallet(daemon.rpc_port(), 0x5f).await;
    let arc = Arc::new(RwLock::new(wallet));
    mine_until_spendable(&daemon, &arc, MINE_BATCH_BLOCKS, MAX_MINE_BATCHES).await;

    let amount = AtomicUnits::from_raw(unlocked_balance(&arc).await.to_raw() / 4);
    let txid = submit_transfer(
        &daemon,
        &arc,
        crate::engine::pending::TxDestination::Address(address),
        amount,
        MINE_BATCH_BLOCKS,
        MAX_MINE_BATCHES,
    )
    .await;
    let hex_id = hex::encode(txid.as_bytes());

    assert!(
        pool_lists(&restricted, txid).await,
        "a restricted listener names a transaction the node shows ({hex_id})"
    );
    let stats = restricted
        .call::<wire::TxpoolStats>(NoParams)
        .await
        .expect("restricted txpool_stats");
    assert_eq!(
        stats.count.0, 1,
        "the restricted stats count the shown transaction; got {stats:?}"
    );
    let by_id = tx_slot(&restricted, txid).await;
    assert!(
        matches!(by_id, Slot::Item(_)),
        "a restricted listener returns a shown transaction by id; got {by_id:?}"
    );
}

/// `daemon status`, `chain difficulty`, `version` and `txpool stats`
/// answer through `shekyl-cli` on an offline regtest daemon.
#[tokio::test]
#[ignore = "requires SHEKYLD_BIN and SHEKYL_CLI_BIN; spawns a live daemon"]
async fn daemon_words_answer_through_shekyl_cli() {
    let daemon = RegtestDaemon::start().await;
    let top_hash = daemon.top_block_hash().await;
    let version = daemon.version().await;
    assert!(!version.is_empty(), "the daemon reports a version");

    let out = daemon.console("daemon status");
    assert!(
        out.contains("Block count: 1/1 (100.0%)") && out.contains("uptime"),
        "the in-process status line must read the live core, start time \
         included; got:\n{out}"
    );

    let out = daemon.console("chain difficulty");
    assert!(
        out.contains(&format!("BH: 1, TH: {top_hash}, DIFF: ")),
        "the in-process diff must name the live tip; got:\n{out}"
    );

    let out = daemon.console("version");
    assert!(
        out.contains(&version),
        "the in-process version must print the build's own version \
         ({version}); got:\n{out}"
    );

    let out = daemon.console("txpool stats");
    assert!(
        out.contains("0 tx(es), 0 weight total") && out.contains("no backlog"),
        "the in-process print_pool_stats must render an empty pool from both \
         of its legs; got:\n{out}"
    );

    for command in [
        "daemon status",
        "chain difficulty",
        "version",
        "txpool stats",
    ] {
        let out = daemon.console(command);
        assert!(
            !out.contains("no reply") && !out.contains("console command failed"),
            "`{command}` must not be reaching a route that is gone; got:\n{out}"
        );
    }
}

#[path = "regtest_e2e_embargo.rs"]
mod embargo;
