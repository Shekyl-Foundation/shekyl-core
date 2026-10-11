// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Origin-guard rig and the live `get_info` gates.
//!
//! A `#[path]` child of the regtest harness, so `regtest_e2e` stays the shared
//! daemon lifecycle. The stem/sink pair holds a transaction un-broadcast for
//! longer than one assertion, which one daemon cannot do. The restricted-listener
//! and in-process console gates that read `get_info` live here with it.

// The production debug-macro lint treats a file as test code only when the
// file itself carries this attribute. The parent harness is already
// test-only; this sibling has to say so on its own.
#![cfg(test)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::json;
use shekyl_rpc_client::Rpc;
use shekyl_rpc_transport::HttpRpc;
use shekyl_rpc_types::GetInfoResponse;
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
/// records it `stem`, embargoed. The sink runs `--no-sync`, never reports
/// itself synchronized, and drops the transaction on receipt — so nothing
/// fluffs it back. It stays `stem` on the origin until the origin's own
/// embargo expires. The flag is load-bearing: a second daemon that
/// synchronizes normally stems the transaction straight back, the origin
/// upgrades the second arrival to fluff, and the hold is over in seconds.
///
/// **What the rig does not fix.** The embargo is a draw (geometric, mean
/// 190 s on clearnet) with no lever, so a short one can end mid-assertion.
/// The rig does not pretend otherwise: [`StemSinkPair::stem_held`] reads the
/// state back, and a caller brackets its assertions with it.
pub(super) struct StemSinkPair {
    origin: RegtestDaemon,
    /// Held only to keep the process alive and to clean it up on drop.
    _sink: RegtestDaemon,
}

/// One entry of the unrestricted `/get_transaction_pool` reply — the three
/// members that say where a transaction is in its relay.
#[derive(Debug, Deserialize)]
struct PoolRelayEntry {
    id_hash: String,
    relayed: bool,
    last_relayed_time: u64,
}

#[derive(Debug, Deserialize)]
struct PoolRelayResp {
    /// Absent when the pool is empty: the C++ serializer drops an empty
    /// sequence, so the default is the wire's own encoding of "none".
    #[serde(default)]
    transactions: Vec<PoolRelayEntry>,
}

/// Where the origin holds a transaction, read from its unrestricted listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StemHold {
    /// Sent on the stem and embargoed: not broadcast.
    Held,
    /// Admitted, and the stem send has not been recorded yet.
    NotYetSent,
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
    pub(super) async fn start() -> StemSinkPair {
        let serial = serial_lock().lock_owned().await;
        let origin_p2p = RegtestDaemon::free_port();
        let sink_p2p = RegtestDaemon::free_port_excluding(&[origin_p2p]);
        let sink = RegtestDaemon::spawn(RegtestSpawn::new(None).with_peering(Peering::Linked {
            p2p_port: sink_p2p,
            peer_p2p_port: origin_p2p,
            sink: true,
        }))
        .await;
        let origin = RegtestDaemon::spawn(
            RegtestSpawn::new(Some(serial))
                .with_restricted_listener()
                .with_peering(Peering::Linked {
                    p2p_port: origin_p2p,
                    peer_p2p_port: sink_p2p,
                    sink: false,
                }),
        )
        .await;
        let pair = StemSinkPair {
            origin,
            _sink: sink,
        };
        pair.await_linked().await;
        pair
    }

    /// The daemon a wallet submits to. It carries both listeners.
    pub(super) fn origin(&self) -> &RegtestDaemon {
        &self.origin
    }

    async fn await_linked(&self) {
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut last = String::new();
        while Instant::now() < deadline {
            let connections: shekyl_rpc_types::GetConnectionsResponse = self
                .origin
                .rpc
                .json_rpc_call("get_connections", None)
                .await
                .expect("origin get_connections");
            let outbound = connections
                .connections
                .iter()
                .filter(|c| !c.incoming)
                .count();
            let synchronized = self
                .origin
                .rpc
                .json_rpc_call::<GetInfoResponse>("get_info", None)
                .await
                .expect("origin get_info")
                .health
                .synchronized;
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
    /// Read from the unrestricted `/get_transaction_pool`, which is the only
    /// reply that carries the relay state: `relayed` is set when a send is
    /// recorded, and `last_relayed_time` is written as `0` for exactly the
    /// entries the pool marks `dandelionpp_stem` (`tx_pool.cpp`,
    /// `get_transactions_and_spent_keys_info`). A broadcast entry carries
    /// the time of its broadcast there.
    pub(super) async fn stem_held(&self, txid: TxHash) -> StemHold {
        let pool: PoolRelayResp = self
            .origin
            .rpc
            .rpc_call("get_transaction_pool", None::<serde_json::Value>)
            .await
            .expect("origin /get_transaction_pool");
        let wanted = hex::encode(txid.as_bytes());
        match pool.transactions.iter().find(|t| t.id_hash == wanted) {
            None => StemHold::Absent,
            Some(entry) if !entry.relayed => StemHold::NotYetSent,
            Some(entry) if entry.last_relayed_time == 0 => StemHold::Held,
            Some(_) => StemHold::Broadcast,
        }
    }
}

/// The restricted listener's posture reaches two native handlers.
///
/// This test was the regression guard for the FFI bridge's origin context,
/// and every leg of it has since moved off the bridge: `/get_transactions`
/// and `/is_key_image_spent` in RK-4c (now
/// `native_handlers_apply_their_own_request_caps`), the header methods in
/// RK-5b, and `/get_info` in RK-5c. What it asserts is still worth
/// asserting live — that the listener a request arrives on decides what the
/// handler discloses — but it says nothing about the bridge any more, and
/// its name no longer claims to. **The bridge's guard is
/// `restricted_listener_hides_a_transaction_this_node_has_not_broadcast`**,
/// on the pool routes, which are the bridged subjects that remain.
///
/// Two legs, both native:
///
/// - `/get_info`: the listener's posture becomes the handler's
///   `Disclosure`. A restricted caller gets the stand-ins for Status
///   (`start_time` 0, `free_space` `u64::MAX`, an empty `version`) and is
///   told it is restricted; the unrestricted listener gets the real values.
/// - `get_block_header_by_hash` over `RESTRICTED_BLOCK_COUNT` is refused on
///   the restricted listener.
///
/// Admin-only method gating is
/// `admin_methods_are_refused_only_on_the_restricted_listener` in
/// `shekyl-daemon-rpc`. The WE result-envelope shape is
/// `jsonrpc_we_carries_handler_status_through_the_result_envelope`. The
/// histogram deletion gate is `get_output_histogram_stays_unrouted`.
///
/// Both listeners come from one daemon, so the postures are compared against
/// the same chain in the same process, and the unrestricted rows are the
/// blast-radius check: the restricted posture must not narrow the admin
/// listener.
#[tokio::test]
#[ignore = "Track-2 regtest: requires SHEKYLD_BIN; spawns a live daemon"]
async fn restricted_listener_gets_stand_ins_and_caps_from_native_handlers() {
    /// `RESTRICTED_BLOCK_COUNT`, the cap on `get_block_header_by_hash`.
    const BLOCK_CAP: usize = 1000;

    let daemon = RegtestDaemon::start_with_restricted_listener().await;
    let restricted = HttpRpc::new(daemon.restricted_url().to_owned())
        .await
        .expect("restricted rpc client");
    let unrestricted = HttpRpc::new(format!("http://127.0.0.1:{}", daemon.rpc_port()))
        .await
        .expect("unrestricted rpc client");

    // Hashes that resolve to nothing: a cap is a request-shape refusal and
    // fires before any lookup, so the chain's contents are irrelevant.
    let hashes = |n: usize| -> Vec<String> { (0..n).map(|i| format!("{i:064x}")).collect() };

    // ── /get_info: the listener decides the disclosure ──────────────────
    let admin_info: GetInfoResponse = unrestricted
        .rpc_call("get_info", None::<serde_json::Value>)
        .await
        .expect("admin get_info");
    let restricted_info: GetInfoResponse = restricted
        .rpc_call("get_info", None::<serde_json::Value>)
        .await
        .expect("restricted get_info");
    let admin_status = admin_info
        .node
        .shown()
        .expect("the admin listener is shown Status");
    // At parity a restricted reply still carries Status, holding stand-ins.
    let restricted_status = restricted_info
        .node
        .shown()
        .expect("a restricted reply carries the Status stand-ins until RK-Q8");
    assert!(
        restricted_info.restricted && !admin_info.restricted,
        "each listener must say which it is"
    );
    assert_eq!(
        restricted_status.start_time, 0,
        "a restricted listener must not disclose the node's start time; if this \
         is the real start time the handler answered a restricted caller in full"
    );
    assert_eq!(
        restricted_status.free_space,
        u64::MAX,
        "a restricted listener must not disclose free space"
    );
    assert_eq!(
        restricted_status.version, "",
        "a restricted listener must not disclose the build's version"
    );
    assert!(
        admin_status.start_time > 0 && !admin_status.version.is_empty(),
        "the admin listener must still report the start time and the version — \
         otherwise the assertions above would hold for a daemon that reports \
         nothing to anyone; got {admin_status:?}"
    );
    assert_ne!(
        admin_status.free_space,
        u64::MAX,
        "the admin listener must report the volume's real free space"
    );
    // The two listeners describe the same chain.
    assert_eq!(restricted_info.health.height, admin_info.health.height);
    // Health is told to both. This daemon runs `--offline`, which binds no
    // p2p hub at all. It still answers, and says it has no peers: offline
    // is configuration, so the handler does not ask a board that is not
    // there. A handler that asked would refuse this request, and the
    // harness would never have seen the daemon come up.
    for (listener, info) in [("restricted", &restricted_info), ("admin", &admin_info)] {
        assert!(
            info.health.offline,
            "{listener}: the harness starts this daemon offline"
        );
        assert!(
            !info.health.has_peers,
            "{listener}: an offline daemon has no peers, and says so"
        );
    }

    // ── JSON-RPC: the header cap ────────────────────────────────────────
    //
    // Over the block cap the handler refuses, so the reply is an error
    // envelope and `result` never appears.
    let hdr: serde_json::Value = restricted
        .rpc_call(
            "json_rpc",
            Some(jsonrpc_body(
                "get_block_header_by_hash",
                &json!({ "hashes": hashes(BLOCK_CAP + 1) }),
            )),
        )
        .await
        .expect("restricted get_block_header_by_hash over cap");
    assert_eq!(
        hdr.pointer("/error/message").and_then(|m| m.as_str()),
        Some("Too many block headers requested in restricted mode"),
        "a restricted listener must refuse more than {BLOCK_CAP} block hashes; \
         if this succeeds the handler answered a restricted caller without its cap"
    );
}

/// A restricted listener does not disclose a transaction this node has not
/// broadcast.
///
/// This is the origin guard anchored on the property the fix protects —
/// `include_sensitive` — and not on a symptom of it. The bridge's REST
/// template passes each handler its caller's origin; each pool handler turns
/// that into the flag it reads the pool with, and a restricted caller must
/// read the broadcast set only. The earlier anchors were request caps, then
/// `/get_info`'s field trimming, and each left with the route that carried
/// it (`DAEMON_RPC_KV_CUTOVER.md` §7, 2026-08-28). The pool routes are the
/// subjects that outlive `/get_info`, so this exists before that route moves.
///
/// **Four reads take the flag, and all four are here.** Three cross the
/// bridge (`dispatch_json`): `/get_transaction_pool`,
/// `/get_transaction_pool_hashes`, `/get_transaction_pool_stats`. The fourth,
/// `/get_transactions`, is native and reads the pool through the facts
/// export with the same flag. `/is_key_image_spent` is not a subject: it
/// reads the broadcast set for every caller.
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

    let pair = StemSinkPair::start().await;
    let origin = pair.origin();
    let restricted = HttpRpc::new(origin.restricted_url().to_owned())
        .await
        .expect("restricted rpc client");
    let admin = HttpRpc::new(format!("http://127.0.0.1:{}", origin.rpc_port()))
        .await
        .expect("unrestricted rpc client");

    // RK-D14, on a live node. The origin holds a handshaken session to the
    // sink. Its restricted listener still writes zero for both connection
    // counts, and beside them says the node has peers, because Health is
    // told to every caller. Before `has_peers` a wallet on this listener
    // could only read the zeros, and raised a false "daemon has no peers"
    // alarm in place of its resubmit probe (the pre-flight's §3.1).
    let restricted_info: GetInfoResponse = restricted
        .rpc_call("get_info", None::<serde_json::Value>)
        .await
        .expect("restricted get_info");
    let admin_info: GetInfoResponse = admin
        .rpc_call("get_info", None::<serde_json::Value>)
        .await
        .expect("admin get_info");
    assert!(
        restricted_info.health.has_peers && admin_info.health.has_peers,
        "a node with a handshaken session has peers, on both listeners"
    );
    let restricted_status = restricted_info
        .node
        .shown()
        .expect("a restricted reply carries the Status stand-ins until RK-Q8");
    assert_eq!(
        (
            restricted_status.outgoing_connections_count,
            restricted_status.incoming_connections_count
        ),
        (0, 0),
        "the restricted listener's counts are the stand-ins, so `has_peers` \
         above did not come from them"
    );
    assert!(
        admin_info
            .node
            .shown()
            .expect("the admin listener is shown Status")
            .outgoing_connections_count
            >= 1,
        "the admin listener reports the session the pair was started with"
    );

    let (wallet, _tmp, address) = mainnet_wallet(origin.rpc_port(), 0x5e).await;
    let arc = Arc::new(RwLock::new(wallet));
    mine_until_spendable(origin, &arc, &address, MINE_BATCH_BLOCKS, MAX_MINE_BATCHES).await;

    let pool_hashes = |reply: &serde_json::Value| -> Vec<String> {
        reply
            .get("tx_hashes")
            .and_then(serde_json::Value::as_array)
            .map(|hashes| {
                hashes
                    .iter()
                    .filter_map(|h| h.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    };
    let pool_ids = |reply: &serde_json::Value| -> Vec<String> {
        reply
            .get("transactions")
            .and_then(serde_json::Value::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|e| e.get("id_hash").and_then(|h| h.as_str()).map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    };
    let pool_total = |reply: &serde_json::Value| -> u64 {
        reply
            .pointer("/pool_stats/txs_total")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_else(|| panic!("pool stats carry txs_total; got {reply}"))
    };

    for attempt in 1..=ATTEMPTS {
        let amount = AtomicUnits::from_raw(unlocked_balance(&arc).await.to_raw() / 4);
        let txid = submit_transfer(
            origin,
            &arc,
            &address,
            &address,
            amount,
            MINE_BATCH_BLOCKS,
            MAX_MINE_BATCHES,
        )
        .await;
        let hex_id = hex::encode(txid.as_bytes());
        let by_hash = json!({ "txs_hashes": [hex_id] });

        // The stem send is recorded a moment after the accept. Wait for it,
        // briefly: `NotYetSent` is also un-broadcast, but it is the state the
        // single-node form raced, and the bracket is on `Held`.
        let mut before = pair.stem_held(txid).await;
        let sent_by = Instant::now() + Duration::from_secs(10);
        while before == StemHold::NotYetSent && Instant::now() < sent_by {
            tokio::time::sleep(Duration::from_millis(50)).await;
            before = pair.stem_held(txid).await;
        }

        let restricted_pool: serde_json::Value = restricted
            .rpc_call("get_transaction_pool", None::<serde_json::Value>)
            .await
            .expect("restricted /get_transaction_pool");
        let restricted_hashes: serde_json::Value = restricted
            .rpc_call("get_transaction_pool_hashes", None::<serde_json::Value>)
            .await
            .expect("restricted /get_transaction_pool_hashes");
        let restricted_stats: serde_json::Value = restricted
            .rpc_call("get_transaction_pool_stats", None::<serde_json::Value>)
            .await
            .expect("restricted /get_transaction_pool_stats");
        let restricted_tx: shekyl_rpc_types::GetTransactionsResponse = restricted
            .rpc_call("get_transactions", Some(by_hash.clone()))
            .await
            .expect("restricted /get_transactions");

        let admin_pool: serde_json::Value = admin
            .rpc_call("get_transaction_pool", None::<serde_json::Value>)
            .await
            .expect("unrestricted /get_transaction_pool");
        let admin_hashes: serde_json::Value = admin
            .rpc_call("get_transaction_pool_hashes", None::<serde_json::Value>)
            .await
            .expect("unrestricted /get_transaction_pool_hashes");
        let admin_stats: serde_json::Value = admin
            .rpc_call("get_transaction_pool_stats", None::<serde_json::Value>)
            .await
            .expect("unrestricted /get_transaction_pool_stats");
        let admin_tx: shekyl_rpc_types::GetTransactionsResponse = admin
            .rpc_call("get_transactions", Some(by_hash))
            .await
            .expect("unrestricted /get_transactions");

        let after = pair.stem_held(txid).await;
        if before != StemHold::Held || after != StemHold::Held {
            eprintln!(
                "attempt {attempt}: the transaction was not held across the reads \
                 ({before:?} before, {after:?} after); discarding the attempt"
            );
            // Clear the pool so the next attempt's counts are its own.
            origin.generate_blocks(1, &address).await;
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
        if pool_ids(&restricted_pool).contains(&hex_id) {
            disclosed.push("/get_transaction_pool listed it");
        }
        if pool_hashes(&restricted_hashes).contains(&hex_id) {
            disclosed.push("/get_transaction_pool_hashes named it");
        }
        if pool_total(&restricted_stats) != 0 {
            disclosed.push("/get_transaction_pool_stats counted it");
        }
        let missed = restricted_tx
            .missed_tx
            .iter()
            .any(|h| h.as_bytes() == txid.as_bytes());
        if !restricted_tx.txs.is_empty() || !missed {
            disclosed.push("/get_transactions returned it by hash");
        }
        assert!(
            disclosed.is_empty(),
            "a restricted listener must not disclose a transaction this node has \
             not broadcast, and it did for {hex_id}: {disclosed:?}. A route named \
             here read the pool with the unrestricted flag — its handler lost the \
             caller's origin, or stopped deriving the flag from it"
        );

        // Blast radius, and the subject's own existence: the unrestricted
        // listener shows the same transaction on the same four reads. Without
        // these, everything above holds for a daemon with an empty pool.
        let mut withheld = Vec::new();
        if !pool_ids(&admin_pool).contains(&hex_id) {
            withheld.push("/get_transaction_pool");
        }
        if !pool_hashes(&admin_hashes).contains(&hex_id) {
            withheld.push("/get_transaction_pool_hashes");
        }
        if pool_total(&admin_stats) != 1 {
            withheld.push("/get_transaction_pool_stats");
        }
        let returned = admin_tx
            .txs
            .iter()
            .any(|t| t.tx_hash.as_bytes() == txid.as_bytes());
        if !returned || !admin_tx.missed_tx.is_empty() {
            withheld.push("/get_transactions");
        }
        assert!(
            withheld.is_empty(),
            "the unrestricted listener must show the held transaction {hex_id} on \
             every pool read, and did not on: {withheld:?}"
        );
        eprintln!("attempt {attempt}: held across the reads; hidden on four, shown on four");

        // The other half: hidden because it is not broadcast, not hidden
        // whatever its state. Mine the transaction and pop the block. A
        // popped transaction returns to the pool recorded as carried by a
        // block, which is in the broadcast set — so the restricted listener
        // must now show the transaction it withheld a moment ago. A listener
        // that hid every pool transaction would pass everything above.
        origin.generate_blocks(1, &address).await;
        assert_eq!(
            origin.tx_pool_size().await,
            0,
            "the held transaction must be mined out of the pool"
        );
        origin.pop_blocks(1).await;
        let broadcast_hashes: serde_json::Value = restricted
            .rpc_call("get_transaction_pool_hashes", None::<serde_json::Value>)
            .await
            .expect("restricted /get_transaction_pool_hashes after the pop");
        let broadcast_tx: shekyl_rpc_types::GetTransactionsResponse = restricted
            .rpc_call("get_transactions", Some(json!({ "txs_hashes": [hex_id] })))
            .await
            .expect("restricted /get_transactions after the pop");
        assert!(
            pool_hashes(&broadcast_hashes).contains(&hex_id),
            "once the transaction is in the broadcast set a restricted listener \
             must name it; if it does not, the listener hides the pool wholesale \
             and the assertions above proved nothing about the flag"
        );
        assert!(
            broadcast_tx
                .txs
                .iter()
                .any(|t| t.tx_hash.as_bytes() == txid.as_bytes()),
            "once the transaction is in the broadcast set a restricted listener \
             must return it by hash; got {broadcast_tx:?}"
        );
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

/// The console commands that read `get_info` answer on the daemon's **own**
/// console.
///
/// RK-5c's half of the gate above. `get_info` is served in Rust, and seven
/// console commands read it. Four were already rendered in Rust over a
/// bridged leg and now call the method directly; three — `diff`, `version`
/// and `print_pool_stats` — were rendered in C++ by calling the handler,
/// and moved because that handler is deleted next.
///
/// On the in-process arm nothing crosses HTTP: the console calls the native
/// method over the live core, with full disclosure, since the operator at
/// the daemon's own console is the host's administrator. What this pins is
/// that each command reaches that core and renders its own text rather than
/// a transport failure — the failure RK-4c shipped, silently, because
/// nothing exercised this arm.
///
/// `print_pool_stats` also reads `/get_transaction_pool_stats`, which is
/// still served from the C++ dispatch table (RK-6). That bridged leg is
/// covered here so that the slice which deletes the route turns this red.
#[tokio::test]
#[ignore = "Track-2 regtest: requires SHEKYLD_BIN; spawns a live daemon"]
async fn get_info_console_commands_answer_on_the_in_process_arm() {
    let mut daemon = RegtestDaemon::start_with_console().await;
    let info: GetInfoResponse = daemon
        .rpc()
        .json_rpc_call("get_info", None)
        .await
        .expect("get_info");
    let top_hash = hex::encode(info.health.top_block_hash.to_bytes());
    let version = info
        .node
        .shown()
        .expect("the harness's own listener is shown Status")
        .version
        .clone();
    assert!(!version.is_empty(), "the daemon reports a version");

    let out = daemon.console("status");
    assert!(
        out.contains("Height: 1/1 (100.0%)") && out.contains("uptime"),
        "the in-process status line must read the live core, start time \
         included; got:\n{out}"
    );

    let out = daemon.console("diff");
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

    let out = daemon.console("print_pool_stats");
    assert!(
        out.contains("0 tx(es), 0 bytes total") && out.contains("no backlog"),
        "the in-process print_pool_stats must render an empty pool from both \
         of its legs; got:\n{out}"
    );

    for command in ["status", "diff", "version", "print_pool_stats"] {
        let out = daemon.console(command);
        assert!(
            !out.contains("no reply") && !out.contains("console command failed"),
            "`{command}` must not be reaching a route that is gone; got:\n{out}"
        );
    }
}
