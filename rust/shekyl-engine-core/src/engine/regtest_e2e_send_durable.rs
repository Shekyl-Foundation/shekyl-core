// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A19 on the real pathway: a real `shekyld` on regtest, real blocks, and a
//! real `shekyl-wallet-rpc` process that is killed, signalled and refused a
//! write (the alpha.11 bug hunt §A19; the wallet lane brief, PR 1).
//!
//! On alpha.11 a send's record, its retained tx secret and its input lock
//! lived in memory until the wallet closed. A wallet server that stopped
//! any other way lost them: the OUTBOUND proof for a payment that settled,
//! and the lock, so the next send re-selected the input and was refused as
//! a double spend. These gates hold the fix where it can be seen: the
//! process, not the engine, dies.
//!
//! Requires `SHEKYLD_BIN` and `SHEKYL_WALLET_RPC_BIN` (both staged in
//! `build/bin` by `cargo xtask build`). Each gate funds a wallet created here
//! from a known seed (the daemon mines to its address), closes it, and
//! hands its directory to the wallet server.

#![cfg(test)]

use std::time::Duration;

use serde_json::json;

use super::mine_address_from_seed;
// `build` (without its submit) serves only the unix stop-signal gate.
#[cfg(unix)]
use super::wallet_server::build;
use super::wallet_server::{fund, open, refresh, send, tail, wallet_and_daemon, WalletServer};

/// The wallet's name on the wire: the server opens `<wallet-dir>/<name>.wallet`.
const NAME: &str = "a19";

fn alarm_for(server: &WalletServer, txid: &str) -> Option<String> {
    server
        .ok("tx_alarm", json!({}))
        .as_array()
        .expect("tx_alarm is a list")
        .iter()
        .find(|row| row["id"] == txid)
        .map(|row| row["alarm"].as_str().expect("alarm keyword").to_owned())
}

fn outgoing_state(server: &WalletServer, txid: &str) -> Option<String> {
    server.ok("get_transfers", json!({}))["transfers"]
        .as_array()
        .expect("get_transfers lists rows")
        .iter()
        .find(|row| row["tx_hash"] == txid && row["direction"] == "OUTGOING")
        .map(|row| row["state"].as_str().expect("state").to_owned())
}

/// The A19 scenario, killed: fund, send, and `kill -9` the wallet server
/// right after the daemon's accept. A new server opens the wallet, and
/// everything the send recorded is there: the record (history), the
/// secret (an OUTBOUND proof that verifies), the bytes (a resend the daemon
/// answers), the lock (a new send that is not a double spend), and the
/// held send listed for the user's decision — then mined, confirmed, and
/// gone from the list.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires SHEKYLD_BIN and SHEKYL_WALLET_RPC_BIN; spawns a live daemon"]
async fn a_send_survives_a_kill_after_its_accept() {
    let (daemon, wallet_dir, logs) = wallet_and_daemon(NAME, 0x61).await;
    let recipient = mine_address_from_seed(
        &[0x62; shekyl_crypto_pq::account::SEED_BYTES],
        shekyl_address::Network::Regtest,
    );
    const AMOUNT: u64 = 1_000_000_000;

    let mut first = WalletServer::spawn(wallet_dir.path(), &daemon, logs.path(), "first");
    open(&first, NAME);
    fund(&daemon, &first, 4 * AMOUNT).await;
    let txid = send(&daemon, &first, &recipient, AMOUNT).await;
    first.signal("KILL");
    let status = first.wait_exit(Duration::from_secs(10));
    assert!(!status.success(), "SIGKILL ends the process: {status}");
    assert!(
        daemon.tx_pool_size().await >= 1,
        "the send is in the daemon's pool"
    );

    let second = WalletServer::spawn(wallet_dir.path(), &daemon, logs.path(), "second");
    open(&second, NAME);

    assert_eq!(
        alarm_for(&second, &txid).as_deref(),
        Some("earlier-session"),
        "the send from before the kill waits for the user's decision"
    );
    assert!(
        outgoing_state(&second, &txid).is_some(),
        "the send's record survived the kill"
    );
    let proof = second.ok("get_tx_proof", json!({"txid": txid, "address": recipient}));
    assert_eq!(proof["direction"], "OUTBOUND", "{proof}");
    let checked = second.ok(
        "check_tx_proof",
        json!({"txid": txid, "address": recipient, "proof": proof["proof"]}),
    );
    assert_eq!(
        checked["valid"], true,
        "the retained secret proves the payment: {checked}"
    );

    // The lock: a new send selects other inputs. Had it re-selected the
    // held send's input, the daemon would refuse it as a double spend.
    let next = send(&daemon, &second, &recipient, AMOUNT).await;
    assert_ne!(next, txid);

    // The bytes: the user's resend is answered by the daemon.
    let resent = second.ok("tx_resend", json!({"id": txid}));
    assert_eq!(resent["tx_hash"], txid);
    assert!(
        resent["verdict"] == "ALREADY_IN_POOL" || resent["verdict"] == "ALREADY_IN_CHAIN",
        "{resent}"
    );

    daemon.generate_blocks(1).await;
    refresh(&second);
    assert_eq!(
        outgoing_state(&second, &txid).as_deref(),
        Some("CONFIRMED"),
        "mined and confirmed"
    );
    assert_eq!(
        alarm_for(&second, &txid),
        None,
        "a confirmed send needs no decision"
    );
}

/// Each stop signal closes the wallet cleanly: the process exits 0 after
/// logging the close, and the next server finds the send it made.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires SHEKYLD_BIN and SHEKYL_WALLET_RPC_BIN; spawns a live daemon"]
async fn each_stop_signal_closes_the_wallet() {
    let (daemon, wallet_dir, logs) = wallet_and_daemon(NAME, 0x63).await;
    let recipient = mine_address_from_seed(
        &[0x64; shekyl_crypto_pq::account::SEED_BYTES],
        shekyl_address::Network::Regtest,
    );
    const AMOUNT: u64 = 1_000_000_000;

    let mut previous: Option<String> = None;
    for signal in ["TERM", "INT", "HUP"] {
        let mut server = WalletServer::spawn(wallet_dir.path(), &daemon, logs.path(), signal);
        open(&server, NAME);
        if let Some(txid) = &previous {
            assert!(
                outgoing_state(&server, txid).is_some(),
                "the send made before the last signal is on disk"
            );
        } else {
            fund(&daemon, &server, 6 * AMOUNT).await;
        }
        let txid = send(&daemon, &server, &recipient, AMOUNT).await;
        server.signal(signal);
        let status = server.wait_exit(Duration::from_secs(60));
        assert!(
            status.success(),
            "SIG{signal}: the server closes the wallet and exits 0, got {status}; log tail:\n{}",
            tail(&server.log_text())
        );
        assert!(
            server.log_text().contains("the wallet is saved and closed"),
            "SIG{signal}: the close is logged; log tail:\n{}",
            tail(&server.log_text())
        );
        daemon.generate_blocks(1).await;
        previous = Some(txid);
    }

    let last = WalletServer::spawn(wallet_dir.path(), &daemon, logs.path(), "last");
    open(&last, NAME);
    let txid = previous.expect("three sends");
    assert!(outgoing_state(&last, &txid).is_some());
}

/// A send whose record cannot be saved is not sent: with every save of the
/// wallet refused ([`BlockedStateSave`](super::super::test_support::BlockedStateSave),
/// which holds for root too) the submit is refused `-29131
/// SAVE_IO_FAILED` at its `rename` step (the blocked rename is the disk's
/// error; Rick, 2026-11-19: `data.step`) and the
/// daemon's pool stays empty; with saves possible again, the kept
/// reservation submits and is accepted.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires SHEKYLD_BIN and SHEKYL_WALLET_RPC_BIN; spawns a live daemon"]
async fn a_send_that_cannot_be_saved_is_not_sent() {
    let (daemon, wallet_dir, logs) = wallet_and_daemon(NAME, 0x65).await;
    let recipient = mine_address_from_seed(
        &[0x66; shekyl_crypto_pq::account::SEED_BYTES],
        shekyl_address::Network::Regtest,
    );
    const AMOUNT: u64 = 1_000_000_000;

    let server = WalletServer::spawn(wallet_dir.path(), &daemon, logs.path(), "nosave");
    open(&server, NAME);
    fund(&daemon, &server, 2 * AMOUNT).await;
    let (id, gen) = build(&daemon, &server, &recipient, AMOUNT).await;
    assert_eq!(
        daemon.tx_pool_size().await,
        0,
        "an empty pool before the submit"
    );

    let blocked = super::super::test_support::BlockedStateSave::block(
        &wallet_dir.path().join(format!("{NAME}.wallet")),
    );
    let refused = server.call(
        "submit_pending_tx",
        json!({"pending_tx_id": id, "seen_gen": gen}),
    );
    drop(blocked);

    let refused = refused.expect_err("a send that cannot be saved is refused");
    assert_eq!(refused.code, -29131, "SAVE_IO_FAILED: {refused:?}");
    assert_eq!(
        refused.data.as_ref().and_then(|data| data.get("step")),
        Some(&json!("rename")),
        "the blocked rename names its step: {refused:?}"
    );
    assert_eq!(daemon.tx_pool_size().await, 0, "nothing reached the daemon");

    let submitted = server.ok(
        "submit_pending_tx",
        json!({"pending_tx_id": id, "seen_gen": gen}),
    );
    assert_eq!(
        submitted["verdict"], "ACCEPTED",
        "the kept reservation submits: {submitted}"
    );
    assert_eq!(daemon.tx_pool_size().await, 1);
}
