// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The balance's legs and the signer's change on the real pathway: a real
//! `shekyld` on regtest, real blocks, and real `shekyl-wallet-rpc`
//! processes (the wallet lane's PR 2: A17 and A16).
//!
//! A funder the daemon mines to pays a payee that mines nothing, so the
//! payee's legs move only with what each gate does. The payee is also held
//! by a second server from the same seed, in its own directory: a second
//! device, which lags the chain or spends behind the first one's back.

#![cfg(test)]

use serde_json::{json, Value};

use super::wallet_server::{
    amount, create_wallet, fund, open, refresh, send, tail, wallet_and_daemon, RpcRefusal,
    WalletServer,
};
use super::{mine_address_from_seed, RegtestDaemon};

const FUNDER: &str = "funder";
const FUNDER_SEED: u8 = 0x71;
const PAYEE: &str = "payee";
const PAYEE_SEED: [u8; shekyl_crypto_pq::account::SEED_BYTES] =
    [0x72; shekyl_crypto_pq::account::SEED_BYTES];

/// What the funder pays the payee, atomic units: one output.
const PAID: u64 = 50_000_000_000;

/// A `get_balance` reply's legs, with the balance's own identity checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Legs {
    balance: u64,
    spendable: u64,
    incoming: u64,
    incoming_wait: Option<u64>,
    outgoing: u64,
}

fn legs(server: &WalletServer) -> Legs {
    let reply = server.ok("get_balance", json!({}));
    let legs = Legs {
        balance: amount(&reply, "balance"),
        spendable: amount(&reply, "spendable"),
        incoming: amount(&reply, "incoming"),
        incoming_wait: reply.get("incoming_wait").map(|w| {
            w.as_u64()
                .unwrap_or_else(|| panic!("incoming_wait is a count: {reply}"))
        }),
        outgoing: amount(&reply, "outgoing"),
    };
    assert_eq!(
        legs.balance,
        legs.spendable + legs.incoming,
        "balance = spendable + incoming: {reply}"
    );
    for gone in ["liquid", "unlocked", "pending", "parked"] {
        assert!(reply.get(gone).is_none(), "{gone} is deleted: {reply}");
    }
    legs
}

/// The daemon, the funder (served), the payee (served) and the payee's
/// second device (served), each wallet in its own directory.
struct Wallets {
    daemon: RegtestDaemon,
    funder: WalletServer,
    payee: WalletServer,
    twin: WalletServer,
    funder_address: String,
    payee_address: String,
    _dirs: Vec<tempfile::TempDir>,
}

async fn wallets() -> Wallets {
    let (daemon, funder_dir, logs) = wallet_and_daemon(FUNDER, FUNDER_SEED).await;
    let payee_dir = tempfile::tempdir().expect("payee dir");
    let twin_dir = tempfile::tempdir().expect("twin dir");
    create_wallet(&daemon, payee_dir.path(), PAYEE, &PAYEE_SEED).await;
    create_wallet(&daemon, twin_dir.path(), PAYEE, &PAYEE_SEED).await;
    let funder = WalletServer::spawn(funder_dir.path(), daemon.rpc_port, logs.path(), "funder");
    let payee = WalletServer::spawn(payee_dir.path(), daemon.rpc_port, logs.path(), "payee");
    let twin = WalletServer::spawn(twin_dir.path(), daemon.rpc_port, logs.path(), "twin");
    open(&funder, FUNDER);
    open(&payee, PAYEE);
    open(&twin, PAYEE);
    let network = shekyl_address::Network::Regtest;
    Wallets {
        funder_address: mine_address_from_seed(
            &[FUNDER_SEED; shekyl_crypto_pq::account::SEED_BYTES],
            network,
        ),
        payee_address: mine_address_from_seed(&PAYEE_SEED, network),
        daemon,
        funder,
        payee,
        twin,
        _dirs: vec![funder_dir, payee_dir, twin_dir, logs],
    }
}

/// Pay the payee `PAID` from the funder and mine the payment.
async fn pay_the_payee(w: &Wallets) {
    fund(&w.daemon, &w.funder, PAID * 2).await;
    send(&w.daemon, &w.funder, &w.payee_address, PAID).await;
    w.daemon.generate_blocks(1).await;
}

/// Mine and refresh `server` until its spendable leg reaches `need`.
async fn mine_until_spendable(w: &Wallets, server: &WalletServer, need: u64) -> Legs {
    for _ in 0..40 {
        refresh(server);
        let now = legs(server);
        if now.spendable >= need {
            return now;
        }
        w.daemon.generate_blocks(1).await;
    }
    panic!("the payee never reached a spendable {need}");
}

fn build_params(address: &str, sent: u64) -> Value {
    json!({
        "recipients": [{"address": address, "amount": sent.to_string()}],
        "priority": "standard",
    })
}

fn discard(server: &WalletServer, built: &Value) {
    server.ok(
        "discard_pending_tx",
        json!({"pending_tx_id": built["pending_tx_id"]}),
    );
}

fn submit(server: &WalletServer, built: &Value) -> Result<Value, RpcRefusal> {
    server.call(
        "submit_pending_tx",
        json!({"pending_tx_id": built["pending_tx_id"], "seen_gen": built["content_gen"]}),
    )
}

/// A17, receiving. At every tip from the payment's block to its first
/// spend the payee's balance and a build agree: while the payment is
/// incoming its wait counts down one per block and a build is refused
/// `-29112` naming that same wait; at the tip where the wait reaches zero
/// the money is spendable and a build succeeds, one block after a build
/// was refused with a wait of 1. The point: the balance says spendable
/// exactly when a build can spend.
///
/// A16, the lag: the payee's second device refreshes only every third
/// block, so it builds 0–2 blocks behind the daemon at the edge, as the
/// TRC-1 wallet did. It decides by its own synced tip, so it is refused
/// `-29112` or builds; nothing reaches the signer to fail there.
///
/// Observed red 2026-11-15 against a wallet server rebuilt with the pre-A17
/// balance rule (spendable from the eligible height): "spendable at a tip a
/// build refused -29112", the balance at 50 SKL spendable and the build's
/// wait at 7.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires SHEKYLD_BIN and SHEKYL_WALLET_RPC_BIN; spawns a live daemon"]
async fn the_balance_says_spendable_exactly_when_a_build_can_spend() {
    let w = wallets().await;
    pay_the_payee(&w).await;

    let small = PAID / 4;
    let mut previous_wait: Option<u64> = None;
    let mut payee_spent = false;
    let mut twin_spent = false;
    for step in 0..60u64 {
        refresh(&w.payee);
        let now = legs(&w.payee);
        if !payee_spent {
            match w
                .payee
                .call("build_pending_tx", build_params(&w.funder_address, small))
            {
                Ok(built) => {
                    assert_eq!(
                        (now.spendable, now.incoming, now.incoming_wait),
                        (PAID, 0, None),
                        "a build succeeded: the balance must say spendable"
                    );
                    assert_eq!(previous_wait, Some(1), "one block earlier the wait was 1");
                    discard(&w.payee, &built);
                    payee_spent = true;
                }
                Err(RpcRefusal {
                    code: -29112, data, ..
                }) => {
                    let wait = data
                        .as_ref()
                        .and_then(|d| d["wait_blocks"].as_u64())
                        .expect("-29112 names its wait");
                    assert_eq!(
                        (now.spendable, now.incoming, now.incoming_wait),
                        (0, PAID, Some(wait)),
                        "spendable at a tip a build refused -29112"
                    );
                    if let Some(previous) = previous_wait {
                        assert_eq!(wait, previous - 1, "the wait counts down one per block");
                    }
                    previous_wait = Some(wait);
                }
                Err(other) => panic!(
                    "the payee's build: {other:?}; log tail:\n{}",
                    tail(&w.payee.log_text())
                ),
            }
        }

        if step % 3 == 0 {
            refresh(&w.twin);
        }
        match w
            .twin
            .call("build_pending_tx", build_params(&w.funder_address, small))
        {
            Ok(built) => {
                discard(&w.twin, &built);
                twin_spent = true;
            }
            Err(RpcRefusal { code: -29112, .. }) => {}
            Err(other) => panic!(
                "a build 0-2 blocks behind the daemon: {other:?}; log tail:\n{}",
                tail(&w.twin.log_text())
            ),
        }
        if payee_spent && twin_spent {
            return;
        }
        w.daemon.generate_blocks(1).await;
    }
    panic!("the payment never became spendable on both devices");
}

/// A17, sending. After the payee dispatches a send of its one output:
/// spendable drops by the input, outgoing is the amount plus the fee,
/// incoming holds the change with no wait (it is not on chain yet), and
/// the balance drops by exactly the amount plus the fee. Mined and
/// refreshed, outgoing is zero and the change is a received output with a
/// wait; matured, it is spendable.
///
/// Observed red 2026-11-15 against a wallet server rebuilt to drop an
/// in-flight send's change from incoming: "incoming holds the change"
/// (0 where 36271315000 was due).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires SHEKYLD_BIN and SHEKYL_WALLET_RPC_BIN; spawns a live daemon"]
async fn a_send_moves_its_input_to_outgoing_and_its_change_to_incoming() {
    let w = wallets().await;
    pay_the_payee(&w).await;
    let before = mine_until_spendable(&w, &w.payee, PAID).await;

    let sent = PAID / 4;
    let built = w
        .payee
        .ok("build_pending_tx", build_params(&w.funder_address, sent));
    let fee = amount(&built, "fee");
    let submitted = submit(&w.payee, &built).expect("submit");
    assert_eq!(submitted["verdict"], "ACCEPTED", "{submitted}");

    let change = PAID - sent - fee;
    let after = legs(&w.payee);
    assert_eq!(
        before.spendable - after.spendable,
        PAID,
        "spendable drops by the input"
    );
    assert_eq!(
        after.outgoing,
        sent + fee,
        "outgoing is the amount plus the fee"
    );
    assert_eq!(after.incoming, change, "incoming holds the change");
    assert_eq!(
        after.incoming_wait, None,
        "the change is not on chain: no wait"
    );
    assert_eq!(
        before.balance - after.balance,
        sent + fee,
        "the balance drops by the amount plus the fee"
    );

    w.daemon.generate_blocks(1).await;
    refresh(&w.payee);
    let mined = legs(&w.payee);
    assert_eq!(mined.outgoing, 0, "a mined send is not outgoing");
    assert_eq!(mined.incoming, change, "the change is a received output");
    assert!(
        mined.incoming_wait.is_some(),
        "an on-chain output has a wait"
    );

    let matured = mine_until_spendable(&w, &w.payee, change).await;
    assert_eq!(
        (matured.spendable, matured.incoming, matured.outgoing),
        (change, 0, 0)
    );
}

/// A17, a terminal refusal. The payee's second device spends the payee's
/// one output; the first device, which has not seen it, builds and
/// submits a send of the same output and the daemon refuses it as a double
/// spend (`-29106`). The refusal returns the input to spendable and
/// outgoing to zero.
///
/// Observed red 2026-11-15 against a wallet server rebuilt to sum outgoing
/// over every journal row, in flight or not: "outgoing goes to zero"
/// (17895351666 after the refusal).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires SHEKYLD_BIN and SHEKYL_WALLET_RPC_BIN; spawns a live daemon"]
async fn a_refused_send_returns_its_input_to_spendable() {
    let w = wallets().await;
    pay_the_payee(&w).await;
    let before = mine_until_spendable(&w, &w.payee, PAID).await;
    mine_until_spendable(&w, &w.twin, PAID).await;

    let twin_built = w.twin.ok(
        "build_pending_tx",
        build_params(&w.funder_address, PAID / 4),
    );
    let twin_sent = submit(&w.twin, &twin_built).expect("the twin's submit");
    assert_eq!(twin_sent["verdict"], "ACCEPTED", "{twin_sent}");

    let built = w.payee.ok(
        "build_pending_tx",
        build_params(&w.funder_address, PAID / 3),
    );
    match submit(&w.payee, &built) {
        Err(RpcRefusal { code: -29106, .. }) => {}
        other => panic!(
            "the second spend of one output must be refused -29106: {other:?}; log tail:\n{}",
            tail(&w.payee.log_text())
        ),
    }
    let after = legs(&w.payee);
    assert_eq!(
        after.spendable, before.spendable,
        "the input is spendable again"
    );
    assert_eq!(after.outgoing, 0, "outgoing goes to zero");
    assert_eq!(after.balance, before.balance);
}

/// A16, the change below dust. The payee holds one output. A send of it
/// less the with-change fee, which would leave a change of zero, is refused
/// before signing. A send of it less the with-change fee and one atomic
/// unit leaves a leftover one unit above the fee. The build signs and the daemon accepts: the fee is
/// the with-change ladder fee and the change is one atomic unit. Before
/// the fix the signer took the no-change fee, left the rest unaccounted,
/// and its balance self-check refused the transaction (the TRC-1 wallet's
/// intermittent `-29119`).
///
/// Observed red 2026-11-15 against a wallet server rebuilt with the
/// pre-fix fee choice: the build was refused `-29119` with `data.fault`
/// `balance-self-check`, the TRC-1 wallet's failure under its own name.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires SHEKYLD_BIN and SHEKYL_WALLET_RPC_BIN; spawns a live daemon"]
async fn a_change_below_dust_balances() {
    let w = wallets().await;
    pay_the_payee(&w).await;
    mine_until_spendable(&w, &w.payee, PAID).await;

    let quote = w.payee.ok(
        "get_default_fee_priority",
        json!({"n_inputs": 1, "n_outputs": 2}),
    );
    let fee_with_change = amount(&quote, "standard");

    // A leftover of exactly the with-change fee would leave a change of zero
    // and a fee sized for an output the transaction does not carry: the
    // selection does not cover it, so the send is refused before signing.
    match w.payee.call(
        "build_pending_tx",
        build_params(&w.funder_address, PAID - fee_with_change),
    ) {
        Err(RpcRefusal { code: -29101, .. }) => {}
        other => panic!("a zero change must not be built: {other:?}"),
    }

    let sent = PAID - fee_with_change - 1;
    let built = match w
        .payee
        .call("build_pending_tx", build_params(&w.funder_address, sent))
    {
        Ok(built) => built,
        Err(refusal) => panic!(
            "build_pending_tx refused: {refusal:?}; log tail:\n{}",
            tail(&w.payee.log_text())
        ),
    };
    assert_eq!(
        amount(&built, "fee"),
        fee_with_change,
        "the with-change ladder fee"
    );
    let submitted = submit(&w.payee, &built).expect("submit");
    assert_eq!(submitted["verdict"], "ACCEPTED", "{submitted}");
    let after = legs(&w.payee);
    assert_eq!(after.incoming, 1, "the change is one atomic unit");
    assert_eq!(after.outgoing, sent + fee_with_change);
}
