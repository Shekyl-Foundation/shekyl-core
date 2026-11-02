// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The performance budget's transaction source (`DAEMON_REDB_STORE.md`
//! §1.3a; PB-S1's pool point): real wallet spends, built and proved by the
//! engine, submitted to a running regtest daemon through its RPC.
//!
//! The budget's rule 7 binds the subject: every row exercises the shipped
//! daemon through its real doors. The source is the load generator beside
//! it, as the generating seed is (the seed takes the armed lever; the
//! subject never does). The shipped wallet RPC cannot be the source: it
//! refuses a `fakechain` daemon and has no flag to change that (`VC-R3`).
//! This harness is where that acceptance is already selected
//! ([`super::regtest_expectation`]), in-process, with no operator surface,
//! and the source uses it unchanged. The daemon under test sees an ordinary
//! wallet's `send_raw_transaction`.
//!
//! Driven by `scripts/bench/drs_crash.py`, which reads its stdout:
//!
//! - `SHEKYL_BENCH_TX_SOURCE=address`: prints `BENCH_TX_SOURCE_ADDR=<addr>`,
//!   the address the seed mines to.
//! - `SHEKYL_BENCH_TX_SOURCE=spend`: a fresh wallet from the same seed scans
//!   the daemon's chain, then builds and submits spends to itself, one line
//!   per daemon answer: `ACCEPTED <txid>` for a fresh accept,
//!   `NOT_SPENDABLE` when no output can be referenced yet (the chain is too
//!   short), `STOPPED <why>` when a build or submit fails (the daemon was
//!   killed, or the wallet ran out). A fresh wallet each run holds no send
//!   record, so every run starts from the same spendable outputs.
//!
//! `SHEKYL_BENCH_DAEMON_RPC` names the daemon's RPC port;
//! `SHEKYL_BENCH_SPEND_ATOMIC` the amount each spend pays (default one
//! SKL); `SHEKYL_BENCH_TX_COUNT` a limit on spends (default none).
//!
//! # Not production code
//!
//! A child of the regtest harness, compiled only under `cfg(test)`. Its
//! entry point is `#[ignore]`d and listed as decided dark in
//! `scripts/ci/run_live_daemon_gates.sh`: it is a load generator, not a
//! pass/fail proposition.

#![cfg(test)]

use std::io::Write;
use std::sync::Arc;

use shekyl_units::AtomicUnits;
use tokio::sync::RwLock;

use super::super::error::SendError;
use super::super::pending::{FeePriority, SubmitOutcome, TxDestination, TxRecipient, TxRequest};
use super::super::refresh::RefreshOptions;
use super::super::{Engine, SoloSigner};
use super::create_wallet;

/// The source's seed: one wallet, the same in every run.
const SEED_BYTE: u8 = 0xB5;

/// One SKL in atomic units.
const DEFAULT_SPEND_ATOMIC: u64 = 1_000_000_000;

fn env_u64(name: &str) -> Option<u64> {
    std::env::var(name).ok().map(|v| {
        v.parse()
            .unwrap_or_else(|_| panic!("{name} must be an integer, got {v:?}"))
    })
}

/// One line on stdout, flushed: the driver acts on each as it arrives.
fn say(line: &str) {
    let mut out = std::io::stdout().lock();
    writeln!(out, "{line}").expect("stdout");
    out.flush().expect("stdout");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "the budget's transaction source; driven by scripts/bench/drs_crash.py"]
async fn bench_tx_source() {
    let mode = std::env::var("SHEKYL_BENCH_TX_SOURCE")
        .expect("SHEKYL_BENCH_TX_SOURCE is address or spend");
    let port = u16::try_from(
        env_u64("SHEKYL_BENCH_DAEMON_RPC").expect("SHEKYL_BENCH_DAEMON_RPC is the daemon's port"),
    )
    .expect("a port");
    let seed = [SEED_BYTE; shekyl_crypto_pq::account::MASTER_SEED_BYTES];
    let (wallet, _tmp) = create_wallet(port, &seed, b"bench-source").await;
    let address = wallet.primary_address().encode().expect("encode address");
    match mode.as_str() {
        "address" => say(&format!("BENCH_TX_SOURCE_ADDR={address}")),
        "spend" => {
            let amount = env_u64("SHEKYL_BENCH_SPEND_ATOMIC").unwrap_or(DEFAULT_SPEND_ATOMIC);
            spend(wallet, &address, amount, env_u64("SHEKYL_BENCH_TX_COUNT")).await;
        }
        other => panic!("SHEKYL_BENCH_TX_SOURCE is address or spend, got {other:?}"),
    }
}

async fn spend(wallet: Engine<SoloSigner>, address: &str, amount: u64, limit: Option<u64>) {
    let arc = Arc::new(RwLock::new(wallet));
    let refreshed = match Engine::start_refresh(arc.clone(), RefreshOptions::default()).await {
        Ok(handle) => handle
            .join()
            .await
            .map(|_| ())
            .map_err(|e| format!("{e:?}")),
        Err(e) => Err(format!("{e:?}")),
    };
    if let Err(why) = refreshed {
        say(&format!("STOPPED refresh: {why}"));
        return;
    }
    let request = TxRequest {
        recipients: vec![TxRecipient {
            destination: TxDestination::Address(address.to_owned()),
            amount_atomic_units: AtomicUnits::from_raw(amount),
            rid: None,
        }],
        priority: FeePriority::Standard,
    };
    let mut sent = 0u64;
    while limit.is_none_or(|n| sent < n) {
        let g = arc.read().await;
        let pending = match g.build_pending_tx_async(&request).await {
            Ok(p) => p,
            Err(SendError::OutputNotYetSpendable { .. }) => {
                say("NOT_SPENDABLE");
                return;
            }
            Err(e) => {
                say(&format!("STOPPED build: {e:?}"));
                return;
            }
        };
        match g
            .submit_pending_tx_async(pending.id, pending.content_gen)
            .await
        {
            Ok(SubmitOutcome::Accepted { hash }) => say(&format!("ACCEPTED {hash}")),
            Ok(other) => {
                say(&format!("STOPPED submit answered {other:?}"));
                return;
            }
            Err(e) => {
                say(&format!("STOPPED submit: {e:?}"));
                return;
            }
        }
        sent += 1;
    }
    say(&format!("STOPPED limit {sent}"));
}
