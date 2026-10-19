// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `RT-P5`, its sizes part (`RPC_CHANNEL.md` §9; RT-W9 step 3): the HTTP
//! message sizes, per method, of a generated wallet's traffic with a
//! regtest daemon. The record channel's size classes are derived from them.
//!
//! The registration is
//! `docs/benchmarks/rt_p5_rpc_message_sizes_20261017.md`. It fixes, before
//! any registered run, the traffic generated here, what is counted, the
//! gates a run must pass, and how the classes are derived from the output
//! (`scripts/bench/rt_p5_classes.py`). Read it before changing anything in
//! this file: a change to the generated traffic is a change to the
//! registered method.
//!
//! # What is counted
//!
//! The bytes a stream adapter over the channel would carry: every HTTP/1.1
//! message whole, start line, headers, body and any chunked framing, in
//! each direction. They are taken from a TCP proxy between the wallet's
//! daemon client and the daemon, at the plaintext RPC layer, not from a
//! packet capture and not from inside the server. The proxy forwards bytes
//! unchanged and keeps a copy; the copy is split into messages only after
//! the traffic has stopped, so a parsing defect cannot disturb what it
//! measures, and every byte must belong to exactly one message.
//!
//! # Not production code
//!
//! A child of the regtest harness, compiled only under `cfg(test)`. Its two
//! measurement entry points are `#[ignore]`d and listed as decided dark in
//! `scripts/ci/run_live_daemon_gates.sh`: they are a registered
//! measurement, not a pass/fail proposition. The byte copy and the HTTP
//! split live in [`trace`], and that module's tests run everywhere.

// The production debug-macro lint treats a file as test code only when the
// file itself carries this attribute. The parent harness is already
// test-only; this sibling has to say so on its own.
#![cfg(test)]

#[path = "regtest_e2e_rt_p5_trace.rs"]
mod trace;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use trace::{pair_messages, CountingProxy, Message};

use shekyl_rpc_client::Rpc;
use shekyl_scanner::WalletLedgerExt;
use shekyl_tx_weight::{predict_size_and_weight, InputCount, OutputCount, MAX_TREE_DEPTH};
use shekyl_units::AtomicUnits;
use tokio::sync::RwLock;

use super::super::pending::{FeePriority, ReservationId, TxDestination, TxRecipient, TxRequest};
use super::super::refresh::RefreshOptions;
use super::super::{Engine, SoloSigner};
use super::{assert_tx_confirmed, create_wallet, require_fresh_accept, RegtestDaemon};

/// The largest record payload a message is split at: `MAX_RECORD_PLAINTEXT`
/// (65,535) less `OCCUPANCY_LEN` (2), both `RPC_CHANNEL.md` §4.4. Neither
/// constant exists in code before RT-W9 step 5, so the value is restated
/// here and in the derivation script, and the registration cites both.
const RECORD_PAYLOAD_MAX: usize = 65_535 - 2;

/// Outputs per fan-out transaction: fifteen recipients and the change.
const FANOUT_RECIPIENTS: usize = 15;

/// Blocks mined to the funder after it can first spend, before the fan-out.
/// Its selection is largest-first and its oldest coinbases are its largest,
/// so with this margin the fan-out's inputs are well past the reference
/// block's spendability boundary, and no block is mined between the four
/// fan-out builds; the gate that they share one block depends on that.
const FANOUT_MARGIN_BLOCKS: u64 = 20;

/// One registered cell: the traffic one run generates.
struct Cell {
    /// Written into every output file, so a dry run's files can never be
    /// read as the registered run's.
    name: &'static str,
    /// The funding wallet's seed byte, repeated.
    funder_seed: u8,
    /// The measured wallet's seed byte, repeated. The restored wallet
    /// uses the same seed.
    wallet_seed: u8,
    /// Fan-out transactions, each paying the measured wallet
    /// [`FANOUT_RECIPIENTS`] equal outputs, mined together in one block.
    fanout_txs: usize,
    /// The measured wallet's spends, as (inputs, outputs), in order.
    shapes: &'static [(usize, usize)],
}

/// The registered traffic: every input count from one to the maximum by
/// doubling, at the smallest and the largest output count.
const SHAPES: &[(usize, usize)] = &[
    (1, 2),
    (2, 2),
    (4, 2),
    (8, 2),
    (1, 16),
    (2, 16),
    (4, 16),
    (8, 16),
];

/// The registered run's cell. Its seeds are used by no other run.
const REGISTERED: Cell = Cell {
    name: "registered",
    funder_seed: 0x51,
    wallet_seed: 0x52,
    fanout_txs: 4,
    shapes: SHAPES,
};

/// The dry run: the same cell under other seeds, so that every gate and
/// every shape is exercised before the registered run, and nothing it
/// writes can be mistaken for the registered data.
const DRY: Cell = Cell {
    name: "dry",
    funder_seed: 0xD1,
    wallet_seed: 0xD2,
    fanout_txs: 4,
    shapes: SHAPES,
};

#[tokio::test(flavor = "multi_thread")]
#[ignore = "RT-P5 dry run: requires SHEKYLD_BIN and RT_P5_OUT; spawns a live daemon"]
async fn rt_p5_dry_run() {
    run_cell(&DRY).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "RT-P5 registered run: requires SHEKYLD_BIN and RT_P5_OUT; spawns a live daemon"]
async fn rt_p5_registered_run() {
    run_cell(&REGISTERED).await;
}

/// Where a run writes: `RT_P5_OUT`, a directory that must not exist yet,
/// so that two runs can never share one.
fn output_dir(cell: &Cell) -> PathBuf {
    let base = std::env::var_os("RT_P5_OUT")
        .map(PathBuf::from)
        .expect("RT_P5_OUT must name a directory for this run's files");
    let dir = base.join(cell.name);
    assert!(
        !dir.exists(),
        "the run directory already exists; a run never writes over another run's files"
    );
    std::fs::create_dir_all(&dir).expect("create the run directory");
    dir
}

async fn refresh(wallet: &Arc<RwLock<Engine<SoloSigner>>>) {
    Engine::start_refresh(wallet.clone(), RefreshOptions::default())
        .await
        .expect("start_refresh")
        .join()
        .await
        .expect("refresh joins");
}

async fn unlocked(wallet: &Arc<RwLock<Engine<SoloSigner>>>) -> AtomicUnits {
    wallet.read().await.ledger().balance().unlocked
}

async fn address_of(wallet: &Arc<RwLock<Engine<SoloSigner>>>) -> String {
    wallet
        .read()
        .await
        .primary_address()
        .encode()
        .expect("encode address")
}

/// One built transaction, as the trace records it.
struct Built {
    wallet: &'static str,
    inputs: usize,
    outputs: usize,
    tx_len: usize,
    fee: u64,
    pending_id: ReservationId,
    content_gen: u64,
    hash: Option<shekyl_types::TxHash>,
}

/// Build `request` from `wallet`, mining to `mine_to` while the outputs the
/// wallet would select are not yet spendable at the reference block (the
/// wallet's `OutputNotYetSpendable`). Any other refusal fails the run: an
/// output the wallet's gate admits but the tree at the reference does not
/// hold (`CurveTreeUnavailable` with `OutputNotDrained`) is the defect this
/// harness's dry run found and this PR fixed (registration, "Dry run").
async fn build(
    daemon: &RegtestDaemon,
    wallet: &Arc<RwLock<Engine<SoloSigner>>>,
    who: &'static str,
    request: &TxRequest,
    mine_to: &str,
) -> Built {
    for _ in 0..48 {
        let attempt = wallet.read().await.build_pending_tx_async(request).await;
        match attempt {
            Ok(pending) => {
                let tx = shekyl_wire::Transaction::from_bytes(&pending.tx_bytes)
                    .expect("a built transaction parses");
                return Built {
                    wallet: who,
                    inputs: tx.prefix.inputs.len(),
                    outputs: tx.prefix.outputs.len(),
                    tx_len: pending.tx_bytes.len(),
                    fee: pending.fee_atomic_units.to_raw(),
                    pending_id: pending.id,
                    content_gen: pending.content_gen,
                    hash: None,
                };
            }
            Err(super::super::error::SendError::OutputNotYetSpendable { .. }) => {
                daemon.generate_blocks(1, mine_to).await;
                refresh(wallet).await;
            }
            Err(e) => panic!(
                "{who}: build a transaction at daemon height {}: {e:?}",
                daemon.height().await
            ),
        }
    }
    panic!("{who}: the outputs never became spendable at the reference block");
}

async fn submit(wallet: &Arc<RwLock<Engine<SoloSigner>>>, built: &mut Built) {
    let outcome = wallet
        .read()
        .await
        .submit_pending_tx_async(built.pending_id, built.content_gen)
        .await
        .expect("the daemon answers the submission");
    built.hash = Some(require_fresh_accept(outcome, built.wallet));
}

/// The traffic, in the order the registration states it.
async fn run_cell(cell: &Cell) {
    let out = output_dir(cell);
    let daemon = RegtestDaemon::start().await;
    let upstream = daemon.rpc_port();

    let funder_proxy = CountingProxy::start(upstream);
    let wallet_proxy = CountingProxy::start(upstream);
    let restore_proxy = CountingProxy::start(upstream);

    let funder_seed = [cell.funder_seed; shekyl_crypto_pq::account::MASTER_SEED_BYTES];
    let wallet_seed = [cell.wallet_seed; shekyl_crypto_pq::account::MASTER_SEED_BYTES];

    let (funder, _funder_dir) = create_wallet(funder_proxy.port, &funder_seed, b"rt-p5-f").await;
    let funder = Arc::new(RwLock::new(funder));
    let (wallet, _wallet_dir) = create_wallet(wallet_proxy.port, &wallet_seed, b"rt-p5-w").await;
    let wallet = Arc::new(RwLock::new(wallet));
    let funder_address = address_of(&funder).await;
    let wallet_address = address_of(&wallet).await;

    // 1. Mature the funder: mine to it in batches of ten until it can
    //    spend.
    for _ in 0..30 {
        daemon.generate_blocks(10, &funder_address).await;
        refresh(&funder).await;
        if unlocked(&funder).await > AtomicUnits::ZERO {
            break;
        }
    }
    assert!(
        unlocked(&funder).await > AtomicUnits::ZERO,
        "the funder never matured"
    );
    daemon
        .generate_blocks(FANOUT_MARGIN_BLOCKS, &funder_address)
        .await;
    refresh(&funder).await;
    let funded = unlocked(&funder).await;
    eprintln!(
        "rt-p5: funder unlocked {funded:?} at height {}",
        daemon.height().await
    );
    assert!(funded > AtomicUnits::ZERO, "the funder never matured");

    // 2. The fan-out: every transaction pays the wallet fifteen outputs of
    //    `unit`, and all of them are mined in one block. `unit` is chosen so
    //    that the fan-out spends at most half of the funder's balance.
    let unit = funded.to_raw()
        / u64::try_from(2 * cell.fanout_txs * FANOUT_RECIPIENTS).expect("small count");
    assert!(
        unit > 0,
        "the funder's balance is too small for the fan-out"
    );
    let mut built = Vec::new();
    for _ in 0..cell.fanout_txs {
        let request = TxRequest {
            recipients: (0..FANOUT_RECIPIENTS)
                .map(|_| TxRecipient {
                    destination: TxDestination::Address(wallet_address.clone()),
                    amount_atomic_units: AtomicUnits::from_raw(unit),
                    rid: None,
                })
                .collect(),
            priority: FeePriority::Standard,
        };
        let mut tx = build(&daemon, &funder, "funder", &request, &funder_address).await;
        eprintln!(
            "rt-p5: fan-out {}: {} in, {} out, {} bytes, at height {}",
            built.len(),
            tx.inputs,
            tx.outputs,
            tx.tx_len,
            daemon.height().await
        );
        submit(&funder, &mut tx).await;
        built.push(tx);
    }
    let block = daemon.generate_blocks(1, &funder_address).await;
    let fanout_block = block.blocks.first().expect("one block mined");
    let carried = daemon.block_tx_hashes(fanout_block).await.len();
    assert_eq!(
        carried, cell.fanout_txs,
        "the fan-out transactions must be mined together in one block"
    );

    // 3. The wallet syncs, and spends each registered shape in turn. A
    //    spend of `k` inputs asks for `(k - 1) * unit + unit / 2`: the
    //    wallet's largest outputs are the fan-out's `unit` outputs (every
    //    change it makes is below `unit`), and its selection is largest
    //    first, so `k` of them are the fewest that cover it. The shape is
    //    read back from the built transaction and checked, never assumed.
    // The fan-out's outputs are spendable once they are `SPENDABLE_AGE`
    // deep; mine one block at a time until all of them are unlocked.
    let received = unit * u64::try_from(cell.fanout_txs * FANOUT_RECIPIENTS).expect("small count");
    refresh(&wallet).await;
    for _ in 0..40 {
        if unlocked(&wallet).await.to_raw() >= received {
            break;
        }
        daemon.generate_blocks(1, &funder_address).await;
        refresh(&wallet).await;
    }
    assert!(
        unlocked(&wallet).await.to_raw() >= received,
        "the fan-out's outputs never unlocked"
    );
    for &(inputs, outputs) in cell.shapes {
        let k = u64::try_from(inputs).expect("small count");
        let amount = (k - 1) * unit + unit / 2;
        let recipients = outputs - 1;
        let share = amount / u64::try_from(recipients).expect("small count");
        let request = TxRequest {
            recipients: (0..recipients)
                .map(|_| TxRecipient {
                    destination: TxDestination::Address(funder_address.clone()),
                    amount_atomic_units: AtomicUnits::from_raw(share),
                    rid: None,
                })
                .collect(),
            priority: FeePriority::Standard,
        };
        let mut tx = build(&daemon, &wallet, "wallet", &request, &funder_address).await;
        assert_eq!(
            (tx.inputs, tx.outputs),
            (inputs, outputs),
            "the spend must have the registered shape"
        );
        submit(&wallet, &mut tx).await;
        assert_tx_confirmed(&daemon, &funder_address, tx.hash.expect("submitted")).await;
        built.push(tx);
        refresh(&wallet).await;
    }

    // 4. A wallet restored from the same seed syncs the whole chain from
    //    genesis.
    let (restored, _restored_dir) =
        create_wallet(restore_proxy.port, &wallet_seed, b"rt-p5-r").await;
    let restored = Arc::new(RwLock::new(restored));
    refresh(&restored).await;

    let depth: serde_json::Value = daemon
        .rpc()
        .json_rpc_call("get_curve_tree_info", None)
        .await
        .expect("get_curve_tree_info");
    let chain_height = daemon.height().await;

    // Every connection closes once its wallet is gone; only then is the
    // copy complete.
    drop(funder);
    drop(wallet);
    drop(restored);
    let mut messages = Vec::new();
    for (who, proxy) in [
        ("funder", funder_proxy),
        ("wallet", wallet_proxy),
        ("restored", restore_proxy),
    ] {
        let conns = proxy.finish(Duration::from_secs(60));
        assert!(!conns.is_empty(), "{who}: the proxy saw no connection");
        for (conn, captured) in conns.into_iter().enumerate() {
            let pairs = pair_messages(&captured)
                .unwrap_or_else(|fault| panic!("{who} connection {conn}: {fault}"));
            for (seq, (request, response)) in pairs.into_iter().enumerate() {
                messages.push(Row {
                    wallet: who,
                    conn,
                    seq,
                    direction: "request",
                    message: request.clone(),
                    label: request.label.clone(),
                });
                messages.push(Row {
                    wallet: who,
                    conn,
                    seq,
                    direction: "response",
                    label: request.label.clone(),
                    message: response,
                });
            }
        }
    }

    check_subjects(&messages, &built);
    write_outputs(&out, cell, &messages, &built, &depth, chain_height);
}

/// The gates of the registration that read the messages (rule 47: the
/// subject must be present, not merely unrefuted).
fn check_subjects(messages: &[Row], built: &[Built]) {
    for needle in [
        "/submit_transaction",
        "json_rpc:get_block",
        "/get_transactions",
        "/get_o_indexes.bin",
    ] {
        assert!(
            messages.iter().any(|m| m.label == needle),
            "the trace must carry `{needle}`"
        );
    }
    assert!(
        !messages.iter().any(|m| m.label.ends_with("(unreadable)")),
        "every JSON-RPC request must name its method"
    );
    let largest = messages
        .iter()
        .map(|m| m.message.total())
        .max()
        .expect("messages");
    assert!(
        largest > RECORD_PAYLOAD_MAX,
        "the trace must carry a message larger than one record ({largest} bytes is the largest)"
    );
    let submissions = messages
        .iter()
        .filter(|m| m.label == "/submit_transaction" && m.direction == "request")
        .count();
    assert_eq!(
        submissions,
        built.len(),
        "one submission message per built transaction"
    );
}

/// One message in the trace.
struct Row {
    wallet: &'static str,
    conn: usize,
    seq: usize,
    direction: &'static str,
    label: String,
    message: Message,
}

fn write_outputs(
    out: &Path,
    cell: &Cell,
    messages: &[Row],
    built: &[Built],
    depth: &serde_json::Value,
    chain_height: u64,
) {
    let mut csv = String::from("cell,wallet,conn,seq,direction,label,head,body,framing,total\n");
    for m in messages {
        csv.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{}\n",
            cell.name,
            m.wallet,
            m.conn,
            m.seq,
            m.direction,
            m.label,
            m.message.head,
            m.message.body,
            m.message.framing,
            m.message.total()
        ));
    }
    std::fs::write(out.join("messages.csv"), csv).expect("write messages.csv");

    // Each submitted transaction, the tree depth its wire size matches,
    // and its wire size at every depth up to eight from the weight crate's
    // structural predictor, which mirrors `Transaction::write`.
    let mut txs = String::from(
        "cell,tx,wallet,inputs,outputs,tx_len,fee,built_depth,depth,predicted_tx_len\n",
    );
    for (index, b) in built.iter().enumerate() {
        // `clamped` would hide an out-of-range count; a built
        // transaction's counts are in range, so equality is checked.
        let n_in = InputCount::clamped(b.inputs);
        let n_out = OutputCount::clamped(b.outputs);
        assert_eq!((n_in.get(), n_out.get()), (b.inputs, b.outputs));
        let built_depth = (1..=MAX_TREE_DEPTH)
            .find(|&d| predict_size_and_weight(n_in, n_out, d, b.fee).0 == b.tx_len)
            .unwrap_or_else(|| {
                panic!(
                    "no tree depth predicts a {}-in {}-out transaction of {} bytes",
                    b.inputs, b.outputs, b.tx_len
                )
            });
        for d in 1..=8u8 {
            txs.push_str(&format!(
                "{},{},{},{},{},{},{},{},{},{}\n",
                cell.name,
                index,
                b.wallet,
                b.inputs,
                b.outputs,
                b.tx_len,
                b.fee,
                built_depth,
                d,
                predict_size_and_weight(n_in, n_out, d, b.fee).0
            ));
        }
    }
    std::fs::write(out.join("transactions.csv"), txs).expect("write transactions.csv");

    std::fs::write(
        out.join("run.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "cell": cell.name,
            "fanout_txs": cell.fanout_txs,
            "shapes": cell.shapes,
            "chain_height": chain_height,
            "curve_tree_info": depth,
        }))
        .expect("encode run.json"),
    )
    .expect("write run.json");
}
