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
//! measurement, not a pass/fail proposition. The parser's own tests below
//! are ordinary unit tests and run everywhere.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use shekyl_rpc_client::Rpc;
use shekyl_scanner::WalletLedgerExt;
use shekyl_tx_weight::{predict_size_and_weight, InputCount, OutputCount, MAX_TREE_DEPTH};
use shekyl_units::AtomicUnits;
use tokio::sync::RwLock;

use super::super::pending::{FeePriority, ReservationId, TxRecipient, TxRequest};
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
/// wallet would select are not yet spendable at the reference block.
///
/// Two refusals mean "wait a block": the wallet's own
/// `OutputNotYetSpendable`, and an output its gate admitted that the tree at
/// the reference block does not hold yet (`OutputNotDrained`, surfacing as
/// `CurveTreeUnavailable`). The second is a wallet defect found by this
/// harness's dry run (registration, "Dry run"): the gate should have
/// classified that output as not yet spendable. Each one is counted in
/// `drain_retries` and written to `run.json`, so the defect stays visible in
/// every run rather than being absorbed.
async fn build(
    daemon: &RegtestDaemon,
    wallet: &Arc<RwLock<Engine<SoloSigner>>>,
    who: &'static str,
    request: &TxRequest,
    mine_to: &str,
    drain_retries: &mut Vec<(&'static str, u64, String)>,
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
            Err(super::super::error::SendError::CurveTreeUnavailable { detail })
                if detail.contains("OutputNotDrained") =>
            {
                drain_retries.push((who, daemon.height().await, detail));
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
    let mut drain_retries = Vec::new();
    for _ in 0..cell.fanout_txs {
        let request = TxRequest {
            recipients: (0..FANOUT_RECIPIENTS)
                .map(|_| TxRecipient {
                    address: wallet_address.clone(),
                    amount_atomic_units: AtomicUnits::from_raw(unit),
                    rid: None,
                })
                .collect(),
            priority: FeePriority::Standard,
        };
        let mut tx = build(
            &daemon,
            &funder,
            "funder",
            &request,
            &funder_address,
            &mut drain_retries,
        )
        .await;
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
                    address: funder_address.clone(),
                    amount_atomic_units: AtomicUnits::from_raw(share),
                    rid: None,
                })
                .collect(),
            priority: FeePriority::Standard,
        };
        let mut tx = build(
            &daemon,
            &wallet,
            "wallet",
            &request,
            &funder_address,
            &mut drain_retries,
        )
        .await;
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
    write_outputs(
        &out,
        cell,
        &messages,
        &built,
        &depth,
        chain_height,
        &drain_retries,
    );
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
    drain_retries: &[(&'static str, u64, String)],
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
            "drain_retries": drain_retries
                .iter()
                .map(|(who, height, detail)| serde_json::json!({
                    "wallet": who,
                    "height": height,
                    "detail": detail,
                }))
                .collect::<Vec<_>>(),
        }))
        .expect("encode run.json"),
    )
    .expect("write run.json");
}

// ---------------------------------------------------------------------------
// The proxy
// ---------------------------------------------------------------------------

/// The bytes of one proxied connection, each direction as it crossed.
#[derive(Default)]
struct Captured {
    to_daemon: Vec<u8>,
    to_wallet: Vec<u8>,
    /// A read or write that failed. Any entry fails the run: a message
    /// cut short by the proxy is not the daemon's message.
    faults: Vec<String>,
}

/// A TCP proxy on loopback that forwards every byte unchanged and keeps a
/// copy, one [`Captured`] per accepted connection.
struct CountingProxy {
    port: u16,
    stop: Arc<AtomicBool>,
    accept: Option<JoinHandle<()>>,
    conns: Arc<Mutex<Vec<Arc<Mutex<Captured>>>>>,
    pumps: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl CountingProxy {
    fn start(upstream: u16) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind the proxy");
        let port = listener.local_addr().expect("proxy address").port();
        let stop = Arc::new(AtomicBool::new(false));
        let conns: Arc<Mutex<Vec<Arc<Mutex<Captured>>>>> = Arc::default();
        let pumps: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::default();
        let accept = {
            let stop = stop.clone();
            let conns = conns.clone();
            let pumps = pumps.clone();
            std::thread::spawn(move || {
                for incoming in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(wallet_side) = incoming else { continue };
                    let daemon_side = TcpStream::connect(("127.0.0.1", upstream))
                        .expect("the proxy reaches the daemon");
                    let captured = Arc::new(Mutex::new(Captured::default()));
                    conns.lock().expect("conns").push(captured.clone());
                    let up = (
                        wallet_side.try_clone().expect("clone"),
                        daemon_side.try_clone().expect("clone"),
                    );
                    let down = (daemon_side, wallet_side);
                    let c_up = captured.clone();
                    let mut held = pumps.lock().expect("pumps");
                    held.push(std::thread::spawn(move || pump(up.0, up.1, &c_up, true)));
                    held.push(std::thread::spawn(move || {
                        pump(down.0, down.1, &captured, false);
                    }));
                }
            })
        };
        Self {
            port,
            stop,
            accept: Some(accept),
            conns,
            pumps,
        }
    }

    /// Stop accepting, wait for every connection to close, and hand back
    /// what crossed. A connection still open after `wait` fails the run:
    /// its last message may be incomplete.
    fn finish(mut self, wait: Duration) -> Vec<Captured> {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the blocked accept; the flag above makes it exit.
        drop(TcpStream::connect(("127.0.0.1", self.port)));
        if let Some(accept) = self.accept.take() {
            accept.join().expect("the accept thread exits");
        }
        let deadline = Instant::now() + wait;
        loop {
            let open = self
                .pumps
                .lock()
                .expect("pumps")
                .iter()
                .filter(|p| !p.is_finished())
                .count();
            if open == 0 {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "{open} proxied directions were still open {wait:?} after the wallets closed"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        let conns = std::mem::take(&mut *self.conns.lock().expect("conns"));
        conns
            .into_iter()
            .map(|c| {
                let captured = Arc::try_unwrap(c)
                    .ok()
                    .expect("no pump still holds a capture")
                    .into_inner()
                    .expect("capture");
                assert!(
                    captured.faults.is_empty(),
                    "the proxy faulted: {:?}",
                    captured.faults
                );
                captured
            })
            .collect()
    }
}

/// Copy `from` to `to` until `from` closes, recording each chunk before it
/// is forwarded; then close `to`'s write half so the peer sees the end.
fn pump(mut from: TcpStream, mut to: TcpStream, sink: &Mutex<Captured>, to_daemon: bool) {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match from.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                {
                    let mut c = sink.lock().expect("capture");
                    if to_daemon {
                        c.to_daemon.extend_from_slice(&buf[..n]);
                    } else {
                        c.to_wallet.extend_from_slice(&buf[..n]);
                    }
                }
                if let Err(e) = to.write_all(&buf[..n]) {
                    sink.lock()
                        .expect("capture")
                        .faults
                        .push(format!("write: {e}"));
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            // A reset by the closing side after its last message is how a
            // pooled connection ends; whether anything was cut short is the
            // parser's to say, since every byte must belong to a message.
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => break,
            Err(e) => {
                sink.lock()
                    .expect("capture")
                    .faults
                    .push(format!("read: {e}"));
                break;
            }
        }
    }
    drop(to.shutdown(Shutdown::Write));
}

// ---------------------------------------------------------------------------
// The parser
// ---------------------------------------------------------------------------

/// One HTTP/1.1 message's bytes, by part.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Message {
    /// Start line and headers, through the blank line.
    head: usize,
    /// The body's content bytes.
    body: usize,
    /// Chunked framing: the size lines, their line ends, the last chunk and
    /// any trailers. Zero for a body with a `Content-Length`.
    framing: usize,
    /// For a request, the method it calls: the path, or `json_rpc:` and the
    /// JSON-RPC `method` for a call to `/json_rpc`. Empty for a response.
    label: String,
}

impl Message {
    fn total(&self) -> usize {
        self.head + self.body + self.framing
    }
}

/// Why a stream could not be split into whole messages.
#[derive(Debug, PartialEq, Eq)]
enum ParseFault {
    /// Bytes remained that do not form a whole message.
    Incomplete { offset: usize },
    /// A header line or chunk size that is not well formed.
    Malformed { offset: usize, what: &'static str },
    /// A different number of requests and responses on one connection.
    Unpaired { requests: usize, responses: usize },
}

impl std::fmt::Display for ParseFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Incomplete { offset } => write!(f, "an incomplete message at byte {offset}"),
            Self::Malformed { offset, what } => write!(f, "{what} at byte {offset}"),
            Self::Unpaired {
                requests,
                responses,
            } => write!(f, "{requests} requests against {responses} responses"),
        }
    }
}

/// Split one connection into (request, response) pairs, in order, the
/// response labelled as its request.
fn pair_messages(captured: &Captured) -> Result<Vec<(Message, Message)>, ParseFault> {
    let requests = split(&captured.to_daemon, true)?;
    let responses = split(&captured.to_wallet, false)?;
    if requests.len() != responses.len() {
        return Err(ParseFault::Unpaired {
            requests: requests.len(),
            responses: responses.len(),
        });
    }
    Ok(requests.into_iter().zip(responses).collect())
}

/// Split a stream into whole messages. Every byte must belong to one.
fn split(stream: &[u8], requests: bool) -> Result<Vec<Message>, ParseFault> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < stream.len() {
        let (message, used) = one_message(&stream[at..], requests).map_err(|f| match f {
            ParseFault::Incomplete { offset } => ParseFault::Incomplete {
                offset: at + offset,
            },
            ParseFault::Malformed { offset, what } => ParseFault::Malformed {
                offset: at + offset,
                what,
            },
            other => other,
        })?;
        out.push(message);
        at += used;
    }
    Ok(out)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// One message from the front of `bytes`, and how many bytes it used.
fn one_message(bytes: &[u8], request: bool) -> Result<(Message, usize), ParseFault> {
    let head = find(bytes, b"\r\n\r\n").ok_or(ParseFault::Incomplete { offset: 0 })? + 4;
    let text = std::str::from_utf8(&bytes[..head]).map_err(|_| ParseFault::Malformed {
        offset: 0,
        what: "a head that is not UTF-8",
    })?;
    let mut lines = text.split("\r\n");
    let start = lines.next().unwrap_or_default();
    let mut content_length = None;
    let mut chunked = false;
    for line in lines.filter(|l| !l.is_empty()) {
        let (name, value) = line.split_once(':').ok_or(ParseFault::Malformed {
            offset: 0,
            what: "a header line without a colon",
        })?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            content_length = Some(value.parse::<usize>().map_err(|_| ParseFault::Malformed {
                offset: 0,
                what: "a Content-Length that is not a number",
            })?);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            chunked = value
                .split(',')
                .any(|c| c.trim().eq_ignore_ascii_case("chunked"));
        }
    }
    let (body, framing, body_range) = if chunked {
        chunked_body(&bytes[head..]).map_err(|f| match f {
            ParseFault::Incomplete { offset } => ParseFault::Incomplete {
                offset: head + offset,
            },
            ParseFault::Malformed { offset, what } => ParseFault::Malformed {
                offset: head + offset,
                what,
            },
            other => other,
        })?
    } else {
        let n = content_length.unwrap_or(0);
        if bytes.len() < head + n {
            return Err(ParseFault::Incomplete { offset: 0 });
        }
        (n, 0, head..head + n)
    };
    let label = if request {
        request_label(start, &bytes[body_range])
    } else {
        String::new()
    };
    let used = head + body + framing;
    Ok((
        Message {
            head,
            body,
            framing,
            label,
        },
        used,
    ))
}

/// A chunked body's content bytes, its framing bytes, and (for labelling)
/// the range of its first chunk. Requests to `/json_rpc` are sent with a
/// length, so the range only ever matters for that case.
fn chunked_body(bytes: &[u8]) -> Result<(usize, usize, std::ops::Range<usize>), ParseFault> {
    let mut at = 0;
    let mut body = 0;
    let mut framing = 0;
    loop {
        let line_end = find(&bytes[at..], b"\r\n").ok_or(ParseFault::Incomplete { offset: at })?;
        let line =
            std::str::from_utf8(&bytes[at..at + line_end]).map_err(|_| ParseFault::Malformed {
                offset: at,
                what: "a chunk size line that is not UTF-8",
            })?;
        let size_hex = line.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_hex, 16).map_err(|_| ParseFault::Malformed {
            offset: at,
            what: "a chunk size that is not hex",
        })?;
        framing += line_end + 2;
        at += line_end + 2;
        if size == 0 {
            // Trailers, if any, then the blank line.
            loop {
                let end =
                    find(&bytes[at..], b"\r\n").ok_or(ParseFault::Incomplete { offset: at })?;
                framing += end + 2;
                at += end + 2;
                if end == 0 {
                    return Ok((body, framing, 0..0));
                }
            }
        }
        if bytes.len() < at + size + 2 {
            return Err(ParseFault::Incomplete { offset: at });
        }
        if &bytes[at + size..at + size + 2] != b"\r\n" {
            return Err(ParseFault::Malformed {
                offset: at + size,
                what: "a chunk not followed by a line end",
            });
        }
        body += size;
        framing += 2;
        at += size + 2;
    }
}

/// The method a request calls: its path, or `json_rpc:<method>` for a
/// JSON-RPC call.
fn request_label(start_line: &str, body: &[u8]) -> String {
    let path = start_line.split(' ').nth(1).unwrap_or_default();
    let path = path.split('?').next().unwrap_or_default();
    if path == "/json_rpc" {
        let method = serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .and_then(|v| v.get("method").and_then(|m| m.as_str()).map(str::to_owned))
            .unwrap_or_else(|| "(unreadable)".to_owned());
        format!("json_rpc:{method}")
    } else {
        path.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn captured(to_daemon: &[u8], to_wallet: &[u8]) -> Captured {
        Captured {
            to_daemon: to_daemon.to_vec(),
            to_wallet: to_wallet.to_vec(),
            faults: Vec::new(),
        }
    }

    const REQ: &[u8] = b"POST /json_rpc HTTP/1.1\r\nhost: 127.0.0.1:1\r\ncontent-length: 34\r\n\r\n{\"jsonrpc\":\"2.0\",\"method\":\"get_x\"}";
    const RESP: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n{}";

    /// Every byte is counted once, and the parts add up to the stream.
    #[test]
    fn a_length_delimited_pair_is_counted_whole() {
        let pairs = pair_messages(&captured(REQ, RESP)).expect("parses");
        assert_eq!(pairs.len(), 1);
        let (request, response) = &pairs[0];
        assert_eq!(request.label, "json_rpc:get_x");
        assert_eq!(request.total(), REQ.len());
        assert_eq!(request.body, 34);
        assert_eq!(response.total(), RESP.len());
    }

    /// Two messages back to back on one connection split at the boundary.
    #[test]
    fn pipelined_messages_split_at_their_boundary() {
        let two_req = [REQ, b"GET /get_height HTTP/1.1\r\nhost: a\r\n\r\n"].concat();
        let two_resp = [RESP, RESP].concat();
        let pairs = pair_messages(&captured(&two_req, &two_resp)).expect("parses");
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[1].0.label, "/get_height");
        let sum: usize = pairs.iter().map(|(q, _)| q.total()).sum();
        assert_eq!(sum, two_req.len());
    }

    /// Chunked framing is counted as framing, not as body, and in the total.
    #[test]
    fn chunked_framing_is_counted() {
        let resp = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n3\r\nabc\r\n2;x=y\r\nde\r\n0\r\nt: v\r\n\r\n";
        let (message, used) = one_message(resp, false).expect("parses");
        assert_eq!(used, resp.len());
        assert_eq!(message.body, 5);
        assert_eq!(message.total(), resp.len());
        assert_eq!(message.framing, resp.len() - message.head - 5);
    }

    /// A message cut short is a fault, never a smaller message.
    #[test]
    fn a_truncated_body_is_refused() {
        let cut = &REQ[..REQ.len() - 1];
        assert!(matches!(
            pair_messages(&captured(cut, RESP)),
            Err(ParseFault::Incomplete { .. })
        ));
        let no_blank_line = b"POST / HTTP/1.1\r\nhost: a\r\n";
        assert!(matches!(
            split(no_blank_line, true),
            Err(ParseFault::Incomplete { .. })
        ));
    }

    /// A request without its response is refused.
    #[test]
    fn an_unanswered_request_is_refused() {
        assert_eq!(
            pair_messages(&captured(REQ, b"")).unwrap_err(),
            ParseFault::Unpaired {
                requests: 1,
                responses: 0
            }
        );
    }

    /// A query string is not part of the method.
    #[test]
    fn a_rest_path_labels_without_its_query() {
        assert_eq!(
            request_label("POST /get_transactions?x=1 HTTP/1.1", b""),
            "/get_transactions"
        );
    }
}
