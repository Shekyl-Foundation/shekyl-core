// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! GF-7 leg-(b) sealing-run harness (`ARCHIVAL_BOND_WI4_MEASUREMENT.md`
//! §19.8) — the receipt-timestamped live-driver form of the wall-clock
//! sweep-phase channel grade. **Scope (§19.10, 2026-07-19): retained as a
//! dispersal-regression tripwire** — the graded `K = 2` concurrent-persona
//! geometry is instrument magnification over a design-foreclosed behavior,
//! and the form's former `K_COVER` seal-input status is withdrawn; what this
//! harness guards is that the dispersal decoupler executes in shipped code
//! (a silently-broken draw would give a wallet's few real posts an
//! exact-phase corroborator).
//!
//! What runs here is the **production** task + dispatch code path
//! (`run_pscan_task` at `PScanConfig::production()` + `DEFAULT_PSCAN_CADENCE`,
//! real tokio sleeps in `pscan/dispatch.rs` phase 3), harness-spawned through
//! the §19.8.1 seam ([`Engine::start_pscan_sealing_run`]) against a live
//! `shekyld --regtest`. The harness owns only the *timestamping* (the
//! recording observer stamps each `BondPostDispatched` receipt against the
//! run epoch) and the artifact; the *judgment* — circular statistic, committed
//! bound `r < 2`, controls — stays sim-side (`shekyl-staking-sim --gf7-seal`).
//!
//! Geometry, controls, and grading are **pre-committed** in §19.8.2–§19.8.4;
//! this file implements them and adds nothing. Notably:
//!
//! - Posts are synthetic bytes seeded directly into `.wallet.pending` through
//!   the engine-held `pending_write_lock` (the WI-2 two-writer discipline).
//!   The receipt emit precedes the send (dispatch phase 3), so the receipt
//!   instant is outcome-independent; the daemon's terminal rejection of the
//!   synthetic bytes retires the record, which is what permits re-seeding
//!   round `j+1` under the one-live-post-per-persona rule.
//! - Runs are sequential (scheduler contention across concurrent runs would
//!   be an unmodeled timing input) and multi-hour by design (§19.8.2
//!   wall-clock budget names ≈ 4–5 h).
//!
//! Run with (from `rust/`):
//!
//! ```text
//! SHEKYLD_BIN=/abs/path/build/bin/shekyld \
//!   cargo test -p shekyl-engine-core --features gf7-hooks \
//!   gf7_sealing_run -- --ignored --nocapture
//! ```
//!
//! The artifact lands at `GF7_SEAL_ARTIFACT` (default
//! `target/gf7-seal-receipts.jsonl`), appended run-by-run so a crash loses at
//! most the in-flight run. Grade it with:
//!
//! ```text
//! cargo run -p shekyl-staking-sim -- --gf7-seal path/to/gf7-seal-receipts.jsonl
//! ```

// Self-declare as test code for the debug-macro CI gate (`build.yml`): the
// `cfg` gate lives at the parent (`mod.rs`, `all(test, feature = "gf7-hooks")`),
// which the gate's scan cannot see; this in-file marker is the `regtest_e2e.rs`
// precedent and is redundant with (never wider than) the parent gate.
#![cfg(test)]

use std::io::Write as _;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use shekyl_engine_state::pending_post_block::{PendingBondPost, PendingPostState, SealAdmission};
use shekyl_standoff::gf7::{BroadcastTimelineObserver, TimelineEvent};
use shekyl_types::{BlockHeight, PCanonicalId, PSlot};
use tokio::sync::RwLock;

use super::pscan::dispatch::{DispatchConfig, PendingPostStore, PendingSealStore};
use super::pscan::start::{
    pending_post_store_for_engine, PScanHandle, SealingRunOverrides, DEFAULT_PSCAN_CADENCE,
};
use super::regtest_e2e::{persona_address, staker_wallet, try_generate_blocks, RegtestDaemon};
use super::{Engine, SoloSigner};

// ---------------------------------------------------------------------------
// §19.8.2 run geometry (pre-committed — do not tune here; amend the doc first)
// ---------------------------------------------------------------------------

/// Anonymity set `N`: wallets per run.
const WALLETS: usize = 10;
/// Wallet size `K`: personas (slots) per wallet.
const PERSONAS_PER_WALLET: usize = 2;
/// Posts per persona `m` (the accumulation the observer integrates over).
const POSTS_PER_PERSONA: usize = 4;
/// Graded production runs `R`.
const PRODUCTION_RUNS: usize = 24;
/// Positive-control runs (§19.8.3 control 1: `dispersal_bound = 0`).
const POSITIVE_CONTROL_RUNS: usize = 8;
/// Pre-mine target: past the production finality horizon
/// (`ARCHIVAL_REORG_DEPTH_BLOCKS` = 720) plus slack, so every sweep does real
/// per-tick fetch work instead of idling on an empty scan window.
const PREMINE_BLOCKS: u64 = shekyl_archival_retention::ARCHIVAL_REORG_DEPTH_BLOCKS + 30;
/// Blocks per `generateblocks` RPC (the established regtest batch size).
const MINE_BATCH_BLOCKS: u64 = 20;
/// Background generator interval (§19.8.2 chain row: ~1 block / 30 s).
const BACKGROUND_MINE_INTERVAL: Duration = Duration::from_secs(30);
/// Background-miner tolerance: the maximum number of *consecutive*
/// `generateblocks` failures the session absorbs; the next one past this fails
/// the run loud (via the health check). Three misses ≈ 90 s without chain
/// advancement — noise against the 720-block finality horizon — while a
/// persistent failure (daemon gone, port dead) must kill the session, not
/// silently freeze the chain under a grading run (§19.8.2 chain row is part of
/// the committed geometry).
const MINER_MAX_CONSECUTIVE_FAILURES: u32 = 3;
/// The production cadence `T` in ms, derived from the engine's own constant
/// (never a mirrored literal). Triple duty, one value: the `φ` stagger window
/// (draws are U[0, T)), the period the §19.8.4 statistic folds by, and the
/// `cadence_ms` stamp on every receipt row — the grader refuses an artifact
/// whose recorded period differs from its own `TICK_MS` fold, so a cadence
/// retune cannot silently invalidate the statistic.
// (`as_secs * 1000` rather than `as_millis`: the latter returns `u128` and
// would need a truncating cast; whole-second + subsec terms stay in u64.)
const CADENCE_MS: u64 =
    DEFAULT_PSCAN_CADENCE.as_secs() * 1000 + DEFAULT_PSCAN_CADENCE.subsec_millis() as u64;
/// Per-run receipt deadline. A round costs `K` ticks (60 s each) plus a
/// dispersal draw; `m = 4` rounds ≈ 8–12 min. Past 30 min something is wedged
/// and the run must fail loudly (an incomplete run is ungradeable, and a
/// silent partial artifact would corrupt the pooled statistic).
const RUN_DEADLINE: Duration = Duration::from_secs(30 * 60);
/// Poll interval for the receipt-driven re-seeding loop.
const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// `usize → u64`, infallible on every supported target; named so the
/// conversion intent (ordinals into the artifact's numeric fields) reads at
/// the call site.
fn ordinal(x: usize) -> u64 {
    u64::try_from(x).expect("usize ordinal fits u64")
}

/// The two §19.8.2 arms. The artifact label, the seed-domain tag, the run
/// count, and the dispatch override all derive from this one value, so a
/// receipt's arm label can never be transposed against the config that
/// produced it — the §19.1 "non-production config does not satisfy" clause
/// binds the graded rows **by construction**, not by call-site convention
/// (the grader trusts the label; a mislabeled row would be undetectable
/// downstream).
#[derive(Clone, Copy)]
enum Arm {
    Production,
    PositiveControl,
}

impl Arm {
    /// The label the grader keys arms by (`gf7_seal.rs` twin constants).
    fn label(self) -> &'static str {
        match self {
            Arm::Production => "production",
            Arm::PositiveControl => "positive-control",
        }
    }

    /// The seed-domain tag: keeps wallet seeds / persona ids / `φ` draws
    /// disjoint across arms.
    fn tag(self) -> u64 {
        match self {
            Arm::Production => 0,
            Arm::PositiveControl => 1,
        }
    }

    /// Runs per arm (§19.8.2 / §19.8.3).
    fn runs(self) -> usize {
        match self {
            Arm::Production => PRODUCTION_RUNS,
            Arm::PositiveControl => POSITIVE_CONTROL_RUNS,
        }
    }

    /// §19.8.3 control 1: `dispersal_bound = 0` at production cadence is the
    /// ONLY permitted config deviation, structurally confined to the
    /// positive-control arm — the production arm cannot carry an override.
    fn dispatch_override(self) -> Option<DispatchConfig> {
        match self {
            Arm::Production => None,
            Arm::PositiveControl => Some(DispatchConfig {
                dispersal_bound: Duration::ZERO,
                ..DispatchConfig::production(DEFAULT_PSCAN_CADENCE)
            }),
        }
    }
}

/// One receipt row of the artifact (§19.8.1 schema: run ordinal, wallet
/// ordinal, persona slot ordinal, receipt instant in ms from the run epoch,
/// ground-truth sibling designation, arm label, recording cadence). The
/// sibling designation is the wallet ordinal: same `sibling_group` = same
/// wallet = ground-truth siblings. Serialized with `serde` (already a
/// dev-dependency) so the writer cannot drift from the grader's
/// `#[derive(Deserialize)]` twin field-by-hand; `cadence_ms` is the load-time
/// period tie (see [`CADENCE_MS`]).
#[derive(Clone, serde::Serialize)]
struct Receipt {
    arm: &'static str,
    run: usize,
    wallet: usize,
    slot: u64,
    receipt_ms: u64,
    sibling_group: usize,
    cadence_ms: u64,
}

/// The harness-local recording observer (§19.8.1: following the landed gate-8
/// precedent of a `cfg(test)` recorder inside the engine crate). One instance
/// per wallet task; stamps each dispatch receipt against the shared run epoch
/// and pushes it onto the run's sink. Timestamps live **here**, never in
/// event payloads — the hooks-spec payload ban stays intact.
struct ReceiptRecorder {
    arm: &'static str,
    run: usize,
    wallet: usize,
    epoch: Instant,
    sink: Arc<Mutex<Vec<Receipt>>>,
}

impl BroadcastTimelineObserver for ReceiptRecorder {
    fn record(&mut self, event: TimelineEvent) {
        if let TimelineEvent::BondPostDispatched { persona, .. } = event {
            let receipt_ms = u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX);
            self.sink
                .lock()
                .expect("receipt sink poisoned")
                .push(Receipt {
                    arm: self.arm,
                    run: self.run,
                    wallet: self.wallet,
                    slot: persona,
                    receipt_ms,
                    sibling_group: self.wallet,
                    cadence_ms: CADENCE_MS,
                });
        }
    }
}

/// SplitMix64 step — the harness's deterministic draw source for wallet
/// seeds, persona ids, and the per-wallet `φ` stagger. Determinism keeps a
/// re-run reproducible for debugging; the *graded* timing randomness (the
/// dispersal draw) stays production-owned (`OsRngGapAdapter` inside the
/// driver), untouched by this.
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// A fresh, unique master seed per (arm, run, wallet) — run independence
/// (§19.8.2) comes from fresh wallets + fresh `φ` draws.
fn wallet_seed(
    arm_tag: u64,
    run: usize,
    wallet: usize,
) -> [u8; shekyl_crypto_pq::account::MASTER_SEED_BYTES] {
    let mut state =
        0x6766_375f_7365_616c ^ (arm_tag << 48) ^ (ordinal(run) << 16) ^ ordinal(wallet);
    let mut seed = [0u8; shekyl_crypto_pq::account::MASTER_SEED_BYTES];
    for chunk in seed.chunks_mut(8) {
        let v = splitmix64(&mut state).to_le_bytes();
        chunk.copy_from_slice(&v[..chunk.len()]);
    }
    seed
}

/// The synthetic persona id for one (arm, run, wallet, slot). Stable across
/// the wallet's `m` rounds: the one-live-post-per-persona rule then serializes
/// re-seeding naturally (round `j+1`'s push is refused until round `j`'s
/// record was terminally rejected and removed), which is exactly the §19.8.2
/// "appended after round `j`'s receipts arrive" discipline.
fn synthetic_persona(arm_tag: u64, run: usize, wallet: usize, slot: usize) -> PCanonicalId {
    let mut state = 0x7063_616e_5f69_6421
        ^ (arm_tag << 56)
        ^ (ordinal(run) << 24)
        ^ (ordinal(wallet) << 8)
        ^ ordinal(slot);
    let mut bytes = [0u8; 32];
    for chunk in bytes.chunks_mut(8) {
        chunk.copy_from_slice(&splitmix64(&mut state).to_le_bytes());
    }
    PCanonicalId::from_bytes(bytes)
}

/// One synthetic pending bond post, due immediately (`anchor_t0 = 0`,
/// `bond_post_offset_blocks = 0`). The bytes are deliberately garbage: the
/// channel under grade ends at the emit (§19.8.5 rejects the full WI-2
/// funding path), and the daemon's terminal rejection is what retires the
/// record for the next round's seed.
fn synthetic_post(persona: PCanonicalId, slot: usize, round: usize) -> PendingBondPost {
    PendingBondPost {
        p_slot: PSlot::from_raw(u32::try_from(slot).expect("slot fits u32")),
        persona,
        tx_bytes: format!("gf7-sealing-run synthetic post slot={slot} round={round}").into_bytes(),
        bond_post_offset_blocks: 0,
        anchor_t0: BlockHeight::from_raw(0),
        funding_gindexes: Vec::new(),
        state: PendingPostState::Pending,
    }
}

/// The artifact path: `GF7_SEAL_ARTIFACT` or the in-tree default.
fn artifact_path() -> std::path::PathBuf {
    std::env::var_os("GF7_SEAL_ARTIFACT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("target/gf7-seal-receipts.jsonl"))
}

/// Append one run's receipts to the artifact (crash-safety: a killed session
/// keeps every completed run's rows).
fn append_receipts(path: &std::path::Path, receipts: &[Receipt]) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create artifact dir");
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .expect("open artifact for append");
    for r in receipts {
        let line = serde_json::to_string(r).expect("serialize receipt row");
        writeln!(f, "{line}").expect("append receipt line");
    }
    f.flush().expect("flush artifact");
}

/// Everything one live wallet task needs for the run loop.
struct WalletTask {
    arc: Arc<RwLock<Engine<SoloSigner>>>,
    _tmp: tempfile::TempDir,
    handle: PScanHandle,
    /// Rounds seeded so far, per slot (index = slot ordinal).
    seeded_rounds: [usize; PERSONAS_PER_WALLET],
}

/// Seed one round's post for `(wallet, slot)` through the wallet's
/// [`PendingPostStore`] (built once per wallet — the store is two `Arc`s over
/// engine + write lock, invariant for the wallet's lifetime, so the 500 ms
/// retry poll must not rebuild it per call). Returns whether the push was
/// accepted (refused while the previous round's record is still live — the
/// caller retries on the next poll).
async fn try_seed<S>(
    store: &PendingPostStore<S>,
    arm_tag: u64,
    run: usize,
    wallet: usize,
    slot: usize,
    round: usize,
) -> bool
where
    S: PendingSealStore,
{
    let persona = synthetic_persona(arm_tag, run, wallet, slot);
    let post = synthetic_post(persona, slot, round);
    store
        .mutate(|block| {
            // Through the shared admission, like production: the harness must
            // not be the one caller able to seed an overlapping reservation.
            let g = block.generation();
            let pushed = block.seal_post(post, g) == SealAdmission::Admit;
            (pushed, pushed)
        })
        .await
        .expect("seed pending post")
}

/// Count receipts per (wallet, slot) in the sink.
fn receipt_count(sink: &Arc<Mutex<Vec<Receipt>>>, wallet: usize, slot: usize) -> usize {
    let slot = ordinal(slot);
    sink.lock()
        .expect("receipt sink poisoned")
        .iter()
        .filter(|r| r.wallet == wallet && r.slot == slot)
        .count()
}

/// One graded run (§19.8.2): `N` fresh staker wallets, each spawning the
/// production P-scan task through the sealing seam at a fresh `φ` stagger;
/// `m` rounds of synthetic posts per persona, re-seeded receipt-by-receipt;
/// returns the run's receipts once every persona has exactly `m`. Fails
/// loudly (≤ one poll interval late) if the background miner died — receipts
/// recorded against a frozen chain violate the committed geometry and must
/// never reach the artifact.
async fn one_run(
    daemon: &RegtestDaemon,
    arm: Arm,
    run: usize,
    miner: &tokio::task::JoinHandle<()>,
) -> Vec<Receipt> {
    let arm_tag = arm.tag();
    let sink: Arc<Mutex<Vec<Receipt>>> = Arc::new(Mutex::new(Vec::new()));
    let epoch = Instant::now();
    let mut stagger_state = 0x7068_695f_6472_6177 ^ (arm_tag << 40) ^ ordinal(run);

    // Fresh wallets, created sequentially (KDF-bound), each seeded with round
    // 0 for both personas before its task starts — the first sweep's dispatch
    // tick then has work immediately. The wallet's `PendingPostStore` is
    // built here, once, and reused by every retry poll.
    let mut wallets: Vec<(Arc<RwLock<Engine<SoloSigner>>>, tempfile::TempDir)> =
        Vec::with_capacity(WALLETS);
    let mut stores = Vec::with_capacity(WALLETS);
    for wallet in 0..WALLETS {
        let seed = wallet_seed(arm_tag, run, wallet);
        let (arc, tmp, _principal) =
            staker_wallet(daemon.rpc_port(), &seed, PSlot::from_raw(0)).await;
        let write_lock = arc.read().await.pending_write_lock.clone();
        let store = pending_post_store_for_engine(arc.clone(), write_lock);
        for slot in 0..PERSONAS_PER_WALLET {
            let pushed = try_seed(&store, arm_tag, run, wallet, slot, 0).await;
            assert!(pushed, "round-0 seed must land on a fresh wallet");
        }
        wallets.push((arc, tmp));
        stores.push(store);
    }

    // φ ~ U[0, T): the task start instant is the phase (§19.8.2). Every
    // stagger sleep runs inside its own spawn so the draws are relative to
    // the run epoch, not cumulative.
    let mut starts = Vec::with_capacity(WALLETS);
    for (wallet, (arc, _)) in wallets.iter().enumerate() {
        let stagger_ms = splitmix64(&mut stagger_state) % CADENCE_MS;
        let observer = ReceiptRecorder {
            arm: arm.label(),
            run,
            wallet,
            epoch,
            sink: sink.clone(),
        };
        let arc_for_start = arc.clone();
        let dispatch_override = arm.dispatch_override();
        starts.push(tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(stagger_ms)).await;
            Engine::<SoloSigner>::start_pscan_sealing_run(
                arc_for_start,
                SealingRunOverrides {
                    observer: Box::new(observer),
                    dispatch_config: dispatch_override,
                },
            )
            .await
            .expect("start sealing-run pscan task")
        }));
    }
    let mut tasks: Vec<WalletTask> = Vec::with_capacity(WALLETS);
    for ((arc, tmp), start) in wallets.into_iter().zip(starts) {
        let handle = start.await.expect("staggered start task");
        tasks.push(WalletTask {
            arc,
            _tmp: tmp,
            handle,
            seeded_rounds: [1; PERSONAS_PER_WALLET],
        });
    }

    // Receipt-driven re-seeding (§19.8.2 posts row): round `j+1` is appended
    // after round `j`'s receipt arrives; the push is refused while round
    // `j`'s record is still live (terminal rejection pending), so we retry.
    let deadline = Instant::now() + RUN_DEADLINE;
    loop {
        // Miner health first: a dead generator freezes the chain, and every
        // receipt recorded after that violates the §19.8.2 chain row. The
        // task only ever ends by panicking (persistent RPC failure), so
        // `is_finished` is exactly "the chain stopped advancing".
        assert!(
            !miner.is_finished(),
            "{} run {run}: the background miner died — chain advancement lost; \
             the session is invalid",
            arm.label()
        );
        let mut all_done = true;
        for (wallet, (task, store)) in tasks.iter_mut().zip(&stores).enumerate() {
            for slot in 0..PERSONAS_PER_WALLET {
                let got = receipt_count(&sink, wallet, slot);
                let seeded = task.seeded_rounds[slot];
                assert!(
                    got <= seeded,
                    "wallet {wallet} slot {slot}: {got} receipts for {seeded} seeded posts — \
                     a resubmit re-emitted (non-terminal daemon verdict on synthetic bytes); \
                     the run is ungradeable"
                );
                if got < POSTS_PER_PERSONA {
                    all_done = false;
                }
                if got == seeded && seeded < POSTS_PER_PERSONA {
                    let round = seeded;
                    if try_seed(store, arm_tag, run, wallet, slot, round).await {
                        task.seeded_rounds[slot] += 1;
                    }
                }
            }
        }
        if all_done {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "{} run {run}: receipts incomplete after {}s — wedged run fails loudly",
            arm.label(),
            RUN_DEADLINE.as_secs()
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }

    // Wind down: cancel every task, then drop engines + tempdirs.
    for task in tasks {
        task.handle.shutdown().await;
        drop(task.arc);
    }

    let receipts = sink.lock().expect("receipt sink poisoned").clone();
    assert_eq!(
        receipts.len(),
        WALLETS * PERSONAS_PER_WALLET * POSTS_PER_PERSONA,
        "{} run {run}: receipt count mismatch",
        arm.label()
    );
    receipts
}

/// The sealing re-run session: pre-mine past the finality horizon, keep a
/// background generator advancing the chain, then the `R = 24` production
/// runs and the `R = 8` positive-control runs, sequentially, appending each
/// run's receipts to the artifact.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "WI-4 §19.8 sealing re-run; needs SHEKYLD_BIN + gf7-hooks; multi-hour by design"]
async fn gf7_sealing_run_writes_receipts_artifact() {
    let artifact = artifact_path();
    assert!(
        !artifact.exists(),
        "artifact {} already exists — move it aside; the grader must see one session only",
        artifact.display()
    );

    let daemon = RegtestDaemon::start().await;
    let miner_address = persona_address(&wallet_seed(0xff, 0, 0), 0);

    // Pre-mine once (≈ 30 min): past `tip − 720` every sweep does real fetch
    // work (§19.8.2 chain row).
    let premine_start = Instant::now();
    let mut mined = 0u64;
    while mined < PREMINE_BLOCKS {
        let batch = MINE_BATCH_BLOCKS.min(PREMINE_BLOCKS - mined);
        daemon.generate_blocks(batch, &miner_address).await;
        mined += batch;
    }
    eprintln!(
        "pre-mined {} blocks in {}s (height {})",
        mined,
        premine_start.elapsed().as_secs(),
        daemon.height().await
    );

    // Background generator: ~1 block / 30 s on an independent RPC client for
    // the whole session, so the finality horizon keeps advancing under the
    // production reorg depth. Transient RPC failures are tolerated up to
    // `MINER_MAX_CONSECUTIVE_FAILURES` (each logged); a persistent failure
    // panics the task, which the run loop's `is_finished` health check
    // converts into a loud session failure — a silently frozen chain must
    // never grade.
    let miner_rpc =
        shekyl_rpc_transport::HttpRpc::new(format!("http://127.0.0.1:{}", daemon.rpc_port()))
            .await
            .expect("miner rpc");
    let miner_addr_bg = miner_address.clone();
    let miner = tokio::spawn(async move {
        let mut consecutive_failures = 0u32;
        loop {
            tokio::time::sleep(BACKGROUND_MINE_INTERVAL).await;
            match try_generate_blocks(&miner_rpc, 1, &miner_addr_bg).await {
                Ok(_) => consecutive_failures = 0,
                Err(e) => {
                    consecutive_failures += 1;
                    eprintln!(
                        "background generateblocks failed \
                         ({consecutive_failures}/{MINER_MAX_CONSECUTIVE_FAILURES}): {e}"
                    );
                    assert!(
                        consecutive_failures <= MINER_MAX_CONSECUTIVE_FAILURES,
                        "background miner: {consecutive_failures} consecutive generateblocks \
                         failures (tolerance {MINER_MAX_CONSECUTIVE_FAILURES}) — \
                         chain advancement lost"
                    );
                }
            }
        }
    });

    // Both arms sequential (§19.8.2): the graded production rows, then the
    // §19.8.3 positive control. Label, seed domain, run count, and dispatch
    // override all ride the `Arm` value.
    for arm in [Arm::Production, Arm::PositiveControl] {
        for run in 0..arm.runs() {
            let started = Instant::now();
            let receipts = one_run(&daemon, arm, run, &miner).await;
            append_receipts(&artifact, &receipts);
            eprintln!(
                "{} run {}/{} done in {}s ({} receipts)",
                arm.label(),
                run + 1,
                arm.runs(),
                started.elapsed().as_secs(),
                receipts.len()
            );
        }
    }

    miner.abort();
    eprintln!(
        "sealing-run session complete; artifact at {} — grade with \
         `cargo run -p shekyl-staking-sim -- --gf7-seal={}`",
        artifact.display(),
        artifact.display()
    );
}
