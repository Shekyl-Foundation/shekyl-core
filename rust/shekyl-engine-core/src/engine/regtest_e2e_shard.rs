// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Closing a shard through the live daemon: the fill, the finality, and
//! the slash pass a compact join waits on.
//!
//! A `#[path]` child of the regtest harness. The production debug-macro
//! lint treats a file as test code only when the file itself carries this
//! attribute.

#![cfg(test)]

use super::*;

/// What [`close_shard_through_the_daemon`] left on the chain: the shard,
/// the block that closed it, and the slash pass that priced it — the
/// three post-genesis operands CEN-J15 reads for a compact join onto it.
#[derive(Clone, Copy, Debug)]
pub(super) struct ClosedShard {
    pub(super) shard: ShardId,
    /// The height whose fold first counted the shard closed — the coverage
    /// row's `freeze_height`, the block `closed_and_final` measures
    /// finality from.
    pub(super) close_height: u64,
    /// The settled epoch whose slash pass first found the shard final and
    /// so wrote its `r_market` row (`scenario_shard.rs`
    /// `first_pricing_epoch`, the same arithmetic).
    pub(super) priced_by_epoch: u64,
    /// The block that ran that pass. A join connecting above it reads the
    /// watermark at its parent; one block earlier the post is J15's.
    pub(super) pass_height: u64,
    /// The wallet spends the fill listed, and their archival bytes.
    pub(super) spends: usize,
    pub(super) archival_bytes: u64,
}

/// Close `shard` on the live daemon's chain and wait until a compact join
/// onto it is admissible: CEN-J15's three post-genesis operands
/// (`shekyl-chain-rules` `tx_bond.rs` `holding_admissible`), each read
/// back from the daemon rather than assumed.
///
/// 1. **Closed.** Ordinary wallet transfers — one-input self-sends of a
///    small fixed amount, about 13 KB of archival good each (the prunable
///    region and the hybrid auths, `Transaction::archival_len`) — are
///    built, submitted and mined [`FILL_SPENDS_PER_BLOCK`] at a time until
///    the chain's cumulative archival length passes `(shard + 1) · W`
///    (`SHARD_LENGTH`, 3 000 000 bytes). The wallet's own byte count only
///    decides when to stop building; the exit is the daemon's.
/// 2. **Final.** `reorg_cap` more blocks, after which the daemon's
///    `get_archival_shard_coverage` — `ClosedUniverse::final_before` at
///    the next connecting height, the predicate J15 applies at the
///    parent — lists the shard. That listing is the loop's exit, and its
///    `freeze_height` is held to the block the wallet's count crossed in.
/// 3. **Priced.** The slash pass of the first epoch whose deadline sits at
///    or above `close + reorg_cap + 1` (`SO-D11f`: a pass prices every
///    shard final as of its parent) writes the shard's `r_market` row.
///    The chain is mined through that pass — the block at the deadline
///    runs it (`scan_slashes`) — and the coverage reply's watermark is
///    held to the epoch. Under the production grace
///    (`SLASH_GRACE_EPOCHS = 1`) the pass of epoch `w` is the last block
///    of epoch `w + 1`, so the earliest join lands in epoch `w + 2`: a
///    walk that shortens its epoch to make this cheap must still expect
///    its bond two epochs after the pricing epoch, never one.
///
/// This is `shekyl-chain-ingest`'s `close_shards` through the daemon's
/// front door: the ingest harness drives the connector in-process with a
/// spender over fixture coinbases; here every spend is a production wallet
/// transfer over RPC and every block the daemon's own template. `W` is the
/// production constant and nothing here is a lever, so the cost is a few
/// hundred real proofs — minutes in a debug build — which is why every
/// caller sits in `scripts/ci/run_live_daemon_gates.sh`'s slow lane.
///
/// **The spender is the caller's staker wallet, opened before the fill.**
/// The retention prune (`shekyl-chain-store` `prune.rs`, S-PRUNE)
/// discards a closed shard's bodies — the prunable regions and the hybrid
/// auths, the archival good itself — at the epoch boundary two epochs
/// after the shard's close epoch, `(close_epoch + 2) · SEB`, and this
/// node then answers `/get_transactions` for them as `archived` in the
/// full form and as a skeleton under `prune` (`SB-Q2`). Until the wallet
/// fetches with `prune` and binds the skeleton (`SB-Q2` item 8), a wallet
/// opened after that cannot scan the fill from this node: its refresh is
/// refused at the first fill block (observed 2026-10-29 under a two-block
/// epoch), and the P-scan reads full bodies (SP-6). So the wallet that
/// will stake is the wallet that fills: its refresh follows the fill
/// block by block, and once the shard is closed the helper runs its
/// P-scan over the fill before mining on — the chain stands still while
/// it scans — so every later P-scan resumes from that seal. The schedule
/// must leave the P-scan's finality lag ([`PSCAN_TEST_REORG_DEPTH`])
/// between the close and that boundary; the helper refuses one that does
/// not. Runs first on an otherwise empty chain: the byte count assumes
/// the coinbases, which carry no archival good, are all that came before,
/// and the daemon's `--mine-address` is the wallet's primary address, so
/// its coinbases are the supply.
pub(super) async fn close_shard_through_the_daemon(
    daemon: &RegtestDaemon,
    arc: &Arc<RwLock<super::super::Engine<super::super::SoloSigner>>>,
    address: &str,
    pscan_seal: &std::path::Path,
    shard: ShardId,
    schedule: RegtestSchedule,
) -> ClosedShard {
    use super::super::pending::{FeePriority, TxDestination, TxRecipient, TxRequest};
    use shekyl_archival_retention::{SettlementEpochBlocks, SettlementSchedule};
    use shekyl_types::archival::SHARD_LENGTH;
    use shekyl_units::AtomicUnits;
    use shekyl_wire::Transaction;

    /// Spends listed per fill block: sixteen one-input spends sit near
    /// 230 KB, under the 300 000-byte full-reward zone with room for the
    /// coinbase (`scenario_shard.rs` `SPENDS_PER_BLOCK`, the same figure).
    const FILL_SPENDS_PER_BLOCK: usize = 16;
    const MINE_BATCH_BLOCKS: u64 = 10;
    const MAX_MINE_BATCHES: usize = 24;
    /// Retries of one spend's build past the wallet's not-yet-spendable
    /// and not-enough-unlocked refusals, each after a batch of blocks.
    const MAX_BUILD_RETRIES: usize = 24;

    let started = Instant::now();
    let w = SHARD_LENGTH.to_raw();
    let target_bytes = shard
        .to_raw()
        .checked_add(1)
        .and_then(|k| k.checked_mul(w))
        .expect("a test shard's end fits a u64");
    let request = TxRequest {
        recipients: vec![TxRecipient {
            destination: TxDestination::Address(address.to_owned()),
            amount_atomic_units: AtomicUnits::from_raw(1_000_000),
            rid: None,
        }],
        priority: FeePriority::Standard,
    };

    // Build one spend, retrying past the wallet's readiness ladder (the
    // reference-spendability gate and the unlocked supply), and return
    // its sealed pending with its archival length.
    async fn build_fill_spend(
        daemon: &RegtestDaemon,
        arc: &Arc<RwLock<super::super::Engine<super::super::SoloSigner>>>,
        request: &TxRequest,
        n: usize,
    ) -> (super::super::pending::PendingTx, u64) {
        for _ in 0..MAX_BUILD_RETRIES {
            let attempt = {
                let g = arc.read().await;
                g.build_pending_tx_async(request).await
            };
            match attempt {
                Ok(pending) => {
                    let len = Transaction::from_bytes(&pending.tx_bytes)
                        .expect("a built spend parses")
                        .archival_len()
                        .to_raw();
                    return (pending, len);
                }
                Err(
                    e @ (super::super::error::SendError::OutputNotYetSpendable { .. }
                    | super::super::error::SendError::InsufficientFunds { .. }),
                ) => {
                    eprintln!("shard fill spend {n}: {e}; mining more");
                    daemon.generate_blocks(MINE_BATCH_BLOCKS).await;
                    refresh(arc).await;
                }
                Err(e) => daemon.panic_with_log("build shard-fill spend", format!("{e:?}")),
            }
        }
        panic!("shard fill spend {n} never built within {MAX_BUILD_RETRIES} retries");
    }

    // The first coinbase spendable, then a sample spend sizes the fill: the
    // wallet takes one input per small spend, so the supply is one matured
    // coinbase per spend, mined ahead now because empty blocks are cheap
    // and proofs are not. The sample is submitted, not dropped — it is the
    // fill's first spend.
    mine_until_spendable(daemon, arc, MINE_BATCH_BLOCKS, MAX_MINE_BATCHES).await;
    let (first, per_spend) = build_fill_spend(daemon, arc, &request, 0).await;
    assert!(per_spend > 0, "a wallet spend carries archival good");
    let spends_needed = target_bytes.div_ceil(per_spend) + 1;
    eprintln!(
        "shard fill: {per_spend} archival bytes per spend; about {spends_needed} spends close \
         shard {} (W = {w}); tip {}",
        shard.to_raw(),
        daemon.height().await,
    );
    submit_built(arc, &first, "shard-fill spend 0").await;
    let mut spends = 1usize;
    let mut archival_bytes = per_spend;
    let supply_ahead = spends_needed + 2 * u64::try_from(FILL_SPENDS_PER_BLOCK).expect("fits");
    daemon.generate_blocks(supply_ahead).await;
    refresh(arc).await;
    eprintln!(
        "shard fill: supply mined ahead ({supply_ahead} blocks), tip {}, {:?} elapsed",
        daemon.height().await,
        started.elapsed()
    );

    // The fill. Build while the wallet's byte count is short of the
    // shard's end, then mine empty blocks for finality; the exit is the
    // daemon listing the shard.
    let cap = schedule.reorg_cap;
    let max_blocks = spends_needed / u64::try_from(FILL_SPENDS_PER_BLOCK).expect("fits") + cap + 64;
    let mut crossed_in: Option<u64> = None;
    let mut blocks = 0u64;
    let listed = loop {
        let coverage = daemon.shard_coverage().await;
        if coverage
            .shards
            .iter()
            .any(|row| row.shard_id == shard.to_raw())
        {
            break coverage;
        }
        assert!(
            blocks < max_blocks,
            "shard {} never listed final after {blocks} fill blocks ({spends} spends, \
             {archival_bytes}/{target_bytes} archival bytes; coverage as of {} lists {} \
             final shard(s), crossed in {crossed_in:?})",
            shard.to_raw(),
            coverage.as_of_height,
            coverage.frozen_count,
        );
        if archival_bytes < target_bytes {
            for _ in 0..FILL_SPENDS_PER_BLOCK {
                let (pending, len) = build_fill_spend(daemon, arc, &request, spends).await;
                submit_built(arc, &pending, "a shard-fill spend").await;
                spends += 1;
                archival_bytes += len;
            }
            let before = daemon.height().await;
            mine_until_pool_drains(daemon, "a shard-fill batch", 1).await;
            refresh(arc).await;
            let after = daemon.height().await;
            if archival_bytes >= target_bytes && crossed_in.is_none() {
                // One block drained the batch: the crossing spend is in
                // it, and that is the height the daemon's fold closes the
                // shard at. More than one, and the crossing block is one
                // of them; the height check below then only bounds.
                crossed_in = Some(after - 1);
                eprintln!(
                    "shard fill: the wallet's byte count crossed {target_bytes} in the batch \
                     mined over {}..{} ({spends} spends); mining {cap} blocks for finality",
                    before,
                    after - 1
                );
                if after - before != 1 {
                    crossed_in = Some(u64::MAX);
                }
            }
        } else {
            daemon.generate_blocks(1).await;
        }
        blocks += 1;
        if let Some(crossed) = crossed_in.filter(|c| *c != u64::MAX) {
            let tip = daemon.height().await;
            assert!(
                tip <= crossed + cap + 8,
                "the wallet's byte count closed shard {} at {crossed} but the daemon lists {} \
                 final shard(s) at tip {tip}, {cap} + 8 blocks later: the fold and \
                 `Transaction::archival_len` disagree",
                shard.to_raw(),
                coverage.frozen_count,
            );
        }
        if blocks.is_multiple_of(4) {
            eprintln!(
                "shard fill: tip {}, {spends} spends, {archival_bytes}/{target_bytes} archival \
                 bytes, {} final shard(s), {:?} elapsed",
                daemon.height().await,
                coverage.frozen_count,
                started.elapsed()
            );
        }
    };
    let row = listed
        .shards
        .iter()
        .find(|row| row.shard_id == shard.to_raw())
        .expect("the loop exited on the listing");
    let close_height = row.freeze_height;
    if let Some(crossed) = crossed_in.filter(|c| *c != u64::MAX) {
        assert_eq!(
            close_height,
            crossed,
            "the daemon closed shard {} at {close_height}; the wallet's archival byte count \
             crossed its end in the block at {crossed}",
            shard.to_raw()
        );
    }
    eprintln!(
        "shard {} closed at {close_height} and final as of {} ({spends} spends, {archival_bytes} \
         archival bytes, {blocks} fill blocks, {:?} elapsed)",
        shard.to_raw(),
        listed.as_of_height,
        started.elapsed()
    );

    // The staker wallet's P-scan covers the fill now, ahead of the
    // retention prune (doc comment): the scan frontier trails the tip by
    // the test horizon, so the tip is first raised just far enough for the
    // close block to sit inside it, and that tip must still be below the
    // boundary whose connect discards the shard.
    let sched = SettlementSchedule::new(
        SettlementEpochBlocks::new(schedule.seb).expect("a schedule's epoch is non-zero"),
    );
    let prune_boundary = sched.open_height(sched.epoch_at_height(close_height) + 2);
    let scan_tip = close_height + PSCAN_TEST_REORG_DEPTH + 1;
    assert!(
        scan_tip < prune_boundary,
        "the P-scan needs the tip at {scan_tip} to cover the close block {close_height}, but \
         the boundary at {prune_boundary} discards shard {}'s bodies first: an epoch of {} is \
         too short for the scan's finality lag; raise SEB",
        shard.to_raw(),
        schedule.seb
    );
    let count = daemon.height().await;
    if count <= scan_tip {
        daemon.generate_blocks(scan_tip + 1 - count).await;
    }
    refresh(arc).await;
    let scanned = pscan_until_within(
        arc,
        pscan_seal,
        "the shard fill, ahead of the retention prune",
        |s| s.synced_height().to_raw() > close_height,
        Duration::from_secs(1800),
    )
    .await;
    eprintln!(
        "P-scan covered the fill: frontier {} past the close block {close_height}, tip {}, \
         prune boundary {prune_boundary} ({:?} elapsed)",
        scanned.synced_height(),
        daemon.height().await,
        started.elapsed()
    );

    // Priced: the first pass whose parent sees the shard final, then the
    // watermark read back. The block at the deadline runs the pass
    // (`scan_slashes`: the count after it exceeds the deadline), so the
    // chain count must exceed the deadline.
    let final_for_a_pass_at = close_height + cap + 1;
    let priced_by_epoch = (0u64..)
        .find(|&e| sched.slash_deadline_height(e) >= final_for_a_pass_at)
        .expect("a test chain's epochs are small");
    let pass_height = sched.slash_deadline_height(priced_by_epoch);
    let count = daemon.height().await;
    if count <= pass_height {
        daemon.generate_blocks(pass_height + 1 - count).await;
    }
    let mut watermark_seen = None;
    for _ in 0..8 {
        let coverage = daemon.shard_coverage().await;
        // The wire's epoch is 0 both before any pass and after the pass
        // of epoch 0; the settled epoch's budget row exists only after a
        // pass (the close writes it; the emission walk pins it positive).
        let watermark = (coverage.settled_epoch > 0 || coverage.budget_atomic > 0)
            .then_some(coverage.settled_epoch);
        watermark_seen = Some((coverage.as_of_height, watermark, coverage.budget_atomic));
        if watermark.is_some_and(|settled| settled >= priced_by_epoch) {
            break;
        }
        daemon.generate_blocks(1).await;
    }
    let (as_of, watermark, budget) = watermark_seen.expect("read at least once");
    assert!(
        watermark.is_some_and(|settled| settled >= priced_by_epoch),
        "the slash pass of epoch {priced_by_epoch} (the block at {pass_height}) must have \
         priced shard {} (closed {close_height}, final from {final_for_a_pass_at}); the \
         coverage as of {as_of} reports watermark {watermark:?}, budget {budget}",
        shard.to_raw()
    );
    eprintln!(
        "shard {} priced: settled epoch {watermark:?} ≥ {priced_by_epoch} (pass at \
         {pass_height}); tip {}; a compact join is admissible from here ({:?} elapsed)",
        shard.to_raw(),
        daemon.height().await,
        started.elapsed()
    );
    ClosedShard {
        shard,
        close_height,
        priced_by_epoch,
        pass_height,
        spends,
        archival_bytes,
    }
}
