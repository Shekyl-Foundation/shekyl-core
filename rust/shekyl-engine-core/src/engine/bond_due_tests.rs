// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What each failure at the due block does to a plan
//! (`ARCHIVAL_BOND_POST_DELAY.md` §3.6, the fill-failure table): ends it at
//! once, holds it to its maximum wait, or retries it with no limit.

use shekyl_types::{BlockHeight, ShardId};

use super::DueBlock;
use crate::engine::bond_assembly::BondAssemblyError;
use crate::engine::holdings_fill::{CompleteTreeFillError, FillFailure, MarketFillError};
use crate::engine::pscan::dispatch::PlanAttempt;
use crate::engine::stake_engine::StakeEngineError;
use shekyl_engine_state::PlanWait;

fn attempt(block: DueBlock) -> PlanAttempt {
    block.into_attempt()
}

fn shard() -> ShardId {
    ShardId::from_raw(7)
}

/// The complete-tree fill, every arm.
#[test]
fn every_fill_failure_maps_to_its_class() {
    let detail = || "x".to_owned();
    let cases: Vec<(CompleteTreeFillError, PlanAttempt)> = vec![
        (
            CompleteTreeFillError::ScanBehind {
                scanned: BlockHeight::from_raw(1),
                needed: BlockHeight::from_raw(2),
            },
            PlanAttempt::Wait(PlanWait::WalletBehind),
        ),
        (
            FillFailure::Discarded { shard: shard() }.into(),
            PlanAttempt::Unbondable,
        ),
        (
            FillFailure::LocalNodeRequired { detail: detail() }.into(),
            PlanAttempt::Wait(PlanWait::NodeNotLocal),
        ),
        (
            FillFailure::DaemonSyncing.into(),
            PlanAttempt::Wait(PlanWait::NodeSyncing),
        ),
        (
            FillFailure::DaemonUnreachable { detail: detail() }.into(),
            PlanAttempt::Wait(PlanWait::NodeUnreachable),
        ),
        (
            FillFailure::ScanStateUnreadable { detail: detail() }.into(),
            PlanAttempt::Wait(PlanWait::WalletBehind),
        ),
        (
            FillFailure::DaemonMismatch {
                shard: shard(),
                detail: detail(),
            }
            .into(),
            PlanAttempt::Wait(PlanWait::NodeMismatch),
        ),
        (
            FillFailure::StoreFailed {
                shard: shard(),
                detail: detail(),
            }
            .into(),
            PlanAttempt::Wait(PlanWait::StoreFailed),
        ),
    ];
    for (failure, expected) in cases {
        let rendered = format!("{failure}");
        assert_eq!(
            attempt(DueBlock::from_fill(failure)),
            expected,
            "{rendered}"
        );
    }
}

/// The classes the ruling asked for: only the discarded bodies end a plan at
/// once; a node that is not local, disagrees with the scan, or a store that
/// cannot write are limited; the rest never limit the wait.
#[test]
fn only_limited_reasons_count_toward_the_maximum() {
    for (wait, limited) in [
        (PlanWait::NodeUnreachable, false),
        (PlanWait::NodeSyncing, false),
        (PlanWait::WalletBehind, false),
        (PlanWait::FeeAboveFunding, true),
        (PlanWait::NodeNotLocal, true),
        (PlanWait::NodeMismatch, true),
        (PlanWait::StoreFailed, true),
        (PlanWait::AssemblyFailed, true),
    ] {
        assert_eq!(wait.is_limited(), limited, "{wait:?}");
    }
}

/// The market fill: a named shard the scan has not reached waits; one not
/// final is limited; the shared failures map as the complete tree's.
#[test]
fn every_market_fill_failure_maps_to_its_class() {
    for (failure, expected) in [
        (
            MarketFillError::ScanBehind { shard: shard() },
            PlanAttempt::Wait(PlanWait::WalletBehind),
        ),
        (
            MarketFillError::NotFinal { shard: shard() },
            PlanAttempt::Wait(PlanWait::AssemblyFailed),
        ),
        (
            MarketFillError::Fill(FillFailure::Discarded { shard: shard() }),
            PlanAttempt::Unbondable,
        ),
    ] {
        let rendered = format!("{failure}");
        assert_eq!(
            attempt(DueBlock::from_market_fill(failure)),
            expected,
            "{rendered}"
        );
    }
}

/// The sweep and the actor: funding short of the bond plus the live fee is
/// the fee case; a tree behind is temporary; anything else is the limited
/// assembly failure, so a plan that can never be assembled ends.
#[test]
fn sweep_and_assembly_failures_map_to_their_class() {
    let short = || BondAssemblyError::InsufficientFunding {
        available: 1,
        required: 2,
    };
    assert_eq!(
        attempt(DueBlock::from_sweep(short())),
        PlanAttempt::Wait(PlanWait::FeeAboveFunding)
    );
    assert_eq!(
        attempt(DueBlock::from_sweep(
            BondAssemblyError::ReferenceResyncing { detail: "behind" }
        )),
        PlanAttempt::Wait(PlanWait::WalletBehind)
    );
    assert_eq!(
        attempt(DueBlock::from_sweep(BondAssemblyError::BondFloorZero)),
        PlanAttempt::Wait(PlanWait::AssemblyFailed)
    );
    assert_eq!(
        attempt(DueBlock::from_engine(StakeEngineError::Assembly(short()))),
        PlanAttempt::Wait(PlanWait::FeeAboveFunding)
    );
    assert_eq!(
        attempt(DueBlock::from_engine(StakeEngineError::Assembly(
            BondAssemblyError::OutputNotYetDrained { gindex: 3 }
        ))),
        PlanAttempt::Wait(PlanWait::WalletBehind)
    );
    assert_eq!(
        attempt(DueBlock::from_engine(StakeEngineError::StaleHandle)),
        PlanAttempt::Wait(PlanWait::AssemblyFailed)
    );
}
