// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The connector's point reads.
//!
//! [`HashAt`], [`HeaderAt`], [`RootAt`], [`BondRecordOf`] and
//! [`BudgetAccruingOf`] answer from the open reader, including after a
//! halt. [`ObserveTarget`] holds a source's claimed height to the height
//! the next block connects at and asks the rules for that height's
//! target. A consistent refusal is an empty reply. A hole halts the writer.

use super::*;

impl Message<HashAt> for Connector {
    type Reply = Result<Option<BlockHash>, RunFault>;

    async fn handle(&mut self, msg: HashAt, _ctx: &mut Context<Self, Self::Reply>) -> Self::Reply {
        Ok(match self.writer.read()?.block_info(msg.height)? {
            AtHeight::Recorded(info) => Some(info.hash),
            AtHeight::AboveTip => None,
        })
    }
}

impl Message<ObserveTarget> for Connector {
    type Reply = Result<(), RunFault>;

    async fn handle(
        &mut self,
        msg: ObserveTarget,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let rule_set = self.rules.in_force(msg.height);
        self.writer.write(|batch| {
            let view = batch.chain_view();
            let (height, _) = connecting(view.tip()?)?;
            if msg.height != height {
                return Err(RunFault::HeightClaim {
                    claimed: msg.height,
                    connecting: height,
                });
            }
            let observed = match shekyl_chain_rules::target_claim(&view, height, &rule_set) {
                // CEN-D6 is a verdict on a consistent window, not a fault.
                Ok(Err(_refused)) => return Ok(()),
                Ok(Ok(target)) => {
                    shekyl_chain_rules::cumulative_difficulty_after(&view, height, target)
                        .map(|_work| ())
                }
                Err(fault) => Err(fault),
            };
            match observed {
                Ok(()) => Ok(()),
                Err(Fault::View(e)) => Err(RunFault::Store(e)),
                Err(Fault::Corrupt(corrupt)) => Err(RunFault::Store(batch.refuse_corrupt(corrupt))),
                Err(Fault::Stale(stale)) => unreachable!("a derivation is never stale: {stale}"),
            }
        })
    }
}

impl Message<HeaderAt> for Connector {
    type Reply = Result<Option<HeaderRecord>, RunFault>;

    async fn handle(
        &mut self,
        msg: HeaderAt,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let read = self.writer.read()?;
        let AtHeight::Recorded(info) = read.block_info(msg.height)? else {
            return Ok(None);
        };
        let AtHeight::Recorded(body) = read.block(msg.height)? else {
            return Ok(None);
        };
        Ok(Some(HeaderRecord {
            hash: info.hash,
            header: body.block.header,
            cumulative_difficulty: info.cumulative_difficulty,
        }))
    }
}

impl Message<RootAt> for Connector {
    type Reply = Result<Option<CurveTreeRoot>, RunFault>;

    async fn handle(&mut self, msg: RootAt, _ctx: &mut Context<Self, Self::Reply>) -> Self::Reply {
        Ok(match self.writer.read()?.root_at(msg.height)? {
            AtHeight::Recorded(root) => Some(root),
            AtHeight::AboveTip => None,
        })
    }
}

impl Message<BondRecordOf> for Connector {
    type Reply = Result<Option<BondRecord>, RunFault>;

    async fn handle(
        &mut self,
        msg: BondRecordOf,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Ok(self.writer.read()?.bond_record(&msg.persona)?)
    }
}

impl Message<BudgetAccruingOf> for Connector {
    type Reply = Result<Option<AtomicUnits>, RunFault>;

    async fn handle(
        &mut self,
        msg: BudgetAccruingOf,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Ok(self.writer.read()?.budget_accruing(msg.epoch)?)
    }
}
