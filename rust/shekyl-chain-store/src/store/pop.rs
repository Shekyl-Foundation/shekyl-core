// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `pop`: remove the tip by replaying its undo row in reverse (S-CHAIN-W
//! commit 7; `DRS_E1_SCHAIN_W.md` §3.3, §5; C2-R8 Q5).
//!
//! The port of `BlockchainDB::pop_block` (`blockchain_db.cpp:724`), which
//! walked five journals with three height bases and a revert function
//! each. Here there is one row per connected height and no per-surface
//! code: the store does not know what a block wrote, only that every write
//! recorded its pre-image, and replay undoes them last-first. The E3 / E4
//! hooks owe nothing on this side — what their connect phases write, their
//! connect phases journal.
//!
//! # The floor
//!
//! A height is poppable **iff** its `undo_log` row exists (§5.4, SCW-7).
//! Genesis is never poppable — `pop` refuses `tip == 0` before consulting
//! the journal — and until the retention prune (S-PRUNE) lands nothing
//! deletes undo rows, so the floor is `1` and
//! [`StoreCannot::PopBelowFloor`] is reachable only at genesis. When the
//! prune arrives it inherits the constraint recorded on its DRS §7 row:
//! undo-log retention ≥ `D_max` (PDM-Q11), or a legal reorg returns this
//! refusal — a capability limit, loud, never a verdict.
//!
//! # SI-6
//!
//! The undo log's top row must be the tip's. A top row at another height
//! means the journal stopped describing the tables — something wrote
//! around it — and no pop can be trusted to land on a coherent state:
//! [`StoreInvariant::UndoLogIncoherent`] with
//! [`UndoFault::TopIsNotTip`](super::UndoFault::TopIsNotTip), poisoning the
//! batch, and the writer halts (§3.6.2).

use shekyl_types::BlockHeight;

use crate::schema::{BLOCK_INFO, UNDO_LOG};

use super::error::{StoreCannot, StoreError, StoreInvariant, UndoFault};
use super::undo::Replayed;
use super::write::WriteBatch;

/// What `pop` removed. The block itself is read through the view **before**
/// popping, as the reorg already does for the witness (audit R-5); the
/// store hands nothing consensus-visible back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Popped {
    /// The height that was the tip.
    pub height: BlockHeight,
    /// Undo entries reversed.
    pub reversed: usize,
}

impl WriteBatch<'_, '_> {
    /// Remove the tip by replaying its undo row in reverse.
    ///
    /// May be called repeatedly on one batch (a reorg pops several); each
    /// call consumes exactly the tip's row and leaves the previous block
    /// as the tip.
    ///
    /// # Errors
    ///
    /// [`StoreCannot::ChainEmpty`] with no block recorded;
    /// [`StoreCannot::PopBelowFloor`] at genesis — the only floor that
    /// exists until S-PRUNE lands and **persists** the one it establishes
    /// (S-CHAIN-W §5.4): nothing deletes undo rows today, so a recorded tip
    /// with no journal row is a journal that does not describe its tables,
    /// [`StoreInvariant::UndoLogIncoherent`] (SI-6, poisons), never a
    /// retention limit the store cannot have reached;
    /// [`StoreInvariant::UndoLogIncoherent`] also if the journal's top row
    /// is not the tip's or an entry cannot be reversed;
    /// [`StoreInvariant::CellCorrupt`] (SI-7, poisons) if the row does not
    /// decode; engine errors.
    pub fn pop(&self) -> Result<Popped, StoreError> {
        let tip = {
            let info = self.open_insert_table(BLOCK_INFO, StoreInvariant::TipMismatch)?;
            let last = info.last()?.map(|(h, _)| h.value());
            last
        };
        let Some(tip) = tip else {
            return Err(StoreCannot::ChainEmpty.into());
        };
        self.journal().note_height(tip);
        if tip == 0 {
            return Err(StoreCannot::PopBelowFloor { tip, floor: 1 }.into());
        }
        let top = {
            let undo = self.open_insert_table(
                UNDO_LOG,
                StoreInvariant::UndoLogIncoherent {
                    height: tip,
                    fault: UndoFault::RowAlreadyRecorded,
                },
            )?;
            let top = undo.last()?.map(|(h, _)| h.value());
            top
        };
        match top {
            // A block is recorded at `tip` and the journal has no row at
            // all. Nothing deletes undo rows until S-PRUNE lands, and when
            // it does it persists the floor it establishes (§5.4) so this
            // arm can tell "pruned below" from "lost"; until then this is a
            // journal that does not describe its tables — SI-6, not a
            // retention limit the store cannot have reached (PR #757
            // review).
            None => {
                return Err(self.poison().arm(StoreInvariant::UndoLogIncoherent {
                    height: tip,
                    fault: UndoFault::NoRowForTip,
                }));
            }
            Some(top) if top != tip => {
                return Err(self.poison().arm(StoreInvariant::UndoLogIncoherent {
                    height: tip,
                    fault: UndoFault::TopIsNotTip { top },
                }));
            }
            Some(_) => {}
        }
        // The tip's row was seen above; the only way replay finds no row is
        // a journal that lost the tip between the check and here —
        // impossible inside one transaction, and named rather than assumed.
        match self.replay_undo(tip)? {
            Replayed::Entries(reversed) => Ok(Popped {
                height: BlockHeight::from_raw(tip),
                reversed,
            }),
            Replayed::NoRow => Err(self.poison().arm(StoreInvariant::UndoLogIncoherent {
                height: tip,
                fault: UndoFault::NoRowForTip,
            })),
        }
    }
}
