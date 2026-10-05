// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The datadir schedule pin: blocks per archival settlement epoch, as the
//! file was built under (S-CHAIN-W SCW-2; C++ `set_settlement_epoch_blocks_pin`,
//! `db_lmdb.cpp`, and the `Blockchain::init` check that consumed it).
//!
//! Persisted epoch-derived state — bond join epochs, serve-credit windows —
//! is only meaningful under the schedule it was written with. The C++ pinned
//! the schedule on FAKECHAIN only, because that is the one network where the
//! lever (`SHEKYL_SETTLEMENT_EPOCH_BLOCKS`) can move it; here the pin is
//! written on every network (rule 71: the store sees a datum, never a
//! nettype), which on a public network is a constant matching a constant.
//! What the store owns is **record at create, compare at open, refuse
//! loudly on mismatch** — the same shape as `schema_version` — and, since
//! DRS-E4 `ARW-15` put the schedule on the rule set, **compare at every
//! connect** against the set in force (`Horizons::check_against`). Which
//! value is in force is the rule set's (`RuleSet::settlement_schedule`);
//! the store never reads the environment.
//!
//! The type is `shekyl_types::archival::SettlementEpochBlocks` — the rule
//! set carries it and the retention crate computes with it, so it lives
//! where all three readers reach (rule 18) — and its codec is
//! `shekyl-store-codec`'s (`vocabulary.rs`), where every impl of the
//! foreign [`Canonical`](super::Canonical) trait on a foreign type has to
//! be. This module is the pin's **meaning** for this store; the cell it
//! fills is [`SettlementEpochBlocksCell`](super::SettlementEpochBlocksCell).
//! `0` is not a schedule: the C++ used it as "unpinned", and a file this
//! crate wrote is never unpinned, so a zero cell is corruption (SI-7), not
//! a state — the type cannot spell it, and the decode refuses it.

pub use shekyl_types::archival::SettlementEpochBlocks;

#[cfg(test)]
mod tests {
    use super::super::{Canonical, CodecError};
    use super::*;

    /// The pin's fixed width as this store's header reads it: exactly one
    /// encoding, or a `CodecError` (the snapshot fixture pins the bytes).
    #[test]
    fn the_pin_round_trips_and_refuses_wrong_widths() {
        let pin = SettlementEpochBlocks::new(10_000).expect("non-zero");
        assert_eq!(SettlementEpochBlocks::decode(&pin.encode()), Ok(pin));
        assert_eq!(pin.to_string(), "10000 blocks/epoch");
        assert_eq!(SettlementEpochBlocks::new(0), None);
        assert_eq!(
            SettlementEpochBlocks::decode(&[1, 0]),
            Err(CodecError::Length {
                codec: "settlement_epoch_blocks",
                expected: 8,
                actual: 2,
            })
        );
    }
}
