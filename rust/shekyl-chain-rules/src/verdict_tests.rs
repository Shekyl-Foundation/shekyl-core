// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use super::*;

#[test]
fn display_names_the_row_and_the_place() {
    let refused = InvalidBlock::new(CenRow::C1, Locus::Block);
    assert_eq!(refused.to_string(), "CEN-C1 refused at block");

    let refused = InvalidBlock::new(
        CenRow::I3,
        Locus::Input {
            slot: TxSlot::Listed(2),
            input: 0,
        },
    );
    assert_eq!(refused.to_string(), "CEN-I3 refused at tx #2 input #0");

    let refused = InvalidBlock::new(
        CenRow::F1,
        Locus::Tx {
            slot: TxSlot::Miner,
        },
    );
    assert_eq!(refused.to_string(), "CEN-F1 refused at miner tx");

    let refused = InvalidBlock::new(CenRow::H1, Locus::Tx { slot: TxSlot::Lone });
    assert_eq!(refused.to_string(), "CEN-H1 refused at tx");
}

#[test]
fn invalid_block_is_an_error_with_no_source() {
    let refused: Box<dyn std::error::Error> = Box::new(InvalidBlock::new(CenRow::A1, Locus::Block));
    assert!(refused.source().is_none());
}

/// The token's `Debug` does not require `V: Debug`. A `derive` would, and
/// the store's view type has no reason to be `Debug`; this pins the
/// hand-written impl against a future re-derive.
#[test]
fn chain_valid_debug_needs_no_debug_view() {
    struct Undebuggable;
    fn is_debug<T: core::fmt::Debug>() {}
    is_debug::<ChainValid<'static, Undebuggable>>();
}
