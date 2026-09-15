// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use super::*;

#[test]
fn rehome_replaces_only_the_lone_slot() {
    let into = TxSlot::Listed(3);
    assert_eq!(
        Locus::Tx { slot: TxSlot::Lone }.rehome(into),
        Locus::Tx { slot: into }
    );
    assert_eq!(
        Locus::Input {
            slot: TxSlot::Lone,
            input: 7
        }
        .rehome(into),
        Locus::Input {
            slot: into,
            input: 7
        }
    );
    // Already-homed loci and the block locus are untouched.
    for fixed in [
        Locus::Block,
        Locus::Tx {
            slot: TxSlot::Miner,
        },
        Locus::Input {
            slot: TxSlot::Listed(0),
            input: 1,
        },
    ] {
        assert_eq!(fixed.rehome(into), fixed);
    }
}

#[test]
fn display_names_the_row_and_the_place() {
    let refused = InvalidBlock {
        rule: CenRow::C1,
        locus: Locus::Block,
    };
    assert_eq!(refused.to_string(), "CEN-C1 refused at block");

    let refused = InvalidBlock {
        rule: CenRow::I3,
        locus: Locus::Input {
            slot: TxSlot::Listed(2),
            input: 0,
        },
    };
    assert_eq!(refused.to_string(), "CEN-I3 refused at tx #2 input #0");

    let refused = InvalidBlock {
        rule: CenRow::F1,
        locus: Locus::Tx {
            slot: TxSlot::Miner,
        },
    };
    assert_eq!(refused.to_string(), "CEN-F1 refused at miner tx");

    let refused = InvalidBlock {
        rule: CenRow::H1,
        locus: Locus::Tx { slot: TxSlot::Lone },
    };
    assert_eq!(refused.to_string(), "CEN-H1 refused at tx");
}

#[test]
fn invalid_block_is_an_error_with_no_source() {
    let refused: Box<dyn std::error::Error> = Box::new(InvalidBlock {
        rule: CenRow::A1,
        locus: Locus::Block,
    });
    assert!(refused.source().is_none());
}
