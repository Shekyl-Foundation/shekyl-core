// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#![no_main]

use libfuzzer_sys::fuzz_target;
use shekyl_wire::tx_extra;

// The `tx_extra` grammar under arbitrary bytes (TX_EXTRA_RUST_CUTOVER.md
// TXE-Q5b). Successor of the C++ `tests/fuzz/tx-extra.cpp`, whose oracle
// was "doesn't crash" and survives the parser's removal intact; seeded from
// its corpus. Two properties beyond not-crashing, because they are the
// codec's contract and cheap to state: whatever parses re-serializes to the
// same bytes (the round trip the daemon relies on), and the shape rules are
// total over any parse (they never panic, whatever the field multiset).
fuzz_target!(|data: &[u8]| {
    let Ok(fields) = tx_extra::parse(data) else {
        return;
    };
    let again = tx_extra::serialize(&fields).expect("a parsed extra re-serializes");
    assert_eq!(again, data, "parse → serialize must be the identity");
    // The output count is not in the extra; try a few, including the
    // leafless case, and both admission arms.
    for n in [0usize, 1, 2, 3] {
        let _ = tx_extra::check_tx_extra_shape(&fields, n, tx_extra::ExtraSubject::Coinbase);
        let _ = tx_extra::check_tx_extra_shape(&fields, n, tx_extra::ExtraSubject::General);
    }
});
