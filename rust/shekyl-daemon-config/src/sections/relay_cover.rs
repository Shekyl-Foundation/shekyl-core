// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The cover opt-out and the upload floor it sets (`CVR-R1`, `CVR-R5`).

use shekyl_options::{Code, Value};
use shekyl_relay_privacy::params::carrier;

use super::tests::build_from;

/// Cover is on unless the operator opts out, and with it on an upload limit
/// below the upload floor refuses the start (`CVR-R1`, `CVR-R5`; Rick,
/// 2026-11-19). The floor is twice the cover budget, a stated rule. The
/// refusal names the row, the floor, the budget, and the way out. With
/// `relay-cover off` the same limit builds.
///
/// Red edits: drop the floor from `read_rates` (the low limit builds), or
/// apply it with cover off (the opted-out node is refused).
#[test]
fn an_upload_limit_below_the_upload_floor_is_refused_while_cover_is_on() {
    let on = build_from(&[], "").expect("the defaults build");
    assert!(on.p2p.relay_cover, "cover is on by default");
    let off = build_from(&["--relay-cover", "off"], "").expect("the opt-out builds");
    assert!(!off.p2p.relay_cover);

    let low = build_from(&["--p2p-upload-max", "4KiB/s"], "").unwrap_err();
    let refusal = low
        .iter()
        .find(|d| d.code == Code::ValueRange && d.option.as_deref() == Some("p2p-upload-max"))
        .expect("the low limit is refused by name");
    let text = refusal.render();
    assert!(
        text.contains(&rate(carrier::UPLOAD_FLOOR_BYTES_PER_SEC)),
        "{text}"
    );
    assert!(
        text.contains(&rate(carrier::PER_NODE_BUDGET_BYTES_PER_SEC)),
        "{text}"
    );
    assert!(text.contains("relay-cover off"), "{text}");

    let opted_out = build_from(&["--p2p-upload-max", "4KiB/s", "--relay-cover", "off"], "")
        .expect("an opted-out node may limit its upload below the floor");
    assert_eq!(opted_out.p2p.upload_max, Some(4 * 1024));
}

/// The floor is exactly twice the budget: a limit at the floor builds, one
/// byte per second under it is refused, and so is the budget itself, which
/// the cover alone would spend.
///
/// Red edits: compare with `<=` (the limit at the floor is refused), or
/// read the floor as the budget (one byte under the floor builds).
#[test]
fn the_upload_floor_is_twice_the_cover_budget_to_the_byte() {
    let budget = carrier::PER_NODE_BUDGET_BYTES_PER_SEC;
    let floor = carrier::UPLOAD_FLOOR_BYTES_PER_SEC;
    assert_eq!(floor, carrier::UPLOAD_FLOOR_BUDGETS * budget);
    assert_eq!(carrier::UPLOAD_FLOOR_BUDGETS, 2);

    let at = build_from(&["--p2p-upload-max", &bytes_per_sec(floor)], "")
        .expect("a limit at the floor builds");
    assert_eq!(at.p2p.upload_max, Some(u64::from(floor)));

    for under in [floor - 1, budget] {
        let refused = build_from(&["--p2p-upload-max", &bytes_per_sec(under)], "").unwrap_err();
        assert!(
            refused.iter().any(
                |d| d.code == Code::ValueRange && d.option.as_deref() == Some("p2p-upload-max")
            ),
            "{under} B/s is under the floor"
        );
    }
}

/// The option's help line states the floor the section enforces.
///
/// Red edit: change [`carrier::UPLOAD_FLOOR_BUDGETS`] without the help
/// line (the line names the old floor).
#[test]
fn the_upload_rows_help_line_names_the_floor() {
    let row = crate::table::TABLE
        .row("p2p-upload-max")
        .expect("the row exists");
    let floor = rate(carrier::UPLOAD_FLOOR_BYTES_PER_SEC);
    assert!(row.help.contains(&floor), "{} lacks {floor}", row.help);
}

/// A rate as the grammar renders it.
fn rate(bytes_per_sec: u32) -> String {
    Value::Rate(u64::from(bytes_per_sec)).render()
}

/// A rate as an operator may type it, in bytes.
fn bytes_per_sec(bytes_per_sec: u32) -> String {
    format!("{bytes_per_sec}B/s")
}
