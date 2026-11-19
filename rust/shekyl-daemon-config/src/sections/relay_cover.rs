// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The cover opt-out and the upload floor it sets (`CVR-R1`, `CVR-R5`).

use shekyl_options::Code;

use super::tests::build_from;

/// Cover is on unless the operator opts out, and with it on an upload limit
/// below the cover rate refuses the start (`CVR-R1`, `CVR-R5`): the carrier
/// sends at that rate whatever else the node has to say. The refusal names
/// the row, the rate, and the way out. With `relay-cover off` the same
/// limit builds.
///
/// Red edits: drop the floor from `read_rates` (the low limit builds), or
/// apply it with cover off (the opted-out node is refused).
#[test]
fn an_upload_limit_below_the_cover_rate_is_refused_while_cover_is_on() {
    let on = build_from(&[], "").expect("the defaults build");
    assert!(on.p2p.relay_cover, "cover is on by default");
    let off = build_from(&["--relay-cover", "off"], "").expect("the opt-out builds");
    assert!(!off.p2p.relay_cover);

    let cover_rate = shekyl_relay_privacy::params::carrier::PER_NODE_BUDGET_BYTES_PER_SEC;
    assert_eq!(
        cover_rate,
        8 * 1024,
        "fixture: the limits below straddle it"
    );
    let low = build_from(&["--p2p-upload-max", "4KiB/s"], "").unwrap_err();
    let refusal = low
        .iter()
        .find(|d| d.code == Code::ValueRange && d.option.as_deref() == Some("p2p-upload-max"))
        .expect("the low limit is refused by name");
    let text = refusal.render();
    assert!(text.contains("8KiB/s"), "{text}");
    assert!(text.contains("relay-cover off"), "{text}");

    assert!(build_from(&["--p2p-upload-max", "8KiB/s"], "").is_ok());
    let opted_out = build_from(&["--p2p-upload-max", "4KiB/s", "--relay-cover", "off"], "")
        .expect("an opted-out node may limit its upload below the cover rate");
    assert_eq!(opted_out.p2p.upload_max, Some(4 * 1024));
}
