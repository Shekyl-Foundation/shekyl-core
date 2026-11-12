// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Fuzz the named front-line untrusted-input surface
//! (`DAEMON_SUBMIT_VERDICT.md` §7.6, §10 item 6): Phase A over arbitrary
//! bytes — size cap, `shekyl-wire` parse, canonical-encoding check,
//! `validate()`, static gates, txid. `tx_submit`'s body reaches Phase A as
//! bytes (its base64 is the wire type's, decoded before dispatch).
//!
//! Phase A's contract is *no panic by construction* — every refusal is a
//! typed `PhaseAReject`, never an `unwrap`/`unreachable!`. The target also
//! asserts the two invariants a successful parse promises downstream:
//! byte-canonicality (re-serialize == the submitted bytes) and the F24 property
//! that admitted bytes round-trip to the same txid.

#![no_main]
use libfuzzer_sys::fuzz_target;

use shekyl_daemon_rpc::submit::parse_submission;

fuzz_target!(|data: &[u8]| {
    if let Ok(parsed) = parse_submission(data) {
        // Admitted ⇒ canonical: the blob is exactly the submitted bytes,
        // and re-parsing it must succeed with the same txid (the §3.4
        // divergence class is unrepresentable past Phase A).
        assert_eq!(parsed.blob, data, "admitted blob must be the input");
        let reparsed = parse_submission(&parsed.blob).expect("admitted bytes must re-admit");
        assert_eq!(
            parsed.txid, reparsed.txid,
            "txid must be a pure function of admitted bytes"
        );
    }
});
