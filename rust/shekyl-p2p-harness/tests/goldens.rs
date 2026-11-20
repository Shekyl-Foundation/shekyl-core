// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Every harness seed against the seam, compared to the recorded parity
//! goldens (`goldens/`): what the `check-goldens` binary runs, as a test of
//! the workspace's own `cargo test`.

use std::path::Path;

use shekyl_p2p_harness::{all_seeds, check_goldens};

#[test]
fn every_seed_matches_its_recorded_goldens() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("goldens");
    // The subject (rule 47): seeds exist, and each has its two goldens, so
    // an empty seed list or a missing file cannot pass as "no mismatch".
    let seeds = all_seeds();
    assert!(!seeds.is_empty(), "no harness seeds");
    for seed in &seeds {
        for role in ["peer", "host"] {
            let golden = dir.join(format!("seed-{seed}-{role}.txt"));
            assert!(golden.is_file(), "missing golden {}", golden.display());
        }
    }
    check_goldens(&dir).unwrap_or_else(|err| panic!("{err}"));
}
