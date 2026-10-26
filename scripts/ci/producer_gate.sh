#!/usr/bin/env bash
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# The bundle producer's gate (`SO-D12` increment 4c,
# `ARCHIVAL_SETTLEMENT_WRITER.md` §16.11), run by nightly.yml's
# producer-gate job: a bundle the producer made is admitted by 4a's verifier
# on a driven chain and connects through the staged door. 4b does not land
# until it holds (round 0, F2), so it runs every night, not only when
# someone remembers the live lane.
#
# It is `#[ignore]`d because it fills a shard with real proofs and mines
# three long epochs. Only this test runs here: the ingest crate's other
# ignored tests have their own lanes or none, and this job does not decide
# for them.
#
# Rule 47: the subject must be in the ignored listing, so a rename or an
# un-ignore fails here by name instead of passing a run that skipped it.
# Rule 46: the listing is captured and judged; the run's exit is the
# verdict and travels through no pipe.
set -euo pipefail
cd "$(dirname "$0")/../../rust"
branch="${BRANCH:-the checked-out ref}"
subject='bundle_producer_gate_tests::a_produced_bundle_is_admitted_and_connects_through_the_staged_door'

list=$(cargo test --locked --release -p shekyl-chain-ingest --lib -- --list --ignored)
matches=$(printf '%s\n' "$list" | grep -cx "${subject}: test" || true)
if [ "${matches}" -ne 1 ]; then
  echo "::error::${subject} is not in shekyl-chain-ingest's ignored set"
  exit 1
fi

START=$(date +%s)
cargo test --locked --release -p shekyl-chain-ingest --lib -- --ignored --exact "${subject}" --nocapture
END=$(date +%s)
echo "::notice::The bundle producer's gate completed on ${branch} in $((END - START))s (budget 120m)"
