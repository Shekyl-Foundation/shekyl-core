#!/usr/bin/env bash
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# The chain-ingest crate's `#[ignore]`d set, run by nightly.yml's
# chain-ingest-ignored job. The set lives here, in the tree under test, for
# the reason ignored_set_chain_store.sh gives: a scheduled workflow runs the
# default branch's copy of nightly.yml over every branch in its matrix, so a
# list written there would judge `dev` by `main`'s.
#
# The crate's docs call this set "the live lane": this job is it, and each
# ignore string names the job. The set: the scenarios that fill shards with
# real proofs (the archival pop round trips, the emission claims, the
# levered slash chain, the join, the two pool-shim posts), the miner over
# real RandomX, the captured-chain replay under the production substrate,
# and the measurements (the switch at the genesis cap, the miner's rate, the
# H19 batch cost). An `#[ignore]`d test no scheduled lane runs is a deleted
# test with a comment on it. Before this job none of these ran, and its
# first run found five red on `dev`: the four switch-timing tests asserted
# an alt table the death rule (0999f8726) had since emptied, and the
# five-block miner test never pinned its seed, which the miner has required
# since e1c39b882. Both were repaired in DRS-X PR 3e.
#
# Budget: the whole set took 44 minutes in release on a 16-core workstation
# under heavy load (the two RandomX switch measurements dominate); the job
# allows 240 minutes for a 4-vCPU runner.
#
# Rule 47: the lane asserts every subject it owns is in the set before
# running it, so a renamed, deleted or un-ignored member fails here by name.
# A further ignored test runs too and is counted, and joins the list when it
# is this lane's to own. Rule 46: the listing is captured once and judged;
# the count reads to the end of its input; the run's own exit is the verdict
# and travels through no pipe.
set -euo pipefail
cd "$(dirname "$0")/../../rust"
branch="${BRANCH:-the checked-out ref}"

list=$(cargo test --locked --release -p shekyl-chain-ingest --features pipeline --lib -- --list --ignored)
for subject in \
  'archival_pop_roundtrip_tests::a_claim_chain_pops_and_reconnects_at_every_block_from_the_joins_on' \
  'archival_pop_roundtrip_tests::a_slash_and_reinstate_chain_pops_and_reconnects_at_every_block_from_the_join_on' \
  'archival_pop_roundtrip_tests::a_popped_claim_restores_the_epoch_its_prune_dropped_and_a_second_claim_is_refused' \
  'archival_slash_tests::the_levered_slash_chain_judges_each_row_on_one_record' \
  'miner_tests::the_miner_extends_the_chain_block_after_block' \
  'miner_tests::the_miners_rate_per_worker' \
  'pool_submit_tests::join_posts_are_accepted_through_the_rust_pool_shim' \
  'pool_submit_tests::two_posts_by_one_persona_are_held_and_the_template_selects_one' \
  'scenario::scenario_tests::a_chain_mines_under_the_production_substrate' \
  'scenario_emission_tests::a_claim_verifies_after_the_epochs_complete_trees_are_released_and_slashed' \
  'scenario_emission_tests::the_drivers_emission_claim_connects_and_pays_the_persona' \
  'scenario_join_tests::a_join_is_written_and_the_blocks_after_it_read_the_record' \
  'switch_timing_tests::production_cap_switch_timing_free_hash_coinbase_only' \
  'switch_timing_tests::production_cap_switch_timing_free_hash_with_spends' \
  'switch_timing_tests::production_cap_switch_timing_randomx_coinbase_only' \
  'switch_timing_tests::production_cap_switch_timing_randomx_with_spends' \
  'vectors_tests::h19_cost::h19_batch_cost_at_the_captured_densities' \
  'vectors_tests::replays_every_captured_chain_under_the_production_substrate'
do
  matches=$(printf '%s\n' "$list" | grep -cx "${subject}: test" || true)
  if [ "${matches}" -eq 0 ]; then
    echo "::error::${subject} is not in shekyl-chain-ingest's ignored set"
    exit 1
  fi
done
count=$(printf '%s\n' "$list" | grep -c ': test$')
echo "shekyl-chain-ingest ignored set: ${count} test(s)"

START=$(date +%s)
cargo test --locked --release -p shekyl-chain-ingest --features pipeline --lib -- --ignored --nocapture
END=$(date +%s)
echo "::notice::Chain-ingest ignored set completed on ${branch} in $((END - START))s (budget 240m)"
