# Floor run sheet

**Status: LIVE — the measurement ledger's floor rows, by session (Brief D's
sweep, ruled 2026-11-13).** Every constant here has `disposition = "floor"`
in [`measurement_ledger.toml`](measurement_ledger.toml), and every such
constant is here: `scripts/ci/check_measurement_ledger.py` holds the two
lists equal. A row leaves this sheet when its capture lands and the ledger
row turns current, or when the ledger gives it another disposition.

The device is the floor of
[`76-device-provisioning-floor`](../../.cursor/rules/76-device-provisioning-floor.mdc),
the Raspberry Pi 4 Model B. The session is claimed on the shared estate
before it starts (rule 38); hosts are named by role here (rule 37). Each
session's record is a dated file under `docs/benchmarks/`, registered
before the run, with the conditions the earlier record of the same session
kept (governor, temperature, what else ran). A count from the CI runner
does not stand in for any row here: these are device times (rule 76).

Rows needing chain state only the chain forge builds are not here. They
are the ledger's `forge` rows, which name the event they wait on.

## 1. The verify surface (`BA-T10`)

**Instrument.** `scripts/bench/gap7_pi4_gate.sh`, which runs
`shekyl-verify-cost`'s `block_connect_pins` test and its
`block_connect_verify` bench (criterion, 10 samples a point), including the
depth sweep (ruled 2026-11-08: the admission pair's depth cells measured,
not projected). The input-count cells are `shekyl-wire`'s
`tests/input_cap_cost.rs` (`#[ignore]`d, run with `--ignored`). The door's
cells are `shekyl-verify-cost`'s `relay_admission_verify` bench.

**Preconditions.** None beyond the device: the fixtures are in the tree.

| Constant | What the session reads |
| --- | --- |
| `block_weight_short_term_surge_factor` | the depth-24 block verify, on which `S` is re-signed (C2-R2 Q3) |
| `block_weight_full_reward_zone_bytes` | the block verify at the zone's fill |
| `fcmp_max_inputs_per_tx` | the verify cost by input count, the cap's derivation (CEN-I4) |
| `fcmp_max_tree_depth` | the verify cost past depth 7, to depth 24 |
| `spec_verify_cost_modal_cell` | the door's masks-and-proof term at the modal cell, after `PL-D3` |
| `pi4_hybrid_sig_1in_ms` | `pqc_per_input` at one input |
| `pi4_hybrid_sig_8in_ms` | `pqc_per_input` at eight inputs |
| `pi4_range_proof_lone_1in_2out_ms` | the lone range proof at 1-in/2-out, on the constant-time opening |
| `pi4_range_proof_lone_8in_2out_ms` | the lone range proof at 8-in/2-out, on the constant-time opening |
| `pi4_aes_bytes_per_sec` | software AES-128-CTR throughput (the device has no AES instructions) |

## 2. The serve path (`BA-T5`)

**Instrument.** `shekyl-p-serve`'s `tests/ba_t5_floor_probe.rs`, which
serves synthetic shard bodies from a store it writes itself, driven by
`scripts/bench/ba_t5_session2_run.sh` (the probe, a daemon binary, a LAN
peer to sync from, and a pass count). The method is the 2026-10-09
session's ([`ba_t5_serve_floor_device_20261009.md`](ba_t5_serve_floor_device_20261009.md)).

**Preconditions.** A LAN peer serving a chain the daemon can sync, for the
sync state. `p_serve_max_inflight` is derived by the rule `BA-Q4` rules on
(its default: from this session). `shekyl_slice_cpu_weight` is the
redefined T2 measurement (`docs/FOLLOWUPS.md`, ruled 2026-10-12): the
daemon as the installed unit in `shekyl.slice`, synced and following the
tip, with the probe serving at N = 64 in a user session.

| Constant | What the session reads |
| --- | --- |
| `serving_workers` | the smallest executor worker count that meets the serving duty |
| `serving_blocking` | the blocking threads per permitted connection at the cap |
| `p_serve_max_inflight` | throughput and wake lateness by N, and refusals at the cap |
| `serve_floor_verdict_frame` | the serve of a frame streamed from the sealed body store |
| `serve_prehead_work_floor` | time to first byte on the unframed stream |
| `shekyl_slice_cpu_weight` | block-verify time with and without the slice weight, under contention |

## 3. Clearnet spans (`BA-T8`)

**Instrument.** The daemon's measurement build (`SHEKYL_MEASUREMENT_SPANS`;
`scripts/ci/check_measurement_spans.py` reads its span lines), on the legs
of the 2026-09-30 records (`p2p_clearnet_*_20260930.tsv`): a LAN leg and a
long-path leg, n = 100 a leg, each reopen rule evaluated.

**Preconditions.** A LAN peer and a distant peer, both on the current tree.

| Constant | What the session reads |
| --- | --- |
| `clearnet_dial_within_ns` | the dial span |
| `clearnet_handshake_within_ns` | the handshake span |
| `clearnet_gap_within_ns` | the gap span |

## 4. The Tor stem hop (`BA-T9`)

**Instrument.** [`D5_TOR_STEM_RUNBOOK.md`](D5_TOR_STEM_RUNBOOK.md): n ≥ 100
stems, each sample mapped to a verify-cost cell, the transit split from the
node-local time (`docs/FOLLOWUPS.md`, the anonymity hop on the floor).

**Preconditions.** Two nodes on the current tree with Tor, as the runbook
says. `fluff_return_ms` is a model figure (degree 12, outbound-only flood);
a two-node session observes one fluff and bounds it, it does not measure the
degree-12 first passage.

| Constant | What the session reads |
| --- | --- |
| `anon_zone_transit_assumption_ms` | the stem's transit in the anonymity zone |
| `adopted_transit_assumption_ms` | the adopted transit |
| `fluff_return_ms` | the fluff's return, as far as two nodes show it |

## 5. The transport's thread budget (`BA-T11`)

**Instrument.** Owed. `shekyl-timing-engine`'s `wake_hints` bench covers
the timer only; the thread-budget legs (the smallest worker, blocking and
executor counts that meet each duty) are `docs/FOLLOWUPS.md`'s D5 item, and
no harness for them is in the tree.

| Constant | What the session reads |
| --- | --- |
| `transport_workers` | the smallest worker count that meets the transport's duty |
| `transport_blocking` | the smallest blocking cap that meets it |

## 6. The wallet scan (`BA-T16`)

**Instrument.** `scripts/bench/fa6_pi4_gate.sh`, which runs
`shekyl-crypto-pq`'s `fa6_decap_prefilter_gate` over the FA-6 scenarios
(`FA-6_VIEW_TAG_ML_KEM.md` §8), with shipping flags: the 2026-06-08 capture
used non-shipping `RUSTFLAGS`, which is half of why these rows are stale.

| Constant | What the session reads |
| --- | --- |
| `fa6_scan_budget_ceiling_a` | the incremental scenario's scan rate |
| `fa6_scan_budget_ceiling_b` | the restore scenario's scan rate |
| `fa6_scan_budget_margin` | the margin between the two and the budget |

## 7. The wallet's key derivation (`BA-T17`)

**Instrument.** `shekyl-engine-file`'s `open` bench, its `default_kdf`
case: the default Argon2 profile timed (the CI arm, `open_iai`, runs a KAT
profile because the default is too slow under callgrind).

| Constant | What the session reads |
| --- | --- |
| `wallet_default_kdf_m_log2` | the open time at the default memory cost |
| `wallet_default_kdf_t` | the open time at the default pass count |

## 8. The wallet's proving-state edge (`BA-T19`)

**Instrument.** `shekyl-wss-q1b-bench`'s `spend_edge` binary, per
[`WSS_Q1B_BENCH_SPEC.md`](../design/WSS_Q1B_BENCH_SPEC.md) (WSS-Q1(b) row 2).

| Constant | What the session reads |
| --- | --- |
| `wss_spend_delta_floor_s` | spend-time replay against proving, in seconds |
| `wss_spend_delta_relative` | the same, relative to proving |

## 9. RandomX cache derivation (`BA-T14`)

**Instrument.** `shekyl-pow-randomx`'s `cache_derive` bench, light mode,
100 samples: never yet run on the floor (341 ms on x86 against the 200 ms
target).

| Constant | What the session reads |
| --- | --- |
| `randomx_cache_derivation_target_ms` | one cache derivation on the floor |
