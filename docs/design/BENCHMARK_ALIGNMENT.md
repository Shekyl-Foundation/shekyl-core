# Benchmark alignment — inventory, gaps, proposed tracked set, rulings needed

**Status: OPEN — round 0, assessment (2026-10-05).** Ruled so far: BA-Q1,
BA-Q3, BA-Q8, BA-Q21 and BA-Q23; BA-Q2 is done (§6). Everything else is unruled: every other
disposition in §2 and row of §5 is a *proposal*. No workflow, baseline or
threshold changes with this document. One tracked benchmark has been built
since: BA-T3, the serve-path gate (§5, 2026-10-06). BA-T33's T1 arm, added
with its row on 2026-10-09, is built; its floor arm is owed.

**Pins.** `shekyl-core`: verified at `dev` `63e456fb95`. `shekyl-gui-wallet`:
branch `dev` at `447908f` (the working branch; `main` is `319517a`,
2026-09-11). Every `path:line` below is at those pins. GUI paths are written
`gui:<path>:<line>` and are not links.

**Identifier families** (registered in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2): `BA-I` inventory
rows, `BA-D` defects (the design or a document says A, the code does B),
`BA-G` gaps, `BA-T` proposed tracked benchmarks, `BA-Q` rulings needed.

## 0. What this document answers

Which measurements does a decision rest on, which of them are tracked, and
which tracked measurements does no decision rest on. A benchmark earns a row
in §5 only if a ruled constant, a capacity figure, a floor-device budget or a
user-facing latency rests on its number.

The floor device is the Raspberry Pi 4 Model B
([`76-device-provisioning-floor`](../../.cursor/rules/76-device-provisioning-floor.mdc)).
Devices are named by role throughout: **floor** (Pi 4, USB3 SSD), **x86 dev**
(a developer laptop or workstation), **CI runner** (GitHub-hosted
`ubuntu-latest`).

### 0.1 Dispositions

Each inventory row carries exactly one proposed disposition.

| Disposition | Meaning |
| --- | --- |
| **Keep, gated** | Instruction-count or deterministic metric that fails a PR on regression |
| **Keep, tracked** | Wall-clock or device metric recorded on a schedule or per release, compared but not gating |
| **Rewrite** | Measures something that matters, but the wrong path, fixture or device |
| **Retire** | No consumer, dead path, Monero-lineage code, or superseded; deletion with its reason ([`15-deletion-and-debt`](../../.cursor/rules/15-deletion-and-debt.mdc)) |
| **Add** | A gap from §3 |

### 0.2 Tiers

| Tier | What | Where | Verdict |
| --- | --- | --- | --- |
| **T1** | Instruction counts (gungraun) | CI runner, per PR | Gates |
| **T2** | Criterion wall-clock | CI runner, per PR or per merge | Trended, never gates |
| **T3** | Floor-device run with a recorded protocol: alternating arms, cache state stated, `n` stated | floor, per release and on any PR touching the path | Compared against the ruled constant's stated margin; a breach reopens the constant |

Two wall-clock checks gate in CI today and fit none of these tiers: the
shard-render smoke (BA-I32) and the RandomX Rust-to-C ratio bounds (BA-I33).
BA-Q22 asks whether they stay gated as named exceptions.

## 1. The CI gate at the pin

One workflow gates performance: `ci/benchmarks`
(`.github/workflows/benchmarks.yml`). Its input is the `BENCHES` array at
`scripts/bench/capture_rust_baseline.sh:87`, ten rows over six crates. On a
pull request it captures the PR head and compares gungraun `instructions`
against `baseline.json` on the `bench-baseline` branch; on a push to `dev` it
refreshes that file. The baseline's tip was captured from `cd51261ab2` on
2026-10-05, on a CI runner.

| Fact | Value at the pin | Source |
| --- | --- | --- |
| Gated rows | 10 (`BENCHES`), 6 crates: engine-state, engine-file, scanner, tx-builder, engine-core, ffi | `scripts/bench/capture_rust_baseline.sh:87` |
| Gated entries | 20 gungraun entries; 21 criterion entries ride along ungated | `bench-baseline:baseline.json` at `e688a5984d` |
| Thresholds | `crypto_bench_*` ±5 % warn, ±15 % fail; `hot_path_bench_*` +5 % / +15 %; `engine_trait_bench_*` ±10 % / ±25 % | `scripts/bench/compare.py:124`, `scripts/bench/compare.py:129` |
| A gated entry absent from the PR | fails the job | `scripts/bench/compare.py:245`, `scripts/bench/compare.py:348` |
| Merge-block | live: the warning-window sentinel `docs/benchmarks/MID_REWIRE_WARNING_WINDOW.active` does not exist | `.github/workflows/benchmarks.yml:318` |
| Trigger | PR or push to `dev` touching one of seven crate directories, the Cargo manifests, `scripts/bench/**` or the workflow | `.github/workflows/benchmarks.yml:61` |
| Device | CI runner only. Nothing in the gate runs on the floor | `.github/workflows/benchmarks.yml:121` |

What the gate covers by subject: wallet ledger postcard round-trip (6
entries), wallet balance compute (3), wallet file open at a KAT KDF (1),
scanner bookkeeping after scan (3), Bulletproofs+ 2-output prove and hybrid
sign for one input (2), four wallet engine-trait read paths (4), and pool
admission verify at the modal 1-in/2-out shape (1). Nineteen of the twenty
entries are wallet-side. Nothing in the gate measures archival serving or
fetch, block connect, the chain store, P2P transport, PoW, or anything on the
floor device.

### 1.1 Defects — the design or a document says A, the code does B

These are reported as defects. None is fixed here; §6 holds the ruling
that fixes or retires each.

| Id | A (stated) | B (at the pin) |
| --- | --- | --- |
| **BA-D1** | `relay_admission_verify_iai` is the drift gate for pool-admission cost: "a change to FCMP++ verification moves this count" (`scripts/bench/capture_rust_baseline.sh:106`) | The workflow's path filter (`.github/workflows/benchmarks.yml:61`) lists `shekyl-oxide` and `shekyl-crypto-pq` but not `rust/shekyl-ffi/**`, `rust/shekyl-fcmp/**` or `rust/shekyl-fcmp-proofs/**`, which the bench calls directly (`rust/shekyl-ffi/benches/relay_admission_fixture.rs`). A PR touching only those crates runs neither the comparison nor the baseline refresh. The next PR that does trigger the gate is then compared against a baseline that predates the change, and carries its delta |
| **BA-D2** | `docs/benchmarks/README.md:66` and `:70`: the capture runs "the five criterion harnesses" and "the five iai-callgrind sibling harnesses" | `BENCHES` holds ten rows; one (`shekyl-ffi::relay_admission_verify_iai`) has no criterion arm (`scripts/bench/capture_rust_baseline.sh:108`) |
| **BA-D3** | Seven gungraun targets are registered for `shekyl-engine-core` (`rust/shekyl-engine-core/Cargo.toml:420`, `:434`, `:454`, `:471`, `:481`, `:501`, `:516`) and two for `shekyl-scanner` (`rust/shekyl-scanner/Cargo.toml:85`, `:102`); `docs/PERFORMANCE_BASELINE.md` frames each `engine_trait_bench_*` as a measurement gate | Four are not in `BENCHES` and so are never captured or compared: `engine_trait_bench_key_account_public_address_iai`, `engine_trait_bench_economics_base_emission_at_iai`, `engine_trait_bench_economics_parameters_snapshot_iai`, `scan_transaction_iai`. They compile; nothing runs them |
| **BA-D4** | `docs/benchmarks/README.md:277` cross-references `tests/wallet_bench/README.md` | That directory was deleted with `wallet2`; the same README says so at `:38` |
| **BA-D5** | `docs/benchmarks/shekyl_rust_v0.json` is described as "frozen numbers" for the Rust baseline (`docs/benchmarks/README.md:13`) | Captured at `a2bf417e4b` on an x86 dev laptop with `iai_callgrind_runner` v0.16.1; six entries name the crate `shekyl-wallet-state`, which no longer exists under `rust/` (`docs/benchmarks/shekyl_rust_v0.json:206`). It holds 15 gungraun entries against the gate's 20. The gate does not read it (`docs/benchmarks/README.md:180`) |
| **BA-D6** | `docs/benchmarks/README.md:84`: the committed baseline is provisional "until a reference machine is provisioned", after which a re-capture replaces it | No document names the reference machine that sentence waits for, and the rolling baseline is captured on whichever CI runner the job lands on |
| **BA-D7** | [`DAEMON_RELAY_PRIVACY.md`](DAEMON_RELAY_PRIVACY.md) §72.2: on pool admission "No ML-DSA verification occurs"; the relay bench header repeats it (`rust/shekyl-ffi/benches/relay_admission_verify.rs:26`) | Pool admission calls `check_tx_inputs` (`src/cryptonote_core/tx_pool.cpp:309`), which verifies one hybrid Ed25519 + ML-DSA-65 signature per input (`src/cryptonote_core/blockchain.cpp:4283`, `src/cryptonote_core/tx_pqc_verify.cpp:148`), after a Bulletproofs+ verify (`src/cryptonote_core/tx_pool.cpp:234`). Both relay benches and the gated count time commitment masks and FCMP++ verify only. Size, from the floor capture `gap7_block_verify_pi4_rust_20260905T181144Z.txt`: 0.97 ms per signature against 126 ms for the admission pair at 1-in/2-out |
| **BA-D8** | The merge path says claims are re-routed through `KeyEngine::try_claim_output` at M3c+ (`rust/shekyl-engine-core/src/engine/merge.rs:252`, `:1090`), and the send and subaddress designs build on that claim path (`docs/design/PHASE_2A_SEND_PATH.md:759`, `docs/design/SUBADDRESS_UNDER_PQC.md:149`) | The re-route has no carrier. `try_claim_output` has no production caller at the pin (every call site outside its definitions at `rust/shekyl-engine-core/src/engine/local_keys.rs:365` and `rust/shekyl-engine-core/src/engine/key_actor.rs:542` is a test or the bench harness), and no `docs/FOLLOWUPS.md` row names M3c+ (`grep -n M3c docs/FOLLOWUPS.md` returns nothing). The gated bench (BA-I8) is not the defect: it holds the cost of the designed path until the caller lands. The defect is a staged step with nothing that says when it lands ([`22-no-lazy-deferral`](../../.cursor/rules/22-no-lazy-deferral.mdc)) |
| **BA-D9** | The three ungated `engine_trait_bench_*_iai` files each say "This is the bench whose `instructions` value the CI gate … uses" (`rust/shekyl-engine-core/benches/engine_trait_bench_economics_base_emission_at_iai.rs:17`); `docs/PERFORMANCE_BASELINE.md:97` says their numbers arrive "via CI" | No `BENCHES` row exists for them (BA-D3), so CI has never produced a number |
| **BA-D10** | `scripts/bench/capture_rust_baseline.sh:14`: "This script is run by humans, not CI" | It is the capture step of both CI jobs (`.github/workflows/benchmarks.yml:168`, `:452`) |
| **BA-D11** | `rust/shekyl-engine-file/benches/open.rs:22`: the bidirectional threshold catches a "silent `m_log2` demotion" of the Argon2id default | The gated sibling pins the KAT profile `m_log2 = 0x08` itself (`rust/shekyl-engine-file/benches/open_iai.rs:9`) and never runs `KdfParams::default()`. A change to the default cost moves no gated count |
| **BA-D12** | `scripts/bench/gap7_pi4_gate.sh` and `scripts/bench/fa6_pi4_gate.sh` are named gates | Neither enforces a performance threshold. The GAP-7 script checks build provenance and that the measurement ran (`scripts/bench/gap7_pi4_gate.sh:123`, `:135`). The FA-6 script runs a binary that prints a classification; its recorded outcome is `fail` and FA-6 shipped (`docs/PERFORMANCE_BASELINE.md:808`). The FA-6 script recommends `-C target-cpu=cortex-a72` (`scripts/bench/fa6_pi4_gate.sh:20`), which the GAP-7 script forbids because it crashes RandomX on the floor board (`scripts/bench/gap7_pi4_gate.sh:34`). The GAP-7 script cites "PERFORMANCE_BASELINE.md §8.2" (`scripts/bench/gap7_pi4_gate.sh:9`); that file has no §8.2 |
| **BA-D13** | [`MID_REWIRE_HARDENING.md`](../MID_REWIRE_HARDENING.md) §3.3 defers the Tier-2 criterion gate to §6 "and its deadline" (`docs/MID_REWIRE_HARDENING.md:382`) | §6.1 (`docs/MID_REWIRE_HARDENING.md:1220`) states triggers and no deadline, and no `docs/FOLLOWUPS.md` row carries the deferral (`grep -n -e 'Tier-2' -e 'Tier 2' docs/FOLLOWUPS.md` returns only an unrelated row). Under [`22-no-lazy-deferral`](../../.cursor/rules/22-no-lazy-deferral.mdc) it has no carrier |
| **BA-D14** | [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) "Verification Time": FCMP++ proof ~35 ms per input, PQC auth ~18 ms per input (`docs/FCMP_PLUS_PLUS.md:1081`, `:1083`); no source or device given | Measured on the floor ([`CHAIN_RULES_SLICE_6.md`](../completed/CHAIN_RULES_SLICE_6.md) §5.4, 2026-09-24, depth 3): the proof verifies in 130.6 ms at one input and 191.9 ms at two, a marginal 63.9 ms per added input; the hybrid signature is about 1.0 ms per input (0.97 ms in GAP-7, 2026-09-05); Bulletproofs+ is a fixed 34.9 ms; a one-input transaction verifies in 166.7 ms and a two-input one in 229.1 ms |
| **BA-D15** | `rust/shekyl-p-serve/src/serve.rs:119`: "The W₂ rig derives the real value" of `MAX_INFLIGHT` on floor hardware | The W₂ runs are finished and read ([`ARCHIVAL_SHARD_T_DERIVATION.md`](../completed/ARCHIVAL_SHARD_T_DERIVATION.md) §10); none varied or derived the serve-side cap. `MAX_INFLIGHT = 64` is still the placeholder the same comment declares it to be (`rust/shekyl-p-serve/src/serve.rs:112`, `:122`) |
| **BA-D16** | `scripts/bench/test_compare.py` is the regression suite for the comparator that decides the gate | No workflow runs it (`grep -rn test_compare .github/workflows` returns nothing). `scripts/bench/test_drs_bench.py`, its sibling, is run (`.github/workflows/docs-gates.yml:313`) |

## 2. Inventory

One row per benchmark, gate script, CI job, baseline file and dated capture.
"Last run" is the most recent run with evidence in the tree or on the
`bench-baseline` branch; "none recorded" means no number from the target
exists in either. "Consumer" is what cites the number: a ruled constant, a
threshold, a design decision. Where none was found the row says how that was
checked. Rows that are not measurements (an index, a functional run record)
are listed so the directory is covered, and carry `n/a`.

Every gated row's last run is the baseline refresh of 2026-10-05 from
`cd51261ab2`, on a CI runner.

### 2.1 Gated rows (`BENCHES`, T1 today)

| Id | Target and path | Measures | Production path? | Consumer | Proposed |
| --- | --- | --- | --- | --- | --- |
| **BA-I1** | `shekyl-engine-state::ledger` / `ledger_iai` — `rust/shekyl-engine-state/benches/ledger_iai.rs` | `WalletLedger` postcard serialize and deserialize at 100 / 1 000 / 10 000 transfers | Yes: `rust/shekyl-engine-file/src/handle.rs:637`, `:537` | Wallet save and open. No stated latency found (searched `docs/` for the bench ids and `postcard`) | **Rewrite** — the fixture leaves each transfer's ciphertext and handle empty (`rust/shekyl-engine-state/benches/ledger.rs:38`); a real transfer carries about 1.1 KiB of them (`rust/shekyl-engine-core/benches/refresh_snapshot.rs:60`) |
| **BA-I2** | `shekyl-engine-state::balance` / `balance_iai` | `BalanceSummary::compute` at 100 / 1 000 / 10 000 transfers | Yes: `rust/shekyl-scanner/src/ledger_ext.rs:208` | The body `LedgerEngine::balance` runs, which the trait spec names as a hot path under measurement (BA-I7). 23 µs at 10 000 transfers on the CI runner | **Keep, gated** |
| **BA-I3** | `shekyl-engine-file::open` / `open_iai` | Cold `WalletFile::open` of an empty ledger; the gated arm at the KAT KDF profile, the criterion arm at the default | Yes: `rust/shekyl-engine-core/src/engine/lifecycle/open.rs:137` | The Argon2id default's target, "under ~500 ms on a commodity desktop" (`rust/shekyl-crypto-pq/src/wallet_envelope.rs:132`). Never measured on the floor | **Rewrite** — BA-D11; the gated arm cannot see the default cost, and the wall-clock arm has no floor run |
| **BA-I4** | `shekyl-scanner::scan_block` / `scan_block_iai` | `process_scanned_outputs` bookkeeping for 0 / 5 / 50 owned outputs; no cryptography | Yes: `rust/shekyl-engine-core/src/engine/merge.rs:995` | Sync rate, indirectly. No stated budget | **Rewrite** — the unit a user waits on is a scanned block: scan plus merge. This times the bookkeeping part alone while the cryptographic part (BA-I15) is ungated |
| **BA-I5** | `shekyl-tx-builder::transfer_e2e` / `transfer_e2e_iai` | Bulletproofs+ prove for 2 outputs and one hybrid signature. Not `sign_transaction`; the gated arm signs through a bench-only entry (`rust/shekyl-crypto-pq/src/signature.rs:479`) | Components only | Send latency. No stated budget | **Rewrite** — named end-to-end, measures two components. FCMP++ proving, 6.05 s on the floor for a 2-input spend (`docs/benchmarks/wss-q1b/spend_edge_20260927T195848Z.txt`), is absent |
| **BA-I6** | `shekyl-engine-core::engine_trait_bench_ledger_synced_height` (+ `_iai`) | A height read behind a lock; about 10 instructions | The trait body is production; the `Engine` accessor the bench enters through has no caller yet | [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md) §3.3.1 names `LedgerEngine::synced_height` among the hot paths under measurement (`docs/V3_ENGINE_TRAIT_BOUNDARIES.md:3129`) | **Keep, gated** |
| **BA-I7** | `shekyl-engine-core::engine_trait_bench_ledger_balance` (+ `_iai`) | `BalanceSummary::compute` over 1 024 transfers through a bench-only shim (`rust/shekyl-engine-core/src/engine/bench_support.rs:45`) | Body yes (BA-I2); the entry is a bench-only shim | [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md) §3.3.1 names `LedgerEngine::balance` (`docs/V3_ENGINE_TRAIT_BOUNDARIES.md:3129`) | **Keep, gated** |
| **BA-I8** | `shekyl-engine-core::engine_trait_bench_key_dispatch` / `_baseline_iai` | `try_claim_output` on `LocalKeys` and through the key actor, one synthetic output | Not yet: the caller is designed and unwritten (BA-D8) | The B9 dispatch ratio ≤ 1.05 ([`PERFORMANCE_BASELINE.md`](../PERFORMANCE_BASELINE.md), key-dispatch section); the claim path the send and subaddress designs build on (`docs/design/PHASE_2A_SEND_PATH.md:759`) | **Keep, gated** — it holds the cost of a designed path until its caller lands (BA-Q6) |
| **BA-I9** | `shekyl-engine-core::engine_trait_bench_key_merge_projection` (+ `_iai`) | `populate_engine_handle_fields` over 256 outputs | Yes: `rust/shekyl-engine-core/src/engine/merge.rs:256` | Evidence for keeping eager projection at merge (`docs/PERFORMANCE_BASELINE.md:577`) | **Keep, gated** |
| **BA-I10** | `shekyl-ffi::relay_admission_verify_iai` — `rust/shekyl-ffi/benches/relay_admission_verify_iai.rs` | `shekyl_check_commitment_masks` + `shekyl_fcmp_verify` at 1-in/2-out, depth 2 | Yes: `src/cryptonote_core/blockchain.cpp:3239`, `:4224` | The hop term and the embargo derived from it (`rust/shekyl-relay-privacy/src/verify_cost.rs:349`) | **Keep, gated** — after BA-D1 (trigger) and BA-D7 (omitted terms) are ruled |
| **BA-I105** | `shekyl-crypto-pq::fn_dsa_hybrid` / `fn_dsa_hybrid_iai` — `rust/shekyl-crypto-pq/benches/fn_dsa_hybrid_iai.rs`. Added 2026-10-09, after the baseline refresh this section is dated at | One nested sign and one nested verify under hybrid scheme 3 (Ed25519 + FN-DSA-1024); the gated sign arm pins the signer's draw, the criterion arm does not | Not yet: the scheme has no caller until the receipt moves onto it ([`FN_DSA_HYBRID.md`](FN_DSA_HYBRID.md) §6) | None yet. The receipt's per-response signing cost on the serve path, and the witness's verification of it, once those are built | **Keep, gated** as a drift signal for the x86 path only; the figure a budget would rest on is BA-T33's floor arm |

### 2.2 Registered Rust bench targets outside the gate

None of these is run by any workflow. The comparator routes gungraun
function names by prefix (`scripts/bench/compare.py:149`); criterion
results are informational. Of the targets below with a gungraun arm,
BA-I11 to BA-I13 already carry a routed prefix, and BA-I15's two functions
carry none, so `scripts/bench/compare.py:155` would class them `unrouted`
if a `BENCHES` row were added without a rename. The rest are
criterion-only and have no instruction count to gate.

| Id | Target and path | Measures | Production path? | Last run | Consumer | Proposed |
| --- | --- | --- | --- | --- | --- | --- |
| **BA-I11** | `engine_trait_bench_key_account_public_address` (+ `_iai`), `shekyl-engine-core` | `LocalKeys::account_public_address` | No: production reads the address through the actor handle (`rust/shekyl-engine-core/src/engine/mod.rs:1018`) | none recorded (`docs/PERFORMANCE_BASELINE.md:451`) | [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md) §3.3.1 names `KeyEngine::account_public_address` (`docs/V3_ENGINE_TRAIT_BOUNDARIES.md:3128`) | **Rewrite** — time the actor handle, which is the path production reads, and add the `BENCHES` row (BA-D3, BA-D9) |
| **BA-I12** | `engine_trait_bench_economics_base_emission_at` (+ `_iai`) | `base_emission_at` at height 262 800 through a bench shim | Not yet in the wallet: only a `cfg(test)` differential and the shim call it (`rust/shekyl-engine-core/src/engine/bench_support.rs:143`) | none recorded | [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md) §3.3.1 names `EconomicsEngine::base_emission_at` (`docs/V3_ENGINE_TRAIT_BOUNDARIES.md:3130`) | **Keep, gated** — add the `BENCHES` row it has never had (BA-D3, BA-D9) |
| **BA-I13** | `engine_trait_bench_economics_parameters_snapshot` (+ `_iai`) | `parameters_snapshot` through a bench shim | As BA-I12 (`rust/shekyl-engine-core/src/engine/bench_support.rs:175`) | none recorded | [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md) §3.3.1 names `EconomicsEngine::parameters_snapshot` (`docs/V3_ENGINE_TRAIT_BOUNDARIES.md:3131`); the stake and archival engines are designed to read it (`docs/V3_ENGINE_TRAIT_BOUNDARIES.md:2316`) | **Keep, gated** — add the `BENCHES` row it has never had (BA-D3, BA-D9) |
| **BA-I14** | `shekyl-engine-core::refresh_snapshot` | `LedgerSnapshot::from_ledger` and clone at 1 000 / 10 000 / 50 000 production-shaped transfers | Yes, through a shim: `rust/shekyl-engine-core/src/engine/local_ledger.rs:360` | none recorded | The per-scan cost that [`PERF_MERGE_INSERTION_INDICES_PREFLIGHT.md`](PERF_MERGE_INSERTION_INDICES_PREFLIGHT.md) investigates | **Keep, tracked** (T2) |
| **BA-I15** | `shekyl-scanner::scan_transaction` (+ `_iai`) | `Scanner::scan` over 1 / 4 / 8 / 16 outputs, worst case and view-tag-filtered, warm and cold | Yes: `rust/shekyl-engine-core/src/engine/local_refresh.rs:907` | 2026-05-20, x86 dev: 12.95 ms cold p99 (`docs/completed/STAGE_1_PR_4_REFRESH_ENGINE.md:4773`) | The per-output safe-point decision in that plan; sync rate | **Keep, gated** — needs a routing prefix and a `BENCHES` row (BA-D3) |
| **BA-I16** | `shekyl-multisig::multisig_v31` | Intent hash, envelope encode and decode, 1 KiB payload encrypt and decrypt, a 16-input fingerprint | Not yet: no caller outside the crate's own tests | none recorded | The multisig engine design ([`V3_1_MULTISIG_RUST_ENGINE.md`](V3_1_MULTISIG_RUST_ENGINE.md)); no latency budget is stated | **Keep, tracked** (T2) — a designed path not yet wired |
| **BA-I17** | `shekyl-crypto-pq::fa6_decap_prefilter`, with the classifier `rust/shekyl-crypto-pq/examples/fa6_decap_prefilter_gate.rs` | `ml_kem_decap_prefilter_with_parsed_dk`, reject path, per output | Yes: `rust/shekyl-scanner/src/scan.rs:670` | 2026-06-08, floor: 266 684 ns per output, outcome `fail` (BA-I72) | The FA-6 budgets, 45 s per app open and 20 min for a restore (`rust/shekyl-crypto-pq/examples/fa6_decap_prefilter_gate.rs:42`) | **Keep, tracked** (T3) |
| **BA-I18** | `shekyl-crypto-pq::pqc_rederivation` | Hybrid decapsulation (id says `ml_kem_768_decapsulate`), leaf derivation, key scalar, and their sum | Mixed: the decapsulate entry is not on the wallet scan path | none recorded | The "PQC Rederivation Benchmark" section of [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md), which quotes no number | **Rewrite** — mislabelled id, and the composition is not the one scan runs |
| **BA-I19** | `shekyl-timing-engine::wake_hints` | `Engine::arm` / `clear` / `poll` at 1 to 262 144 armed deadlines | Yes: `rust/shekyl-timing-engine/src/service/mod.rs:652` | 2026-09-26, floor (BA-I90) | The engine-thread budget, which is not yet written (`docs/design/P2P_TIMING_ENGINE.md:204`) | **Keep, tracked** (T3) |
| **BA-I20** | `shekyl-ffi::block_connect_verify`, with `block_connect_fixture.rs` and the fixture pins `rust/shekyl-ffi/tests/block_connect_pins.rs` | Per-transaction verify terms through the FFI exports (admission pair, hybrid signature, a Rust Bulletproofs+ stand-in, parse), a block-budget fill, and one RandomX hash | The exports are what C++ block connect calls today (`src/cryptonote_core/blockchain.cpp:4224`, `:4283`). The Bulletproofs+ term is a Rust proxy for the shipped C++ verifier | 2026-09-05, floor (BA-I77) | The surge factor `S = 4` and the 300 000-byte zone (`config/consensus_constants.json:16`, `:17`) | **Rewrite** — it composes pre-cutover FFI terms; the Rust validator the cutover makes consensus verifies no proof yet (`rust/shekyl-chain-rules/src/rules/tx_against.rs:325`), and the capture predates `PL-D3` (BA-G4) |
| **BA-I21** | `shekyl-ffi::relay_admission_verify` | The BA-I10 pair over 64 cells: depth and layout by 1 to 8 inputs | Yes, as BA-I10 | 2026-08-05, floor; the result grids are not in the tree (`rust/shekyl-relay-privacy/src/verify_cost.rs:46`) | `SPEC_VERIFY_COST`, whose own comment says the floor re-measurement is owed (`rust/shekyl-relay-privacy/src/verify_cost.rs:347`) | **Keep, tracked** (T3) |
| **BA-I22** | `shekyl-p2p-transport::c5` | Noise handshake initiator and responder, seal/open at four sizes, rekey | Yes: `rust/shekyl-clearnet/src/handshake.rs:321`, `:368`. Never compiled in CI: its `c5-bench` feature is enabled nowhere | 2026-09-26, floor (BA-I79) | The clearnet accept-rate bound, which is not yet written (`docs/design/P2P_TRANSPORT_LAYER.md:1522`) | **Keep, tracked** (T3) |
| **BA-I23** | `shekyl-pow-randomx::cache_derive` | `PreparedCache::derive` for one seed | Yes: `rust/shekyl-pow-randomx/src/cache_store.rs:535` | 2026-05-22, x86 dev: 341 ms (`rust/shekyl-pow-randomx/BENCH_RESULTS.md:32`) | The 150–200 ms cache-miss budget (`docs/design/RANDOMX_V2_RUST.md:398`) | **Keep, tracked** — and a floor run is a gap (BA-G9) |
| **BA-I24** | `shekyl-pow-randomx::compute_hash_alloc` | `compute_hash` under two names, and a pooled variant that never ships | `compute_hash` yes: `rust/shekyl-ffi/src/pow_randomx_ffi.rs:228` | 2026-05-22, x86 dev: 296 ms per hash. Its record sets that against the ≤ 100 µs target, which bounds VM allocation and not a hash (`rust/shekyl-pow-randomx/BENCH_RESULTS.md:262`) | Per-block PoW verify cost; no per-hash budget is stated | **Rewrite** — two arms time one function, and there is no per-hash budget for it to report against |
| **BA-I25** | `shekyl-pow-randomx::per_call_alloc` | Mirrors of the VM's two allocations, through `std` directly | No: it does not call the crate's functions | 2026-05-24, x86 dev: 47.75 µs. Never on the floor | The per-call allocation target of ≤ 100 µs, which decides whether a VM pool is added (`docs/design/RANDOMX_V2_RUST.md:500`) | **Retire** — the target is met and the pooling decision is made |
| **BA-I26** | `helioselene` — `rust/shekyl-oxide/crypto/helioselene/benches/helioselene.rs` | Selene point add and field operations, printed from a hand-rolled timer | Indirect, through FCMP++ | none recorded | None found (`grep -rn benches/helioselene docs` finds one audit-trail note) | `n/a` — vendored with the fork and kept or dropped with it ([`10-shekyl-first`](../../.cursor/rules/10-shekyl-first.mdc)); no tracked row is proposed |

### 2.3 Bench-like code outside `benches/`

| Id | Path | Measures | Device, last run | Consumer | Proposed |
| --- | --- | --- | --- | --- | --- |
| **BA-I27** | `rust/shekyl-chain-store/src/store/slash_scan_bench_tests.rs` (`#[ignore]`) | Rust `validate` plus store `connect` per block, ordinary against deadline block, 1 300 blocks, 64 personas | x86 dev, 2026-09-30, 2 runs. Never on the floor | The slash-scan placement ruling ([`DRS_E4_ARCHIVAL_WRITER.md`](../completed/DRS_E4_ARCHIVAL_WRITER.md) §3.1) | **Keep, tracked** (T3) — it is the only timing of the post-cutover connect path |
| **BA-I28** | `rust/shekyl-chain-store/src/store/weights_read_bench_tests.rs` (`#[ignore]`) | Two read shapes for the weight window over 100 000 blocks; the cursor arm is a copy of the function that later landed (`rust/shekyl-chain-store/src/store/read.rs:279`) | floor, 2026-09-27, n = 1: 36.6 ms against 598 ms | The read-shape ruling ([`CHAIN_RULES_SLICE_7.md`](../completed/CHAIN_RULES_SLICE_7.md)); ruled with about ten times headroom | **Retire** — decision made, and the arm no longer times production code |
| **BA-I29** | `rust/shekyl-levin/tests/inbound_cost_bench.rs` (`#[ignore]`) | RSS, high-water RSS and descriptors of a real daemon at 0 to 128 inbound peers | x86 dev and floor; no capture in `docs/benchmarks/` | The inbound ceiling, where a measurement is owed (`docs/FOLLOWUPS.md:1290`) | **Keep, tracked** (T3) |
| **BA-I30** | `rust/shekyl-wire/tests/input_cap_cost.rs` (`#[ignore]`) | Prove and verify for real 1 / 2 / 4 / 8-input spends | x86 dev and floor, 2026-09-24, n = 1 each: on the floor 166.7 ms to verify one input, and 64.9 ms for each added input | The input cap of 8, whose derivation is owed (`docs/FOLLOWUPS.md:141`) | **Keep, tracked** (T3) |
| **BA-I31** | `rust/shekyl-archival-retention/src/challenge_assignment.rs:620` (`#[ignore]`) | Full-epoch challenge replay on reorg, 972 000 draws | none recorded | Not traced | **Keep, tracked** — pending BA-Q12 |
| **BA-I32** | `rust/shekyl-shard-visual/examples/budget_matrix.rs` | Shard render latency, 36 cells; an x86 smoke profile and the floor targets | CI runner per PR (smoke); floor 2026-09-06 (BA-I89) | `FLOOR_TARGETS` (`rust/shekyl-shard-visual/examples/budget_matrix.rs:34`) | **Keep, gated** for the smoke; the floor arm is T3 |
| **BA-I33** | `rust/shekyl-randomx-differential/src/mode_latency.rs`, `rust/shekyl-randomx-differential/tests/worst_case_ratio.rs` | Rust-to-C RandomX latency ratio, typical and adversarial | CI runner, daily and weekly cron | The ratio bounds 3.0 and 5.0 (`rust/shekyl-randomx-differential/src/mode_latency.rs:127`) | **Keep, gated** — no aarch64 leg (BA-G9) |
| **BA-I34** | `rust/shekyl-wss-q1b-bench` (four binaries) | Wallet proving-state edges: spend-time replay against proving, open-time refetch, root read, path assembly | floor and others (BA-I96 to BA-I103) | The spend-edge and open-edge thresholds (`docs/design/WALLET_SIDE_STORE.md:815`, `:816`) | **Keep, tracked** (T3) |
| **BA-I35** | `rust/shekyl-sp-t3-spike` binaries `pd-f2-measure`, `pd-f2-u1b`, `serve-only` | Whole-shard fetch over Tor against the production serve endpoint and fetch client; content verification is stubbed to accept (`rust/shekyl-sp-t3-spike/src/harness.rs:460`) | internal node and floor (BA-I91 to BA-I95) | `W`, `L`, the retry budget, `p_attempt`, and the per-epoch read capacity (§4) | **Rewrite** — every archival latency constant rests on a crate that calls itself disposable, with a verify step that verifies nothing |
| **BA-I36** | `rust/shekyl-tor-transit-spike`, `rust/shekyl-rt-p2-spike/tests/probes.rs` | Tor transit and RPC-transport probes | none recorded in `docs/benchmarks/` | Not traced | **Keep, tracked** — pending BA-Q12 |

### 2.4 Scripts

| Id | Path | Does | Runs where | Proposed |
| --- | --- | --- | --- | --- |
| **BA-I37** | `scripts/bench/capture_rust_baseline.sh` | Runs each `BENCHES` row and writes the envelope | CI, both jobs (BA-D10) | **Keep, gated** |
| **BA-I38** | `scripts/bench/compare.py` | Routes each gungraun entry through its threshold | CI | **Keep, gated** |
| **BA-I39** | `scripts/bench/post_comment.py` | Renders and upserts the PR comment | CI | **Keep, gated** |
| **BA-I40** | `scripts/bench/test_compare.py` | Tests the comparator | Nowhere (BA-D16) | **Keep, gated** — wire it into CI |
| **BA-I41** | `scripts/bench/fa6_pi4_gate.sh` | Runs the FA-6 classifier on the floor and archives its output | By hand, floor | **Rewrite** — BA-D12 |
| **BA-I42** | `scripts/bench/gap7_pi4_gate.sh` | Runs the block-connect bench, its pins and the C++ Bulletproofs+ timer on the floor | By hand, floor | **Rewrite** — BA-D12 |
| **BA-I43** | `scripts/bench/drs_bench.py`, `scripts/bench/drs_artifact.py` | Two-daemon IBD wall time, CPU, RSS and disk; refuses a comparison across differing conditions | By hand, x86 dev | **Keep, tracked** — the redb arm it exists for cannot run yet (`docs/FOLLOWUPS.md:179`) |
| **BA-I44** | `scripts/bench/test_drs_bench.py` | Tests the DRS comparator against the committed artifacts | CI (`.github/workflows/docs-gates.yml:313`) | **Keep, gated** |
| **BA-I45** | `scripts/bench/wss_q1b_regtest_open_edge.sh` | Mines coinbase-only blocks and runs the open-edge binary; "not a grading instrument" by its own header | By hand | **Keep, tracked** |
| **BA-I46** | `scripts/remote-bench.sh` | Runs a `cargo bench` on a remote host without truncating its output | By hand | **Keep, tracked** — it is the transport the T3 runs use |
| **BA-I47** | `scripts/ci/check_bench_not_a_dependency.py` | Refuses a production dependency on the WSS bench crate | CI (`.github/workflows/docs-gates.yml:624`) | **Keep, gated** |

### 2.5 CI jobs

| Id | Workflow and job | Runs | Gates? | Proposed |
| --- | --- | --- | --- | --- |
| **BA-I48** | `benchmarks.yml` `capture-pr` and `compare` | BA-I37 to BA-I39 on the PR head | Yes, per PR, on the path filter | **Keep, gated** — BA-D1 |
| **BA-I49** | `benchmarks.yml` `profile-on-fail` | Re-runs the tripped bench's criterion sibling under a sampler | No | **Keep, tracked** |
| **BA-I50** | `benchmarks.yml` `update-baseline` | Refreshes `bench-baseline` on push to `dev` | Feeds the gate | **Keep, gated** — BA-D1 applies to it equally |
| **BA-I51** | `rust-audit-test.yml`, step `shard-visual-x86-smoke` (`.github/workflows/rust-audit-test.yml:467`) | BA-I32, smoke profile | Yes, per PR; it cannot bound the floor | **Keep, gated** |
| **BA-I52** | `randomx-v2-differential.yml`, latency mode (`.github/workflows/randomx-v2-differential.yml:552`) | BA-I33, typical ratio | Yes, daily cron | **Keep, gated** |
| **BA-I53** | `randomx-v2-adversarial-ratio.yml` (`.github/workflows/randomx-v2-adversarial-ratio.yml:215`) | BA-I33, adversarial ratio | Yes, weekly cron | **Keep, gated** |
| **BA-I54** | `docs-gates.yml` | BA-I44 and BA-I47 | Yes; harness structure, not timings | **Keep, gated** |
| **BA-I55** | `build.yml` ctest (`.github/workflows/build.yml:479`) | `wallet-crypto-bench` (BA-I57), correctness only | Yes, on a mismatch | follows BA-I57 |

### 2.6 C++

| Id | Path | Measures | State | Consumer | Proposed |
| --- | --- | --- | --- | --- | --- |
| **BA-I56** | `tests/performance_tests/` | Monero-lineage primitives: hash checks, ed25519 group and scalar operations, the CryptoNote signature, key derivation and key image, Bulletproofs+ prove and verify, multiexp | Built (`tests/CMakeLists.txt:74`) and never run: no `add_test`, no workflow. The signature, key-derivation, key-image and Bos-Coster subjects have no caller under `src/` (`tests/performance_tests/main.cpp:112`, `:119`, `:178`). `range_proof.h` is an unreferenced stub | None. A deletion-or-adoption audit has been open since 2026-07-03 (`docs/FOLLOWUPS.md:666`) | **Retire** — [`60-no-monero-legacy`](../../.cursor/rules/60-no-monero-legacy.mdc). The one live consensus subject, the shipped Bulletproofs+ verifier, is timed by BA-I58 |
| **BA-I57** | `tests/benchmark.cpp` (`shekyl-wallet-crypto-bench`) | `generate_key_derivation` across two library builds | Runs in every PR's ctest (`tests/CMakeLists.txt:213`) with no timing threshold; its subject has no caller under `src/` | None | **Retire** — rule 60 |
| **BA-I58** | `tests/unit_tests/gap7_bp_bench.cpp` (`tests/unit_tests/gap7_bp_bench.cpp:71`) | The shipped C++ Bulletproofs+ verifier, single and batched | Disabled in ctest; run by BA-I42 on the floor, 2026-09-05 | The Bulletproofs+ term in the `S = 4` composition | **Keep, tracked** (T3) until the cutover retires the C++ verifier |

### 2.7 Baselines, manifests and records

| Id | Path | Is | Read by | Proposed |
| --- | --- | --- | --- | --- |
| **BA-I59** | `bench-baseline:baseline.json`, `baseline.iai.snapshot`, `README.md` | The rolling baseline | The gate | **Keep, gated** |
| **BA-I60** | `docs/benchmarks/shekyl_rust_v0.json`, `shekyl_rust_v0.iai.snapshot` | A 2026-05-03 x86 dev capture | Nothing: the scripts write these paths and CI uploads fresh copies, but no reader opens the committed content | **Retire** — BA-D5 |
| **BA-I61** | `docs/benchmarks/shekyl_rust_v0.manifest.md` | Per-bench operation lists | Bench headers and the README link to it | **Rewrite** — it names a renamed bench, calls shipped benches deferred, and has no section for four gated rows |
| **BA-I62** | `docs/benchmarks/wallet2_baseline_v0.manifest.md` | The retired C++ harness's specification; no numbers | The Rust manifest cross-references it | **Retire** — its harness is deleted; git history is the archive |
| **BA-I63** | `docs/benchmarks/reference-captures/` (`README.md`, `stage-0-pr-2-c4c-shekyl_rust_v0.json`) | The CI-runner capture behind the frozen Stage-0 numbers | [`PERFORMANCE_BASELINE.md`](../PERFORMANCE_BASELINE.md) | follows BA-I64 |
| **BA-I64** | `docs/PERFORMANCE_BASELINE.md` | Frozen Stage 0–2 wallet numbers and the FA-6 table | [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md); `docs/FOLLOWUPS.md:545` | **Rewrite** — it frames eight wallet benches, three of which have never produced a number, and holds no figure for anything outside the wallet but FA-6 |
| **BA-I65** | `docs/benchmarks/README.md` | The directory's index and the gate's description | — | **Rewrite** — BA-D2, BA-D4, BA-D5, BA-D6 |
| **BA-I66** | `rust/shekyl-pow-randomx/BENCH_RESULTS.md` | The 2026-05-22 x86 dev RandomX record | The RandomX plans | **Rewrite** with BA-I24; it links two plan docs at paths they have left |
| **BA-I67** | `docs/investigation/2026-05-09-bench-baseline-flake.md` | The root-cause record for a capture anomaly | The capture script and workflow cite it | `n/a` |
| **BA-I68** | `docs/benchmarks/D5_TOR_STEM_RUNBOOK.md` | The command sequence for the Tor stem-hop run, with one run recorded (n = 1) | `docs/FOLLOWUPS.md:65` | **Keep, tracked** — it is the protocol for BA-T9 |

### 2.8 Dated captures in `docs/benchmarks/`

No script, workflow or schedule re-runs any measurement in this table. Where
a "reopen if p99 exceeds X" rule exists it is prose; nothing evaluates it.
Devices are as each file, or the document that summarises it, records them.

Landed after the pin and so not rows here: the 2026-10-05 serve-cost record
and its two observation files (BA-G1). They are the first evidence for
BA-T5.

| Id | File | Measures (n) | Device | Consumer | Proposed |
| --- | --- | --- | --- | --- | --- |
| **BA-I69** | `drs_bench_ibd_lmdb_h2000_x86_64_20260913T192136Z.json` | IBD to height 2 001, LMDB, coinbase-only, one peer: 226.8 s wall | x86 dev, NVMe | The first LMDB baseline for the IBD floor ([`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) §7.4) | **Keep, tracked** |
| **BA-I70** | `drs_bench_ibd_lmdb_h2000_x86_64_20260913T192638Z.json` | The same run repeated: 215.6 s | x86 dev | as BA-I69 | **Keep, tracked** |
| **BA-I71** | `drs_bench_ibd_lmdb_h200_x86_64_20260913T193129Z.json` | IBD to height 201: 22.4 s | x86 dev | as BA-I69 | **Keep, tracked** |
| **BA-I72** | `fa6_decap_prefilter_pi4_fa6_b_20260608T220614Z.txt` | FA-6 pre-filter, restore scenario: 266 684 ns per output over 525 960 000 outputs, outcome `fail` | floor, with `-C target-cpu=cortex-a72` | The decision to ship FA-6 over its budget (`docs/PERFORMANCE_BASELINE.md:808`) | **Rewrite** — captured under `RUSTFLAGS` that are not the shipping configuration (BA-D12), and before `PL-D3` |
| **BA-I73** | `gap7_block_verify_pi4_cpp_20260905T053148Z.txt` | Shipped C++ Bulletproofs+ verify: 13.6 ms at 2 outputs, 1.75 ms per proof batched (21 runs) | floor | The `S = 4` composition | **Keep, tracked** |
| **BA-I74** | `gap7_block_verify_pi4_pins_20260905T032729Z.txt` | Fixture pins, no timing | floor, non-shipping flags | None by name | **Retire** — superseded by BA-I75 |
| **BA-I75** | `gap7_block_verify_pi4_pins_20260905T175137Z.txt` | Fixture pins, no timing | floor | Provenance for BA-I77 | **Keep, tracked** |
| **BA-I76** | `gap7_block_verify_pi4_rust_20260905T034720Z.txt` | Verify terms under non-shipping flags; ends in an illegal-instruction crash | floor | The bench header still quotes its 128.97 ms figure beside the canonical 126.05 ms | **Retire** — superseded by BA-I77 |
| **BA-I77** | `gap7_block_verify_pi4_rust_20260905T181144Z.txt` | Verify terms and block-budget fill: admission pair 126.05 ms at 1-in/2-out, one RandomX hash 1.2845 s (10 samples per point) | floor, at `8af70a60a` | `block_weight_short_term_surge_factor = 4` and the 300 000-byte zone (`config/consensus_constants.json:16`, `:17`); the read-shape rule in BA-I28 | **Rewrite** — pre-`PL-D3` (BA-G4) |
| **BA-I78** | `lv3_950_clearnet_pair_20261004.md` | A one-hour functional run of two clearnet nodes; not a timing distribution | not recorded | None found (`grep -rn lv3_950 docs rust src scripts`) | `n/a` |
| **BA-I79** | `p2p_c5_pi4_20260926T005507Z.txt` | Transport handshake and AEAD: responder 685 µs, initiator 928 µs (10 samples) | floor | The clearnet accept-rate bound, not yet written (`docs/FOLLOWUPS.md:954`) | **Keep, tracked** |
| **BA-I80** | `p2p_clearnet_lan_floor_initiator_run1_20260930.tsv` | Clearnet dial and handshake spans, LAN (100) | floor dialer, x86 responder | Input to the node-local residual; does not bind | **Keep, tracked** |
| **BA-I81** | `p2p_clearnet_lan_floor_initiator_run2_20260930.tsv` | As BA-I80 with pre-write spans (100) | as BA-I80 | as BA-I80 | **Keep, tracked** |
| **BA-I82** | `p2p_clearnet_lan_floor_responder_20260930.tsv` | Responder-side spans (100) | x86 dialer, floor responder | as BA-I80 | **Keep, tracked** |
| **BA-I83** | `p2p_clearnet_nyc_floor_initiator_20260930.tsv` | Clearnet dial to a datacenter peer: residual 7.2 ms (100) | floor dialer | Clearnet dial 1.415 s and gap 1.430 s (`src/p2p/net_node.inl:3445`, `:3447`) | **Keep, tracked** |
| **BA-I84** | `p2p_clearnet_wan_floor_initiator_20260930.tsv` | Clearnet dial over a 170 ms path: handshake residual 12.6 ms (100) | floor dialer | Clearnet handshake 1.426 s (`src/p2p/net_node.inl:3446`) | **Keep, tracked** |
| **BA-I85** | `p2p_cutover_crossbuild_20260929.md` | The summaries and derivations for BA-I80 to BA-I88 | per section | Cited from the constants' own comment (`src/p2p/net_node.inl:3429`) | **Keep, tracked** |
| **BA-I86** | `p2p_tor_dial_floor_20260929.tsv` | Tor dial: p99 4.54 s; gap p99 1.26 s (100) | floor dialer, off-site peer | Tor dial and shutdown 9.1 s, Tor gap 2.6 s (`src/p2p/net_node.inl:3448`, `:3449`); the proxied clearnet dial borrows the 9.1 s (`docs/FOLLOWUPS.md:77`) | **Keep, tracked** |
| **BA-I87** | `p2p_tor_inbound_floor_20260930.tsv` | Tor inbound, both circuit ends on one device (67) | floor | None: its summary marks it superseded and unused | **Retire** — superseded by BA-I88 |
| **BA-I88** | `p2p_tor_inbound_floor_distant_20260930.tsv` | Tor inbound from a distant dialer: gap p99 1.22 s (110) | floor responder | The smaller of the two Tor gaps; does not bind | **Keep, tracked** |
| **BA-I89** | `shard_visual_budget_matrix_pi4_20260906T090000Z.txt` | Shard render, 36 cells, median of 5: worst 12.44 s at 1 024 px | floor | `FLOOR_TARGETS` (BA-I32); a standing manual re-run trigger (`docs/FOLLOWUPS.md:1132`) | **Keep, tracked** |
| **BA-I90** | `timing_engine_wake_hints_pi4_20260926T003745Z.txt` | Timer arm and poll, 1 to 262 144 deadlines (10 samples) | floor | The engine-thread budget, not yet written | **Keep, tracked** |
| **BA-I91** | `u1b_control_20261002.tsv` | Whole-shard fetch over Tor, control arm (1 904) | internal node, not the floor | The `U1b` reading ([`ARCHIVAL_SHARD_T_DERIVATION.md`](../completed/ARCHIVAL_SHARD_T_DERIVATION.md) §10.8) | **Rewrite** — measured on the pre-#954 serve path (BA-G3) |
| **BA-I92** | `u1b_floor_device_20261002.tsv` | The same with reader and server on one device (1 846): 1.95 % missed; 18 229 pairs per epoch | floor | `W` stands; the read-capacity figure (`docs/FOLLOWUPS.md:109`) | **Rewrite** — BA-G3 |
| **BA-I93** | `w2_ladder_interleaved_pow_off_20261001.tsv` | Fetch-time ladder by object size (955) | internal node | The `W` derivation | **Rewrite** — BA-G3; not a floor run |
| **BA-I94** | `w2_ladder_interleaved_pow_on_20261001.tsv` | The governing arm (955): 13 of 319 missed at 1× | internal node | `W = 3 000 000` and `p_attempt = 0.30` | **Rewrite** — BA-G3 |
| **BA-I95** | `w2_ladder_soak_pow_off_20260930.tsv` | Soak (1 466) | internal node | `L = 4` and the two-retry budget | **Rewrite** — BA-G3 |
| **BA-I96** | `wss-q1b/assemble_edge_20261002T052942Z.json` | Path assembly: 103 to 169 s per call (6 per arm) | an x86 virtual machine; the revision stamp is known stale (`docs/FOLLOWUPS.md:26`) | [`CT6_PROVING_STATE.md`](CT6_PROVING_STATE.md) | **Rewrite** — wrong device |
| **BA-I97** | `wss-q1b/assemble_edge_20261002T052942Z.txt` | Summary of BA-I96 | — | None by name | follows BA-I96 |
| **BA-I98** | `wss-q1b/spend_edge_20260927T195848Z.json` | Spend-time replay 388.8 s (5, not converged) against proving 6.05 s (10) | floor | The spend-edge threshold; ungraded (`docs/FOLLOWUPS.md:1253`) | **Keep, tracked** |
| **BA-I99** | `wss-q1b/spend_edge_20260927T195848Z.txt` | Summary of BA-I98 | floor | as BA-I98 | follows BA-I98 |
| **BA-I100** | `wss-q1b/spend_edge_20260929T133841Z.json` | The same off the rig, from a dirty tree: proving 1.09 s | x86 dev | [`CT6_PROVING_STATE.md`](CT6_PROVING_STATE.md) | **Keep, tracked** |
| **BA-I101** | `wss-q1b/verify_edge_20260927T195848Z.txt` | Root read, worst case: 393.9 s unfrozen, 8.8 s frozen | not recorded in the file | [`WSS_Q1B_BENCH_SPEC.md`](WSS_Q1B_BENCH_SPEC.md) §7.3 | **Keep, tracked** |
| **BA-I102** | `wss-q1b/verify_nominal_20260927T235515Z.json` | Root read, nominal density: 53.7 s unfrozen, 0.6 s frozen | floor | as BA-I101 | **Keep, tracked** |
| **BA-I103** | `wss-q1b/verify_nominal_20260927T235515Z.txt` | Summary of BA-I102 | — | as BA-I101 | follows BA-I102 |

### 2.9 `shekyl-gui-wallet`

| Id | Subject | State at `447908f` | Proposed |
| --- | --- | --- | --- |
| **BA-I104** | Benchmarks, timing harnesses, performance CI | None. Checked by: `git ls-files` filtered on `bench`, `perf`, `lighthouse`, `profil`, `timing` (no file); `package.json` scripts (`test` is `vitest run`; no bench script and no bench, lighthouse, playwright or webdriver dependency); `git grep` for `vitest bench`, `bench(`, `criterion`, `performance.now`, `performance.mark`, `console.time` (no hit in source); the five workflows under `.github/workflows/` (none mentions a benchmark); `src-tauri/Cargo.toml` (no `[[bench]]`). No document in the repository states a latency budget | **Add** — BA-G14 |

## 3. Gaps

A gap is a measurement that a ruled constant, a capacity figure or a
floor-device budget rests on, with no tracked benchmark behind it. Each row
names the decision and the code path. A constant derived from a single
capture counts as a gap until a tracked T3 run reproduces it.

| Id | What is not measured | The decision it feeds | Code path | State of the evidence |
| --- | --- | --- | --- | --- |
| **BA-G1** | Serve cost per response on the v3 path: CPU and wall-clock, by shard size and by responses in flight | Serve-side `MAX_INFLIGHT` (`rust/shekyl-p-serve/src/serve.rs:122`); the read capacity one device sustains per epoch (`docs/FOLLOWUPS.md:109`); the inputs to `W` and `L` | `digest_body`, `resolve_body`, `write_response` (`rust/shekyl-p-serve/src/serve.rs:505`, `:542`, `:642`) | Two floor runs on 2026-10-05, recorded in [`sfd8_serve_cost_floor_device_20261005.md`](../benchmarks/sfd8_serve_cost_floor_device_20261005.md) (landed after this document's pin, by PR #968). One full segment over loopback from an on-disk store, warm cache, arms alternating: median per response 24.8 ms before #954 and 104.2 ms after, 103.1 ms after #961; CPU per response 30–36 ms against 110–113 ms; at 8 in flight, 74–84 responses per second against 37–38. The digest alone is 23.9 ms per pass and runs twice; the other 30 ms or so, the second read among it, is not separately timed. Not covered: a cold cache, Tor, a daemon alongside, other shard sizes, more than 8 in flight. No bench of the serve path exists in `rust/shekyl-p-serve`, `shekyl-p-fetch` or `shekyl-p-host`; the probe was built on the device and is quoted in that record, not committed as a target. `ci/benchmarks` ran on #954's head and passed. At the pin every production response pays this cost and is then refused: the persona key is not yet wired (BA-Q3) |
| **BA-G2** | Client verify cost per fetched shard: the delivery digest, the hybrid countersignature check, and content verification | Fetch-side `MAX_INFLIGHT = 8` (`rust/shekyl-p-fetch/src/client.rs:60`); the cost every witness pays per assigned pair | `rust/shekyl-p-fetch/src/client.rs:297`, `:298`, `:308`; the `ContentVerify` trait (`rust/shekyl-p-fetch/src/target.rs:96`) | Never measured. No production `ContentVerify` exists; the only implementation accepts everything (`rust/shekyl-sp-t3-spike/src/harness.rs:460`), so no archival latency figure includes it. The digest pass is new in #954. The cap's memory argument compares against the floor by arithmetic (`rust/shekyl-p-fetch/src/client.rs:45`), and its design has since changed to a streaming verify that is not built (`docs/design/ARCHIVAL_SHARD_FETCH.md:850`) |
| **BA-G3** | Whole-shard fetch time and miss rate over Tor on the v3 serve path | `archival_shard_length_bytes = 3 000 000` and `archival_attestation_anchor_lag_blocks = 4` (`config/consensus_constants.json:40`, `:37`); the two-retry budget (`docs/completed/ARCHIVAL_SHARD_T_DERIVATION.md:2110`); `p_attempt = 0.30`; the 18 229-pair capacity | BA-G1's serve path and `PFetchClient::fetch` (`rust/shekyl-p-fetch/src/client.rs:225`) | BA-I91 to BA-I95, all before #954. The ladder ran on an internal node, not the floor. The 2026-10-05 record (BA-G1) sets the 78 ms that #954 added beside the same device's Tor reads of the same object (median 14.8 s): 0.5 % of a read, so the fetch-time inputs to `W` and `L` are unlikely to have moved, while serve throughput at 8 in flight halved. Neither was re-measured over Tor. A re-measurement "at the gate" is named as a reopen condition (`docs/design/CLIENT_VERSION_CONSTANTS_VALIDATION.md:947`) with no date, rig or owner |
| **BA-G4** | Transaction and block verify cost on the floor after `PL-D3` | The surge factor 4 and the 300 000-byte zone (`config/consensus_constants.json:16`, `:17`); `SPEC_VERIFY_COST`, the hop and the embargo (`rust/shekyl-relay-privacy/src/verify_cost.rs:349`); the input cap (`src/cryptonote_config.h:316`) | `shekyl_fcmp_verify` (`rust/shekyl-ffi/src/legacy_fcmp.rs:390`), called at `src/cryptonote_core/blockchain.cpp:4224` | BA-I77 was captured at `8af70a60a`, 2026-09-05; `PL-D3` (`20738bf714`, 2026-09-14) is not an ancestor of it and "moved every shape" (`rust/shekyl-relay-privacy/src/verify_cost.rs:346`). The depth-24 cost `S = 4` is signed on is composed from per-layer slopes, not measured. Carriers already open: `docs/FOLLOWUPS.md:65`, `:917`, `:964` |
| **BA-G5** | The validation path the cutover makes consensus: Rust `validate` and store `connect`, with proof verification in it | The cutover itself; its only performance acceptance is the DRS-BENCH suite ([`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) §8.1, `docs/design/DAEMON_REDB_STORE.md:2079`) | `rust/shekyl-chain-rules/src/validate.rs:355`, `:558`, `:622`; `rust/shekyl-chain-store/src/store/connect.rs:170` | The FCMP++ and Bulletproofs+ rows are still pending in the Rust validator (`rust/shekyl-chain-rules/src/census.rs:445`, `:476`). The Rust batch verifier it would use has never run on the floor. BA-I27 and BA-I28 are the only timings, on a fixture with no proofs |
| **BA-G6** | Chain store on redb: write and read per block, IBD rate | The IBD floor, redb ≤ 1.25× LMDB (`docs/design/DAEMON_REDB_STORE.md:398`) | `rust/shekyl-chain-store/src/store/connect.rs:170` | BA-I69 to BA-I71: LMDB only, x86 dev, coinbase-only. The redb arm waits on a build target (`docs/FOLLOWUPS.md:179`). The floor is specified on x86 by design (`docs/design/DAEMON_REDB_STORE.md:396`); no floor-device IBD figure exists. Reorg cost has no threshold, deliberately (`docs/design/DAEMON_REDB_STORE.md:430`) |
| **BA-G7** | The P2P deadline distributions, re-measured | Clearnet dial, handshake and gap; Tor dial, gap and shutdown (`src/p2p/net_node.inl:3445` to `:3449`) | `dial_one` in `rust/shekyl-clearnet/src/drive.rs:207` and `rust/shekyl-tor/src/drive.rs:157` | BA-I80 to BA-I88: one capture each, n ≈ 100, floor. Each carries a reopen rule that nothing evaluates. The proxied clearnet dial is unmeasured (`docs/FOLLOWUPS.md:77`) |
| **BA-G8** | The Tor stem hop: transit and node-local time as a distribution | `ANON_ZONE_TRANSIT_ASSUMPTION_MS = 1 625` and `ADOPTED_TRANSIT_ASSUMPTION_MS = 50` (`rust/shekyl-relay-privacy/src/verify_cost.rs:560`, `:465`), and through them the embargo and `ADOPTED_PROPAGATION_TIMEOUT_SECS = 2 297` (`rust/shekyl-relay-privacy/src/schedule.rs:473`) | The Tor-edge embargo (`rust/shekyl-relay/src/graph/edge.rs:537`) | One stem, n = 1 (BA-I68). Carrier open: `docs/FOLLOWUPS.md:65` |
| **BA-G9** | RandomX on the floor: per-hash verify and cache derivation | The floor's per-block PoW verify budget and its tip-advance stall at an epoch boundary (`rust/shekyl-difficulty/src/seed_epoch.rs:37`); the dataset-mode decision | `compute_hash` (`rust/shekyl-ffi/src/pow_randomx_ffi.rs:228`); `PreparedCache::derive` (`rust/shekyl-pow-randomx/src/cache_store.rs:535`) | One floor figure, 1.2845 s per hash, a by-product of BA-I77. Cache derivation has never run on the floor; on x86 dev it is 341 ms against a 150–200 ms budget. No budget is stated for the floor, and the ratio gates (BA-I33) run on x86 only |
| **BA-G10** | Thread budgets under load | `workers = 2`, `blocking = 1` (`src/p2p/net_node.inl:3452`, `:3453`), described in place as a structural floor | The transport pool and the timing-engine service | Unmeasured. Carrier open: `docs/FOLLOWUPS.md:69` |
| **BA-G11** | Inbound connection cost and accept rate | The inbound ceiling and the clearnet accept-rate bound, neither yet a number | BA-I29's subject; the handshake in BA-I22 | Carriers open: `docs/FOLLOWUPS.md:954`, `:1290` |
| **BA-G12** | Wallet open on the floor at the default KDF | The Argon2id default (`rust/shekyl-crypto-pq/src/wallet_envelope.rs:135`), sized for a commodity desktop | `WalletFile::open` (`rust/shekyl-engine-core/src/engine/lifecycle/open.rs:137`) | No floor figure. The gated arm cannot see the default (BA-D11) |
| **BA-G13** | Transfer build end to end, on the floor | Send latency; [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) states "~2-5 seconds" with no source | `sign_transaction` and the proof inside it (`rust/shekyl-tx-builder/src/sign.rs:57`, `:171`) | One floor figure, 6.05 s to prove a 2-input spend, a by-product of BA-I98. Nothing tracks it |
| **BA-G14** | GUI wallet: startup to usable, sync-progress overhead, send flow, shard render | User-facing latency; no budget is stated for any of them | `gui:src-tauri/src/lifecycle.rs:153` (`open_wallet`), `gui:src-tauri/src/wallet_care.rs:42` (`refresh`), `gui:src-tauri/src/send.rs:265` and `:297` (`build_pending_tx`, `submit_pending_tx`), `gui:src-tauri/src/shard_coverage.rs:74` (`get_shard_render`) | Nothing measured (BA-I104) |
| **BA-G15** | Wallet scan rate on the floor at the shipping configuration | The FA-6 budgets (BA-I17) | `rust/shekyl-scanner/src/scan.rs:670` | BA-I72: one capture, June 2026, non-shipping flags, outcome `fail`. The quick-sync scenario is quoted only in [`PERFORMANCE_BASELINE.md`](../PERFORMANCE_BASELINE.md) |
| **BA-G16** | Per-block admission cost of attestation records | `ARCHIVAL_MAX_ATTESTATION_RECORDS = 256` (`src/cryptonote_config.h:444`), justified in place as bounding that cost | The coinbase admission path | No measurement found |

## 4. Constants justified by a cost or a latency

Each row is covered by a tracked measurement, by a gap, or by a stated reason
it needs neither. "Tracked today" means a run that would notice the cost
moving; at the pin only the first row has one.

| Constant | Defined | Rests on | Measured where | Tracked today | Covered by |
| --- | --- | --- | --- | --- | --- |
| Hop term, clearnet 175 ms; embargo | `rust/shekyl-relay-privacy/src/verify_cost.rs:349` | Modal admission verify, 124.5 ms | floor, 2026-08-05, pre-`PL-D3` | BA-I10, instruction counts on a CI runner; the floor figure is not | BA-G4, BA-T1, BA-T10 |
| `block_weight_short_term_surge_factor = 4` | `config/consensus_constants.json:16` | Worst cold-block verify within a third of the block time | floor, 2026-09-05, pre-`PL-D3` | No | BA-G4, BA-T2, BA-T10 |
| `block_weight_full_reward_zone_bytes = 300 000` | `config/consensus_constants.json:17` | Zone-point block verifies in 7.23 s | as above | No | BA-G4, BA-T10 |
| `FCMP_MAX_INPUTS_PER_TX = 8` | `src/cryptonote_config.h:316` | "bounds proof generation time and tx size"; derivation owed | floor and x86 dev, 2026-09-24, n = 1 | No | `docs/FOLLOWUPS.md:141`, BA-T10 |
| Maximum tree depth 24 | `rust/shekyl-fcmp/src/lib.rs:50` | Proving cost and proof size | Nothing past depth 7 | No | BA-G4 |
| `ARCHIVAL_MAX_ATTESTATION_RECORDS = 256` | `src/cryptonote_config.h:444` | Per-block admission cost | Not measured | No | BA-G16 |
| IBD floor, redb ≤ 1.25× LMDB | `scripts/bench/drs_artifact.py:29` | Slower IBD means fewer full nodes | x86 dev, LMDB arm only | No | BA-G6, BA-T13 |
| Read shape for the weight window | ruled in [`CHAIN_RULES_SLICE_7.md`](../completed/CHAIN_RULES_SLICE_7.md) | ≤ 5 % of zone-point verify; measured 0.5 % | floor, 2026-09-27, n = 1 | No | None needed: about ten times headroom, and the denominator is BA-G4's |
| Slash-scan placement | ruled in [`DRS_E4_ARCHIVAL_WRITER.md`](../completed/DRS_E4_ARCHIVAL_WRITER.md) | About 10 ms once per epoch | x86 dev only | No | BA-T12 |
| RandomX cache derivation ≤ 200 ms; cache-miss budget 150–200 ms | `docs/design/RANDOMX_V2_RUST.md:499`, `:398` | One-off stall at an epoch boundary | x86 dev: 341 ms | No | BA-G9, BA-T14 |
| RandomX per-call VM allocation ≤ 100 µs | `docs/design/RANDOMX_V2_RUST.md:500` | Whether to add a VM pool | x86 dev: 47.75 µs | No | None needed on x86: met with about twice the headroom. Not measured on the floor (BA-G9) |
| RandomX ratio bounds 3.0 and 5.0 | `rust/shekyl-randomx-differential/src/mode_latency.rs:127` | Verification-DoS bound against the C reference | CI runner, cron | Yes, x86 only | BA-I33, BA-G9 |
| FA-6 budgets: 45 s, 20 min, margin 0.20 | `rust/shekyl-crypto-pq/examples/fa6_decap_prefilter_gate.rs:42` | User-facing sync time | floor, 2026-06-08, outcome `fail` | No | BA-G15, BA-T16 |
| Argon2id default: 64 MiB, t = 3 | `rust/shekyl-crypto-pq/src/wallet_envelope.rs:135` | "under ~500 ms on a commodity desktop" | Not on the floor | No | BA-G12, BA-T17 |
| Spend edge ≤ max(2 s, 15 % of proving); open edge ≤ 5 s | `docs/design/WALLET_SIDE_STORE.md:815`, `:816` | Maintainer judgment, stated as such | floor, 2026-09-27, ungraded | No | `docs/FOLLOWUPS.md:1253`, BA-T19 |
| Key-dispatch ratio ≤ 1.05 | [`PERFORMANCE_BASELINE.md`](../PERFORMANCE_BASELINE.md) | Mailbox overhead against decapsulation | CI runner | The baseline arm only | BA-I8, BA-T28 |
| Serve-side `MAX_INFLIGHT = 64` | `rust/shekyl-p-serve/src/serve.rs:122` | Nothing: a declared placeholder | Did not bind at ≤ 32 readers on x86 hosts, on the spike's serve loop; on the floor device at N = 64 exactly, one refusal in 6,144 for a requester that reconnects as its last stream closes (`BA-T5` session 2, 2026-10-09) | No | BA-G1, BA-T5, BA-Q4 |
| Fetch-side `MAX_INFLIGHT = 8` | `rust/shekyl-p-fetch/src/client.rs:60` | Largest non-churning width, and floor memory by arithmetic | 2026-09-16; device not recorded; pre-#954 | No | BA-G2, BA-T6 |
| `archival_shard_length_bytes = 3 000 000` | `config/consensus_constants.json:40` | Fetch time and miss rate by size | internal node and floor, pre-#954 | No | BA-G3, BA-T7 |
| `archival_attestation_anchor_lag_blocks = 4` | `config/consensus_constants.json:37` | Fetch span plus skew | internal node, pre-#954 | No | BA-G3, BA-T7 |
| Retry budget, 2 retries; `p_attempt = 0.30` | `docs/completed/ARCHIVAL_SHARD_T_DERIVATION.md:2110`; `rust/shekyl-economics-sim/src/mn_feasibility.rs:410` | The same ladder | internal node, pre-#954 | No | BA-G3, BA-T7 |
| Read capacity, 18 229 pairs per device per epoch | `docs/FOLLOWUPS.md:109` | One read in flight | floor, 2026-10-03, pre-#954 | No | BA-G1, BA-T5 |
| `CHALLENGE_RESPONSE_BLOCKS = 500` | `rust/shekyl-archival-retention/src/constants.rs:180` | A latency argument | — | No | None needed: ruled as not resting on a measurement (`rust/shekyl-archival-retention/src/constants.rs:137`) |
| Clearnet dial 1.415 s, handshake 1.426 s, gap 1.430 s | `src/p2p/net_node.inl:3445` | Twice a 700 ms path ceiling plus the node-local residual | floor, 2026-09-30, n = 100 | No | BA-G7, BA-T8 |
| Tor dial and shutdown 9.1 s; Tor gap 2.6 s | `src/p2p/net_node.inl:3448`, `:3449` | Twice the measured p99 | floor, 2026-09-29 and 09-30, n ≈ 100 | No | BA-G7, BA-T8 |
| `workers = 2`, `blocking = 1` | `src/p2p/net_node.inl:3452` | A structural floor, pending measurement | Not measured | No | BA-G10, BA-T11 |
| Anonymity-zone transit 1 625 ms; clearnet transit 50 ms | `rust/shekyl-relay-privacy/src/verify_cost.rs:560`, `:465` | Assumptions, declared as such | One stem, n = 1 | No | BA-G8, BA-T9 |
| `fluff_return_ms = 3 250` | `rust/shekyl-relay-privacy/src/params.rs:397` | A simulation on an earlier graph | Simulated | No | BA-G8 |
| `ADOPTED_PROPAGATION_TIMEOUT_SECS = 2 297` | `rust/shekyl-relay-privacy/src/schedule.rs:473` | Derived from the three rows above | — | No | BA-G4, BA-G8 |
| `PI4_AES_BYTES_PER_SEC` | `rust/shekyl-relay-privacy/src/verify_cost.rs:295` | Floor AES throughput | floor, 2026-08-21; no capture in the tree | No | BA-T10 |
| `P2P_ANON_FAILED_ADDR_FORGET_SECONDS = 240`; `P2P_DEFAULT_SOCKS_CONNECT_TIMEOUT = 45` | `src/cryptonote_config.h:257`, `:196` | Measured recovery and connect behaviour of Tor hidden services (n = 20 and n = 60) | An isolated fleet; inline in [`Q12_D6A_PEER_DISCOVERY_RUN.md`](Q12_D6A_PEER_DISCOVERY_RUN.md) | No | None proposed: they time Tor's protocol, not device work; a Tor version change is the trigger (BA-Q13) |
| Shard-render `FLOOR_TARGETS` | `rust/shekyl-shard-visual/examples/budget_matrix.rs:34` | Twice the worst floor median | floor, 2026-09-06 | x86 smoke only | BA-I32, BA-T18 |
| Write-stall deadline | design only (`docs/design/LV3_CONNECTION_OBJECT.md:30`) | A distribution that does not exist yet | — | No | The design defers the number until samples exist; BA-T8 collects them |
| Clearnet accept-rate bound; inbound ceiling | design only | Handshake cost per connection; memory and descriptors per peer | floor, 2026-09-26 (handshake) | No | BA-G11, `docs/FOLLOWUPS.md:954`, `:1290` |

**`config/consensus_constants.json`, the remaining keys.** Four of its 28
keys appear above. Of the other 24, two — `archival_failure_window_m` and
`archival_failure_window_n` — are provisional until re-pinned against a
measured outage-duration distribution at the Round-2 testnet gate; that is
an observation of the network, not a cost a benchmark can produce, and none
is proposed. The remaining 22 carry no cost or latency rationale in their
comment field: `fcmp_reference_block_min_age`,
`fcmp_reference_block_max_age`, `ct_type_fcmp_plus_plus_pqc`,
`daa_window_n`, `daa_target_seconds`, `daa_ftl_seconds`, `daa_mtp_window`,
`daa_genesis_difficulty`, `block_weight_long_term_window_blocks`,
`block_weight_short_term_window_blocks`, `archival_bond_floor_atomic`,
`settlement_epoch_blocks`, `max_settlement_epochs_per_emission`,
`max_claim_age_w`, `retention_horizon_blocks`,
`archival_reorg_depth_blocks`, `release_cooldown_epochs`,
`archival_max_holdings_shards`, `bond_duration_base_epochs`,
`bond_duration_age_scale`, `archival_reward_age_weight_milli`,
`segment_leaf_count`. Their owning documents were not each re-read for a
cost argument made outside the comment field (§7).

**Economics and staking simulators.** No document states that a
simulator's turnaround blocks a ruling, and neither crate holds timing code
(`grep -rln 'Instant::now' rust/shekyl-economics-sim rust/shekyl-staking-sim`
returns nothing). No benchmark is proposed.

## 5. Proposed tracked set

What would exist after alignment, if §6 is ruled at its defaults. Owner lanes
are named by subject. Device roles are as §0.

**Protocol common to every T3 row.** A release build whose revision is
stamped in the capture; shipping `RUSTFLAGS` (unset); governor and thermal
state recorded; miner state stated; cache state stated (cold means the page
cache dropped before each arm); `n` stated per cell; where two revisions are
compared, the arms alternate (A, B, A, B) inside one session. The capture
lands under `docs/benchmarks/` with the device named by role, and its
headline figures are appended to one ledger file so that a release can be
compared with the last (BA-Q11).

**Privacy.** Every row runs against synthetic fixtures on a dedicated rig or
over loopback. None adds logging to a node that carries real traffic, and
none records request contents, persona identifiers or per-request timing on
a live node.

| Id | Benchmark | Tier and device | Protocol beyond the common one | Replaces or extends | Owner lane |
| --- | --- | --- | --- | --- | --- |
| **BA-T1** | Pool-admission verify at the modal shape | T1, CI runner | gungraun; scope per BA-Q9 | BA-I10 | relay privacy |
| **BA-T2** | Block-connect verify terms: admission pair, hybrid signature, Bulletproofs+, parse, at the modal and the cost-densest shape | T1, CI runner | gungraun over the pinned fixtures | new; subject of BA-I20 | chain rules |
| **BA-T3** | Serve one response at three shard sizes from an in-memory store; the work before the first byte at two; the chunked read-and-fold loop beside the one-shot digest at three. **Built 2026-10-06** on the single-pass serve: `shekyl-p-serve` `benches/serve_response_iai.rs`, four `crypto_bench_serve_*` functions (manifest §12) | T1, CI runner | gungraun | built (BA-G1) | archival serve |
| **BA-T4** | Verify one fetched shard: delivery digest, hybrid check, content verification once it exists | T1, CI runner | gungraun | new (BA-G2) | archival fetch |
| **BA-T5** | Serve cost per response, **split by phase: read, hash, sign**; CPU and wall-clock by shard size (smallest, `W`, heaviest) and by responses in flight (1, 8, 32, 64). **First run 2026-10-07** on the floor device, daemon resident, two arms: [`ba_t5_serve_floor_device_20261007.md`](../benchmarks/ba_t5_serve_floor_device_20261007.md). Pre-registered pass lines for "can the floor device serve". All four hold on the frames production serves, which are full segments. The fourth (CPU per abandoned request under 5 ms) failed as registered, against a one-leaf frame that production cannot serve; that figure, 8.4 ms, is a projection for any future design that serves short frames. **Session 2, 2026-10-09**, a discovery run by ruling (no pass lines; predictions recorded against measurements): [`ba_t5_serve_floor_device_20261009.md`](../benchmarks/ba_t5_serve_floor_device_20261009.md). N in {8, 16, 32, 64} with the daemon idle, syncing the chain beside the probe, and syncing with the probe at nice 19; time to first byte at one in flight. Serving under sync runs at 70 % of idle throughput with the daemon keeping about a third (31 to 37 %) of its no-serve sync rate; nice 19 gives the daemon 90 to 97 % back at a seventh to a fifth of the serving throughput; throughput flat from N = 16, p99 lateness rising steeply with N (× 2 to × 3 across each of the first two doublings, × 1.1 to × 1.4 across the last); TTFB 0.19 ms p50 idle; one refusal in 6,144 at N = 64. Five of seven predictions held | T3, floor | Loopback, on-disk store, no Tor and no daemon; cold and warm; n ≥ 100 per cell. Two arms in one session, alternating: the two-pass path at `b5e7dbfed5` and option S (BA-Q3). Extends the 2026-10-05 runs (BA-G1), which have no S arm, no phase split beyond the digest, one shard size and at most 8 in flight. Falsifier for S: it recovers under 24 ms of the 78 ms #954 added | new (BA-G1) | archival serve |
| **BA-T6** | Client verify per shard, by shard size | T3, floor | n ≥ 100 per size | new (BA-G2) | archival fetch |
| **BA-T7** | Whole-shard fetch over Tor on the production serve and fetch path: time and miss rate by object size, with and without mining | T3, floor serving and an internal node reading | The size-ladder and one-device protocols already written in [`ARCHIVAL_SHARD_T_DERIVATION.md`](../completed/ARCHIVAL_SHARD_T_DERIVATION.md) §10 | BA-I35, BA-I91 to BA-I95 | archival serve |
| **BA-T8** | P2P span distributions: clearnet dial, handshake, gap on a LAN and a long path; Tor dial; Tor inbound; write-stall samples | T3, floor | n = 100 per leg; each reopen rule evaluated and its verdict recorded | BA-I80 to BA-I88 | P2P transport |
| **BA-T9** | Tor stem hop: transit and node-local time | T3, floor | The runbook BA-I68; n ≥ 100; each sample mapped to a verify-cost cell | BA-I68 | relay privacy |
| **BA-T10** | The floor verify surface: admission pair by input count and depth, hybrid signature, shipped Bulletproofs+ single and batched, parse, block-budget fill, AES throughput | T3, floor | Criterion, 10 samples per point; depth cells that are projections labelled so | BA-I20, BA-I21, BA-I30, BA-I42, BA-I58, BA-I73, BA-I75, BA-I77 | chain rules, relay privacy |
| **BA-T11** | Timer arm and poll cost, and the thread-budget legs: the smallest worker, blocking and executor counts that meet each duty | T3, floor | Per `docs/FOLLOWUPS.md:69`; criterion, 10 samples, for the timer | BA-I19, BA-I90; new (BA-G10) | P2P transport |
| **BA-T12** | Rust `validate` plus store `connect` per block, ordinary and deadline block; with proof verification once it lands | T1 on a CI runner; T3 on the floor | Fixture as BA-I27; the proof-bearing fixture when it exists | BA-I27, BA-I28 | chain rules, daemon store |
| **BA-T13** | IBD wall time, CPU, RSS and disk, LMDB against redb | T3; x86 dev as the design specifies, floor per BA-Q14 | `scripts/bench/drs_bench.py`, conditions-first | BA-I43, BA-I69 to BA-I71 | daemon store |
| **BA-T14** | RandomX per-hash verify and cache derivation | T2 on a CI runner; T3 on the floor | Light mode; 100 samples | BA-I23, BA-I24 | PoW |
| **BA-T15** | Scan one block: `Scanner::scan` plus merge, typical and worst case | T1, CI runner | gungraun | BA-I4, BA-I15, BA-I18 | wallet engine |
| **BA-T16** | Scan rate: the FA-6 incremental and restore scenarios | T3, floor | Shipping flags; the scenarios of [`FA-6_VIEW_TAG_ML_KEM.md`](FA-6_VIEW_TAG_ML_KEM.md) §8 | BA-I17, BA-I41, BA-I72 | wallet engine |
| **BA-T17** | Wallet open: the KAT profile under gungraun with the default parameters pinned by assertion; the default profile timed | T1 on a CI runner; T3 on the floor | A populated, production-shaped ledger | BA-I3 | wallet engine |
| **BA-T18** | Shard render matrix | T3, floor; the x86 smoke stays in CI | The matrix of BA-I32; triggered as `docs/FOLLOWUPS.md:1132` states | BA-I32, BA-I51, BA-I89 | shard visual |
| **BA-T19** | Wallet proving-state edges: spend-time replay against proving, open-time refetch | T3, floor | [`WSS_Q1B_BENCH_SPEC.md`](WSS_Q1B_BENCH_SPEC.md) | BA-I34, BA-I45, BA-I96 to BA-I103 | wallet-side store |
| **BA-T20** | Transfer build: Bulletproofs+ prove, hybrid sign through the production entry, FCMP++ prove at 1 and 2 inputs; `sign_transaction` end to end | T1 on a CI runner for the components; T3 on the floor end to end | Seeded fixtures | BA-I5 | wallet engine |
| **BA-T21** | Wallet ledger round-trip at 100 / 1 000 / 10 000 production-shaped transfers | T1, CI runner | gungraun | BA-I1 | wallet engine |
| **BA-T22** | Merge-time handle projection | T1, CI runner | as today | BA-I9 | wallet engine |
| **BA-T23** | GUI wallet: startup to usable, send flow from confirm to submitted, sync-progress overhead, shard render | T3, an x86 desktop until BA-Q15 rules the device | Cold and warm start, n ≥ 10 each, a synthetic wallet against a local regtest daemon; report only, no threshold | new (BA-G14) | GUI wallet |
| **BA-T24** | Transport handshake and AEAD | T2 on a CI runner, which also makes it compile there; T3 on the floor | Criterion | BA-I22, BA-I79 | P2P transport |
| **BA-T25** | Inbound connection cost: RSS and descriptors per peer, startup peak | T3, floor | Per `docs/FOLLOWUPS.md:1290` | BA-I29 | P2P transport |
| **BA-T26** | Per-refresh ledger snapshot at 1 000 / 10 000 / 50 000 transfers | T2, CI runner | Criterion | BA-I14 | wallet engine |
| **BA-T27** | RandomX Rust-to-C latency ratio, typical and adversarial | Gated on a CI runner by exception (BA-Q22); daily and weekly cron | As `rust/shekyl-randomx-differential` runs it today | BA-I33, BA-I52, BA-I53 | PoW |
| **BA-T28** | The engine-trait hot paths the trait spec names: `synced_height`, `balance` and its body, `account_public_address` through the actor handle, `base_emission_at`, `parameters_snapshot`; and key dispatch | T1, CI runner | gungraun; the thresholds `scripts/bench/compare.py` already routes | BA-I2, BA-I6, BA-I7, BA-I8, BA-I11, BA-I12, BA-I13 | wallet engine |
| **BA-T29** | Multisig intent and envelope operations | T2, CI runner | Criterion | BA-I16 | wallet engine |
| **BA-T30** | A block producer's reader: completing one won block's challenge reads inside `W₂` — about 117 whole-shard reads at the sim's mean, 156 at 30 % dropout — and the sustained rate at a hashrate share (about 290 KB/s at a tenth) | T3 protocol on a **mining-class box**, not the floor: the load is a producer's, and the floor device essentially never produces. Measured, not gated (`SCS-P10`, ruled 2026-10-07) | Readers against real serving personas over Tor, the reads spread at random across `W₂`; completion share and time per won block at 1, 5 and 50 won blocks per window; `n` stated. The count rule it would inform is provisional | none: no producer-side reader exists in the tree | archival serve credit ([`ARCHIVAL_SERVE_CREDIT_SPEC.md`](ARCHIVAL_SERVE_CREDIT_SPEC.md) §12) |
| **BA-T31** | The share of challenge draws left unread after the witness's three reads at hour-scale spacing (`x`), with the first-read failure (`p`) and the conditional rate `c = x / p`. The failure window `(11, 13)` clears the per-archiver false-slash budget when `x ≤ 0.2076`; at `p = 0.30` that is `c ≤ 0.692`. `c` is not the mixture weight `ρ` of the specification's table: `ρ = (c − p²) / (1 − p²)` | T3 protocol, against serving personas over Tor, the requester on any always-on box; the serving side on the floor device | Each sample is three whole reads of one shard through the shared fetch path as `SF-D3` rules it (fresh SOCKS credentials per read, so a rendezvous circuit per read; no isolation flags), each read with a fresh nonce, a later read made only when the one before ended stall-class. Every read is on a new circuit through the same entry guard, which is the dependence `ρ` stands for. One arm per spacing between consecutive reads: seconds (the control the one-read calibration rests on), 1 h, 4 h, 8 h. A multi-day series that includes a bad day. Reported per arm: `p`, `x`, `c`, each with its interval and `n`; and failures **per serving host as well as per read**, since one persona serves all its shards from one host and the per-archiver figure assumes they fail independently. Two additions for `SF-D3` as ruled 2026-10-07: (a) confirm the onion descriptor cache is shared across SOCKS credentials, so a read with new credentials does not refetch the descriptor — confirmed for Tor 0.4.9.11 on 2026-10-07, six runs, no descriptor fetch under new credentials ([`sfd3_read_isolation_20261007.md`](../benchmarks/sfd3_read_isolation_20261007.md)); the first read of a persona is not covered; (b) a run against a proof-of-work-enabled onion under load, recording the cost per read (circuit setup time, effort paid) and the failure rate | none: the W₂ size ladder measured single reads, never a re-read at this spacing | archival serve credit ([`ARCHIVAL_SERVE_CREDIT_SPEC.md`](ARCHIVAL_SERVE_CREDIT_SPEC.md) §5, §12; `ESR-11`, sim plan §5.15) |
| **BA-T32** | The settlement walk of one epoch: for every pair with an issued draw, read its list, hash each draw into the integrity digest, select the three counted draws and write the row; with the re-walk of `D`. All in the one block that settles the epoch | T3 on the **floor device**: it runs inside connect on every node | Wall time at maturity (324,000 pairs, the sim's draws per block) at 0, 10 and 30 % producer dropout; against the block interval | none: no settlement writer is wired. The urn's full-epoch replay, 1.09 s for 972,000 draws on a development host, is the nearest figure and is not this one | archival serve credit ([`ARCHIVAL_SERVE_CREDIT_SPEC.md`](ARCHIVAL_SERVE_CREDIT_SPEC.md) §9.3, §9.5) |
| **BA-T33** | One nested sign and one nested verify under hybrid scheme 3, Ed25519 + FN-DSA-1024, with seeded key generation beside them. **T1 arm built 2026-10-09**: `shekyl-crypto-pq` `benches/fn_dsa_hybrid_iai.rs`, two `crypto_bench_fn_dsa_hybrid_*` functions (manifest §13) | T1 on a CI runner, as a drift signal for the x86 path. T3 on the **floor device** for the figures: signing is hardware floating point, and x86 dispatches to AVX2 code the floor never runs | Criterion `fn_dsa_hybrid` on the floor: sign through the production entry (rejection sampling, so the distribution and not a point), verify, key generation. The stack a sign needs on the device, by the ladder that found 256 KiB for an optimized build on x86_64 ([`FN_DSA_HYBRID.md`](FN_DSA_HYBRID.md) `FND-4`) | none: the scheme is new (BA-I105) | archival serve credit ([`FN_DSA_HYBRID.md`](FN_DSA_HYBRID.md)) |

The gate's machinery (BA-I37 to BA-I40, BA-I44, BA-I46 to BA-I50, BA-I54,
BA-I59) persists with the tiers it serves and has no row of its own. The
documents marked **Rewrite** (BA-I61, BA-I64, BA-I65, BA-I66) are rewritten
under BA-Q17, and BA-I31 and BA-I36 wait on BA-Q12. A dated
capture kept in §2.8 is the evidence for a constant until the first run of
the T3 row that replaces it; it is then superseded by that run's capture.

**What happens to the gate's coverage.** The gate holds 20 entries today.
At the defaults none leaves: 12 are re-fixtured in place (BA-I1: 6; BA-I3:
1; BA-I4: 3; BA-I5: 2) and 8 stay as they are (BA-I2: 3; BA-I6 to BA-I10: 1
each). BA-T28 adds the three trait paths that were registered and never
captured. The T1 rows BA-T2, BA-T3, BA-T4, BA-T12, BA-T15 and BA-T20 add
subjects the gate has none of today: block connect, archival serve,
archival fetch, the Rust validator, scan cryptography and proving.

## 6. Rulings needed

Each open question has a default, and a ruled one says so in its heading.
Nothing above depends on a default being taken: every disposition in §2
and every row in §5 is conditional on the ruling named here.

**BA-Q1 — RULED 2026-10-05: the three tiers of §0.2 are the meaning of
"tracked", and §5 is the target set.** T1 gates per PR; T2 is trended and
never gates; T3 runs per release and on any PR that touches the path, and a
breach of a ruled constant's margin reopens that constant. Each **Rewrite**
in §2 is carried out by the §5 row that names it. Ruled by the maintainer
on review of PR #964.

**BA-Q2 — DONE 2026-10-05: the serve-cost runs are landed as a dated
capture.** PR #968 merged a record and two observation files,
[`sfd8_serve_cost_floor_device_20261005.md`](../benchmarks/sfd8_serve_cost_floor_device_20261005.md),
and pointed the read-capacity row in `docs/FOLLOWUPS.md` at the result.
Nothing is left to rule.

**BA-Q3 — RULED 2026-10-05: one pass, signed last, as an abuse mitigation.**
The order of read, digest and sign on the serve path. As ruled
on 2026-10-04 (`SF-D8`, `docs/design/ARCHIVAL_SHARD_FETCH.md:1292`), the
persona reads the shard once to compute the delivery digest `D`, signs, then
reads it again to send, holding no more than a chunk. Neither the ruling nor
the documents that record it state what the second read and the digest cost.

*What the digest provides,* since any change is judged against it:

1. `D` cannot be precomputed for a shard, published, or lifted from one read
   into another: the requester's nonce leads a hash over the whole framed
   body (`docs/design/ARCHIVAL_SHARD_FETCH.md:1101`).
2. The signature binds the bytes delivered. The requester recomputes `D`
   from what it received and never reads it back from the response.
3. A refusal is the shared 404 and never a truncated 200, because the
   persona signs before the first byte goes out
   (`rust/shekyl-p-serve/src/serve.rs:529`).
4. No pass holds more than a chunk of the shard.
5. *Audit, which follows from 1 and is stated nowhere.* A pass record
   carries the nonce and `D`, so anyone who later holds the shard can
   recompute `D` and check a historical pass. A pass signed for bytes that
   were not the shard is permanent evidence against its signer. This holds
   while the frame is a function of the shard, which the write-zero padding
   rule makes it today (`rust/shekyl-curve-tree/src/served_frame.rs:162`);
   a padding scheme keeps it only if the padded frame stays recomputable.

`D` does not show that the persona stores the shard; that is unchanged in
every option below.

*Option T, a digest over a root of chunk hashes — withdrawn by its proposer,
2026-10-05.* With `D = H(nonce ‖ root)`, a persona that has discarded a shard
and kept its 32-byte root can stream junk and sign a `D` that is consistent
with the real shard. An honest requester still catches the bytes (property
2), but a witness that skips the check, by collusion or by modified
software, files a pass that audits clean forever, where under the flat hash
it is provably fraudulent to anyone holding the shard. T loses property 5.
It is also not what was ruled: a salted digest of a digest is not a
nonce-salted digest of the whole response.

*Option S, the candidate: hash while streaming, sign at the end.* The
signature is already the last bytes on the wire. The persona runs the anchor
gate before touching the store, as now; confirms before the head goes out
that it can sign; streams the body once, folding exactly the bytes it writes
into the same flat salted digest; then signs and appends the signature.

- **Unchanged:** `D`'s definition, byte for byte. No wire, consensus or
  domain-registry change. Properties 1, 2, 4 and 5 hold.
- **Gained:** one read and one hash per response where there are two of
  each. The signature covers the bytes on the wire by construction, so the
  second fold and its comparison (PR #961) are not needed.
- **Cost 1, property 3 weakens.** A signer that fails after the body has
  streamed produces a truncated 200, a class the serve loop names as a
  probe surface that must not widen for ordinary misses
  (`rust/shekyl-p-serve/src/serve.rs:404`). The exposure: holdings are
  public through the bond, so a 404 on a bonded shard already means "store
  fault or signer refusal"; S would let any requester tell those two apart.
  If the key can be absent while the store serves, signer state becomes an
  oracle for whatever makes it absent.
- **The mitigation is a pre-flight check, and it is a new trait method.**
  `PassKey` has one operation today, `sign_pass`
  (`rust/shekyl-p-serve/src/countersign.rs:81`). S needs a second that
  answers "can this key sign" before the head, costs the same whichever way
  it answers, and turns key absence into the shared 404. A refusal after
  the body is then a cryptographic fault only: rare, counted, and of the
  same class as a store fault mid-body, which truncates today.
- **Cost 2, a store fault mid-body is signed, not truncated.** Today the
  signature is released only when the sent fold equals the signed one, so a
  shard that changes between the reads is cut short and counted
  (`rust/shekyl-p-serve/src/serve.rs:413`). Under S there is one fold, and
  the persona signs what it read. Detection moves to the requester's
  content verification, which has no production implementation (BA-G2). An
  honest witness still refuses to file, and a dishonest one now holds
  signed evidence, which strengthens property 5; but the operator's own
  signal is gone.

*The prerequisite: can the key be absent while the store serves?* Read at
the pin:

- ~~**Today it always is.** Production binds a placeholder key that refuses
  every transcript.~~ **SUPERSEDED 2026-10-06 (SH-2):** production binds
  the persona's resident key (`ResidentPassKey`,
  `rust/shekyl-engine-core/src/engine/stake_engine/serving/pass_key.rs`);
  the placeholder is deleted. The pre-flight is still what turns a stopped
  actor into a 503 before the read.
- **The design intends residency for as long as the host serves**
  (`docs/design/ARCHIVAL_SHARD_FETCH.md:945`), and the key bundles are
  derived when the wallet opens and held for the session
  ([`ARCHIVAL_BOND_CONSTRUCTION.md`](ARCHIVAL_BOND_CONSTRUCTION.md) §10.2).
  The engine has no locked-while-open state at the pin.
- **The contract still allows absence at sign time**: "key not resident,
  signer offline, or a host-side policy refusal"
  (`rust/shekyl-p-serve/src/countersign.rs:74`). Whether the signing
  capability can go away while the listener stays up was the unwired
  remainder of `SH-2`. **Settled 2026-10-06**
  ([`SH2_RESIDENT_KEY_AUDIT.md`](SH2_RESIDENT_KEY_AUDIT.md) §3 Q2): the
  serving task's life is a subset of the stake actor's by *teardown
  order* (`tasks.shutdown()` before `drop(engine)`, pinned by test), and
  the key holds a **weak** actor handle, so the one case the order cannot
  cover — the actor fail-stopping under a live listener — is observed by
  `PassKey::ready` as a refusal, not prevented. The capability can go
  away; when it does, the pre-flight is what answers 503 before the read.

So the pre-flight is mandatory under S: `SH-2` made the serving task's
life a subset of the key's by construction for the ordinary path, and
chose observe-not-prevent for the fail-stop, which is exactly the case
the pre-flight exists for.

*What S is expected to buy.* The floor runs (BA-G1) put the cost #954 added
at 78 ms per response, of which the digest is 23.9 ms per pass, twice: 48
ms, about three fifths. The other 30 ms or so was not separately timed and
includes the second read. S drops one digest pass and the second read, so
it should recover between 24 ms and something over 50 ms of the 78. That
range is a prediction until BA-T5 times read, hash and sign apart with S as
an arm. A faster digest (TurboSHAKE or KangarooTwelve) is a separate change
to the wire and the domain registry and is not part of S.

*The ruling (maintainer, 2026-10-05).* S, framed as an abuse mitigation,
which gives it a rule that can be tested: **`P` does no work that scales
with shard size until the requester has received the bytes that work is
for.** Before the 200 head `P` does constant work only: parsing, the
anchor gate, opening the shard, and the key's pre-flight. Each read, hash
and write after the head is paid for by the requester receiving the
bytes, and the signature comes last. T is not an option.

The same day's rulings on what a held shard may answer replace property 3
above. There is no shared 404: an invalid request is a bare 400, a shard
that is not held is the 404, a fault on `P`'s own side (store, tip or key)
is a bare 503, and a signer that fails after the body closes the response
with a refusal trailer where the signature goes, so the response is its
full declared length and says in `P`'s own bytes that it did not sign.
Cost 1 above is therefore not a truncated 200. PR #974 built the order
and the five answers and amended `SF-D8`
([`ARCHIVAL_SHARD_FETCH.md`](ARCHIVAL_SHARD_FETCH.md)); PR #982 added the
tests that hold the invariant, made the pre-flight a required method
(`PassKey::ready`), and counted the late refusal apart.

*Costs the ruling accepts.* A signing fault after the body spends a whole
shard on a response nobody can use; it is counted on its own. A store
that changes a shard under a response is signed for the bytes sent, not
withheld (cost 2), which moves detection to content verification and
raises BA-G2's priority. *Not covered, and left to BA-Q4:* a slow reader
holding an in-flight permit to the stall timeout, which costs `P` a
permit and no CPU, so it is not an amplification.

*What was predicted, and what was measured.* The section above predicted
that S would recover "between 24 ms and something over 50 ms of the 78".
A sharper prediction was made on 2026-10-06 before the floor result was
read: about 50 ms per response at one in flight, band 40 to 60, being the
pre-#954 arm (24.8 ms) plus one digest pass (23.9 ms). Run 3 on the floor
device measured the single-pass tree the same day
([`sfd8_serve_cost_floor_device_20261005.md`](../benchmarks/sfd8_serve_cost_floor_device_20261005.md)):

| Quantity | Predicted | Measured | Verdict |
| --- | --- | --- | --- |
| Median per response, one in flight | 40 to 60 ms | 67.2 ms | **falsified** |
| Digest cost inside the stream | 23.9 ms, its cost alone | 43 ms (67.2 − 24.6) | 19 ms unexplained |
| Responses per second, eight in flight | 37 to 60 | 49.7, median of six blocks (`BA-T5`, 2026-10-07) | **held** |
| Work before the first byte | under 1 ms | 0.19 ms p50 time to first byte at one in flight, daemon idle, a bound from above on the whole pre-head step (`BA-T5` session 2, 2026-10-09); 1.85 ms p50 beside a syncing daemon | **held** |

The prediction assumed the digest costs the same inside the stream as
alone. It does not. BA-T3 narrows where the difference can be: on x86 the
chunked read-and-fold loop is 2.2 % above the one-shot digest in
instructions, at an eighth of a segment and at a full one, so the 19 ms
is not instructions spent interleaving the hash with the read. What the
instruction count leaves out is what remains to suspect: the on-disk
store's read path, the blocking-pool hand-off per chunk (51 for a full
segment), and cache behaviour on the floor device. BA-T5's split by phase
is the measurement that says which.

BA-T3 also puts a first number on the abuse figure. Work before the head
is 13,527 instructions for one leaf and 13,579 for a full segment, flat
across a 25,992-fold change in size, and 0.007 % of a full response. By
that share of the measured 67.2 ms it is about 5 µs on the floor; the
store is in memory in the gate, so a cold shard open is not in the figure
and the estimate keeps its ceiling of 1 ms until the floor measures it.

The predictions are in the measurement ledger. Two are retired
estimates, each beside the floor capture that settled it and with a
verdict the check computes: the per-response figure (falsified by run 3)
and throughput at eight in flight (held, by the first run of `BA-T5`,
2026-10-07). The third, work before the first byte, was an open estimate
after that run, which bounded it from above at 2.2 ms with one chunk read
and hashed inside the figure; `BA-T5` session 2 (2026-10-09) measured
time to first byte at one in flight at 0.19 ms p50 with the daemon idle,
a bound from above inside the band, and the estimate is a measured
constant on that capture (`serve_prehead_work_floor`).
The run's record also explains run 3's two disagreeing blocks
(the executor-side hash made throughput bimodal) and puts the digest
alone at 23.9 ms of a 57.7 ms response.

*Carried.* The invariant is general, and a rules-queue row in
`docs/FOLLOWUPS.md` asks the same of daemon RPC, Levin object and
transaction requests, and the fetch client's handling of large responses.

**BA-Q4 — Derive serve-side `MAX_INFLIGHT`.** Default: derive it from BA-T5
on the floor, as the constant's own comment promises (BA-D15), and state
which resource bound. The serving device class is itself open
(`docs/FOLLOWUPS.md:1257`); the default keeps the floor as the conservative
interim.

*Inputs from the first `BA-T5` run (2026-10-07).* The floor device is
ruled the serving floor, and it serves today's shards at 41 to 56 per
second at eight in flight. The cost an unpaid request can impose is about
4 ms of CPU today and about 8 ms at a frame small enough to be buffered
whole. The control over how many such requests one rendezvous circuit can
make is the serving onion's stream cap, 8 per circuit with the circuit
closed past it (`SERVING_MAX_STREAMS`), a carried placeholder: its value
is part of this question, beside `MAX_INFLIGHT`.

*Inputs from `BA-T5` session 2 (2026-10-09, a discovery run by the ruling
of 2026-10-08; it sets nothing).* The sweep N in {8, 16, 32, 64} on the
floor device, daemon idle and syncing
([`ba_t5_serve_floor_device_20261009.md`](../benchmarks/ba_t5_serve_floor_device_20261009.md)):
throughput is flat from N = 16 in every state (idle 51 → 55 → 57 → 55
responses/s; under sync 37 → 41 → 41 → 40), so beyond 16 the cap buys
no throughput on this device; p99 executor wake lateness rises steeply
with N (idle 5.5 → 11.7 → 35.8 → 51.6 ms; sync 7.2 → 14.3 → 45.0 →
60.0 ms: × 2 to × 3 across each of the first two doublings, × 1.3 to
× 1.4 across the last), so each doubling costs latency; CPU per response is 66
to 72 ms at every N. At N = 64 = `MAX_INFLIGHT`, a requester that opens
its next connections the instant its last stream closes was refused once
in 6,144 under sync and never with the daemon idle: the in-flight permit
is dropped after the stream, so for such a requester the cap is N − ε.
Whether the permit should outlive the stream, and what resource the
constant bounds (on this device, latency, not throughput or CPU), are
this question's to rule. N = 128 was not run: no test-only override of
the constant exists, and none was added.

**BA-Q5 — Re-measure `W`, `L`, the retry budget and the read capacity on the
v3 path.** Default: BA-T7 runs before the Round-2 gate re-pins them, with an
owner and a date entered beside the reopen condition in
[`CLIENT_VERSION_CONSTANTS_VALIDATION.md`](CLIENT_VERSION_CONSTANTS_VALIDATION.md).

*An input the `W` derivation must take (2026-10-07).* The floor device's
serve verdict holds because a shard of `W` bytes is far larger than what
can be buffered between the persona and the requester. If `W` falls to
that amount, every abandoned request costs the persona a whole response
and a signature
([`ba_t5_serve_floor_device_20261007.md`](../benchmarks/ba_t5_serve_floor_device_20261007.md),
"How far this verdict reaches"). The amount is tor's stream window plus
the kernel's socket buffers, about 250 KB by the specification and not
yet measured through an onion; BA-T7 measures it. The ledger row
`serve_floor_verdict_frame` fails when `W` changes, until the verdict is
re-graded.

**BA-Q6 — The key-dispatch gate and the re-route it waits on (BA-D8).**
The design routes claims through `KeyEngine::try_claim_output`; the caller
is not written. Default: BA-I8 stays gated, since a gate on a designed path
keeps its cost from drifting before the caller lands, and the M3c+ re-route
gets a carrier: a `docs/FOLLOWUPS.md` row owned by the engine-trait
contract. The bench is retired only if the re-route is ruled out of the
design.

**BA-Q7 — Retire what is superseded or dead.** Captures superseded by a
later capture of the same subject: BA-I74, BA-I76, BA-I87. Benches whose
decision is made and whose arm no longer times production code: BA-I25,
BA-I28. Default: retire these five. A row that only lacks a production
caller is not on this list; a designed path keeps its bench.

**BA-Q8 — RULED 2026-10-05: the workflow triggers on `rust/**`,
`scripts/bench/**` and itself, for both the PR and the push job** (closes
BA-D1). The alternative, a path list derived from each bench's dependency
closure, would need a gate of its own to stay true. Ruled by the maintainer
on review of PR #964; the change lands in its own PR.

**BA-Q9 — Scope of the pool-admission bench (BA-D7).** Default: correct
§72.2 to what admission runs, add the hybrid-signature and Bulletproofs+
terms to BA-T1, and re-derive the hop from BA-T10's floor figures.

**BA-Q10 — Re-measure verify cost on the floor after `PL-D3`.** Default: one
BA-T10 run serves the surge factor, the zone, the hop surface and the input
cap; the signed values stand unless the run breaches a stated margin.

**BA-Q11 — Cadence, authority and record for T3.** Default: T3 is an item on
the release checklist, run by the release lane under the shared-estate claim
protocol; each run appends its headline figures to one ledger file under
`docs/benchmarks/`; the two floor scripts are renamed captures, not gates,
and lose their stale flags and citations (BA-D12).

**BA-Q12 — Bench-like code with no traced consumer** (BA-I31, BA-I36).
Default: its owning lane names the decision it feeds, or it is deleted at
next touch under [`15-deletion-and-debt`](../../.cursor/rules/15-deletion-and-debt.mdc).

**BA-Q13 — Constants that time Tor's protocol and not the device.** Default:
no tracked benchmark; a Tor version change is the re-measurement trigger,
recorded beside each constant.

**BA-Q14 — Chain store and cutover acceptance.** Default: BA-T12 on the
floor, with proof verification in the path, joins the DRS-BENCH suite as a
cutover acceptance item; BA-T13 gains a floor arm beside its x86 one.

**BA-Q15 — GUI wallet budgets and device.** No latency budget and no minimum
device is stated for the GUI wallet. Default: measure the four paths of
BA-G14 once on an x86 desktop and report; rule budgets from that report;
no gate before a budget exists.

**BA-Q16 — `tests/performance_tests/` and `wallet-crypto-bench`** (BA-I56,
BA-I57). Default: delete both, which discharges `docs/FOLLOWUPS.md:666`;
the shipped Bulletproofs+ verifier keeps BA-I58 until the cutover.

**BA-Q17 — The frozen baseline files and the contract documents**
(BA-I60 to BA-I66). Default: delete BA-I60 and BA-I62;
[`PERFORMANCE_BASELINE.md`](../PERFORMANCE_BASELINE.md) becomes the contract
of record for the tracked set, holding each row's threshold and protocol;
`docs/benchmarks/README.md`, the manifest and the RandomX record are
rewritten against it; this document is archived when that lands.

**BA-Q18 — Wall-clock on CI (BA-D13).** Default: T2 is trended on shared
runners and never gates; the dedicated-runner upgrade is rejected with a
reopening criterion, or gets a `docs/FOLLOWUPS.md` row with a named blocker.

**BA-Q19 — RandomX budgets on the floor.** Three targets are stated, all on
x86: the latency ratio (gated), cache derivation ≤ 200 ms (341 ms measured,
unmet), and per-call allocation ≤ 100 µs (47.75 µs measured, met). None is
stated for the floor, and no per-hash budget exists on any device. Default:
state a per-hash and a cache-derivation budget for the floor from BA-T14's
run, and either re-rule the 200 ms cache target or record the x86 figure as
a standing breach. The allocation target stands.

**BA-Q20 — Figures in documents that no measurement supports** (BA-D14).
Default: replace them with floor-measured values that cite their capture.

**BA-Q21 — RULED 2026-10-05: `scripts/bench/test_compare.py` runs in the
workflow that runs `scripts/bench/test_drs_bench.py`** (closes BA-D16).
Ruled by the maintainer on review of PR #964; the change lands with BA-Q8's.

**BA-Q22 — Wall-clock checks that gate today** (BA-I32 with BA-I51; BA-I33
with BA-I52 and BA-I53). Under BA-Q1 wall-clock never gates. The shard
smoke gates on absolute x86 thresholds per PR; the RandomX bounds gate on a
same-machine ratio on a schedule. Default: both stay gated as named
exceptions, the ratio because both arms share a machine and the smoke
because its thresholds sit far above the measured figures; any further
wall-clock gate needs its own ruling.

**BA-Q23 — RULED 2026-10-05: a machine-readable measurement ledger and a
staleness check.** The failure behind most of §3 is one pattern: a constant
is derived from a capture at one revision, the code under it changes later,
and nothing notices, because the link between constant, capture and code
path is prose. Each cost-justified constant gets a ledger row naming where
the constant is defined, the §5 row that measures it, the capture and its
revision, and the code paths whose cost it budgets. One deterministic CI
check asks of every row whether any commit touching those paths is newer
than the capture, and names the commit when one is. A declared path that no
longer exists fails the check. Staleness is cleared in the ledger itself:
by a newer capture, by a reviewed note that the change is cost-neutral, or
by marking the row stale with the carrier of its re-measurement. The check
needs no hardware and no timing data. Seeded from §4. Ruled by the
maintainer on review of PR #964; it lands in its own PR.

## 7. What this round examined, and what it did not

Nothing in this document was measured for it. No benchmark was run; "last
run" is read from records.

**Examined and found to hold no benchmark or timing code:**
`rust/shekyl-chain-rules`, `rust/shekyl-economics-sim`,
`rust/shekyl-staking-sim` (no `Instant::now`); `rust/shekyl-p-serve`,
`rust/shekyl-p-fetch`, `rust/shekyl-p-host` (no `benches/`, no criterion
dependency); `shekyl-gui-wallet` at `447908f` (BA-I104).

**Examined, with citations spot-checked against the pin:** every `benches/`
directory under `rust/`; `scripts/bench/`; `tests/performance_tests/`;
`.github/workflows/`; every file under `docs/benchmarks/`;
`config/consensus_constants.json`; the constants in the archival, P2P, Tor,
relay-privacy, consensus, PoW, crypto and wallet crates whose comments cite
a measurement.

**Not examined, or examined only in part:**

- `tests/stressnet/` and `tests/randomx_v2_parity/xmrig_ceiling/` were
  listed and not read.
- The consumers of BA-I31 and BA-I36 were not traced (BA-Q12).
- Several operations in `tests/performance_tests/` were not traced to a
  production caller one by one; the row's disposition rests on the subjects
  that were.
- `docs/FOLLOWUPS.md` rows that mention a measurement were read at their
  heading and first lines.
- Whether BA-I10 tripped when `PL-D3` merged, or the baseline simply
  absorbed the change, cannot be told from the tree.
- Whether `PL-D3` moved wallet scan cost is not established; BA-G15 does not
  depend on it.
- `shekyl-mobile-wallet` and `shekyl-web` are outside this round.
- The owning documents of the 22 `consensus_constants.json` keys listed in
  §4 were not each re-read for a cost argument outside the comment field.
- `config/economics_params.json` holds no entry justified by a cost or a
  latency; its entries were not traced to their derivations.
