// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! GAP-7 instrument: worst-case **COLD-block** connect-verification cost.
//!
//! # On the connect path every block is cold
//!
//! `form` (`shekyl-chain-rules` `validate.rs`) judges every listed
//! transaction with `judge_slot_stateless` — `tx_form`, the signatures
//! (CEN-I17/I18), the FCMP++ proof (CEN-I15) — and then folds every listed
//! range proof into one batch (CEN-H19). It never takes the pool's prior
//! pass (E5-Q8): CEN-M8's cache spares only the pool's *re*-judgement of a
//! transaction whose claim has not moved (`judge_lone_stateless`), never a
//! block's. So the bill this file prices is what every connected block pays,
//! whether or not its transactions came through our pool. The two states
//! GAP-7 was written for pay it like any other block:
//!
//! 1. **Initial sync on the provisioning floor** (rule 76: Raspberry Pi 4),
//!    where every historical block is connected in turn; and
//! 2. **the withhold-then-announce adversary**, who keeps transactions out of
//!    relay and announces a full block. On this path withholding buys no
//!    extra verification — the announced block costs what a relayed one
//!    does — so the adversary's lever is the block's *contents* (the argmax
//!    below), not its novelty.
//!
//! # SHAPE, NOT FLOOR — rule 76 §3/§4, do not misread these numbers
//!
//! This bench runs on a development machine and establishes **which component
//! dominates and how cost scales with the constants census-C2 R2 ratifies**.
//! It is NOT a floor measurement and must never be presented as one:
//!
//! - *"Any constant derived from measured work time is provisioned at the
//!   floor device, not at the machine that happened to be available"*
//!   (rule 76 §1) — record the machine beside every number.
//! - *"Cross-machine ratios are measured, never assumed"* (§3).
//! - *"Values AND INCREMENTS for the floor device are measured ON it, never
//!   scaled to it"* (§4) — the rule's own counter-example saw aggregate
//!   ratios of 5.36–5.75× while the per-layer MARGINAL ratio was 5.98×, so
//!   scaling an increment by an aggregate ratio under-provisions invisibly.
//!
//! GAP-7's hardware half therefore stays OPEN whatever this reports; the
//! point of this file is that a Pi arriving tomorrow has something to run.
//!
//! # What is measured, mapped to the rows that pay it — and what is NOT
//!
//! **Scope, stated precisely: this instrument measures the enumerated
//! dominant CRYPTO terms through the bodies `form` runs. It is not an
//! end-to-end production-path harness** — the fixture is not a
//! consensus-valid transaction ([`shekyl_verify_cost::connect`]), so it
//! cannot be handed to `form` itself. Unmeasured acceptance-path residue,
//! named: the rest of `tx_form` (the structural and `tx_extra` rows, CEN-H18's
//! cleartext balance), CEN-I17's signing-hash derivation and the
//! transaction hash, and `validate`'s view-bound rows (`tx_against` over the
//! store's `ChainView`: key-image and reference lookups) — µs-class CPU work
//! plus storage-dependent lookups. **Direction of the omission: every
//! omitted term ENLARGES the real bill, so the composed `verify_floor` is a
//! lower bound on cost and the derived `surge_max` is an UPPER bound** —
//! consistent with the one-directional rule that further measurement only
//! tightens. The ruling consuming these numbers takes its margin below
//! `surge_max`, never at it.
//!
//! **Authorization-scheme fence: the sweep models scheme-1 (single hybrid
//! sig per input). Scheme-2 M-of-N multisig (`verify_pqc_auth`'s scheme-2
//! arm, `shekyl_crypto_pq::multisig::verify_multisig`, M ≤
//! `MAX_MULTISIG_PARTICIPANTS` = 5) is consensus-valid and costs up to M
//! hybrid verifications per input — but it CANNOT flip the argmax, by
//! floor-measured arithmetic:** the pqc term is 934 µs/verify against an
//! adm term of 129 ms, so even M = 5 adds ≈ 3.7 ms/input to the numerator
//! while the multisig containers add ~20-30 kB/input to the DENOMINATOR —
//! per-byte density falls well below the minimal-spend argmax (bigger wire
//! beats bigger verify at these magnitudes). Recorded as an arithmetic
//! fence with its operands; a scheme-2 fixture is the belt if a future
//! round wants the measurement.
//!
//! Per transaction, at shape `(n_in, n_out)`:
//!
//! - **`adm`** — `shekyl_ct_balance::check_commitment_masks` +
//!   `shekyl_fcmp::proof::verify`, the bodies of CEN-H17 and CEN-I15 (via
//!   the relay bench's fixture; its 64-cell depth/layout surface owns the
//!   tree-depth axis — this bench pins depth 2 / `Spread`, today's
//!   production topology, and does not re-sweep that axis).
//! - **`pqc_per_input`** — one hybrid Ed25519+ML-DSA-65 verification
//!   (`shekyl_crypto_pq::signature::verify_pqc_auth` on a single-signer,
//!   scheme-1 slot). `form` runs one authorization check **per input**
//!   (CEN-I18, `judge_signatures`) for every transaction but the coinbase
//!   and the serve credit: this term for a single-signer input, M of it for
//!   an M-of-N multisig input (scheme 2, M ≤ 5). The relay bench's sequence leaves
//!   this term out; the pool door pays it as well (see that bench).
//! - **`bp_lone`** — Bp+ aggregate verification over `n_out` commitments,
//!   as a batch of one: `shekyl_bulletproofs::verify_batch`, CEN-H19's
//!   body and the shipped verifier. A batch of one is what the pool door
//!   pays at `TxSlot::Lone` (`H19::verify_lone`); a block folds every listed
//!   proof into ONE batch after its slot loop (`H19::verify_block`), which
//!   `budget_fill` times.
//! - **`parse`** — `Transaction::from_bytes` on the fixture's wire bytes.
//!
//! Per block: **`randomx_once`** — one PoW hash (`compute_hash` against a
//! prepared cache, as the ingest's substrate calls it; cache derivation is
//! epoch-scoped and amortized out).
//!
//! # Budget fill and the marginal rule
//!
//! `budget_fill` runs the per-transaction terms in `form`'s slot order —
//! parse, masks, `n_in` signatures, the proof — N times at measured budget
//! points (N = budget / weight(shape), duplicated fixtures — legitimate
//! because none of the measured calls hold cross-tx caches; key-image
//! uniqueness is the view's, CEN-L1, outside them), then CEN-H19's fold over
//! the N range proofs as one batch. Points span 600 000 (2× the
//! penalty-free zone — the permanent floor operating point) up to 4 800 000;
//! the 30 MB surge ceiling (`2 × 50 × LTEM`, census CEN-G6/G6b) is reported
//! by extrapolation from the measured MARGINAL cost per weight-byte across
//! these points — never from two endpoints — with the measured span stated
//! beside it (data to 4.8 MB; 30 MB is 6.25× beyond the last measured
//! point). A linearity failure across the points is a finding, not an
//! obstacle, and the multi-point design exists so the instrument can see one.
//!
//! **The 30 MB figure is RECORDS-WAS, and the value it refuted is gone
//! (2026-09-12).** `2 × 50 × LTEM` was the ceiling under the inherited ×50.
//! This extrapolation is what fired against that value: C2-R2 Q3 struck ×50 as
//! REFUTED-not-superseded and re-derived **S = 4**, now implemented and
//! single-sourced in `config/consensus_constants.json`. The reachable ceiling
//! is therefore `2 × 4 × LTEM` = **2.4 MB at launch**, which sits INSIDE the
//! measured span rather than 6.25× beyond it. The 30 MB extrapolation is kept
//! because it is the evidence, not because it describes a state the chain can
//! now enter — do not read it as the current bound.
//!
//! # The dated results below, and what they measured
//!
//! The 2026-09-04/05 runs timed each block's range proofs ONE AT A TIME in
//! the fill (the `bp_proxy` cell, `verify_batch` over a batch of one, then
//! the Rust sibling of a C++ acceptance-path verifier,
//! `bulletproofs_plus.cc`), and took the batched figure from a C++
//! microbench of that verifier. Both C++ artifacts are deleted:
//! `verify_batch` is the acceptance path's verifier, `bp_lone` is the
//! `bp_proxy` cell under its current name, and the fill's fold times the
//! batched regime directly. The figures stand as the record they are; the
//! next run of each phase replaces them.
//!
//! # Results — dev box, first run (SHAPE data; re-read the rule-76 section)
//!
//! **Machine: Intel i9-11950H (8C/16T, 5.0 GHz boost), Linux 6.12, `cargo
//! bench` profile, 2026-09-04.** Every number below is a dev-box SHAPE
//! observation; none is a floor value (rule 76 §1/§4 above).
//!
//! Per-term, per-tx (median):
//!
//! | shape (in/out) | weight | adm (fcmp+masks) | pqc ×1 | bp_proxy | parse |
//! |---|---|---|---|---|---|
//! | 1/2  | 13 007 | 22.8 ms | 178 µs | 2.82 ms | 0.68 µs |
//! | 8/2  | 59 231 | 69.8 ms | 179 µs | 2.85 ms | 2.77 µs |
//! | 1/16 | 33 990 | 23.3 ms | 179 µs | 16.4 ms | 1.87 µs |
//! | 8/16 | 80 214 | 69.9 ms | 178 µs | 16.5 ms | 3.91 µs |
//! | 4/4  | 37 339 | 39.4 ms | 178 µs | 4.86 ms | 1.79 µs |
//! | 2/8  | 29 864 | 26.6 ms | 179 µs | 8.77 ms | 1.57 µs |
//!
//! RandomX, once per block: **317 ms** (prepared cache; light-verify path).
//!
//! **Finding 1 — the dominant term is FCMP++ verification, and its FIXED
//! cost is what shapes the worst case:** adm ≈ 16.1 ms per proof +
//! ≈ 6.72 ms per input (from the 1→8 input span), output-insensitive.
//!
//! **Finding 2 — the argmax REVERSED the presumed candidates.** Cost per
//! weight-byte: 1-in/2-out ≈ 1.95 µs/B > 8-in/2-out 1.25 > 4/4 1.21 > 2/8
//! 1.20 > 1/16 1.17 > 8/16 1.09. The per-proof fixed cost means a block of
//! MANY MINIMAL transactions outprices every density extreme — the
//! adversarial worst case is maximum tx count, bounded only by the minimal
//! spend's own wire weight (≈ 13 kB, mostly proof + hybrid-auth bytes).
//! Budget fill at the measured argmax (1-in/2-out): 1.165 s @ 600 kB
//! (n = 46), 2.306 s @ 1.2 MB, 4.566 s @ 2.4 MB, 9.146 s @ 4.8 MB (every
//! 30 MB figure below is extrapolation 6.25× beyond this measured span) —
//! **marginal 1.90 µs/weight-byte** vs aggregate 1.95 (the §4
//! marginal-vs-aggregate gap, here 2.5 %, measured not assumed).
//!
//! **Finding 3 — Bp+ does not move the argmax, single or batched.** The
//! single-proof cell at 16 outputs (16.4 ms) was within 4.3× of the top
//! term, close enough that verifier choice could have flipped the argmax to
//! output-heavy packing. The C++ verifier then on the acceptance path
//! measured 4.40 ms @ 2-out and 23.6 ms @ 16-out single-proof on the same
//! machine (1.44–1.56× this file's cell — far from the ~5× that would have
//! flipped it), and **batched**, 46 × 2-out proofs in 24.5 ms total =
//! **0.53 ms/proof amortized** (8.3× amortization). **The count-argmax
//! therefore HOLDS**, and under block batching the Bp+ term nearly vanishes
//! from the argmax bill (0.53 ms against adm's 22.8): FCMP++ verification
//! dominates. On the Rust path the regimes split the same way: the pool
//! door verifies a transaction's range proof as a batch of one
//! (`bp_lone`), a block's connect folds the block's proofs into one batch
//! (the fill). No double-count with the `adm` term: `proof::verify`
//! proves membership/spend-auth (`shekyl-fcmp` `proof.rs`), not ranges —
//! the wire carries `bulletproofs` and `fcmp_proof` as separate prunable
//! fields. (One small term this bench does not time separately: CEN-H18's
//! cleartext balance, `shekyl_ct_balance::verify_ct_balance`, a per-tx
//! commitment sum of a handful of EC ops — µs-class against a ms-class
//! bill.) Composed per-byte at the argmax with the C++-batched Bp+
//! (composition arithmetic, not a direct fill run): ≈ 1.81 µs/B vs the
//! single-proof 1.95 — same order, same conclusion, surge-ceiling ≈ 54 s
//! instead of 57.
//!
//! **Finding 4 — the hybrid-signature term is NOT load-bearing today:**
//! 178 µs per verification, ≈ 38× under the fcmp per-input marginal. Parse
//! is noise (µs against ms). Neither can move the constants.
//!
//! **Outcome statement (steering's two-way), stated as HEADROOM on the
//! measured machine — never as a floor prediction (rule 76 §3/§4 forbid
//! assumed cross-machine ratios):** at the permanent floor operating point
//! (600 kB) the worst-case cold block costs ≈ 1.5 s on this machine —
//! crypto 1.17 s + RandomX 0.32 s (the PoW term is ~21 % of the zone-point
//! bill; a reader summing only the fill term mis-adds) — ≈ 1.2 % of
//! T = 120 s. At the ×50 surge ceiling (30 MB — **an extrapolation 6.25×
//! beyond the measured 4.8 MB span**): ≈ 57 s, i.e. **the worst-case cold
//! block consumes ≈ 48 % of a block interval on the fastest machine
//! available to the project, leaving under 2× headroom before the interval
//! is exhausted — on a machine that is by definition faster than the
//! stated floor.** That composition speaks directly to the condition
//! census C2-R2 Q3 attached to the ×50 ratification (its named
//! re-derivation target is the surge factor, not the zone); what the
//! floor device measures remains GAP-7's open half. **That re-derivation
//! has since happened (2026-09-12): the condition fired, ×50 was struck,
//! and S = 4 is ratified and implemented — so the ≈ 48 % of a block
//! interval below is the cost of a block the consensus rules no longer
//! admit. At the ratified ceiling the same extrapolation lands inside the
//! measured span.** The paragraph is kept as the measurement that forced
//! the change.
//!
//! # FLOOR RESULTS — the floor device, Raspberry Pi 4 Model B Rev 1.4 (verify_floor)
//!
//! **Capture provenance note (review finding): the first rust-phase
//! capture was taken under the FA-6 §8.2 flags, TERMINATED at the RandomX
//! SIGILL (its last lines are the crash; pipefail skipped thermal_end),
//! and the flagless RandomX figure initially existed only outside the
//! archive. The phase re-runs FLAGLESS end-to-end — the shipping regime —
//! and the re-run capture supersedes the flagged one as the verify_floor
//! source; the flagged capture stays archived as the SIGILL record.**
//!
//! Captures: `docs/benchmarks/gap7_block_verify_pi4_{pins,rust,cpp}_2026….txt`
//! (device row, toolchain, flags, thermal trace, and the SD/8 GB as-found
//! deviations recorded in each header). Pins ran FIRST and green (4/4 —
//! validating the instrument as well as the fixtures: the run also exposed
//! a broken thermal reader whose vcgencmd branch presence-tested the BINARY
//! when the capability is the DEVICE NODE). Thermal regime: CLEAN — stock
//! 1.8 GHz in 230/231 samples, peak 70.6 °C, no throttling; the fill is
//! exactly linear (marginal ≡ aggregate).
//!
//! Per-term at the argmax (1-in/2-out), floor vs i9 ratio bracketed:
//! adm 128.97 ms [5.65×; per-input marginal 40.2 ms = 5.98× — rule 76 §4's
//! own cited figure, reproduced]; pqc 934 µs [5.25×]; RandomX (flagless)
//! 1.222 s/block [3.86×]; C++ Bp+ single 13.59 ms @ 2-out / 71.8 ms @
//! 16-out — **2.56× FASTER than this file's single-proof cell on the A72,
//! the inverse of the i9's 1.56×-slower ratio**; C++ batched 46× =
//! 1.745 ms/proof (amortization 7.79× vs i9's 8.3× — algorithmic-first,
//! confirmed). **Four-plus per-term floor ratios spanning 3.86× to ≈12×,
//! one of them INVERTED: no single assumed scaling factor could have been
//! right anywhere (rule 76 §3, measured).** Dev-box RELATIVE shape costs
//! are not floor relative costs — the sub-argmax ordering flipped.
//!
//! **What that ratio means for the shipped bill:** the composition below
//! takes its Bp+ term from the C++ verifier, and `verify_batch` — the
//! verifier that ships — measured 2.56× slower than it single-proof on this
//! board. Its batched cost on the floor is unmeasured: the `rust` phase of
//! `scripts/bench/gap7_pi4_gate.sh` now times it (`bp_lone`, and the fold
//! inside `budget_fill`), and `verify_floor` is owed that re-run before it
//! is read as the shipped figure. Direction: the Bp+ term can only have
//! grown, so `surge_max` below can only fall.
//!
//! **Interim until that re-run (2026-11-08, ruled by Rick): an Assumption,
//! not a measurement.** Scale the C++ batched Bp+ term by the measured
//! single-proof ratio, 2.56 (1.745 → 4.47 ms/proof), assuming the batch
//! amortises the Rust verifier as it did the C++ one. Per argmax tx that
//! adds 2.72 ms: verify_floor ≈ 131.49 ms/tx (≈ 10.11 µs per weight-byte),
//! 46.13 argmax txs per 600 kB zone block, RandomX 1.2845 s per block, and
//! `surge_max = (f·T − RandomX) / (zone fill)`. The tiers become ≈ 6.38 at
//! d2, ≈ 5.58 at d7 and **≈ 3.92 at d24**, against the composition below
//! (6.52 / 5.69 / 3.97, quoted as 6.5 / 5.7 / 4.0). The signed ×4 is the
//! d24 figure, so under this interim it sits above its own bound. The
//! conservative bracket, the Rust single-proof cost (34.8 ms) in place of
//! the batched term, gives ≈ 3.43 at d24.
//!
//! **Regime note:** the sweep was measured with the FA-6 §8.2 flags; a
//! one-point comparison against the shipping configuration (generic
//! aarch64 — no repo `target-cpu`, verified) showed flagless 3.2% FASTER
//! on adm, identical on Bp+ — the sweep is ≤3.2 % conservative for what
//! ships. The flags also SIGILL RandomX on this board (BCM2711 has no
//! ARMv8 crypto extensions; LLVM's cortex-a72 def includes +aes), so the
//! §8.2 convention is unsafe here, unrepresentative, and not even faster —
//! routed as its own item.
//!
//! **verify_floor, composed at the argmax, from the flagless
//! shipping-regime capture (`gap7_block_verify_pi4_rust_20260905T181144Z`,
//! canonical codec encoding, end-to-end incl. RandomX 1.2845 s, clock at
//! stock in 229/231 samples, fill marginal ≡ aggregate 12.44 µs/B), with
//! the C++-batched Bp+ term:**
//! 128.77 ms/tx ⇒ 9.90 µs per weight-byte ⇒ zone-point worst cold block
//! **7.23 s ≈ 6.0 % of T** (RandomX is 18 % of that bill). Against the
//! signed f·T = 40 s: **surge_max ≈ 6.5, an UPPER bound** (the omitted
//! acceptance-path residue only lowers it; the consuming ruling margins
//! below) — INTERPOLATED (6.5 ⇒ ≈ 3.9 MB implied limit, inside the
//! measured 0.6–4.8 MB span). The earlier flagged-capture composition
//! (surge_max ≈ 6.4) is superseded; its capture stays archived as the
//! SIGILL record. Pre-registered bracket [≈3.6, ≈6.2]: realized just
//! above the anchor edge because the bracket capped the C++/single-proof
//! ratio at ≥ 1 — the inverted ratio was the one direction not priced. The
//! ×50 surge factor therefore re-derives to ×6 territory at those
//! verification costs.
//!
//! # Round-3 closures — domain, depth, batch, cache (each finding, one
//! disposition, directions stated SEPARATELY per steering's ruling)
//!
//! **Output-domain closure (every valid count 2..16, computed from measured
//! padded-tier costs + codec-exact weights — Bp+ cost depends only on the
//! padded slot count, verified input-insensitive in the captures):** in the
//! SINGLE-PROOF regime (the relay-admission shape, `bp_lone`) the density
//! argmax is NOT 2-out — the padded-boundary shapes win: 1-in/5-out
//! = 12.84 µs/B > 9-out 12.76 > 3-out 12.67 > 2-out 12.46 (a tx just past a
//! padding boundary pays a full Bp+ tier on minimal extra weight — the
//! review predicted exactly this). In the BATCHED regime (the connect path
//! this instrument prices) the Bp+ term collapses (1.745 ms/proof measured
//! at the zone count, C++) and the argmax REVERTS to 1-in/2-out at
//! 9.90 µs/B: the boundary shapes' edge is entirely Bp+, and batching
//! removes it. The composed surge_max therefore stands on the 2-out
//! argmax — with the 8/16-padded batched terms labeled composed-not-measured
//! (ratio-scaled diagnostics); the fill's fold measures the batch at each
//! fill shape and budget on the next floor run.
//!
//! **Two direction arguments, NOT jointly comforting — one is free, one is
//! a dependency on the margin:**
//!
//! - **Batch cardinality (free, conservative):** batching was measured at
//!   the zone count (46); the surge-ceiling block holds ≈ 299 minimal txs,
//!   and per-proof batched cost cannot exceed the measured SINGLE cost —
//!   composing at single-proof cost gives surge_max ≈ 6.0. So the batch
//!   unknown brackets **surge_max ∈ [≈6.0, ≈6.5]** and errs safe: the
//!   46-point bill overstates per-proof cost at larger batches.
//! - **Tree depth (NOT free — this is what the ruling's margin absorbs):**
//!   the sweep pins depth 2, today's shallowest tree; depth grows with the
//!   chain, no code change. Composing the relay bench's FLOOR-MEASURED
//!   per-layer slope (DAEMON_RELAY_PRIVACY.md §85.3: 1-in +3.76 ms/layer on
//!   the floor device) onto this campaign's terms: **surge_max ≈ 6.5 at d2, ≈ 5.7 at
//!   d7, ≈ 4.0 at the consensus-max d24** (composed, labeled — same
//!   machine, different fixture generation). An upper bound on ALLOWED
//!   surge is the unsafe direction to sit at: the consuming ruling margins
//!   below 6.5 precisely because depth eats toward it over chain life.
//!   State the tier for the horizon the ruling covers; never quote 6.5
//!   without its depth.
//!
//! **Cache-warmth fence (pointed the unsafe way; bounded, not waved off):**
//! the fill reuses one fixture, keeping its ~13-80 kB working set hot,
//! where a real block streams distinct txs. The measured terms are
//! compute-dominated — the dominant working set is the SHARED generator/
//! multiexp tables, identical for distinct txs — and the input-dependent
//! bytes are read once per verify either way, so the hot-vs-streaming
//! delta is bounded by budget-bytes over DRAM bandwidth: ≈ 0.2 ms per
//! 600 kB block ≈ 0.003 % of the bill. A distinct-fixture fill is the
//! named belt if any future term becomes memory-bound.
//!
//! # Fences
//!
//! Archival families (serve-credit / bond-post / emission) are OUT of this
//! first cut, **as reasoning, not verified impossibility**: their admission
//! requires consensus-valid archival state — a bonded `P` identity, a sealed
//! challenge, the epoch window (CEN-J7, CEN-J10; bond floor
//! `archival_bond_floor_atomic`) — so an adversary cannot pack them to the
//! weight cap the way spends pack, and their honest density is settlement-
//! cadence-bounded. **Reopener:** if archival load at scale approaches
//! weight-cap density, they carry hybrid signature verification per vin and
//! must enter the argmax. The pins test asserts the spend fixtures saturate
//! the caps they claim; nothing asserts archival absence — it is a scope
//! fence, stated.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand_core::OsRng;

use shekyl_verify_cost::connect::{
    bp_verify, bp_verify_block, build_connect_tx, parse_wire, pqc_verify, ConnectTxFixture,
};
use shekyl_verify_cost::relay::{admission_verify, masks_check, membership_verify, ChunkLayout};

/// The candidate worst-case shapes. The argmax must EMERGE from the sweep —
/// these are the two density extremes plus the interior, not a presumed
/// winner.
const SWEEP_SHAPES: [(usize, usize); 6] = [
    (1, 2),  // modal control (relay bench's pinned shape)
    (8, 2),  // max input density — fcmp + pqc heavy
    (1, 16), // max output density — bp + extra heavy
    (8, 16), // both caps
    (4, 4),  // interior
    (2, 8),  // interior
];

/// Today's production topology: depth 2, scattered inputs. The depth axis is
/// the relay bench's surface (its d1..d7 sweep); re-sweeping it here would
/// duplicate an instrument.
const TREE_DEPTH: u8 = 2;

/// Every component the bench times verifies, or it times a reject path.
fn assert_verifies(fx: &ConnectTxFixture) {
    let status = admission_verify(&fx.adm);
    assert!(status.verified(), "admission fixture: {status:?}");
    assert_eq!(pqc_verify(&fx.pqc), Ok(()), "pqc auth");
    assert!(bp_verify(&fx.bp), "bp+ fixture");
}

/// One listed transaction's per-slot terms, in `form`'s order: the parse,
/// `tx_form`'s mask row (CEN-H17), the signatures (CEN-I18, one per input),
/// the proof (CEN-I15). The range proof is not here: `form` verifies a
/// block's range proofs together after the slot loop (CEN-H19).
fn slot_verify(fx: &ConnectTxFixture) {
    // Shape agreement between the crypto fixtures and the wire form — the
    // same pin the tests carry, kept live where the timing happens.
    assert_eq!(fx.bp.commitments.len(), fx.n_out);
    let parsed = parse_wire(fx);
    std::hint::black_box(parsed);
    assert_eq!(masks_check(&fx.adm), Ok(()));
    for _ in 0..fx.n_in {
        assert_eq!(pqc_verify(&fx.pqc), Ok(()));
    }
    assert!(matches!(membership_verify(&fx.adm), Ok(true)));
}

fn weight_bytes(bytes: usize) -> Throughput {
    Throughput::Bytes(u64::try_from(bytes).expect("weight fits u64"))
}

fn bench_terms(c: &mut Criterion) {
    let mut group = c.benchmark_group("block_connect_terms");
    group.sample_size(10);

    for (n_in, n_out) in SWEEP_SHAPES {
        let fx = build_connect_tx(&mut OsRng, n_in, n_out, TREE_DEPTH, ChunkLayout::Spread);
        assert_verifies(&fx);

        let tag = format!("in{n_in}_out{n_out}_w{}", fx.weight);
        group.throughput(weight_bytes(fx.weight));

        group.bench_with_input(BenchmarkId::new("adm", &tag), &fx, |b, f| {
            b.iter(|| admission_verify(&f.adm))
        });
        group.bench_with_input(BenchmarkId::new("pqc_per_input", &tag), &fx, |b, f| {
            b.iter(|| pqc_verify(&f.pqc))
        });
        group.bench_with_input(BenchmarkId::new("bp_lone", &tag), &fx, |b, f| {
            b.iter(|| bp_verify(&f.bp))
        });
        group.bench_with_input(BenchmarkId::new("parse", &tag), &fx, |b, f| {
            b.iter(|| parse_wire(f))
        });
    }

    group.finish();
}

fn bench_budget_fill(c: &mut Criterion) {
    let mut group = c.benchmark_group("block_connect_budget_fill");
    group.sample_size(10);

    // The two density extremes, PLUS the measured argmax: the first sweep
    // found the smallest tx (1-in/2-out) carries the highest cost per
    // weight-byte — the per-proof fixed cost dominates, so a block of many
    // minimal txs outprices both presumed extremes. The candidates stay so
    // the fill re-verifies the ordering, not just the winner.
    for (n_in, n_out, shape_tag) in [
        (1usize, 2usize, "in1_out2"),
        (8usize, 2usize, "in8_out2"),
        (1usize, 16usize, "in1_out16"),
    ] {
        let fx = build_connect_tx(&mut OsRng, n_in, n_out, TREE_DEPTH, ChunkLayout::Spread);
        assert_verifies(&fx);

        // Multi-point span so the marginal per-byte cost is MEASURED, not
        // inferred from endpoints (rule 76 §4's failure mode within one
        // machine). 600 000 = 2 × zone, the permanent floor operating point.
        for budget in [600_000usize, 1_200_000, 2_400_000, 4_800_000] {
            let n_txs = budget / fx.weight;
            assert!(n_txs >= 1, "budget below one tx weight");
            assert!(bp_verify_block(&fx.bp, n_txs), "the block's fold verifies");
            group.throughput(weight_bytes(n_txs * fx.weight));
            group.bench_with_input(
                BenchmarkId::new(shape_tag, format!("budget{budget}_n{n_txs}")),
                &fx,
                |b, f| {
                    b.iter(|| {
                        for _ in 0..n_txs {
                            slot_verify(f);
                        }
                        assert!(bp_verify_block(&f.bp, n_txs));
                    })
                },
            );
        }
    }

    group.finish();
}

fn bench_randomx_once(c: &mut Criterion) {
    let mut group = c.benchmark_group("block_connect_pow");
    group.sample_size(10);

    // Cache derivation is epoch-scoped (once per seed epoch, amortized over
    // thousands of blocks) — derived in setup, deliberately outside the
    // per-block figure. The per-block PoW term is one compute_hash.
    let prepared = shekyl_pow_randomx::PreparedCache::derive(
        shekyl_pow_randomx::Seedhash::from_bytes([7u8; 32]),
    );
    let header = [0x5Au8; 80];

    group.bench_function("randomx_once_per_block", |b| {
        b.iter(|| shekyl_pow_randomx::compute_hash(&prepared, &header))
    });

    group.finish();
}

criterion_group!(benches, bench_terms, bench_budget_fill, bench_randomx_once);
criterion_main!(benches);
