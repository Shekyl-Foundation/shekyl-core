// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The adopted per-shape verification-cost surface — option D of
//! `DAEMON_RELAY_PRIVACY.md` §80, with §87's structural guards.
//!
//! `hop`'s dominant measurable term is the FCMP++ verification a relay
//! performs before forwarding (§71), and that cost is **sorted by transaction
//! shape**: at the spec machine the pool door's sequence spans 148.0 ms
//! (1 input, genesis tree) to 2 456.4 ms (20 inputs, depth-7 tree) — the
//! floor session's membership-proof cells plus the door's signature and
//! range-proof terms (§72.2, BA-Q9; `CEN_I4_INPUT_CAP_DERIVATION.md`
//! `ICD-R5`). A scalar provisioned anywhere
//! on that range either over-provisions the modal transaction or
//! under-provisions the tail, and the tail's gap *widens* with chain age
//! (§82.3: 3.0× → 5.3× over the chain's life). So the adopted shape is a
//! **lookup table over two closed axes** — `f(n_in, depth)` — never a scalar
//! and never a fitted curve, which would invite evaluation past the domain's
//! edge (§80.5: "a table cannot be evaluated at 9").
//!
//! # The spec machine, and why every spec cell must come from it
//!
//! Constants derived from measured work time inherit the measuring machine's
//! speed. Derive them on a fast machine and the result is anonymity that
//! correlates with operator hardware — silently, because below-spec nodes
//! miss timing windows with no feedback channel (rule
//! `76-device-provisioning-floor`). The floor is **Raspberry Pi 4 Model B**
//! (§80.4), so every cell on the spec path carries [`Provenance`] and must be
//! [`Provenance::MeasuredPi4`] — asserted by test, not review (§87.2). The
//! x86 arm exists to detect workload changes (§84.2); it derives nothing.
//!
//! # Refuse, never clamp (§83.3)
//!
//! [`SpecVerifyCost::f_ms`] returns an error for any cell the table does not
//! carry. A clamped row would give large-input senders an embargo derived for
//! a shallower tree than the one they are actually traversing — invisibly,
//! and falling on exactly the population §75's sorting is about. Refusing
//! turns tree growth past the table's edge into a loud, immediate condition;
//! tree depth is knowable at runtime, so the check costs nothing. A dated
//! note in a design document is a hope; a table that stops answering is a
//! deadline.
//!
//! # Every legal cell is measured
//!
//! The table holds every shape a mineable transaction can take at `n_out = 2`:
//! `n_in = 1..=N(d)` at each depth `d` from 2 to 7, where `N(d)` is the most
//! inputs the weight limit admits at that depth (22, 22, 22, 21, 21, 20; 128
//! cells). Each row's length *is* its depth's legal count, so a count past it
//! is refused by name ([`VerifyCostRefusal::NoLegalShapeAtDepth`]), never
//! answered. All 128 were measured on the floor device in one session on one
//! binary (`CEN_I4_INPUT_CAP_DERIVATION.md` `ICD-R5`, 2026-11-27;
//! `docs/benchmarks/relay_admission_verify_pi4_rust_20261127T144430Z.txt`).
//! `tests/spec_decision_matrix.rs` pins each row's length to the wire's
//! legal-shape function and each operand to that capture.

use crate::basis::{AdmissibleBasis, DerivationMs};

/// Where a cell's number comes from — a **field**, not a comment (§87.2).
///
/// The shortcut this arc keeps catching is a value measured on a fast machine
/// standing in for a value the spec machine owes: `175` (a 2019 laptop
/// comment), `peers = 8` (a 2015 server graph), `F` (an instrument at degree
/// 8), and §80.3's own first pricing (x86 × 5.56 presented as "measured").
/// Rule 76.4 forbids it in prose — **values and increments** are measured on
/// the floor device, never scaled to it (§85.5 measured the marginal ratio at
/// 5.98× against the totals' 5.56×, so a scaled increment under-provisions
/// the tail rows by ~7.5 %). As a field with an assertion on top, the
/// shortcut stops being a review item and becomes an edit someone has to make
/// to a thing that names its own purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// Measured **on the spec machine** — the floor device in the
    /// configuration `ICD-R5` names (Raspberry Pi 4 Model B Rev 1.4, 1.8 GHz,
    /// 8 GB, `ondemand` governor), thermal margin recorded (§73.1, §85.1).
    MeasuredPi4,
    /// Measured on the reference machine. Diagnostic only (§84.2): it exists
    /// to detect a workload change, never to derive a spec value.
    MeasuredX86,
    /// **Not measured on any machine**: an x86 total multiplied by a factor,
    /// present only to bracket a decision. Never a spec value (rule 76.4).
    ScaledFromX86,
}

/// What tree the cell was measured against — §81.2's label, carried at the
/// value so a reader cannot mistake a synthesized number for a measured fact
/// about the deployed chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeBasis {
    /// The genesis-era tree the network actually runs today (depth 2).
    Genesis,
    /// A synthesized deep tree under genesis-era conditions. The real
    /// depth-N tree arrives years out, with different data volumes and
    /// memory pressure — so this number is a **prior to be confirmed by
    /// re-measurement on the spec machine against the actual tree**, not a
    /// measurement of that tree (§81.2, §81.3). Treating it as measured is
    /// `175`'s failure exactly: a plausible number standing where a
    /// measurement belongs.
    SynthesizedProjection,
}

/// One populated cell of the verification-cost surface.
///
/// # A cell asserts CO-OCCURRENCE, which constrains how its fields may be set
///
/// This record names a shape — `(n_in, depth)`, at `n_out = 2` — so every field
/// must describe **that** transaction. Setting one field to a worst case while
/// another holds a measurement of a different shape produces a figure for a
/// configuration **that cannot occur**, and such a figure is not conservative;
/// it is meaningless, and it reliably *looks* conservative, which is why
/// inspection does not catch it.
///
/// Three instances of that one class have been found in this arc, all reading
/// as safe:
///
/// 1. §94.9's negligibility test compared the largest **message** against the
///    cheapest **verification** — shapes that cannot co-occur — and reported
///    5.66 % where like-for-like gives 1.07 %.
/// 2. An early `resonance_clearance_ms` reported the distance to a boundary the
///    hop had **already passed**, so the smallest true clearance produced the
///    largest reported one.
/// 3. Pinning [`Self::msg_bytes`] at `MAX_OUTPUTS` while [`Self::millis`]
///    measured `n_out = 2` — proposed as a conservative fix for (1)'s family and
///    reversed for being (1) again, one field over.
///
/// **The discipline: worst-case-per-field is sound for a scalar standing alone
/// and unsound inside a record that already names its shape.** Where a field
/// cannot be set consistently, leave the axis **unpriced and named** — the
/// answer this table already gives past [`MAX_TABLE_DEPTH`] — rather than
/// approximated.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct VerifyCell {
    /// Verification cost in milliseconds of the pool door's sequence at this
    /// shape and `n_out = 2` (§72.2, amended 2026-11-08): the FCMP++
    /// membership proof with the output masks (the floor session's cell), `n_in` hybrid
    /// Ed25519 + ML-DSA-65 signature verifications (CEN-I18), and the range
    /// proof as a batch of one (CEN-H19 at `TxSlot::Lone`). See
    /// [`DoorOperands`] for the sum and its sources.
    ///
    /// The output axis is excluded from the cell, not from the cost: the
    /// masks term is ~0.07 ms per output (§72.3), and the range proof grows
    /// with the padded output count (18.838 ms at 2 outputs, 107.3 ms at 16,
    /// `bp_lone` in
    /// `docs/benchmarks/gap7_block_verify_pi4_rust_20261108T232442Z.txt`).
    /// That is the unpriced output axis [`Self::msg_bytes`] names; a
    /// wider-output cell is measured, never scaled from these.
    pub millis: f64,
    /// Which machine produced the number.
    pub provenance: Provenance,
    /// Which tree the number was measured against.
    pub basis: TreeBasis,
    /// Wire bytes of the `NOTIFY_NEW_TRANSACTIONS` carrying this cell's shape —
    /// transaction plus levin envelope, at the cell's own `n_out = 2`.
    ///
    /// **Derived, not measured**, and deliberately a separate field from
    /// [`Self::millis`]: `millis` carries a [`Provenance`], and folding a
    /// computed term into a measured one would put a synthesized number under
    /// a `MeasuredPi4` label — the exact confusion `Provenance` exists to
    /// prevent (§87.2).
    ///
    /// # The output axis: a NAMED GAP, not a silent one — and not a cushion
    ///
    /// `millis` excludes the output count because §72.3 measured verification
    /// at ~0.07 ms per output, genuinely unable to move the constant. **Message
    /// size is not like that**: each output adds ~2.4 KiB of wire, so at the
    /// same `(n_in, depth)` a 16-output transaction is **27–134 % larger** than
    /// the 2-output one, and its crypto term is larger by the same factor.
    ///
    /// **This field is nonetheless pinned at the cell's own `n_out = 2`, and
    /// the reason is coherence.** A cell whose `millis` measured a 2-output
    /// transaction and whose `msg_bytes` described a 16-output one would
    /// describe a transaction that **cannot exist** — which is precisely the
    /// mispairing that produced §94.9's wrong disposition, one field over.
    /// Provisioning a term at the worst case is sound when the term stands
    /// alone; inside a cell that already names its shape, it is a mismatch.
    ///
    /// So the surface prices the `n_out = 2` shape, as it always did, and the
    /// output axis is **unpriced rather than approximated**. That is the same
    /// answer this table gives past [`MAX_TABLE_DEPTH`]: it refuses instead of
    /// extrapolating. Closing the gap means **measuring** wider-output cells on
    /// the spec machine (§84.2), never scaling these.
    ///
    /// Recorded because it is a real under-provision in the privacy-losing
    /// direction (§65, §66): a wider transaction's hop is understated, which
    /// shortens its derived embargo. It is bounded — the embargo is a
    /// network-wide constant derived at the modal shape, and the term is ~1 ms
    /// against a ~700 ms hop — but it is a gap, and it is named here rather
    /// than left for someone to rediscover.
    ///
    /// Pinned against `predict_size_and_weight` + a real `notify` in
    /// `tests/carrier_window.rs`; nothing here is a literal that check could
    /// agree with by construction.
    pub msg_bytes: u32,
}

/// The shallowest tree depth the table covers — the genesis tree.
pub const GENESIS_TREE_DEPTH: u32 = 2;

/// The deepest tree depth the table covers (≈ 675 M outputs, §82.1). Past
/// this edge [`SpecVerifyCost::f_ms`] refuses — see the module docs.
pub const MAX_TABLE_DEPTH: u32 = 7;

/// The input-count domain the table covers: `1..=22`, the longest row.
///
/// It is the consensus cap: the weight limit admits 22 inputs at the
/// shallowest depths, and no depth admits more. `shekyl-node` asserts this
/// constant equals the cap the wire enforces, so the table neither prices a
/// count consensus refuses nor leaves a consensus-legal count unpriced. A
/// count inside it that a deeper tree cannot carry is
/// [`VerifyCostRefusal::NoLegalShapeAtDepth`].
pub const MAX_TABLE_INPUTS: usize = 22;

const DEPTH_TIERS: usize = (MAX_TABLE_DEPTH - GENESIS_TREE_DEPTH + 1) as usize;

/// Why the table did not answer. Every variant is a **refusal, not a
/// fallback** — the calling layer must surface it loudly, never substitute a
/// neighbouring cell (§83.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyCostRefusal {
    /// `n_in` is outside `1..=MAX_TABLE_INPUTS`. Zero-input transactions do
    /// not exist, and consensus refuses every count past the cap — a table is
    /// not evaluated past its domain (§80.5).
    InputCountOutsideDomain {
        /// The out-of-domain input count.
        n_in: usize,
    },
    /// The tree is outside the table's depth coverage. This is the loud
    /// condition §83.3 designs for: the chain grew past the surface's edge
    /// and the scheduled re-measurement is now **due**, not merely dated. A
    /// clamped answer here would hand large-input senders an embargo derived
    /// for a shallower tree than they are traversing — invisibly.
    DepthOutsideTable {
        /// The uncovered depth.
        depth: u32,
    },
    /// `n_in` is inside the cap, but no transaction of that many inputs fits
    /// the weight limit at this depth (the depth's row is shorter: 21 inputs
    /// at depths 5 and 6, 20 at depth 7). Consensus refuses such a
    /// transaction by weight (CEN-H3), so there is no cost to price, and the
    /// shallower row beside it is not this shape's cost.
    NoLegalShapeAtDepth {
        /// The requested input count.
        n_in: usize,
        /// The requested depth.
        depth: u32,
    },
}

/// The spec-path verification-cost table: `f(n_in, depth)` on the machine the
/// guarantee is provisioned to.
#[derive(Debug)]
pub struct SpecVerifyCost {
    /// One row per depth, genesis first; a row's length is its depth's legal
    /// input count and `row[n_in - 1]` is that shape's cell.
    rows: [&'static [VerifyCell]; DEPTH_TIERS],
}

/// The node's own symmetric-crypto cost over a message of `msg_bytes`, on the
/// floor device.
///
/// Crate-internal: [`SpecVerifyCost::f_ms`] is the only consumer, and the
/// public surface is the summed hop term rather than its parts. The measured
/// half is [`VerifyCell::millis`], reached via [`SpecVerifyCost::populated`].
///
/// `const` because [`SpecVerifyCost::f_ms`] is, and that is not incidental:
/// `f_ms` is consumed in `const` contexts (`spec_decision_matrix.rs` binds its
/// results to `const` items), so a runtime-only term here would have forced
/// those to become runtime lookups.
///
/// The cast is exact: `msg_bytes` is a `u32` and every value below `2^53` is
/// representable in `f64`. `f64::from` would be the idiomatic form but is not
/// `const`.
#[allow(clippy::cast_lossless)]
const fn node_crypto_ms(msg_bytes: u32) -> f64 {
    msg_bytes as f64 * NODE_CRYPTO_PASSES / PI4_AES_BYTES_PER_SEC * 1_000.0
}

mod door;
use door::{
    DoorOperands, PI4_MASKS_AND_PROOF_D2_MS, PI4_MASKS_AND_PROOF_D3_MS, PI4_MASKS_AND_PROOF_D4_MS,
    PI4_MASKS_AND_PROOF_D5_MS, PI4_MASKS_AND_PROOF_D6_MS, PI4_MASKS_AND_PROOF_D7_MS,
};

const fn pi4(millis: f64, basis: TreeBasis, msg_bytes: u32) -> VerifyCell {
    VerifyCell {
        millis,
        provenance: Provenance::MeasuredPi4,
        basis,
        msg_bytes,
    }
}

/// Passes an emitted message's bytes take through symmetric crypto on the
/// node's own hop.
///
/// Crate-internal for the same reason as [`node_crypto_ms`]: it is an input to
/// the summed term, not part of the surface — Tor cell layer plus TLS, counted in BOTH directions with
/// slack.
const NODE_CRYPTO_PASSES: f64 = 10.0;

/// MEASURED floor AES-128-CTR on the floor device (the reference Pi 4 Model B),
/// 2026-08-21. Units: **decimal** bytes/sec. `openssl speed` reports "in 1000s
/// of bytes per second"; the 8 KB-block figure was `138993.66k`, so
/// `138_993.66 * 1000 = 138_993_660` B/s — used EXACTLY, not rounded to
/// `0.139e9`. Rounding a measured rate *up* makes the crypto look cheaper,
/// which is the wrong direction; when this is re-measured, replace the literal
/// rather than tidying it.
///
/// The Cortex-A72 has NO ARMv8 crypto extension (cpuinfo Features:
/// `fp asimd evtstrm crc32 cpuid` — no aes), so this is software AES, ~94×
/// slower than the x86 reference. An earlier draft ASSUMED hardware AES and
/// bounded it at 0.8 GB/s; the floor measurement (§94.9) refuted that by 5.8×.
const PI4_AES_BYTES_PER_SEC: f64 = 138_993_660.0;

/// A populated cell must be a plausible per-hop verification cost: positive,
/// finite, and under ten seconds. `millis > 0.0` is `false` for NaN, and the
/// upper bound excludes `+inf` along with any figure that could not be a
/// verification measurement (the costliest cell is 2 456.4 ms; ten
/// seconds is four times that, not a tuning bound).
const fn cell_is_plausible(millis: f64) -> bool {
    millis > 0.0 && millis < 10_000.0
}

// The cells are authored at compile time, so the malformed-constant guard
// runs then too: a NaN, infinite, negative, or absurd cell is a **compile
// error**, never a value that flows out of `f_ms` and saturates in a cast
// downstream. A runtime refusal variant for this was considered and
// rejected — no runtime path can produce the state, so the variant would be
// permanent error surface with no producer (rule 21), where this guard is
// the same §83.3 device the table already uses: the mistake requires a
// visible edit, and here it cannot even build.
const _: () = {
    let mut d = 0;
    while d < DEPTH_TIERS {
        let row = SPEC_VERIFY_COST.rows[d];
        assert!(
            row.len() <= MAX_TABLE_INPUTS,
            "a depth's row is longer than the table's input domain"
        );
        let mut n = 0;
        while n < row.len() {
            assert!(
                cell_is_plausible(row[n].millis),
                "a populated verification-cost cell is not a plausible \
                 measurement (NaN, non-positive, infinite, or >= 10 s)"
            );
            n += 1;
        }
        d += 1;
    }
};

/// Wire bytes of each depth's `NOTIFY_NEW_TRANSACTIONS` at `n_in = 1..=N(d)`,
/// `n_out = 2` ([`VerifyCell::msg_bytes`]): transaction plus Levin envelope,
/// fee varint at its widest. Derived from the wire model, not measured;
/// `tests/carrier_window.rs` checks every one against
/// `predict_size_and_weight` and a real `notify`.
const MSG_BYTES_D2: [u32; 22] = [
    13_311, 21_297, 27_297, 34_513, 38_913, 45_617, 52_321, 58_897, 64_513, 69_361, 75_809, 82_129,
    88_449, 94_897, 101_217, 107_538, 113_026, 119_218, 124_066, 130_130, 136_450, 142_642,
];
const MSG_BYTES_D3: [u32; 22] = [
    13_695, 20_465, 28_065, 33_937, 39_937, 46_769, 52_257, 58_833, 64_449, 71_025, 77_473, 84_049,
    89_281, 95_729, 102_178, 108_498, 113_986, 120_306, 126_754, 133_074, 139_522, 145_714,
];
const MSG_BYTES_D4: [u32; 22] = [
    14_335, 21_745, 28_513, 34_513, 40_641, 47_601, 53_217, 59_921, 65_665, 72_369, 78_945, 85_650,
    91_010, 97_586, 104_162, 110_610, 116_226, 122_674, 129_250, 135_698, 142_274, 148_594,
];
const MSG_BYTES_D5: [u32; 21] = [
    14_719, 22_257, 27_937, 35_281, 40_449, 47_409, 54_369, 61_201, 67_073, 72_817, 79_521, 86_226,
    92_930, 99_634, 106_338, 112_914, 118_658, 125_234, 131_938, 137_426, 144_002,
];
const MSG_BYTES_D6: [u32; 21] = [
    15_359, 22_065, 28_001, 35_345, 41_729, 47_857, 54_945, 61_777, 68_866, 74_738, 80_738, 87_442,
    94_274, 101_106, 107_938, 114_514, 121_346, 128_178, 135_010, 140_626, 147_330,
];
const MSG_BYTES_D7: [u32; 20] = [
    14_783, 21_617, 28_513, 35_153, 42_497, 48_753, 55_969, 62_097, 69_186, 76_146, 82_274, 89_106,
    96_066, 103_026, 109_986, 115_858, 122_818, 129_650, 136_610, 143_314,
];

/// One depth's row: cell `i` is the `(i + 1)`-input shape, its door
/// sequence composed from that shape's masks-and-proof term.
const fn row<const N: usize>(
    masks_and_proof_ms: [f64; N],
    msg_bytes: [u32; N],
    basis: TreeBasis,
) -> [VerifyCell; N] {
    let mut cells = [pi4(0.0, basis, 0); N];
    let mut i = 0;
    while i < N {
        cells[i] = pi4(
            DoorOperands::at(masks_and_proof_ms[i], i + 1).millis(),
            basis,
            msg_bytes[i],
        );
        i += 1;
    }
    cells
}

const ROW_D2: [VerifyCell; 22] = row(PI4_MASKS_AND_PROOF_D2_MS, MSG_BYTES_D2, TreeBasis::Genesis);
const ROW_D3: [VerifyCell; 22] = row(
    PI4_MASKS_AND_PROOF_D3_MS,
    MSG_BYTES_D3,
    TreeBasis::SynthesizedProjection,
);
const ROW_D4: [VerifyCell; 22] = row(
    PI4_MASKS_AND_PROOF_D4_MS,
    MSG_BYTES_D4,
    TreeBasis::SynthesizedProjection,
);
const ROW_D5: [VerifyCell; 21] = row(
    PI4_MASKS_AND_PROOF_D5_MS,
    MSG_BYTES_D5,
    TreeBasis::SynthesizedProjection,
);
const ROW_D6: [VerifyCell; 21] = row(
    PI4_MASKS_AND_PROOF_D6_MS,
    MSG_BYTES_D6,
    TreeBasis::SynthesizedProjection,
);
const ROW_D7: [VerifyCell; 20] = row(
    PI4_MASKS_AND_PROOF_D7_MS,
    MSG_BYTES_D7,
    TreeBasis::SynthesizedProjection,
);

/// The adopted table (§80): every legal shape at `n_out = 2`, measured on the
/// floor device.
///
/// Each cell is [`DoorOperands::millis`] over the floor session's operands
/// (`door.rs`): the masks-and-proof term at that shape, `n_in` hybrid
/// signature verifications and the lone range proof, all from one session on
/// one binary (`ICD-R5`, 2026-11-27). The session ran with the node stopped
/// and no login during the bench; the core temperature stayed between 49.7
/// and 58.9 °C against the 80 °C soft-throttle. Every fixture verified before
/// it was timed, so no cell times a reject path. Depths 3 to 7 are
/// synthesized-tree projections per §81.2 and labelled so.
/// `tests/spec_decision_matrix.rs` recomputes every cell from the committed
/// capture.
pub const SPEC_VERIFY_COST: SpecVerifyCost = SpecVerifyCost {
    rows: [&ROW_D2, &ROW_D3, &ROW_D4, &ROW_D5, &ROW_D6, &ROW_D7],
};

impl SpecVerifyCost {
    /// The **node-local** term of `hop` for a transaction of `n_in` inputs
    /// against a tree of the given depth, in milliseconds — or a refusal.
    ///
    /// # Two terms, one axis (2026-08-23)
    ///
    /// This is FCMP++ verification **plus the node's own Tor/TLS crypto over
    /// the emitted message**. The second used to be tracked separately as a
    /// "fourth hop term" that had to be shown negligible. It is not a fourth
    /// axis: node-crypto cost scales with message size, message size is a
    /// function of `(n_in, depth)`, and this function is already a function of
    /// exactly those. Folding it in **removes the negligibility question**
    /// rather than answering it — there is no longer a fraction to compare
    /// against a bar.
    ///
    /// The two terms keep separate provenance: [`VerifyCell::millis`] is
    /// measured on the spec machine, [`VerifyCell::msg_bytes`] is derived from
    /// the wire model, and only the sum crosses here. The measured half is
    /// `cell.millis` from [`Self::populated`].
    ///
    /// # This does NOT price the crypto term across the admissible range
    ///
    /// The table refuses past [`MAX_TABLE_DEPTH`] (7) while transactions are
    /// admissible to `MAX_TREE_DEPTH` (24), so folding a term into this
    /// function puts it behind the same refusal. That is Option D's
    /// table-refuses-past-its-edge design working as ruled — but "folded into
    /// `f_ms`" must not be read as "priced across every shape the consensus
    /// admits". It is priced exactly where the table answers.
    ///
    /// # Errors
    ///
    /// Refuses — never clamps — outside the populated surface; see
    /// [`VerifyCostRefusal`] for why each refusal is the correct answer and
    /// what harm a fallback would do (§83.3, §87.3).
    pub const fn f_ms(&self, n_in: usize, depth: u32) -> Result<f64, VerifyCostRefusal> {
        // `?` is not yet stable in `const fn` (rustc 1.94).
        match self.cell(n_in, depth) {
            Ok(cell) => Ok(cell.millis + node_crypto_ms(cell.msg_bytes)),
            Err(e) => Err(e),
        }
    }

    /// The populated cell at `(n_in, depth)`, or the same refusal [`Self::f_ms`]
    /// would return. One lookup; `f_ms` is the hop term composed from it.
    const fn cell(&self, n_in: usize, depth: u32) -> Result<VerifyCell, VerifyCostRefusal> {
        if n_in < 1 || n_in > MAX_TABLE_INPUTS {
            return Err(VerifyCostRefusal::InputCountOutsideDomain { n_in });
        }
        if depth < GENESIS_TREE_DEPTH || depth > MAX_TABLE_DEPTH {
            return Err(VerifyCostRefusal::DepthOutsideTable { depth });
        }
        let row = self.rows[(depth - GENESIS_TREE_DEPTH) as usize];
        if n_in > row.len() {
            return Err(VerifyCostRefusal::NoLegalShapeAtDepth { n_in, depth });
        }
        Ok(row[n_in - 1])
    }

    /// The populated cells, for the §87.2 provenance assertion and for
    /// instruments that report the surface. Order: `n_in` major, depth minor.
    pub fn populated(&self) -> impl Iterator<Item = (usize, u32, VerifyCell)> + '_ {
        (1..=MAX_TABLE_INPUTS).flat_map(move |n_in| {
            // Rows are DEPTH_TIERS long and DEPTH_TIERS is derived from this
            // exact range, so the zip is total by construction.
            (GENESIS_TREE_DEPTH..=MAX_TABLE_DEPTH)
                .zip(self.rows.iter())
                .filter_map(move |(depth, row)| row.get(n_in - 1).map(|c| (n_in, depth, *c)))
        })
    }
}

/// The transit term of `hop`, **assumed, not measured** — 50 ms, §86.2.
///
/// §21's own justification for the inherited `175` contained "at least 50 ms
/// … if crossing an ocean"; this carries that assumption forward *labelled*,
/// which is the difference §86.2 asks for. It ships as an assumption because
/// transit is the one term of `hop` that **passes** §83.4's sorting test —
/// it is a property of the path between two nodes, not of the sender's
/// **hardware**, so it cannot reintroduce the sorting the table and the Pi
/// floor remove (§86.1 — recorded here per §87.4 because a check that only
/// ever convicts is a worry, not an instrument; transit is its first
/// acquittal). It is also dominated at the tail: about 2.5 s of verification
/// against ~50 of transit at the 20-input depth-7 cell.
///
/// > **Narrowed 2026-08-20 (§94.5).** This previously read "not of the
/// > sender's hardware *or the transaction's shape*". **Only the hardware
/// > clause was ever load-bearing.** §83.4 asks *does this axis cost every
/// > participant the same?* — a question about sorting **nodes**. Size
/// > sorts **transactions**: a 16 KiB spend costs more transit than the modal
/// > one, but it costs *every* relaying node the same extra, and advantages
/// > no machine over another. The acquittal is unaffected.
/// >
/// > The shape clause was also never true of `hop` as a whole, two lines
/// > below: verification is `f_ms(n_in, depth)` and spans **23.6 ms to 792 ms**
/// > — 33× on exactly the disclaimed axis. A size term in transit adds to an
/// > existing axis rather than opening a new one.
/// >
/// > It was free to write at ~50 ms, where size-dependence is buried, and
/// > stops being free at [`ANON_ZONE_TRANSIT_ASSUMPTION_MS`] on a
/// > cell-quantised transport. Three regimes: clearnet ordinary — negligible;
/// > **anonymity ordinary — unknown, and §94's round measures the slope**;
/// > anonymity **carrier** — constant by construction, since fixed 3 KiB slots
/// > make per-slot transit invariant and size enters only as fragment count,
/// > which §2.8 already counts explicitly.
///
/// When it is measured (whenever convenient — it is a refinement, not a
/// gate, §86.2): a **quantile, not a mean**, with `F`'s asymmetry —
/// under-estimating shortens the embargo, the privacy-losing direction.
/// Under Ruling B (§97) that measurement is taken on the Rust path; a
/// reading with C++ in the path is not what replaces this.
pub const ADOPTED_TRANSIT_ASSUMPTION_MS: f64 = 50.0;

/// [`ADOPTED_TRANSIT_ASSUMPTION_MS`] as the value a derivation consumes: an
/// assumption (§86.2; the register, §97). The bare `f64` is the number the
/// flood instrument and the measurement ledger name.
pub const ADOPTED_TRANSIT: DerivationMs = DerivationMs::assumption(50);

const _: () = assert!(ADOPTED_TRANSIT.ms() == 50);
const _: () = assert!(ADOPTED_TRANSIT_ASSUMPTION_MS == 50.0);

/// Row names for the flood instrument.
///
/// Not a connector identity. This crate's dependency is `shekyl-draw-rng`,
/// which has no connector type, so `ConnectorId` is not in scope. These
/// variants name flood-instrument rows.
/// Production transit is the D7 declaration's `transit_ms` cell, which is
/// these constants with their basis. Neither row is a measurement: both are
/// assumptions (§97). A new reading is a variant here; it does not by itself
/// make a connector stemmable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MeasuredConnector {
    /// [`ADOPTED_TRANSIT`].
    Clearnet,
    /// [`ANON_ZONE_TRANSIT`].
    Tor,
}

impl MeasuredConnector {
    /// Closed set of instrument rows. A new variant is a member here.
    pub const ALL: [Self; 2] = [Self::Clearnet, Self::Tor];
}

/// The transit assumption for one [`MeasuredConnector`] row, with its basis.
#[must_use]
pub const fn transit_ms_for_connector(connector: MeasuredConnector) -> DerivationMs {
    match connector {
        MeasuredConnector::Clearnet => ADOPTED_TRANSIT,
        MeasuredConnector::Tor => ANON_ZONE_TRANSIT,
    }
}

/// The transit assumption for the **anonymity zones** (Tor), in
/// milliseconds.
///
/// # THE PREMISE THIS IS DERIVED ON — re-grounded 2026-08-23, see §89.8.4
///
/// > This value is derived on the premise that a transaction entering an
/// > anonymity zone's stem **completes that stem there**. That premise was
/// > not shipped when this comment was first written: `relay_txpool_transactions`
/// > re-relayed anonymity-arrived traffic to `zone::public_` because the
/// > `forward` class never reached `send_txs` at arrival, and the remaining
/// > hops this constant spaces ran on a network it is not sized for.
/// >
/// > **Q12-U2 closed that path.** Arrivals enter as `stem`. Arrival-coherence
/// > (`KeepArrival`) is deleted: the session's notifier stems a forward, and
/// > `set_relayed` draws
/// > the per-zone embargo — the zone is a parameter beside `tx_relay`, which
/// > is the input §89.2 already had. Originated traffic still keeps `local`
/// > and does not draw, by §89.8.3. The checklist at §89.8.4 is the current
/// > claim; do not restate liveness here.
/// >
/// > **Do not read the interim below as awaiting a mechanism.** The mechanism
/// > for relayed arrivals has landed. What this value still awaits is the
/// > measurement that replaces the guess. The hop-to-step pin (entry 2 of
/// > that checklist) is live on the relayed path.
///
/// # INTERIM AND UNMEASURED — §89.5
///
/// This is an *assumption*, recorded at its site the way
/// [`ADOPTED_TRANSIT_ASSUMPTION_MS`] is, and it is **not** a measurement.
/// §89 ruled that the anonymity zone stems, which creates Tor-latency hops
/// inside a stem for the first time and makes this term load-bearing on the
/// embargo — §86's "refinement, not a gate" was stated under the no-stem
/// posture and expired with it.
///
/// **Provenance, and why it survives its own section.** §63.2 swept the
/// anonymity path to *"ten times clearnet latency"*, `hop = 1750 ms`, as its
/// worst case. This constant is that hop less the membership-proof cell it
/// was swept beside (1750 − 124.5 = 1625.5 → 1625); paired with the door's
/// whole sequence (§72.2, BA-Q9) the Tor hop is 1774 ms.
///
/// **§63.2's conclusion is retired and its sweep is not, and the distinction is
/// the whole reason this citation is usable.** What §63.2 concluded — that the
/// anonymity path is over-provisioned by ≥75 % — depended on the diffusing
/// posture, where stem length was 1 with certainty; §89.1 retired that.
/// What it *swept* was the plausible range of a Tor-borne `hop`, and that range
/// is a property of the network's latency, not of whether the zone stems. The
/// bound is therefore inherited from a withdrawn section without inheriting its
/// argument — a reader following the citation should expect to land in retired
/// text and find only the sweep still standing.
///
/// It remains an upper bound taken on faith, not a measurement, and §63.2 never
/// claimed otherwise: 10× was chosen as a comfortable ceiling precisely because
/// nothing measured the real value.
///
/// **Why err high.** Under-estimating shortens the embargo, which is the
/// privacy-losing direction (§65, §66). Over-estimating costs black-hole
/// recovery latency and nothing else (§44.3 prices the pattern). So the
/// interim deliberately provisions above any plausible rendezvous path, and
/// **narrows** when the measurement lands.
///
/// **What the measurement must be.** Onion-to-onion *rendezvous* latency
/// between two Shekyl nodes — the anonymity zone addresses peers by `.onion`
/// (`src/net/tor_address.h`), so no exit relay appears in the topology a stem
/// will ever traverse. A clearnet-vs-exit delta measures a different path and
/// must not be substituted (§89.5). Under Ruling B (§97) it is taken on the
/// Rust path.
pub const ANON_ZONE_TRANSIT_ASSUMPTION_MS: f64 = 1_625.0;

/// [`ANON_ZONE_TRANSIT_ASSUMPTION_MS`] as the value a derivation consumes:
/// an assumption (§89.5; the register, §97). The bare `f64` is the number.
pub const ANON_ZONE_TRANSIT: DerivationMs = DerivationMs::assumption(1_625);

const _: () = assert!(ANON_ZONE_TRANSIT.ms() == 1_625);
const _: () = assert!(ANON_ZONE_TRANSIT_ASSUMPTION_MS == 1_625.0);

/// The adopted `hop` for a transaction shape: measured verification floor
/// plus the labelled transit assumption, rounded to whole milliseconds.
///
/// Composition per §71.3: `hop = transit + verification + scheduling`. The
/// scheduling term is carried as 0. **That 0 is a C++-path claim** (§97):
/// it says a stem forward is dispatched at once on the C++ zone strand
/// (`dandelionpp_notify` plans and sends with no deliberate per-hop delay;
/// the fluff scheduler's draw belongs to `F`, not here). It describes the
/// C++ relay, not the Rust one, and is re-measured on the Rust path after
/// RD. [`DerivationMs`] has no basis for a C++-path reading, so the 0 stays
/// a stated omission: the derivation does not consume it.
///
/// # What this is and is not (§66.3, honestly)
///
/// §66.3's policy wants an *effective scalar reproducing the p90 of
/// `Σ k·hop_k`* under the shipped stem-length distribution — which needs the
/// measured per-hop **distribution**, and the clearnet field measurement is
/// still owed (§65.3). This value is the **measured floor** of that scalar:
/// verification is inside every hop's critical path (§71.5), so no measured
/// distribution can come back below it. It supersedes the inherited `175`'s
/// provenance (a 2019 laptop comment) with the spec machine's own cells; it
/// does not close §65.3, and the params-level doc says so.
///
/// # Errors
///
/// Propagates the table's refusal — a shape the table does not price must
/// not silently become a hop value (§83.3).
pub fn adopted_hop_ms(n_in: usize, depth: u32) -> Result<DerivationMs, VerifyCostRefusal> {
    adopted_hop_ms_with_transit(n_in, depth, ADOPTED_TRANSIT)
}

/// [`adopted_hop_ms`] with the transit term supplied by the caller.
///
/// The verification floor is **shared across transports and this is not an
/// approximation**: it is the same proof verified on the same machine, so the
/// only term a transport can move is transit (§71.3's composition). That is
/// why the per-zone `hop` is one substituted constant rather than a second
/// measured surface — and why §63.2's keeper holds in code as well as in
/// prose, `hop` being transport-bound while the cost inside it is not.
///
/// The transit is a [`DerivationMs`]. A C++-path reading has no basis to
/// pass (§97): [`AdmissibleBasis`] does not name one. Callers pass
/// [`ADOPTED_TRANSIT`] for clearnet or [`ANON_ZONE_TRANSIT`] for Tor; prefer
/// [`crate::params::DandelionParams::adopted_for_transit_ms`] over calling
/// this directly, so the connector chooses the constant rather than the
/// call site. The hop returned carries the weakest basis of its inputs: the
/// verification floor is a Rust-path measurement
/// ([`VERIFICATION_FLOOR_BASIS`]), so the transit is the term that decides
/// what the hop rests on, and the shipped hop reads as an assumption.
///
/// # Errors
///
/// Propagates the table's refusal — a shape the table does not price must not
/// silently become a hop value (§83.3).
pub fn adopted_hop_ms_with_transit(
    n_in: usize,
    depth: u32,
    transit: DerivationMs,
) -> Result<DerivationMs, VerifyCostRefusal> {
    let f = SPEC_VERIFY_COST.f_ms(n_in, depth)?;
    // CLIPPY: exact — every populated cell is const-asserted plausible
    // (positive, finite, < 10 s) and the transit is a whole `u32`, so
    // `f + transit` stays well inside u32 with neither truncation nor sign
    // loss. A NaN cannot reach this cast; it cannot build (see the const
    // guard).
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let hop = (f + f64::from(transit.ms())).round() as u32;
    Ok(DerivationMs::derive(
        hop,
        &[transit.basis(), VERIFICATION_FLOOR_BASIS],
    ))
}

/// The basis of every populated verification cell: measured by the Rust
/// verifier on the floor device (`Provenance::MeasuredPi4`, `ICD-R5`). The
/// depth-3 to depth-7 cells are projections against a synthesized tree
/// (`TreeBasis::SynthesizedProjection`), which is a statement about the
/// tree, not about the path the number was taken on.
pub const VERIFICATION_FLOOR_BASIS: AdmissibleBasis = AdmissibleBasis::RustPath;

#[cfg(test)]
mod tests {
    use super::*;

    /// Named for the harm, not the mechanism (§87.1/§87.3): **a clamped row
    /// gives large-input senders an embargo derived for a shallower tree
    /// than the one they are traversing, invisibly** — reintroducing exactly
    /// the sorting the table was built to remove, on the population it was
    /// built to protect, with no feedback channel (§83.2).
    ///
    /// This bites against the refusal being converted into any fallback —
    /// clamping to the last populated row, defaulting to the modal cell, or
    /// interpolating. It does NOT cover the *value* of populated cells;
    /// that is the price-list gate in `tests/spec_decision_matrix.rs`.
    /// Removing this test requires deleting a name that states the
    /// consequence, which is a different act from relaxing a `panic!`.
    #[test]
    fn clamping_would_underprovision_the_tail() {
        // Past the table's depth edge: the §83.3 loud condition.
        assert_eq!(
            SPEC_VERIFY_COST.f_ms(8, MAX_TABLE_DEPTH + 1),
            Err(VerifyCostRefusal::DepthOutsideTable {
                depth: MAX_TABLE_DEPTH + 1
            }),
        );
        // Inside the cap, but no legal shape at this depth: 22 inputs fit the
        // weight limit at depth 2 and not at depth 7. The depth-7 answer must
        // refuse, not borrow its own 20-input cell or the genesis column.
        assert_eq!(
            SPEC_VERIFY_COST.f_ms(MAX_TABLE_INPUTS, MAX_TABLE_DEPTH),
            Err(VerifyCostRefusal::NoLegalShapeAtDepth {
                n_in: MAX_TABLE_INPUTS,
                depth: MAX_TABLE_DEPTH
            }),
        );
        assert_eq!(
            SPEC_VERIFY_COST.f_ms(21, MAX_TABLE_DEPTH),
            Err(VerifyCostRefusal::NoLegalShapeAtDepth {
                n_in: 21,
                depth: MAX_TABLE_DEPTH
            }),
        );
        assert!(SPEC_VERIFY_COST.f_ms(20, MAX_TABLE_DEPTH).is_ok());
        // Outside the consensus input domain: a table cannot be evaluated
        // one past the cap (§80.5).
        assert_eq!(
            SPEC_VERIFY_COST.f_ms(MAX_TABLE_INPUTS + 1, GENESIS_TREE_DEPTH),
            Err(VerifyCostRefusal::InputCountOutsideDomain {
                n_in: MAX_TABLE_INPUTS + 1
            }),
        );
        assert_eq!(
            SPEC_VERIFY_COST.f_ms(0, GENESIS_TREE_DEPTH),
            Err(VerifyCostRefusal::InputCountOutsideDomain { n_in: 0 }),
        );
        // And the refusal propagates through the hop composition — an
        // unpriced shape must not become a hop value by addition.
        assert!(adopted_hop_ms(MAX_TABLE_INPUTS, MAX_TABLE_DEPTH).is_err());
    }

    /// §87.2: every cell on the spec path is measured on the spec machine.
    /// Filling a tier by scaling from the x86 arm fails here, not in review.
    ///
    /// This bites against a cell landing with [`Provenance::MeasuredX86`] or
    /// [`Provenance::ScaledFromX86`]; it does NOT check the numbers are
    /// *correct* Pi measurements — that is what pinning them against the
    /// floor capture in the price-list gate is for. The enum deliberately admits the
    /// non-Pi variants so that recording a diagnostic cell is possible and
    /// this assertion is a real gate rather than a tautology.
    #[test]
    fn every_spec_path_cell_is_measured_on_the_spec_machine() {
        let mut populated = 0;
        for (n_in, depth, cell) in SPEC_VERIFY_COST.populated() {
            assert_eq!(
                cell.provenance,
                Provenance::MeasuredPi4,
                "spec cell ({n_in}-in, depth {depth}) is not a spec-machine \
                 measurement; a scaled or x86 row is a diagnostic wearing a \
                 spec value's clothes (§84.2, rule 76.4)"
            );
            populated += 1;
        }
        assert_eq!(
            populated, 128,
            "the table is every legal shape at depths 2 to 7: 22 + 22 + 22 + 21 + 21 + 20"
        );
    }

    /// §81.2: a synthesized-tree number must say so at the value, or a
    /// future reader treats it as measured and skips the re-measurement the
    /// schedule exists to trigger — `175`'s failure exactly.
    #[test]
    fn deep_tree_cells_are_labelled_projections_and_genesis_cells_are_not() {
        for (_, depth, cell) in SPEC_VERIFY_COST.populated() {
            let expected = if depth == GENESIS_TREE_DEPTH {
                TreeBasis::Genesis
            } else {
                TreeBasis::SynthesizedProjection
            };
            assert_eq!(cell.basis, expected, "depth {depth} basis label");
        }
    }

    /// The adopted modal hop is the priced value: the modal cell's door
    /// sequence (147.99 ms: 128.06 membership proof and masks, 1.01 one hybrid
    /// signature, 18.92 the lone range proof), plus 0.96 ms of node crypto
    /// over its 13,311 B message, plus the 50 ms transit assumption, is
    /// 198.95 ms, 199. If a table cell or the transit assumption moves, this
    /// pin moves with the §80.2 price list, deliberately.
    ///
    /// The inherited `175` it replaced was ~80 ms of Monero-era verification
    /// plus one ocean crossing (§71.3); the masks-and-proof cell alone plus
    /// the same crossing comes close to it, and the door's two further terms
    /// (§72.2) are the 20 ms between them.
    #[test]
    fn the_adopted_modal_hop_is_the_priced_199() {
        assert_eq!(
            adopted_hop_ms(1, GENESIS_TREE_DEPTH).map(DerivationMs::ms),
            Ok(199)
        );
        // And the consensus tail at genesis, 22 inputs: 1 332.34 ms door
        // sequence (1 291.1 + 22 × 1.0145 + 18.919) + 10.26 ms node crypto
        // over that shape's 142,642 B message + 50 ms transit = 1 392.60.
        assert_eq!(
            adopted_hop_ms(MAX_TABLE_INPUTS, GENESIS_TREE_DEPTH).map(DerivationMs::ms),
            Ok(1393)
        );
    }

    /// The node-crypto term is INSIDE [`SpecVerifyCost::f_ms`], and this pins
    /// that it is — replacing the negligibility check that used to stand here.
    ///
    /// # The test this replaces was mispaired, and the mispairing was invisible
    ///
    /// `node_crypto_hop_fraction_is_negligible` compared the **largest**
    /// message against `f_ms(1, GENESIS_TREE_DEPTH)` — the **cheapest**
    /// verification — and called that conservative, because a smaller
    /// denominator makes the fraction larger. But a max-size message comes from
    /// an 8-input transaction, whose verification is `f_ms(8, ·)`. **The two
    /// describe a transaction that cannot exist**, and a test whose inputs
    /// describe an impossible transaction cannot tell you anything about a real
    /// one.
    ///
    /// **It survived review because it was pessimistic.** It reported 5.66 %
    /// where like-for-like pairing gives 1.07 % — a worse number than reality,
    /// which is the direction nobody double-checks. A conservative-looking
    /// wrong oracle is harder to catch than an optimistic one, and that is the
    /// generalisable half of this defect.
    ///
    /// # Why there is no bar here now
    ///
    /// Node-crypto cost scales with message size; message size is a function of
    /// `(n_in, depth)`; `f_ms` is already a function of exactly those. Folding
    /// the term in **removes the question** rather than answering it — there is
    /// no separate fraction left to compare against a threshold. What this test
    /// asserts instead is that the fold actually happened.
    ///
    /// What edit reds this: making `f_ms` return `cell.millis` alone.
    #[test]
    fn f_ms_carries_the_node_crypto_term_not_just_the_measurement() {
        for (n_in, depth, cell) in SPEC_VERIFY_COST.populated() {
            let total = SPEC_VERIFY_COST.f_ms(n_in, depth).expect("populated");
            let measured = cell.millis;
            assert!(
                total > measured,
                "f_ms({n_in}, {depth}) returned {total} ms and the cell's millis is \
                 {measured} ms — the node-crypto term is not in the sum"
            );
            let delta = total - measured;
            let expected = node_crypto_ms(cell.msg_bytes);
            // Relative, not absolute: `f_ms` sums in a different association
            // order than this test does, so the two differ in the last ulp.
            assert!(
                (delta - expected).abs() <= expected * 1e-12,
                "f_ms({n_in}, {depth}) adds {delta} ms of crypto but the cell's {} B \
                 message implies {expected} ms",
                cell.msg_bytes
            );
        }
    }

    /// The crypto term stays a small fraction of the shape it belongs to — a
    /// REPORT, not a gate.
    ///
    /// Deliberately not an assertion with a threshold. §94.9's bar was
    /// self-invented, and the fold above removes the question it answered; a
    /// replacement threshold would re-introduce a knob with no derivation
    /// behind it. What this pins is the ARITHMETIC — that the term is computed
    /// per-shape from that shape's own message — so the numbers below cannot
    /// drift silently even though no bar guards them.
    ///
    /// For the record, like-for-like: 0.65 % (1-in, genesis), 0.53 % (1-in,
    /// depth 7), **0.96 %** (4-in at genesis depth, the worst), 0.96 % (8-in,
    /// genesis), 0.77 % (22-in, genesis), 0.42 % (20-in, depth 7). The worst
    /// cell is at genesis depth because verification grows faster with depth
    /// than message size does. Along the input axis the proof's cost moves in
    /// padding steps while the message grows by every input, so the worst
    /// fraction sits on a shape just below a step (4 inputs) — and it is a
    /// shape that exists today.
    ///
    /// What edit reds this: changing `NODE_CRYPTO_PASSES`,
    /// `PI4_AES_BYTES_PER_SEC`, or any cell's `msg_bytes` without updating the
    /// bounds below.
    #[test]
    fn the_node_crypto_fraction_is_reported_per_shape() {
        let mut worst: (usize, u32, f64) = (0, 0, 0.0);
        for (n_in, depth, cell) in SPEC_VERIFY_COST.populated() {
            let fraction = node_crypto_ms(cell.msg_bytes) / cell.millis;
            if fraction > worst.2 {
                worst = (n_in, depth, fraction);
            }
        }
        assert_eq!(
            (worst.0, worst.1),
            (4, GENESIS_TREE_DEPTH),
            "the worst crypto fraction should be 4 inputs at genesis depth"
        );
        assert!(
            (0.0095..0.0098).contains(&worst.2),
            "worst-cell crypto fraction is {:.4} — outside the recorded \
             0.96 % band, so the arithmetic moved",
            worst.2
        );
    }

    #[test]
    fn measured_connector_rows_name_their_transit_assumptions() {
        let clearnet = transit_ms_for_connector(MeasuredConnector::Clearnet);
        let tor = transit_ms_for_connector(MeasuredConnector::Tor);
        assert_eq!(clearnet, ADOPTED_TRANSIT);
        assert_eq!(tor, ANON_ZONE_TRANSIT);
        assert!(tor.ms() > clearnet.ms());
        // Neither row is a measurement (§97). The type says so at every use.
        assert_eq!(clearnet.basis(), crate::basis::AdmissibleBasis::Assumption);
        assert_eq!(tor.basis(), crate::basis::AdmissibleBasis::Assumption);
    }

    /// The hop carries the basis of the transit it consumed. The same number
    /// built as a model result and as an assumption yields the same hop, and
    /// a C++-path reading has no basis to pass (the `compile_fail` doctest
    /// on [`crate::basis::AdmissibleBasis`]).
    #[test]
    fn the_hop_derivation_consumes_only_an_admissible_transit() {
        let as_assumption = ADOPTED_TRANSIT;
        let as_model = DerivationMs::model(ADOPTED_TRANSIT.ms());
        let from_assumption = adopted_hop_ms_with_transit(1, GENESIS_TREE_DEPTH, as_assumption)
            .expect("the modal cell is pinned");
        let from_model = adopted_hop_ms_with_transit(1, GENESIS_TREE_DEPTH, as_model)
            .expect("the modal cell is pinned");
        assert_eq!(from_assumption.ms(), from_model.ms());
        assert_eq!(
            from_assumption.basis(),
            crate::basis::AdmissibleBasis::Assumption
        );
        assert_eq!(from_model.basis(), crate::basis::AdmissibleBasis::Model);
        assert_eq!(adopted_hop_ms(1, GENESIS_TREE_DEPTH), Ok(from_assumption));
    }
}
