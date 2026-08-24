// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The adopted per-shape verification-cost surface — option D of
//! `DAEMON_RELAY_PRIVACY.md` §80, with §87's structural guards.
//!
//! `hop`'s dominant measurable term is the FCMP++ verification a relay
//! performs before forwarding (§71), and that cost is **sorted by transaction
//! shape**: at the spec machine it spans 124.5 ms (1 input, genesis tree) to
//! 791.9 ms (8 inputs, depth-7 tree) — §85.3. A scalar provisioned anywhere
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
//! # What is populated today, and what is owed
//!
//! The full 48-cell surface (`n_in ∈ 1..=8` × depth `2..=7`) is **measured on
//! both arms** (§82, §85), but only the four corner cells are pinned in-tree
//! (§85.3); the full grids live in the sweep's criterion artifacts on the
//! bench hosts. Populating the remaining 44 cells is a data-recovery task,
//! not a re-measurement (`docs/FOLLOWUPS.md`, "Relay: populate the 48-cell
//! Pi verification surface"). Until a cell is populated it refuses — which
//! is the same §83.3 posture the table will keep at its depth edge forever.

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
    /// Measured **on the spec machine** — Raspberry Pi 4 Model B,
    /// `performance` governor on all four cores, thermal margin recorded
    /// (§73.1, §85.1).
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
    /// Verification cost in milliseconds: the FCMP++ membership-proof verify
    /// plus the per-output prime-order check, at `n_out = 2` (§72.3 measured
    /// the output axis at ~0.07 ms per output — it cannot move the constant,
    /// which is why it is excluded rather than an axis).
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

/// The input-count domain the table covers: `1..=FCMP_MAX_INPUTS_PER_TX`.
///
/// `8` is consensus-enforced at three layers (`cryptonote_config.h`'s
/// `FCMP_MAX_INPUTS_PER_TX`, the verify FFI, and `proof::verify` itself —
/// §80.1), so the surface over `1..=8` **is** the specification, not a
/// sample of it. The cross-crate pin lives in `tests/spec_decision_matrix.rs`
/// (this crate does not depend on `shekyl-fcmp`; the dev-dependency does):
/// `the_measured_surface_covers_the_whole_consensus_domain` asserts **this
/// constant** against `shekyl_fcmp::MAX_INPUTS`, not just the diagnostic x86
/// array beside it — a cap rise that moved only the array would leave
/// `f_ms` refusing consensus-legal shapes as `InputCountOutsideDomain`, a
/// refusal this module documents as *correct* and which would therefore read
/// as design rather than a stale cap. If the cap moves: new cells are
/// **measured** on the spec machine, never extrapolated (§84.2) — and until
/// they are, the table refuses them, which is the correct interim.
pub const MAX_TABLE_INPUTS: usize = 8;

const DEPTH_TIERS: usize = (MAX_TABLE_DEPTH - GENESIS_TREE_DEPTH + 1) as usize;

/// Why the table did not answer. Every variant is a **refusal, not a
/// fallback** — the calling layer must surface it loudly, never substitute a
/// neighbouring cell (§83.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyCostRefusal {
    /// `n_in` is outside `1..=MAX_TABLE_INPUTS`. Zero-input transactions do
    /// not exist; above the cap is consensus-unreachable today, and if the
    /// cap ever rises the new cells are measured, not extrapolated — a table
    /// cannot be evaluated at 9 (§80.5).
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
    /// The cell is inside the domain but not yet populated with a
    /// spec-machine measurement (see the module docs: 44 of 48 cells await
    /// recovery of the §85 sweep artifacts). Refusing is the same posture as
    /// [`Self::DepthOutsideTable`], one measurement earlier.
    UnpopulatedCell {
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
    cells: [[Option<VerifyCell>; DEPTH_TIERS]; MAX_TABLE_INPUTS],
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

/// MEASURED floor AES-128-CTR on `skl-pi` (the reference Pi 4 Model B),
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
/// verification measurement (the deepest measured cell is 791.9 ms; ten
/// seconds is two orders of headroom, not a tuning bound).
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
    let mut n = 0;
    while n < MAX_TABLE_INPUTS {
        let mut d = 0;
        while d < DEPTH_TIERS {
            if let Some(cell) = SPEC_VERIFY_COST.cells[n][d] {
                assert!(
                    cell_is_plausible(cell.millis),
                    "a populated verification-cost cell is not a plausible \
                     measurement (NaN, non-positive, infinite, or >= 10 s)"
                );
            }
            d += 1;
        }
        n += 1;
    }
};

/// The adopted table (§80), populated with the spec machine's pinned cells.
///
/// Values are §85.3's measurements: Pi 4 Model B, `performance` on all four
/// cores, verify-check exit 0 on every fixture (no cell times a reject
/// path), thermal max 69.6 °C against the 80 °C soft-throttle. Depth-7 cells
/// are synthesized-tree projections per §81.2 and labelled so.
pub const SPEC_VERIFY_COST: SpecVerifyCost = {
    const NONE: Option<VerifyCell> = None;
    const EMPTY_ROW: [Option<VerifyCell>; DEPTH_TIERS] = [NONE; DEPTH_TIERS];
    let mut cells = [EMPTY_ROW; MAX_TABLE_INPUTS];
    // n_in = 1 (the modal shape): genesis and depth-7 endpoints.
    cells[0][0] = Some(pi4(124.5, TreeBasis::Genesis, 13_122));
    cells[0][DEPTH_TIERS - 1] = Some(pi4(143.3, TreeBasis::SynthesizedProjection, 15_554));
    // n_in = 8 (the consensus maximum): the tail §75's sorting is about.
    cells[7][0] = Some(pi4(399.2, TreeBasis::Genesis, 59_348));
    cells[7][DEPTH_TIERS - 1] = Some(pi4(791.9, TreeBasis::SynthesizedProjection, 63_765));
    SpecVerifyCost { cells }
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
        match self.cells[n_in - 1][(depth - GENESIS_TREE_DEPTH) as usize] {
            Some(cell) => Ok(cell),
            None => Err(VerifyCostRefusal::UnpopulatedCell { n_in, depth }),
        }
    }

    /// The populated cells, for the §87.2 provenance assertion and for
    /// instruments that report the surface. Order: `n_in` major, depth minor.
    pub fn populated(&self) -> impl Iterator<Item = (usize, u32, VerifyCell)> + '_ {
        self.cells.iter().enumerate().flat_map(|(i, row)| {
            // Rows are DEPTH_TIERS long and DEPTH_TIERS is derived from this
            // exact range, so the zip is total by construction — no index
            // arithmetic, no cast.
            (GENESIS_TREE_DEPTH..=MAX_TABLE_DEPTH)
                .zip(row.iter())
                .filter_map(move |(depth, cell)| cell.map(|c| (i + 1, depth, c)))
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
/// acquittal). It is also dominated at the tail: 792 ms of verification
/// against ~50 of transit at the 8-input depth-7 cell.
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
pub const ADOPTED_TRANSIT_ASSUMPTION_MS: f64 = 50.0;

/// The transit assumption for the **anonymity zones** (i2p/tor), in
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
/// > **Q12-U2 closed that path.** Arrivals now enter as `stem`, coherence
/// > keeps them on the arrival zone (`KeepArrival`), and `set_relayed` draws
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
/// worst case. Pairing this constant with the shared verification floor
/// reproduces that hop exactly (124.5 + 1625 = 1749.5 → 1750).
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
/// must not be substituted (§89.5).
pub const ANON_ZONE_TRANSIT_ASSUMPTION_MS: f64 = 1_625.0;

/// The adopted `hop` for a transaction shape: measured verification floor
/// plus the labelled transit assumption, rounded to whole milliseconds.
///
/// Composition per §71.3: `hop = transit + verification + scheduling`, and
/// the scheduling term is structurally ~0 on this path — a stem forward is
/// dispatched immediately on the zone strand (`dandelionpp_notify` plans and
/// sends with no deliberate per-hop delay; the fluff scheduler's draw
/// belongs to `F`, not here).
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
/// Propagates the table's refusal — an unpopulated or out-of-domain cell
/// must not silently become a hop value (§83.3).
pub fn adopted_hop_ms(n_in: usize, depth: u32) -> Result<u32, VerifyCostRefusal> {
    adopted_hop_ms_with_transit(n_in, depth, ADOPTED_TRANSIT_ASSUMPTION_MS)
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
/// Callers pass [`ADOPTED_TRANSIT_ASSUMPTION_MS`] for clearnet or
/// [`ANON_ZONE_TRANSIT_ASSUMPTION_MS`] for i2p/tor; prefer
/// [`crate::params::DandelionParams::adopted_for`] over calling this directly,
/// so the zone chooses the constant rather than the call site.
///
/// # Errors
///
/// Propagates the table's refusal — an unpopulated or out-of-domain cell must
/// not silently become a hop value (§83.3).
pub fn adopted_hop_ms_with_transit(
    n_in: usize,
    depth: u32,
    transit_ms: f64,
) -> Result<u32, VerifyCostRefusal> {
    let f = SPEC_VERIFY_COST.f_ms(n_in, depth)?;
    // CLIPPY: exact — every populated cell is const-asserted plausible
    // (positive, finite, < 10 s) and both shipped transit constants are
    // finite and positive, so `f + transit` stays well inside u32 with
    // neither truncation nor sign loss. A NaN cannot reach this cast; it
    // cannot build (see the const guard).
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Ok((f + transit_ms).round() as u32)
}

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
        // Inside the domain, cell not yet populated: same posture, one
        // measurement earlier. 4-in at depth 4 is measured (§82) but its
        // artifact is not yet recovered in-tree — it must refuse, not
        // borrow the 8-in row above it or the genesis column beside it.
        assert_eq!(
            SPEC_VERIFY_COST.f_ms(4, 4),
            Err(VerifyCostRefusal::UnpopulatedCell { n_in: 4, depth: 4 }),
        );
        // Outside the consensus input domain: a table cannot be evaluated
        // at 9 (§80.5).
        assert_eq!(
            SPEC_VERIFY_COST.f_ms(9, GENESIS_TREE_DEPTH),
            Err(VerifyCostRefusal::InputCountOutsideDomain { n_in: 9 }),
        );
        assert_eq!(
            SPEC_VERIFY_COST.f_ms(0, GENESIS_TREE_DEPTH),
            Err(VerifyCostRefusal::InputCountOutsideDomain { n_in: 0 }),
        );
        // And the refusal propagates through the hop composition — an
        // unpopulated cell must not become a hop value by addition.
        assert!(adopted_hop_ms(4, 4).is_err());
    }

    /// §87.2: every cell on the spec path is measured on the spec machine.
    /// Filling a tier by scaling from the x86 arm fails here, not in review.
    ///
    /// This bites against a cell landing with [`Provenance::MeasuredX86`] or
    /// [`Provenance::ScaledFromX86`]; it does NOT check the numbers are
    /// *correct* Pi measurements — that is what pinning them against §85.3
    /// in the price-list gate is for. The enum deliberately admits the
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
        assert_eq!(populated, 4, "the in-tree surface is the four §85.3 pins");
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

    /// The adopted modal hop reproduces the priced value: the Pi modal cell
    /// plus the 50 ms transit assumption is 175 ms — numerically equal to
    /// the inherited constant, by the arithmetic §71.3 noted (the inherited
    /// number was never pure transit: ~80 ms Monero-era verification + one
    /// ocean crossing; ours is 124.5 ms FCMP++ verification + the same
    /// crossing). Same value, different provenance — which is the entire
    /// point of the landing. If a table cell or the transit assumption
    /// moves, this pin moves with the §80.2 price list, deliberately.
    ///
    /// **2026-08-23: the tail endpoint moved 449 -> 453**, and the modal one
    /// did not move at all. Folding the node-crypto term into `f_ms` adds
    /// 0.94 ms at the modal shape (175.44, still 175) and 4.26 ms at the
    /// 8-input shape (453.46, was 449.2). The modal pin surviving is not luck
    /// — it is the same fact the fold rests on: the crypto term scales with
    /// message size, so it is small exactly where the message is.
    #[test]
    fn the_adopted_modal_hop_is_the_priced_175() {
        assert_eq!(adopted_hop_ms(1, GENESIS_TREE_DEPTH), Ok(175));
        // And the tail endpoint at genesis: 399.2 + 50 + 4.26 ms node crypto
        // over that shape's 59,348 B message.
        assert_eq!(adopted_hop_ms(8, GENESIS_TREE_DEPTH), Ok(453));
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
    /// For the record, like-for-like at the four populated cells: 0.75 %,
    /// 0.78 %, **1.07 %** (8-in at genesis depth, the worst), 0.58 %. The worst
    /// cell is max-inputs-at-min-depth because verification grows faster with
    /// depth than message size does, so the cheapest verification pairs with an
    /// already-large message — and it is a shape that exists today.
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
            (8, GENESIS_TREE_DEPTH),
            "the worst crypto fraction should be max-inputs at min-depth"
        );
        assert!(
            (0.0105..0.0110).contains(&worst.2),
            "worst-cell crypto fraction is {:.4} — outside the recorded \
             1.07 % band, so the arithmetic moved",
            worst.2
        );
    }
}
