//! The conformance-correct entry-seam draw — float-free by construction.
//!
//! `s ~ U[0, window]` via unbiased integer **rejection sampling** (no float, no
//! modulo bias — the bias would be privacy-load-bearing) plus a fair order
//! coin. Generic over [`GapRng`] so the same code serves the simulator's seeded
//! `SplitMix64`, the published golden vector, and a wallet's CSPRNG. Pure
//! integer arithmetic ⇒ deterministic and bit-identical across architectures.

/// Minimal RNG abstraction the draw is generic over. The simulator and KAT
/// supply a seeded `SplitMix64` (deterministic replay); a wallet supplies a
/// CSPRNG. A single method keeps this crate dependency-free and lets one draw
/// implementation serve sim, conformance vector, and production.
pub trait GapRng {
    /// Next uniformly-distributed 64-bit word.
    fn next_u64(&mut self) -> u64;
}

/// Draw a uniformly-distributed integer in the inclusive range `[0, max]` from
/// `rng`, free of modulo bias. The naive `next_u64() % (max + 1)` over-weights
/// the low residues whenever `max + 1` does not divide `2^64`; here the
/// incomplete top bucket is rejected so every value in `[0, max]` is
/// equiprobable. Pure integer arithmetic, so the result is deterministic and
/// identical on every architecture.
///
/// Public because it is the standoff family's single unbiased sampler: the
/// entry-gap draw and the cover-amount draw use it internally, and the WI-3
/// dispatch driver's send-time dispersal draw
/// (`ARCHIVAL_BOND_WI3_DISPATCH.md` §3.2 part 3) draws through the same
/// audited rejection sampling rather than re-implementing it — the bias
/// would be privacy-load-bearing there exactly as here.
pub fn bounded_uniform<R: GapRng + ?Sized>(rng: &mut R, max: u64) -> u64 {
    if max == u64::MAX {
        // Full range: every draw is already uniform over [0, u64::MAX].
        return rng.next_u64();
    }
    let range = max + 1; // number of outcomes in [0, max], >= 1
                         // `2^64 mod range`, computed without overflowing u64. `(u64::MAX % range)`
                         // is `(2^64 - 1) mod range`; adding 1 gives `2^64 mod range`, except when
                         // that lands on `range` itself (range divides 2^64 evenly), which folds to 0.
    let rem = {
        let r = (u64::MAX % range) + 1;
        if r == range {
            0
        } else {
            r
        }
    };
    // Accept the largest range-aligned prefix `[0, 2^64 - rem)`; reject the top
    // `rem` values so the accepted region is an exact multiple of `range`.
    loop {
        let x = rng.next_u64();
        if rem == 0 || x <= u64::MAX - rem {
            return x % range;
        }
    }
}

/// Canonical entry-gap **window** (in blocks) for the funding standoff draw.
///
/// This is the single source of truth for the `window` argument to
/// [`draw_entry_gap`]: the published golden vector (`tests/golden_vector.rs`)
/// freezes its `(spread, bond_first)` reference at this window, and the wallet
/// draws at this window (`shekyl-engine-core`'s `stake_timing::DEFAULT_ENTRY_GAP`
/// wraps this value in the typed `NetworkGap`). Single-sourcing the *value* — not
/// just the
/// [`draw_entry_gap`] *function* — closes the otherwise-unguarded drift between
/// "the window the RNG is certified at" and "the window the wallet draws at":
/// change this const and the golden vector re-draws and fails until re-frozen,
/// so the certified window can never silently diverge from the operational one.
///
/// `600` blocks is the multi-event entry/announce/bond-post horizon
/// (`ARCHIVAL_FIREWALL_GATE6.md` §10.12 / `ARCHIVAL_TIMING_CONSTANTS.md` §7).
pub const DEFAULT_ENTRY_GAP_WINDOW: u64 = 600;

/// Conformance-correct entry-seam draw. At the private intent, draw the gap
/// directly `s ~ U[0, window]` (unbiased integer) and flip a fair order-coin;
/// returns `(spread_blocks, bond_first)`. Uniform separation, fair inversion,
/// maximum latency `window`, per-`P` independence (the caller supplies an
/// independent RNG). Float-free, so the value a wallet computes is identical on
/// every architecture and reproduces the published golden vector exactly.
pub fn draw_entry_gap<R: GapRng + ?Sized>(window: u64, rng: &mut R) -> (u64, bool) {
    let spread = bounded_uniform(rng, window);
    let bond_first = (rng.next_u64() & 1) == 1;
    (spread, bond_first)
}
