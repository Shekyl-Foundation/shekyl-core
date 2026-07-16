//! The exit-seam draw — one-sided, written against the F-D4 provisional
//! sentinel (`docs/design/ARCHIVAL_EXIT_STANDOFF_FD4_WINDOW.md` §5.4;
//! Gate-6 §12.5 F-D3).
//!
//! At the release anchor `H_0(P)` — the cooldown-pinned earliest-spend height,
//! consensus-computable per persona (`shekyl-archival-retention`'s
//! `release_cooldown` module owns the F-D6 anchor derivation) — the wallet
//! draws a latency `s ~ U[0, window]` and posts the `Unbond` /
//! `HoldingsUpdate`-drop at `H_0 + s`. **No order coin, no inversion**:
//! collateral is not spendable before the cooldown, so one-sidedness is forced
//! (F-D4 §1) — structurally, [`draw_exit_gap`] returns a bare [`ExitGap`], and
//! the entry seam's `bond_first` coin does not exist at this seam. The draw is
//! wallet discipline, consensus-unenforceable (the same posture as the entry
//! draw), applied **per event** to the terminal `Unbond` drain and to each
//! recurring `HoldingsUpdate`-drop.
//!
//! # Sentinel mechanics (F-D4 §5.4, mirroring `k_cover.rs`)
//!
//! [`DEFAULT_EXIT_GAP_WINDOW`] has **no derivable pre-measurement value**: the
//! X-1 bound spans a ~19× planning box driven by `ρ_x`, a pre-testnet unknown
//! (F-W3). The value is sealed by the Phase 7.7 stressnet read through the
//! frozen decision rule
//!
//! ```text
//! W := the smallest multiple of SETTLEMENT_EPOCH_BLOCKS
//!      >= max( (N_t - 1) / rho_x ,  2 x SETTLEMENT_EPOCH_BLOCKS )
//! ```
//!
//! (X-1 rate bound at the 10th percentile of the joint `(N_P, c)` read, F-W4;
//! X-3 anchor-merge floor, F-W6; `N_t` re-derived for the exit adversary
//! before the seal, F-W5). Until the seal:
//!
//! 1. **The provisional value is the sentinel `0`** — invariant *provisional ⇔
//!    0, sealed ⇒ ≥ 1*, asserted at compile time below. A plausible-looking
//!    provisional value is unrepresentable, not merely discouraged.
//! 2. **Building without acknowledgment refuses.** The `compile_error!` below
//!    fires for any build of this crate while
//!    [`DEFAULT_EXIT_GAP_WINDOW_PROVISIONAL`] is set unless the
//!    `provisional-exit-gap-window` feature is enabled. Every consumer carries
//!    a grep-able acknowledgment line in its `Cargo.toml`; the shipping guard
//!    is the compile refusal, never the sentinel's runtime semantics.
//! 3. KAT/conformance parameterization goes through [`ExitGapWindow::for_kat`]
//!    behind the **permanent** dev-only `exit-window-kat` feature (it must
//!    survive the seal, so it does not ride `provisional-exit-gap-window`).
//!
//! **Sealing** (the Phase 7.7 read lands, `RELEASE_CHECKLIST.md` beside
//! `K_COVER`): set [`DEFAULT_EXIT_GAP_WINDOW`] to the rule's value (≥ 1), flip
//! [`DEFAULT_EXIT_GAP_WINDOW_PROVISIONAL`] to `false`, delete the
//! `compile_error!` block, the `provisional-exit-gap-window` feature, and
//! every acknowledgment line, and re-freeze the exit golden vector at the
//! sealed window (`tests/exit_golden_vector.rs` fails loudly at the seal until
//! re-frozen) — the deletion target is the seal itself
//! (`15-deletion-and-debt.mdc`: the version is named by the event). Post-seal
//! the value is **soft-frozen**: technically mutable, practically once-only —
//! changing a shipped window splits the wallet population into two draw
//! distributions (the §16.1 partition trap as a flag day).

use crate::draw::{bounded_uniform, GapRng};

/// Canonical exit-gap **window** (in blocks) for the release standoff draw —
/// **a provisional sentinel, not a value** (F-D4 §5.4). See the module docs
/// for the sentinel mechanics, the frozen decision rule the seal applies, and
/// the seal procedure.
///
/// Single-sourcing mirrors [`DEFAULT_ENTRY_GAP_WINDOW`](crate::draw::DEFAULT_ENTRY_GAP_WINDOW):
/// this const is the only production window (threaded by
/// [`ExitGapWindow::wallet_default`]), and the sealed-window golden-vector
/// tripwire re-draws against it, so the certified window can never silently
/// diverge from the operational one.
pub const DEFAULT_EXIT_GAP_WINDOW: u64 = 0;

/// `true` while [`DEFAULT_EXIT_GAP_WINDOW`] is the unsealed sentinel. Flipped
/// to `false` (in the same edit that sets the sealed value) by the Phase 7.7
/// stressnet seal — never independently.
pub const DEFAULT_EXIT_GAP_WINDOW_PROVISIONAL: bool = true;

// The armed refusal (F-D4 §5.4 rule; `k_cover.rs` shape). Deleted at seal
// together with the `provisional-exit-gap-window` feature and every consumer
// acknowledgment line.
#[cfg(not(feature = "provisional-exit-gap-window"))]
compile_error!(
    "DEFAULT_EXIT_GAP_WINDOW is a provisional sentinel — its value is sealed only by the \
     Phase 7.7 stressnet rate read through the frozen decision rule \
     (ARCHIVAL_EXIT_STANDOFF_FD4_WINDOW.md §5.4). A genesis or release artifact must not \
     build against it. Non-genesis builds acknowledge explicitly by enabling the \
     `provisional-exit-gap-window` feature on shekyl-standoff (grep-able; delete at seal)."
);

// Tripwire (the `WORK_MILLI_SCALE` / `k_cover.rs` idiom): the two expressible
// states are (provisional, 0) and (sealed, >= 1). Re-asserted here so a seal
// edit that sets the value without flipping the flag — or vice versa — fails
// to compile.
const _: () = assert!(
    DEFAULT_EXIT_GAP_WINDOW_PROVISIONAL == (DEFAULT_EXIT_GAP_WINDOW == 0),
    "DEFAULT_EXIT_GAP_WINDOW sentinel invariant violated: provisional iff 0 \
     (ARCHIVAL_EXIT_STANDOFF_FD4_WINDOW.md §5.4 sentinel mechanics)"
);

/// Capability newtype for the exit-gap window (the `KCover` shape, F-D4 §5.4).
///
/// A bare `u64` window lets any future caller pass an arbitrary value — or the
/// pre-seal sentinel `0`, which collapses the draw to the fixed-offset tell
/// the mechanism exists to break — and it compiles. This newtype makes that a
/// **type error**: the only production constructor is
/// [`ExitGapWindow::wallet_default`], which threads
/// [`DEFAULT_EXIT_GAP_WINDOW`] verbatim. KAT/conformance parameterization goes
/// through [`ExitGapWindow::for_kat`], gated behind the **permanent** dev-only
/// `exit-window-kat` feature (enabled only via dev-dependencies; it survives
/// the §5.4 seal, so it does not ride `provisional-exit-gap-window`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitGapWindow(u64);

impl ExitGapWindow {
    /// The shipped wallet default — the only production constructor. Threads
    /// [`DEFAULT_EXIT_GAP_WINDOW`] verbatim; there is no way to construct a
    /// divergent window without the `exit-window-kat` feature.
    #[must_use]
    pub const fn wallet_default() -> Self {
        Self(DEFAULT_EXIT_GAP_WINDOW)
    }

    /// KAT-injection constructor: the exit golden vector and the conformance
    /// arms parameterize the window per case so the fixtures survive the §5.4
    /// seal without rewrite. Test-only by construction — `cfg(test)` for
    /// in-crate unit tests, the `exit-window-kat` dev-only feature for
    /// integration tests. Never call from production code.
    #[cfg(any(test, feature = "exit-window-kat"))]
    #[must_use]
    pub const fn for_kat(value: u64) -> Self {
        Self(value)
    }

    /// The window value, for the draw and for grading a realized sample.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A drawn exit gap: the latency (in blocks) added past the release anchor
/// `H_0(P)` before the exit-class post is broadcast. One-sided by
/// construction — there is no order coin to carry, so the type carries none
/// (contrast the entry draw's `(spread, bond_first)` tuple).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitGap(u64);

impl ExitGap {
    /// The drawn latency in blocks past `H_0`.
    #[must_use]
    pub const fn blocks(self) -> u64 {
        self.0
    }
}

/// Conformance-correct exit-seam draw: `s ~ U[0, window]` via the same audited
/// unbiased rejection sampling as the entry draw ([`bounded_uniform`] — the
/// bias would be privacy-load-bearing here exactly as there). **One-sided**:
/// no order coin (module docs). Float-free pure-integer arithmetic, so the
/// value a wallet computes is deterministic and bit-identical on every
/// architecture and reproduces the published exit golden vector exactly.
///
/// Per-event independence is the caller's obligation: each `Unbond` /
/// `HoldingsUpdate`-drop draws fresh from an independent RNG — a shared or
/// replayed draw across a cohort is the clustering failure the conformance
/// harness's shared-trigger negative control exists to catch
/// (F-D4 §8.3).
pub fn draw_exit_gap<R: GapRng + ?Sized>(window: ExitGapWindow, rng: &mut R) -> ExitGap {
    ExitGap(bounded_uniform(rng, window.get()))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SplitMix64(u64);
    impl GapRng for SplitMix64 {
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
    }

    #[test]
    fn wallet_default_threads_the_const_verbatim() {
        assert_eq!(
            ExitGapWindow::wallet_default().get(),
            DEFAULT_EXIT_GAP_WINDOW
        );
    }

    #[test]
    fn draw_stays_within_kat_window() {
        let window = ExitGapWindow::for_kat(10_007);
        let mut rng = SplitMix64(0x1234_5678_9ABC_DEF0);
        for _ in 0..100_000 {
            let gap = draw_exit_gap(window, &mut rng);
            assert!(gap.blocks() <= window.get());
        }
    }

    #[test]
    fn provisional_sentinel_draws_zero_always() {
        // The sentinel's runtime semantics, pinned executably: pre-seal the
        // wallet-default draw is the degenerate zero gap (behavior identical
        // to no-draw), and the *shipping* guard against ever exercising this
        // is the compile refusal, never this value. This test flips meaning
        // at the seal — see `tests/exit_golden_vector.rs` for the loud
        // seal-time tripwire.
        if DEFAULT_EXIT_GAP_WINDOW_PROVISIONAL {
            let mut rng = SplitMix64(0xDEAD_BEEF_0000_0001);
            for _ in 0..1000 {
                assert_eq!(
                    draw_exit_gap(ExitGapWindow::wallet_default(), &mut rng).blocks(),
                    0
                );
            }
        }
    }
}
