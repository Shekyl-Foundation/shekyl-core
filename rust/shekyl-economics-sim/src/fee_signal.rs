// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! FL-C9: how far one public fee rung shrinks an anchored observer's
//! candidate set (`docs/design/FEE_LADDER_DERIVATION.md` §4.7).
//!
//! Report-layer arithmetic over tier shares, in floating point: nothing
//! here mirrors a chain computation, which is why it is not in a fold file
//! (DQ-2G). `fee_ladder::report` includes its rows.

use serde::Serialize;

/// How far one public fee rung shrinks an anchored observer's candidate set.
///
/// FCMP++ puts no linkage on the wire. The attack acquires an anchor
/// off-chain and filters the height window by every public field. The
/// rung contributes `1/usage_share` on that one transaction, once.
/// Surprisal is `log2` of the same factor. The single state-computed rate
/// contributes ×1.
#[derive(Serialize)]
pub struct AnchoredReduction {
    pub traffic_model: &'static str,
    /// Tier shares ×1000, in economy / standard / priority order.
    pub shares_milli: [u64; 3],
    /// `1/share` ×1000, per rung.
    pub reduction_factor_milli: [u64; 3],
    /// `log2(reduction)` ×1000, per rung.
    pub rung_surprisal_milli: [u64; 3],
    /// `H(rung)` ×1000.
    pub ladder_bits_per_tx_milli: u64,
    /// The single rate's reduction ×1000. `1000` is ×1.
    pub single_rate_reduction_milli: u64,
}

#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
pub fn anchored_reduction(
    traffic_model: &'static str,
    shares_milli: [u64; 3],
) -> AnchoredReduction {
    let mut h = 0.0f64;
    let mut surprisal = [0u64; 3];
    let mut reduction = [0u64; 3];
    for (i, &m) in shares_milli.iter().enumerate() {
        let p = m as f64 / 1000.0;
        if p > 0.0 {
            let s_bits = -p.log2();
            h += p * s_bits;
            surprisal[i] = (s_bits * 1000.0).round() as u64;
            reduction[i] = (1000.0 / p).round() as u64;
        }
    }
    AnchoredReduction {
        traffic_model,
        shares_milli,
        reduction_factor_milli: reduction,
        rung_surprisal_milli: surprisal,
        ladder_bits_per_tx_milli: (h * 1000.0).round() as u64,
        single_rate_reduction_milli: 1000,
    }
}

/// The registered traffic models (§1.8) and the sensitivity arms.
///
/// Shares are economy / standard / priority. The defaulted model puts the
/// 80 % majority on standard. Equal thirds do not divide 1000, so 33/33/33
/// is 334 + 333 + 333.
pub fn registered_models() -> Vec<AnchoredReduction> {
    vec![
        anchored_reduction("registered 50/40/10", [500, 400, 100]),
        anchored_reduction("sensitivity 70/25/5", [700, 250, 50]),
        anchored_reduction("sensitivity 33/33/33", [334, 333, 333]),
        anchored_reduction("defaulted 15/80/5", [150, 800, 50]),
    ]
}
