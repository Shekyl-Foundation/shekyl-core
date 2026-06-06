//! L14 — proof-of-archival / free-rider economics, in harmony with retrieval.
//!
//! Reward is paid for *provable* archival, but coverage scores reward *declared* holdings.
//! The gap is the free-rider: claim a shard (collect reward) without storing it (save the
//! flow cost), or store-but-refuse-to-serve. The bond is the standing capital cost; what
//! actually deters the free-rider is the **operational audit** — the probability per epoch
//! that a holder is asked to prove possession and slashed if it cannot.
//!
//! The L14×L15 spec's central observation: **a successful, content-bound retrieval *is* a
//! proof of possession.** So every real read audits its shard for free. Explicit
//! proof-of-retrievability *challenges* are therefore only needed for the **cold tail** —
//! shards no one read this epoch — and only at the cadence that tops the real-read audit
//! probability up to the deterrence threshold. This module quantifies the resulting
//! **non-productive (oversight-only) traffic** and shows it collapses onto the cold,
//! most-irreplaceable shards. Gated by `audit_model`; inert (byte-identical) otherwise.

/// Per-epoch probability a shard of normalized `age` ∈ [0,1] receives a real read.
/// Reads follow recency: `read_hot · exp(−read_decay · age)`, floored at `read_cold` (a
/// long-tail floor — even ancient data is occasionally fetched). Hot shards (age→0) are
/// read often and self-prove; the oldest (age→1) approach the cold floor and need
/// explicit challenges.
pub fn read_prob(age: f64, read_hot: f64, read_decay: f64, read_cold: f64) -> f64 {
    (read_hot * (-read_decay * age).exp()).max(read_cold)
}

/// Audit probability needed to deter free-riding: a free-rider gains `benefit` per epoch
/// (the saved flow cost) and loses `penalty` (the slashed bond) if caught, so it abstains
/// iff `a · penalty ≥ benefit`, i.e. `a ≥ benefit / penalty`. Clamped to [0,1]; a threshold
/// `≥ 1` means no finite audit deters at that benefit/penalty ratio (the penalty is too
/// small — raise the bond/slash, not the challenge rate).
pub fn deterrence_threshold(benefit: f64, penalty: f64) -> f64 {
    if penalty <= 0.0 {
        return 1.0;
    }
    (benefit / penalty).clamp(0.0, 1.0)
}

/// Explicit-challenge rate a shard needs *given its real-read audit*. The real read already
/// audits with probability `p_read`; an independent challenge at rate `c` lifts the total
/// caught-probability to `1 − (1−p_read)(1−c)`. Setting that ≥ `a_star` and solving for the
/// minimal `c`: `c = max(0, (a_star − p_read) / (1 − p_read))`. Hot shards with
/// `p_read ≥ a_star` need **zero** challenge — reads alone over-prove them. `p_read ≥ 1`
/// ⇒ 0 (always read).
pub fn challenge_needed(p_read: f64, a_star: f64) -> f64 {
    if p_read >= 1.0 {
        return 0.0;
    }
    ((a_star - p_read) / (1.0 - p_read)).max(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_prob_decays_with_age_and_floors() {
        let p_hot = read_prob(0.0, 0.6, 4.0, 0.01);
        let p_mid = read_prob(0.5, 0.6, 4.0, 0.01);
        let p_old = read_prob(1.0, 0.6, 4.0, 0.01);
        assert!((p_hot - 0.6).abs() < 1e-9);
        assert!(p_mid < p_hot && p_old < p_mid);
        assert!(p_old >= 0.01); // floored
    }

    #[test]
    fn hot_shards_need_no_challenge_cold_shards_do() {
        let a_star = deterrence_threshold(0.1, 1.0); // 0.1
                                                     // Hot: p_read 0.6 ≥ a* ⇒ reads over-prove ⇒ no challenge.
        assert_eq!(challenge_needed(0.6, a_star), 0.0);
        // Cold: p_read 0.01 < a* ⇒ challenge tops up to a*.
        let c = challenge_needed(0.01, a_star);
        assert!(c > 0.0 && c < a_star + 1e-9);
        // The top-up restores the threshold: 1 − (1−0.01)(1−c) ≈ a*.
        let total = 1.0 - (1.0 - 0.01) * (1.0 - c);
        assert!((total - a_star).abs() < 1e-9);
    }

    #[test]
    fn weak_penalty_cannot_deter() {
        // benefit 0.5, penalty 0.2 ⇒ threshold clamps to 1.0 (no finite audit deters).
        assert_eq!(deterrence_threshold(0.5, 0.2), 1.0);
    }
}
