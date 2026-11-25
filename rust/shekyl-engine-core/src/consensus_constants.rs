//! Cross-language consensus parameters from `config/consensus_constants.json`.
//!
//! This crate's `build.rs` generates the values from that file.
//! The CT wire type is also consumed by `shekyl_multisig::intent` via its own
//! `include!` of a file generated from the same JSON.

include!(concat!(
    env!("OUT_DIR"),
    "/consensus_constants_generated.rs"
));

/// The bond floor. Generated once, in `shekyl-archival-retention`. This
/// crate used to emit a second copy of the same JSON key.
pub use shekyl_archival_retention::ARCHIVAL_BOND_FLOOR_ATOMIC;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archival_bond_floor_matches_gate4_calibration() {
        assert_eq!(ARCHIVAL_BOND_FLOOR_ATOMIC, 750_000_000);
    }

    /// The exit-fee reserve stays strictly below one cover rung, the tiling
    /// draw's exclusive upper bound (`ARCHIVAL_BOND_CONSTRUCTION.md` §7.2's
    /// dominance relation): a fresh cover draw clears the reserve with high
    /// probability, and the fully-inverted sizing — every fresh pool below
    /// the reserve, every fresh live drain blocked — fails here. The rung is
    /// the archival bond floor, which `shekyl-standoff` does not read, so
    /// this crate, which sees both, holds the relation.
    #[test]
    fn the_exit_fee_reserve_is_below_one_cover_rung() {
        let rung = shekyl_archival_retention::archival_params().bond_floor_atomic;
        assert!(shekyl_standoff::EXIT_FEE_RESERVE_ATOMIC < rung);
    }
}
