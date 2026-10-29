//! Cross-language consensus parameters from `config/consensus_constants.json`.
//!
//! The C++ mirror is `shekyl/consensus_constants_generated.h` (CMake configure).
//! FCMP reference-block ages and CT wire type are also consumed by
//! [`crate::multisig::v31::intent`] via a separate `include!` of the same
//! generated file.

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
}
