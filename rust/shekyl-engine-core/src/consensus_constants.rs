//! Cross-language consensus parameters from `config/consensus_constants.json`.
//!
//! The C++ mirror is `shekyl/consensus_constants_generated.h` (CMake configure).
//! FCMP reference-block ages and RCT wire type are also consumed by
//! [`crate::multisig::v31::intent`] via a separate `include!` of the same
//! generated file.

include!(concat!(
    env!("OUT_DIR"),
    "/consensus_constants_generated.rs"
));

// Sentinel against silent loss-of-meaning if the JSON authority is bumped
// without revisiting the gate-4 calibration workbook
// (`docs/design/FOUNDATION_GENESIS_IDENTITY_SET.md` §9.3).
const _: () = assert!(
    ARCHIVAL_BOND_FLOOR_ATOMIC == 750_000_000,
    "ARCHIVAL_BOND_FLOOR_ATOMIC diverged from gate-4 pin (750_000_000 = 0.75 SKL); \
     update §9.3 calibration and genesis sentinels before changing the JSON authority"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archival_bond_floor_matches_gate4_calibration() {
        assert_eq!(ARCHIVAL_BOND_FLOOR_ATOMIC, 750_000_000);
    }
}
