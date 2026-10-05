// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("segment path depth must be at least 2")]
    PathTooShallow,
    #[error("challenged leaf x-coordinate not present in first Helios branch")]
    LeafNotInOpening,
    #[error("recomputed sub-root does not match R_k")]
    SubrootMismatch,
    /// `SHT-11`: a branch layer is empty or ends in a zero scalar. A layer hashes as a
    /// positional vector commitment, on which an appended zero scalar contributes
    /// nothing, so a padded layer would be a second valid encoding of the same opening.
    #[error("{family} branch layer {index} is not canonical (empty, or a trailing zero scalar)")]
    NonCanonicalBranchLayer {
        /// `"c1"` (Selene) or `"c2"` (Helios) — which of the path's two layer lists.
        family: &'static str,
        /// The layer's position within that list.
        index: usize,
    },
    // `LeafIndexMismatch` DELETED by RF-D6: the index is verifier-derived, never
    // transported, so there is no wire value left to mismatch.
}
