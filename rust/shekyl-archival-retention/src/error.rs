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
    #[error("leaf index {got} does not match epoch challenge index {expected}")]
    LeafIndexMismatch { got: u32, expected: u32 },
}
