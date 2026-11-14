// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The exact-length rule the archival vin codecs share: a length-delimited
//! payload carries no byte past its canonical field span. The bond-post and
//! emission readers ([`crate::bond_wire`], [`crate::emission_wire`]) call
//! [`ensure_payload_fully_consumed`] after their last field.

use std::io::{self, Read};

/// The only two failure modes of [`ensure_payload_fully_consumed`].
///
/// A dedicated 2-variant type so every caller maps it **exhaustively** into
/// its own error, never through a lossy catch-all.
#[derive(Debug)]
pub enum ExactParseError {
    /// A byte exists past the canonical field span.
    TrailingBytes,
    /// A non-EOF read error while probing.
    Io(io::Error),
}

/// Reject length-delimited vin payloads that carry bytes outside the canonical field span.
pub fn ensure_payload_fully_consumed<R: Read>(r: &mut R) -> Result<(), ExactParseError> {
    let mut extra = [0u8; 1];
    match r.read_exact(&mut extra) {
        Ok(()) => Err(ExactParseError::TrailingBytes),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(()),
        Err(e) => Err(ExactParseError::Io(e)),
    }
}
