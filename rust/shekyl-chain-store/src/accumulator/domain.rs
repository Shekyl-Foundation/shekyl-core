// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Non-empty cSHAKE customization for one accumulator.

use core::fmt;

/// cSHAKE customization string for one table's accumulator.
///
/// Non-empty by construction: empty customization degrades cSHAKE256 to
/// SHAKE256 and silently drops the domain separation the accumulators
/// exist to provide.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccumulatorDomain(&'static [u8]);

impl AccumulatorDomain {
    /// Wrap a production or test domain string.
    ///
    /// # Panics
    ///
    /// Panics if `bytes` is empty.
    #[must_use]
    pub const fn new(bytes: &'static [u8]) -> Self {
        assert!(
            !bytes.is_empty(),
            "accumulator domain must be non-empty \
             (empty cSHAKE customization degrades to SHAKE256)"
        );
        Self(bytes)
    }

    /// The customization bytes passed to cSHAKE.
    #[must_use]
    pub const fn as_bytes(self) -> &'static [u8] {
        self.0
    }
}

impl fmt::Display for AccumulatorDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match core::str::from_utf8(self.0) {
            Ok(s) => f.write_str(s),
            Err(_) => write!(f, "{:?}", self.0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "non-empty")]
    fn empty_domain_is_rejected() {
        let _domain = AccumulatorDomain::new(b"");
    }

    #[test]
    fn display_is_the_utf8_string() {
        let d = AccumulatorDomain::new(b"shekyl/test/chain");
        assert_eq!(d.to_string(), "shekyl/test/chain");
    }
}
