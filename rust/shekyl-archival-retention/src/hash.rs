// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! cSHAKE256 helpers shared across archival domain labels.

use sha3::digest::core_api::CoreWrapper;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{CShake256, CShake256Core};

/// SP 800-185 cSHAKE256 with 32-byte output.
#[must_use]
pub fn cshake256_32(customization: &[u8], input: &[u8]) -> [u8; 32] {
    let core = CShake256Core::new(customization);
    let mut hasher: CShake256 = CoreWrapper::from_core(core);
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    let mut out = [0u8; 32];
    reader.read(&mut out);
    out
}
