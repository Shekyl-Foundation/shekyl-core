// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The type's own unconstructibility, independent of `OutputData` field
//! visibility. If this compiles, nine chosen bytes are an
//! `EncryptedOutputField` and the guarantee is gone even when the
//! `OutputData` fields stay `pub(crate)`.

use shekyl_crypto_pq::output::EncryptedOutputField;

fn main() {
    let _ = EncryptedOutputField([0u8; 9]);
}
