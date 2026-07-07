// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `P_canonical_id` derivation (emission §6.1; `ARCHIVAL_CONSENSUS_STATE.md`).

use shekyl_types::PCanonicalId;

use crate::hash::cshake256_32;

/// cSHAKE256 customization for archival principal identity.
pub const P_CANONICAL_ID_CUSTOMIZATION: &[u8] = b"shekyl/archival-p-id-v1";

/// `P_canonical_id = cSHAKE256(cust, hybrid_sign_pk.canonical_bytes())`.
///
/// Returns the domain newtype [`PCanonicalId`]; a wire struct that needs the raw
/// bytes converts at its edge with [`PCanonicalId::as_bytes`].
#[must_use]
pub fn p_canonical_id_from_hybrid_pubkey(hybrid_pubkey: &[u8]) -> PCanonicalId {
    PCanonicalId::from_bytes(cshake256_32(P_CANONICAL_ID_CUSTOMIZATION, hybrid_pubkey))
}
