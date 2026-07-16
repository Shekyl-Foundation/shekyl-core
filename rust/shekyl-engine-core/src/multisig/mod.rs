// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved. BSD-3-Clause

//! Shekyl V3.1 multisig — Option E′ (`v31`).
//!
//! The Option A FROST wrapper (`MultisigGroup` / `MultisigDkgSession` /
//! `MultisigSigningSession`) was deleted under R1-F-3: it fused FROST-SAL
//! threshold keys with a fixed-per-group `pqc_public_key` — Option A,
//! rejected 2026-04-04 because a fixed group PQC key in plaintext
//! `pqc_auth` is a ~1996-byte on-chain fingerprint that collapses FCMP++
//! anonymity. The FROST-SAL / DKG primitives it wrapped live on in
//! `shekyl-fcmp` (`frost_sal`, `frost_dkg`); the shipping design is `v31`.

pub mod v31;
