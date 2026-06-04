// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Membership-path assembly (CT-4).
//!
//! Given a drained leaf and the reconstructed tree layers, produce the
//! `AssembledPath` that an FCMP++ membership proof consumes (the sibling
//! chunks from leaf to root at the reference height). Deferred until the
//! reconstruct-root baseline ([`crate::recon`]) lands and is KAT-verified;
//! a path assembled against a wrong tree is a wrong proof.
//!
//! See `docs/design/CURVE_TREE_CLIENT.md` §5.
