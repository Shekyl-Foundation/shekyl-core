// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The second round for every signer but the proposer
//! (`PQC_MULTISIG.md` §11.1, steps 8 and 9).

use rand::{CryptoRng, RngCore};

use super::super::context::SigningContext;
use super::super::files::{Authenticated, FinalTx, HybridSig};
use super::super::{CeremonyError, Role};
use super::{check_final_tx, expect_role, seal_as};

/// The responder or a holder, in the second round: stateless, so a member
/// that kept nothing since the first round signs from its rebuilt context
/// (`PQC_MULTISIG.md` §11.1, §13.1).
pub struct Cosigner;

impl Cosigner {
    /// Step 8 received, step 9 sent: check every signer's keys, verify the
    /// FCMP++ proof and the range proof against this member's own context,
    /// assemble the transaction from this member's own values, sign every
    /// input, and write the `HybridSig`.
    ///
    /// # Errors
    ///
    /// [`CeremonyError`]: this member is the proposer, the file is not from
    /// the proposer or is for another intent, its `Proposal` does not open,
    /// a key does not match, a proof does not verify, the transaction is
    /// not well formed, or a signer or seal refusal.
    pub fn sign_final_tx(
        ctx: &SigningContext<'_>,
        file: &Authenticated<FinalTx>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Vec<u8>, CeremonyError> {
        expect_role(ctx, Role::COSIGNERS)?;
        let (_, signable) = check_final_tx(ctx, file)?;
        let signatures = signable.sign_as_member(ctx)?;
        seal_as(ctx, &HybridSig { signatures }, rng)
    }
}
