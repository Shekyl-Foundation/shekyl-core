// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The pool door's verification sequence at `TxSlot::Lone`: BA-T1's subject,
//! and the drift gate's (`benches/relay_admission_verify_iai.rs`).
//!
//! `shekyl_chain_rules::judge_slot_stateless` at `TxSlot::Lone` runs, in
//! order: `tx_form` (CEN-H17's mask rule among its rows), the signatures
//! (CEN-I17 derives each input's signing hash, CEN-I18 verifies each
//! input's hybrid signature over it), the proof (CEN-I15), and the range
//! proof as a batch of one (CEN-H19). [`door_verify`] calls the bodies of
//! H17, I18, I15 and H19 in that order: [`relay::masks_check`],
//! [`connect::pqc_verify`] once per input, [`relay::membership_verify`] and
//! [`connect::bp_verify`]. Those are the three terms BA-Q9 builds each
//! `SPEC_VERIFY_COST` cell from (`DAEMON_RELAY_PRIVACY.md` §72.2): the
//! masks and the proof, one hybrid signature per input, and the lone range
//! proof.
//!
//! # What it leaves out
//!
//! - **CEN-I17's derivation.** Each signing hash is keccak over the
//!   finished transaction, which the fixture does not have ([`relay`]'s
//!   module docs say why). Each signature is over a stand-in message of the
//!   hash's type and width ([`connect::stand_in_signed_hash`]); the verify's
//!   cost depends on the message's length, not its content.
//! - **`tx_form`'s other rows**, which judge the wire form's structure and
//!   verify nothing.
//! - **The multisig container.** A single-signer input pays one hybrid
//!   verification and an M-of-N input pays M. The fixture carries the
//!   single-signer form, the modal one.
//!
//! The parts are not bound to each other: the proof's per-input key scalar
//! is not derived from that input's signing key, and the range proof's
//! commitments are not the outputs' masks. No verification here reads
//! another's operands, so the bindings do not change what any of them
//! costs.

use rand_core::{CryptoRng, RngCore};

use shekyl_crypto_pq::error::PqcVerifyError;
use shekyl_ct_balance::OutputPointsError;
use shekyl_fcmp::proof::VerifyError;
use shekyl_types::SigningPayloadHash;

pub use crate::connect::stand_in_signed_hash;

use crate::connect::{self, BpFixture, PqcAuthFixture};
use crate::relay::{self, AdmissionFixture, ChunkLayout};

/// The four checks' results, kept apart and in the door's order.
///
/// Same construction as [`relay::AdmissionStatus`], for the same reason: a
/// fold into one flag loses which check refused, and a fixture that stopped
/// verifying would then be timed on the reject path while its self-witness
/// assert passed. [`DoorStatus::verified`] is true for one state only.
#[derive(Debug)]
pub struct DoorStatus {
    /// CEN-H17's body over the outputs' commitment masks.
    pub masks: Result<(), OutputPointsError>,
    /// CEN-I18's body over every input, refused at the first input whose
    /// signature does not verify, as the door names it.
    pub signatures: Result<(), (usize, PqcVerifyError)>,
    /// CEN-I15's body over the proof.
    pub membership: Result<bool, VerifyError>,
    /// CEN-H19's body over the range proof, as a batch of one.
    pub range: bool,
}

impl DoorStatus {
    /// Every check accepted: the only status a fixture the gate times may
    /// have.
    #[must_use]
    pub fn verified(&self) -> bool {
        self.masks.is_ok()
            && self.signatures.is_ok()
            && matches!(self.membership, Ok(true))
            && self.range
    }
}

/// Everything the door's verifications read for one transaction.
pub struct DoorFixture {
    /// The masks and the proof.
    pub adm: AdmissionFixture,
    /// One hybrid signature per input, in input order: I18's loop.
    pub auths: Vec<PqcAuthFixture>,
    /// The transaction's range proof over its `n_out` outputs.
    pub bp: BpFixture,
}

impl DoorFixture {
    /// Assemble a door fixture from its parts.
    ///
    /// The signatures are made by the caller. The hedged path is
    /// [`build_door_fixture`]; the drift gate passes a seeded signer to
    /// [`build_door_fixture_with`], because
    /// `sign_pqc_auth_for_output_with_ml_dsa_seed` is `shekyl-crypto-pq`'s
    /// `test-utils` surface and this crate's library edge does not enable it.
    ///
    /// # Panics
    ///
    /// If the parts disagree on the shape: a signature count other than the
    /// input count, or a range proof over other than the output count. The
    /// door refuses both shapes, so a fixture built that way would time the
    /// reject path.
    #[must_use]
    pub fn new(adm: AdmissionFixture, auths: Vec<PqcAuthFixture>, bp: BpFixture) -> Self {
        assert_eq!(
            auths.len(),
            adm.n_in,
            "one hybrid signature per input: {} for {} inputs",
            auths.len(),
            adm.n_in
        );
        assert_eq!(
            bp.commitments.len(),
            adm.n_out,
            "the range proof covers every output: {} commitments for {} outputs",
            bp.commitments.len(),
            adm.n_out
        );
        Self { adm, auths, bp }
    }
}

/// Build a door fixture at shape `(n_in, n_out)`, signed by the wallet's own
/// hedged signer ([`connect::build_pqc_auth`]).
///
/// For tests and wall-clock use. The drift gate passes its seeded signer to
/// [`build_door_fixture_with`] so both paths share this draw order.
pub fn build_door_fixture<R: RngCore + CryptoRng>(
    rng: &mut R,
    n_in: usize,
    n_out: usize,
    tree_depth: u8,
    layout: ChunkLayout,
) -> DoorFixture {
    build_door_fixture_with(rng, n_in, n_out, tree_depth, layout, |rng, message| {
        connect::build_pqc_auth(rng, message)
    })
}

/// Build a door fixture, signing each input with `sign`.
///
/// Draw order, on one `rng`: the admission fixture (the masks and the
/// proof), then one signature per input, then the range proof. The drift
/// gate depends on that order. Its admission operands are whatever
/// [`relay::build_fixture`] draws first from the pinned seed, and `sign`
/// may draw from the same stream; the range proof continues after it.
///
/// `sign` receives each input's [`stand_in_signed_hash`], in input order.
pub fn build_door_fixture_with<R, S>(
    rng: &mut R,
    n_in: usize,
    n_out: usize,
    tree_depth: u8,
    layout: ChunkLayout,
    mut sign: S,
) -> DoorFixture
where
    R: RngCore + CryptoRng,
    S: FnMut(&mut R, SigningPayloadHash) -> PqcAuthFixture,
{
    let adm = relay::build_fixture(rng, n_in, n_out, tree_depth, layout);
    let auths = (0..adm.n_in)
        .map(|input| sign(rng, stand_in_signed_hash(input)))
        .collect();
    let bp = connect::build_bp(rng, adm.n_out);
    DoorFixture::new(adm, auths, bp)
}

/// The door's verifications, in its order: the masks, each input's
/// signature, the proof, the range proof.
///
/// The door stops at the first refusal. This runs every check, so a fixture
/// that stops verifying names each one that refused; on an accepting
/// fixture, the only kind the gate times, the two do the same work.
pub fn door_verify(f: &DoorFixture) -> DoorStatus {
    let masks = relay::masks_check(&f.adm);
    let signatures = signatures_verify(&f.auths);
    let membership = relay::membership_verify(&f.adm);
    let range = connect::bp_verify(&f.bp);
    DoorStatus {
        masks,
        signatures,
        membership,
        range,
    }
}

/// CEN-I18's loop: every input's hybrid signature, refused at the first
/// that does not verify.
fn signatures_verify(auths: &[PqcAuthFixture]) -> Result<(), (usize, PqcVerifyError)> {
    for (input, auth) in auths.iter().enumerate() {
        connect::pqc_verify(auth).map_err(|error| (input, error))?;
    }
    Ok(())
}
