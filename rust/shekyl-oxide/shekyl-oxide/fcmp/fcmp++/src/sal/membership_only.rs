//! Membership-only spend authority: the `R_O` leg of SAL, without a key image.
//!
//! `MembershipSpendAuth` proves knowledge of the `(x, y~)` opening of a rerandomized
//! output key `O~ = x·G + y~·T` — spend authority — without producing the key image
//! `L = x·I`. It is the SAL-replacement leg of [`crate::FcmpMembershipOnly`], the first
//! consumer of which is the reward-emission vin
//! (`docs/design/REWARD_EMISSION_LEG.md` §7.2).
//!
//! This is a sibling type to [`SpendAuthAndLinkability`], not a mode flag: cross-type
//! rejection is a compile-time property at the typed API, and the transcript
//! domain-separation tag ([`SAL_MEMBERSHIP_ONLY_DST`]) is the guard at the byte seam,
//! where the type guarantee evaporates. See `docs/design/FCMP_MEMBERSHIP_ONLY.md` §2.2,
//! §4.
//!
//! ## Nonce synthesis
//!
//! All per-proof scalars (the Schnorr nonces `alpha`, `r_y` and the four
//! rerandomization scalars) are derived RFC-6979-style — a hash over a per-scalar
//! domain tag, the secret spend scalar, the binding context, and fresh RNG output —
//! rather than drawn raw from the RNG. A degraded RNG therefore cannot produce zero or
//! cross-context-reused nonces; the worst case collapses to
//! deterministic-but-distinct-per-context. This is the prevention layer for the
//! non-linkability property (`docs/design/FCMP_MEMBERSHIP_ONLY.md` §6); the
//! construction guard in [`membership_only_rerandomize`] is the backstop.
//!
//! As with any RFC-6979-style derivation, the secret spend scalar transits the hash
//! state, which is transient stack memory not covered by wipe-on-drop. This matches
//! the crate's existing posture (e.g. [`RerandomizedOutput::write`] serializes
//! rerandomization secrets by design) and is recorded here rather than silently
//! assumed.

use std_shims::io;

use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

use blake2::{Blake2b512, Digest};

use ciphersuite::{
    group::{ff::PrimeField, Group, GroupEncoding},
    Ciphersuite,
};
use dalek_ff_group::{Ed25519, EdwardsPoint, Scalar};

use shekyl_generators::T;

use crate::{
    sal::{
        sal_dst, tags_pairwise_distinct, OpenedInputTuple, RerandomizedOutput,
        SAL_MEMBERSHIP_ONLY_DST,
    },
    Input, Output,
};

/// An error encountered while constructing a membership-only proof component.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MembershipOnlyError {
    /// A rerandomized component equalled its base (or `R` was the identity).
    ///
    /// With working nonce synthesis this is a ~2^-252 event per component; in practice
    /// it indicates a broken RNG seam or a regression bypassing synthesis. The proof is
    /// not produced: shipping it would make repeated backing proofs of the same leaf
    /// directly linkable (`docs/design/FCMP_MEMBERSHIP_ONLY.md` §6).
    DegenerateRerandomization,
}

/// Synthesize a per-proof scalar RFC-6979-style.
///
/// `Blake2b512(domain ‖ x ‖ context parts ‖ fresh RNG output) → Scalar::from_hash`.
/// Every context part is fixed-width or length-prefixed by the caller per the framing
/// discipline (`docs/design/FCMP_MEMBERSHIP_ONLY.md` §4.3).
fn synthesize_scalar(
    rng: &mut (impl RngCore + CryptoRng),
    domain: &[u8; 64],
    x: &Scalar,
    context_parts: &[&[u8]],
) -> Zeroizing<Scalar> {
    let mut transcript = Blake2b512::new();
    transcript.update(domain);
    transcript.update(x.to_repr());
    for part in context_parts {
        transcript.update(part);
    }
    let mut fresh = [0u8; 32];
    rng.fill_bytes(&mut fresh);
    transcript.update(fresh);
    fresh.zeroize();
    Zeroizing::new(Scalar::from_hash(transcript))
}

const MO_NONCE_R_O: [u8; 64] = sal_dst(b"Shekyl FCMP++ MO nonce r_o v1");
const MO_NONCE_R_I: [u8; 64] = sal_dst(b"Shekyl FCMP++ MO nonce r_i v1");
const MO_NONCE_R_R_I: [u8; 64] = sal_dst(b"Shekyl FCMP++ MO nonce r_r_i v1");
const MO_NONCE_R_C: [u8; 64] = sal_dst(b"Shekyl FCMP++ MO nonce r_c v1");
const MO_NONCE_ALPHA: [u8; 64] = sal_dst(b"Shekyl FCMP++ MO nonce alpha v1");
const MO_NONCE_R_Y: [u8; 64] = sal_dst(b"Shekyl FCMP++ MO nonce r_y v1");

// The per-scalar nonce domain tags are load-bearing for nonce-role independence: two
// roles sharing a tag would synthesize identical nonces from identical inputs, which a
// copy/paste of the strings above could silently introduce. Reject that at compile time.
const _: () = assert!(
    tags_pairwise_distinct(&[
        MO_NONCE_R_O,
        MO_NONCE_R_I,
        MO_NONCE_R_R_I,
        MO_NONCE_R_C,
        MO_NONCE_ALPHA,
        MO_NONCE_R_Y,
    ]),
    "membership-only nonce domain tags must be pairwise distinct"
);

/// Rerandomize an output for a membership-only proof, with synthesized blinds.
///
/// `x` is the secret spend scalar for the output's `O = x·G + y·T`; `context` is a
/// caller-supplied binding context (the emission caller passes the reference root) and
/// is length-prefixed internally. The rerandomization scalars are synthesized from
/// `(x, leaf tuple, context, fresh entropy)`, so distinct contexts yield distinct
/// rerandomizations even under a totally degraded RNG.
///
/// Returns [`MembershipOnlyError::DegenerateRerandomization`] — loudly, before any
/// proof exists — if a rerandomized component equals its base.
pub fn membership_only_rerandomize(
    rng: &mut (impl RngCore + CryptoRng),
    output: Output,
    x: &Scalar,
    context: &[u8],
) -> Result<RerandomizedOutput, MembershipOnlyError> {
    let leaf_o = output.O().to_bytes();
    let leaf_i = output.I().to_bytes();
    let leaf_c = output.C().to_bytes();
    // Fixed-width length prefix for the variable-length context, per the framing
    // discipline (`docs/design/FCMP_MEMBERSHIP_ONLY.md` §4.3). `usize` is at most
    // 64 bits on every supported target, so the cast is lossless.
    let context_len = (context.len() as u64).to_le_bytes();
    let context_parts: &[&[u8]] = &[&leaf_o, &leaf_i, &leaf_c, &context_len, context];

    let r_o = synthesize_scalar(rng, &MO_NONCE_R_O, x, context_parts);
    let r_i = synthesize_scalar(rng, &MO_NONCE_R_I, x, context_parts);
    let r_r_i = synthesize_scalar(rng, &MO_NONCE_R_R_I, x, context_parts);
    let r_c = synthesize_scalar(rng, &MO_NONCE_R_C, x, context_parts);

    let rerandomized = RerandomizedOutput::with_blinds(output, *r_o, *r_i, *r_r_i, *r_c);

    check_nondegenerate(&rerandomized.input(), &output)?;

    Ok(rerandomized)
}

/// F-6 construction guard: never ship a linkable rerandomization.
///
/// A rerandomized component equal to its base means the corresponding blind was zero;
/// an identity `R` means both of its blinds were zero.
pub(crate) fn check_nondegenerate(
    input: &Input,
    output: &Output,
) -> Result<(), MembershipOnlyError> {
    if (input.O_tilde() == output.O())
        || (input.I_tilde() == output.I())
        || (input.C_tilde() == output.C())
        || input.R().is_identity().into()
    {
        return Err(MembershipOnlyError::DegenerateRerandomization);
    }
    Ok(())
}

/// The membership-only spend-authority proof for an input: the `R_O` leg of SAL alone.
///
/// Proves knowledge of the `(x, y~)` opening of `O~` over `(G, T)` without binding a
/// key image. Soundness of this leg in isolation, and its composition with the `Fcmp`
/// membership leg, is argued in `docs/design/FCMP_MEMBERSHIP_ONLY.md` §5.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct MembershipSpendAuth {
    R_O: <Ed25519 as Ciphersuite>::G,
    s_alpha: <Ed25519 as Ciphersuite>::F,
    s_y: <Ed25519 as Ciphersuite>::F,
}

impl MembershipSpendAuth {
    /// Byte length of a serialized membership-only SAL-replacement leg: 1 point
    /// (`R_O`) plus 2 scalars (`s_alpha`, `s_y`).
    ///
    /// Single source of truth for the leg's contribution to
    /// [`crate::FcmpMembershipOnly::proof_size`]. Asserted against the actual
    /// [`MembershipSpendAuth::write`] footprint in the crate tests.
    pub const WIRE_SIZE: usize = 3 * crate::ED25519_REPR_BYTES;

    /// The membership-only challenge.
    ///
    /// Preimage (all fields fixed-width per the length-regularity invariant,
    /// `docs/design/FCMP_MEMBERSHIP_ONLY.md` §4.2): the 64-byte membership-only tag,
    /// the signable tx hash, the input's index (`u32` LE — binds slot position so a
    /// `MembershipSpendAuth` cannot be transplanted across inputs, even identical
    /// ones), the input tuple without `L`, and the nonce commitment `R_O`.
    fn challenge(
        signable_tx_hash: [u8; 32],
        input_index: u32,
        input: &Input,
        R_O: EdwardsPoint,
    ) -> Scalar {
        let mut transcript = Blake2b512::new();

        transcript.update(SAL_MEMBERSHIP_ONLY_DST);
        transcript.update(signable_tx_hash);
        transcript.update(input_index.to_le_bytes());
        transcript.update(input.O_tilde().to_bytes());
        transcript.update(input.I_tilde().to_bytes());
        transcript.update(input.C_tilde().to_bytes());
        transcript.update(input.R().to_bytes());
        transcript.update(R_O.to_bytes());

        Scalar::from_hash(transcript)
    }

    /// Prove membership-only spend authority for an opened input tuple.
    ///
    /// `input_index` is the input's position in the transaction's ordered input set.
    pub fn prove(
        rng: &mut (impl RngCore + CryptoRng),
        signable_tx_hash: [u8; 32],
        input_index: u32,
        opening: &OpenedInputTuple,
    ) -> MembershipSpendAuth {
        let G = <Ed25519 as Ciphersuite>::G::generator();
        let T_ = EdwardsPoint(*T);

        let index_bytes = input_index.to_le_bytes();
        let o_tilde = opening.input.O_tilde().to_bytes();
        let i_tilde = opening.input.I_tilde().to_bytes();
        let c_tilde = opening.input.C_tilde().to_bytes();
        let r = opening.input.R().to_bytes();
        let context_parts: &[&[u8]] = &[
            &signable_tx_hash,
            &index_bytes,
            &o_tilde,
            &i_tilde,
            &c_tilde,
            &r,
        ];

        let alpha = synthesize_scalar(rng, &MO_NONCE_ALPHA, &opening.x, context_parts);
        let r_y = synthesize_scalar(rng, &MO_NONCE_R_Y, &opening.x, context_parts);

        let R_O = (G * *alpha) + (T_ * *r_y);

        let e = Self::challenge(signable_tx_hash, input_index, &opening.input, R_O);

        // Identical in form and distribution to the full SAL's s_alpha / s_y
        // (`docs/design/FCMP_MEMBERSHIP_ONLY.md` §5.2).
        let s_alpha = *alpha + (e * opening.x);
        let s_y = *r_y + (e * opening.y);

        MembershipSpendAuth { R_O, s_alpha, s_y }
    }

    /// Verify a membership-only spend-authority proof.
    ///
    /// This only queues the proof for batch verification — one `queue` call for the
    /// single `R_O` equation, preserving per-equation independent weighting
    /// (`docs/design/FCMP_MEMBERSHIP_ONLY.md` §5.4). The BatchVerifier MUST also be
    /// verified.
    pub fn verify(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        verifier: &mut multiexp::BatchVerifier<(), <Ed25519 as Ciphersuite>::G>,
        signable_tx_hash: [u8; 32],
        input_index: u32,
        input: &Input,
    ) {
        let G = <Ed25519 as Ciphersuite>::G::generator();
        let T_ = EdwardsPoint(*T);

        let e = Self::challenge(signable_tx_hash, input_index, input, self.R_O);

        // O_tilde GSP verification statement: R_O + e O~ == s_alpha G + s_y T
        verifier.queue(
            rng,
            (),
            [
                (Scalar::ONE, self.R_O),
                (e, input.O_tilde()),
                // RHS
                (-self.s_alpha, G),
                (-self.s_y, T_),
            ],
        );
    }

    /// Write a membership-only spend-authority proof.
    pub fn write(&self, writer: &mut impl io::Write) -> io::Result<()> {
        writer.write_all(&self.R_O.to_bytes())?;
        writer.write_all(&self.s_alpha.to_repr())?;
        writer.write_all(&self.s_y.to_repr())
    }

    /// Read a membership-only spend-authority proof.
    pub fn read(reader: &mut impl io::Read) -> io::Result<Self> {
        Ok(Self {
            R_O: Ed25519::read_G(reader)?,
            s_alpha: Ed25519::read_F(reader)?,
            s_y: Ed25519::read_F(reader)?,
        })
    }
}
