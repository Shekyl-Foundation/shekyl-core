// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The FROST spend-auth-and-linkability (SAL) leg of an Option E′ multisig
//! spend, as a thin layer over `modular_frost`'s own signing machines.
//!
//! A multisig output's key is `O = x·G + y·T` with `x = ho + b`, which every
//! member computes, and `y = y_group + y_kem`. `y_group` is shared M-of-N
//! by Shamir over the Ed25519 scalar field; `y_kem` is the output's public
//! tweak, recovered by every member from the output's group KEM secret.
//! The SAL proves knowledge of `x` and `y` for the rerandomized output
//! `O~ = O + r_o·T`, so the FROST group key the machines sign under is
//! `(y_group + y_kem + r_o)·T`: the member's keys offset by `y_kem − o_blind`.
//!
//! Three things live here:
//!
//! - [`dealer_split`] samples `y_group` and splits it for a new group;
//!   [`threshold_keys`] turns one member's stored share back into
//!   `ThresholdKeys<Ed25519T>`, refusing a share set that does not open the
//!   address's `Y_group`.
//! - [`SalSigningParams`] is what the proposer fixes for one input: the
//!   output, its rerandomization, the transaction's `tx_signable`, and the
//!   member-known scalars `x` and `y_kem`. Every signer builds the same
//!   [`SalAlgorithm`] from it, so all of them share one transcript.
//! - [`preprocess`], [`from_cache`], [`sign`], [`complete`] and [`cache`]
//!   drive the machines. A sign machine exists only through [`preprocess`]
//!   or [`from_cache`], both of which offset the keys and check that they
//!   open the rerandomized output, so the `SalAlgorithm` contract ("the
//!   keys are already offset; undefined behavior if not") is met by
//!   construction.
//!
//! Nonce custody is the machine's: `modular_frost` hedges each nonce with
//! the secret share and binds every signer's nonces to the whole signing
//! set (FROST's binding factor). Nothing here sees a nonce.
//!
//! Signing under a public additive tweak of the group key is standard, but
//! its soundness here is a Phase 6 review question
//! (`docs/design/V3_1_MULTISIG_RUST_ENGINE.md` §0.5), not a settled one.

use std::collections::HashMap;
use std::fmt;

use ciphersuite::group::{ff::PrimeField, Group, GroupEncoding};
use ciphersuite::Ciphersuite;
use dalek_ff_group::{EdwardsPoint, Scalar};
use modular_frost::dkg::Interpolation;
use modular_frost::sign::{
    AlgorithmMachine, AlgorithmSignMachine, AlgorithmSignatureMachine, PreprocessMachine,
    SignMachine, SignatureMachine,
};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, OsRng, RngCore, SeedableRng};
use transcript::{RecommendedTranscript, Transcript};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub use modular_frost::sign::{CachedPreprocess, Preprocess, SignatureShare};
pub use modular_frost::{FrostError, Participant, ThresholdKeys, ThresholdParams};
pub use shekyl_fcmp_proofs::sal::multisig::{Ed25519T, SalAlgorithm};
use shekyl_fcmp_proofs::sal::{RerandomizedOutput, SpendAuthAndLinkability};
use shekyl_fcmp_proofs::Output;
use shekyl_types::TxSignableHash;

use shekyl_crypto_pq::multisig::MAX_MULTISIG_PARTICIPANTS;

/// The SAL algorithm every signer of one input runs.
pub type FrostSal = SalAlgorithm<ChaCha20Rng, RecommendedTranscript>;
/// A signer after round 1 (preprocess), holding its nonces.
pub type SalSignMachine = AlgorithmSignMachine<Ed25519T, FrostSal>;
/// A signer after round 2 (sign), waiting for the other shares.
pub type SalSignatureMachine = AlgorithmSignatureMachine<Ed25519T, FrostSal>;
/// One signer's round-1 message.
pub type SalPreprocess = Preprocess<Ed25519T, ()>;
/// One signer's round-2 message.
pub type SalShare = SignatureShare<Ed25519T>;

// ---------------------------------------------------------------------------
// Dealer split and the member-share loader
// ---------------------------------------------------------------------------

/// Why a group's FROST key material cannot be built or loaded. Member
/// indices are 0-based, as the member file and the address number them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FrostKeyError {
    /// `n` is 0 or above [`MAX_MULTISIG_PARTICIPANTS`], or `m` is 0 or above `n`.
    #[error("no {m}-of-{n} multisig group exists")]
    GroupShape {
        /// The member count.
        n: u8,
        /// The threshold.
        m: u8,
    },
    /// The member index is not below `n`.
    #[error("member {index} is not in a group of {n}")]
    MemberIndex {
        /// The index given.
        index: u8,
        /// The member count.
        n: u8,
    },
    /// There is not one verification share per member.
    #[error("expected {expected} verification shares, got {got}")]
    VerificationShareCount {
        /// `n`.
        expected: usize,
        /// The count given.
        got: usize,
    },
    /// The member's share is not the canonical encoding of a scalar.
    #[error("the member's share is not a canonical scalar")]
    NonCanonicalShare,
    /// A verification share is not the canonical encoding of a
    /// prime-order, non-identity point.
    #[error("member {member}'s verification share is not a valid point")]
    VerificationShare {
        /// Whose share it is.
        member: u8,
    },
    /// The member's share times `T` is not the member's own verification
    /// share: the share and the shares list belong to different splits, or
    /// to different members.
    #[error("the member's share does not match its verification share")]
    ShareMismatch,
    /// The first `m` verification shares interpolate to a key other than
    /// the address's `Y_group`.
    #[error("the verification shares do not open the address's group key")]
    GroupKeyMismatch,
    /// This member's verification share is not on the polynomial the
    /// shares before it define, so any signing set that includes it would
    /// fail and blame an honest signer.
    #[error("member {member}'s verification share is not on the group's polynomial")]
    OffPolynomial {
        /// Whose share it is.
        member: u8,
    },
}

/// A new group's `y_group`, split M-of-N. Index `i` of each list is member
/// `i` (0-based); the member's FROST participant is `i + 1`.
///
/// `y_group` itself is gone by the time this exists: only its public key
/// and the shares leave [`dealer_split`].
pub struct DealerSplit {
    /// `Y_group = y_group·T`, compressed: the address's `Y_group`.
    pub y_group: [u8; 32],
    /// Each member's share of `y_group`, canonical scalar bytes.
    pub shares: Vec<Zeroizing<[u8; 32]>>,
    /// `share_i·T` for every member, compressed. Every member file
    /// carries all of them.
    pub verification_shares: Vec<[u8; 32]>,
}

impl fmt::Debug for DealerSplit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DealerSplit")
            .field("y_group", &self.y_group)
            .field("shares", &"[REDACTED]")
            .field("verification_shares", &self.verification_shares)
            .finish()
    }
}

/// Sample `y_group` and split it M-of-N (Shamir over the Ed25519 scalar
/// field at `x = 1..=n`, verification shares under `T`).
///
/// The split is `dkg-dealer`'s `key_gen`, whose coefficients wipe on drop.
///
/// # Errors
///
/// [`FrostKeyError::GroupShape`] for a group no address can carry.
pub fn dealer_split(
    n: u8,
    m: u8,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<DealerSplit, FrostKeyError> {
    check_group_shape(n, m)?;
    // `key_gen` refuses only a shape `check_group_shape` already refused.
    // A refusal here is dkg disagreeing with that check, not a caller's group.
    let keys = dkg_dealer::key_gen::<_, Ed25519T>(rng, u16::from(m), u16::from(n))
        .expect("dkg-dealer splits every group check_group_shape accepts");
    let first = &keys[&participant(0)];
    let mut shares = Vec::with_capacity(usize::from(n));
    let mut verification_shares = Vec::with_capacity(usize::from(n));
    for index in 0..n {
        let p = participant(index);
        shares.push(Zeroizing::new(keys[&p].original_secret_share().to_repr()));
        verification_shares.push(first.original_verification_share(p).to_bytes());
    }
    Ok(DealerSplit {
        y_group: first.original_group_key().to_bytes(),
        shares,
        verification_shares,
    })
}

/// One member's `ThresholdKeys<Ed25519T>` from what its member file stores.
///
/// `member_index` is the file's 0-based index; this is the one place it
/// becomes dkg's 1-based [`Participant`]. `y_group` is the address's
/// `Y_group`. Every check runs before the keys exist, so a member file that
/// loads is one whose shares sign:
///
/// - the share is canonical and every verification share is a canonical,
///   prime-order, non-identity point;
/// - the share is the discrete log of the member's own verification share;
/// - the first `m` verification shares interpolate to `Y_group`;
/// - every later share lies on the same polynomial (each window of `m`
///   consecutive shares interpolates to `Y_group`, which pins the share
///   entering the window).
///
/// # Errors
///
/// [`FrostKeyError`], naming the first check that failed.
pub fn threshold_keys(
    n: u8,
    m: u8,
    member_index: u8,
    share: &[u8; 32],
    verification_shares: &[[u8; 32]],
    y_group: &[u8; 32],
) -> Result<ThresholdKeys<Ed25519T>, FrostKeyError> {
    check_group_shape(n, m)?;
    if member_index >= n {
        return Err(FrostKeyError::MemberIndex {
            index: member_index,
            n,
        });
    }
    if verification_shares.len() != usize::from(n) {
        return Err(FrostKeyError::VerificationShareCount {
            expected: usize::from(n),
            got: verification_shares.len(),
        });
    }
    let share = Zeroizing::new(
        Option::<Scalar>::from(Scalar::from_repr(*share))
            .ok_or(FrostKeyError::NonCanonicalShare)?,
    );
    let points = verification_shares
        .iter()
        .zip(0u8..)
        .map(|(bytes, member)| {
            decode_point(bytes).ok_or(FrostKeyError::VerificationShare { member })
        })
        .collect::<Result<Vec<_>, _>>()?;

    if Ed25519T::generator() * *share != points[usize::from(member_index)] {
        return Err(FrostKeyError::ShareMismatch);
    }
    let window = usize::from(m);
    if interpolate_at_zero(&points, 0, window).to_bytes() != *y_group {
        return Err(FrostKeyError::GroupKeyMismatch);
    }
    for start in 1..=points.len() - window {
        if interpolate_at_zero(&points, start, window).to_bytes() != *y_group {
            let entering = u8::try_from(start + window - 1).expect("below n, a u8");
            return Err(FrostKeyError::OffPolynomial { member: entering });
        }
    }

    // Both constructors refuse only shapes and participant sets this function
    // already checked. A refusal is dkg disagreeing with those checks.
    let params = ThresholdParams::new(u16::from(m), u16::from(n), participant(member_index))
        .expect("dkg accepts a member of a group check_group_shape accepts");
    let by_participant = points
        .into_iter()
        .zip(0u8..)
        .map(|(point, member)| (participant(member), point))
        .collect::<HashMap<_, _>>();
    Ok(
        ThresholdKeys::new(params, Interpolation::Lagrange, share, by_participant)
            .expect("dkg accepts one Lagrange share per participant of a checked group"),
    )
}

/// dkg's participant for a 0-based member index.
fn participant(member_index: u8) -> Participant {
    Participant::new(u16::from(member_index) + 1).expect("index + 1 is never zero")
}

fn check_group_shape(n: u8, m: u8) -> Result<(), FrostKeyError> {
    if n == 0 || n > MAX_MULTISIG_PARTICIPANTS || m == 0 || m > n {
        return Err(FrostKeyError::GroupShape { n, m });
    }
    Ok(())
}

/// A canonical, prime-order, non-identity point, or `None`.
fn decode_point(bytes: &[u8; 32]) -> Option<EdwardsPoint> {
    let point = Option::<EdwardsPoint>::from(EdwardsPoint::from_bytes(bytes))?;
    let canonical = point.to_bytes() == *bytes;
    (canonical && !bool::from(point.is_identity())).then_some(point)
}

/// `Σ λ_j·V_j` over the members `start..start + len` (0-based), with `λ_j`
/// the Lagrange coefficient at zero for their participants `start + 1 ..`.
fn interpolate_at_zero(points: &[EdwardsPoint], start: usize, len: usize) -> EdwardsPoint {
    let xs: Vec<Scalar> = (start..start + len)
        .map(|i| Scalar::from(u64::try_from(i + 1).expect("a small index")))
        .collect();
    xs.iter()
        .zip(&points[start..start + len])
        .map(|(x_i, point)| {
            let (num, den) = xs
                .iter()
                .filter(|x_j| *x_j != x_i)
                .fold((Scalar::ONE, Scalar::ONE), |(num, den), x_j| {
                    (num * x_j, den * (*x_j - x_i))
                });
            *point * (num * Option::<Scalar>::from(den.invert()).expect("distinct participants"))
        })
        .sum()
}

// ---------------------------------------------------------------------------
// Signing parameters
// ---------------------------------------------------------------------------

/// Why an input's signing parameters cannot be built, or why a member's keys
/// cannot sign for them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FrostSalError {
    /// The output key is not a canonical, prime-order, non-identity point.
    #[error("the output key is not a valid point")]
    OutputKey,
    /// The commitment is not a canonical, prime-order, non-identity point.
    #[error("the output's commitment is not a valid point")]
    Commitment,
    /// `x = ho + b` is not the canonical encoding of a scalar.
    #[error("the spend scalar x is not a canonical scalar")]
    SpendScalar,
    /// `y_kem` is not the canonical encoding of a scalar.
    #[error("the output tweak y_kem is not a canonical scalar")]
    OutputTweak,
    /// The commitment mask `z` is not the canonical encoding of a scalar.
    #[error("the commitment mask is not a canonical scalar")]
    CommitmentMask,
    /// The pseudo-out blind `a` is not the canonical encoding of a scalar.
    #[error("the pseudo-out blind is not a canonical scalar")]
    PseudoOutBlind,
    /// The keys, offset for this output, are not the `T` part of the
    /// rerandomized output key: `x`, `y_kem` or the keys belong to some
    /// other output or group.
    #[error("these keys do not open this output's rerandomized key")]
    KeysDoNotOpenOutput,
}

/// One group output being spent, as every member knows it from its own
/// scan: the output key and commitment (public), and the group-plaintext
/// secrets `x = ho + b` (`shekyl_crypto_pq::output::compute_output_key_image`),
/// `y_kem` (the `y` the output's group secret derives) and the commitment
/// mask `z`.
pub struct SpentOutput<'a> {
    /// `O`, compressed.
    pub output_key: &'a [u8; 32],
    /// `C`, compressed.
    pub commitment: &'a [u8; 32],
    /// `x = ho + b`.
    pub spend_scalar: &'a [u8; 32],
    /// The output's per-output tweak `y_kem`.
    pub y_kem: &'a [u8; 32],
    /// The commitment mask `z` (`C = z·G + amount·H`).
    pub commitment_mask: &'a [u8; 32],
}

/// What the proposer fixes for one input. Every signer signs from the same
/// value, so every signer's [`SalAlgorithm`] has the same transcript.
///
/// `x` and `y_kem` are secret to the group (every member can compute them
/// from the output), and the rerandomization links the input to its output,
/// so the whole value wipes on drop, its `Debug` shows only the output, and
/// it is not `Clone`: signers share it by reference.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SalSigningParams {
    #[zeroize(skip)]
    output: Output,
    rerandomized: RerandomizedOutput,
    #[zeroize(skip)]
    signable: TxSignableHash,
    x: Scalar,
    y_kem: Scalar,
}

impl fmt::Debug for SalSigningParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SalSigningParams")
            .field("output", &self.output)
            .finish_non_exhaustive()
    }
}

impl SalSigningParams {
    /// The proposer's parameters for spending `spent` as one input of a
    /// transaction whose message is `signable`, with pseudo-out blind
    /// `pseudo_out_blind` (`a`).
    ///
    /// The rerandomization's commitment blind is `r_c = a − z`, so the
    /// input's pseudo-out is `C~ = C + r_c·G = a·G + amount·H`: the
    /// assembler picks every `a` and balances the last one, exactly as the
    /// solo prover does. The other three blinds are drawn from `rng`. The
    /// key-image generator is `Hp(O)`.
    ///
    /// # Errors
    ///
    /// [`FrostSalError`] for a point or scalar that does not decode.
    pub fn propose(
        rng: &mut (impl RngCore + CryptoRng),
        spent: &SpentOutput<'_>,
        pseudo_out_blind: &[u8; 32],
        signable: TxSignableHash,
    ) -> Result<Self, FrostSalError> {
        let o = decode_point(spent.output_key).ok_or(FrostSalError::OutputKey)?;
        let c = decode_point(spent.commitment).ok_or(FrostSalError::Commitment)?;
        let i = EdwardsPoint(shekyl_curve_generators::biased_hash_to_point(
            *spent.output_key,
        ));
        let output = Output::new(o, i, c).map_err(|_| FrostSalError::OutputKey)?;
        let z = Zeroizing::new(
            Option::<Scalar>::from(Scalar::from_repr(*spent.commitment_mask))
                .ok_or(FrostSalError::CommitmentMask)?,
        );
        let a = Zeroizing::new(
            Option::<Scalar>::from(Scalar::from_repr(*pseudo_out_blind))
                .ok_or(FrostSalError::PseudoOutBlind)?,
        );
        let r_c = Zeroizing::new(*a - *z);
        // The wipe-on-drop owner exists before either secret is decoded, and
        // each decodes straight into its field: a refusal of `y_kem` drops
        // the params, which wipes `x`.
        let mut params = Self {
            output,
            rerandomized: RerandomizedOutput::with_commitment_blind(rng, output, *r_c),
            signable,
            x: Scalar::ZERO,
            y_kem: Scalar::ZERO,
        };
        params.x = Option::<Scalar>::from(Scalar::from_repr(*spent.spend_scalar))
            .ok_or(FrostSalError::SpendScalar)?;
        params.y_kem = Option::<Scalar>::from(Scalar::from_repr(*spent.y_kem))
            .ok_or(FrostSalError::OutputTweak)?;
        Ok(params)
    }

    /// The output being spent, as `prove_with_sal` takes it.
    #[must_use]
    pub fn output(&self) -> Output {
        self.output
    }

    /// The input's rerandomization, as `prove_with_sal` takes it.
    #[must_use]
    pub fn rerandomized(&self) -> &RerandomizedOutput {
        &self.rerandomized
    }

    /// The algorithm every signer runs for this input.
    fn algorithm(&self) -> FrostSal {
        // The algorithm's RNG only weights `complete`'s batch check of the
        // aggregate signature; it never reaches a nonce.
        let mut seed = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(seed.as_mut());
        SalAlgorithm::new(
            ChaCha20Rng::from_seed(*seed),
            // LIVE domain (Shekyl-authored, not inherited). Its bytes root
            // every multisig SAL transcript, so changing the spelling
            // re-derives every multisig challenge — a versioned breaking
            // change, not a rename (SIGNATURE_ALIGNMENT.md §5;
            // CRYPTO_DOMAIN_REGISTRY.tsv, mechanism 3).
            RecommendedTranscript::new(b"Shekyl FROST SAL v1"),
            self.signable,
            self.rerandomized.clone(),
            self.x,
        )
    }

    /// `keys` offset by `y_kem − o_blind`, so their group key is the `T`
    /// part of the rerandomized output key `O~ − x·G`.
    fn offset_keys(
        &self,
        keys: ThresholdKeys<Ed25519T>,
    ) -> Result<ThresholdKeys<Ed25519T>, FrostSalError> {
        let keys = keys.offset(self.y_kem - self.rerandomized.o_blind());
        let t_part = self.rerandomized.input().O_tilde() - (EdwardsPoint::generator() * self.x);
        if keys.group_key() != t_part {
            return Err(FrostSalError::KeysDoNotOpenOutput);
        }
        Ok(keys)
    }
}

// ---------------------------------------------------------------------------
// The machines
// ---------------------------------------------------------------------------

/// Round 1 for one input: this member's sign machine and the preprocess it
/// sends to the other signers.
///
/// # Errors
///
/// [`FrostSalError::KeysDoNotOpenOutput`] when `keys` are not this output's
/// group's keys.
pub fn preprocess(
    params: &SalSigningParams,
    keys: ThresholdKeys<Ed25519T>,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(SalSignMachine, SalPreprocess), FrostSalError> {
    let keys = params.offset_keys(keys)?;
    Ok(AlgorithmMachine::new(params.algorithm(), keys).preprocess(rng))
}

/// This round-1 state as a seed that [`from_cache`] rebuilds it from.
///
/// The seed is as secret as the member's share, and is used once: signing
/// twice from one seed reveals the share.
#[must_use]
pub fn cache(machine: SalSignMachine) -> CachedPreprocess {
    machine.cache()
}

/// Rebuild a round-1 state from [`cache`]'s seed, for the same params and
/// keys.
///
/// # Errors
///
/// [`FrostSalError::KeysDoNotOpenOutput`], as for [`preprocess`].
pub fn from_cache(
    params: &SalSigningParams,
    keys: ThresholdKeys<Ed25519T>,
    cached: CachedPreprocess,
) -> Result<(SalSignMachine, SalPreprocess), FrostSalError> {
    let keys = params.offset_keys(keys)?;
    Ok(SalSignMachine::from_cache(params.algorithm(), keys, cached))
}

/// Round 2: this member's share, over every other signer's preprocess. The
/// signers who sent one are the signing set. The SAL's message is fixed at
/// [`SalSigningParams`]; the FROST message is empty, as `SalAlgorithm`
/// requires.
///
/// # Errors
///
/// `modular_frost`'s refusal of the signing set (too few signers, an
/// unknown or repeated participant, a preprocess count that is not the
/// set's).
pub fn sign(
    machine: SalSignMachine,
    preprocesses: HashMap<Participant, SalPreprocess>,
) -> Result<(SalSignatureMachine, SalShare), FrostError> {
    machine.sign(preprocesses, &[])
}

/// The aggregate SAL from every other signer's share. `modular_frost`
/// checks the aggregate and, when it fails, finds the signer whose share
/// is bad.
///
/// # Errors
///
/// [`FrostError::InvalidShare`] naming a signer whose share does not
/// verify; [`FrostError::InternalError`] when every share verifies but the
/// aggregate does not (the keys were not offset for this output); a
/// share-count refusal.
pub fn complete(
    machine: SalSignatureMachine,
    shares: HashMap<Participant, SalShare>,
) -> Result<SpendAuthAndLinkability, FrostError> {
    machine.complete(shares)
}

#[cfg(test)]
#[path = "frost_sal_tests.rs"]
mod tests;
