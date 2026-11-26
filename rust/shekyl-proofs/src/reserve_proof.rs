// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Reserve proof: proves ownership of unspent outputs.
//!
//! Per output the proof carries: ho, y, k_amount, key_image, DLEQ(c, s).
//! The DLEQ proves `key_image = x * Hp(O)` where `x = ho + b`, which
//! the verifier checks against the spent key image pool to confirm the
//! output is unspent.
//!
//! ```text
//! Wire format: reserve_proof_size(N) = 69 + 192*N bytes
//!   header: version[1] + schnorr[64] + output_count[4]
//!   per-output: ho[32] + y[32] + k_amount[32] + key_image[32] + dleq(c[32]+s[32])
//! ```
//!
//! Those two sizes are the sums of the fields, and [`reserve_proof_size`] is
//! the only length a proof can verify at. Opening refuses a declared count
//! other than the chain list before that length: the declared count does not
//! choose how long the proof must be.
//!
//! The verifier reads `enc_amount` from the blockchain, NOT from the proof.
//! This is load-bearing for soundness (see FCMP_PLUS_PLUS.md section 21).

#![deny(unsafe_code)]

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT as G_POINT,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};

use shekyl_curve_generators::T as T_LAZY;

use crate::dleq::{self, DleqProof};
use crate::error::ProofError;
use shekyl_crypto_pq::key_image::KeyImage;
use shekyl_crypto_pq::output::ProofSecrets;
use shekyl_crypto_pq::schnorr;
use shekyl_network::envelope::{Framed32, IdDomain};
use shekyl_network::NetworkId;

/// The reserve proof format's version, the proof's first byte. Version 3: the
/// Schnorr signs the envelope frame of the proof's fields under the network's
/// id ([`RESERVE_MESSAGE`]), each DLEQ binds the frame of its context
/// ([`RESERVE_DLEQ_CONTEXT`]), and the address bytes are the address alone
/// (the signing envelope §2.3). A proof of another version is refused as an
/// unsupported version.
pub const CURRENT_PROOF_VERSION: u8 = 3;

const RESERVE_DOMAIN: &[u8] = b"shekyl-reserve-proof-v1";

/// What a reserve proof's Schnorr signs: the envelope frame, bound to the
/// network's id, of `[address_bytes, user_message, per_output_data]` (the
/// signing envelope §2.3; NI-R15: proved against the chain, so the id).
pub const RESERVE_MESSAGE: IdDomain<3> = IdDomain::new(b"shekyl/reserve-proof-message-v1");

/// What each output's DLEQ binds as its context: the envelope frame, bound
/// to the network's id, of `[address_bytes, user_message, output_key]`.
pub const RESERVE_DLEQ_CONTEXT: IdDomain<3> =
    IdDomain::new(b"shekyl/reserve-proof-dleq-context-v1");

/// Width of one scalar or compressed point on this proof (`ho`, `y`,
/// `k_amount`, the key image). One width for the family; the record is
/// their concatenation plus the DLEQ.
const FIELD_LEN: usize = 32;

const VERSION_LEN: usize = 1;
const VERSION_AT: usize = 0;
const SIG_AT: usize = VERSION_AT + VERSION_LEN;
/// Little-endian `u32` width of the declared output count.
const OUTPUT_COUNT_LEN: usize = core::mem::size_of::<u32>();
const OUTPUT_COUNT_AT: usize = SIG_AT + schnorr::SIG_LEN;

const HO_LEN: usize = FIELD_LEN;
const HO_AT: usize = 0;
const Y_LEN: usize = FIELD_LEN;
const Y_AT: usize = HO_AT + HO_LEN;
const K_AMOUNT_LEN: usize = FIELD_LEN;
const K_AMOUNT_AT: usize = Y_AT + Y_LEN;
const KEY_IMAGE_LEN: usize = FIELD_LEN;
const KEY_IMAGE_AT: usize = K_AMOUNT_AT + K_AMOUNT_LEN;
const DLEQ_LEN: usize = DleqProof::SIZE;
const DLEQ_AT: usize = KEY_IMAGE_AT + KEY_IMAGE_LEN;

const PER_OUTPUT_SIZE: usize = HO_LEN + Y_LEN + K_AMOUNT_LEN + KEY_IMAGE_LEN + DLEQ_LEN;
const HEADER_SIZE: usize = VERSION_LEN + schnorr::SIG_LEN + OUTPUT_COUNT_LEN;

/// The published wire. The sums above are what the code uses; these pins
/// are the contract a field-width edit has to meet on purpose.
const PUBLISHED_HEADER_SIZE: usize = 69;
const PUBLISHED_PER_OUTPUT_SIZE: usize = 192;

const _: () = assert!(HEADER_SIZE == PUBLISHED_HEADER_SIZE);
const _: () = assert!(PER_OUTPUT_SIZE == PUBLISHED_PER_OUTPUT_SIZE);
const _: () = assert!(OUTPUT_COUNT_AT + OUTPUT_COUNT_LEN == HEADER_SIZE);
const _: () = assert!(DLEQ_AT + DLEQ_LEN == PER_OUTPUT_SIZE);
const _: () = assert!(OUTPUT_COUNT_LEN == 4);

/// Byte length of a reserve proof for `output_count` outputs.
///
/// The header plus one per-output record per output. This is the only
/// length a verifier accepts for a chain list of that length. The
/// generator and the opener both call it; neither re-derives the sum.
pub const fn reserve_proof_size(output_count: usize) -> usize {
    HEADER_SIZE + output_count * PER_OUTPUT_SIZE
}

// ── Per-output entry ────────────────────────────────────────────────

/// Input data for one output in a reserve proof (prover side).
///
/// Holds no bare secret of its own: `proof_secrets` is itself `ZeroizeOnDrop`
/// (wipes its HKDF scalars), and `key_image` / `output_key` are public
/// on-chain values (a key image is a published nullifier). A reserve proof's
/// spend authority is the *global* master key passed to
/// [`generate_reserve_proof`] as `spend_secret_key` (the prover derives
/// `x = ho + b` from it); there is no per-output spend secret. (A vestigial
/// per-output `spend_secret` field, which the prover never read, was removed
/// in the secret-hardening sweep along with the FFI `spend_secrets` parameter
/// that fed it.)
pub struct ReserveOutputEntry {
    pub proof_secrets: ProofSecrets,
    pub key_image: KeyImage,
    pub output_key: [u8; 32],
}

/// Per-output data from a verified reserve proof entry.
#[derive(Debug)]
pub struct VerifiedReserveOutput {
    pub output_index: usize,
    pub key_image: KeyImage,
    pub amount: u64,
}

fn write_per_output(
    ps: &ProofSecrets,
    key_image: &KeyImage,
    dleq_proof: &DleqProof,
    buf: &mut Vec<u8>,
) {
    let start = buf.len();
    buf.resize(start + PER_OUTPUT_SIZE, 0);
    let record = &mut buf[start..];
    record[HO_AT..Y_AT].copy_from_slice(&ps.ho);
    record[Y_AT..K_AMOUNT_AT].copy_from_slice(&ps.y);
    record[K_AMOUNT_AT..KEY_IMAGE_AT].copy_from_slice(&ps.k_amount);
    record[KEY_IMAGE_AT..DLEQ_AT].copy_from_slice(key_image.as_bytes());
    record[DLEQ_AT..PER_OUTPUT_SIZE].copy_from_slice(&dleq_proof.to_bytes());
}

// ── Schnorr ─────────────────────────────────────────────────────────
//
// Owned by `shekyl_crypto_pq::schnorr` (domain-parameterized). This file
// used to carry its own copy; see that module's docs for why one owner
// matters more than it looks — the hedged nonce reached only one of the
// three copies that existed.

fn assemble_proof_message(
    network_id: &NetworkId,
    address_bytes: &[u8],
    user_message: &[u8],
    per_output_data: &[u8],
) -> Framed32 {
    RESERVE_MESSAGE.frame(network_id, [address_bytes, user_message, per_output_data])
}

// ═══════════════════════════════════════════════════════════════════════
// Generate
// ═══════════════════════════════════════════════════════════════════════

/// Generate a reserve proof.
///
/// The prover signs with `spend_secret_key` (b). For each output, a DLEQ
/// proof is generated proving `key_image = (ho + b) * Hp(O)`.
///
/// # Arguments
/// - `spend_secret_key`: the wallet's spend secret key b (32 bytes)
/// - `address_bytes`: canonical encoding of the prover's address
/// - `user_message`: arbitrary user-supplied message string
/// - `entries`: per-output data including ProofSecrets, key_image, and output_key
#[allow(clippy::cast_possible_truncation)]
pub fn generate_reserve_proof(
    network_id: &NetworkId,
    spend_secret_key: &[u8; 32],
    address_bytes: &[u8],
    user_message: &[u8],
    entries: &[ReserveOutputEntry],
) -> Result<Vec<u8>, ProofError> {
    if entries.is_empty() {
        return Err(ProofError::InvalidFormat("no outputs specified".into()));
    }

    let b_scalar: Scalar = Option::from(Scalar::from_canonical_bytes(*spend_secret_key)).ok_or(
        ProofError::InvalidFormat("spend_secret_key not canonical".into()),
    )?;
    let b_point = b_scalar * G_POINT;

    let n = entries.len();
    let mut per_output_blob = Vec::with_capacity(n * PER_OUTPUT_SIZE);

    for entry in entries {
        let ho_scalar: Scalar = Option::from(Scalar::from_canonical_bytes(entry.proof_secrets.ho))
            .ok_or(ProofError::InvalidFormat("non-canonical ho".into()))?;

        let x = ho_scalar + b_scalar;

        let hp_of_o = shekyl_curve_generators::biased_hash_to_point(entry.output_key);

        let p = x * G_POINT; // P = x*G = O - y*T
        let ki_point = x * hp_of_o;

        let expected_ki = ki_point.compress().to_bytes();
        if &expected_ki != entry.key_image.as_bytes() {
            return Err(ProofError::VerificationFailed(
                "key_image does not match (ho+b)*Hp(O)".into(),
            ));
        }

        let dleq_msg =
            assemble_dleq_context(network_id, address_bytes, user_message, &entry.output_key);
        let dleq_proof = dleq::prove_dleq(&x, &hp_of_o, &p, &ki_point, &dleq_msg);

        write_per_output(
            &entry.proof_secrets,
            &entry.key_image,
            &dleq_proof,
            &mut per_output_blob,
        );
    }

    let message = assemble_proof_message(network_id, address_bytes, user_message, &per_output_blob);
    let sig = sign_reserve(&b_scalar, &b_point, &message);

    let mut proof = vec![0u8; reserve_proof_size(n)];
    proof[VERSION_AT] = CURRENT_PROOF_VERSION;
    proof[SIG_AT..OUTPUT_COUNT_AT].copy_from_slice(&sig);
    proof[OUTPUT_COUNT_AT..HEADER_SIZE].copy_from_slice(&(n as u32).to_le_bytes());
    proof[HEADER_SIZE..].copy_from_slice(&per_output_blob);

    Ok(proof)
}

/// Sign a reserve proof's frame under [`RESERVE_DOMAIN`].
///
/// The domain lives here, beside the [`Framed32`] it signs, so a caller
/// cannot apply it to bytes it assembled itself.
fn sign_reserve(
    secret: &Scalar,
    public: &EdwardsPoint,
    message: &Framed32,
) -> [u8; schnorr::SIG_LEN] {
    schnorr::sign(RESERVE_DOMAIN, secret, public, message.as_bytes())
}

/// Whether `signature` holds for a reserve proof's frame under
/// [`RESERVE_DOMAIN`].
fn reserve_holds(
    public: &EdwardsPoint,
    message: &Framed32,
    signature: &[u8; schnorr::SIG_LEN],
) -> bool {
    schnorr::verify(RESERVE_DOMAIN, public, message.as_bytes(), signature)
}

fn assemble_dleq_context(
    network_id: &NetworkId,
    address_bytes: &[u8],
    user_message: &[u8],
    output_key: &[u8; 32],
) -> Framed32 {
    RESERVE_DLEQ_CONTEXT.frame(network_id, [address_bytes, user_message, output_key])
}

// ═══════════════════════════════════════════════════════════════════════
// Verify
// ═══════════════════════════════════════════════════════════════════════

/// On-chain data the verifier fetches for each output in a reserve proof.
///
/// `enc_amount` MUST come from the blockchain, NOT from the proof itself.
pub struct ReserveOnChainOutput {
    pub output_key: [u8; 32],
    pub commitment: [u8; 32],
    pub enc_amount: [u8; 8],
}

/// One per-output record, split at the field offsets the writer used.
struct OutputWire {
    ho: [u8; HO_LEN],
    y: [u8; Y_LEN],
    k_amount: [u8; K_AMOUNT_LEN],
    key_image: [u8; KEY_IMAGE_LEN],
    dleq: [u8; DLEQ_LEN],
}

impl OutputWire {
    fn read(record: &[u8]) -> Self {
        Self {
            ho: read_at(record, HO_AT),
            y: read_at(record, Y_AT),
            k_amount: read_at(record, K_AMOUNT_AT),
            key_image: read_at(record, KEY_IMAGE_AT),
            dleq: read_at(record, DLEQ_AT),
        }
    }
}

fn read_at<const N: usize>(bytes: &[u8], at: usize) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[at..at + N]);
    out
}

/// The count field of a proof whose header is already known to be present.
fn declared_output_count(proof_bytes: &[u8]) -> usize {
    let mut raw = [0u8; OUTPUT_COUNT_LEN];
    raw.copy_from_slice(&proof_bytes[OUTPUT_COUNT_AT..HEADER_SIZE]);
    u32::from_le_bytes(raw) as usize
}

/// A reserve proof opened against a chain list of a known length.
///
/// Constructing one is the format refusal. The signature and the body are
/// then what the cryptographic checks read, and a body shorter than one
/// record per chain output cannot be represented here.
struct OpenedReserveProof<'a> {
    signature: [u8; schnorr::SIG_LEN],
    body: &'a [u8],
}

impl<'a> OpenedReserveProof<'a> {
    /// Refuse a declared count other than `chain_count` before the byte length.
    ///
    /// The only length that can verify is [`reserve_proof_size`] of the
    /// chain list. The declared count does not choose that length. Reserve
    /// proofs compare with equality, so a length derived from the declared
    /// count is a second predicate a short proof can satisfy on its own
    /// (a header whose count is zero) and then never leave.
    fn open(proof_bytes: &'a [u8], chain_count: usize) -> Result<Self, ProofError> {
        if proof_bytes.len() < HEADER_SIZE {
            return Err(ProofError::InvalidFormat(
                "proof too short for header".into(),
            ));
        }

        let version = proof_bytes[VERSION_AT];
        if version != CURRENT_PROOF_VERSION {
            return Err(ProofError::InvalidFormat(format!(
                "unsupported proof version {version}, expected {CURRENT_PROOF_VERSION}"
            )));
        }

        let declared_count = declared_output_count(proof_bytes);
        if declared_count != chain_count {
            return Err(ProofError::InvalidFormat(format!(
                "proof has {declared_count} outputs but {chain_count} on-chain outputs provided"
            )));
        }

        let expected_len = reserve_proof_size(chain_count);
        if proof_bytes.len() != expected_len {
            return Err(ProofError::InvalidFormat(format!(
                "proof length {}, expected {expected_len} for {declared_count} outputs",
                proof_bytes.len(),
            )));
        }

        let mut signature = [0u8; schnorr::SIG_LEN];
        signature.copy_from_slice(&proof_bytes[SIG_AT..OUTPUT_COUNT_AT]);
        Ok(Self {
            signature,
            body: &proof_bytes[HEADER_SIZE..],
        })
    }

    fn record(&self, index: usize) -> &[u8] {
        let start = index * PER_OUTPUT_SIZE;
        let end = start + PER_OUTPUT_SIZE;
        debug_assert!(
            end <= self.body.len(),
            "open() returns one record per chain output"
        );
        &self.body[start..end]
    }
}

/// Verify a reserve proof.
///
/// Returns per-output verification results including key images and
/// decrypted amounts. The caller is responsible for checking each
/// key_image against the spent pool.
///
/// Format refusal happens while the proof is opened against the chain
/// list's length, before the signature or any DLEQ.
///
/// # Arguments
/// - `proof_bytes`: the serialized proof blob
/// - `address_bytes`: canonical encoding of the prover's address
/// - `user_message`: arbitrary user-supplied message string
/// - `spend_pubkey`: B (32 bytes, the prover's spend public key)
/// - `on_chain_outputs`: per-output data fetched from the blockchain
pub fn verify_reserve_proof(
    network_id: &NetworkId,
    proof_bytes: &[u8],
    address_bytes: &[u8],
    user_message: &[u8],
    spend_pubkey: &[u8; 32],
    on_chain_outputs: &[ReserveOnChainOutput],
) -> Result<Vec<VerifiedReserveOutput>, ProofError> {
    let opened = OpenedReserveProof::open(proof_bytes, on_chain_outputs.len())?;

    let b_point = CompressedEdwardsY(*spend_pubkey)
        .decompress()
        .ok_or(ProofError::InvalidFormat("invalid spend pubkey".into()))?;

    let message = assemble_proof_message(network_id, address_bytes, user_message, opened.body);

    if !reserve_holds(&b_point, &message, &opened.signature) {
        return Err(ProofError::SignatureFailed);
    }

    let mut results = Vec::with_capacity(on_chain_outputs.len());

    for (i, on_chain) in on_chain_outputs.iter().enumerate() {
        let wire = OutputWire::read(opened.record(i));

        let ho_scalar: Scalar = Option::from(Scalar::from_canonical_bytes(wire.ho)).ok_or(
            ProofError::InvalidFormat(format!("non-canonical ho at output {i}")),
        )?;
        let y_scalar: Scalar = Option::from(Scalar::from_canonical_bytes(wire.y)).ok_or(
            ProofError::InvalidFormat(format!("non-canonical y at output {i}")),
        )?;

        let expected_o = ho_scalar * G_POINT + b_point + y_scalar * *T_LAZY;
        let on_chain_o = CompressedEdwardsY(on_chain.output_key).decompress().ok_or(
            ProofError::InvalidFormat(format!("invalid on-chain output key at index {i}")),
        )?;

        if expected_o != on_chain_o {
            return Err(ProofError::OutputKeyMismatch { index: i });
        }

        let hp_of_o = shekyl_curve_generators::biased_hash_to_point(on_chain.output_key);

        // P = O - y*T = (ho + b)*G = x*G
        let p = expected_o - y_scalar * *T_LAZY;

        let ki_point =
            CompressedEdwardsY(wire.key_image)
                .decompress()
                .ok_or(ProofError::InvalidFormat(format!(
                    "invalid key image at index {i}"
                )))?;

        let dleq_proof = DleqProof::from_bytes(&wire.dleq);
        let dleq_msg = assemble_dleq_context(
            network_id,
            address_bytes,
            user_message,
            &on_chain.output_key,
        );

        if !dleq::verify_dleq(&hp_of_o, &p, &ki_point, &dleq_msg, &dleq_proof) {
            return Err(ProofError::VerificationFailed(format!(
                "DLEQ verification failed at output {i}: key_image != x*Hp(O)"
            )));
        }

        let mut amount_bytes = on_chain.enc_amount;
        for (masked, mask) in amount_bytes.iter_mut().zip(wire.k_amount) {
            *masked ^= mask;
        }
        let amount = u64::from_le_bytes(amount_bytes);

        results.push(VerifiedReserveOutput {
            output_index: i,
            key_image: KeyImage::from_canonical_bytes(wire.key_image),
            amount,
        });
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use shekyl_network::Network;

    use super::*;

    fn one_output() -> [ReserveOnChainOutput; 1] {
        [ReserveOnChainOutput {
            output_key: [0u8; FIELD_LEN],
            commitment: [0u8; FIELD_LEN],
            enc_amount: [0u8; 8],
        }]
    }

    /// The format error `verify_reserve_proof` returns. These refusals all
    /// happen before the signature, so the network id is not consulted;
    /// testnet is the id the round-trip proofs are made under.
    fn format_error(proof: &[u8], on_chain: &[ReserveOnChainOutput]) -> String {
        verify_reserve_proof(
            &Network::Testnet.network_id(),
            proof,
            b"addr",
            b"msg",
            &[0u8; FIELD_LEN],
            on_chain,
        )
        .expect_err("format refusal happens before the signature")
        .to_string()
    }

    fn header_claiming(count: u32) -> Vec<u8> {
        let mut header = vec![0u8; HEADER_SIZE];
        header[VERSION_AT] = CURRENT_PROOF_VERSION;
        header[OUTPUT_COUNT_AT..HEADER_SIZE].copy_from_slice(&count.to_le_bytes());
        header
    }

    /// This bites a swapped refusal order: a header whose declared count is
    /// not the chain list is refused for the count, even though its bytes
    /// are also the wrong length.
    ///
    /// It does NOT cover a body whose length is `reserve_proof_size` of a
    /// lying count, and it does NOT cover a matching count with a short
    /// body. Those are the two tests below.
    #[test]
    fn a_header_whose_count_is_not_the_chain_list_is_refused_for_the_count() {
        let text = format_error(&header_claiming(99), &one_output());
        assert_eq!(
            text,
            "invalid proof format: proof has 99 outputs but 1 on-chain outputs provided"
        );
    }

    /// This bites deletion of the length refusal on the path that would
    /// otherwise slice a per-output record past the header. A declared
    /// count equal to the chain list, and a body shorter than one record,
    /// is refused for its length.
    ///
    /// It does NOT cover the count refusal, and it does NOT by itself keep
    /// the two checks in order: with the count already equal, either order
    /// names the length.
    #[test]
    fn a_matching_count_with_a_short_body_is_refused_for_its_length() {
        let text = format_error(&header_claiming(1), &one_output());
        let expected = reserve_proof_size(1);
        assert_eq!(
            text,
            format!(
                "invalid proof format: proof length {HEADER_SIZE}, expected {expected} for 1 outputs"
            )
        );
    }

    /// This bites a count check that only runs for a short header. A proof
    /// whose length is `reserve_proof_size` of its declared count, and whose
    /// declared count is not the chain list, is refused for the count and
    /// does not reach the signature.
    ///
    /// It does NOT cover a swapped order. Both orders refuse this proof for
    /// the count, because the length matches the lie. It does NOT cover the
    /// signature or the per-output checks: the body is zeros.
    #[test]
    fn a_well_sized_lie_is_refused_for_the_count() {
        let mut proof = vec![0u8; reserve_proof_size(2)];
        proof[VERSION_AT] = CURRENT_PROOF_VERSION;
        proof[OUTPUT_COUNT_AT..HEADER_SIZE].copy_from_slice(&2u32.to_le_bytes());
        let text = format_error(&proof, &one_output());
        assert_eq!(
            text,
            "invalid proof format: proof has 2 outputs but 1 on-chain outputs provided"
        );
    }
}
