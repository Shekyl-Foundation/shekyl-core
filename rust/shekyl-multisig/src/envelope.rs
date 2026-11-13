// Copyright (c) 2026, The Shekyl Foundation
// All rights reserved. BSD-3-Clause

//! A ceremony file: what one member hands another (R-9, R-10, R-6;
//! `SHEKYL_MULTISIG_WIRE_FORMAT.md` §1, §4).
//!
//! ```text
//! file      = format_version(1) ‖ nonce(24) ‖ ciphertext ‖ tag(16)      (shekyl_crypto_pq::multisig_blob)
//! plaintext = address_fingerprint(32) ‖ intent_hash(32) ‖ sender_index(1) ‖ message_type(1)
//!             ‖ u32_le(body_len) ‖ body ‖ u32_le(sig_len) ‖ sender_sig
//! ```
//!
//! Only the format version is in the clear. The sender's signature is its
//! envelope key's over every other plaintext field, framed with the network
//! id (`shekyl_crypto_pq::multisig_envelope`), so a member who holds the
//! group transport secret still cannot write a file "from" another member.
//!
//! **Import is trial decryption.** A wallet tries each of its groups;
//! a file that opens under none is "not for this wallet". A file that opens
//! is then checked in this order, each failure a named refusal, and its body
//! reaches nothing before every check has passed:
//!
//! 1. the plaintext parses exactly, every length bounded before it is read;
//! 2. the fingerprint is that group's;
//! 3. the sender index names a member;
//! 4. the sender's signature verifies under that member's envelope key;
//! 5. the message type is assigned.

use rand::{CryptoRng, RngCore};
use shekyl_address::multisig_address::address_fingerprint;
use shekyl_crypto_pq::multisig_blob::{check_blob_version, open_blob, seal_blob, BlobError};
use shekyl_crypto_pq::multisig_envelope::{
    envelope_message, sign_multisig_envelope, verify_multisig_envelope, EnvelopeFields,
};
use shekyl_crypto_pq::signature::HybridSignature;
use shekyl_network::NetworkId;
use zeroize::Zeroizing;

use crate::member_file::MemberFile;
use crate::messages::MessageType;

/// Bytes of the plaintext header: fingerprint, intent hash, sender, type.
pub const PLAINTEXT_HEADER_LEN: usize = 32 + 32 + 1 + 1;

/// The largest body a file carries (1 MiB): above any transaction or
/// preprocess set a ceremony moves, and bounded before it is read.
pub const MAX_BODY_LEN: usize = 1 << 20;

/// The sender signature's exact length: one canonical hybrid signature.
pub const SENDER_SIG_LEN: usize = HybridSignature::CANONICAL_LEN;

const LEN_PREFIX: usize = 4;

/// Why a file could not be written.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SealError {
    /// The body is longer than [`MAX_BODY_LEN`].
    #[error("a ceremony body of {0} bytes exceeds {MAX_BODY_LEN}")]
    BodyTooLong(usize),
    /// The envelope key could not sign.
    #[error("the envelope signature could not be made")]
    Sign,
    /// The AEAD refused to seal.
    #[error("the file could not be sealed")]
    Seal,
}

/// Why an imported file was refused. Each names one check; none of them
/// says more about the file than that check's verdict.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ImportRefusal {
    /// Too short to be a ceremony file.
    #[error("not a ceremony file")]
    Truncated,
    /// A version-1 file, the clear-header layout nothing shipped.
    #[error("a version-1 ceremony file is not accepted")]
    ClearHeaderVersion,
    /// A format version this build does not know.
    #[error("unknown ceremony file version {0}")]
    UnknownVersion(u8),
    /// The file opens under none of this wallet's groups.
    #[error("the file is not for any group in this wallet")]
    NotForThisWallet,
    /// The plaintext does not parse exactly.
    #[error("the file's contents are malformed")]
    Malformed,
    /// The file opens under a group's key but names another group.
    #[error("the file names another group")]
    ForeignFingerprint,
    /// The sender index names no member of the group.
    #[error("sender index {sender} is not a member of a {n}-member group")]
    SenderOutOfRange { sender: u8, n: u8 },
    /// The sender signature is not that member's over this file.
    #[error("the file is not signed by the member it names")]
    BadSignature,
    /// The signature verified, but the message type is not assigned.
    #[error("unknown message type {0:#04x}")]
    UnknownMessageType(u8),
}

/// A file that passed every check.
#[derive(Debug)]
pub struct OpenedEnvelope {
    /// Which of the caller's groups the file is for: an index into the
    /// slice [`open_envelope`] was given.
    pub group: usize,
    /// The intent the file belongs to.
    pub intent_hash: [u8; 32],
    /// The member who sent it, its signature verified.
    pub sender_index: u8,
    /// The ceremony step.
    pub message_type: MessageType,
    /// The body. It may carry FROST material, so it is wiped on drop.
    pub body: Zeroizing<Vec<u8>>,
}

/// A parsed plaintext, before any check but its shape.
struct Plaintext<'a> {
    address_fingerprint: &'a [u8; 32],
    intent_hash: &'a [u8; 32],
    sender_index: u8,
    message_type: u8,
    body: &'a [u8],
    sender_sig: &'a [u8],
}

impl<'a> Plaintext<'a> {
    fn fields(&self) -> EnvelopeFields<'a> {
        EnvelopeFields {
            address_fingerprint: self.address_fingerprint,
            intent_hash: self.intent_hash,
            sender_index: self.sender_index,
            message_type: self.message_type,
            body: self.body,
        }
    }
}

/// Split `bytes` at `n`, or `None` if it is shorter.
fn take<'a>(bytes: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    if bytes.len() < n {
        return None;
    }
    let (head, rest) = bytes.split_at(n);
    *bytes = rest;
    Some(head)
}

fn take_len(bytes: &mut &[u8]) -> Option<usize> {
    let raw: [u8; LEN_PREFIX] = take(bytes, LEN_PREFIX)?.try_into().ok()?;
    usize::try_from(u32::from_le_bytes(raw)).ok()
}

/// Parse a plaintext exactly: the header, a body no longer than
/// [`MAX_BODY_LEN`] and no longer than what follows, and a signature of
/// exactly [`SENDER_SIG_LEN`] bytes that ends the plaintext. Never panics;
/// `None` for any other shape.
fn parse_plaintext(mut bytes: &[u8]) -> Option<Plaintext<'_>> {
    let address_fingerprint = take(&mut bytes, 32)?.try_into().ok()?;
    let intent_hash = take(&mut bytes, 32)?.try_into().ok()?;
    let sender_index = take(&mut bytes, 1)?[0];
    let message_type = take(&mut bytes, 1)?[0];
    let body_len = take_len(&mut bytes)?;
    if body_len > MAX_BODY_LEN {
        return None;
    }
    let body = take(&mut bytes, body_len)?;
    if take_len(&mut bytes)? != SENDER_SIG_LEN {
        return None;
    }
    let sender_sig = take(&mut bytes, SENDER_SIG_LEN)?;
    if !bytes.is_empty() {
        return None;
    }
    Some(Plaintext {
        address_fingerprint,
        intent_hash,
        sender_index,
        message_type,
        body,
        sender_sig,
    })
}

/// Whether `bytes` parse as a plaintext. The fuzz target's entry point
/// (`fuzz_envelope_v2_decode`); production reaches the parser through
/// [`open_envelope`] only.
#[doc(hidden)]
#[must_use]
pub fn plaintext_parses(bytes: &[u8]) -> bool {
    parse_plaintext(bytes).is_some()
}

/// Write a ceremony file as `member`: sign the fields with its envelope
/// key, lay out the plaintext, and seal it under the group's key.
///
/// # Errors
///
/// [`SealError::BodyTooLong`] for a body over [`MAX_BODY_LEN`];
/// [`SealError::Sign`] or [`SealError::Seal`] if crypto-pq refuses.
pub fn seal_envelope(
    member: &MemberFile,
    network_id: &NetworkId,
    intent_hash: &[u8; 32],
    message_type: MessageType,
    body: &[u8],
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Vec<u8>, SealError> {
    if body.len() > MAX_BODY_LEN {
        return Err(SealError::BodyTooLong(body.len()));
    }
    let fingerprint = address_fingerprint(member.address());
    let fields = EnvelopeFields {
        address_fingerprint: &fingerprint,
        intent_hash,
        sender_index: member.member_index(),
        message_type: message_type as u8,
        body,
    };
    let sig = sign_multisig_envelope(
        member.envelope_secret(),
        &envelope_message(network_id, &fields),
    )
    .and_then(|sig| sig.to_canonical_bytes())
    .map_err(|_| SealError::Sign)?;
    debug_assert_eq!(sig.len(), SENDER_SIG_LEN);
    let plaintext = encode_plaintext(&fields, &sig);
    seal_blob(member.transport_secret(), &plaintext, rng).map_err(|_| SealError::Seal)
}

/// The plaintext layout, the inverse of [`parse_plaintext`]. Secret-bearing
/// (the body), so returned wiped-on-drop.
fn encode_plaintext(fields: &EnvelopeFields<'_>, sender_sig: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut plaintext = Zeroizing::new(Vec::with_capacity(
        PLAINTEXT_HEADER_LEN + 2 * LEN_PREFIX + fields.body.len() + sender_sig.len(),
    ));
    plaintext.extend_from_slice(fields.address_fingerprint);
    plaintext.extend_from_slice(fields.intent_hash);
    plaintext.push(fields.sender_index);
    plaintext.push(fields.message_type);
    plaintext.extend_from_slice(&len_prefix(fields.body.len()));
    plaintext.extend_from_slice(fields.body);
    plaintext.extend_from_slice(&len_prefix(sender_sig.len()));
    plaintext.extend_from_slice(sender_sig);
    plaintext
}

fn len_prefix(len: usize) -> [u8; LEN_PREFIX] {
    u32::try_from(len)
        .expect("bounded by MAX_BODY_LEN or a signature's length")
        .to_le_bytes()
}

/// Import a ceremony file into a wallet whose groups are `groups` (each
/// given by this wallet's member file for it).
///
/// # Errors
///
/// An [`ImportRefusal`], in the module doc's check order.
pub fn open_envelope(
    groups: &[&MemberFile],
    network_id: &NetworkId,
    file: &[u8],
) -> Result<OpenedEnvelope, ImportRefusal> {
    check_blob_version(file).map_err(|e| match e {
        BlobError::ClearHeaderVersion => ImportRefusal::ClearHeaderVersion,
        BlobError::UnknownVersion(v) => ImportRefusal::UnknownVersion(v),
        _ => ImportRefusal::Truncated,
    })?;
    let (group, plaintext) = groups
        .iter()
        .enumerate()
        .find_map(|(i, member)| {
            open_blob(member.transport_secret(), file)
                .ok()
                .map(|plaintext| (i, plaintext))
        })
        .ok_or(ImportRefusal::NotForThisWallet)?;
    let member = groups[group];

    let parsed = parse_plaintext(&plaintext).ok_or(ImportRefusal::Malformed)?;
    if *parsed.address_fingerprint != address_fingerprint(member.address()) {
        return Err(ImportRefusal::ForeignFingerprint);
    }
    let n = member.address().n_total();
    let sender_key = member
        .envelope_public_keys()
        .get(usize::from(parsed.sender_index))
        .ok_or(ImportRefusal::SenderOutOfRange {
            sender: parsed.sender_index,
            n,
        })?;
    let sig = HybridSignature::from_canonical_bytes(parsed.sender_sig)
        .map_err(|_| ImportRefusal::BadSignature)?;
    verify_multisig_envelope(
        sender_key,
        &envelope_message(network_id, &parsed.fields()),
        &sig,
    )
    .map_err(|_| ImportRefusal::BadSignature)?;
    let message_type = MessageType::from_u8(parsed.message_type)
        .ok_or(ImportRefusal::UnknownMessageType(parsed.message_type))?;

    Ok(OpenedEnvelope {
        group,
        intent_hash: *parsed.intent_hash,
        sender_index: parsed.sender_index,
        message_type,
        body: Zeroizing::new(parsed.body.to_vec()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::member_file::{MemberSecrets, HYBRID_KEM_SECRET_LEN};
    use rand::rngs::OsRng;
    use shekyl_address::multisig_address::{MultisigAddressPayload, HYBRID_KEM_PUBKEY_LEN};
    use shekyl_address::Network;
    use shekyl_crypto_pq::multisig_blob::BLOB_VERSION_LEN;
    use shekyl_crypto_pq::multisig_envelope::{
        mint_multisig_envelope_keypair, MultisigEnvelopeSecret,
    };

    const NET: NetworkId = [0x4E; 16];
    const INTENT: [u8; 32] = [0x1D; 32];

    /// Every member's file of a new `n`-member group. `tag` sets the group's
    /// spend point and transport secret, so two tags are two groups.
    fn group(n: u8, tag: u8) -> Vec<MemberFile> {
        let address = MultisigAddressPayload::new(
            Network::Testnet,
            n,
            2,
            [tag; 32],
            [0x71; 32],
            vec![0x40; HYBRID_KEM_PUBKEY_LEN],
            (0..n).map(|i| vec![i; HYBRID_KEM_PUBKEY_LEN]).collect(),
        )
        .unwrap();
        let keys: Vec<_> = (0..n)
            .map(|_| mint_multisig_envelope_keypair(&mut OsRng).unwrap())
            .collect();
        let publics: Vec<_> = keys.iter().map(|(pk, _)| pk.clone()).collect();
        (0u8..)
            .zip(keys)
            .map(|(i, (_, envelope_secret))| {
                MemberFile::new(
                    address.clone(),
                    i,
                    (0..n).map(|j| [0x50 + j; 32]).collect(),
                    publics.clone(),
                    MemberSecrets {
                        b: Zeroizing::new([0x0B; 32]),
                        y_share: Zeroizing::new([0x0F; 32]),
                        group_kem_secret: Zeroizing::new(vec![0x6A; HYBRID_KEM_SECRET_LEN]),
                        member_kem_secret: Zeroizing::new(vec![0x6B; HYBRID_KEM_SECRET_LEN]),
                        transport_secret: Zeroizing::new([tag; 32]),
                        envelope_secret,
                    },
                )
                .unwrap()
            })
            .collect()
    }

    fn seal(member: &MemberFile, message_type: MessageType, body: &[u8]) -> Vec<u8> {
        seal_envelope(member, &NET, &INTENT, message_type, body, &mut OsRng).unwrap()
    }

    /// A file sealed under `transport` from arbitrary fields, signed by
    /// `signer`: what an insider holding the transport secret can write.
    fn craft(
        transport: &[u8; 32],
        fields: &EnvelopeFields<'_>,
        signer: &MultisigEnvelopeSecret,
    ) -> Vec<u8> {
        let sig = sign_multisig_envelope(signer, &envelope_message(&NET, fields))
            .unwrap()
            .to_canonical_bytes()
            .unwrap();
        seal_blob(transport, &encode_plaintext(fields, &sig), &mut OsRng).unwrap()
    }

    fn fields<'a>(
        member: &MemberFile,
        fingerprint: &'a [u8; 32],
        sender: u8,
        body: &'a [u8],
    ) -> EnvelopeFields<'a> {
        let _ = member;
        EnvelopeFields {
            address_fingerprint: fingerprint,
            intent_hash: &INTENT,
            sender_index: sender,
            message_type: MessageType::Proposal as u8,
            body,
        }
    }

    #[test]
    fn every_message_type_round_trips() {
        let members = group(3, 0xA1);
        for t in MessageType::ALL {
            let body = [t as u8; 300];
            let file = seal(&members[1], t, &body);
            let opened = open_envelope(&[&members[2]], &NET, &file).unwrap();
            assert_eq!(opened.group, 0);
            assert_eq!(opened.intent_hash, INTENT);
            assert_eq!(opened.sender_index, 1);
            assert_eq!(opened.message_type, t);
            assert_eq!(opened.body.as_slice(), body);
        }
    }

    /// Trial decryption: among a wallet's groups the file opens under its
    /// own, and a file for none of them is "not for this wallet".
    #[test]
    fn trial_decryption_finds_the_group_and_refuses_a_foreign_file() {
        let a = group(2, 0xA1);
        let b = group(3, 0xB2);
        let c = group(2, 0xC3);
        let file = seal(&b[0], MessageType::Commitment, b"for b");
        let opened = open_envelope(&[&a[1], &b[2], &c[0]], &NET, &file).unwrap();
        assert_eq!(opened.group, 1);
        assert_eq!(opened.body.as_slice(), b"for b");
        assert_eq!(
            open_envelope(&[&a[1], &c[0]], &NET, &file).unwrap_err(),
            ImportRefusal::NotForThisWallet
        );
    }

    #[test]
    fn a_version_one_or_unknown_file_is_refused_by_name() {
        let members = group(2, 0xA1);
        let mut file = seal(&members[0], MessageType::Proposal, b"x");
        file[0] = 1;
        assert_eq!(
            open_envelope(&[&members[1]], &NET, &file).unwrap_err(),
            ImportRefusal::ClearHeaderVersion
        );
        file[0] = 9;
        assert_eq!(
            open_envelope(&[&members[1]], &NET, &file).unwrap_err(),
            ImportRefusal::UnknownVersion(9)
        );
        assert_eq!(
            open_envelope(&[&members[1]], &NET, &file[..10]).unwrap_err(),
            ImportRefusal::Truncated
        );
    }

    #[test]
    fn an_edited_ciphertext_is_for_no_group() {
        let members = group(2, 0xA1);
        let mut file = seal(&members[0], MessageType::Proposal, b"x");
        let mid = file.len() / 2;
        file[mid] ^= 1;
        assert_eq!(
            open_envelope(&[&members[1]], &NET, &file).unwrap_err(),
            ImportRefusal::NotForThisWallet
        );
    }

    /// A file under group A's key that names group B is refused, even
    /// signed by a real member of A.
    #[test]
    fn another_groups_fingerprint_under_this_groups_key_is_refused() {
        let a = group(2, 0xA1);
        let b = group(2, 0xB2);
        let foreign = address_fingerprint(b[0].address());
        let file = craft(
            a[0].transport_secret(),
            &fields(&a[0], &foreign, 0, b"x"),
            a[0].envelope_secret(),
        );
        assert_eq!(
            open_envelope(&[&a[1]], &NET, &file).unwrap_err(),
            ImportRefusal::ForeignFingerprint
        );
    }

    #[test]
    fn a_sender_index_outside_the_group_is_refused() {
        let members = group(3, 0xA1);
        let fp = address_fingerprint(members[0].address());
        let file = craft(
            members[0].transport_secret(),
            &fields(&members[0], &fp, 3, b"x"),
            members[0].envelope_secret(),
        );
        assert_eq!(
            open_envelope(&[&members[1]], &NET, &file).unwrap_err(),
            ImportRefusal::SenderOutOfRange { sender: 3, n: 3 }
        );
    }

    /// The R-6 adversary: member 2 holds the transport secret and its own
    /// envelope key, and writes a `Proposal` claiming to be member 0. The
    /// file opens and parses; the signature refuses it.
    #[test]
    fn a_member_cannot_write_a_file_as_another_member() {
        let members = group(3, 0xA1);
        let fp = address_fingerprint(members[0].address());
        let forged = craft(
            members[2].transport_secret(),
            &fields(&members[2], &fp, 0, b"a proposal member 0 never made"),
            members[2].envelope_secret(),
        );
        assert_eq!(
            open_envelope(&[&members[1]], &NET, &forged).unwrap_err(),
            ImportRefusal::BadSignature
        );
        // The same file, honestly attributed, is accepted.
        let honest = craft(
            members[2].transport_secret(),
            &fields(&members[2], &fp, 2, b"a proposal member 0 never made"),
            members[2].envelope_secret(),
        );
        assert_eq!(
            open_envelope(&[&members[1]], &NET, &honest)
                .unwrap()
                .sender_index,
            2
        );
    }

    /// A valid file whose body is edited after signing and re-sealed by an
    /// insider is refused at the signature.
    #[test]
    fn a_body_edited_after_signing_is_refused() {
        let members = group(2, 0xA1);
        let file = seal(&members[0], MessageType::SigningSet, b"the set");
        let mut plaintext = open_blob(members[1].transport_secret(), &file).unwrap();
        let body_at = PLAINTEXT_HEADER_LEN + LEN_PREFIX;
        plaintext[body_at] ^= 1;
        let resealed = seal_blob(members[1].transport_secret(), &plaintext, &mut OsRng).unwrap();
        assert_eq!(
            open_envelope(&[&members[1]], &NET, &resealed).unwrap_err(),
            ImportRefusal::BadSignature
        );
    }

    /// Signed on one network, imported on another: refused.
    #[test]
    fn a_file_is_bound_to_its_network() {
        let members = group(2, 0xA1);
        let file = seal(&members[0], MessageType::Proposal, b"x");
        assert_eq!(
            open_envelope(&[&members[1]], &[0x4F; 16], &file).unwrap_err(),
            ImportRefusal::BadSignature
        );
    }

    /// An unassigned type is refused after the signature, by its value.
    #[test]
    fn an_unassigned_message_type_is_refused_by_value() {
        let members = group(2, 0xA1);
        let fp = address_fingerprint(members[0].address());
        let mut f = fields(&members[0], &fp, 0, b"x");
        f.message_type = 0x08;
        let file = craft(
            members[0].transport_secret(),
            &f,
            members[0].envelope_secret(),
        );
        assert_eq!(
            open_envelope(&[&members[1]], &NET, &file).unwrap_err(),
            ImportRefusal::UnknownMessageType(0x08)
        );
    }

    /// Every length is checked: a body longer than what follows, a body over
    /// the cap, a signature of the wrong length, and trailing bytes each
    /// refuse the plaintext as malformed; the honest layout parses.
    #[test]
    fn the_plaintext_parses_exactly() {
        let fp = [0x22; 32];
        let f = EnvelopeFields {
            address_fingerprint: &fp,
            intent_hash: &INTENT,
            sender_index: 0,
            message_type: 0x0C,
            body: b"body",
        };
        let honest = encode_plaintext(&f, &[0; SENDER_SIG_LEN]);
        assert!(plaintext_parses(&honest));
        let body_len_at = PLAINTEXT_HEADER_LEN;
        let mut long_body = honest.to_vec();
        long_body[body_len_at..body_len_at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(!plaintext_parses(&long_body));
        let mut over_cap = honest.to_vec();
        over_cap[body_len_at..body_len_at + 4]
            .copy_from_slice(&u32::try_from(MAX_BODY_LEN + 1).unwrap().to_le_bytes());
        assert!(!plaintext_parses(&over_cap));
        assert!(!plaintext_parses(&encode_plaintext(
            &f,
            &[0; SENDER_SIG_LEN - 1]
        )));
        let mut trailing = honest.to_vec();
        trailing.push(0);
        assert!(!plaintext_parses(&trailing));
        for cut in [0, PLAINTEXT_HEADER_LEN, honest.len() - 1] {
            assert!(!plaintext_parses(&honest[..cut]), "cut {cut}");
        }
        assert_eq!(
            seal_envelope(
                &group(2, 0xA1)[0],
                &NET,
                &INTENT,
                MessageType::FinalTx,
                &vec![0; MAX_BODY_LEN + 1],
                &mut OsRng
            )
            .unwrap_err(),
            SealError::BodyTooLong(MAX_BODY_LEN + 1)
        );
    }

    /// What a file shows: its version byte and its size. Two files sealed
    /// from the same plaintext share no aligned 8-byte window after the
    /// version (a chance match is 2^-64 per window), and neither contains
    /// the fingerprint, the intent hash, or the plaintext header's 66
    /// bytes. A one-byte field such as the sender index cannot be tested
    /// as a substring: some byte of any file equals it.
    #[test]
    fn a_file_shows_nothing_but_its_version_and_size() {
        let members = group(3, 0xA1);
        let fp = address_fingerprint(members[0].address());
        let fixed = fields(&members[1], &fp, 1, &[0x44; 256]);
        let sig = sign_multisig_envelope(
            members[1].envelope_secret(),
            &envelope_message(&NET, &fixed),
        )
        .unwrap()
        .to_canonical_bytes()
        .unwrap();
        let plaintext = encode_plaintext(&fixed, &sig);
        let a = seal_blob(members[1].transport_secret(), &plaintext, &mut OsRng).unwrap();
        let b = seal_blob(members[1].transport_secret(), &plaintext, &mut OsRng).unwrap();
        assert_eq!(a.len(), b.len());
        for (wa, wb) in a[BLOB_VERSION_LEN..]
            .chunks_exact(8)
            .zip(b[BLOB_VERSION_LEN..].chunks_exact(8))
        {
            assert_ne!(wa, wb);
        }
        let contains = |hay: &[u8], needle: &[u8]| hay.windows(needle.len()).any(|w| w == needle);
        for file in [&a, &b] {
            assert!(!contains(file, &fp));
            assert!(!contains(file, &INTENT));
            assert!(!contains(file, &plaintext[..PLAINTEXT_HEADER_LEN]));
        }
    }
}
