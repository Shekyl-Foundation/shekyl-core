// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! M-of-N PQC multisig (Option E′): the key blob, the signature blob, and
//! their verification.
//!
//! Both blobs ride in the ordinary `pqc_auth` fields (`hybrid_public_key`,
//! `hybrid_signature`) with `scheme_id = 2` (`docs/PQC_MULTISIG.md` §5).
//!
//! **What the output commits to.** Each member `i` of an `n`-member group has
//! a per-output hybrid signing key `pk_i`, derived from a KEM secret only that
//! member (and the sender) holds. The output does not commit to the keys; it
//! commits to their hashes, `h_i = frame(shekyl/multisig-key-hash-v1, id,
//! [pk_i])`, in the **committed form**
//!
//! ```text
//! 0x02 ‖ n ‖ m ‖ h_1 ‖ … ‖ h_n          (3 + 32·n bytes)
//! ```
//!
//! The leaf scalar is `k = H_ℓ(committed form)`. Committing to hashes is what
//! lets `m` signers spend without the other `n − m`: a signer cannot derive a
//! non-signer's `pk_j`, but it can read `h_j` (the wallet decrypts the hashes
//! from the output's `0x0D` entry).
//!
//! **What a spend reveals** ([`MultisigKeyBlob`]):
//!
//! ```text
//! committed form ‖ signer_bitmap(1) ‖ pk_{i_1} ‖ … ‖ pk_{i_m}
//! ```
//!
//! The verifier checks each revealed key against the hash at its index, then
//! the signatures. `k` is derived from the committed form only
//! ([`crate::signature::pqc_leaf_key_bytes`]), so the leaf binds the group
//! and its threshold, and the bitmap and keys are checked against it.

use shekyl_network::envelope::IdDomain;
use shekyl_network::NetworkId;
use shekyl_types::SigningPayloadHash;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::PqcVerifyError;
use crate::signature::{HybridEd25519MlDsa, HybridPublicKey, HybridSignature, SignatureScheme};

/// Largest multisig group served (MSW-G, settled 2026-07-15: 2f+1 at f=2).
/// The value is the *correctness* cap — the parsers refuse `n > MAX` — and
/// is deliberately NOT the source of the DoS ceilings below (see
/// `PQC_MAX_*_BLOB`).
pub const MAX_MULTISIG_PARTICIPANTS: u8 = 5;
/// The `pqc_auth.scheme_id` of a multisig spend.
pub const HYBRID_SCHEME_ID_MULTISIG: u8 = 2;

/// The container version, and the group's `spend_auth_version`: Option E′
/// threshold classical SAL plus M-of-N hybrid signatures. One discriminator,
/// on chain, where a later verifier dispatches on it. `0x01` was Option D's
/// and was never issued; a blob carrying it is refused with
/// [`PqcVerifyError::ContainerVersion`].
pub const MULTISIG_CONTAINER_VERSION: u8 = 0x02;

// The address stamps the same version: one constant in two crates, pinned.
const _: () = assert!(
    MULTISIG_CONTAINER_VERSION == shekyl_address::multisig_address::SPEND_AUTH_VERSION,
    "the container version and the address's spend_auth_version diverged"
);

/// Bytes of one member's key hash `h_i`.
pub const MULTISIG_KEY_HASH_LEN: usize = 32;

/// Size of a single `HybridPublicKey` in canonical encoding (1996). Aliased
/// from the type that owns the encoding — one canonical definition (MSW-1).
pub const SINGLE_KEY_CANONICAL_LEN: usize = HybridPublicKey::CANONICAL_LEN;

/// Size of a single `HybridSignature` in canonical encoding (3385). Aliased
/// from the type that owns the encoding — one canonical definition (MSW-1).
pub const SINGLE_SIG_CANONICAL_LEN: usize = HybridSignature::CANONICAL_LEN;

/// The shortest legal multisig key blob: a 1-of-1 group revealing its one key
/// (`3 + 32 + 1 + 1996 = 2032`). The structural floor both consensus
/// verifiers apply before the exact parse (CEN-I16, K13).
pub const MULTISIG_KEY_BLOB_MIN: usize = MultisigKeyBlob::expected_len(1, 1);

/// DoS pre-bound for a serialized multisig **key** blob
/// (`pqc_auth.hybrid_public_key`, scheme 2). A generous, round ceiling
/// **decoupled** from `MAX_MULTISIG_PARTICIPANTS`: correctness (exact byte
/// count, `n ≤ MAX`) is [`MultisigKeyBlob::from_canonical_bytes`], not this
/// bound. Bumping it needs a consensus rationale. The `const` assert below
/// makes a ceiling *below* the largest legal blob a **compile error**
/// (MSW-1 / F-1).
pub const PQC_MAX_PUBLIC_KEY_BLOB: usize = 16_384;

/// DoS pre-bound for a serialized multisig **signature** blob. Same
/// discipline as `PQC_MAX_PUBLIC_KEY_BLOB`.
pub const PQC_MAX_SIGNATURE_BLOB: usize = 32_768;

// Compile-time ceiling ladder: the largest legal blob at MAX must fit under
// the ceiling.
const _: () = assert!(
    MultisigKeyBlob::expected_len(MAX_MULTISIG_PARTICIPANTS, MAX_MULTISIG_PARTICIPANTS)
        <= PQC_MAX_PUBLIC_KEY_BLOB,
    "PQC_MAX_PUBLIC_KEY_BLOB below the largest legal MultisigKeyBlob — see MSW-1/F-1"
);
const _: () = assert!(
    MultisigSigContainer::expected_sig_len(MAX_MULTISIG_PARTICIPANTS) <= PQC_MAX_SIGNATURE_BLOB,
    "PQC_MAX_SIGNATURE_BLOB below the largest legal MultisigSigContainer — see MSW-1/F-1"
);

// MSW-1: the participant cap is enforced at two validation surfaces — these
// parsers and the multisig address payload (`shekyl-address`). An address
// that exceeds this cap is dead on arrival, so the two are pinned equal at
// compile time; a bound duplicated across a boundary is caught by a
// mechanism, not by review.
const _: () = assert!(
    MAX_MULTISIG_PARTICIPANTS == shekyl_address::multisig_address::MAX_MULTISIG_PARTICIPANTS,
    "MSW-1: shekyl-crypto-pq and shekyl-address multisig participant caps diverged"
);

// MSW-2, length-primary disjointness: a solo key blob (1996 bytes) is never
// a legal multisig length. The shortest multisig blob is longer than it.
const _: () = assert!(
    MULTISIG_KEY_BLOB_MIN > SINGLE_KEY_CANONICAL_LEN,
    "MSW-2: a solo key blob length must never parse as a multisig key blob"
);

/// The member key hash: `h_i = cSHAKE256(S = "shekyl/multisig-key-hash-v1",
/// X = network_id ‖ framed(pk_i))`, 32 bytes (the signing envelope; registry
/// row `shekyl/multisig-key-hash-v1`, binding `id`). It is checked by
/// consensus at every multisig spend, so it binds the chain's network id: a
/// key hash made for one network is not one for another.
pub const MULTISIG_KEY_HASH: IdDomain<1> = IdDomain::new(b"shekyl/multisig-key-hash-v1");

/// `h_i` for one member's per-output key (see [`MULTISIG_KEY_HASH`]).
#[must_use]
pub fn multisig_key_hash(
    network: &NetworkId,
    key: &HybridPublicKey,
) -> [u8; MULTISIG_KEY_HASH_LEN] {
    let bytes = key
        .to_canonical_bytes()
        .expect("a parsed or derived HybridPublicKey always encodes");
    MULTISIG_KEY_HASH.frame(network, [&bytes]).into_bytes()
}

/// The bytes an output's leaf commits to: `0x02 ‖ n ‖ m ‖ h_1 ‖ … ‖ h_n`.
///
/// Fields are private and every constructor checks `1 ≤ m ≤ n ≤ MAX` and
/// `n` hashes, so a committed form that does not parse does not exist.
/// The hashes are the decrypted `0x0D` plaintext until a spend publishes
/// them, so the form and every serialization of it wipe on drop.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct MultisigCommittedForm {
    n_total: u8,
    m_required: u8,
    key_hashes: Vec<[u8; MULTISIG_KEY_HASH_LEN]>,
}

impl std::fmt::Debug for MultisigCommittedForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultisigCommittedForm")
            .field("n_total", &self.n_total)
            .field("m_required", &self.m_required)
            .field("key_hashes", &self.key_hashes.len())
            .finish()
    }
}

impl MultisigCommittedForm {
    /// The committed form's length for `n` members.
    #[must_use]
    pub const fn expected_len(n: u8) -> usize {
        3 + (n as usize) * MULTISIG_KEY_HASH_LEN
    }

    /// Build the committed form from the members' key hashes, member order.
    ///
    /// # Errors
    ///
    /// [`PqcVerifyError::ParameterBounds`] unless `1 ≤ m ≤ n ≤ MAX`, where
    /// `n` is `key_hashes.len()`.
    pub fn new(
        m_required: u8,
        key_hashes: Vec<[u8; MULTISIG_KEY_HASH_LEN]>,
    ) -> Result<Self, PqcVerifyError> {
        // Wiped on every refusal. On success the allocation moves into the
        // form, which wipes it on drop.
        let mut key_hashes = Zeroizing::new(key_hashes);
        let Ok(n_total) = u8::try_from(key_hashes.len()) else {
            return Err(PqcVerifyError::ParameterBounds);
        };
        check_bounds(n_total, m_required)?;
        Ok(Self {
            n_total,
            m_required,
            key_hashes: std::mem::take(&mut *key_hashes),
        })
    }

    /// `n`.
    #[must_use]
    pub const fn n_total(&self) -> u8 {
        self.n_total
    }

    /// `m`.
    #[must_use]
    pub const fn m_required(&self) -> u8 {
        self.m_required
    }

    /// `h_1 … h_n`, member order.
    #[must_use]
    pub fn key_hashes(&self) -> &[[u8; MULTISIG_KEY_HASH_LEN]] {
        &self.key_hashes
    }

    /// The canonical bytes — what `k = H_ℓ(·)` hashes.
    ///
    /// The buffer wipes on drop. A caller that publishes the encoding copies
    /// it out; that copy is the published blob, and this one does not remain.
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Vec::with_capacity(Self::expected_len(self.n_total));
        out.push(MULTISIG_CONTAINER_VERSION);
        out.push(self.n_total);
        out.push(self.m_required);
        for h in &self.key_hashes {
            out.extend_from_slice(h);
        }
        Zeroizing::new(out)
    }

    /// Parse the header and hashes at the front of `bytes`, returning the
    /// form and the rest. The rest is the caller's: [`Self::from_bytes`]
    /// requires it empty, [`MultisigKeyBlob`] reads the signers from it.
    fn parse_prefix(bytes: &[u8]) -> Result<(Self, &[u8]), PqcVerifyError> {
        let [version, n_total, m_required, rest @ ..] = bytes else {
            return Err(PqcVerifyError::KeyBlobLength);
        };
        if *version != MULTISIG_CONTAINER_VERSION {
            return Err(PqcVerifyError::ContainerVersion);
        }
        check_bounds(*n_total, *m_required)?;
        let hashes_len = usize::from(*n_total) * MULTISIG_KEY_HASH_LEN;
        if rest.len() < hashes_len {
            return Err(PqcVerifyError::KeyBlobLength);
        }
        let (hashes, rest) = rest.split_at(hashes_len);
        let key_hashes = hashes
            .chunks_exact(MULTISIG_KEY_HASH_LEN)
            .map(|h| h.try_into().expect("chunks_exact width"))
            .collect();
        Ok((
            Self {
                n_total: *n_total,
                m_required: *m_required,
                key_hashes,
            },
            rest,
        ))
    }

    /// Parse exactly one committed form.
    ///
    /// # Errors
    ///
    /// [`PqcVerifyError::ContainerVersion`] for a version other than `0x02`;
    /// [`PqcVerifyError::ParameterBounds`] for `n`/`m` out of range;
    /// [`PqcVerifyError::KeyBlobLength`] unless the length is `3 + 32·n`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqcVerifyError> {
        let (form, rest) = Self::parse_prefix(bytes)?;
        if !rest.is_empty() {
            return Err(PqcVerifyError::KeyBlobLength);
        }
        Ok(form)
    }

    /// The committed form's length when `blob` starts with one: `3 + 32·n`
    /// after the version and bounds check. The hashes are parsed to know
    /// that the prefix is that long, then wiped with the temporary form.
    pub(crate) fn prefix_len(blob: &[u8]) -> Result<usize, PqcVerifyError> {
        let (form, _) = Self::parse_prefix(blob)?;
        Ok(Self::expected_len(form.n_total))
    }
}

fn check_bounds(n_total: u8, m_required: u8) -> Result<(), PqcVerifyError> {
    if m_required == 0
        || n_total == 0
        || m_required > n_total
        || n_total > MAX_MULTISIG_PARTICIPANTS
    {
        return Err(PqcVerifyError::ParameterBounds);
    }
    Ok(())
}

/// The key blob a multisig spend reveals:
/// `committed form ‖ signer_bitmap ‖ pk_{i_1} ‖ … ‖ pk_{i_m}`.
///
/// Bit `i` of `signer_bitmap` (least significant first) marks member `i` as
/// a signer; exactly `m` bits are set, none at or above `n`. The keys follow
/// in ascending member order. [`Self::from_canonical_bytes`] and
/// [`Self::assemble`] are the only constructors and both check all of that.
#[derive(Debug, Clone)]
pub struct MultisigKeyBlob {
    committed: MultisigCommittedForm,
    signer_bitmap: u8,
    signer_keys: Vec<HybridPublicKey>,
}

impl MultisigKeyBlob {
    /// The blob's length for an `m`-of-`n` group: `3 + 32·n + 1 + 1996·m`.
    /// Injective in `(n, m)` over the legal range, since `32·MAX < 1996`.
    #[must_use]
    pub const fn expected_len(n: u8, m: u8) -> usize {
        MultisigCommittedForm::expected_len(n) + 1 + (m as usize) * SINGLE_KEY_CANONICAL_LEN
    }

    /// Assemble a spend's key blob from the output's committed form and the
    /// signers' keys, given as `(member index, key)` in any order.
    ///
    /// # Errors
    ///
    /// [`PqcVerifyError::ThresholdMismatch`] unless exactly `m` signers;
    /// [`PqcVerifyError::IndexOutOfRange`] for an index `≥ n`;
    /// [`PqcVerifyError::IndicesNotAscending`] for a repeated index.
    /// The keys are not checked against the hashes here — that is
    /// [`verify_multisig`]'s, which needs the network id.
    pub fn assemble(
        committed: MultisigCommittedForm,
        mut signers: Vec<(u8, HybridPublicKey)>,
    ) -> Result<Self, PqcVerifyError> {
        if signers.len() != usize::from(committed.m_required) {
            return Err(PqcVerifyError::ThresholdMismatch);
        }
        signers.sort_by_key(|(index, _)| *index);
        let mut signer_bitmap = 0u8;
        for (index, _) in &signers {
            if *index >= committed.n_total {
                return Err(PqcVerifyError::IndexOutOfRange);
            }
            let bit = 1u8 << index;
            if signer_bitmap & bit != 0 {
                return Err(PqcVerifyError::IndicesNotAscending);
            }
            signer_bitmap |= bit;
        }
        Ok(Self {
            committed,
            signer_bitmap,
            signer_keys: signers.into_iter().map(|(_, key)| key).collect(),
        })
    }

    /// The committed form this blob reveals keys against.
    #[must_use]
    pub fn committed(&self) -> &MultisigCommittedForm {
        &self.committed
    }

    /// The signer bitmap.
    #[must_use]
    pub const fn signer_bitmap(&self) -> u8 {
        self.signer_bitmap
    }

    /// The signers' member indices, ascending — the set bits of the bitmap.
    #[must_use]
    pub fn signer_indices(&self) -> Vec<u8> {
        (0..self.committed.n_total)
            .filter(|i| self.signer_bitmap & (1u8 << i) != 0)
            .collect()
    }

    /// The signers' keys, in [`Self::signer_indices`] order.
    #[must_use]
    pub fn signer_keys(&self) -> &[HybridPublicKey] {
        &self.signer_keys
    }

    /// The canonical bytes, as carried in `pqc_auth.hybrid_public_key`.
    ///
    /// # Errors
    ///
    /// [`PqcVerifyError::DeserializationFailed`] if a key does not encode.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, PqcVerifyError> {
        let mut committed_bytes = self.committed.to_bytes();
        // The committed form's own buffer wipes when it drops. What remains
        // is the key blob, which a spend publishes.
        let mut out = std::mem::take(&mut *committed_bytes);
        out.reserve(1 + self.signer_keys.len() * SINGLE_KEY_CANONICAL_LEN);
        out.push(self.signer_bitmap);
        for key in &self.signer_keys {
            let bytes = key
                .to_canonical_bytes()
                .map_err(|_| PqcVerifyError::DeserializationFailed)?;
            out.extend_from_slice(&bytes);
        }
        debug_assert_eq!(
            out.len(),
            Self::expected_len(self.committed.n_total, self.committed.m_required)
        );
        Ok(out)
    }

    /// Parse a key blob.
    ///
    /// # Errors
    ///
    /// [`PqcVerifyError::ContainerVersion`] for a version other than `0x02`;
    /// [`PqcVerifyError::ParameterBounds`] for `n`/`m` out of range;
    /// [`PqcVerifyError::KeyBlobLength`] unless the length is exactly
    /// [`Self::expected_len`]`(n, m)`; [`PqcVerifyError::SignerBitmap`] for a
    /// bitmap with a bit at or above `n` or other than `m` bits set;
    /// [`PqcVerifyError::DeserializationFailed`] for a key that does not
    /// parse.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PqcVerifyError> {
        let (committed, rest) = MultisigCommittedForm::parse_prefix(bytes)?;
        let n = committed.n_total;
        let m = committed.m_required;
        if bytes.len() != Self::expected_len(n, m) {
            return Err(PqcVerifyError::KeyBlobLength);
        }
        let (&signer_bitmap, keys) = rest.split_first().ok_or(PqcVerifyError::KeyBlobLength)?;
        // `n ≤ 5`, so the mask fits; bits at or above `n` name no member.
        let members = (1u16 << n) - 1;
        if u16::from(signer_bitmap) & !members != 0 || signer_bitmap.count_ones() != u32::from(m) {
            return Err(PqcVerifyError::SignerBitmap);
        }
        let signer_keys = keys
            .chunks_exact(SINGLE_KEY_CANONICAL_LEN)
            .map(|chunk| {
                HybridPublicKey::from_canonical_bytes(chunk)
                    .map_err(|_| PqcVerifyError::DeserializationFailed)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            committed,
            signer_bitmap,
            signer_keys,
        })
    }

    /// Whether two revealed keys are byte-identical.
    #[must_use]
    pub fn has_duplicate_keys(&self) -> bool {
        let encoded: Vec<Vec<u8>> = self
            .signer_keys
            .iter()
            .map(|k| k.to_canonical_bytes().expect("parsed keys encode"))
            .collect();
        encoded
            .iter()
            .enumerate()
            .any(|(i, a)| encoded[i + 1..].contains(a))
    }
}

/// Serialized M-of-N signature blob.
///
/// Wire layout: `sig_count(1) || sig[0](3385) || ... || sig[M-1](3385) || idx[0](1) || ... || idx[M-1](1)`
///
/// The indices repeat the key blob's bitmap; [`verify_multisig`] refuses a
/// signature blob whose indices are not exactly the bitmap's set bits, so
/// there is one list of signers, not two.
#[derive(Debug, Clone)]
pub struct MultisigSigContainer {
    pub sig_count: u8,
    pub sigs: Vec<HybridSignature>,
    pub signer_indices: Vec<u8>,
}

impl MultisigSigContainer {
    /// Expected byte length of an `m`-signature canonical encoding:
    /// `sig_count(1) || m·sig(3385) || m·idx(1)`. `const fn` so the
    /// `PQC_MAX_SIGNATURE_BLOB` ceiling can assert against it at compile time.
    pub const fn expected_sig_len(m: u8) -> usize {
        1 + (m as usize) * SINGLE_SIG_CANONICAL_LEN + (m as usize)
    }

    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, PqcVerifyError> {
        let cap = Self::expected_sig_len(self.sig_count);
        let mut out = Vec::with_capacity(cap);
        out.push(self.sig_count);
        for sig in &self.sigs {
            let sb = sig
                .to_canonical_bytes()
                .map_err(|_| PqcVerifyError::DeserializationFailed)?;
            out.extend_from_slice(&sb);
        }
        out.extend_from_slice(&self.signer_indices);
        debug_assert_eq!(out.len(), cap);
        Ok(out)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PqcVerifyError> {
        if bytes.is_empty() {
            return Err(PqcVerifyError::SigBlobLength);
        }
        let sig_count = bytes[0];
        if sig_count == 0 || sig_count > MAX_MULTISIG_PARTICIPANTS {
            return Err(PqcVerifyError::ParameterBounds);
        }

        let expected_len = Self::expected_sig_len(sig_count);
        if bytes.len() != expected_len {
            return Err(PqcVerifyError::SigBlobLength);
        }

        let mut sigs = Vec::with_capacity(sig_count as usize);
        let mut cursor = 1usize;
        for _ in 0..sig_count {
            let end = cursor + SINGLE_SIG_CANONICAL_LEN;
            let sig = HybridSignature::from_canonical_bytes(&bytes[cursor..end])
                .map_err(|_| PqcVerifyError::DeserializationFailed)?;
            sigs.push(sig);
            cursor = end;
        }

        let signer_indices = bytes[cursor..].to_vec();
        debug_assert_eq!(signer_indices.len(), sig_count as usize);

        Ok(Self {
            sig_count,
            sigs,
            signer_indices,
        })
    }
}

/// Verify an M-of-N multisig spend authorization.
///
/// In order, each refusal a [`PqcVerifyError`]:
/// 1. `scheme_id` is 2 ([`PqcVerifyError::SchemeMismatch`]);
/// 2. the key blob parses ([`MultisigKeyBlob::from_canonical_bytes`]:
///    version, bounds, exact length, bitmap, keys);
/// 3. the signature blob parses;
/// 4. it carries `m` signatures ([`PqcVerifyError::ThresholdMismatch`]);
/// 5. its indices are in range and ascending, and are exactly the bitmap's
///    set bits ([`PqcVerifyError::SignerListMismatch`]);
/// 6. every revealed key hashes to the committed hash at its index, under
///    this network ([`PqcVerifyError::KeyHashMismatch`]) — before any
///    signature work;
/// 7. no two revealed keys are equal ([`PqcVerifyError::DuplicateKeys`]);
/// 8. every signature verifies under
///    [`crate::signature::SCHEME_DOMAIN_PQC_AUTH_TX_MULTISIG`]
///    ([`PqcVerifyError::CryptoVerifyFailed`]).
///
/// The leaf scalar `k` is not this function's: the caller derives it from
/// the committed form ([`crate::signature::pqc_leaf_key_bytes`]).
///
/// Group identity is not checked here: it is the address fingerprint
/// (`shekyl-address`), not a property of one output.
///
/// Returns `Ok(())` on success and `Err` on any failure — `Result<()>`, **not**
/// `Result<bool>` (SA-R-1): there is no `Ok(false)` for a caller to mishandle.
/// Do not restore a boolean return.
pub fn verify_multisig(
    scheme_id: u8,
    key_blob: &[u8],
    sig_blob: &[u8],
    message: &SigningPayloadHash,
    network: &NetworkId,
) -> Result<(), PqcVerifyError> {
    if scheme_id != HYBRID_SCHEME_ID_MULTISIG {
        return Err(PqcVerifyError::SchemeMismatch);
    }
    let keys = MultisigKeyBlob::from_canonical_bytes(key_blob)?;
    let sigs = MultisigSigContainer::from_canonical_bytes(sig_blob)?;
    if sigs.sig_count != keys.committed.m_required {
        return Err(PqcVerifyError::ThresholdMismatch);
    }
    if sigs
        .signer_indices
        .iter()
        .any(|&idx| idx >= keys.committed.n_total)
    {
        return Err(PqcVerifyError::IndexOutOfRange);
    }
    if sigs.signer_indices.windows(2).any(|w| w[1] <= w[0]) {
        return Err(PqcVerifyError::IndicesNotAscending);
    }
    let indices = keys.signer_indices();
    if sigs.signer_indices != indices {
        return Err(PqcVerifyError::SignerListMismatch);
    }
    for (&idx, key) in indices.iter().zip(&keys.signer_keys) {
        if multisig_key_hash(network, key) != keys.committed.key_hashes[usize::from(idx)] {
            return Err(PqcVerifyError::KeyHashMismatch);
        }
    }
    if keys.has_duplicate_keys() {
        return Err(PqcVerifyError::DuplicateKeys);
    }
    let message = message.as_bytes();
    for (sig, key) in sigs.sigs.iter().zip(&keys.signer_keys) {
        HybridEd25519MlDsa
            .verify(
                key,
                crate::signature::SCHEME_DOMAIN_PQC_AUTH_TX_MULTISIG,
                message,
                sig,
            )
            .map_err(|_| PqcVerifyError::CryptoVerifyFailed)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::HybridSecretKey;

    const MSD: &[u8] = crate::signature::SCHEME_DOMAIN_PQC_AUTH_TX_MULTISIG;
    const NET: NetworkId = [0x4E; 16];
    const OTHER_NET: NetworkId = [0x4F; 16];

    /// A test's message: its label, zero-padded to a signing payload hash.
    fn payload(label: &[u8]) -> SigningPayloadHash {
        let mut bytes = [0u8; 64];
        bytes[..label.len()].copy_from_slice(label);
        SigningPayloadHash::from_bytes(bytes)
    }

    fn gen_keypairs(n: usize) -> Vec<(HybridPublicKey, HybridSecretKey)> {
        (0..n)
            .map(|_| {
                HybridEd25519MlDsa
                    .generate_ephemeral_keypair_for_tests()
                    .unwrap()
            })
            .collect()
    }

    /// An `m`-of-`n` group: the members' keys and the committed form over
    /// their hashes on [`NET`].
    fn group(
        n: usize,
        m: u8,
    ) -> (
        Vec<(HybridPublicKey, HybridSecretKey)>,
        MultisigCommittedForm,
    ) {
        let pairs = gen_keypairs(n);
        let hashes = pairs
            .iter()
            .map(|(pk, _)| multisig_key_hash(&NET, pk))
            .collect();
        (pairs, MultisigCommittedForm::new(m, hashes).unwrap())
    }

    fn key_blob(
        committed: &MultisigCommittedForm,
        pairs: &[(HybridPublicKey, HybridSecretKey)],
        signers: &[u8],
    ) -> Vec<u8> {
        let signers = signers
            .iter()
            .map(|&i| (i, pairs[usize::from(i)].0.clone()))
            .collect();
        MultisigKeyBlob::assemble(committed.clone(), signers)
            .unwrap()
            .to_canonical_bytes()
            .unwrap()
    }

    fn sig_blob(
        pairs: &[(HybridPublicKey, HybridSecretKey)],
        signers: &[u8],
        message: &SigningPayloadHash,
    ) -> Vec<u8> {
        let sigs = signers
            .iter()
            .map(|&i| {
                HybridEd25519MlDsa
                    .sign(&pairs[usize::from(i)].1, MSD, message.as_bytes())
                    .unwrap()
            })
            .collect::<Vec<_>>();
        MultisigSigContainer {
            sig_count: u8::try_from(sigs.len()).unwrap(),
            sigs,
            signer_indices: signers.to_vec(),
        }
        .to_canonical_bytes()
        .unwrap()
    }

    fn verify(key: &[u8], sig: &[u8], msg: &SigningPayloadHash) -> Result<(), PqcVerifyError> {
        verify_multisig(HYBRID_SCHEME_ID_MULTISIG, key, sig, msg, &NET)
    }

    #[test]
    fn committed_form_round_trips_at_three_plus_32n() {
        for n in 1..=MAX_MULTISIG_PARTICIPANTS {
            let hashes = (0..n).map(|i| [i; 32]).collect();
            let form = MultisigCommittedForm::new(1, hashes).unwrap();
            let bytes = form.to_bytes();
            assert_eq!(bytes.len(), 3 + 32 * usize::from(n));
            assert_eq!(bytes[0], 0x02);
            assert_eq!(MultisigCommittedForm::from_bytes(&bytes).unwrap(), form);
        }
    }

    #[test]
    fn committed_form_refuses_bounds_and_lengths() {
        assert_eq!(
            MultisigCommittedForm::new(0, vec![[0; 32]]),
            Err(PqcVerifyError::ParameterBounds)
        );
        assert_eq!(
            MultisigCommittedForm::new(2, vec![[0; 32]]),
            Err(PqcVerifyError::ParameterBounds)
        );
        assert_eq!(
            MultisigCommittedForm::new(1, vec![[0; 32]; 6]),
            Err(PqcVerifyError::ParameterBounds)
        );
        let bytes = MultisigCommittedForm::new(1, vec![[7; 32]; 2])
            .unwrap()
            .to_bytes();
        let mut longer = bytes.clone();
        longer.extend_from_slice(&[7; 32]);
        assert_eq!(
            MultisigCommittedForm::from_bytes(&longer),
            Err(PqcVerifyError::KeyBlobLength)
        );
        assert_eq!(
            MultisigCommittedForm::from_bytes(&bytes[..bytes.len() - 1]),
            Err(PqcVerifyError::KeyBlobLength)
        );
    }

    /// The never-issued `0x01` is refused by name, not as a bounds error.
    #[test]
    fn version_0x01_is_refused_with_a_typed_error() {
        let mut bytes = MultisigCommittedForm::new(1, vec![[7; 32]])
            .unwrap()
            .to_bytes();
        bytes[0] = 0x01;
        assert_eq!(
            MultisigCommittedForm::from_bytes(&bytes),
            Err(PqcVerifyError::ContainerVersion)
        );
        let (pairs, form) = group(1, 1);
        let mut blob = key_blob(&form, &pairs, &[0]);
        blob[0] = 0x01;
        assert_eq!(
            MultisigKeyBlob::from_canonical_bytes(&blob).unwrap_err(),
            PqcVerifyError::ContainerVersion
        );
    }

    /// MSW-1: every legal `(n, m)` round-trips at exactly its expected length.
    #[test]
    fn msw1_key_blob_lengths_and_round_trip_over_all_n_m() {
        let pairs = gen_keypairs(usize::from(MAX_MULTISIG_PARTICIPANTS));
        for n in 1..=MAX_MULTISIG_PARTICIPANTS {
            for m in 1..=n {
                let hashes = pairs[..usize::from(n)]
                    .iter()
                    .map(|(pk, _)| multisig_key_hash(&NET, pk))
                    .collect();
                let form = MultisigCommittedForm::new(m, hashes).unwrap();
                let signers: Vec<u8> = (0..m).collect();
                let bytes = key_blob(&form, &pairs, &signers);
                assert_eq!(bytes.len(), MultisigKeyBlob::expected_len(n, m));
                let parsed = MultisigKeyBlob::from_canonical_bytes(&bytes).unwrap();
                assert_eq!(parsed.committed(), &form);
                assert_eq!(parsed.signer_indices(), signers);
                assert_eq!(parsed.to_canonical_bytes().unwrap(), bytes);
            }
        }
        assert_eq!(MULTISIG_KEY_BLOB_MIN, 2032);
    }

    /// MSW-2, length-primary: the solo key length is never a multisig length,
    /// and no two legal `(n, m)` share a length.
    #[test]
    fn msw2_lengths_are_injective_and_disjoint_from_the_solo_key() {
        let mut seen = std::collections::BTreeMap::new();
        for n in 1..=MAX_MULTISIG_PARTICIPANTS {
            for m in 1..=n {
                let len = MultisigKeyBlob::expected_len(n, m);
                assert_ne!(len, SINGLE_KEY_CANONICAL_LEN);
                assert!(seen.insert(len, (n, m)).is_none(), "length {len} repeats");
            }
        }
    }

    #[test]
    fn valid_spends_verify() {
        for (n, m, signers) in [
            (1usize, 1u8, vec![0u8]),
            (3, 2, vec![0, 2]),
            (5, 3, vec![1, 3, 4]),
            (5, 5, vec![0, 1, 2, 3, 4]),
        ] {
            let (pairs, form) = group(n, m);
            let msg = payload(b"valid");
            let key = key_blob(&form, &pairs, &signers);
            let sig = sig_blob(&pairs, &signers, &msg);
            assert_eq!(verify(&key, &sig, &msg), Ok(()), "{m}-of-{n} {signers:?}");
        }
    }

    /// Any `m` of the `n` can sign: every 3-subset of a 3-of-5 group.
    #[test]
    fn every_three_of_five_subset_verifies() {
        let (pairs, form) = group(5, 3);
        let msg = payload(b"subsets");
        for a in 0..5u8 {
            for b in a + 1..5 {
                for c in b + 1..5 {
                    let signers = [a, b, c];
                    let key = key_blob(&form, &pairs, &signers);
                    let sig = sig_blob(&pairs, &signers, &msg);
                    assert_eq!(verify(&key, &sig, &msg), Ok(()), "{signers:?}");
                }
            }
        }
    }

    #[test]
    fn a_wrong_hash_at_a_signer_index_is_refused_before_signatures() {
        let (pairs, form) = group(3, 2);
        let msg = payload(b"wrong-hash");
        let mut hashes = form.key_hashes().to_vec();
        hashes[2][0] ^= 1;
        let tampered = MultisigCommittedForm::new(2, hashes).unwrap();
        let key = key_blob(&tampered, &pairs, &[0, 2]);
        // The signatures are valid; the hash is what fails.
        let sig = sig_blob(&pairs, &[0, 2], &msg);
        assert_eq!(
            verify(&key, &sig, &msg),
            Err(PqcVerifyError::KeyHashMismatch)
        );
        // A non-signer's wrong hash is the leaf's business, not this check's.
        let key = key_blob(&tampered, &pairs, &[0, 1]);
        let sig = sig_blob(&pairs, &[0, 1], &msg);
        assert_eq!(verify(&key, &sig, &msg), Ok(()));
    }

    #[test]
    fn a_non_member_key_is_refused() {
        let (pairs, form) = group(3, 2);
        let outsider = gen_keypairs(1);
        let msg = payload(b"outsider");
        let key = MultisigKeyBlob::assemble(
            form,
            vec![(0, pairs[0].0.clone()), (1, outsider[0].0.clone())],
        )
        .unwrap()
        .to_canonical_bytes()
        .unwrap();
        let mut both = vec![pairs[0].clone(), outsider[0].clone()];
        both.push(pairs[2].clone());
        let sig = sig_blob(&both, &[0, 1], &msg);
        assert_eq!(
            verify(&key, &sig, &msg),
            Err(PqcVerifyError::KeyHashMismatch)
        );
    }

    /// The key hash binds the network: hashes made on one network do not
    /// verify on another.
    #[test]
    fn key_hashes_bind_the_network() {
        let (pairs, form) = group(2, 2);
        let msg = payload(b"network");
        let key = key_blob(&form, &pairs, &[0, 1]);
        let sig = sig_blob(&pairs, &[0, 1], &msg);
        assert_eq!(verify(&key, &sig, &msg), Ok(()));
        assert_eq!(
            verify_multisig(HYBRID_SCHEME_ID_MULTISIG, &key, &sig, &msg, &OTHER_NET),
            Err(PqcVerifyError::KeyHashMismatch)
        );
    }

    #[test]
    fn a_bad_bitmap_is_refused() {
        let (pairs, form) = group(3, 2);
        let blob = key_blob(&form, &pairs, &[0, 1]);
        let at = MultisigCommittedForm::expected_len(3);
        for (name, bitmap) in [
            ("one bit for m = 2", 0b001u8),
            ("three bits for m = 2", 0b111),
            ("a bit at n", 0b1001),
        ] {
            let mut bad = blob.clone();
            bad[at] = bitmap;
            assert_eq!(
                MultisigKeyBlob::from_canonical_bytes(&bad).unwrap_err(),
                PqcVerifyError::SignerBitmap,
                "{name}"
            );
        }
    }

    #[test]
    fn a_blob_one_byte_off_is_refused_by_length() {
        let (pairs, form) = group(2, 1);
        let blob = key_blob(&form, &pairs, &[1]);
        let mut long = blob.clone();
        long.push(0);
        for bad in [&blob[..blob.len() - 1], long.as_slice()] {
            assert_eq!(
                MultisigKeyBlob::from_canonical_bytes(bad).unwrap_err(),
                PqcVerifyError::KeyBlobLength
            );
        }
    }

    #[test]
    fn the_signature_blob_must_name_the_bitmap_signers() {
        let (pairs, form) = group(3, 2);
        let msg = payload(b"signer-list");
        let key = key_blob(&form, &pairs, &[0, 2]);
        let sig = sig_blob(&pairs, &[0, 1], &msg);
        assert_eq!(
            verify(&key, &sig, &msg),
            Err(PqcVerifyError::SignerListMismatch)
        );
        let sig = sig_blob(&pairs, &[0], &msg);
        assert_eq!(
            verify(&key, &sig, &msg),
            Err(PqcVerifyError::ThresholdMismatch)
        );
        let sig = sig_blob(&pairs, &[2, 0], &msg);
        assert_eq!(
            verify(&key, &sig, &msg),
            Err(PqcVerifyError::IndicesNotAscending)
        );
    }

    #[test]
    fn assemble_refuses_wrong_signer_sets() {
        let (pairs, form) = group(3, 2);
        let k = |i: usize| pairs[i].0.clone();
        assert_eq!(
            MultisigKeyBlob::assemble(form.clone(), vec![(0, k(0))]).unwrap_err(),
            PqcVerifyError::ThresholdMismatch
        );
        assert_eq!(
            MultisigKeyBlob::assemble(form.clone(), vec![(0, k(0)), (3, k(1))]).unwrap_err(),
            PqcVerifyError::IndexOutOfRange
        );
        assert_eq!(
            MultisigKeyBlob::assemble(form, vec![(1, k(0)), (1, k(1))]).unwrap_err(),
            PqcVerifyError::IndicesNotAscending
        );
    }

    #[test]
    fn duplicate_revealed_keys_are_refused() {
        let pairs = gen_keypairs(1);
        let h = multisig_key_hash(&NET, &pairs[0].0);
        let form = MultisigCommittedForm::new(2, vec![h, h]).unwrap();
        let twice = vec![pairs[0].clone(), pairs[0].clone()];
        let msg = payload(b"dup");
        let key = key_blob(&form, &twice, &[0, 1]);
        let sig = sig_blob(&twice, &[0, 1], &msg);
        assert_eq!(verify(&key, &sig, &msg), Err(PqcVerifyError::DuplicateKeys));
    }

    #[test]
    fn signatures_are_checked_under_the_multisig_domain_and_message() {
        let (pairs, form) = group(1, 1);
        let msg = payload(b"domain");
        let key = key_blob(&form, &pairs, &[0]);
        let solo_domain = HybridEd25519MlDsa
            .sign(
                &pairs[0].1,
                crate::signature::SCHEME_DOMAIN_PQC_AUTH_TX,
                msg.as_bytes(),
            )
            .unwrap();
        let sig = MultisigSigContainer {
            sig_count: 1,
            sigs: vec![solo_domain],
            signer_indices: vec![0],
        }
        .to_canonical_bytes()
        .unwrap();
        assert_eq!(
            verify(&key, &sig, &msg),
            Err(PqcVerifyError::CryptoVerifyFailed)
        );
        let sig = sig_blob(&pairs, &[0], &payload(b"another message"));
        assert_eq!(
            verify(&key, &sig, &msg),
            Err(PqcVerifyError::CryptoVerifyFailed)
        );
        assert_eq!(
            verify_multisig(1, &key, &sig_blob(&pairs, &[0], &msg), &msg, &NET),
            Err(PqcVerifyError::SchemeMismatch)
        );
    }
}
