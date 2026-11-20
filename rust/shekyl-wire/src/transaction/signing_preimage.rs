// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The **PQC signing preimage** — what every hybrid (Ed25519 + ML-DSA)
//! signature on a transaction is over (`FCMP_SPEND_SIGNING_PREIMAGE.md`
//! §1.1), and the transaction's one network-bound message, `tx_signable`,
//! that every authorization of it proves over (the signing envelope §2.2;
//! `NETWORK_IDENTITY.md` NI-F12 (b)). The derivation of record: the wallet
//! signs over it (`shekyl-tx-builder`), the daemon verifies against it
//! through `shekyl_tx_pqc_signing_payload_hashes`, and the validator
//! records it as CEN-I17. One body; the KAT in
//! `tests/pqc_signing_preimage_kat.rs` holds it to the specification's
//! output over eight daemon-accepted shapes.
//!
//! ```text
//! tx_signable    = frame("shekyl/tx-signable-v1", id, [prefix_hash, ct_base_hash])
//!   where prefix_hash is CEN-J22's: the prefix hash without the emission
//!   input, the plain prefix hash when there is none
//! signed_hash(i) = frame64("shekyl/fcmp-spend-signing-v2", id,
//!                          [tx_signable, header(i), key_hashes, prunable_hash])
//! ```
//!
//! `frame64` is the same frame read to 64 bytes (§2.7): the spend hash is
//! a hybrid signature's signed content.
//!
//! `frame` is the envelope ([`shekyl_network::envelope`]); `id` is the
//! network's 16-byte genesis-derived id (NI-R10), so a proof or signature
//! is valid on exactly one network by construction. `prefix_hash` and
//! `ct_base_hash` are the txid's first two components, read from the
//! functions the txid uses (Rick's ruling 4): together they bind version,
//! prefix, CT type, fee, reference block and the committed base —
//! everything a node keeps after pruning. The SAL proof (full and
//! membership-only) and FROST prove over `tx_signable`, so each commits to
//! the network itself, not through the signature around it.
//!
//! A signature must also bind the discardable regions by digest, the
//! signer's own public key, and every other input's key — so no proof,
//! output, reference or key can be substituted under a standing signature:
//! `header(i)` is the signing input's scheme and key, `key_hashes` the
//! concatenated `keccak256` of every input's key in input order (one field,
//! its length gives the count), and `prunable_hash` the txid's
//! [`PrunableHash`] component.

use shekyl_crypto_hash::keccak256;
use shekyl_network::envelope::{IdDomain, W64};
use shekyl_network::NetworkId;
use shekyl_types::{CtBaseHash, PrefixHash, PrunableHash, SigningPayloadHash, TxSignableHash};

use super::{Ct, Input, PqcAuth, Transaction};

/// A transaction's one network-bound message (the signing envelope §2.2):
/// fields `[prefix_hash, ct_base_hash]`.
pub const TX_SIGNABLE: IdDomain<2> = IdDomain::new(b"shekyl/tx-signable-v1");

/// The spend signature's hash (`NETWORK_IDENTITY.md` §2.4.1, the signing
/// envelope §2.2): fields `[tx_signable, header(i), key_hashes,
/// prunable_hash]`, 64 bytes wide because a hybrid ML-DSA-65 signature
/// signs it (§2.7).
pub const FCMP_SPEND_SIGNING: IdDomain<4, W64> = IdDomain::new(b"shekyl/fcmp-spend-signing-v2");

/// `tx_signable` on the network whose id is `network_id`, from the txid's
/// first two components. [`Transaction::tx_signable`] reads them from a
/// finished body; a signer that has not assembled the body yet reads
/// `prefix_hash` from [`super::TxPrefix::hash`] and `ct_base_hash` from
/// [`super::fcmp_base_hash`], the same functions.
#[must_use]
pub fn tx_signable(
    network_id: &NetworkId,
    prefix_hash: PrefixHash,
    ct_base_hash: CtBaseHash,
) -> TxSignableHash {
    TxSignableHash::from_bytes(
        TX_SIGNABLE
            .frame(
                network_id,
                [prefix_hash.as_bytes(), ct_base_hash.as_bytes()],
            )
            .into_bytes(),
    )
}

/// A transaction's PQC signing preimage on one network — the fields shared
/// by every input's `signed_hash(i)`, derived once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqcSigningPreimage {
    /// The network the signatures are valid on.
    network_id: NetworkId,
    /// The transaction's network-bound message: prefix and base.
    tx_signable: TxSignableHash,
    /// The prunable region, bound by its digest — the txid's
    /// [`PrunableHash`] component: the proof and the pseudo-outs cannot be
    /// swapped without changing every signature's preimage.
    prunable_hash: PrunableHash,
    /// `keccak256` of every input's hybrid public key, in input order,
    /// concatenated: each input's signature binds every input's key, so no
    /// one key can be substituted without invalidating the others.
    key_hashes: Vec<u8>,
}

impl PqcSigningPreimage {
    /// The preimage of `tx` on the network whose id is `network_id`, or
    /// `None` for a body that has none: a coinbase (`Null` CT); the
    /// storage-pruned spend form (no prunable region to bind); and a body
    /// with no `pqc_auths`, which has nothing to sign this preimage (the
    /// count rules, CEN-I8, H21 and H22, refuse it).
    #[must_use]
    pub fn of(tx: &Transaction, network_id: &NetworkId) -> Option<Self> {
        let Ct::Fcmp {
            pqc_auths,
            prunable: Some(_),
            ..
        } = &tx.ct
        else {
            return None;
        };
        if pqc_auths.is_empty() {
            return None;
        }
        Some(Self {
            network_id: *network_id,
            tx_signable: tx.tx_signable(network_id),
            prunable_hash: tx.prunable_hash(),
            key_hashes: pqc_auths
                .iter()
                .flat_map(|auth| keccak256(&auth.hybrid_public_key))
                .collect(),
        })
    }

    /// `signed_hash(i)` for the input whose authentication is `auth`: the
    /// message its hybrid signature is made over and verified against,
    /// typed so it can never be passed where a txid component is expected
    /// (RTN-7). `header(i)` is the auth's scheme and public key, never its
    /// signature: a signature is not over itself.
    #[must_use]
    pub fn signed_hash(&self, auth: &PqcAuth) -> SigningPayloadHash {
        let mut header = Vec::with_capacity(4 + auth.hybrid_public_key.len());
        auth.write_header(&mut header)
            .expect("writing to a Vec is infallible");
        SigningPayloadHash::from_bytes(
            FCMP_SPEND_SIGNING
                .frame(
                    &self.network_id,
                    [
                        self.tx_signable.as_bytes(),
                        &header,
                        &self.key_hashes,
                        self.prunable_hash.as_bytes(),
                    ],
                )
                .into_bytes(),
        )
    }
}

impl Transaction {
    /// CEN-J22's signable prefix hash: the prefix hash of this transaction
    /// with its emission input removed whole (F-C1c). The input cannot be
    /// covered by a hash its own backing proof and auths prove over, and
    /// every property its removal loses is bound again by the auths' fields
    /// 1–6 (J22). For a transaction with no emission input it is the plain
    /// prefix hash, so there is no emission branch in [`Self::tx_signable`].
    ///
    /// Every emission input is removed; consensus admits at most one
    /// (Q3 arity 1), so for a body the validator accepts this is J22's
    /// "the emission vin".
    #[must_use]
    pub fn signable_prefix_hash(&self) -> PrefixHash {
        let is_emission = |input: &Input| matches!(input, Input::ArchivalRewardEmission { .. });
        if !self.prefix.inputs.iter().any(is_emission) {
            return self.prefix_hash();
        }
        let mut prefix = self.prefix.clone();
        prefix.inputs.retain(|input| !is_emission(input));
        prefix.hash()
    }

    /// This transaction's `tx_signable` on the network whose id is
    /// `network_id` ([`tx_signable`]): J22's signable prefix hash
    /// ([`Self::signable_prefix_hash`]) and the base hash, framed. One
    /// message for every transaction: the SAL proofs (the fee inputs' and an
    /// emission's backing proof alike), the emission auths and the
    /// signatures over [`Self::pqc_signing_payload_hashes`] all read it (the
    /// signing envelope §2.2).
    #[must_use]
    pub fn tx_signable(&self, network_id: &NetworkId) -> TxSignableHash {
        tx_signable(network_id, self.signable_prefix_hash(), self.ct.base_hash())
    }

    /// Every input's `signed_hash(i)` on the network whose id is
    /// `network_id`, in input order — one per `pqc_auths`
    /// entry (`== nvin` for a body [`Transaction::validate`] admits; a
    /// hand-built body with mismatched arity yields one per auth, and the
    /// arity is the validator's to refuse). Empty for a body with no
    /// preimage ([`PqcSigningPreimage::of`]).
    #[must_use]
    pub fn pqc_signing_payload_hashes(&self, network_id: &NetworkId) -> Vec<SigningPayloadHash> {
        let Some(preimage) = PqcSigningPreimage::of(self, network_id) else {
            return Vec::new();
        };
        let Ct::Fcmp { pqc_auths, .. } = &self.ct else {
            return Vec::new();
        };
        pqc_auths
            .iter()
            .map(|auth| preimage.signed_hash(auth))
            .collect()
    }
}
