// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The emission auth inventory: two role domains and the nine fields both
//! hybrid auths sign.
//!
//! The length prefix is [`shekyl_network::envelope::framed_fields`]. This
//! module does not own a second framer. The vin codec stays in
//! [`emission_wire`](crate::emission_wire).

use shekyl_network::envelope::{framed_fields, IdDomain, W64};
use shekyl_network::NetworkId;
use shekyl_types::TxSignableHash;

use crate::bond_wire::encode_holdings_descriptor;
use crate::emission_wire::{ArchivalRewardEmissionVin, RewardCommit, WireError};
use crate::id::p_canonical_id_from_hybrid_pubkey;

/// cSHAKE256 customization for the **stake-side** auth (`auth_backing`) binding
/// message. See [`ArchivalRewardEmissionVin::auth_msg`].
///
/// **`-v2` (`ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md` F-E):** the digest binds
/// the work-claim bytes (field 6), whose per-entry semantics changed from
/// scarcity-milli to scarcity-micro (D1 fix). The zero-tolerance recompute
/// already rejects milli-valued entries under micro rules, so no ambiguity
/// *attack* exists; the separator bump makes "same bytes, different meaning"
/// non-colliding *structurally* rather than by a reconstructed argument.
///
/// **`-v3` (`NETWORK_IDENTITY.md` NI-F11):** the input starts with the
/// network's 16-byte id, so the message binds one network on its own.
///
/// **`-v4` (the signing envelope §2.2, §2.7):** the message is the envelope
/// frame of nine fields under the network's id, 64 bytes wide (a hybrid
/// signature signs it). Field 8 is the transaction's `tx_signable`, and
/// field 9 the backing's wire bytes, which CEN-J22's signable prefix no
/// longer covers. `-v4` has never been released, so the ninth field joins it
/// without a new label.
pub const EMISSION_AUTH_BACKING: IdDomain<9, W64> =
    IdDomain::new(b"shekyl/archival-emission-auth-backing-v4");

/// The envelope domain of the **claim-side** auth (`auth_claim`) binding
/// message. See [`ArchivalRewardEmissionVin::auth_msg`]. Bumped alongside
/// the backing domain: `-v2` for the D1 micro change, `-v3` for the network
/// id, `-v4` for the envelope and `tx_signable` (see there).
pub const EMISSION_AUTH_CLAIM: IdDomain<9, W64> =
    IdDomain::new(b"shekyl/archival-emission-auth-claim-v4");

/// Which of the two Q1 auths a binding message is for. Distinct cSHAKE
/// customizations make the two messages domain-separated **by construction**
/// (Q1: "two distinct binding messages, not one signature checked twice") while
/// both inherit the full R1.A commitment inventory from the one shared builder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmissionAuthRole {
    Backing,
    Claim,
}

/// The two role digests of one emission vin (see
/// [`ArchivalRewardEmissionVin::auth_msgs`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EmissionAuthMsgs {
    /// Stake-side (`auth_backing`) binding message.
    pub backing: [u8; 64],
    /// Claim-side (`auth_claim`) binding message.
    pub claim: [u8; 64],
}

impl EmissionAuthRole {
    /// The role's envelope domain (the Q1 domain separation).
    #[must_use]
    pub const fn domain(self) -> IdDomain<9, W64> {
        match self {
            Self::Backing => EMISSION_AUTH_BACKING,
            Self::Claim => EMISSION_AUTH_CLAIM,
        }
    }

    /// The role's registered customization string.
    #[must_use]
    pub const fn customization(self) -> &'static [u8] {
        self.domain().customization()
    }
}

impl ArchivalRewardEmissionVin {
    /// The 64-byte cSHAKE256 binding message both hybrid auths sign — the R1.A
    /// `emission_auth_msg` inventory with the §8.0.3 freeze additions, one field
    /// construction for both roles (wallet builder and PR-E3 verify call this
    /// same function, so signer and verifier cannot drift).
    ///
    /// **Two distinct messages via customization (Q1 ⊕ R1.A).** Q1 ratified
    /// *two* auths over *two distinct* binding messages ("not one signature
    /// checked twice"); R1.A pinned *one* canonical field inventory. Reconciled
    /// here the cSHAKE way: the same length-prefixed field inventory hashed
    /// under role-distinct customizations
    /// ([`EMISSION_AUTH_BACKING`] / [`EMISSION_AUTH_CLAIM`]), so a backing signature can never
    /// stand in the claim slot (or vice versa) even under the same key, while
    /// both auths inherit every R1.A anti-replay binding.
    ///
    /// The message is the envelope frame of the field inventory under the
    /// network's id, read to 64 bytes (the signing envelope §2.2, §2.7):
    /// `frame(role domain, network_id, [field 1, …, field 9])`. The id is the
    /// network's 16-byte genesis-derived id (`NETWORK_IDENTITY.md` NI-F11)
    /// at position 0, so the message is valid on one network whatever the
    /// transaction around it carries.
    ///
    /// Field inventory ([`Self::auth_msg_framed`]; TupleHash-style: each
    /// field prefixed with its u64-LE byte length, in this order):
    /// 1. `P_canonical_id` (§6.1 derivation from `p_pubkey`)
    /// 2. `p_pubkey` canonical bytes (no key substitution)
    /// 3. holdings canonical encoding (§3.4.1 bytes, shared with the bond wire)
    /// 4. `settlement_epochs` (u64-LE each — epoch replay)
    /// 5. `reward_amount_plain` (u64-LE each — §8.0.3: the digest commits the
    ///    vin's loud per-epoch amounts, not just the vout set)
    /// 6. work-claim canonical wire bytes ([`Self::encode_work_claim`])
    /// 7. ordered reward vout commit set (per entry:
    ///    `commitment ‖ amount_plain u64-LE ‖ one_time_key` — destination swap)
    /// 8. `tx_signable`, the transaction's one network-bound message (cross-tx
    ///    replay; [`shekyl_wire::Transaction::tx_signable`], over CEN-J22's
    ///    signable prefix hash)
    /// 9. backing canonical wire bytes ([`Self::encode_backing`]: the proof,
    ///    `pseudo_out`, the backing key and the tree depth). CEN-J22 takes the
    ///    emission input out of the signable prefix whole, so nothing else
    ///    signs these bytes; with this field, every byte of the input is
    ///    either a field both auths sign or one of the two auth signatures.
    ///
    /// `reward_commits` and `tx_signable` are tx-level context supplied by
    /// the caller (wallet builder / PR-E3), not vin fields.
    ///
    /// Validates the struct first ([`Self::validate`]) so the digest and wire
    /// builders share one precondition — a builder cannot sign a digest over a
    /// struct that `write()` would reject.
    pub fn auth_msg(
        &self,
        network_id: &NetworkId,
        reward_commits: &[RewardCommit],
        tx_signable: &TxSignableHash,
        role: EmissionAuthRole,
    ) -> Result<[u8; 64], WireError> {
        let fields = self.auth_msg_fields(reward_commits, tx_signable)?;
        Ok(role
            .domain()
            .frame(network_id, fields.each_ref().map(Vec::as_slice)))
    }

    /// Both role digests in one pass: the field inventory is built once and
    /// framed under each role's domain, byte-identical to two
    /// [`Self::auth_msg`] calls. Preferred on the per-vin sign/verify paths,
    /// which always need both.
    pub fn auth_msgs(
        &self,
        network_id: &NetworkId,
        reward_commits: &[RewardCommit],
        tx_signable: &TxSignableHash,
    ) -> Result<EmissionAuthMsgs, WireError> {
        let fields = self.auth_msg_fields(reward_commits, tx_signable)?;
        let fields = fields.each_ref().map(Vec::as_slice);
        Ok(EmissionAuthMsgs {
            backing: EMISSION_AUTH_BACKING.frame(network_id, fields),
            claim: EMISSION_AUTH_CLAIM.frame(network_id, fields),
        })
    }

    /// The nine fields of [`Self::auth_msg`], in order, each its raw bytes:
    /// the envelope frames each behind its length. A list field (4, 5, 7) is
    /// one field, the concatenation of its fixed-width entries.
    fn auth_msg_fields(
        &self,
        reward_commits: &[RewardCommit],
        tx_signable: &TxSignableHash,
    ) -> Result<[Vec<u8>; 9], WireError> {
        self.validate()?;
        let u64_le =
            |values: &[u64]| -> Vec<u8> { values.iter().flat_map(|v| v.to_le_bytes()).collect() };
        let mut commits = Vec::with_capacity(reward_commits.len() * 72);
        for rc in reward_commits {
            commits.extend_from_slice(&rc.commitment);
            commits.extend_from_slice(&rc.amount_plain.to_le_bytes());
            commits.extend_from_slice(&rc.one_time_key);
        }
        Ok([
            p_canonical_id_from_hybrid_pubkey(&self.p_pubkey)
                .to_bytes()
                .to_vec(),
            self.p_pubkey.clone(),
            encode_holdings_descriptor(&self.holdings)?,
            u64_le(&self.settlement_epochs),
            u64_le(&self.reward_amount_plain),
            self.encode_work_claim(),
            commits,
            tx_signable.as_bytes().to_vec(),
            self.encode_backing(),
        ])
    }

    /// The framed field inventory: each of [`Self::auth_msg`]'s nine fields
    /// behind its u64-LE length, the part of the envelope's input after the
    /// network id. Public so the `EMISSION_AUTH_MSG_V1` vectors can pin it and
    /// an independent oracle can recompute each digest from it. The length
    /// prefix is [`framed_fields`], not a second framer.
    ///
    /// # Errors
    ///
    /// As [`Self::validate`].
    pub fn auth_msg_framed(
        &self,
        reward_commits: &[RewardCommit],
        tx_signable: &TxSignableHash,
    ) -> Result<Vec<u8>, WireError> {
        let fields = self.auth_msg_fields(reward_commits, tx_signable)?;
        Ok(framed_fields(&fields.each_ref().map(Vec::as_slice)))
    }
}
