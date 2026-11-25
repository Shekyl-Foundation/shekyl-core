// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One member's receive of one output, end to end (`docs/PQC_MULTISIG.md`
//! §8; R-35).
//!
//! [`receive_group_output`] takes an output as the chain carries it and the
//! member's keys, and does every check a group output needs: the solo
//! recovery under the group's KEM key (the amount decrypts and the
//! commitment opens at it), the recovered spend key is the group's, the key
//! image, and the member check ([`crate::multisig_output`]). What it returns
//! is the wallet's only evidence that the output passed:
//!
//! - a [`GroupReceipt`] for an output the group can spend and this member
//!   can sign for. Its fields are private and only this crate makes one, so
//!   a group coin built from a receipt exists only for an output that
//!   passed. The scanner adds the output's place on the chain (its
//!   transaction, its global index, its block), which this crate cannot
//!   see; the spend-time check that each coin's commitment opens at its
//!   amount (R-27) stays behind it.
//! - a [`GroupRefusal`] for an output paid to the group's keys that failed a
//!   check, with the reason and who it is lost to ([`RefusalReach`]).
//!
//! An output the group's view key does not open is not the group's, and
//! returns `None`, as a solo scan skips it.

use subtle::ConstantTimeEq;

use crate::kem::{MlKemDecapsKey, X25519_KEM_CT_LEN};
use crate::key_image::KeyImage;
use crate::leaf_commitment::{PQC_LEAF_ENTRY_LEN, PQC_LEAF_POINT_LEN};
use crate::multisig::MultisigCommittedForm;
use crate::multisig_output::{
    open_multisig_entry, MultisigEntryView, MultisigMemberView, MultisigReceiveError, RefusalReach,
};
use crate::output::{compute_output_key_image, scan_output_recover_with_ml_kem_dk};
use shekyl_curve_generators::biased_hash_to_point;

/// The group's scanning keys, as a member holds them.
pub struct GroupScanKeys<'a> {
    /// The group KEM key's X25519 secret.
    pub view_x25519: &'a [u8; 32],
    /// The group KEM key's ML-KEM-768 decapsulation key, parsed.
    pub view_ml_kem: &'a MlKemDecapsKey,
    /// The group's spend key `B_group + Y_group`, compressed: the key an
    /// output's recovered spend key must equal.
    pub spend_key: &'a [u8; 32],
    /// `b`, the group-plaintext spend scalar every member holds. The key
    /// image is `(ho + b)·Hp(O)`.
    pub b: &'a [u8; 32],
}

/// One output's `0x0D` entry as the chain carries it.
pub struct GroupEntryOnChain<'a> {
    /// The entry's output index byte.
    pub out_idx: u8,
    /// Each member's `(X25519, ML-KEM-768)` ciphertext, member order.
    pub member_cts: Vec<(&'a [u8; X25519_KEM_CT_LEN], &'a [u8])>,
    /// The encrypted key hashes and their tag.
    pub enc_key_hashes: &'a [u8],
}

/// One output as the chain carries it, as a member's scanner hands it over.
pub struct GroupOutputOnChain<'a> {
    /// The output's index in its transaction.
    pub output_index: u64,
    /// The output key `O`.
    pub output_key: &'a [u8; 32],
    /// The commitment `C`.
    pub commitment: &'a [u8; 32],
    /// The encrypted amount.
    pub enc_amount: &'a [u8; 8],
    /// The amount's tag.
    pub amount_tag: u8,
    /// The encrypted label.
    pub enc_label: &'a [u8; 8],
    /// The label's tag.
    pub label_tag: u8,
    /// The view tag.
    pub view_tag: u8,
    /// The output's `0x06` X25519 ciphertext.
    pub source_x25519_ct: &'a [u8; X25519_KEM_CT_LEN],
    /// The output's `0x06` ML-KEM-768 ciphertext.
    pub source_ml_kem_ct: &'a [u8],
    /// The output's `0x07` leaf entry, if the transaction carries one.
    pub leaf_entry: Option<&'a [u8; PQC_LEAF_ENTRY_LEN]>,
    /// The output's `0x0D` entry, if the transaction carries one.
    pub entry: Option<GroupEntryOnChain<'a>>,
}

/// Why an output paid to the group's keys is not a coin this member can
/// sign for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupRefusalReason {
    /// The transaction carries no `0x07` leaf entry for the output.
    LeafEntryAbsent,
    /// The transaction carries no `0x0D` entry for the output: it was paid
    /// to the group's keys as a solo output, whose leaf commits to a key
    /// every member can derive.
    EntryAbsent,
    /// The member check refused it.
    Check(MultisigReceiveError),
}

impl GroupRefusalReason {
    /// Who the output is lost to (R-35). A missing entry is the group's
    /// loss: no member can spend the output under the group's rules.
    #[must_use]
    pub const fn reach(self) -> RefusalReach {
        match self {
            Self::LeafEntryAbsent | Self::EntryAbsent => RefusalReach::Everyone,
            Self::Check(err) => err.reach(),
        }
    }
}

/// An output the group can spend and this member can sign for, with what
/// this crate checked about it. Only [`receive_group_output`] makes one.
pub struct GroupReceipt {
    output_index: u64,
    output_key: [u8; 32],
    commitment: [u8; 32],
    amount: u64,
    key_image: KeyImage,
    source_x25519_ct: [u8; X25519_KEM_CT_LEN],
    source_ml_kem_ct: Vec<u8>,
    leaf_point: [u8; PQC_LEAF_POINT_LEN],
    committed_form: MultisigCommittedForm,
    own_x25519_ct: [u8; X25519_KEM_CT_LEN],
    own_ml_kem_ct: Vec<u8>,
}

impl std::fmt::Debug for GroupReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupReceipt")
            .field("output_index", &self.output_index)
            .field("amount", &"[REDACTED]")
            .field("key_image", &self.key_image)
            .finish_non_exhaustive()
    }
}

impl GroupReceipt {
    /// The output's index in its transaction.
    #[must_use]
    pub fn output_index(&self) -> u64 {
        self.output_index
    }
    /// The output key `O`.
    #[must_use]
    pub fn output_key(&self) -> &[u8; 32] {
        &self.output_key
    }
    /// The commitment `C`, which opens at [`Self::amount`].
    #[must_use]
    pub fn commitment(&self) -> &[u8; 32] {
        &self.commitment
    }
    /// The amount, decrypted.
    #[must_use]
    pub fn amount(&self) -> u64 {
        self.amount
    }
    /// The key image `(ho + b)·Hp(O)`.
    #[must_use]
    pub fn key_image(&self) -> &KeyImage {
        &self.key_image
    }
    /// The output's `0x06` X25519 ciphertext, to the group's KEM key.
    #[must_use]
    pub fn source_x25519_ct(&self) -> &[u8; X25519_KEM_CT_LEN] {
        &self.source_x25519_ct
    }
    /// The output's `0x06` ML-KEM-768 ciphertext, to the group's KEM key.
    #[must_use]
    pub fn source_ml_kem_ct(&self) -> &[u8] {
        &self.source_ml_kem_ct
    }
    /// The leaf commitment point `CM`, as published.
    #[must_use]
    pub fn leaf_point(&self) -> &[u8; PQC_LEAF_POINT_LEN] {
        &self.leaf_point
    }
    /// The committed form the leaf binds.
    #[must_use]
    pub fn committed_form(&self) -> &MultisigCommittedForm {
        &self.committed_form
    }
    /// This member's own `0x0D` X25519 ciphertext.
    #[must_use]
    pub fn own_x25519_ct(&self) -> &[u8; X25519_KEM_CT_LEN] {
        &self.own_x25519_ct
    }
    /// This member's own `0x0D` ML-KEM-768 ciphertext.
    #[must_use]
    pub fn own_ml_kem_ct(&self) -> &[u8] {
        &self.own_ml_kem_ct
    }
}

/// An output paid to the group's keys that is not a coin this member can
/// sign for (R-35). Only [`receive_group_output`] makes one.
#[derive(Debug)]
pub struct GroupRefusal {
    output_index: u64,
    output_key: [u8; 32],
    commitment: [u8; 32],
    amount: u64,
    key_image: KeyImage,
    reason: GroupRefusalReason,
}

impl GroupRefusal {
    /// The output's index in its transaction.
    #[must_use]
    pub fn output_index(&self) -> u64 {
        self.output_index
    }
    /// The output key `O`.
    #[must_use]
    pub fn output_key(&self) -> &[u8; 32] {
        &self.output_key
    }
    /// The commitment `C`, which opens at [`Self::amount`].
    #[must_use]
    pub fn commitment(&self) -> &[u8; 32] {
        &self.commitment
    }
    /// The amount, decrypted.
    #[must_use]
    pub fn amount(&self) -> u64 {
        self.amount
    }
    /// The key image, by which a spend of the output is recognised.
    #[must_use]
    pub fn key_image(&self) -> &KeyImage {
        &self.key_image
    }
    /// The check that refused the output.
    #[must_use]
    pub fn reason(&self) -> GroupRefusalReason {
        self.reason
    }
    /// Who the output is lost to.
    #[must_use]
    pub fn reach(&self) -> RefusalReach {
        self.reason.reach()
    }
}

/// What one member's receive makes of an output the group's keys own.
#[derive(Debug)]
pub enum GroupReceived {
    /// The group can spend it and this member can sign for it.
    Coin(GroupReceipt),
    /// Paid to the group's keys, refused by a check.
    Refused(GroupRefusal),
}

/// Receive one output as one member (module docs). `None` when the output is
/// not the group's: the group's view key does not open it, its amount or
/// commitment do not check, or its recovered spend key is not the group's.
#[must_use]
pub fn receive_group_output(
    keys: &GroupScanKeys<'_>,
    member: &MultisigMemberView<'_>,
    output: &GroupOutputOnChain<'_>,
) -> Option<GroupReceived> {
    let recovered = scan_output_recover_with_ml_kem_dk(
        keys.view_x25519,
        keys.view_ml_kem,
        output.source_x25519_ct,
        output.source_ml_kem_ct,
        output.output_key,
        output.commitment,
        output.enc_amount,
        output.amount_tag,
        output.enc_label,
        output.label_tag,
        output.view_tag,
        output.output_index,
    )
    .ok()?;
    // Constant time: the recovered key derives from secret scan material.
    if !bool::from(recovered.recovered_spend_key.ct_eq(keys.spend_key)) {
        return None;
    }
    let hp = biased_hash_to_point(*output.output_key)
        .compress()
        .to_bytes();
    let key_image =
        compute_output_key_image(&recovered.combined_ss, output.output_index, keys.b, &hp)
            .ok()?
            .key_image;

    let refused = |reason| {
        Some(GroupReceived::Refused(GroupRefusal {
            output_index: output.output_index,
            output_key: *output.output_key,
            commitment: *output.commitment,
            amount: recovered.amount,
            key_image,
            reason,
        }))
    };
    let Some(published_leaf) = output.leaf_entry else {
        return refused(GroupRefusalReason::LeafEntryAbsent);
    };
    let Some(entry) = &output.entry else {
        return refused(GroupRefusalReason::EntryAbsent);
    };
    let n = u8::try_from(entry.member_cts.len()).ok();
    let own = entry.member_cts.get(usize::from(member.member_index));
    let (Some(n), Some(&(own_x25519_ct, own_ml_kem_ct))) = (n, own) else {
        return refused(GroupRefusalReason::Check(MultisigReceiveError::GroupSize));
    };
    let committed_form = match open_multisig_entry(
        &recovered.combined_ss,
        output.output_index,
        member,
        &MultisigEntryView {
            out_idx: entry.out_idx,
            n,
            own_x25519_ct,
            own_ml_kem_ct,
            enc_key_hashes: entry.enc_key_hashes,
        },
        published_leaf,
    ) {
        Ok(form) => form,
        Err(err) => return refused(GroupRefusalReason::Check(err)),
    };
    let leaf_point: [u8; PQC_LEAF_POINT_LEN] = published_leaf[..PQC_LEAF_POINT_LEN]
        .try_into()
        .expect("the entry starts with the point");
    Some(GroupReceived::Coin(GroupReceipt {
        output_index: output.output_index,
        output_key: *output.output_key,
        commitment: *output.commitment,
        // A copy out of the wiped recovery, as the solo scan's: the amount
        // is the wallet's to show.
        amount: recovered.amount,
        key_image,
        source_x25519_ct: *output.source_x25519_ct,
        source_ml_kem_ct: output.source_ml_kem_ct.to_vec(),
        leaf_point,
        committed_form,
        own_x25519_ct: *own_x25519_ct,
        own_ml_kem_ct: own_ml_kem_ct.to_vec(),
    }))
}

#[cfg(test)]
#[path = "multisig_receive_tests.rs"]
mod tests;
