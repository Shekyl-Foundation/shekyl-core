// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A group wallet's ledger (`docs/PQC_MULTISIG.md` §8; R-30, R-35, R-36).
//!
//! A group wallet and a solo wallet are different wallets (R-30), and their
//! ledgers are different types. A solo ledger ([`crate::WalletLedger`])
//! holds solo transfers; a group ledger ([`GroupWalletLedger`]) holds what
//! a member's scanner found paid to the group, as [`GroupOutput`]s. Neither
//! converts to the other, and the solo ledger is unchanged by this module
//! (R-36).
//!
//! A group output is one of two records:
//!
//! - a [`GroupCoin`]: the group can spend it and this member can sign for
//!   it. Its fields are private; it is made only from the receipt
//!   `shekyl-crypto-pq`'s receive check returns
//!   ([`shekyl_crypto_pq::multisig_receive::GroupReceipt`]), which only that
//!   crate can make, or read back from the wallet's own sealed file. It
//!   holds no secret: the per-output secrets are re-derived from its `0x06`
//!   ciphertext when it is spent, and its membership path comes from the
//!   curve tree then (R-26).
//! - a [`RefusedGroupOutput`]: paid to the group's keys and refused by a
//!   check, with the reason and who it is lost to (R-35). Lost to
//!   everyone, it counts in no balance. Lost to this member only, it is
//!   group funds this member cannot sign for.
//!
//! A group ledger has no staking and no send-journal parts: a group wallet
//! neither stakes nor sends alone (R-32). Its spends are ceremonies, whose
//! durable records live in `.wallet.multisig`.
//!
//! # Versions (rule 142)
//!
//! - [`GROUP_LEDGER_BLOCK_VERSION`] ↔ `schemas/group_ledger_block.snap`
//! - [`GROUP_WALLET_LEDGER_FORMAT_VERSION`] ↔ `schemas/group_wallet_ledger.snap`
//!
//! Version 1 of each is this layout.

use std::collections::HashSet;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use shekyl_crypto_pq::kem::HybridCiphertext;
use shekyl_crypto_pq::key_image::KeyImage;
use shekyl_crypto_pq::multisig::MultisigCommittedForm;
use shekyl_crypto_pq::multisig_output::{MultisigReceiveError, RefusalReach};
use shekyl_crypto_pq::multisig_receive::{GroupReceipt, GroupRefusal, GroupRefusalReason};
use std::ops::Range;

use shekyl_types::{BlockHash, BlockHeight, GlobalOutputIndex, OutputIndexInTx, TxHash};
use shekyl_units::AtomicUnits;

use crate::bookkeeping_block::BookkeepingBlock;
use crate::error::WalletLedgerError;
use crate::ledger_block::{BlockchainTip, ReorgBlocks, ScanDerived};
use crate::sync_state_block::SyncStateBlock;
use crate::transfer::UnspendableReason;
use crate::tx_meta_block::TxMetaBlock;

/// Version of [`GroupLedgerBlock`]'s layout. Bumps with
/// `schemas/group_ledger_block.snap`; a file of another version is refused,
/// not migrated (pre-genesis, rule 15).
pub const GROUP_LEDGER_BLOCK_VERSION: u32 = 1;

/// Version of [`GroupWalletLedger`]'s layout. Bumps with
/// `schemas/group_wallet_ledger.snap`.
pub const GROUP_WALLET_LEDGER_FORMAT_VERSION: u32 = 1;

/// Stable name of the load-time check that a group ledger's outputs are a
/// set: one output key, and one key image, each.
pub const INV_GROUP_OUTPUTS_UNIQUE: &str = "group-outputs-unique";

/// Where an output sits on the chain: what the scanner adds to a receipt,
/// which `shekyl-crypto-pq` cannot see.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainPlace {
    /// The transaction that carries the output.
    pub tx_hash: TxHash,
    /// The output's chain-wide index, by which an intent names it.
    pub global_output_index: GlobalOutputIndex,
    /// The block the output is in.
    pub block_height: BlockHeight,
    /// The first height at which the output may be spent.
    pub eligible_height: BlockHeight,
}

/// The spend that consumed an output, as the member's scan saw it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, postcard_schema::Schema)]
pub struct SpentAt {
    /// The block the spend is in.
    pub height: BlockHeight,
    /// The spending transaction.
    pub tx_hash: TxHash,
}

/// The committed form, persisted as its canonical bytes
/// ([`MultisigCommittedForm::to_bytes`]) and read back through
/// [`MultisigCommittedForm::from_bytes`], which refuses a form that does
/// not parse. It wipes on drop either way.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CommittedForm(MultisigCommittedForm);

impl Serialize for CommittedForm {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // A slice serializes as postcard's length-prefixed sequence of
        // bytes, the same wire as the `Vec<u8>` the schema names.
        self.0.to_bytes().as_slice().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CommittedForm {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = zeroize::Zeroizing::new(Vec::<u8>::deserialize(deserializer)?);
        MultisigCommittedForm::from_bytes(&bytes)
            .map(Self)
            .map_err(|_| serde::de::Error::custom("a committed form that does not parse"))
    }
}

impl postcard_schema::Schema for CommittedForm {
    const SCHEMA: &'static postcard_schema::schema::NamedType =
        &postcard_schema::schema::NamedType {
            name: "MultisigCommittedForm",
            ty: <Vec<u8> as postcard_schema::Schema>::SCHEMA.ty,
        };
}

/// An output the group can spend and this member can sign for (module
/// docs). Made only from a receipt, or read back from the wallet's own
/// sealed file. `Clone` copies public values and the committed form, which
/// wipes on drop in every copy.
#[derive(Clone, Debug, Serialize, Deserialize, postcard_schema::Schema)]
pub struct GroupCoin {
    tx_hash: TxHash,
    internal_output_index: OutputIndexInTx,
    global_output_index: GlobalOutputIndex,
    block_height: BlockHeight,
    eligible_height: BlockHeight,
    amount: AtomicUnits,
    output_key: [u8; 32],
    commitment: [u8; 32],
    key_image: KeyImage,
    source_ciphertext: HybridCiphertext,
    leaf_point: [u8; 32],
    committed_form: CommittedForm,
    own_ciphertext: HybridCiphertext,
    spent: Option<SpentAt>,
}

impl GroupCoin {
    /// The coin `receipt` attests, at `place` on the chain.
    #[must_use]
    pub fn received(receipt: &GroupReceipt, place: ChainPlace) -> Self {
        Self {
            tx_hash: place.tx_hash,
            internal_output_index: OutputIndexInTx::from_raw(receipt.output_index()),
            global_output_index: place.global_output_index,
            block_height: place.block_height,
            eligible_height: place.eligible_height,
            amount: AtomicUnits::from_raw(receipt.amount()),
            output_key: *receipt.output_key(),
            commitment: *receipt.commitment(),
            key_image: *receipt.key_image(),
            source_ciphertext: HybridCiphertext {
                x25519: *receipt.source_x25519_ct(),
                ml_kem: receipt.source_ml_kem_ct().to_vec(),
            },
            leaf_point: *receipt.leaf_point(),
            committed_form: CommittedForm(receipt.committed_form().clone()),
            own_ciphertext: HybridCiphertext {
                x25519: *receipt.own_x25519_ct(),
                ml_kem: receipt.own_ml_kem_ct().to_vec(),
            },
            spent: None,
        }
    }

    /// The transaction that carries the output.
    #[must_use]
    pub fn tx_hash(&self) -> &TxHash {
        &self.tx_hash
    }
    /// The output's index in its transaction (its derivations bind it).
    #[must_use]
    pub fn internal_output_index(&self) -> OutputIndexInTx {
        self.internal_output_index
    }
    /// The output's chain-wide index, by which an intent names it.
    #[must_use]
    pub fn global_output_index(&self) -> GlobalOutputIndex {
        self.global_output_index
    }
    /// The block the output is in.
    #[must_use]
    pub fn block_height(&self) -> BlockHeight {
        self.block_height
    }
    /// The first height at which the output may be spent.
    #[must_use]
    pub fn eligible_height(&self) -> BlockHeight {
        self.eligible_height
    }
    /// The amount, which the commitment opens at.
    #[must_use]
    pub fn amount(&self) -> AtomicUnits {
        self.amount
    }
    /// The output key `O`.
    #[must_use]
    pub fn output_key(&self) -> &[u8; 32] {
        &self.output_key
    }
    /// The commitment `C`.
    #[must_use]
    pub fn commitment(&self) -> &[u8; 32] {
        &self.commitment
    }
    /// The key image, by which a spend of the coin is recognised.
    #[must_use]
    pub fn key_image(&self) -> &KeyImage {
        &self.key_image
    }
    /// The output's `0x06` ciphertext, to the group's KEM key: the spend
    /// re-derives the output's secrets from it.
    #[must_use]
    pub fn source_ciphertext(&self) -> &HybridCiphertext {
        &self.source_ciphertext
    }
    /// The leaf commitment point `CM`, as published.
    #[must_use]
    pub fn leaf_point(&self) -> &[u8; 32] {
        &self.leaf_point
    }
    /// The committed form the output's leaf binds.
    #[must_use]
    pub fn committed_form(&self) -> &MultisigCommittedForm {
        &self.committed_form.0
    }
    /// This member's own `0x0D` ciphertext: its per-output signing key
    /// comes from it.
    #[must_use]
    pub fn own_ciphertext(&self) -> &HybridCiphertext {
        &self.own_ciphertext
    }
    /// The spend that consumed the coin, once the scan has seen it.
    #[must_use]
    pub fn spent(&self) -> Option<SpentAt> {
        self.spent
    }
    /// Record the spend the scan saw.
    pub fn mark_spent(&mut self, at: SpentAt) {
        self.spent = Some(at);
    }
    /// Forget a spend a reorg undid.
    pub fn clear_spent(&mut self) {
        self.spent = None;
    }
}

/// Who a refused group output is lost to (R-35), as persisted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, postcard_schema::Schema)]
pub enum GroupRefusalKind {
    /// No member can spend it. It counts in no balance.
    LostToEveryone,
    /// The group can spend it and this member cannot sign for it. It is
    /// group funds: it counts in the group's balance, and this member is
    /// not a signer of an intent that spends it.
    LostToThisMember,
}

impl From<RefusalReach> for GroupRefusalKind {
    fn from(reach: RefusalReach) -> Self {
        match reach {
            RefusalReach::Everyone => Self::LostToEveryone,
            RefusalReach::ThisMember => Self::LostToThisMember,
        }
    }
}

/// The persisted reason for a refusal: one [`UnspendableReason`] per check,
/// so the ledger names the check that failed. The match is total, so a new
/// refusal cannot collapse into a neighbour.
#[must_use]
pub fn unspendable_reason(reason: GroupRefusalReason) -> UnspendableReason {
    match reason {
        GroupRefusalReason::LeafEntryAbsent => UnspendableReason::PqcLeafEntryAbsent,
        GroupRefusalReason::EntryAbsent => UnspendableReason::MultisigEntryAbsent,
        GroupRefusalReason::Check(err) => match err {
            MultisigReceiveError::GroupSize => UnspendableReason::MultisigGroupSize,
            MultisigReceiveError::HashesUndecryptable => {
                UnspendableReason::MultisigHashesUndecryptable
            }
            MultisigReceiveError::MemberDecap => UnspendableReason::MultisigMemberDecap,
            MultisigReceiveError::MemberKeyHash => UnspendableReason::MultisigMemberKeyHash,
            MultisigReceiveError::DuplicateKeyHash => UnspendableReason::MultisigDuplicateKeyHash,
            MultisigReceiveError::LeafMismatch => UnspendableReason::MultisigLeafMismatch,
        },
    }
}

/// An output paid to the group's keys that a check refused (R-35). Never a
/// group coin and never a solo transfer.
#[derive(Debug, Serialize, Deserialize, postcard_schema::Schema)]
pub struct RefusedGroupOutput {
    tx_hash: TxHash,
    internal_output_index: OutputIndexInTx,
    global_output_index: GlobalOutputIndex,
    block_height: BlockHeight,
    amount: AtomicUnits,
    output_key: [u8; 32],
    commitment: [u8; 32],
    key_image: KeyImage,
    reason: UnspendableReason,
    kind: GroupRefusalKind,
    spent: Option<SpentAt>,
}

impl RefusedGroupOutput {
    /// The refusal `refusal` records, at `place` on the chain.
    #[must_use]
    pub fn refused(refusal: &GroupRefusal, place: ChainPlace) -> Self {
        Self {
            tx_hash: place.tx_hash,
            internal_output_index: OutputIndexInTx::from_raw(refusal.output_index()),
            global_output_index: place.global_output_index,
            block_height: place.block_height,
            amount: AtomicUnits::from_raw(refusal.amount()),
            output_key: *refusal.output_key(),
            commitment: *refusal.commitment(),
            key_image: *refusal.key_image(),
            reason: unspendable_reason(refusal.reason()),
            kind: refusal.reach().into(),
            spent: None,
        }
    }

    /// The transaction that carries the output.
    #[must_use]
    pub fn tx_hash(&self) -> &TxHash {
        &self.tx_hash
    }
    /// The output's index in its transaction.
    #[must_use]
    pub fn internal_output_index(&self) -> OutputIndexInTx {
        self.internal_output_index
    }
    /// The output's chain-wide index.
    #[must_use]
    pub fn global_output_index(&self) -> GlobalOutputIndex {
        self.global_output_index
    }
    /// The block the output is in.
    #[must_use]
    pub fn block_height(&self) -> BlockHeight {
        self.block_height
    }
    /// The amount, which the commitment opens at.
    #[must_use]
    pub fn amount(&self) -> AtomicUnits {
        self.amount
    }
    /// The output key `O`.
    #[must_use]
    pub fn output_key(&self) -> &[u8; 32] {
        &self.output_key
    }
    /// The commitment `C`.
    #[must_use]
    pub fn commitment(&self) -> &[u8; 32] {
        &self.commitment
    }
    /// The key image, by which a spend of the output is recognised.
    #[must_use]
    pub fn key_image(&self) -> &KeyImage {
        &self.key_image
    }
    /// The check that refused the output.
    #[must_use]
    pub fn reason(&self) -> UnspendableReason {
        self.reason
    }
    /// Who the output is lost to.
    #[must_use]
    pub fn kind(&self) -> GroupRefusalKind {
        self.kind
    }
    /// Whether the output counts in the group's balance while unspent:
    /// only an output lost to this member alone is still group funds.
    #[must_use]
    pub fn counts_in_group_balance(&self) -> bool {
        self.kind == GroupRefusalKind::LostToThisMember
    }
    /// The spend that consumed the output, once the scan has seen it.
    #[must_use]
    pub fn spent(&self) -> Option<SpentAt> {
        self.spent
    }
    /// Record the spend the scan saw.
    pub fn mark_spent(&mut self, at: SpentAt) {
        self.spent = Some(at);
    }
    /// Forget a spend a reorg undid.
    pub fn clear_spent(&mut self) {
        self.spent = None;
    }
}

/// One output a member's scan found paid to the group (module docs).
#[derive(Debug, Serialize, Deserialize, postcard_schema::Schema)]
pub enum GroupOutput {
    /// The group can spend it and this member can sign for it.
    Coin(GroupCoin),
    /// A check refused it.
    Refused(RefusedGroupOutput),
}

impl GroupOutput {
    /// The output key `O`.
    #[must_use]
    pub fn output_key(&self) -> &[u8; 32] {
        match self {
            Self::Coin(coin) => coin.output_key(),
            Self::Refused(refused) => refused.output_key(),
        }
    }

    /// The key image, by which a spend of the output is recognised.
    #[must_use]
    pub fn key_image(&self) -> &KeyImage {
        match self {
            Self::Coin(coin) => coin.key_image(),
            Self::Refused(refused) => refused.key_image(),
        }
    }

    fn mark_spent(&mut self, at: SpentAt) {
        match self {
            Self::Coin(coin) => coin.mark_spent(at),
            Self::Refused(refused) => refused.mark_spent(at),
        }
    }
}

/// A group wallet's scan-derived ledger: the group's outputs, the scan
/// pointer and the reorg window. The solo counterpart is
/// [`crate::LedgerBlock`]; the tip and the window are the same types.
#[derive(Debug, Serialize, Deserialize, postcard_schema::Schema)]
pub struct GroupLedgerBlock {
    /// Always [`GROUP_LEDGER_BLOCK_VERSION`] on construction; refused on
    /// load if it does not match.
    pub block_version: u32,
    /// The outputs the member's scan found paid to the group.
    pub outputs: Vec<GroupOutput>,
    /// The scan pointer.
    pub tip: BlockchainTip,
    /// The `(height, hash)` window for reorg detection.
    pub reorg_blocks: ReorgBlocks,
}

impl ScanDerived for Vec<GroupOutput> {}
impl ScanDerived for GroupOutput {}

/// C7 (`docs/design/WALLET_SEND_RECORD.md` §2), as for the solo block: a
/// rescan rebuilds this block wholesale, so every field holds a
/// scan-derived type. One line per field, in declaration order.
const _GROUP_LEDGER_BLOCK_HOLDS_ONLY_SCAN_DERIVED_TYPES: () = {
    const fn assert_scan_derived<T: ScanDerived>() {}
    assert_scan_derived::<u32>(); // block_version
    assert_scan_derived::<Vec<GroupOutput>>(); // outputs
    assert_scan_derived::<BlockchainTip>(); // tip
    assert_scan_derived::<ReorgBlocks>(); // reorg_blocks
};

impl GroupLedgerBlock {
    /// A fresh, empty block at the current version.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            block_version: GROUP_LEDGER_BLOCK_VERSION,
            outputs: Vec::new(),
            tip: BlockchainTip::default(),
            reorg_blocks: ReorgBlocks::default(),
        }
    }

    /// Version gate.
    pub fn check_version(&self) -> Result<(), WalletLedgerError> {
        crate::version_gate::gate_version(
            self.block_version,
            "group ledger",
            GROUP_LEDGER_BLOCK_VERSION,
        )
    }

    /// Append one scanned block's group outputs and advance the scan
    /// pointer and the reorg window to it, as the solo ledger's ingest does.
    /// An output whose key the ledger already holds is skipped: two outputs
    /// with one key are the burning bug, and only one can be spent. Returns
    /// the range of `outputs` the block appended.
    pub fn ingest_block(
        &mut self,
        block_height: BlockHeight,
        block_hash: BlockHash,
        outputs: Vec<GroupOutput>,
    ) -> Range<usize> {
        let start = self.outputs.len();
        for output in outputs {
            if self.outputs.iter().any(|held| {
                held.output_key() == output.output_key() || held.key_image() == output.key_image()
            }) {
                tracing::warn!(
                    "duplicate group output detected (potential burning bug) -- skipping"
                );
                continue;
            }
            self.outputs.push(output);
        }
        self.tip.synced_height = block_height;
        self.tip.tip_hash = Some(block_hash);
        self.reorg_blocks.blocks.push((block_height, block_hash));
        start..self.outputs.len()
    }

    /// Mark the output whose key image is `key_image` spent at `at`.
    /// Returns whether the ledger holds such an output.
    pub fn mark_spent(&mut self, key_image: &KeyImage, at: SpentAt) -> bool {
        match self
            .outputs
            .iter_mut()
            .find(|output| output.key_image() == key_image)
        {
            Some(output) => {
                output.mark_spent(at);
                true
            }
            None => false,
        }
    }

    /// The group's coins: the only thing a group spend selects from. A solo
    /// transfer is not a group coin, and no conversion makes one.
    ///
    /// ```compile_fail
    /// // A group spend cannot select a solo transfer.
    /// fn select(coins: &[&shekyl_engine_state::GroupCoin]) {}
    /// let solo = shekyl_engine_state::WalletLedger::empty();
    /// let transfers: Vec<&shekyl_engine_state::TransferDetails> =
    ///     solo.ledger.transfers.iter().collect();
    /// select(&transfers);
    /// ```
    pub fn coins(&self) -> impl Iterator<Item = &GroupCoin> {
        self.outputs.iter().filter_map(|output| match output {
            GroupOutput::Coin(coin) => Some(coin),
            GroupOutput::Refused(_) => None,
        })
    }

    /// The group's unspent coins.
    pub fn unspent_coins(&self) -> impl Iterator<Item = &GroupCoin> {
        self.coins().filter(|coin| coin.spent().is_none())
    }

    /// The outputs a check refused.
    pub fn refused(&self) -> impl Iterator<Item = &RefusedGroupOutput> {
        self.outputs.iter().filter_map(|output| match output {
            GroupOutput::Refused(refused) => Some(refused),
            GroupOutput::Coin(_) => None,
        })
    }

    /// The outputs are a set. A repeated output key is the burning bug,
    /// and a repeated key image is the same spend recorded twice. The scan
    /// skips either as it arrives ([`Self::ingest_block`]); a file that
    /// already holds one is refused here, on open and on save.
    pub fn check_unique_outputs(&self) -> Result<(), WalletLedgerError> {
        let mut output_keys = HashSet::with_capacity(self.outputs.len());
        let mut key_images = HashSet::with_capacity(self.outputs.len());
        for output in &self.outputs {
            if !output_keys.insert(*output.output_key()) {
                return Err(duplicate_output("two group outputs share an output key"));
            }
            if !key_images.insert(*output.key_image()) {
                return Err(duplicate_output("two group outputs share a key image"));
            }
        }
        Ok(())
    }
}

fn duplicate_output(detail: &str) -> WalletLedgerError {
    WalletLedgerError::GroupInvariantFailed {
        invariant: INV_GROUP_OUTPUTS_UNIQUE,
        detail: detail.to_owned(),
    }
}

/// A group wallet's ledger (module docs): its scan-derived block and the
/// bookkeeping, per-transaction and sync blocks a solo ledger also has. No
/// staking and no send journal (R-32): they are absent from the type, not
/// empty in it.
///
/// ```compile_fail
/// // A group ledger has no staking block.
/// let ledger = shekyl_engine_state::GroupWalletLedger::empty();
/// let _ = &ledger.staking;
/// ```
///
/// ```compile_fail
/// // A group ledger has no send journal.
/// let ledger = shekyl_engine_state::GroupWalletLedger::empty();
/// let _ = &ledger.send_journal;
/// ```
#[derive(Debug, Serialize, Deserialize, postcard_schema::Schema)]
pub struct GroupWalletLedger {
    /// Always [`GROUP_WALLET_LEDGER_FORMAT_VERSION`] on construction;
    /// refused on load if it does not match.
    pub format_version: u32,
    /// The group's outputs, the scan pointer and the reorg window.
    pub ledger: GroupLedgerBlock,
    /// The primary label and the address book.
    pub bookkeeping: BookkeepingBlock,
    /// Per-transaction notes and attributes.
    pub tx_meta: TxMetaBlock,
    /// The scan anchor and the daemon context.
    pub sync_state: SyncStateBlock,
}

impl GroupWalletLedger {
    /// A fresh, empty group ledger at the current versions.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            format_version: GROUP_WALLET_LEDGER_FORMAT_VERSION,
            ledger: GroupLedgerBlock::empty(),
            bookkeeping: BookkeepingBlock::empty(),
            tx_meta: TxMetaBlock::empty(),
            sync_state: SyncStateBlock::empty(),
        }
    }

    /// Serialize to postcard bytes.
    pub fn to_postcard_bytes(&self) -> Result<Vec<u8>, WalletLedgerError> {
        postcard::to_allocvec(self).map_err(Into::into)
    }

    /// Deserialize from postcard bytes produced by
    /// [`Self::to_postcard_bytes`]. The format version is read and gated
    /// before the body is decoded, as the solo ledger's is, so a file of
    /// another version names its version instead of failing as corruption.
    pub fn from_postcard_bytes(bytes: &[u8]) -> Result<Self, WalletLedgerError> {
        let (file_version, _) = postcard::take_from_bytes::<u32>(bytes)?;
        Self::gate_format_version(file_version)?;
        let ledger: Self = postcard::from_bytes(bytes)?;
        ledger.check_all_block_versions()?;
        ledger.check_invariants()?;
        Ok(ledger)
    }

    fn gate_format_version(file: u32) -> Result<(), WalletLedgerError> {
        if file != GROUP_WALLET_LEDGER_FORMAT_VERSION {
            return Err(WalletLedgerError::UnsupportedGroupFormatVersion {
                file,
                binary: GROUP_WALLET_LEDGER_FORMAT_VERSION,
            });
        }
        Ok(())
    }

    /// The outputs are a set ([`GroupLedgerBlock::check_unique_outputs`]).
    pub fn check_invariants(&self) -> Result<(), WalletLedgerError> {
        self.ledger.check_unique_outputs()
    }

    /// Every block's version gate, in declaration order.
    pub fn check_all_block_versions(&self) -> Result<(), WalletLedgerError> {
        Self::gate_format_version(self.format_version)?;
        self.ledger.check_version()?;
        self.bookkeeping.check_version()?;
        self.tx_meta.check_version()?;
        self.sync_state.check_version()?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "group_ledger_tests.rs"]
mod tests;
