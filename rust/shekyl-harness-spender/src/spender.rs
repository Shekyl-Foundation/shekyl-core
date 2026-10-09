// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The wallet-side tree over a chain of mined blocks and the spends it
//! sources — the crate's body; the crate docs carry the argument for why
//! the tree is the wallet's and not the store's.

use std::collections::{BTreeMap, BTreeSet};

use shekyl_chain_rules::newest_admissible_reference;
use shekyl_crypto_pq::derivation::derive_pqc_public_key;
use shekyl_crypto_pq::output::{
    compute_output_key_image, construct_output, recover_combined_ss, scan_output, OutputData,
};
use shekyl_curve_tree::{
    AssembleInput, BlockLeaves, CurveTreeClient, Gindex, RawOutput, ReferenceBlock, TargetKind,
    TxLeafInputs,
};
use shekyl_fcmp::proof::{self, ShekylFcmpProof};
use shekyl_fcmp::PqcKeyScalar;
use shekyl_tx_builder::{
    open_spend, sign_transaction_with_terms, tx_prefix_hash_from_parts_with_extra, AuthSlots,
    InputTerm, LeafEntry, OutputInfo, OutputTerm, SpendInput, SpendLayout, TreeContext,
};
use shekyl_types::{BlockHash, BlockHeight, CurveTreeRoot, KeyImage};
use shekyl_units::AtomicUnits;
use shekyl_wire::tx_extra::{
    admitted_leaf_blob, parse, pqc_kem_per_output, pqc_leaf_entries_per_output, serialize,
    TxExtraField,
};
use shekyl_wire::{Ct, Input, Transaction};

use crate::bond::PostedBond;
use crate::{MinedBlock, MinerWallet, Owner, Recipient};

/// An output sourced for spending: the signer's input, its key image, and
/// the tree context the path was assembled in.
pub struct Sourced {
    /// The tx-builder's view of the output, path included.
    pub input: SpendInput,
    /// `I = x·Hp(O)`.
    pub key_image: shekyl_types::KeyImage,
    /// The reference the path was assembled against.
    pub tree: TreeContext,
}

/// A watched output found in a pushed block: the transaction that listed
/// it, its index in that transaction, and its global index in the tree.
struct Located {
    tx: Transaction,
    index_in_tx: u64,
    gindex: u64,
}

/// The wallet-side tree over a chain's mined blocks, and the facts a
/// spend of one of its coinbases needs (crate docs).
pub struct Spender {
    client: CurveTreeClient,
    /// `hashes[h]` — block `h`'s identity (the reference block's).
    hashes: Vec<BlockHash>,
    /// `coinbases[h]` — block `h`'s miner transaction.
    coinbases: Vec<Transaction>,
    /// `first_gid[h]` — the global index of block `h`'s first output
    /// (its coinbase's), dense in connect order as the store keys them.
    first_gid: Vec<u64>,
    /// The next global index — the count of outputs pushed so far.
    next: u64,
    /// Output keys to register with the tree when a pushed block lists
    /// them ([`Self::own`]).
    watched: BTreeSet<[u8; 32]>,
    /// Watched outputs a pushed block has listed, by output key.
    located: BTreeMap<[u8; 32], Located>,
}

impl Spender {
    /// The tree after every block of `mined`, in order, from genesis.
    #[must_use]
    pub fn over<B: MinedBlock>(mined: &[B]) -> Self {
        let mut spender = Self {
            client: CurveTreeClient::new(),
            hashes: Vec::new(),
            coinbases: Vec::new(),
            first_gid: Vec::new(),
            next: 0,
            watched: BTreeSet::new(),
            located: BTreeMap::new(),
        };
        for block in mined {
            spender.push(block);
        }
        spender
    }

    /// Watch for `output_key`: when a pushed block lists it, the tree
    /// registers it as owned (so its path material is captured) and
    /// [`Self::owned_input`] can source it. Call before pushing the block
    /// that carries it, as a wallet names what its scan found before the
    /// block is folded in.
    pub fn own(&mut self, output_key: [u8; 32]) {
        self.watched.insert(output_key);
    }

    /// Feed the next mined block to the wallet-side tree, exactly as the
    /// engine's ingest would: the miner transaction first, then the listed
    /// bodies, each with its `0x07` leaf field.
    pub fn push<B: MinedBlock>(&mut self, mined: &B) {
        let height = mined.height().to_raw();
        assert_eq!(
            height,
            self.hashes.len() as u64,
            "blocks are pushed consecutively from genesis"
        );
        let miner_transaction = mined.miner_transaction();
        let mut leaf_blobs: Vec<Vec<u8>> = Vec::new();
        let mut raw: Vec<Vec<RawOutput>> = Vec::new();
        let txs: Vec<&Transaction> = std::iter::once(miner_transaction)
            .chain(mined.listed().iter())
            .collect();
        for tx in &txs {
            let fields = parse(&tx.prefix.extra).expect("a mined transaction's extra parses");
            leaf_blobs.push(
                admitted_leaf_blob(&fields, tx.prefix.outputs.len()).expect("admitted leaf field"),
            );
            let commitments = match &tx.ct {
                Ct::Null(base) | Ct::Fcmp { base, .. } => &base.commitments,
            };
            raw.push(
                tx.prefix
                    .outputs
                    .iter()
                    .zip(commitments)
                    .map(|(output, commitment)| RawOutput {
                        output_key: shekyl_curve_tree::OneTimePubkey::from_bytes(output.key),
                        commitment: Some(shekyl_curve_tree::CommitmentBytes::from_bytes(
                            *commitment,
                        )),
                        target: TargetKind::TaggedKey,
                    })
                    .collect(),
            );
        }
        let inputs: Vec<TxLeafInputs<'_>> = txs
            .iter()
            .enumerate()
            .map(|(i, _)| TxLeafInputs {
                is_miner: i == 0,
                tx_hash: None,
                leaf_entry_blob: Some(leaf_blobs[i].as_slice()),
                outputs: raw[i].as_slice(),
            })
            .collect();
        // The miner's wallet names its coinbase before the block is folded
        // in, as a wallet's refresh does with what its scan found: the tree
        // captures path material only for outputs it has been told about,
        // and told now, this one is captured as its chunks close. The store
        // keys outputs dense in connect order, so the coinbase's index is
        // the running count — and every watched output the block lists is
        // named alongside it, at its own dense index.
        let mut owned = vec![(
            Gindex::from_raw(self.next),
            shekyl_curve_tree::OneTimePubkey::from_bytes(miner_transaction.prefix.outputs[0].key),
        )];
        let mut gindex = self.next;
        for tx in &txs {
            for (index_in_tx, output) in tx.prefix.outputs.iter().enumerate() {
                if self.watched.remove(&output.key) {
                    owned.push((
                        Gindex::from_raw(gindex),
                        shekyl_curve_tree::OneTimePubkey::from_bytes(output.key),
                    ));
                    self.located.insert(
                        output.key,
                        Located {
                            tx: (*tx).clone(),
                            index_in_tx: index_in_tx as u64,
                            gindex,
                        },
                    );
                }
                gindex += 1;
            }
        }
        self.client
            .sync_owned(&owned)
            .expect("the wallet-side tree registers the coinbase and the watched outputs");
        self.client
            .ingest_block(BlockLeaves {
                height: shekyl_curve_tree::BlockHeight::from_raw(height),
                txs: &inputs,
            })
            .expect("the wallet-side tree ingests a mined block");
        // The store keys outputs dense in connect order (SOK-2): this
        // block's coinbase output is the next index, and the block's outputs
        // advance the counter.
        self.first_gid.push(self.next);
        self.next += txs
            .iter()
            .map(|tx| tx.prefix.outputs.len() as u64)
            .sum::<u64>();
        self.hashes.push(mined.hash());
        self.coinbases.push(miner_transaction.clone());
    }

    /// [`Self::push`], then hold the ingested root equal to `expected`.
    ///
    /// `expected` is the root the other tree recorded going into this
    /// height: the store header's `curve_tree_root`, or the validator
    /// tree's root going into the height. A disagreement is the block
    /// that opened it.
    pub fn push_agreeing<B: MinedBlock>(&mut self, mined: &B, expected: CurveTreeRoot) {
        let height = mined.height();
        self.push(mined);
        assert_eq!(
            self.root_at(height),
            expected,
            "height {height:?}: the wallet-side tree agrees on the root going in"
        );
    }

    /// The wallet-side tree's root going into `height` — the state the
    /// header at `height` commits to, keyed as the store's `root_at` is.
    #[must_use]
    pub fn root_at(&self, height: BlockHeight) -> CurveTreeRoot {
        self.client
            .root_at(shekyl_curve_tree::BlockHeight::from_raw(height.to_raw()))
            .expect("a height at or below the ingested tip")
    }

    /// A spend of block `height`'s coinbase, listed in the block connecting
    /// at `connecting`, paying `fee` and the rest back to the miner in two
    /// outputs. Anchored at the newest admissible reference (CEN-I11),
    /// whose root is the wallet-side tree's at that height.
    #[must_use]
    pub fn spend_coinbase(
        &self,
        wallet: &MinerWallet,
        height: BlockHeight,
        connecting: BlockHeight,
        fee: u64,
    ) -> Transaction {
        self.spend_coinbase_posting(wallet, height, connecting, fee, None)
    }

    /// [`Self::spend_coinbase`] with an archival bond post riding it
    /// (DRS-E4 commit 4; the ingest's `scenario_archival`): the post is the prefix's one
    /// extra input, its term sits on the side its kind fixes — a credit is a
    /// sink the outputs shrink by, a debit a source they grow by — and the
    /// bond slot is the last `pqc_auths` entry, signed by the key the post
    /// names over the same phase-1 payload hash the spend's own slot signs.
    /// That is `shekyl-engine-core`'s `bond_post_assemble` shape; with no
    /// post the bytes are [`Self::spend_coinbase`]'s exactly (the `_with_*`
    /// builders are the plain ones with empty extras).
    #[must_use]
    pub fn spend_coinbase_posting(
        &self,
        wallet: &MinerWallet,
        height: BlockHeight,
        connecting: BlockHeight,
        fee: u64,
        bond: Option<&PostedBond<'_>>,
    ) -> Transaction {
        self.spend_coinbase_to(wallet, height, connecting, fee, bond, wallet.recipient())
    }

    /// Source an output for spending: the scanner's recovery of what `tx`'s
    /// output `index_in_tx` holds for `owner`, its key image, and its path
    /// from the wallet-side tree at the newest admissible reference for
    /// `connecting` (CEN-I11).
    fn source(
        &self,
        owner: &Owner<'_>,
        tx: &Transaction,
        index_in_tx: u64,
        gindex: u64,
        connecting: BlockHeight,
    ) -> Sourced {
        let at = usize::try_from(index_in_tx).expect("small");
        let fields = parse(&tx.prefix.extra).expect("the transaction's extra parses");
        let kem_blob = fields
            .iter()
            .find_map(|f| match f {
                TxExtraField::PqcKemCiphertext(bytes) => Some(bytes.clone()),
                _ => None,
            })
            .expect("a paying transaction carries its KEM ciphertexts");
        let kem = pqc_kem_per_output(&kem_blob).expect("one ciphertext per output");
        let kem = &kem[at];
        let output = &tx.prefix.outputs[at];
        let base = match &tx.ct {
            Ct::Null(base) | Ct::Fcmp { base, .. } => base,
        };
        let commitment = base.commitments[at];
        let enc_amount = base.enc_amounts[at];
        let enc_label = base.enc_labels[at];

        // The scanner's path: decapsulate, derive, verify, decrypt.
        let combined_ss =
            recover_combined_ss(owner.x25519_sk, owner.ml_kem_dk, &kem.x25519, &kem.ml_kem)
                .expect("the owner's KEM keys decapsulate the output");
        let scanned = scan_output(
            owner.x25519_sk,
            owner.ml_kem_dk,
            &kem.x25519,
            &kem.ml_kem,
            &output.key,
            &commitment,
            enc_amount[..8].try_into().expect("8-byte ciphertext"),
            enc_amount[8],
            enc_label[..8].try_into().expect("8-byte ciphertext"),
            enc_label[8],
            output.view_tag,
            owner.spend_public,
            index_in_tx,
        )
        .expect("the owner owns the output");
        let hp_of_o = shekyl_curve_generators::biased_hash_to_point(output.key)
            .compress()
            .to_bytes();
        let ki =
            compute_output_key_image(&combined_ss.0, index_in_tx, owner.spend_secret, &hp_of_o)
                .expect("key image");

        // The path, from the wallet-side tree at the reference height.
        let reference_height =
            newest_admissible_reference(connecting).expect("connecting height admits a reference");
        let reference = ReferenceBlock {
            height: shekyl_curve_tree::BlockHeight::from_raw(reference_height.to_raw()),
            curve_tree_root: self.root_at(reference_height),
            block_hash: shekyl_curve_tree::BlockHash::from_bytes(
                self.hashes[usize::try_from(reference_height.to_raw()).expect("small")].to_bytes(),
            ),
        };
        let path = self
            .client
            .assemble_path(
                &AssembleInput {
                    gindex: Gindex::from_raw(gindex),
                    output_key: shekyl_curve_tree::OneTimePubkey::from_bytes(output.key),
                    commitment: shekyl_curve_tree::CommitmentBytes::from_bytes(commitment),
                },
                &reference,
            )
            .expect("the output has matured into the tree at the reference height");
        let leaf_chunk: Vec<LeafEntry> = path
            .leaf_chunk
            .iter()
            .map(|cl| LeafEntry {
                output_key: cl.output_key.to_bytes(),
                key_image_gen: cl.key_image_gen,
                commitment: cl.commitment.to_bytes(),
                cm_x: cl.cm_x,
            })
            .collect();
        Sourced {
            input: SpendInput {
                output_key: output.key,
                commitment,
                amount: AtomicUnits::from_raw(scanned.amount),
                spend_key_x: *ki.spend_secret_x,
                spend_key_y: scanned.y,
                commitment_mask: scanned.z,
                combined_ss: combined_ss.0.to_vec(),
                output_index: index_in_tx,
                leaf_chunk,
                c1_layers: path.c1_layers.clone(),
                c2_layers: path.c2_layers.clone(),
            },
            key_image: ki.key_image,
            tree: TreeContext {
                reference_block: path.tree.reference_block,
                tree_root: path.tree.tree_root,
                tree_depth: path.tree.tree_depth,
            },
        }
    }

    /// Source a watched output ([`Self::own`]) that a pushed block has
    /// listed, for `owner`, anchored for a spend connecting at
    /// `connecting`. Panics if no pushed block listed `output_key`.
    #[must_use]
    pub fn owned_input(
        &self,
        owner: &Owner<'_>,
        output_key: [u8; 32],
        connecting: BlockHeight,
    ) -> Sourced {
        let located = self
            .located
            .get(&output_key)
            .expect("a watched output some pushed block listed");
        self.source(
            owner,
            &located.tx,
            located.index_in_tx,
            located.gindex,
            connecting,
        )
    }

    /// [`Self::spend_coinbase_posting`] paying `recipient` instead of the
    /// miner (E6 slice 8 row 7): the two outputs are addressed to the
    /// recipient's keys, each with its own KEM ciphertext and leaf entry,
    /// so a persona can be funded by a coinbase spend and later source
    /// them through [`Self::owned_input`].
    #[must_use]
    pub fn spend_coinbase_to(
        &self,
        wallet: &MinerWallet,
        height: BlockHeight,
        connecting: BlockHeight,
        fee: u64,
        bond: Option<&PostedBond<'_>>,
        recipient: &Recipient,
    ) -> Transaction {
        let sourced = vec![self.source_coinbase(wallet, height, connecting)];
        Self::spend_sourced(sourced, connecting, fee, bond, recipient)
    }

    /// A spend of several blocks' coinbases in **one** transaction, listed
    /// in the block connecting at `connecting`, paying `fee` and the rest
    /// back to the miner in two outputs — the multi-input shape, up to the
    /// prover's `shekyl_fcmp::MAX_INPUTS` (CEN-I4's cap). Each input
    /// carries its own `pqc_auths` slot, so the body's archival length
    /// grows by a hybrid key and signature per input; this is how a
    /// fixture chain reaches an archival length with bytes every landed
    /// rule verifies, rather than by padding a region none does.
    ///
    /// Yields the body and the coinbase heights **in the body's input
    /// order** — the inputs are sorted by key image (CEN-I5), not listed
    /// as asked — so a caller pairing each input's key image with the
    /// coinbase it spends reads the pairing here rather than deriving it.
    #[must_use]
    pub fn spend_coinbases(
        &self,
        wallet: &MinerWallet,
        heights: &[BlockHeight],
        connecting: BlockHeight,
        fee: u64,
    ) -> (Transaction, Vec<BlockHeight>) {
        assert!(!heights.is_empty(), "a spend has an input");
        let pairs: Vec<(BlockHeight, Sourced)> = heights
            .iter()
            .map(|&height| (height, self.source_coinbase(wallet, height, connecting)))
            .collect();
        // `spend_sourced` is the one CEN-I5 sort. Heights come back from the
        // encoded body's key images, so a sort here would have to stay
        // identical to that one or the pairing would describe a different order.
        let height_of: BTreeMap<KeyImage, BlockHeight> = pairs
            .iter()
            .map(|(height, source)| (source.key_image, *height))
            .collect();
        assert_eq!(
            height_of.len(),
            pairs.len(),
            "each spent coinbase has its own key image"
        );
        let inputs: Vec<Sourced> = pairs.into_iter().map(|(_, source)| source).collect();
        let tx = Self::spend_sourced(inputs, connecting, fee, None, wallet.recipient());
        let spent_heights: Vec<BlockHeight> = tx
            .prefix
            .inputs
            .iter()
            .filter_map(|input| match input {
                Input::ToKey { key_image, .. } => Some(
                    height_of
                        .get(&KeyImage::from_bytes(*key_image))
                        .copied()
                        .expect("the body's key image is one of the spent coinbases"),
                ),
                _ => None,
            })
            .collect();
        assert_eq!(
            spent_heights.len(),
            height_of.len(),
            "a coinbase spend lists only the spent coinbases"
        );
        (tx, spent_heights)
    }

    /// Block `height`'s coinbase sourced for the miner, for a spend
    /// connecting at `connecting`.
    fn source_coinbase(
        &self,
        wallet: &MinerWallet,
        height: BlockHeight,
        connecting: BlockHeight,
    ) -> Sourced {
        let coinbase = &self.coinbases[usize::try_from(height.to_raw()).expect("small")];
        let gindex = self.first_gid[usize::try_from(height.to_raw()).expect("small")];
        self.source(&Owner::miner(wallet), coinbase, 0, gindex, connecting)
    }

    /// The spend of `sourced` — one or more inputs, every path assembled
    /// against the same reference — paying `fee` to the chain and the rest
    /// to `recipient` in two outputs, with `bond` riding it if given. The
    /// body every `spend_*` builder hands out.
    fn spend_sourced(
        mut sourced: Vec<Sourced>,
        connecting: BlockHeight,
        fee: u64,
        bond: Option<&PostedBond<'_>>,
        recipient: &Recipient,
    ) -> Transaction {
        // Inputs in strict-descending key-image order (CEN-I5), as the
        // engine's `sign_bridge` orders them before signing; the prefix
        // hash, the signer's inputs and the pseudo-outs all follow it.
        sourced.sort_by(|a, b| b.key_image.as_bytes().cmp(a.key_image.as_bytes()));
        let tree = sourced[0].tree.clone();
        assert!(
            sourced
                .iter()
                .all(|s| s.tree.reference_block == tree.reference_block
                    && s.tree.tree_root == tree.tree_root
                    && s.tree.tree_depth == tree.tree_depth),
            "every input's path is assembled against the one reference"
        );
        let spend_inputs: Vec<SpendInput> = sourced.iter().map(|s| s.input.clone()).collect();
        let key_images: Vec<shekyl_types::KeyImage> = sourced.iter().map(|s| s.key_image).collect();
        let amount: u64 = spend_inputs
            .iter()
            .map(|i| i.amount.to_raw())
            .try_fold(0u64, u64::checked_add)
            .expect("the inputs' amounts sum");

        // Two outputs to the recipient, each with its own KEM and leaf.
        // The balance the signer proves: `Σ amount + debit = outputs + fee +
        // credit` (`shekyl_ct_balance::verify_ct_balance`, CEN-H21's
        // equation), so what the outputs carry is what is left after the
        // fee and the post's term.
        let credit = bond
            .and_then(|b| b.credit)
            .map_or(0, |t| t.amount().to_raw());
        let debit = bond
            .and_then(|b| b.debit)
            .map_or(0, |t| t.amount().to_raw());
        let spendable = amount
            .checked_add(debit)
            .and_then(|funds| funds.checked_sub(fee))
            .and_then(|funds| funds.checked_sub(credit))
            .expect("the coinbase funds the fee and the bond credit");
        let payment_amount = spendable / 2;
        let change_amount = spendable - payment_amount;
        // The transaction key is a seed (`derive_kem_seed` hashes it), so
        // any 32 bytes serve; what matters is that two spends are never
        // built from one. Keyed on the connecting height alone, two spends
        // in one block to one recipient derived identical output keys —
        // the same seed, the same keys, the same indices — and a block
        // listing both carried a duplicate output, not two bodies. The
        // spent outputs' key images are the spend's own identity, so the
        // first (the largest, after the CEN-I5 sort — no two spends share
        // one) is mixed in.
        let tx_secret = {
            let mut s = [0u8; 32];
            s[..8].copy_from_slice(&(0x5e00_0000_0000_0000u64 ^ connecting.to_raw()).to_le_bytes());
            s[8..].copy_from_slice(&key_images[0].as_bytes()[8..]);
            s
        };
        let pay = |amount: u64, index: u64| -> OutputData {
            construct_output(
                &tx_secret,
                &recipient.x25519_pk,
                &recipient.ml_kem_ek,
                &recipient.spend_public,
                amount,
                index,
            )
            .expect("construct output")
        };
        let payment = pay(payment_amount, 0);
        let change = pay(change_amount, 1);
        let mut kem_blob = Vec::new();
        let mut leaf_blob = Vec::new();
        for od in [&payment, &change] {
            kem_blob.extend_from_slice(&od.kem_ciphertext_x25519);
            kem_blob.extend_from_slice(&od.kem_ciphertext_ml_kem);
            leaf_blob.extend_from_slice(&od.pqc_leaf.entry_bytes());
        }
        assert_eq!(
            pqc_leaf_entries_per_output(&leaf_blob)
                .expect("whole entries")
                .len(),
            2
        );
        let extra = serialize(&[
            TxExtraField::PqcKemCiphertext(kem_blob),
            TxExtraField::PqcLeafEntries(leaf_blob),
        ])
        .expect("extra serializes");
        let info = |od: &OutputData, amount: u64| OutputInfo {
            dest_key: od.output_key,
            amount: AtomicUnits::from_raw(amount),
            commitment_mask: od.z,
            enc_amount: od.enc_amount_wire(),
            enc_label: od.enc_label_wire(),
        };
        let outputs = [info(&payment, payment_amount), info(&change, change_amount)];
        let output_keys = [payment.output_key, change.output_key];
        let view_tags = [
            Some(payment.view_tag_prefilter),
            Some(change.view_tag_prefilter),
        ];

        // Sign, then encode through the production encoder and read back.
        let extra_inputs: Vec<shekyl_wire::Input> =
            bond.map(|b| vec![b.input.clone()]).unwrap_or_default();
        let extra_input_terms: Vec<InputTerm> = bond.and_then(|b| b.debit).into_iter().collect();
        let extra_output_terms: Vec<OutputTerm> = bond.and_then(|b| b.credit).into_iter().collect();
        let key_image_bytes: Vec<[u8; 32]> = key_images.iter().map(|k| *k.as_bytes()).collect();
        let tx_prefix_hash = tx_prefix_hash_from_parts_with_extra(
            &key_image_bytes,
            &extra_inputs,
            &output_keys,
            &[0, 0],
            &view_tags,
            &extra,
        )
        .expect("the prefix hashes");
        let signed = sign_transaction_with_terms(
            tx_prefix_hash,
            &spend_inputs,
            &outputs,
            AtomicUnits::from_raw(fee),
            &extra_input_terms,
            &extra_output_terms,
            &tree,
        )
        .expect("sign the spend");
        // One revealed key per spend input, each derived from its own
        // output's shared secret at its own index (the signer's derivation).
        // `open_spend` hashes these keys, signs the spend slots, and refuses
        // a derived key that is not the key the payload covered (CEN-I17 / I18).
        let revealed_pks: Vec<Vec<u8>> = spend_inputs
            .iter()
            .map(|input| {
                let combined64: &[u8; 64] = input.combined_ss[..]
                    .try_into()
                    .expect("a 64-byte combined shared secret");
                derive_pqc_public_key(combined64, input.output_index).expect("hybrid pk")
            })
            .collect();
        let n_spend = spend_inputs.len();
        let open = open_spend(
            signed,
            &spend_inputs,
            SpendLayout {
                key_images: key_image_bytes,
                extra_inputs,
                output_keys: output_keys.to_vec(),
                output_amounts: vec![0; output_keys.len()],
                view_tags: view_tags.to_vec(),
                tx_extra: extra,
                fee,
                slots: AuthSlots {
                    spend: revealed_pks.clone(),
                    extra: bond.map(|b| vec![b.slot_pk.clone()]).unwrap_or_default(),
                },
            },
        )
        .expect("the spend opens");

        // Self-check through the consensus verifier against the wallet-side
        // root at the reference height — CEN-I15's exact operation — so the
        // object handed to the caller is known sound before any rule judges
        // it. A test then holds this root equal to the store's at the same
        // height (`Spender::root_at` vs `RootAt`), which is what makes the
        // proof valid against the header the block will carry. `layers` is
        // the prover's layer count `L`; the verifier takes that same `L`.
        let pqc_scalars: Vec<PqcKeyScalar> = revealed_pks
            .iter()
            .map(|pk| PqcKeyScalar::from_pqc_public_key(pk))
            .collect();
        let verified = proof::verify(
            &ShekylFcmpProof {
                data: open.fcmp_proof().to_vec(),
                num_inputs: u32::try_from(n_spend).expect("under the prover's cap"),
                tree_depth: open.layers(),
            },
            &key_images,
            open.pseudo_outs(),
            &pqc_scalars,
            tree.tree_root.as_bytes(),
            open.layers(),
            tx_prefix_hash.to_bytes(),
        )
        .expect("verify runs");
        assert!(
            verified,
            "the spend verifies against the wallet-side root at the reference height"
        );
        // The bond slot, when present, is signed by the persona's key over
        // its own payload. A plain spend seals with no extra signature.
        let extra_signatures = match bond {
            Some(posted) => {
                let payload = open
                    .sole_extra_payload()
                    .expect("the bond slot has a payload");
                vec![posted.sign_slot(payload)]
            }
            None => Vec::new(),
        };
        let bytes = open
            .encode(extra_signatures)
            .expect("the production encoder emits the spend");
        Transaction::from_bytes(&bytes).expect("the encoder's bytes parse as a transaction")
    }
}
