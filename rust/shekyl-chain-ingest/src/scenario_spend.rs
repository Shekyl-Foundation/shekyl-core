// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A real spend for the scenario driver (DRS-E3 commit 7,
//! `DRS_E3_CURVE_WRITER.md` §2.3, §6 row 7) — the object CEN-I15 and
//! CEN-H19's verification half wait for (FOLLOWUPS: *"blocked on the
//! scenario driver being able to produce a spend"*).
//!
//! A membership proof is valid only against the tree it was made in, so
//! the spend needs a path through the tree the **store** grew. This module
//! takes it from the **wallet-side** tree instead — `shekyl_curve_tree`'s
//! `CurveTreeClient`, the proving store DRS-D3c owns — fed the same blocks
//! the scenario mined, in order. That is deliberate, and it is the second
//! oracle this increment lands: the daemon-side writer (`grow.rs`, this PR)
//! and the wallet-side client are two Rust producers of one tree over one
//! sequence of blocks, and [`Spender::root_at`] against the store's
//! `root_at` holds them equal at every height a test asks (§2.5). If the
//! path were assembled from the store's own rows the spend would prove
//! nothing about the wallet side; if the client's tree diverged from the
//! store's, the spend would not verify against the header's root — CEN-I15
//! is exactly the rule that would refuse it, which is the point of
//! building the object here rather than a fixture (slice 6 §5.3).
//!
//! What is real: the miner's keys and the coinbase the template paid them
//! (`0x06` KEM ciphertext, `0x07` leaf entry), recovered by the production
//! scanner (`recover_combined_ss`, `scan_output`, `compute_output_key_image`);
//! the path (`assemble_path`); the signature (`sign_transaction`,
//! `sign_pqc_auths`); the wire bytes (`encode_final_tx`). Nothing is a
//! filler point or a conforming blob.
//!
//! E6 slice 8 row 7 widened the recipient and the owner. A spend can pay a
//! [`Recipient`] other than the miner — a persona's base address — and the
//! tree can be told to watch ([`Spender::own`]) for listed outputs so that,
//! once a block carrying them is pushed, [`Spender::owned_input`] sources
//! them for any [`Owner`] holding the matching secrets. That is what the
//! driver's emission claim spends: a backing output and a fee output paid
//! to the persona by an earlier spend of the miner's coinbase.

use std::collections::{BTreeMap, BTreeSet};

use shekyl_block_template::MinerKeys;
use shekyl_bulletproofs::Bulletproof;
use shekyl_chain_rules::harness::fixture::newest_admissible_reference;
use shekyl_crypto_pq::archival_p::ArchivalPKeys;
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
    encode_final_tx, phase1_payload_hashes, sign_pqc_auths, sign_transaction_with_terms,
    tx_prefix_hash_from_parts_with_extra, InputTerm, LeafEntry, OutputInfo, OutputTerm, SpendInput,
    TreeContext, WireEncodeInput,
};
use shekyl_types::{BlockHash, BlockHeight, CurveTreeRoot};
use shekyl_units::AtomicUnits;
use shekyl_wire::tx_extra::{
    admitted_leaf_blob, parse, pqc_kem_per_output, pqc_leaf_entries_per_output, serialize,
    TxExtraField,
};
use shekyl_wire::{Ct, Transaction};

use crate::scenario::{Mined, MinerWallet};
use crate::scenario_archival::PostedBond;

/// Whom a spend pays: the three public keys `construct_output` addresses
/// an output to.
pub struct Recipient {
    /// The Edwards spend public key (`B`).
    pub spend_public: [u8; 32],
    /// X25519 half of the hybrid KEM target.
    pub x25519_pk: [u8; 32],
    /// ML-KEM-768 encapsulation key.
    pub ml_kem_ek: Vec<u8>,
}

impl Recipient {
    /// The miner — what the template pays, and what the coinbase spends
    /// paid before row 7.
    pub fn miner(keys: &MinerKeys) -> Self {
        Self {
            spend_public: keys.spend_public,
            x25519_pk: keys.x25519_pk,
            ml_kem_ek: keys.ml_kem_ek.clone(),
        }
    }

    /// A persona's base address — where its backing and fee outputs live
    /// (`ARCHIVAL_BOND_CONSTRUCTION.md`: funded by a plain payment to `P`).
    pub fn persona(keys: &ArchivalPKeys) -> Self {
        Self {
            spend_public: *keys.spend_pk.as_canonical_bytes(),
            x25519_pk: keys.x25519_pk,
            ml_kem_ek: keys.ml_kem_ek.to_vec(),
        }
    }
}

/// What a wallet needs to recognise and spend an output paid to it: the
/// scanner's two decapsulation secrets, and the spend pair.
pub struct Owner<'a> {
    /// The X25519 decapsulation scalar (the view secret).
    pub x25519_sk: &'a [u8; 32],
    /// The ML-KEM-768 decapsulation key.
    pub ml_kem_dk: &'a [u8],
    /// The Edwards spend public key the output was addressed to.
    pub spend_public: &'a [u8; 32],
    /// The Edwards spend secret `b`; `x = ho + b` is the one-time secret.
    pub spend_secret: &'a [u8; 32],
}

impl Owner<'_> {
    /// The miner's wallet.
    pub fn miner(wallet: &MinerWallet) -> Owner<'_> {
        Owner {
            x25519_sk: &wallet.kem_secret.x25519,
            ml_kem_dk: &wallet.kem_secret.ml_kem,
            spend_public: &wallet.keys.spend_public,
            spend_secret: &wallet.spend_secret,
        }
    }

    /// A persona, over the same secrets the engine's
    /// `derive_p_source_secrets_bundle` reads.
    pub fn persona(keys: &ArchivalPKeys) -> Owner<'_> {
        Owner {
            x25519_sk: keys.view_sk.as_canonical_bytes(),
            ml_kem_dk: keys.ml_kem_dk.as_canonical_bytes(),
            spend_public: keys.spend_pk.as_canonical_bytes(),
            spend_secret: keys.spend_sk.as_canonical_bytes(),
        }
    }
}

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

/// The wallet-side tree over a scenario's mined blocks, and the facts a
/// spend of one of its coinbases needs (module docs).
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
    pub fn over(mined: &[Mined]) -> Self {
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
    pub fn push(&mut self, mined: &Mined) {
        let height = mined.height.to_raw();
        assert_eq!(
            height,
            self.hashes.len() as u64,
            "blocks are pushed consecutively from genesis"
        );
        let block = &mined.template.block;
        let mut leaf_blobs: Vec<Vec<u8>> = Vec::new();
        let mut raw: Vec<Vec<RawOutput>> = Vec::new();
        let txs: Vec<&Transaction> = std::iter::once(&block.miner_transaction)
            .chain(mined.template.transactions.iter())
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
            shekyl_curve_tree::OneTimePubkey::from_bytes(
                block.miner_transaction.prefix.outputs[0].key,
            ),
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
        self.hashes.push(mined.hash);
        self.coinbases.push(block.miner_transaction.clone());
    }

    /// The wallet-side tree's root going into `height` — the state the
    /// header at `height` commits to, keyed as the store's `root_at` is.
    pub fn root_at(&self, height: u64) -> CurveTreeRoot {
        self.client
            .root_at(shekyl_curve_tree::BlockHeight::from_raw(height))
            .expect("a height at or below the ingested tip")
    }

    /// A spend of block `height`'s coinbase, listed in the block connecting
    /// at `connecting`, paying `fee` and the rest back to the miner in two
    /// outputs. Anchored at the newest admissible reference (CEN-I11),
    /// whose root is the wallet-side tree's at that height.
    pub fn spend_coinbase(
        &self,
        wallet: &MinerWallet,
        height: u64,
        connecting: u64,
        fee: u64,
    ) -> Transaction {
        self.spend_coinbase_posting(wallet, height, connecting, fee, None)
    }

    /// [`Self::spend_coinbase`] with an archival bond post riding it
    /// (DRS-E4 commit 4; `scenario_archival`): the post is the prefix's one
    /// extra input, its term sits on the side its kind fixes — a credit is a
    /// sink the outputs shrink by, a debit a source they grow by — and the
    /// bond slot is the last `pqc_auths` entry, signed by the key the post
    /// names over the same phase-1 payload hash the spend's own slot signs.
    /// That is `shekyl-engine-core`'s `bond_post_assemble` shape; with no
    /// post the bytes are [`Self::spend_coinbase`]'s exactly (the `_with_*`
    /// builders are the plain ones with empty extras).
    pub fn spend_coinbase_posting(
        &self,
        wallet: &MinerWallet,
        height: u64,
        connecting: u64,
        fee: u64,
        bond: Option<&PostedBond<'_>>,
    ) -> Transaction {
        self.spend_coinbase_to(
            wallet,
            height,
            connecting,
            fee,
            bond,
            &Recipient::miner(&wallet.keys),
        )
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
        connecting: u64,
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
        let reference_height = newest_admissible_reference(BlockHeight::from_raw(connecting))
            .expect("connecting height admits a reference")
            .to_raw();
        let reference = ReferenceBlock {
            height: shekyl_curve_tree::BlockHeight::from_raw(reference_height),
            curve_tree_root: self.root_at(reference_height),
            block_hash: shekyl_curve_tree::BlockHash::from_bytes(
                self.hashes[usize::try_from(reference_height).expect("small")].to_bytes(),
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
    pub fn owned_input(&self, owner: &Owner<'_>, output_key: [u8; 32], connecting: u64) -> Sourced {
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
    pub fn spend_coinbase_to(
        &self,
        wallet: &MinerWallet,
        height: u64,
        connecting: u64,
        fee: u64,
        bond: Option<&PostedBond<'_>>,
        recipient: &Recipient,
    ) -> Transaction {
        let coinbase = &self.coinbases[usize::try_from(height).expect("small")];
        let gindex = self.first_gid[usize::try_from(height).expect("small")];
        let Sourced {
            input: spend_input,
            key_image,
            tree,
        } = self.source(&Owner::miner(wallet), coinbase, 0, gindex, connecting);
        let amount = spend_input.amount.to_raw();

        // Two outputs to the recipient, each with its own KEM and leaf.
        // The balance the signer proves: `amount + debit = outputs + fee +
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
        let tx_secret = {
            let mut s = [0u8; 32];
            s[..8].copy_from_slice(&(0x5e00_0000_0000_0000u64 ^ connecting).to_le_bytes());
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
        let tx_prefix_hash = tx_prefix_hash_from_parts_with_extra(
            &[*key_image.as_bytes()],
            &extra_inputs,
            &output_keys,
            &[0, 0],
            &view_tags,
            &extra,
        )
        .expect("the prefix hashes");
        let signed = sign_transaction_with_terms(
            tx_prefix_hash,
            std::slice::from_ref(&spend_input),
            &outputs,
            AtomicUnits::from_raw(fee),
            &extra_input_terms,
            &extra_output_terms,
            &tree,
        )
        .expect("sign the spend");
        // The PQC auth signs `Transaction::pqc_signing_payload_hashes` — a
        // hash over the assembled body with the public key in place (CEN-I17
        // / I18) — so the body is encoded once with the key and an empty
        // signature, hashed, signed, and encoded again with the signature.
        let combined64: &[u8; 64] = spend_input.combined_ss[..]
            .try_into()
            .expect("a 64-byte combined shared secret");
        let revealed_pk = derive_pqc_public_key(combined64, 0).expect("hybrid pk");
        let bulletproof = Bulletproof::read_plus(&mut signed.bulletproof_plus.as_slice())
            .expect("the signer's Bulletproof+ blob reads back");
        let wire = |pqc_auths: Vec<shekyl_tx_builder::PqcAuth>| -> WireEncodeInput {
            WireEncodeInput {
                key_images: vec![*key_image.as_bytes()],
                extra_inputs: extra_inputs.clone(),
                output_keys: output_keys.to_vec(),
                output_amounts: vec![0, 0],
                view_tags: view_tags.to_vec(),
                tx_extra: extra.clone(),
                fee,
                enc_amounts: signed.enc_amounts.clone(),
                enc_labels: signed.enc_labels.clone(),
                out_commitments: signed.commitments.clone(),
                pseudo_outs: signed.pseudo_outs.clone(),
                bulletproof: bulletproof.clone(),
                reference_block: signed.reference_block,
                fcmp_proof: signed.fcmp_proof.clone(),
                pqc_auths,
                fcmp_layers: signed.tree_depth,
            }
        };
        // Phase 1: every slot's key in place with an empty signature — the
        // spend's revealed key, then the bond slot's — hashed per input.
        let empty = |public_key: Vec<u8>| shekyl_tx_builder::PqcAuth {
            auth_version: 1,
            signature: Vec::new(),
            public_key,
        };
        let mut slots = vec![empty(revealed_pk.clone())];
        if let Some(b) = bond {
            slots.push(empty(b.slot_pk.clone()));
        }
        let payloads = phase1_payload_hashes(&wire(slots)).expect("the unsigned body hashes");
        assert_eq!(
            payloads.len(),
            1 + usize::from(bond.is_some()),
            "one payload per input"
        );
        // Phase 2: the spend's slot through the production signer; the bond
        // slot by the persona's key over its own payload (I17 / I18 hold
        // each to its input's preimage).
        let mut pqc_auths =
            sign_pqc_auths(&payloads[..1], std::slice::from_ref(&spend_input)).expect("PQC auths");
        assert_eq!(
            pqc_auths[0].public_key, revealed_pk,
            "the key the payload bound"
        );
        if let Some(b) = bond {
            pqc_auths.push(shekyl_tx_builder::PqcAuth {
                auth_version: 1,
                signature: b.sign_slot(&payloads[1]),
                public_key: b.slot_pk.clone(),
            });
        }
        let bytes =
            encode_final_tx(&wire(pqc_auths)).expect("the production encoder emits the spend");

        // Self-check through the consensus verifier against the wallet-side
        // root at the reference height — CEN-I15's exact operation — so the
        // object handed to the driver is known sound before any rule judges
        // it. A test then holds this root equal to the store's at the same
        // height (`Spender::root_at` vs `RootAt`), which is what makes the
        // proof valid against the header the block will carry.
        let verified = proof::verify(
            &ShekylFcmpProof {
                data: signed.fcmp_proof.clone(),
                num_inputs: 1,
                tree_depth: signed.tree_depth,
            },
            &[key_image],
            &signed.pseudo_outs,
            &[PqcKeyScalar::from_pqc_public_key(&revealed_pk)],
            tree.tree_root.as_bytes(),
            signed.tree_depth,
            tx_prefix_hash.to_bytes(),
        )
        .expect("verify runs");
        assert!(
            verified,
            "the driver's spend verifies against the wallet-side root at the reference height"
        );
        Transaction::from_bytes(&bytes).expect("the encoder's bytes parse as a transaction")
    }
}
