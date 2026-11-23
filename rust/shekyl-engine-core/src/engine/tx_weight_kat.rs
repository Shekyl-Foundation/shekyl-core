// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! §3.10.1 weight KAT helpers (2a-3).

#[cfg(test)]
pub(crate) mod support {
    use crate::engine::local_keys::LocalKeys;
    use crate::engine::synthetic_tree::consistent_synthetic_path;
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::EdwardsPoint;
    use shekyl_crypto_pq::kem::HybridCiphertext;
    use shekyl_crypto_pq::output::construct_output;
    use shekyl_curve_generators::biased_hash_to_point;
    use shekyl_fcmp::PqcLeafScalar;
    use shekyl_tx_builder::{
        sign_transaction, LeafEntry, OutputInfo, SpendInput, TreeContext, TxBuilderError,
    };
    use shekyl_units::AtomicUnits;

    const TEST_SEED: [u8; 32] = [7u8; 32];
    const TEST_TX_KEY: [u8; 32] = [11u8; 32];

    /// Measure `sign_transaction` FCMP proof blob size for a KAT grid cell.
    pub(crate) fn measure_fcmp_proof_len(n_in: usize, tree_depth: u8) -> Result<usize, String> {
        kat_cell(n_in, tree_depth)?
            .sign()
            .map(|signed| signed.fcmp_proof.len())
    }

    /// One KAT grid cell, built and ready to sign: everything
    /// `sign_transaction` reads, so a caller can time the signing alone.
    pub(crate) struct KatCell {
        spend_inputs: Vec<SpendInput>,
        outputs: Vec<OutputInfo>,
        fee: AtomicUnits,
        tree: TreeContext,
        prefix_hash: shekyl_types::PrefixHash,
    }

    impl KatCell {
        /// `sign_transaction` over this cell: the Bulletproofs+ range proof,
        /// the hybrid PQC authorizations and the FCMP++ membership proof.
        pub(crate) fn sign(&self) -> Result<shekyl_tx_builder::SignedProofs, String> {
            sign_transaction(
                &shekyl_network::Network::Testnet.network_id(),
                self.prefix_hash,
                &self.spend_inputs,
                &self.outputs,
                self.fee,
                &self.tree,
            )
            .map_err(|e| format!("sign_transaction: {e}"))
        }
    }

    pub(crate) fn kat_cell(n_in: usize, tree_depth: u8) -> Result<KatCell, String> {
        if n_in == 0 || n_in > 8 || tree_depth == 0 || tree_depth > 24 {
            return Err("grid cell out of bounds".into());
        }

        let keys = LocalKeys::from_test_seed(TEST_SEED);
        // Base spend key `b·G` — the witness is `ho + b` (no claim offset), so the
        // synthetic output must be paid to the base key for the SAL open to hold.
        let recipient = *keys.keys.spend_pk.as_canonical_bytes();

        let mut leaf_chunk = Vec::with_capacity(n_in);
        let mut spend_inputs = Vec::with_capacity(n_in);
        let mut input_total = 0u64;

        for i in 0..n_in {
            let amount = 50_000u64 + u64::try_from(i).unwrap() * 10_000;
            input_total = input_total
                .checked_add(amount)
                .ok_or("input amount overflow")?;
            let constructed = construct_output(
                &shekyl_crypto_pq::TxKey::seeded(TEST_TX_KEY),
                &keys.keys.x25519_pk,
                &keys.keys.ml_kem_ek,
                &recipient,
                amount,
                i as u64,
            )
            .map_err(|e| format!("construct_output: {e}"))?;

            let ciphertext = HybridCiphertext {
                x25519: constructed.kem_ciphertext_x25519,
                ml_kem: constructed.kem_ciphertext_ml_kem.clone(),
            };
            let bundle = keys
                .derive_primary_source_secrets_bundle(&ciphertext, i as u64)
                .map_err(|e| format!("derive bundle: {e:?}"))?;

            // The real leaf scalar: the signer re-derives the opening and
            // checks it against this entry (PL-D3), so it must be honest.
            let h_pqc = PqcLeafScalar::from_commitment_point(&constructed.pqc_leaf.point)
                .expect("constructed leaf commitment decompresses")
                .0;
            leaf_chunk.push(LeafEntry {
                output_key: constructed.output_key,
                key_image_gen: biased_hash_to_point(constructed.output_key)
                    .compress()
                    .to_bytes(),
                commitment: constructed.commitment,
                cm_x: h_pqc,
            });

            spend_inputs.push(SpendInput {
                output_key: leaf_chunk[i].output_key,
                commitment: leaf_chunk[i].commitment,
                amount: AtomicUnits::from_raw(amount),
                spend_key_x: *bundle.spend_key_x,
                spend_key_y: *bundle.spend_key_y,
                commitment_mask: *bundle.commitment_mask,
                combined_ss: bundle.combined_ss.to_vec(),
                output_index: i as u64,
                // Filled below with the one shared depth-consistent path.
                leaf_chunk: Vec::new(),
                c1_layers: Vec::new(),
                c2_layers: Vec::new(),
            });
        }

        // PF7: one depth-consistent single-path tree over the shared leaf chunk
        // (all inputs sit in it — the M3c shape). Every input shares the same
        // branches and root, so the FCMP++ witness is consistent at any depth.
        let (c1, c2, tree_root) = consistent_synthetic_path(&leaf_chunk, tree_depth);
        for inp in &mut spend_inputs {
            inp.leaf_chunk = leaf_chunk.clone();
            inp.c1_layers = c1.clone();
            inp.c2_layers = c2.clone();
        }

        let fee = 1_000u64;
        let payment = input_total.saturating_sub(fee);
        if payment == 0 {
            return Err("payment would be zero".into());
        }

        // The fewest outputs a transaction carries (CEN-I1), paying
        // `payment` between them. The FCMP++ proof this cell measures does
        // not depend on the output count.
        // Avoid input/output index collision (M3c fixture note): matching
        // `(combined_ss, output_index)` collapses pseudo-out blinding to zero.
        let recipient_output_index = (n_in as u64) + 100;
        let n_out = shekyl_wire::transaction::MIN_NON_COINBASE_OUTPUTS as u64;
        if payment < n_out {
            return Err(format!(
                "payment {payment} cannot pay {n_out} nonzero outputs"
            ));
        }
        let mut outputs = Vec::new();
        let mut kem_blobs = Vec::new();
        let mut output_keys = Vec::new();
        let mut view_tags = Vec::new();
        for j in 0..n_out {
            let amount = payment / n_out + u64::from(j < payment % n_out);
            let constructed = construct_output(
                &shekyl_crypto_pq::TxKey::seeded(TEST_TX_KEY),
                &keys.keys.x25519_pk,
                &keys.keys.ml_kem_ek,
                &recipient,
                amount,
                recipient_output_index + j,
            )
            .map_err(|e| format!("output construct: {e}"))?;
            let mut kem_blob = Vec::with_capacity(32 + constructed.kem_ciphertext_ml_kem.len());
            kem_blob.extend_from_slice(&constructed.kem_ciphertext_x25519);
            kem_blob.extend_from_slice(&constructed.kem_ciphertext_ml_kem);
            kem_blobs.push(kem_blob);
            output_keys.push(constructed.output_key);
            view_tags.push(Some(constructed.view_tag_prefilter));
            outputs.push(OutputInfo {
                dest_key: constructed.output_key,
                amount: AtomicUnits::from_raw(amount),
                commitment_mask: constructed.commitment_mask(),
                enc_amount: constructed.enc_amount_wire(),
                enc_label: constructed.enc_label_wire(),
            });
        }

        let tree = TreeContext {
            reference_block: shekyl_types::BlockHash::from_bytes([0xD4; 32]),
            tree_root,
            tree_depth,
        };

        use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
        let tx_pubkey_scalar = Scalar::from_bytes_mod_order(TEST_TX_KEY);
        let tx_pubkey: EdwardsPoint = &tx_pubkey_scalar * ED25519_BASEPOINT_TABLE;
        let tx_extra =
            shekyl_scanner::extra::Extra::for_hybrid_transfer(tx_pubkey, kem_blobs).serialize();

        let key_images: Vec<[u8; 32]> = spend_inputs
            .iter()
            .map(|inp| {
                let combined: [u8; 64] = inp.combined_ss[..64].try_into().unwrap();
                let ki = shekyl_crypto_pq::output::compute_output_key_image(
                    &combined,
                    inp.output_index,
                    keys.keys.spend_sk.as_canonical_bytes(),
                    &biased_hash_to_point(inp.output_key).compress().to_bytes(),
                )
                .expect("key image");
                *ki.key_image.as_bytes()
            })
            .collect();

        let prefix_hash = shekyl_tx_builder::tx_prefix_hash_from_parts(
            &key_images,
            &output_keys,
            &view_tags,
            &tx_extra,
        );

        Ok(KatCell {
            spend_inputs,
            outputs,
            fee: AtomicUnits::from_raw(fee),
            tree,
            prefix_hash,
        })
    }

    /// The signing cost a wallet pays per transfer, at the shapes a user
    /// meets: wall time of `sign_transaction` alone (the cell is built
    /// outside the timed region), median of `REPS` runs, in a release
    /// build. The FCMP++ membership proof dominates it, and every
    /// non-vartime multiexp in that prover takes secret scalars, so this
    /// is the figure that prices a change to multiexp's constant-time
    /// selection (rule 76: read it on the floor device). It includes the
    /// builder's membership self-verify, which runs inside
    /// `sign_transaction`. Diagnostic, not a gate: it prints, and asserts
    /// only that every cell signs.
    /// The builder verifies the membership proof it has just made before
    /// returning it. The prover does not read the tree root it is given, so
    /// a cell whose root its path does not reach proves without complaint;
    /// the self-verify refuses it, at one input and depth 1 and at two
    /// inputs and depth 3 (a layer count above the leaf layer's). The same
    /// cells with their own root sign, carrying one key image per input.
    /// Red edit: drop `verify_own_membership` from `sign_with`.
    #[test]
    fn a_proof_over_a_root_its_path_does_not_reach_is_refused_before_it_leaves() {
        for (n_in, depth) in [(1, 1), (2, 3)] {
            let cell = kat_cell(n_in, depth).unwrap_or_else(|e| panic!("({n_in},{depth}): {e}"));
            let signed = cell
                .sign()
                .unwrap_or_else(|e| panic!("({n_in},{depth}) with its own root: {e}"));
            assert_eq!(signed.key_images.len(), n_in, "({n_in},{depth})");

            let mut wrong_root = cell.tree.clone();
            let mut root = *wrong_root.tree_root.as_bytes();
            root[0] ^= 1;
            wrong_root.tree_root = shekyl_types::CurveTreeRoot::from_bytes(root);
            let refused = sign_transaction(
                &shekyl_network::Network::Testnet.network_id(),
                cell.prefix_hash,
                &cell.spend_inputs,
                &cell.outputs,
                cell.fee,
                &wrong_root,
            )
            .expect_err("a proof over a root its path does not reach must not be returned");
            assert!(
                matches!(refused, TxBuilderError::MembershipSelfCheck(_)),
                "({n_in},{depth}): {refused:?}"
            );
        }
    }

    /// An ordinary send keeps the builder's fault at its PQC signing and its
    /// final encoding, as the staking paths do, and each reaches the signer's
    /// error unchanged. Red edit: map either back to a wallet-side fault.
    #[test]
    fn a_send_keeps_the_builders_fault_at_its_last_two_steps() {
        use crate::engine::error::{KeyEngineError, SignerError};
        use crate::engine::sign_bridge::{assemble_transfer_wire, sign_spend_auths};
        use crate::engine::signer::encode_signed;
        use shekyl_tx_builder::{InternalSignFault, SignFault};

        let cell = kat_cell(2, 2).expect("a cell");
        let signed = cell.sign().expect("it signs");
        let images: Vec<[u8; 32]> = signed.key_images.iter().map(|i| *i.as_bytes()).collect();
        let slot_keys: Vec<Vec<u8>> = cell
            .spend_inputs
            .iter()
            .map(|input| {
                let combined: &[u8; 64] = input.combined_ss[..].try_into().expect("64 bytes");
                shekyl_crypto_pq::derivation::derive_pqc_public_key(combined, input.output_index)
                    .expect("a hybrid key")
            })
            .collect();
        let output_count = signed.commitments.len();
        let mut wire = assemble_transfer_wire(
            images,
            vec![[2; 32]; output_count],
            vec![Some(1); output_count],
            Vec::new(),
            cell.fee.to_raw(),
            signed,
            &slot_keys,
        )
        .expect("its own layout assembles");

        let network = shekyl_network::Network::Testnet.network_id();
        let pqc_fault = SignFault::Internal(InternalSignFault::PqcSignError);
        let refused = sign_spend_auths(&wire, &network, &[]).expect_err("no input to sign");
        assert!(
            matches!(refused, KeyEngineError::Sign(f) if f == pqc_fault),
            "{refused:?}"
        );
        assert!(matches!(
            SignerError::from(refused),
            SignerError::Sign(f) if f == pqc_fault
        ));

        wire.pseudo_outs.pop();
        assert!(matches!(
            encode_signed(&wire),
            Err(SignerError::Sign(SignFault::Internal(
                InternalSignFault::WireError
            )))
        ));
    }

    /// The path ordinary transfers and drains share holds the transaction to
    /// what its proof verified: its own key images and slot keys assemble, and
    /// another key image, another slot key or a missing image is the signer's
    /// `membership-self-check` fault. Red edit: drop `hold_spend_layout` from
    /// `assemble_transfer_wire`.
    #[test]
    fn a_transfer_carrying_what_its_proof_did_not_verify_is_refused_at_assembly() {
        use crate::engine::error::KeyEngineError;
        use crate::engine::sign_bridge::assemble_transfer_wire;
        use shekyl_tx_builder::{InternalSignFault, SignFault};

        let cell = kat_cell(2, 1).expect("a cell");
        let signed = cell.sign().expect("it signs");
        let images: Vec<[u8; 32]> = signed.key_images.iter().map(|i| *i.as_bytes()).collect();
        let slot_keys: Vec<Vec<u8>> = cell
            .spend_inputs
            .iter()
            .map(|input| {
                let combined: &[u8; 64] = input.combined_ss[..].try_into().expect("64 bytes");
                shekyl_crypto_pq::derivation::derive_pqc_public_key(combined, input.output_index)
                    .expect("a hybrid key")
            })
            .collect();
        let assemble = |images: Vec<[u8; 32]>, slot_keys: &[Vec<u8>]| {
            assemble_transfer_wire(
                images,
                vec![[2; 32]],
                vec![Some(1)],
                Vec::new(),
                cell.fee.to_raw(),
                signed.clone(),
                slot_keys,
            )
        };
        assemble(images.clone(), &slot_keys).expect("its own layout assembles");

        let mut other_image = images.clone();
        other_image[1][0] ^= 1;
        let mut other_key = slot_keys.clone();
        other_key.swap(0, 1);
        for refused in [
            assemble(other_image, &slot_keys),
            assemble(images.clone(), &other_key),
            assemble(images[..1].to_vec(), &slot_keys[..1]),
        ] {
            assert!(matches!(
                refused,
                Err(KeyEngineError::Sign(SignFault::Internal(
                    InternalSignFault::MembershipSelfCheck
                )))
            ));
        }
    }

    #[test]
    #[ignore = "timing: run in release with --ignored --nocapture; prices the prover (rule 76)"]
    fn time_sign_transaction_by_shape() {
        const REPS: usize = 5;
        // Depth 1 and 4 are a young tree; the consensus maximum is where
        // the prover's multiexps, and so a full-scan multiexp's cost, peak.
        const DEEPEST: u8 = shekyl_tx_weight::MAX_TREE_DEPTH;
        const SHAPES: [(usize, u8); 8] = [
            (1, 1),
            (2, 1),
            (8, 1),
            (1, 4),
            (2, 4),
            (8, 4),
            (1, DEEPEST),
            (2, DEEPEST),
        ];
        println!("sign_transaction wall time, median of {REPS} (ms):");
        for (n_in, tree_depth) in SHAPES {
            let cell =
                kat_cell(n_in, tree_depth).unwrap_or_else(|e| panic!("({n_in},{tree_depth}): {e}"));
            let mut ms: Vec<f64> = (0..REPS)
                .map(|_| {
                    let start = std::time::Instant::now();
                    cell.sign()
                        .unwrap_or_else(|e| panic!("({n_in},{tree_depth}): {e}"));
                    start.elapsed().as_secs_f64() * 1e3
                })
                .collect();
            ms.sort_by(f64::total_cmp);
            println!(
                "  inputs={n_in} depth={tree_depth}: median {:.1} min {:.1} max {:.1}",
                ms[REPS / 2],
                ms[0],
                ms[REPS - 1]
            );
        }
    }
}
