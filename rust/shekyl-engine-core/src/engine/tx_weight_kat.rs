// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! §3.10.1 weight KAT helpers (2a-3).

#[cfg(test)]
pub(crate) mod support {
    use crate::engine::local_keys::LocalKeys;
    use crate::engine::synthetic_tree::{
        enrich_input_tree, selene_single_chunk_tree_root, synthetic_h_pqc_bytes,
    };
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::EdwardsPoint;
    use shekyl_crypto_pq::kem::HybridCiphertext;
    use shekyl_crypto_pq::output::construct_output;
    use shekyl_generators::biased_hash_to_point;
    use shekyl_tx_builder::{sign_transaction, LeafEntry, OutputInfo, SpendInput, TreeContext};
    use shekyl_units::AtomicUnits;

    const TEST_SEED: [u8; 32] = [7u8; 32];
    const TEST_TX_KEY: [u8; 32] = [11u8; 32];

    /// Measure `sign_transaction` FCMP proof blob size for a KAT grid cell.
    pub(crate) fn measure_fcmp_proof_len(n_in: usize, tree_depth: u8) -> Result<usize, String> {
        measure_kat_sign(n_in, tree_depth).map(|signed| signed.fcmp_proof.len())
    }

    fn measure_kat_sign(
        n_in: usize,
        tree_depth: u8,
    ) -> Result<shekyl_tx_builder::SignedProofs, String> {
        if n_in == 0 || n_in > 8 || tree_depth == 0 || tree_depth > 24 {
            return Err("grid cell out of bounds".into());
        }

        let keys = LocalKeys::from_test_seed(TEST_SEED);
        let recipient = keys.primary_claim_spend_pk();

        let mut leaf_chunk = Vec::with_capacity(n_in);
        let mut spend_inputs = Vec::with_capacity(n_in);
        let mut input_total = 0u64;

        for i in 0..n_in {
            let amount = 50_000u64 + u64::try_from(i).unwrap() * 10_000;
            input_total = input_total
                .checked_add(amount)
                .ok_or("input amount overflow")?;
            let constructed = construct_output(
                &TEST_TX_KEY,
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

            let h_pqc = synthetic_h_pqc_bytes(i as u64 + u64::from(tree_depth) * 1_000);
            leaf_chunk.push(LeafEntry {
                output_key: constructed.output_key,
                key_image_gen: biased_hash_to_point(constructed.output_key)
                    .compress()
                    .to_bytes(),
                commitment: constructed.commitment,
                h_pqc,
            });

            let (lc, c1, c2, _) = enrich_input_tree(vec![leaf_chunk[i].clone()], tree_depth);
            spend_inputs.push(SpendInput {
                output_key: leaf_chunk[i].output_key,
                commitment: leaf_chunk[i].commitment,
                amount: AtomicUnits::from_raw(amount),
                spend_key_x: *bundle.spend_key_x,
                spend_key_y: *bundle.spend_key_y,
                commitment_mask: *bundle.commitment_mask,
                h_pqc: leaf_chunk[i].h_pqc,
                combined_ss: bundle.combined_ss.to_vec(),
                output_index: i as u64,
                leaf_chunk: lc,
                c1_layers: c1,
                c2_layers: c2,
            });
        }

        // Shared leaf chunk for multi-input (M3c shape).
        if n_in > 1 {
            for inp in &mut spend_inputs {
                inp.leaf_chunk = leaf_chunk.clone();
            }
        }

        let fee = 1_000u64;
        let payment = input_total.saturating_sub(fee);
        if payment == 0 {
            return Err("payment would be zero".into());
        }

        // Avoid input/output index collision (M3c fixture note): matching
        // `(combined_ss, output_index)` collapses pseudo-out blinding to zero.
        let recipient_output_index = (n_in as u64) + 100;
        let out_constructed = construct_output(
            &TEST_TX_KEY,
            &keys.keys.x25519_pk,
            &keys.keys.ml_kem_ek,
            &recipient,
            payment,
            recipient_output_index,
        )
        .map_err(|e| format!("output construct: {e}"))?;

        let output = OutputInfo {
            dest_key: out_constructed.output_key,
            amount: AtomicUnits::from_raw(payment),
            commitment_mask: out_constructed.z,
            enc_amount: {
                let mut buf = [0u8; 9];
                buf[..8].copy_from_slice(&out_constructed.enc_amount);
                buf[8] = out_constructed.amount_tag;
                buf
            },
            enc_label: {
                let mut buf = [0u8; 9];
                buf[..8].copy_from_slice(&out_constructed.enc_label);
                buf[8] = out_constructed.label_tag;
                buf
            },
        };

        let tree_root = selene_single_chunk_tree_root(&leaf_chunk);
        let tree = TreeContext {
            reference_block: [0xD4; 32],
            tree_root,
            tree_depth,
        };

        use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
        let tx_pubkey_scalar = Scalar::from_bytes_mod_order(TEST_TX_KEY);
        let tx_pubkey: EdwardsPoint = &tx_pubkey_scalar * ED25519_BASEPOINT_TABLE;
        let mut kem_blob = Vec::with_capacity(32 + out_constructed.kem_ciphertext_ml_kem.len());
        kem_blob.extend_from_slice(&out_constructed.kem_ciphertext_x25519);
        kem_blob.extend_from_slice(&out_constructed.kem_ciphertext_ml_kem);
        let tx_extra = shekyl_scanner::extra::Extra::for_hybrid_transfer(tx_pubkey, vec![kem_blob])
            .serialize();

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

        let output_keys = vec![out_constructed.output_key];
        let view_tags = vec![Some(out_constructed.view_tag_prefilter)];
        let prefix_hash = shekyl_tx_builder::tx_prefix_hash_from_parts(
            &key_images,
            &output_keys,
            &view_tags,
            &tx_extra,
        );

        sign_transaction(
            prefix_hash,
            &spend_inputs,
            &[output],
            AtomicUnits::from_raw(fee),
            &tree,
        )
        .map_err(|e| format!("sign_transaction: {e}"))
    }
}
