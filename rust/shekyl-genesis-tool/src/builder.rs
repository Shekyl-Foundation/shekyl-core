// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Genesis coinbase-tx and block assembly.
//!
//! Byte-mirror of the retired C++
//! `cryptonote::build_genesis_coinbase_from_destinations` +
//! `generate_genesis_block` pair (`cryptonote_tx_utils.cpp`), with one
//! deliberate change: the tx key is the deterministic [`crate::txkey`]
//! derivation instead of a fresh `keypair::generate`.
//!
//! `tx_extra` is emitted directly in the C++ `sort_tx_extra` fixed-point
//! order for the genesis field subset — `0x01` pubkey, one aggregated `0x06`
//! KEM-ciphertext blob, one aggregated `0x07` leaf-hash blob (pick order:
//! `cryptonote_format_utils.cpp`, `sort_tx_extra`) — so no general sorter is
//! needed and the emitted extra is already canonical.

use shekyl_address::Network;
use shekyl_crypto_pq::montgomery::ed25519_pk_to_x25519_pk;
use shekyl_crypto_pq::output::construct_output;
use shekyl_wire::block::{Block, BlockHeader};
use shekyl_wire::transaction::{Ct, CtBase, Input, Output, Transaction, TxPrefix};
use shekyl_wire::tx_extra::{self, TxExtraField, ML_KEM_768_CT_BYTES, PQC_LEAF_HASH_BYTES};

use crate::recipients::{Recipient, GENESIS_TOTAL_ATOMIC};
use crate::txkey::{derive_genesis_tx_secret, tx_pubkey};
use crate::{invalid, GenesisToolError};

/// Genesis block major version (`CURRENT_BLOCK_MAJOR_VERSION`,
/// `src/cryptonote_config.h`).
pub const GENESIS_BLOCK_MAJOR_VERSION: u8 = 1;

/// Genesis block minor version (`CURRENT_BLOCK_MINOR_VERSION`,
/// `src/cryptonote_config.h`).
pub const GENESIS_BLOCK_MINOR_VERSION: u8 = 0;

/// A built genesis coinbase transaction.
pub struct BuiltGenesis {
    /// The assembled transaction (validated + round-tripped).
    pub tx: Transaction,
    /// Lowercase hex of the serialized tx — the `GENESIS_TX` pin.
    pub hex: String,
    /// Consensus transaction hash.
    pub tx_hash: [u8; 32],
}

/// Build the genesis coinbase transaction for `net` from validated
/// recipients.
///
/// Shape (`docs/design/GENESIS_TX_WIRE_FORMAT.md` §9): version 3, unlock_time
/// = coinbase maturity window, one `txin_gen{height=0}`, one cleartext-amount
/// tagged-key output per recipient, ct type Null with per-output
/// `enc_amount`/`enc_label`/commitment, and the canonical three-field extra.
pub fn build_genesis_tx(
    net: Network,
    recipients: &[Recipient],
) -> Result<BuiltGenesis, GenesisToolError> {
    let tx_secret = derive_genesis_tx_secret(net, recipients);
    let tx_pub = tx_pubkey(&tx_secret);

    let mut outputs = Vec::with_capacity(recipients.len());
    let mut enc_amounts = Vec::with_capacity(recipients.len());
    let mut enc_labels = Vec::with_capacity(recipients.len());
    let mut commitments = Vec::with_capacity(recipients.len());
    let mut kem_blob = Vec::new();
    let mut leaf_blob = Vec::new();
    let mut total: u64 = 0;

    for (i, r) in recipients.iter().enumerate() {
        // The address carries only the ML-KEM encap key; the X25519 half of
        // the hybrid KEM target is recovered from the view key via the
        // Edwards→Montgomery birational map (same recovery the engine's
        // decode→pay path uses).
        let x25519_pk = ed25519_pk_to_x25519_pk(&r.address.view_key)
            .map_err(|e| invalid(format!("recipient {i} view key → X25519: {e:?}")))?;

        let index = u64::try_from(i).expect("recipient index fits u64");
        let od = construct_output(
            &tx_secret,
            &x25519_pk,
            &r.address.ml_kem_encap_key,
            &r.address.spend_key,
            r.amount,
            index,
        )
        .map_err(|e| invalid(format!("construct_output for recipient {i}: {e:?}")))?;

        if od.kem_ciphertext_ml_kem.len() != ML_KEM_768_CT_BYTES {
            return Err(invalid(format!(
                "recipient {i} ML-KEM ciphertext length {} != {ML_KEM_768_CT_BYTES}",
                od.kem_ciphertext_ml_kem.len()
            )));
        }

        outputs.push(Output {
            amount: r.amount,
            key: od.output_key,
            view_tag: od.view_tag_prefilter,
        });

        enc_amounts.push(od.enc_amount_wire().to_bytes());
        enc_labels.push(od.enc_label_wire().to_bytes());

        commitments.push(od.commitment);

        kem_blob.extend_from_slice(&od.kem_ciphertext_x25519);
        kem_blob.extend_from_slice(&od.kem_ciphertext_ml_kem);
        leaf_blob.extend_from_slice(&od.h_pqc);

        total = total
            .checked_add(r.amount)
            .ok_or_else(|| invalid("output amount sum overflows u64"))?;
    }

    if total != GENESIS_TOTAL_ATOMIC {
        return Err(invalid(format!(
            "built output sum {total} != genesis total {GENESIS_TOTAL_ATOMIC}"
        )));
    }
    debug_assert_eq!(leaf_blob.len(), recipients.len() * PQC_LEAF_HASH_BYTES);

    let extra = tx_extra::serialize(&[
        TxExtraField::PubKey(tx_pub),
        TxExtraField::PqcKemCiphertext(kem_blob),
        TxExtraField::PqcLeafHashes(leaf_blob),
    ])?;

    let tx = Transaction {
        prefix: TxPrefix {
            // Coinbase maturity window (C++ CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW).
            unlock_time: u64::try_from(shekyl_consensus::COINBASE_LOCK_WINDOW)
                .expect("lock window fits u64"),
            inputs: vec![Input::Gen(0)],
            outputs,
            extra,
        },
        ct: Ct::Null(CtBase {
            enc_amounts,
            enc_labels,
            commitments,
        }),
    };

    // Self-checks before anything is emitted: context-free validity, then a
    // serialize → parse round-trip so the emitted hex is guaranteed to be
    // exactly what a consumer will decode.
    tx.validate_context_free_pruned()
        .map_err(|e| invalid(format!("built genesis tx fails validation: {e}")))?;
    let blob = tx.serialize();
    let reparsed = Transaction::from_bytes(&blob)
        .map_err(|e| invalid(format!("built genesis tx fails re-parse: {e}")))?;
    if reparsed != tx {
        return Err(invalid(
            "built genesis tx does not round-trip (serialize → parse mismatch)",
        ));
    }

    let tx_hash = tx.hash();
    Ok(BuiltGenesis {
        tx,
        hex: hex::encode(&blob),
        tx_hash,
    })
}

/// Assemble the genesis block around a built coinbase tx.
///
/// Mirrors C++ `generate_genesis_block`: header 1/0, timestamp 0, zero
/// previous hash, the empty curve-tree root, the empty attestation root, and
/// the configured nonce — which survives verbatim because genesis difficulty
/// is 1 (the first nonce tried always satisfies the PoW check).
pub fn genesis_block(tx: Transaction, nonce: u32) -> Result<Block, GenesisToolError> {
    let attestation_root = shekyl_archival_retention::attestation_wire::attestation_root(&[])
        .map_err(|e| invalid(format!("empty attestation root: {e:?}")))?;
    Ok(Block {
        header: BlockHeader {
            major_version: GENESIS_BLOCK_MAJOR_VERSION,
            minor_version: GENESIS_BLOCK_MINOR_VERSION,
            timestamp: 0,
            previous: [0u8; 32],
            nonce,
            curve_tree_root: shekyl_fcmp::tree::selene_hash_init(),
            attestation_root,
        },
        miner_transaction: tx,
        transaction_hashes: Vec::new(),
    })
}
