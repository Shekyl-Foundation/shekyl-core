// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Block and transaction scanning pipeline using hybrid PQC KEM.
//!
//! Scans `ScannableBlock`s for outputs belonging to the wallet's view pair,
//! using the Shekyl V3 two-component key derivation:
//!
//! 1. Parse `tx_extra` for PQC KEM ciphertext (tag 0x06)
//! 2. X25519 DH pre-filter via view tag (rejects ~99.6% of non-matching outputs)
//! 3. Full hybrid KEM decap + HKDF via `scan_output_recover`
//! 4. Subaddress lookup via recovered spend key `B' = O - ho*G - y*T`
//! 5. Key image computation via native Rust (no FFI)

use std::collections::HashMap;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use shekyl_oxide::{
    io::CompressedPoint,
    primitives::Commitment,
    transaction::{Pruned, Transaction},
};
use shekyl_rpc::ScannableBlock;

use shekyl_crypto_pq::{
    output::{scan_output_recover, compute_output_key_image},
    kem::ML_KEM_768_CT_LEN,
};
use shekyl_generators::hash_to_point;

use crate::{
    SubaddressIndex,
    ViewPair,
    GuaranteedViewPair,
    extra::{Extra, PaymentId},
    output::*,
};

const X25519_CT_BYTES: usize = 32;
const HYBRID_KEM_CT_BYTES: usize = X25519_CT_BYTES + ML_KEM_768_CT_LEN;

/// A recovered output with all PQC secrets populated at scan time.
///
/// Carries the HKDF-derived secrets (ho, y, z, k_amount), combined shared secret,
/// and key image so that `TransferDetails` can be fully populated without
/// re-derivation. Implements `ZeroizeOnDrop` — secrets are wiped when this
/// struct leaves scope.
#[derive(ZeroizeOnDrop)]
pub struct RecoveredWalletOutput {
    pub(crate) base: WalletOutput,
    pub(crate) ho: Zeroizing<[u8; 32]>,
    pub(crate) y: Zeroizing<[u8; 32]>,
    pub(crate) z: Zeroizing<[u8; 32]>,
    pub(crate) k_amount: Zeroizing<[u8; 32]>,
    pub(crate) combined_shared_secret: Zeroizing<[u8; 64]>,
    pub(crate) key_image: [u8; 32],
    /// Recovered amount from KEM decryption.
    #[zeroize(skip)]
    pub(crate) amount: u64,
}

impl Zeroize for RecoveredWalletOutput {
    fn zeroize(&mut self) {
        self.base.zeroize();
        self.ho.zeroize();
        self.y.zeroize();
        self.z.zeroize();
        self.k_amount.zeroize();
        self.combined_shared_secret.zeroize();
        self.key_image.zeroize();
        self.amount.zeroize();
    }
}

impl RecoveredWalletOutput {
    pub fn wallet_output(&self) -> &WalletOutput { &self.base }
    pub fn ho(&self) -> &[u8; 32] { &self.ho }
    pub fn y(&self) -> &[u8; 32] { &self.y }
    pub fn z(&self) -> &[u8; 32] { &self.z }
    pub fn k_amount(&self) -> &[u8; 32] { &self.k_amount }
    pub fn combined_shared_secret(&self) -> &[u8; 64] { &self.combined_shared_secret }
    pub fn key_image(&self) -> &[u8; 32] { &self.key_image }
    pub fn amount(&self) -> u64 { self.amount }

    #[cfg(any(test, feature = "test-utils"))]
    pub fn new_for_test(base: WalletOutput, amount: u64) -> Self {
        Self {
            base,
            ho: Zeroizing::new([0u8; 32]),
            y: Zeroizing::new([0u8; 32]),
            z: Zeroizing::new([0u8; 32]),
            k_amount: Zeroizing::new([0u8; 32]),
            combined_shared_secret: Zeroizing::new([0u8; 64]),
            key_image: [0u8; 32],
            amount,
        }
    }
}

/// A collection of recovered outputs from a block scan.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Timelocked(pub(crate) Vec<RecoveredWalletOutput>);

impl Timelocked {
    /// Create a Timelocked collection from a vector of outputs.
    pub fn from_vec(outputs: Vec<RecoveredWalletOutput>) -> Self {
        Self(outputs)
    }

    /// Consume the wrapper and return all outputs.
    #[must_use]
    pub fn into_inner(mut self) -> Vec<RecoveredWalletOutput> {
        let mut res = vec![];
        core::mem::swap(&mut self.0, &mut res);
        res
    }

    /// The number of outputs in this collection.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether this collection is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Errors when scanning a block.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum ScanError {
    /// The block was for an unsupported protocol version.
    #[error("unsupported protocol version ({0})")]
    UnsupportedProtocol(u8),
    /// The ScannableBlock was invalid.
    #[error("invalid scannable block ({0})")]
    InvalidScannableBlock(&'static str),
}

#[derive(Clone)]
struct InternalScanner {
    pair: ViewPair,
    spend_secret: Zeroizing<[u8; 32]>,
    subaddresses: HashMap<CompressedPoint, Option<SubaddressIndex>>,
}

impl Zeroize for InternalScanner {
    fn zeroize(&mut self) {
        self.pair.zeroize();
        self.spend_secret.zeroize();
        for (mut key, mut value) in self.subaddresses.drain() {
            key.zeroize();
            value.zeroize();
        }
    }
}
impl Drop for InternalScanner {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for InternalScanner {}

impl InternalScanner {
    fn new(pair: ViewPair, spend_secret: Zeroizing<[u8; 32]>) -> Self {
        let mut subaddresses = HashMap::new();
        subaddresses.insert(pair.spend().compress().into(), None);
        Self {
            pair,
            spend_secret,
            subaddresses,
        }
    }

    fn register_subaddress(&mut self, subaddress: SubaddressIndex) {
        let (spend, _) = self.pair.subaddress_keys(subaddress);
        self.subaddresses
            .insert(spend.compress().into(), Some(subaddress));
    }

    fn scan_transaction(
        &self,
        output_index_for_first_ringct_output: u64,
        tx_hash: [u8; 32],
        tx: &Transaction<Pruned>,
    ) -> Result<Timelocked, ScanError> {
        if tx.version() != 2 {
            return Ok(Timelocked(vec![]));
        }

        let Ok(extra) = Extra::read(&mut tx.prefix().extra.as_slice()) else {
            return Ok(Timelocked(vec![]));
        };

        let kem_ct_blob = extra.pqc_kem_ciphertext();
        let payment_id = extra.payment_id();

        let mut res = vec![];
        for (o, output) in tx.prefix().outputs.iter().enumerate() {
            let Some(output_key_point) = output.key.decompress() else {
                continue;
            };
            let output_key_bytes = output_key_point.compress().to_bytes();

            let view_tag_on_chain: u8 = output.view_tag.unwrap_or(0);

            let (enc_amount, amount_tag_on_chain, commitment_bytes) =
                match &tx {
                    Transaction::V2 { proofs: Some(ref proofs), .. } => {
                        match proofs.base.encrypted_amounts.get(o) {
                            Some(ea) => {
                                let c = proofs.base.commitments.get(o)
                                    .ok_or(ScanError::InvalidScannableBlock(
                                        "proofs without a commitment per output",
                                    ))?;
                                (ea.amount, ea.amount_tag, c.0)
                            }
                            None => continue,
                        }
                    }
                    _ => {
                        if output.amount.is_some() {
                            ([0u8; 8], 0u8, [0u8; 32])
                        } else {
                            continue;
                        }
                    }
                };

            // --- Try KEM path (tag 0x06) ---
            let Some(blob) = kem_ct_blob else { continue };
            let ct_offset = o * HYBRID_KEM_CT_BYTES;
            if blob.len() < ct_offset + HYBRID_KEM_CT_BYTES {
                continue;
            }

            let ct_slice = &blob[ct_offset..ct_offset + HYBRID_KEM_CT_BYTES];
            let ct_x25519: &[u8; 32] = ct_slice[..X25519_CT_BYTES]
                .try_into()
                .expect("slice is exactly 32 bytes");
            let ct_ml_kem = &ct_slice[X25519_CT_BYTES..];
            debug_assert_eq!(ct_ml_kem.len(), ML_KEM_768_CT_LEN);

            let recovered = match scan_output_recover(
                self.pair.x25519_sk(),
                self.pair.ml_kem_dk(),
                ct_x25519,
                ct_ml_kem,
                &output_key_bytes,
                &commitment_bytes,
                &enc_amount,
                amount_tag_on_chain,
                view_tag_on_chain,
                o as u64,
            ) {
                Ok(r) => r,
                Err(_) => continue,
            };

            // --- Subaddress lookup via recovered spend key B' ---
            let recovered_b_compressed: CompressedPoint =
                CompressedPoint(recovered.recovered_spend_key);
            let Some(subaddress) = self.subaddresses.get(&recovered_b_compressed) else {
                continue;
            };
            let subaddress = *subaddress;

            let amount = recovered.amount;
            let commitment = Commitment::new(
                curve25519_dalek::Scalar::from_canonical_bytes(recovered.z)
                    .expect("z from wide_reduce is always canonical")
                    .into(),
                amount,
            );

            // --- Key image: KI = x * Hp(O) where x = ho + b ---
            let hp_of_o = hash_to_point(output_key_bytes);
            let hp_bytes = hp_of_o.compress().to_bytes();

            let ki_result = compute_output_key_image(
                &recovered.combined_ss,
                o as u64,
                &*self.spend_secret,
                &hp_bytes,
            );
            let key_image = match ki_result {
                Ok(r) => r.key_image,
                Err(_) => continue,
            };

            // V3 does not use encrypted payment IDs. Pass through as-is.
            let decrypted_payment_id = payment_id;

            let global_index = output_index_for_first_ringct_output
                .checked_add(o as u64)
                .ok_or(ScanError::InvalidScannableBlock(
                    "transaction's output's index isn't representable as a u64",
                ))?;

            let base_output = WalletOutput {
                absolute_id: AbsoluteId {
                    transaction: tx_hash,
                    index_in_transaction: o as u64,
                },
                relative_id: RelativeId {
                    index_on_blockchain: global_index,
                },
                data: OutputData {
                    key: output_key_point,
                    key_offset: curve25519_dalek::Scalar::from_canonical_bytes(recovered.ho)
                        .expect("ho from wide_reduce is always canonical")
                        .into(),
                    commitment,
                },
                metadata: Metadata {
                    additional_timelock: tx.prefix().additional_timelock,
                    subaddress,
                    payment_id: decrypted_payment_id,
                    arbitrary_data: extra.arbitrary_data(),
                },
                staking: output.staking,
            };

            res.push(RecoveredWalletOutput {
                base: base_output,
                ho: Zeroizing::new(recovered.ho),
                y: Zeroizing::new(recovered.y),
                z: Zeroizing::new(recovered.z),
                k_amount: Zeroizing::new(recovered.k_amount),
                combined_shared_secret: Zeroizing::new(recovered.combined_ss),
                key_image,
                amount,
            });
        }

        Ok(Timelocked(res))
    }

    fn scan(&mut self, block: ScannableBlock) -> Result<Timelocked, ScanError> {
        let ScannableBlock {
            block,
            transactions,
            output_index_for_first_ringct_output,
        } = block;
        if block.transactions.len() != transactions.len() {
            Err(ScanError::InvalidScannableBlock(
                "scanning a ScannableBlock with more/less transactions than it should have",
            ))?;
        }
        let Some(mut output_index_for_first_ringct_output) =
            output_index_for_first_ringct_output
        else {
            return Ok(Timelocked(vec![]));
        };

        if block.header.hardfork_version < 1 {
            Err(ScanError::UnsupportedProtocol(block.header.hardfork_version))?;
        }

        let mut txs_with_hashes = vec![(
            block.miner_transaction().hash(),
            Transaction::<Pruned>::from(block.miner_transaction().clone()),
        )];
        for (hash, tx) in block.transactions.iter().zip(transactions) {
            txs_with_hashes.push((*hash, tx));
        }

        let mut res = Timelocked(vec![]);
        for (hash, tx) in txs_with_hashes {
            {
                let mut this_txs_outputs = vec![];
                core::mem::swap(
                    &mut self
                        .scan_transaction(output_index_for_first_ringct_output, hash, &tx)?
                        .0,
                    &mut this_txs_outputs,
                );
                res.0.extend(this_txs_outputs);
            }

            if matches!(tx, Transaction::V2 { .. }) {
                output_index_for_first_ringct_output +=
                    u64::try_from(tx.prefix().outputs.len())
                        .expect("couldn't convert amount of outputs (usize) to u64")
            }
        }

        // Shekyl never supports unencrypted payment IDs — strip them.
        for output in &mut res.0 {
            if matches!(output.base.metadata.payment_id, Some(PaymentId::Unencrypted(_))) {
                output.base.metadata.payment_id = None;
            }
        }

        Ok(res)
    }
}

/// A transaction scanner using hybrid PQC KEM (X25519 + ML-KEM-768).
///
/// Scans blocks for outputs belonging to this wallet. When an output is found,
/// its key MUST be checked against the local database for prior observation
/// (burning bug protection).
///
/// The scanner computes key images at scan time. All HKDF-derived secrets
/// (ho, y, z, k_amount) are stored in the returned `RecoveredWalletOutput`
/// to avoid re-derivation at sign time.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Scanner(InternalScanner);

impl Scanner {
    /// Create a Scanner from a ViewPair and the wallet's spend secret key.
    ///
    /// The spend secret is needed to compute key images at scan time
    /// (KI = (ho + b) * Hp(O)).
    pub fn new(pair: ViewPair, spend_secret: Zeroizing<[u8; 32]>) -> Self {
        Self(InternalScanner::new(pair, spend_secret))
    }

    /// Register a subaddress to scan for.
    pub fn register_subaddress(&mut self, subaddress: SubaddressIndex) {
        self.0.register_subaddress(subaddress)
    }

    /// Scan a block for outputs belonging to this wallet.
    pub fn scan(&mut self, block: ScannableBlock) -> Result<Timelocked, ScanError> {
        self.0.scan(block)
    }
}

/// A scanner that guarantees scanned outputs are spendable (burning-bug immune).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct GuaranteedScanner(InternalScanner);

impl GuaranteedScanner {
    /// Create a GuaranteedScanner from a GuaranteedViewPair and spend secret.
    pub fn new(pair: GuaranteedViewPair, spend_secret: Zeroizing<[u8; 32]>) -> Self {
        Self(InternalScanner::new(pair.0, spend_secret))
    }

    /// Register a subaddress to scan for.
    pub fn register_subaddress(&mut self, subaddress: SubaddressIndex) {
        self.0.register_subaddress(subaddress)
    }

    /// Scan a block for outputs belonging to this wallet.
    pub fn scan(&mut self, block: ScannableBlock) -> Result<Timelocked, ScanError> {
        self.0.scan(block)
    }
}
