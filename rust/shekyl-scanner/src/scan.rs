// Copyright (c) 2025-2026, The Shekyl Foundation
//
// Adapted from monero-oxide (shekyl-wallet), MIT license.
// All rights reserved.
// BSD-3-Clause

//! Block and transaction scanning pipeline.
//!
//! Scans `ScannableBlock`s for outputs belonging to the wallet's view pair,
//! with Shekyl extensions for KEM decapsulation and staking detection.

use core::ops::Deref;
use std::collections::HashMap;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;

use shekyl_oxide::{
    io::CompressedPoint,
    primitives::Commitment,
    transaction::{Timelock, Pruned, Transaction},
};
use shekyl_rpc::ScannableBlock;

use crate::{
    SubaddressIndex,
    ViewPair,
    GuaranteedViewPair,
    SharedKeyDerivations,
    extra::{Extra, PaymentId},
    output::*,
};

/// A collection of outputs that may be subject to additional timelocks.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Timelocked(pub(crate) Vec<WalletOutput>);

impl Timelocked {
    /// Create a Timelocked collection from a vector of outputs.
    pub fn from_vec(outputs: Vec<WalletOutput>) -> Self {
        Self(outputs)
    }

    /// Return only the outputs without additional timelocks.
    #[must_use]
    pub fn not_additionally_locked(self) -> Vec<WalletOutput> {
        self.0
            .iter()
            .filter(|o| o.additional_timelock() == Timelock::None)
            .cloned()
            .collect()
    }

    /// Return outputs whose additional timelock is satisfied by the given block/time.
    #[must_use]
    pub fn additional_timelock_satisfied_by(self, block: usize, time: u64) -> Vec<WalletOutput> {
        self.0
            .iter()
            .filter(|o| {
                (o.additional_timelock() <= Timelock::Block(block))
                    || (o.additional_timelock() <= Timelock::Time(time))
            })
            .cloned()
            .collect()
    }

    /// Consume the wrapper and return all outputs, ignoring timelocks.
    #[must_use]
    pub fn ignore_additional_timelock(mut self) -> Vec<WalletOutput> {
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
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
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
    guaranteed: bool,
    subaddresses: HashMap<CompressedPoint, Option<SubaddressIndex>>,
}

impl Zeroize for InternalScanner {
    fn zeroize(&mut self) {
        self.pair.zeroize();
        self.guaranteed.zeroize();
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
    fn new(pair: ViewPair, guaranteed: bool) -> Self {
        let mut subaddresses = HashMap::new();
        subaddresses.insert(pair.spend().compress().into(), None);
        Self {
            pair,
            guaranteed,
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

        let Some((tx_keys, additional)) = extra.keys() else {
            return Ok(Timelocked(vec![]));
        };
        let payment_id = extra.payment_id();

        let mut res = vec![];
        for (o, output) in tx.prefix().outputs.iter().enumerate() {
            let Some(output_key) = output.key.decompress() else {
                continue;
            };

            let additional = additional.as_ref().map(|additional| additional.get(o));

            #[allow(clippy::manual_let_else)]
            for key in tx_keys
                .iter()
                .map(|key| Some(Some(key)))
                .chain(core::iter::once(additional))
            {
                let key = match key {
                    Some(Some(key)) => key,
                    Some(None) | None => continue,
                };

                let ecdh = Zeroizing::new(self.pair.view.deref() * key);
                let output_derivations = SharedKeyDerivations::output_derivations(
                    if self.guaranteed {
                        Some(SharedKeyDerivations::uniqueness(&tx.prefix().inputs))
                    } else {
                        None
                    },
                    ecdh.clone(),
                    o,
                );

                if let Some(actual_view_tag) = output.view_tag {
                    if actual_view_tag != output_derivations.view_tag {
                        continue;
                    }
                }

                let Some(subaddress) = ({
                    let subaddress_spend_key =
                        output_key - (&output_derivations.shared_key * ED25519_BASEPOINT_TABLE);
                    self.subaddresses
                        .get::<CompressedPoint>(&subaddress_spend_key.compress().into())
                }) else {
                    continue;
                };
                let subaddress = *subaddress;

                let mut key_offset = output_derivations.shared_key;
                if let Some(subaddress) = subaddress {
                    key_offset += self.pair.subaddress_derivation(subaddress);
                }

                let mut commitment = Commitment::zero();

                if let Some(amount) = output.amount {
                    commitment.amount = amount;
                } else {
                    let Transaction::V2 {
                        proofs: Some(ref proofs),
                        ..
                    } = &tx
                    else {
                        Err(ScanError::InvalidScannableBlock(
                            "non-miner v2 transaction without proofs",
                        ))?
                    };

                    commitment = match proofs.base.encrypted_amounts.get(o) {
                        Some(amount) => output_derivations.decrypt(amount),
                        None => Err(ScanError::InvalidScannableBlock(
                            "proofs without an encrypted amount per output",
                        ))?,
                    };

                    if Some(&CompressedPoint::from(commitment.calculate().compress()))
                        != proofs.base.commitments.get(o)
                    {
                        continue;
                    }
                }

                let payment_id =
                    payment_id.map(|id| id ^ SharedKeyDerivations::payment_id_xor(ecdh));

                let o = u64::try_from(o).expect("couldn't convert output index (usize) to u64");

                res.push(WalletOutput {
                    absolute_id: AbsoluteId {
                        transaction: tx_hash,
                        index_in_transaction: o,
                    },
                    relative_id: RelativeId {
                        index_on_blockchain: output_index_for_first_ringct_output
                            .checked_add(o)
                            .ok_or(ScanError::InvalidScannableBlock(
                                "transaction's output's index isn't representable as a u64",
                            ))?,
                    },
                    data: OutputData {
                        key: output_key,
                        key_offset,
                        commitment,
                    },
                    metadata: Metadata {
                        additional_timelock: tx.prefix().additional_timelock,
                        subaddress,
                        payment_id,
                        arbitrary_data: extra.arbitrary_data(),
                    },
                    staking: output.staking,
                });

                break;
            }
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

        // Shekyl never supports unencrypted payment IDs
        for output in &mut res.0 {
            if matches!(output.metadata.payment_id, Some(PaymentId::Unencrypted(_))) {
                output.metadata.payment_id = None;
            }
        }

        Ok(res)
    }
}

/// A transaction scanner for finding received outputs.
///
/// When an output is found, its key MUST be checked against the local database
/// for prior observation (burning bug protection).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Scanner(InternalScanner);

impl Scanner {
    /// Create a Scanner from a ViewPair.
    pub fn new(pair: ViewPair) -> Self {
        Self(InternalScanner::new(pair, false))
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
    /// Create a GuaranteedScanner from a GuaranteedViewPair.
    pub fn new(pair: GuaranteedViewPair) -> Self {
        Self(InternalScanner::new(pair.0, true))
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
