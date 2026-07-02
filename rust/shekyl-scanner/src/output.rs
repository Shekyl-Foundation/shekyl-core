// Copyright (c) 2025-2026, The Shekyl Foundation
//
// Adapted from monero-oxide (shekyl-wallet), MIT license.
// All rights reserved.
// BSD-3-Clause

//! Scanned output representation.

use std::io::{self, Read, Write};

use zeroize::{Zeroize, ZeroizeOnDrop};

use curve25519_dalek::{edwards::EdwardsPoint, Scalar};

use shekyl_curve_io::*;
use shekyl_curve_primitives::Commitment;
use shekyl_types::Timelock;

use crate::extra::{PaymentId, MAX_ARBITRARY_DATA_SIZE, MAX_EXTRA_SIZE_BY_RELAY_RULE};

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub(crate) struct AbsoluteId {
    pub(crate) transaction: [u8; 32],
    pub(crate) index_in_transaction: u64,
}

impl core::fmt::Debug for AbsoluteId {
    fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        fmt.debug_struct("AbsoluteId")
            .field("transaction", &hex::encode(self.transaction))
            .field("index_in_transaction", &self.index_in_transaction)
            .finish()
    }
}

impl AbsoluteId {
    fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.transaction)?;
        w.write_all(&self.index_in_transaction.to_le_bytes())
    }

    fn read<R: Read>(r: &mut R) -> io::Result<AbsoluteId> {
        Ok(AbsoluteId {
            transaction: read_bytes(r)?,
            index_in_transaction: read_u64(r)?,
        })
    }
}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub(crate) struct RelativeId {
    pub(crate) index_on_blockchain: u64,
}

impl core::fmt::Debug for RelativeId {
    fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        fmt.debug_struct("RelativeId")
            .field("index_on_blockchain", &self.index_on_blockchain)
            .finish()
    }
}

impl RelativeId {
    fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.index_on_blockchain.to_le_bytes())
    }

    fn read<R: Read>(r: &mut R) -> io::Result<Self> {
        Ok(RelativeId {
            index_on_blockchain: read_u64(r)?,
        })
    }
}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub(crate) struct OutputData {
    pub(crate) key: EdwardsPoint,
    pub(crate) key_offset: Scalar,
    pub(crate) commitment: Commitment,
}

impl core::fmt::Debug for OutputData {
    fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        fmt.debug_struct("OutputData")
            .field("key", &hex::encode(self.key.compress().0))
            .field("commitment", &self.commitment)
            .finish_non_exhaustive()
    }
}

impl OutputData {
    pub(crate) fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.key.compress().to_bytes())?;
        w.write_all(&self.key_offset.to_bytes())?;
        self.commitment.write(w)
    }

    pub(crate) fn read<R: Read>(r: &mut R) -> io::Result<OutputData> {
        Ok(OutputData {
            key: read_point(r)?,
            key_offset: read_scalar(r)?,
            commitment: Commitment::read(r)?,
        })
    }
}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub(crate) struct Metadata {
    pub(crate) additional_timelock: Timelock,
    pub(crate) payment_id: Option<PaymentId>,
    pub(crate) arbitrary_data: Vec<Vec<u8>>,
}

impl core::fmt::Debug for Metadata {
    fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        fmt.debug_struct("Metadata")
            .field("additional_timelock", &self.additional_timelock)
            .field("payment_id", &self.payment_id)
            .field(
                "arbitrary_data",
                &self
                    .arbitrary_data
                    .iter()
                    .map(hex::encode)
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl Metadata {
    fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        // Block-height-only unlock encoding: 0 = None, else the block height. The
        // owning wire format keeps the varint; `Timelock` is a pure value type.
        write_varint(&self.additional_timelock.to_unlock_raw(), w)?;

        // FA-2: subaddress metadata slot is always absent on wire.
        w.write_all(&[0])?;

        if let Some(payment_id) = self.payment_id {
            w.write_all(&[1])?;
            payment_id.write(w)?;
        } else {
            w.write_all(&[0])?;
        }

        write_varint(&self.arbitrary_data.len(), w)?;
        for part in &self.arbitrary_data {
            const _ASSERT_MAX_ARBITRARY_DATA_SIZE_FITS_WITHIN_U8: [(); (u8::MAX as usize)
                - MAX_ARBITRARY_DATA_SIZE] = [(); _];
            w.write_all(&[u8::try_from(part.len())
                .expect("piece of arbitrary data exceeded max length of u8::MAX")])?;
            w.write_all(part)?;
        }
        Ok(())
    }

    fn read<R: Read>(r: &mut R) -> io::Result<Metadata> {
        // Lift through the canonical, sentinel-aware lift (not a bare 0→None/else→Block
        // cast): a persisted value `>= UNLOCK_TIME_BLOCK_SENTINEL` is the deleted
        // timestamp form (corruption or a legacy cache), and is mapped to `None` rather
        // than materialized as a huge `Timelock::Block`, preserving block-height-only.
        let additional_timelock = crate::scan::timelock_from_unlock_time(read_varint(r)?);

        match read_byte(r)? {
            0 => {}
            1 => {
                let _ = read_u32(r)?;
                return Err(io::Error::other(
                    "subaddress metadata not supported at V3.0 (FA-2)",
                ));
            }
            _ => {
                return Err(io::Error::other(
                    "invalid subaddress is_some boolean in metadata",
                ));
            }
        }

        Ok(Metadata {
            additional_timelock,
            payment_id: if read_byte(r)? == 1 {
                PaymentId::read(r).ok()
            } else {
                None
            },
            arbitrary_data: {
                let mut data = vec![];
                let mut total_len = 0usize;
                for _ in 0..read_varint::<_, usize>(r)? {
                    let len = read_byte(r)?;
                    let chunk = read_raw_vec(read_byte, usize::from(len), r)?;
                    total_len = total_len.wrapping_add(chunk.len());
                    if total_len > MAX_EXTRA_SIZE_BY_RELAY_RULE {
                        Err(io::Error::other(
                            "amount of arbitrary data exceeded amount allowed by policy",
                        ))?;
                    }
                    data.push(chunk);
                }
                data
            },
        })
    }
}

/// A scanned output and all associated data.
///
/// Contains everything needed to spend this output or treat it as a payment.
/// Bound to a specific blockchain state; must be discarded on reorg.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct WalletOutput {
    pub(crate) absolute_id: AbsoluteId,
    pub(crate) relative_id: RelativeId,
    pub(crate) data: OutputData,
    pub(crate) metadata: Metadata,
}

impl WalletOutput {
    /// The hash of the transaction that created this output.
    pub fn transaction(&self) -> [u8; 32] {
        self.absolute_id.transaction
    }

    /// The output's index within its transaction.
    pub fn index_in_transaction(&self) -> u64 {
        self.absolute_id.index_in_transaction
    }

    /// The output's global index on the blockchain.
    pub fn index_on_blockchain(&self) -> u64 {
        self.relative_id.index_on_blockchain
    }

    /// The output key.
    pub fn key(&self) -> EdwardsPoint {
        self.data.key
    }

    /// Scalar offset: `spend_key + key_offset` is the discrete log of the output key.
    pub fn key_offset(&self) -> Scalar {
        self.data.key_offset
    }

    /// The Pedersen commitment for this output.
    pub fn commitment(&self) -> &Commitment {
        &self.data.commitment
    }

    /// Additional timelock beyond the default 10-block lock window.
    pub fn additional_timelock(&self) -> Timelock {
        self.metadata.additional_timelock
    }

    /// Payment ID included with this output.
    pub fn payment_id(&self) -> Option<PaymentId> {
        self.metadata.payment_id
    }

    /// Arbitrary data from the transaction's extra field.
    pub fn arbitrary_data(&self) -> &[Vec<u8>] {
        &self.metadata.arbitrary_data
    }

    /// Construct a WalletOutput for testing or programmatic use.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn new_for_test(
        tx_hash: [u8; 32],
        index_in_transaction: u64,
        index_on_blockchain: u64,
        key: curve25519_dalek::edwards::EdwardsPoint,
        key_offset: curve25519_dalek::Scalar,
        commitment: shekyl_curve_primitives::Commitment,
    ) -> Self {
        WalletOutput {
            absolute_id: AbsoluteId {
                transaction: tx_hash,
                index_in_transaction,
            },
            relative_id: RelativeId {
                index_on_blockchain,
            },
            data: OutputData {
                key,
                key_offset,
                commitment,
            },
            metadata: Metadata {
                additional_timelock: Timelock::None,
                payment_id: None,
                arbitrary_data: vec![],
            },
        }
    }

    /// Set the additional timelock (test/programmatic builder). Lets a test
    /// construct a coinbase-style block-locked output without widening
    /// [`Self::new_for_test`]'s signature for every caller.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn with_additional_timelock(mut self, timelock: Timelock) -> Self {
        self.metadata.additional_timelock = timelock;
        self
    }

    /// Write the WalletOutput.
    pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        self.absolute_id.write(w)?;
        self.relative_id.write(w)?;
        self.data.write(w)?;
        self.metadata.write(w)?;
        Ok(())
    }

    /// Serialize the WalletOutput to a `Vec<u8>`.
    pub fn serialize(&self) -> Vec<u8> {
        let mut serialized = Vec::with_capacity(128);
        self.write(&mut serialized)
            .expect("write failed but <Vec as io::Write> doesn't fail");
        serialized
    }

    /// Read a WalletOutput.
    pub fn read<R: Read>(r: &mut R) -> io::Result<WalletOutput> {
        let absolute_id = AbsoluteId::read(r)?;
        let relative_id = RelativeId::read(r)?;
        let data = OutputData::read(r)?;
        let metadata = Metadata::read(r)?;
        Ok(WalletOutput {
            absolute_id,
            relative_id,
            data,
            metadata,
        })
    }
}
