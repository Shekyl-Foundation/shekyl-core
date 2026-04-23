// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Payment ID carried in a transaction's `tx_extra` nonce field.
//!
//! Shekyl V3 is NOT backward-compatible with Monero's payment-ID zoo. The legacy
//! 32-byte unencrypted form has been dropped from the protocol: the only accepted
//! shape is an 8-byte encrypted ID. `PaymentId::read` refuses the legacy marker
//! byte, so no downstream "strip unencrypted" defensive code is needed — the type
//! cannot represent an unencrypted ID.

use core::ops::BitXor;
use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Wire marker byte for an encrypted payment ID.
const ENCRYPTED_PAYMENT_ID_MARKER: u8 = 1;

/// An 8-byte encrypted payment ID.
///
/// Wire form: marker byte `0x01` followed by 8 bytes of ciphertext. The previous
/// Monero-era 32-byte unencrypted form (marker `0x00`) is REJECTED at parse time.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize, Serialize, Deserialize)]
pub struct PaymentId(pub [u8; 8]);

impl BitXor<[u8; 8]> for PaymentId {
    type Output = PaymentId;

    fn bitxor(self, bytes: [u8; 8]) -> PaymentId {
        PaymentId((u64::from_le_bytes(self.0) ^ u64::from_le_bytes(bytes)).to_le_bytes())
    }
}

impl PaymentId {
    /// The raw ciphertext bytes.
    pub const fn bytes(&self) -> &[u8; 8] {
        &self.0
    }

    /// Write the PaymentId's wire form (marker `0x01` || 8 bytes).
    pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&[ENCRYPTED_PAYMENT_ID_MARKER])?;
        w.write_all(&self.0)
    }

    /// Serialize the PaymentId's wire form to a `Vec<u8>` (9 bytes).
    pub fn serialize(&self) -> Vec<u8> {
        let mut res = Vec::with_capacity(1 + 8);
        self.write(&mut res)
            .expect("write failed but <Vec as io::Write> doesn't fail");
        res
    }

    /// Read a PaymentId from its wire form. Rejects any marker other than `0x01`.
    pub fn read<R: Read>(r: &mut R) -> io::Result<PaymentId> {
        let mut marker = [0u8; 1];
        r.read_exact(&mut marker)?;
        match marker[0] {
            ENCRYPTED_PAYMENT_ID_MARKER => {
                let mut buf = [0u8; 8];
                r.read_exact(&mut buf)?;
                Ok(PaymentId(buf))
            }
            0 => Err(io::Error::other(
                "unencrypted payment IDs are not supported in Shekyl V3",
            )),
            _ => Err(io::Error::other("unknown payment ID marker")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_roundtrip() {
        let p = PaymentId([1, 2, 3, 4, 5, 6, 7, 8]);
        let s = serde_json::to_string(&p).unwrap();
        let back: PaymentId = serde_json::from_str(&s).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn wire_roundtrip() {
        let p = PaymentId([9, 8, 7, 6, 5, 4, 3, 2]);
        let bytes = p.serialize();
        assert_eq!(bytes.len(), 9);
        assert_eq!(bytes[0], ENCRYPTED_PAYMENT_ID_MARKER);
        let back = PaymentId::read(&mut bytes.as_slice()).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn read_rejects_unencrypted_marker() {
        // Legacy Monero-era 32-byte unencrypted payment ID.
        let mut legacy = vec![0u8];
        legacy.extend_from_slice(&[0x11; 32]);
        let err = PaymentId::read(&mut legacy.as_slice()).unwrap_err();
        assert!(err.to_string().contains("unencrypted"));
    }

    #[test]
    fn read_rejects_unknown_marker() {
        let blob = [0xFFu8, 0, 0, 0, 0, 0, 0, 0, 0];
        let err = PaymentId::read(&mut blob.as_slice()).unwrap_err();
        assert!(err.to_string().contains("unknown payment ID marker"));
    }

    #[test]
    fn bitxor_encrypt_decrypt() {
        let key = [0xDEu8, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        let clear = PaymentId([1, 2, 3, 4, 5, 6, 7, 8]);
        let encrypted = clear ^ key;
        let round = encrypted ^ key;
        assert_eq!(clear, round);
    }
}
