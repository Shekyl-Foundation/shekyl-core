// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Region-2 payload framing: "Shekyl Wallet State Payload" (SWSP).
//!
//! The envelope layer ([`shekyl_crypto_pq::wallet_envelope`]) treats
//! `.wallet`'s post-decryption plaintext as opaque bytes. That is the
//! right split: the envelope is responsible for confidentiality and
//! companion-file binding, and deliberately does not know what lives
//! inside. This module supplies the framing layer that sits *immediately
//! inside* Region 2's ciphertext and tells the orchestrator:
//!
//! - "This really is a Shekyl wallet state payload, not random bytes a
//!   future bug happened to feed to `open_state_file`." (`SWSP` magic)
//! - "Which payload schema am I?" (`payload_kind`, currently only
//!   `WalletLedgerPostcard = 0x01`)
//! - "Which version of that schema?" (`payload_version`, currently `0x01`)
//! - "How long is the body?" (`body_len`, u32 LE)
//!
//! # Why a separate framing layer?
//!
//! Without a frame, Region 2's "plaintext" would be *exactly* the
//! postcard-encoded `WalletLedger`. That couples two concerns we want to
//! keep orthogonal:
//!
//! 1. **Versioning.** Bumping the envelope's `state_version` changes the
//!    on-disk layout. Bumping `WalletLedger`'s `format_version` changes
//!    only the payload. Without a framing layer, every payload-schema
//!    change forces an envelope bump (or vice versa). SWSP decouples
//!    them: envelope owns AEAD/binding; SWSP owns "what kind of
//!    plaintext does this wallet file carry".
//!
//! 2. **Payload kinds.** V3.0 writes exactly one kind
//!    (`WalletLedgerPostcard`). V3.1+ may introduce variants for
//!    hardware-offload state, multisig rounds, or streaming-chunked
//!    ledgers. `payload_kind` lets the orchestrator refuse an unknown
//!    kind loudly instead of feeding it to postcard and watching the
//!    decode explode at a random offset.
//!
//! 3. **KATs separate from envelope KATs.** This module's KATs exercise
//!    SWSP framing byte-for-byte against synthesized bodies. They do
//!    *not* sit behind a keys-file / password / Argon2 derivation. This
//!    separation was explicitly called out in plan review: "Region-2
//!    payload framing requires its own KATs, distinct from envelope
//!    KATs." Envelope KATs live in `docs/test_vectors/` and test the
//!    full sealed blob; SWSP KATs test just bytes [0..12+body_len).
//!
//! # Wire format (frozen at `payload_version = 0x01`)
//!
//! | Offset | Bytes | Field             | Notes                           |
//! |--------|-------|-------------------|---------------------------------|
//! | 0      | 4     | `magic = "SWSP"`  | ASCII, fixed                    |
//! | 4      | 1     | `payload_version` | `0x01` for V3.0                 |
//! | 5      | 1     | `payload_kind`    | `0x01` = `WalletLedgerPostcard` |
//! | 6      | 2     | `_reserved = 00`  | must be zero on V3.0            |
//! | 8      | 4     | `body_len` (LE)   | u32, length of `body` in bytes  |
//! | 12     | N     | `body`            | kind-specific bytes             |
//!
//! Total framed size = `12 + body_len`. `u32` caps `body_len` at ~4 GiB;
//! a realistic wallet ledger is well under 1 MiB, so u32 is ample.
//!
//! # Refusal discipline
//!
//! [`decode_payload`] refuses, in this order:
//!
//! 1. Input shorter than the 12-byte header.
//! 2. Magic mismatch. This is the "someone fed us non-SWSP bytes" case.
//! 3. `payload_version > CURRENT_PAYLOAD_VERSION`. V3.0 never silently
//!    migrates forward.
//! 4. `payload_kind` not in the enum.
//! 5. `_reserved != 0`. V3.0 pins reserved bytes to zero; a future V3.1
//!    may repurpose them, but V3.0 refuses to interpret files that set
//!    them.
//! 6. `12 + body_len` not equal to the framed slice length. No silent
//!    trailing bytes, no truncation.
//!
//! Every refusal is a typed `PayloadError` variant so the orchestrator
//! can surface precise diagnostics without leaking information about
//! which specific check failed across a trust boundary (the envelope
//! AEAD already authenticated these bytes, so the refusal happens after
//! the AEAD check; it is not a password oracle).

/// Fixed 4-byte magic that identifies a Region-2 plaintext as an SWSP-
/// framed Shekyl wallet state payload. Distinct from the envelope's
/// `SHEKYLWT` / `SHEKYLWS` magics, which live outside the AEAD.
pub const PAYLOAD_MAGIC: &[u8; 4] = b"SWSP";

/// The only payload_version this binary writes. Readers refuse anything
/// strictly greater. Bumping this value is a hard-fork-style change to
/// the payload schema and requires a matching docs update in
/// `docs/WALLET_FILE_FORMAT_V1.md` (and, when V2 ships, a V2 spec file).
pub const CURRENT_PAYLOAD_VERSION: u8 = 0x01;

/// Size of the fixed SWSP header. `body` begins at this offset.
pub const PAYLOAD_HEADER_LEN: usize = 12;

/// Upper bound on `body_len` we're willing to read. u32::MAX is obviously
/// too large to be a real wallet; this cap is a sanity guard rather than
/// a security invariant (the envelope already authenticates the full
/// ciphertext length). 64 MiB is ~1000× a realistic wallet ledger and
/// still fits a pathological test easily.
pub const PAYLOAD_BODY_MAX: usize = 64 * 1024 * 1024;

/// Discriminator for `payload_kind`. Encoded as a single byte on the
/// wire; the enum exists so the orchestrator cannot accidentally accept
/// a kind it does not know how to decode.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PayloadKind {
    /// `body` is a postcard-encoded [`shekyl_wallet_state::WalletLedger`].
    /// This is the only kind V3.0 writes and reads.
    WalletLedgerPostcard = 0x01,
}

impl PayloadKind {
    /// Parse the single `payload_kind` byte. Rejects unknown values
    /// loudly rather than casting into `transmute`-style UB.
    pub fn from_byte(byte: u8) -> Result<Self, PayloadError> {
        match byte {
            0x01 => Ok(Self::WalletLedgerPostcard),
            other => Err(PayloadError::UnknownPayloadKind(other)),
        }
    }
}

/// Typed refusal reasons for [`decode_payload`]. Each variant maps 1:1
/// to a specific pre-condition violation. No variant carries the body
/// bytes themselves — keeping refusals cheap and allocation-free helps
/// the hot "is this a valid wallet file?" path.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PayloadError {
    /// Slice shorter than the 12-byte fixed header.
    #[error("payload too short: got {got} bytes, need at least {need}")]
    TooShort { got: usize, need: usize },

    /// Magic mismatch. The envelope's AEAD succeeded, but the bytes
    /// inside do not start with `SWSP`. Most likely cause in practice:
    /// a future payload schema we were not compiled to read, or a file
    /// that was sealed by some other tool reusing the envelope.
    #[error("payload magic mismatch: expected b\"SWSP\"")]
    BadMagic,

    /// File's `payload_version` is strictly greater than what this
    /// binary knows how to interpret. No silent migration.
    #[error(
        "unsupported payload version: file = {file}, binary = {binary}; \
         no migration path exists in this binary"
    )]
    UnsupportedVersion { file: u8, binary: u8 },

    /// `payload_kind` byte did not match any known [`PayloadKind`].
    #[error("unknown payload kind byte: 0x{0:02x}")]
    UnknownPayloadKind(u8),

    /// V3.0 pins the two reserved bytes at offsets [6..8) to zero.
    /// A non-zero value indicates either a future schema or a
    /// corruption the AEAD did not catch (shouldn't happen, but belt-
    /// and-braces).
    #[error("reserved bytes must be zero in payload_version 0x01")]
    NonZeroReserved,

    /// The `body_len` header field does not match the actual slice
    /// length. `12 + body_len` must equal `input.len()` exactly.
    #[error("body length mismatch: header says {declared}, slice has {actual} trailing bytes")]
    BodyLenMismatch { declared: usize, actual: usize },

    /// `body_len` exceeds [`PAYLOAD_BODY_MAX`]. Not a security invariant
    /// (the AEAD already authenticated the length) but a DoS / sanity
    /// guard that refuses obviously malformed inputs before we allocate.
    #[error("body length {got} exceeds sanity cap of {cap} bytes")]
    BodyLenTooLarge { got: usize, cap: usize },
}

/// Decoded SWSP frame. The orchestrator pulls `body` out of here and
/// hands it to the per-kind decoder (currently postcard → `WalletLedger`).
/// `body` borrows from the caller's input buffer; no allocation on the
/// hot decode path.
#[derive(Debug, PartialEq, Eq)]
pub struct DecodedPayload<'a> {
    /// Must equal [`CURRENT_PAYLOAD_VERSION`] for a binary that just
    /// successfully decoded. A future reader binary that accepts
    /// multiple versions would populate this accordingly.
    pub payload_version: u8,
    /// Refusal happens before this field is populated, so by the time a
    /// caller sees it, it is guaranteed to be a known kind.
    pub payload_kind: PayloadKind,
    /// Slice of the kind-specific body, already length-validated.
    pub body: &'a [u8],
}

/// Encode a framed payload. The caller supplies a `body` slice (for the
/// only current kind, this is the postcard-encoded `WalletLedger`) and
/// we prepend the 12-byte SWSP header. The returned `Vec<u8>` is what
/// gets handed to [`shekyl_crypto_pq::wallet_envelope::seal_state_file`]
/// as the `state_plaintext` argument.
///
/// # Errors
///
/// [`PayloadError::BodyLenTooLarge`] if `body.len()` exceeds
/// [`PAYLOAD_BODY_MAX`]. This is the only failure mode on the encode
/// side: magic, version, kind, and reserved bytes are pinned by
/// construction.
pub fn encode_payload(kind: PayloadKind, body: &[u8]) -> Result<Vec<u8>, PayloadError> {
    if body.len() > PAYLOAD_BODY_MAX {
        return Err(PayloadError::BodyLenTooLarge {
            got: body.len(),
            cap: PAYLOAD_BODY_MAX,
        });
    }
    let body_len_u32 = u32::try_from(body.len()).expect("checked against PAYLOAD_BODY_MAX above");

    let mut out = Vec::with_capacity(PAYLOAD_HEADER_LEN + body.len());
    out.extend_from_slice(PAYLOAD_MAGIC);
    out.push(CURRENT_PAYLOAD_VERSION);
    out.push(kind as u8);
    out.extend_from_slice(&[0u8, 0u8]); // _reserved
    out.extend_from_slice(&body_len_u32.to_le_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

/// Decode a framed payload. Zero-copy: `result.body` borrows from
/// `input`. See the module docs for the exact refusal order.
pub fn decode_payload(input: &[u8]) -> Result<DecodedPayload<'_>, PayloadError> {
    if input.len() < PAYLOAD_HEADER_LEN {
        return Err(PayloadError::TooShort {
            got: input.len(),
            need: PAYLOAD_HEADER_LEN,
        });
    }
    if &input[0..4] != PAYLOAD_MAGIC {
        return Err(PayloadError::BadMagic);
    }
    let payload_version = input[4];
    if payload_version > CURRENT_PAYLOAD_VERSION {
        return Err(PayloadError::UnsupportedVersion {
            file: payload_version,
            binary: CURRENT_PAYLOAD_VERSION,
        });
    }
    let payload_kind = PayloadKind::from_byte(input[5])?;
    if input[6] != 0 || input[7] != 0 {
        return Err(PayloadError::NonZeroReserved);
    }
    let body_len_bytes: [u8; 4] = input[8..12]
        .try_into()
        .expect("slice length pinned by PAYLOAD_HEADER_LEN");
    let body_len = u32::from_le_bytes(body_len_bytes) as usize;
    if body_len > PAYLOAD_BODY_MAX {
        return Err(PayloadError::BodyLenTooLarge {
            got: body_len,
            cap: PAYLOAD_BODY_MAX,
        });
    }
    let declared_total =
        PAYLOAD_HEADER_LEN
            .checked_add(body_len)
            .ok_or(PayloadError::BodyLenTooLarge {
                got: body_len,
                cap: PAYLOAD_BODY_MAX,
            })?;
    if declared_total != input.len() {
        return Err(PayloadError::BodyLenMismatch {
            declared: declared_total,
            actual: input.len(),
        });
    }
    Ok(DecodedPayload {
        payload_version,
        payload_kind,
        body: &input[PAYLOAD_HEADER_LEN..],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// KAT #1: empty body. The smallest legal frame. This vector is
    /// hand-computed and must remain byte-stable across refactors — if
    /// it ever changes the payload_version must bump.
    #[test]
    fn kat_empty_body_is_byte_stable() {
        let encoded = encode_payload(PayloadKind::WalletLedgerPostcard, &[]).unwrap();
        assert_eq!(
            encoded,
            [
                b'S', b'W', b'S', b'P', // magic
                0x01, // payload_version
                0x01, // payload_kind = WalletLedgerPostcard
                0x00, 0x00, // reserved
                0x00, 0x00, 0x00, 0x00, // body_len = 0 (LE)
            ],
            "SWSP empty-body frame must be byte-stable; bumping payload_version is a \
             format-breaking change requiring a docs/CHANGELOG entry"
        );
        let decoded = decode_payload(&encoded).unwrap();
        assert_eq!(decoded.payload_version, 0x01);
        assert_eq!(decoded.payload_kind, PayloadKind::WalletLedgerPostcard);
        assert_eq!(decoded.body, b"");
    }

    /// KAT #2: small non-empty body. Exercises the u32-LE body_len
    /// encoding and the zero-copy body slice.
    #[test]
    fn kat_short_body_is_byte_stable() {
        let body = b"hello";
        let encoded = encode_payload(PayloadKind::WalletLedgerPostcard, body).unwrap();
        assert_eq!(
            encoded,
            [
                b'S', b'W', b'S', b'P', // magic
                0x01, // payload_version
                0x01, // payload_kind
                0x00, 0x00, // reserved
                0x05, 0x00, 0x00, 0x00, // body_len = 5 (LE)
                b'h', b'e', b'l', b'l', b'o',
            ]
        );
        let decoded = decode_payload(&encoded).unwrap();
        assert_eq!(decoded.body, body);
    }

    /// KAT #3: body_len straddling a byte boundary to catch endianness
    /// bugs (0x1234 = 4660 bytes, LE = `34 12 00 00`).
    #[test]
    fn kat_body_len_encoding_is_little_endian() {
        let body = vec![0xABu8; 0x1234];
        let encoded = encode_payload(PayloadKind::WalletLedgerPostcard, &body).unwrap();
        assert_eq!(&encoded[8..12], &[0x34, 0x12, 0x00, 0x00]);
        let decoded = decode_payload(&encoded).unwrap();
        assert_eq!(decoded.body.len(), 0x1234);
        assert!(decoded.body.iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn roundtrip_large_body_within_cap() {
        let body = vec![0x42u8; 1024 * 1024];
        let encoded = encode_payload(PayloadKind::WalletLedgerPostcard, &body).unwrap();
        let decoded = decode_payload(&encoded).unwrap();
        assert_eq!(decoded.body, body.as_slice());
    }

    #[test]
    fn refuse_below_header_len() {
        for n in 0..PAYLOAD_HEADER_LEN {
            let short = vec![0u8; n];
            let err = decode_payload(&short).unwrap_err();
            match err {
                PayloadError::TooShort { got, need } => {
                    assert_eq!(got, n);
                    assert_eq!(need, PAYLOAD_HEADER_LEN);
                }
                other => panic!("unexpected refusal for len={n}: {other:?}"),
            }
        }
    }

    #[test]
    fn refuse_bad_magic() {
        let mut bytes = encode_payload(PayloadKind::WalletLedgerPostcard, b"body").unwrap();
        bytes[0] = b'X';
        assert_eq!(decode_payload(&bytes).unwrap_err(), PayloadError::BadMagic);
    }

    #[test]
    fn refuse_future_payload_version() {
        let mut bytes = encode_payload(PayloadKind::WalletLedgerPostcard, b"body").unwrap();
        bytes[4] = 0x02;
        let err = decode_payload(&bytes).unwrap_err();
        assert!(
            matches!(
                err,
                PayloadError::UnsupportedVersion {
                    file: 0x02,
                    binary: 0x01
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn refuse_unknown_payload_kind() {
        let mut bytes = encode_payload(PayloadKind::WalletLedgerPostcard, b"body").unwrap();
        bytes[5] = 0xFF;
        let err = decode_payload(&bytes).unwrap_err();
        assert_eq!(err, PayloadError::UnknownPayloadKind(0xFF));
    }

    #[test]
    fn refuse_nonzero_reserved() {
        let mut bytes = encode_payload(PayloadKind::WalletLedgerPostcard, b"body").unwrap();
        bytes[6] = 0x01;
        assert_eq!(
            decode_payload(&bytes).unwrap_err(),
            PayloadError::NonZeroReserved
        );

        let mut bytes2 = encode_payload(PayloadKind::WalletLedgerPostcard, b"body").unwrap();
        bytes2[7] = 0x01;
        assert_eq!(
            decode_payload(&bytes2).unwrap_err(),
            PayloadError::NonZeroReserved
        );
    }

    #[test]
    fn refuse_body_len_mismatch_trailing() {
        let mut bytes = encode_payload(PayloadKind::WalletLedgerPostcard, b"body").unwrap();
        bytes.push(0xCC);
        let err = decode_payload(&bytes).unwrap_err();
        match err {
            PayloadError::BodyLenMismatch { declared, actual } => {
                assert_eq!(declared, PAYLOAD_HEADER_LEN + 4);
                assert_eq!(actual, PAYLOAD_HEADER_LEN + 5);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn refuse_body_len_mismatch_truncated() {
        let mut bytes = encode_payload(PayloadKind::WalletLedgerPostcard, b"body").unwrap();
        bytes.pop();
        let err = decode_payload(&bytes).unwrap_err();
        assert!(matches!(err, PayloadError::BodyLenMismatch { .. }));
    }

    #[test]
    fn refuse_body_len_above_sanity_cap() {
        // Craft a header that claims a body larger than PAYLOAD_BODY_MAX
        // without actually allocating that much.
        let mut bytes = [0u8; PAYLOAD_HEADER_LEN];
        bytes[0..4].copy_from_slice(PAYLOAD_MAGIC);
        bytes[4] = CURRENT_PAYLOAD_VERSION;
        bytes[5] = PayloadKind::WalletLedgerPostcard as u8;
        // body_len = PAYLOAD_BODY_MAX + 1, LE
        let bad_len = u32::try_from(PAYLOAD_BODY_MAX + 1).unwrap();
        bytes[8..12].copy_from_slice(&bad_len.to_le_bytes());
        let err = decode_payload(&bytes).unwrap_err();
        assert!(
            matches!(err, PayloadError::BodyLenTooLarge { .. }),
            "got {err:?}"
        );
    }

    /// The encode-side cap check is symmetric with the decode-side one,
    /// but testing it directly would require allocating `PAYLOAD_BODY_MAX
    /// + 1` bytes. Instead we assert the reachable path — the check
    /// runs, and under the cap it returns `Ok(_)`.
    #[test]
    fn encode_accepts_bodies_up_to_cap() {
        let ok = encode_payload(PayloadKind::WalletLedgerPostcard, &[]).unwrap();
        assert_eq!(ok.len(), PAYLOAD_HEADER_LEN);
        let ok = encode_payload(PayloadKind::WalletLedgerPostcard, &[0u8; 32]).unwrap();
        assert_eq!(ok.len(), PAYLOAD_HEADER_LEN + 32);
    }
}
