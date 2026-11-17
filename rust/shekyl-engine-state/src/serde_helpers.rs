// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Small `#[serde(with = "...")]` adapters used by the wallet-state blocks.
//!
//! The philosophy here is to NEVER pull in the `curve25519-dalek/serde` feature or any
//! transitive serde feature on a crypto dep. Instead we pin the wire-format for every
//! non-trivial type as bytes we control (compressed-Edwards-Y, canonical scalar encoding,
//! etc.), and encode them through these helpers. This makes the postcard-encoded ledger
//! section byte-stable regardless of future upstream serde choices.

use curve25519_dalek::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    Scalar,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use shekyl_curve_primitives::Commitment;

// ── EdwardsPoint (compressed Y, 32 bytes, canonical) ──

pub mod edwards_point_bytes {
    use super::*;

    pub fn serialize<S: Serializer>(point: &EdwardsPoint, s: S) -> Result<S::Ok, S::Error> {
        let bytes = point.compress().to_bytes();
        serde_bytes::Bytes::new(&bytes).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<EdwardsPoint, D::Error> {
        let bytes = <serde_bytes::ByteBuf as Deserialize>::deserialize(d)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::invalid_length(
                bytes.len(),
                &"32-byte compressed Edwards point",
            ));
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&bytes);
        CompressedEdwardsY(buf)
            .decompress()
            .ok_or_else(|| serde::de::Error::custom("point is not on the curve"))
    }
}

// ── Scalar (canonical 32-byte little-endian) ──

pub mod scalar_bytes {
    use super::*;

    pub fn serialize<S: Serializer>(scalar: &Scalar, s: S) -> Result<S::Ok, S::Error> {
        let bytes = scalar.to_bytes();
        serde_bytes::Bytes::new(&bytes).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Scalar, D::Error> {
        let bytes = <serde_bytes::ByteBuf as Deserialize>::deserialize(d)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::invalid_length(
                bytes.len(),
                &"32-byte canonical scalar",
            ));
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&bytes);
        Option::<Scalar>::from(Scalar::from_canonical_bytes(buf))
            .ok_or_else(|| serde::de::Error::custom("scalar is not canonical"))
    }
}

// ── Commitment (32-byte scalar + u64 LE, matches Commitment::write/read) ──

pub mod commitment_bytes {
    use super::*;

    pub fn serialize<S: Serializer>(c: &Commitment, s: S) -> Result<S::Ok, S::Error> {
        let mut buf = [0u8; 40];
        buf[..32].copy_from_slice(&c.mask.to_bytes());
        buf[32..].copy_from_slice(&c.amount.to_le_bytes());
        serde_bytes::Bytes::new(&buf).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Commitment, D::Error> {
        let bytes = <serde_bytes::ByteBuf as Deserialize>::deserialize(d)?;
        if bytes.len() != 40 {
            return Err(serde::de::Error::invalid_length(
                bytes.len(),
                &"40-byte commitment (scalar || u64)",
            ));
        }
        let mut mask_buf = [0u8; 32];
        mask_buf.copy_from_slice(&bytes[..32]);
        let mask = Option::<Scalar>::from(Scalar::from_canonical_bytes(mask_buf))
            .ok_or_else(|| serde::de::Error::custom("commitment mask is not canonical"))?;
        let mut amt = [0u8; 8];
        amt.copy_from_slice(&bytes[32..]);
        Ok(Commitment::new(mask, u64::from_le_bytes(amt)))
    }
}

// ── LocalLabel (UTF-8 string, postcard-compatible with a plain `String`) ──
//
// The wire format is identical to a plain `String` so retyping a
// previously-`String` field to `LocalLabel` does not bump any block
// version. The deserialization path drops the deserializer's
// intermediate `String` allocation immediately into a `Zeroizing`
// wrapper; the very-brief un-wiped lifetime of that intermediate is
// the price of postcard wire compatibility, and is consistent with
// `LocalLabel`'s threat model — locality of UI metadata, not
// resistance to a heap-snapshotting attacker. Cross-cutting lock 9.

pub mod local_label {
    use super::*;
    use crate::local_label::LocalLabel;

    pub fn serialize<S: Serializer>(label: &LocalLabel, s: S) -> Result<S::Ok, S::Error> {
        // `expose_for_disk` is the explicit, named persistence-only
        // accessor; routing through it makes the serde adapter the
        // sole place the underlying bytes flow into a serializer.
        s.serialize_str(label.expose_for_disk())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<LocalLabel, D::Error> {
        let s = String::deserialize(d)?;
        Ok(LocalLabel::from_owned(s))
    }
}

// `Schema` derive needs to know the on-disk shape of every typed
// field. `LocalLabel` is wire-compatible with `String`, so callers
// that derive `Schema` on a struct containing
// `#[serde(with = "local_label")] field: LocalLabel` also annotate
// the field with `#[postcard(with = "String")]` (or the equivalent
// schema-side override). The bookkeeping retype commit covers that.

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct PointWrapper {
        #[serde(with = "edwards_point_bytes")]
        p: EdwardsPoint,
    }

    #[test]
    fn edwards_point_roundtrips_via_json() {
        let w = PointWrapper {
            p: ED25519_BASEPOINT_POINT,
        };
        let s = serde_json::to_string(&w).unwrap();
        let back: PointWrapper = serde_json::from_str(&s).unwrap();
        assert_eq!(w, back);
    }

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct ScalarWrapper {
        #[serde(with = "scalar_bytes")]
        s: Scalar,
    }

    #[test]
    fn scalar_roundtrips_via_json() {
        let w = ScalarWrapper { s: Scalar::ONE };
        let s = serde_json::to_string(&w).unwrap();
        let back: ScalarWrapper = serde_json::from_str(&s).unwrap();
        assert_eq!(w, back);
    }

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct CommitmentWrapper {
        #[serde(with = "commitment_bytes")]
        c: Commitment,
    }

    #[test]
    fn commitment_roundtrips_via_json() {
        let w = CommitmentWrapper {
            c: Commitment::new(Scalar::ONE, 12345),
        };
        let s = serde_json::to_string(&w).unwrap();
        let back: CommitmentWrapper = serde_json::from_str(&s).unwrap();
        assert_eq!(w, back);
    }

    // ── LocalLabel adapter ──
    //
    // The wire-stability test below is the load-bearing one: it
    // pins that postcard bytes for a struct with a
    // `#[serde(with = "local_label")] field: LocalLabel` are
    // identical to postcard bytes for an otherwise-identical struct
    // with `field: String`. That property is what permits the
    // bookkeeping_block / tx_meta_block retype commit to land
    // *without* bumping BOOKKEEPING_BLOCK_VERSION or
    // TX_META_BLOCK_VERSION.

    use crate::local_label::LocalLabel;

    #[derive(Serialize, Deserialize, Debug)]
    struct Labeled {
        #[serde(with = "local_label")]
        note: LocalLabel,
        n: u32,
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct Plain {
        note: String,
        n: u32,
    }

    #[test]
    fn local_label_postcard_round_trips() {
        let w = Labeled {
            note: LocalLabel::from_str("alice savings"),
            n: 42,
        };
        let bytes = postcard::to_allocvec(&w).expect("serialize");
        let back: Labeled = postcard::from_bytes(&bytes).expect("deserialize");
        assert_eq!(back.note.expose_for_disk(), "alice savings");
        assert_eq!(back.n, 42);
    }

    #[test]
    fn local_label_postcard_wire_matches_plain_string() {
        // The crucial property: retyping `note: String` to
        // `note: LocalLabel` (with `#[serde(with = "local_label")]`)
        // is a binary no-op on the postcard ledger. If this test
        // fails, the bookkeeping/tx_meta retype is no longer a
        // zero-version-bump operation and the ledger versions need
        // to advance.
        let labeled = Labeled {
            note: LocalLabel::from_str("hello"),
            n: 7,
        };
        let plain = Plain {
            note: "hello".to_owned(),
            n: 7,
        };
        let labeled_bytes = postcard::to_allocvec(&labeled).expect("serialize labeled");
        let plain_bytes = postcard::to_allocvec(&plain).expect("serialize plain");
        assert_eq!(labeled_bytes, plain_bytes);
    }

    #[test]
    fn local_label_round_trips_unicode() {
        let w = Labeled {
            note: LocalLabel::from_str("résumé 💼"),
            n: 1,
        };
        let bytes = postcard::to_allocvec(&w).expect("serialize");
        let back: Labeled = postcard::from_bytes(&bytes).expect("deserialize");
        assert_eq!(back.note.expose_for_disk(), "résumé 💼");
    }

    #[test]
    fn local_label_round_trips_empty() {
        let w = Labeled {
            note: LocalLabel::empty(),
            n: 0,
        };
        let bytes = postcard::to_allocvec(&w).expect("serialize");
        let back: Labeled = postcard::from_bytes(&bytes).expect("deserialize");
        assert!(back.note.is_empty());
    }
}
