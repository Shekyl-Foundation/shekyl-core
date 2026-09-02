// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The `COMPRESSED` flag path — **this module is the policy owner**.
//!
//! Since the 2026-08-06 compression-shim cut, `epee::levin`'s
//! `try_compress_message` and `decompress_payload` are marshaling shims
//! over the `shekyl_levin_*` FFI that reaches these functions. The codec,
//! the 256-byte minimum, the only-if-smaller rule, level 1, the inflate
//! caps, **and which messages may be compressed at all** are single-sourced
//! here; the C++ carries none of it. Do not "mirror C++" when editing —
//! C++ is the consumer.
//!
//! With the `zstd` cargo feature disabled, compression is a no-op and
//! receiving a compressed bucket is a hard error. That shape exists for
//! pure-Rust unavailability tests (`--no-default-features`); the production
//! daemon image always builds with the feature on.

use crate::error::Error;
use crate::header::{BucketHead, Flags, HEADER_SIZE};

/// Payloads below this size are never compressed (`COMPRESSION_MIN_PAYLOAD`).
pub const COMPRESSION_MIN_PAYLOAD: usize = 256;

/// Safety cap on a zstd frame's declared content size (128 MiB,
/// `DECOMPRESSED_MAX_SIZE`).
pub const DECOMPRESSED_MAX_SIZE: u64 = 128 * 1024 * 1024;

/// zstd compression level (fast mode; `ZSTD_COMPRESSION_LEVEL`).
pub const ZSTD_COMPRESSION_LEVEL: i32 = 1;

/// Whether this build can compress/decompress (`is_compression_available`).
#[must_use]
pub const fn is_compression_available() -> bool {
    cfg!(feature = "zstd")
}

/// Compress one payload under the production Levin policy.
///
/// The three outcomes are distinct on purpose, because the C++ shim has to
/// react differently to each:
///
/// - `Ok(Some(bytes))` — compressed; frame it with the `COMPRESSED` flag.
/// - `Ok(None)` — **declined**, meaning "send it uncompressed". Not an
///   error: compression unavailable, payload below
///   [`COMPRESSION_MIN_PAYLOAD`], codec failure, or a result that is not
///   strictly smaller than the input. Every one of these is an ordinary
///   outcome on a live relay path.
/// - `Err(`[`Error::OversizeDeflate`]`)` — the caller offered a payload
///   larger than any plaintext this protocol carries. Not a decline: no
///   conforming caller can produce one, so folding it into `Ok(None)`
///   would silently paper over a caller bug.
///
/// This is the payload-level half of the policy; [`compress_message`] wraps
/// it with the header questions and is what the C++ shim actually reaches.
///
/// # Errors
///
/// [`Error::OversizeDeflate`] when `payload` exceeds
/// [`DECOMPRESSED_MAX_SIZE`].
pub fn compress_payload(payload: &[u8]) -> Result<Option<Vec<u8>>, Error> {
    // The bound that belongs here is the *plaintext* one. Bounding the
    // compressor's input by the wire packet limit would reject exactly the
    // 100–128 MB payloads compression exists to bring under that limit —
    // the input to this function has not been framed yet, and the thing the
    // packet limit constrains is the compressed frame that comes out.
    let len = u64::try_from(payload.len()).expect("usize fits in u64");
    if len > DECOMPRESSED_MAX_SIZE {
        return Err(Error::OversizeDeflate {
            len,
            limit: DECOMPRESSED_MAX_SIZE,
        });
    }
    if !is_compression_available() || payload.len() < COMPRESSION_MIN_PAYLOAD {
        return Ok(None);
    }
    let Some(compressed) = zstd_compress(payload) else {
        return Ok(None);
    };
    if compressed.len() >= payload.len() {
        return Ok(None);
    }
    Ok(Some(compressed))
}

/// Try to compress **one** finalized Levin message (header + payload).
///
/// Returns the input unchanged when compression is unavailable, the message
/// is too small, already compressed, below [`COMPRESSION_MIN_PAYLOAD`], or
/// not smaller compressed. On success the returned message carries the
/// `COMPRESSED` flag and a `length` field covering the compressed payload.
///
/// Three inputs are also returned unchanged rather than re-framed. Until
/// the 2026-08-06 cut these were divergences from a C++ emit path that had
/// none of them (it `memcpy`d the header unchecked); that path now forwards
/// here, so they are simply the rules:
///
/// - a buffer whose header signature does not verify;
/// - a buffer whose header `length` disagrees with the bytes after it — i.e.
///   anything other than exactly one message, such as the multi-bucket
///   stream [`crate::fragmented_notify`] returns. Compressing that would
///   re-frame several buckets as one corrupt bucket;
/// - the noise/fragment class (neither `Q` nor `S`). Every such message is
///   exactly `noise_size` bytes *because* that is the property the
///   white-noise feature exists to provide; compressing one would shorten it
///   and make cover traffic distinguishable from real traffic on the wire.
///   This is the one with teeth: a 4 KiB dummy compresses to ~52 bytes.
///
/// The C++ has **three** call sites, not one, and two of them are
/// command-generic: `make_payload_send_txs` (`levin_notify.cpp`, the
/// Dandelion++ tx path), `relay_notify_to_list` and `invoke_notify_to_peer`
/// (both `src/p2p/net_node.inl`, which compress whatever command they are
/// handed). All three pass a single `finalize_notify` message, so none
/// reaches the guards above today — but "the only call site passes X" is not
/// what keeps them unreachable, and stating it that way invites the next
/// caller to be added without checking.
///
/// One class of message is *not* guardable from in here, because nothing on
/// the wire distinguishes it: a message whose **size is itself the privacy
/// property**. Two exist today.
///
/// - `--pad-transactions` quantizes a `NOTIFY_NEW_TRANSACTIONS` blob to a
///   1024-byte boundary with a run of spaces, which zstd erases almost
///   perfectly — recovering the very size signal the padding was bought to
///   hide.
/// - When a notification fits in one noise bucket, `fragmented_notify`
///   emits an ordinary `Q` message zero-padded to the noise size, carrying
///   no marking that separates it from any other notification.
///
/// Both are the calling layer's obligation: it knows it shaped the size,
/// and the bytes do not say so. `make_payload_send_txs` discharges the
/// first by not calling the compressor at all when `pad` is set.
///
/// # Invariant for anyone routing a NEW message type through here
///
/// **No message carrying secret or otherwise confidential material is ever
/// compressed — of any lifetime.**
/// Ruled by `docs/design/SHEKYL_P2P_PROTOCOL.md` PWD-T7, and stated at this
/// call site rather than only in the design doc because **this is where the
/// decision is actually made** — by whoever adds the next message type.
///
/// Compress-then-encrypt is the CRIME/BREACH shape. That attack needs a
/// **secret** and **attacker-influenced data** compressed in the same context,
/// so an adversary can vary its own input and watch the ciphertext length.
/// **The secret's lifetime is irrelevant to it** — a node-local static value or
/// a reused token is as extractable as a per-session one, and is worth *more*
/// once extracted, so "per-connection" is not the boundary.
/// It is safe on this path today for one specific reason: p2p payloads are
/// blocks and transactions — **public consensus data, carrying no confidential
/// value of any kind**. Not "no per-connection secret": that scoping is the one
/// the paragraph above disowns, and it would leave a node-local static or a
/// reused token outside the claim. The blobs do contain ciphertexts, and those
/// are public by design — the invariant is about values whose *disclosure*
/// matters, not values that happen to be encrypted. The safety is a property of
/// the *message set*, not of the compressor, so it stops holding the moment the
/// message set changes.
///
/// If a message would carry **any** confidential value — session key, node-local
/// secret, reused token, anything whose disclosure matters — **do not compress
/// it**. PWD-T7 records bucket-padding after compression as the named retreat
/// if the invariant ever has to be relaxed rather than obeyed.
#[must_use]
pub fn try_compress_message(message: Vec<u8>) -> Vec<u8> {
    match compress_message(&message) {
        Some(compressed) => compressed,
        None => message,
    }
}

/// The borrowing form of [`try_compress_message`]: `None` means "send the
/// input unchanged", `Some(bytes)` a re-framed `COMPRESSED` message.
///
/// This is the shape the C++ shim reaches through
/// `shekyl_levin_compress_message`, which owns a `byte_slice` it wants to
/// keep on the decline path and so has nothing to hand over. Every rule in
/// [`try_compress_message`]'s contract lives here; that function is the
/// owned-`Vec` convenience over it.
#[must_use]
pub fn compress_message(message: &[u8]) -> Option<Vec<u8>> {
    if !is_compression_available() || message.len() <= HEADER_SIZE {
        return None;
    }
    let header_bytes = <&[u8; HEADER_SIZE]>::try_from(&message[..HEADER_SIZE]).ok()?;
    let mut head = BucketHead::read(header_bytes).ok()?;
    if head.flags.contains(Flags::COMPRESSED) {
        return None;
    }
    // Exactly one message: the header must account for every byte after it.
    if head.payload_len != u64::try_from(message.len() - HEADER_SIZE).expect("usize fits in u64") {
        return None;
    }
    // Noise/fragment class: constant on-wire size is the point of it.
    if !head.flags.intersects(Flags::REQUEST.union(Flags::RESPONSE)) {
        return None;
    }
    // A message that reached here is at most one packet, so the plaintext
    // bound cannot fire; treating an error like a decline keeps this
    // function total ("leave the input alone") rather than growing a failure
    // mode its callers have no way to act on.
    let compressed = compress_payload(&message[HEADER_SIZE..]).ok()??;

    head.flags = head.flags.union(Flags::COMPRESSED);
    head.payload_len = u64::try_from(compressed.len()).expect("usize fits in u64");

    let mut out = Vec::with_capacity(HEADER_SIZE + compressed.len());
    out.extend_from_slice(&head.write());
    out.extend_from_slice(&compressed);
    Some(out)
}

/// Read a `COMPRESSED` bucket's frame header and return the exact number of
/// bytes it will inflate to, validated against
/// `min(max_output, DECOMPRESSED_MAX_SIZE)`.
///
/// This is the **allocation gate**, split out from the inflation itself so
/// that no buffer is sized from a number the frame merely claims until that
/// number has been checked. Callers pass the same limit the bucket header
/// was checked against, so an inflated payload can never exceed the
/// packet-size limit in force — [`DECOMPRESSED_MAX_SIZE`] alone would not
/// achieve that, being larger than [`crate::DEFAULT_MAX_PACKET_SIZE`] and
/// four orders of magnitude above the pre-handshake limit.
///
/// # Errors
///
/// [`Error::CompressionUnavailable`] without the `zstd` feature;
/// [`Error::Decompress`] on a malformed or size-less frame;
/// [`Error::OversizeInflate`] when the declared size exceeds the limit.
pub fn inflated_size(input: &[u8], max_output: u64) -> Result<usize, Error> {
    zstd_inflated_size(input, max_output.min(DECOMPRESSED_MAX_SIZE))
}

/// Inflate `input` directly into `out`, returning the bytes written.
///
/// `out` must be sized from [`inflated_size`] on the same `input`. Writing
/// into caller-owned storage is what lets the C++ shim inflate straight
/// into the `std::string` it is going to hand upward: no Rust-side
/// allocation, no copy across the boundary, and no heap ownership crossing
/// the FFI in either direction. It is also why nothing here needs wiping —
/// Levin payloads are public wire data, and the buffer belongs to the
/// caller either way.
///
/// # Errors
///
/// [`Error::CompressionUnavailable`] without the `zstd` feature;
/// [`Error::Decompress`] if the codec rejects the frame or writes a
/// different number of bytes than `out` is sized for.
pub fn decompress_into(input: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    zstd_decompress_into(input, out)
}

/// Allocate-and-inflate convenience over [`inflated_size`] +
/// [`decompress_into`], for Rust consumers such as [`crate::BucketReader`]
/// that want an owned buffer.
///
/// # Errors
///
/// As [`inflated_size`] and [`decompress_into`].
pub fn decompress_payload(input: &[u8], max_output: u64) -> Result<Vec<u8>, Error> {
    let size = inflated_size(input, max_output)?;
    let mut out = vec![0u8; size];
    let written = decompress_into(input, &mut out)?;
    // `decompress_into` already rejects a short write, so this is a
    // restatement rather than a second check; keeping it makes the
    // postcondition local to the buffer being returned.
    out.truncate(written);
    Ok(out)
}

#[cfg(feature = "zstd")]
fn zstd_compress(payload: &[u8]) -> Option<Vec<u8>> {
    zstd::bulk::compress(payload, ZSTD_COMPRESSION_LEVEL).ok()
}

#[cfg(not(feature = "zstd"))]
fn zstd_compress(_payload: &[u8]) -> Option<Vec<u8>> {
    None
}

#[cfg(feature = "zstd")]
fn zstd_inflated_size(input: &[u8], limit: u64) -> Result<usize, Error> {
    let declared = zstd::zstd_safe::get_frame_content_size(input)
        .map_err(|err| Error::Decompress {
            reason: format!("cannot read frame header: {err}"),
        })?
        .ok_or_else(|| Error::Decompress {
            reason: "frame does not declare its content size".to_owned(),
        })?;
    if declared > limit {
        return Err(Error::OversizeInflate { declared, limit });
    }
    // `limit` is at most DECOMPRESSED_MAX_SIZE (128 MiB), so on any target
    // this crate builds for the checked value already fits `usize`; the
    // conversion is written fallibly rather than asserted so a 16-bit
    // target would fail loudly instead of truncating.
    usize::try_from(declared).map_err(|_| Error::Decompress {
        reason: format!("frame claims {declared} bytes, exceeds address space"),
    })
}

#[cfg(not(feature = "zstd"))]
fn zstd_inflated_size(_input: &[u8], _limit: u64) -> Result<usize, Error> {
    Err(Error::CompressionUnavailable)
}

#[cfg(feature = "zstd")]
fn zstd_decompress_into(input: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let written = zstd::zstd_safe::decompress(out, input).map_err(|code| Error::Decompress {
        reason: zstd::zstd_safe::get_error_name(code).to_owned(),
    })?;
    // A frame that declares one content size and delivers another is
    // malformed. zstd checks this itself, but the caller sized `out` from
    // the declared size, so a short write would otherwise surface as
    // trailing zeros in an "successfully" inflated payload.
    if written != out.len() {
        return Err(Error::Decompress {
            reason: format!("frame declared {} bytes but produced {written}", out.len()),
        });
    }
    Ok(written)
}

#[cfg(not(feature = "zstd"))]
fn zstd_decompress_into(_input: &[u8], _out: &mut [u8]) -> Result<usize, Error> {
    Err(Error::CompressionUnavailable)
}

#[cfg(all(test, feature = "zstd"))]
mod tests {
    use super::*;
    use crate::fragment::{fragmented_notify, noise_notify};
    use crate::message::notify;

    #[test]
    fn small_payload_not_compressed() {
        let msg = notify(2002, &[0u8; COMPRESSION_MIN_PAYLOAD - 1]);
        assert_eq!(try_compress_message(msg.clone()), msg);
    }

    #[test]
    fn compressible_payload_roundtrips() {
        let payload = vec![0u8; 4096];
        let msg = notify(2002, &payload);
        let compressed = try_compress_message(msg.clone());
        assert_ne!(compressed, msg);

        let head = BucketHead::read(compressed[..HEADER_SIZE].try_into().unwrap()).unwrap();
        assert!(head.flags.contains(Flags::COMPRESSED));
        assert_eq!(
            head.payload_len,
            u64::try_from(compressed.len() - HEADER_SIZE).unwrap()
        );

        let decompressed =
            decompress_payload(&compressed[HEADER_SIZE..], DECOMPRESSED_MAX_SIZE).unwrap();
        assert_eq!(decompressed, payload);
    }

    #[test]
    fn already_compressed_left_alone() {
        let msg = try_compress_message(notify(2002, &vec![0u8; 4096]));
        let twice = try_compress_message(msg.clone());
        assert_eq!(twice, msg);
    }

    #[test]
    fn garbage_frame_rejected() {
        assert!(decompress_payload(b"not a zstd frame", DECOMPRESSED_MAX_SIZE).is_err());
    }

    /// The declared content size is rejected against the caller's limit, not
    /// only against `DECOMPRESSED_MAX_SIZE` — and before any allocation.
    ///
    /// The oversize verdict must arrive as its own variant: an operator
    /// seeing repeated disconnects has to be able to tell "this peer's
    /// batch outgrew the cap" from "this peer sent garbage", and those call
    /// for opposite responses.
    #[test]
    fn declared_size_over_the_callers_limit_rejected() {
        let payload = vec![0u8; 4096];
        let compressed = try_compress_message(notify(2002, &payload));
        let frame = &compressed[HEADER_SIZE..];

        // Well under DECOMPRESSED_MAX_SIZE, so only the caller's limit bites.
        assert_eq!(
            decompress_payload(frame, 1024).unwrap_err(),
            Error::OversizeInflate {
                declared: 4096,
                limit: 1024
            }
        );
        // The same frame at a sufficient limit still inflates.
        assert_eq!(decompress_payload(frame, 4096).unwrap(), payload);
    }

    /// Negative control on the variant split: a garbage frame must NOT come
    /// back as `OversizeInflate`, or the two codes would be a distinction
    /// the C++ shim reports without the receive path ever making it.
    #[test]
    fn malformed_frame_is_not_reported_as_oversize() {
        let err = decompress_payload(b"not a zstd frame", DECOMPRESSED_MAX_SIZE).unwrap_err();
        assert!(
            matches!(err, Error::Decompress { .. }),
            "unexpected error: {err:?}"
        );
    }

    /// `decompress_into` writes into caller storage and reports the count;
    /// this is the shape the C++ shim uses to inflate straight into its
    /// `std::string` with no Rust-side allocation.
    #[test]
    fn decompress_into_caller_storage() {
        let payload = vec![3u8; 8192];
        let compressed = try_compress_message(notify(2002, &payload));
        let frame = &compressed[HEADER_SIZE..];

        let size = inflated_size(frame, DECOMPRESSED_MAX_SIZE).unwrap();
        assert_eq!(size, payload.len());

        let mut out = vec![0u8; size];
        assert_eq!(decompress_into(frame, &mut out).unwrap(), payload.len());
        assert_eq!(out, payload);
    }

    /// An undersized destination is a codec error, not a silent truncation.
    #[test]
    fn decompress_into_undersized_buffer_errors() {
        let payload = vec![3u8; 8192];
        let compressed = try_compress_message(notify(2002, &payload));
        let frame = &compressed[HEADER_SIZE..];

        let mut out = vec![0u8; 16];
        assert!(decompress_into(frame, &mut out).is_err());
        assert_eq!(
            out,
            vec![0u8; 16],
            "no partial write into the caller's buffer"
        );
    }

    /// Compression bounds its input by the *plaintext* maximum, not the
    /// wire packet limit. A payload between the two must still compress —
    /// bringing it under the wire limit is the whole point of the codec.
    #[test]
    fn payload_above_the_wire_limit_still_compresses() {
        let len = usize::try_from(crate::DEFAULT_MAX_PACKET_SIZE).unwrap() + 4096;
        let payload = vec![0u8; len];
        let compressed = compress_payload(&payload)
            .expect("under the plaintext maximum")
            .expect("a run of zeros compresses");
        assert!(u64::try_from(compressed.len()).unwrap() < crate::DEFAULT_MAX_PACKET_SIZE);
    }

    /// Above the plaintext maximum it is a caller bug, reported as such —
    /// not folded into the "send it uncompressed" decline.
    #[test]
    fn payload_above_the_plaintext_maximum_is_an_error() {
        let len = usize::try_from(DECOMPRESSED_MAX_SIZE).unwrap() + 1;
        let payload = vec![0u8; len];
        assert_eq!(
            compress_payload(&payload).unwrap_err(),
            Error::OversizeDeflate {
                len: DECOMPRESSED_MAX_SIZE + 1,
                limit: DECOMPRESSED_MAX_SIZE
            }
        );
    }

    /// A multi-bucket buffer must come back untouched: compressing it would
    /// re-frame several buckets as one corrupt bucket.
    #[test]
    fn multi_bucket_input_left_alone() {
        let payload: Vec<u8> = (0u32..4000)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        let stream = fragmented_notify(1024, 114, &payload).unwrap();
        assert!(stream.len() > 1024, "must be more than one bucket");
        assert_eq!(try_compress_message(stream.clone()), stream);
    }

    /// Compressing a dummy would shorten it, and constant on-wire size is
    /// exactly what the white-noise feature buys.
    #[test]
    fn noise_class_left_alone() {
        let dummy = noise_notify(4096).unwrap();
        assert_eq!(try_compress_message(dummy.clone()), dummy);
    }

    /// A header whose `length` disagrees with the buffer is not one message.
    #[test]
    fn header_length_disagreeing_with_buffer_left_alone() {
        let mut msg = notify(2002, &vec![0u8; 4096]);
        msg.extend_from_slice(&[0u8; 16]); // trailing bytes the header omits
        assert_eq!(try_compress_message(msg.clone()), msg);
    }
}

/// Feature-off unavailability path: with the `zstd` feature disabled,
/// compression is the identity and a `COMPRESSED` bucket is a hard error.
/// Without these the `--no-default-features` CI leg would only prove the
/// crate compiles.
#[cfg(all(test, not(feature = "zstd")))]
mod tests_without_zstd {
    use super::*;
    use crate::message::notify;

    #[test]
    fn compression_reports_unavailable() {
        assert!(!is_compression_available());
    }

    #[test]
    fn try_compress_is_the_identity() {
        // Large and highly compressible: the only thing stopping it is the
        // absent codec.
        let msg = notify(2002, &vec![0u8; 4096]);
        assert_eq!(try_compress_message(msg.clone()), msg);
    }

    #[test]
    fn decompress_is_a_hard_error() {
        assert_eq!(
            decompress_payload(b"any bytes at all", DECOMPRESSED_MAX_SIZE),
            Err(Error::CompressionUnavailable)
        );
        // Both primitives, not only the convenience wrapper — the C++ shim
        // reaches `inflated_size` and `decompress_into` directly, so an arm
        // covered only through `decompress_payload` would not be covered
        // where production actually enters.
        assert_eq!(
            inflated_size(b"any bytes at all", DECOMPRESSED_MAX_SIZE),
            Err(Error::CompressionUnavailable)
        );
        assert_eq!(
            decompress_into(b"any bytes at all", &mut [0u8; 8]),
            Err(Error::CompressionUnavailable)
        );
    }

    /// The decline path stays a decline with the codec absent: "send it
    /// uncompressed" is the correct outcome, not an error.
    #[test]
    fn compress_declines_rather_than_failing() {
        assert_eq!(compress_payload(&vec![0u8; 4096]), Ok(None));
    }
}
