// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The response body behind a complete head.
//!
//! One reader, used by [`PFetchClient::fetch`](crate::PFetchClient::fetch):
//! content is taken exactly to the declared length, hashed into the
//! delivery digest and checked as a `shard_frame` one transaction at a
//! time; the fixed-width countersignature envelope follows and is not
//! hashed; then the probe for `P`'s close. The head parser stays with the
//! client. Nothing here dials or admits.

use std::sync::Arc;
use std::time::Duration;

use shekyl_archival_retention::{
    ArchivalTx, PassDeliveryHasher, ShardViewHasher, PASS_DELIVERY_DIGEST_LEN,
};
use shekyl_crypto_pq::signature::HybridSignature;
use shekyl_types::ShardId;
use shekyl_wire::shard_frame::{
    check_components, check_lengths, check_version, ContentMismatch, FrameError, VarintDecoder,
};
use shekyl_wire::TxidParts;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::OwnedSemaphorePermit;
use tokio::time::timeout;

use crate::error::{FetchError, Malformed, Stall};
use crate::header::RequestHeader;
use crate::target::{ExpectedShard, TxSink, VerifiedTx};

/// Width of the countersignature envelope that closes the body: the
/// canonical `HybridSignature` encoding and nothing else (`SF-D8`). Both
/// ends read `HybridSignature::CANONICAL_LEN`; this name is the
/// fetch-side statement that the body's **last** bytes are a signature —
/// `P` releases it only after the body, so a countersignature in hand
/// means the whole read was delivered.
pub const SIGNATURE_ENVELOPE_LEN: usize = HybridSignature::CANONICAL_LEN;

/// Largest single read while draining a body. A bound on one `read`, not
/// on what stays resident: the resident term is one transaction's two
/// segments, and this only caps how many of their bytes arrive together.
const BODY_CHUNK: usize = 64 * 1024;

/// The in-flight slot and the per-transaction state that travel through
/// the blocking checks: the view-hash fold, the sink, and the two segment
/// buffers (reused across entries so a fetch allocates for the largest
/// entry once, not per entry).
pub(crate) struct Checker {
    _slot: OwnedSemaphorePermit,
    view: ShardViewHasher,
    sink: Arc<dyn TxSink>,
    pqc_auths: Vec<u8>,
    prunable: Vec<u8>,
}

impl Checker {
    pub(crate) fn new(
        slot: OwnedSemaphorePermit,
        shard_id: ShardId,
        sink: Arc<dyn TxSink>,
    ) -> Self {
        Self {
            _slot: slot,
            view: ShardViewHasher::begin(shard_id),
            sink,
            pqc_auths: Vec::new(),
            prunable: Vec::new(),
        }
    }

    /// Hash the resident entry against its row; on a match fold it into
    /// the view hash and hand it to the sink. Blocking: CPU over the
    /// segments plus whatever the sink does.
    fn check(
        &mut self,
        index: u64,
        parts: &TxidParts,
        pqc_auth_count: u64,
    ) -> Result<(), ContentMismatch> {
        check_components(
            index,
            parts,
            pqc_auth_count,
            &self.pqc_auths,
            &self.prunable,
        )?;
        self.view.fold_tx(ArchivalTx {
            txid: &parts.hash,
            prunable: &self.prunable,
            pqc_auths: &self.pqc_auths,
        });
        self.sink.accept(&VerifiedTx {
            index,
            parts,
            pqc_auth_count,
            pqc_auths: &self.pqc_auths,
            prunable: &self.prunable,
        });
        Ok(())
    }

    pub(crate) fn finish(self) -> shekyl_types::ShardViewHash {
        self.view.finish()
    }
}

/// Read the frame ahead of the envelope against `expected`, one entry
/// resident at a time.
///
/// Returns the checker and the first content mismatch, if any — after
/// which the rest of the content was drained into the digest unparsed, so
/// the envelope behind it can still decide whether the mismatch is `P`'s.
/// Grammar faults and a frame that does not fit its content exactly are
/// [`Malformed`] and return at once.
pub(crate) async fn read_frame<S: AsyncRead + Unpin>(
    reader: &mut BodyReader<'_, S>,
    expected: &ExpectedShard,
    mut checker: Checker,
) -> Result<(Checker, Option<ContentMismatch>), FetchError> {
    check_version(reader.byte().await?).map_err(Malformed::Frame)?;
    let declared = reader.varint().await?;
    if declared != expected.tx_count() {
        reader.drain().await?;
        return Ok((
            checker,
            Some(ContentMismatch::TxCount {
                expected: expected.tx_count(),
                declared,
            }),
        ));
    }
    for (i, parts) in expected.txs().iter().enumerate() {
        let index = u64::try_from(i).expect("a range index fits u64");
        let pqc_auth_count = reader.varint().await?;
        let pqc_auths_len = reader.varint().await?;
        let prunable_len = reader.varint().await?;
        if let Err(mismatch) =
            check_lengths(index, parts, pqc_auth_count, pqc_auths_len, prunable_len)
        {
            reader.drain().await?;
            return Ok((checker, Some(mismatch)));
        }
        // Lengths passed: each is at most the row's `archival_len`, so the
        // buffers are bounded by the requester's own rows.
        reader
            .segment(pqc_auths_len, &mut checker.pqc_auths)
            .await?;
        reader.segment(prunable_len, &mut checker.prunable).await?;
        // `TxidParts` is `Copy`; the row travels into the blocking task
        // with the checker and the checker comes back.
        let parts = *parts;
        let (outcome, returned) = tokio::task::spawn_blocking(move || {
            let outcome = checker.check(index, &parts, pqc_auth_count);
            (outcome, checker)
        })
        .await
        .expect("check task does not panic");
        checker = returned;
        if let Err(mismatch) = outcome {
            reader.drain().await?;
            return Ok((checker, Some(mismatch)));
        }
    }
    if reader.content_remaining() != 0 {
        return Err(FetchError::Malformed(Malformed::FrameLong));
    }
    Ok((checker, None))
}

/// The response body behind a complete head, read exactly to its declared
/// length under a per-read stall bound — content first (hashed into the
/// delivery digest), then the envelope (not hashed), then the probe for
/// `P`'s close.
///
/// "Exactly" is checked in both directions. Fewer bytes before the close
/// is [`Stall::Truncated`], at every offset; more bytes — already buffered
/// behind the head, or arriving on the probe for the close — is
/// [`Malformed::Overlength`] (`SF-D6`: body long of agreed `N` is
/// malformed, not trimmed). The probe is what makes the second direction
/// decidable: `RF-R1` has `P` close after the body, so a conforming `P`'s
/// EOF is already behind the last byte, and a `P` that sends neither EOF
/// nor bytes within the stall bound is [`Stall::NoClose`].
pub(crate) struct BodyReader<'a, S> {
    stream: &'a mut S,
    /// Bytes read from the stream and not yet consumed: `buf[pos..]`.
    buf: Vec<u8>,
    pos: usize,
    /// Bytes `content-length` declared, and how many have arrived.
    declared: u64,
    received: u64,
    /// Content bytes (ahead of the envelope) not yet consumed.
    content_remaining: u64,
    digest: PassDeliveryHasher,
    stall: Duration,
}

impl<'a, S: AsyncRead + Unpin> BodyReader<'a, S> {
    /// `carried` is what arrived behind the head. More of it than
    /// `declared` is already [`Malformed::Overlength`].
    pub(crate) fn new(
        stream: &'a mut S,
        carried: Vec<u8>,
        declared: u64,
        header: &RequestHeader,
        stall: Duration,
    ) -> Result<Self, FetchError> {
        let received = u64::try_from(carried.len()).expect("carried bytes fit u64");
        if received > declared {
            return Err(FetchError::Malformed(Malformed::Overlength { declared }));
        }
        let envelope = u64::try_from(SIGNATURE_ENVELOPE_LEN).expect("envelope fits u64");
        Ok(Self {
            stream,
            buf: carried,
            pos: 0,
            declared,
            received,
            content_remaining: declared.saturating_sub(envelope),
            digest: PassDeliveryHasher::new(header.nonce()),
            stall,
        })
    }

    fn content_remaining(&self) -> u64 {
        self.content_remaining
    }

    fn buffered(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    /// Make at least one byte available in the buffer.
    async fn fill(&mut self) -> Result<(), FetchError> {
        if self.pos < self.buf.len() {
            return Ok(());
        }
        let want = usize::try_from(self.declared - self.received)
            .expect("declared length within the ceiling")
            .min(BODY_CHUNK);
        if want == 0 {
            // Everything declared has arrived; a caller still wanting
            // bytes has outrun the declaration. The content methods refuse
            // before asking; the envelope cannot (its width was checked at
            // the head), so this arm is unreachable in practice.
            return Err(FetchError::Malformed(Malformed::FrameShort));
        }
        self.buf.resize(want, 0);
        self.pos = 0;
        let n = timeout(self.stall, self.stream.read(&mut self.buf))
            .await
            .map_err(|_| Stall::BodyTimeout)?
            .map_err(Stall::from)?;
        self.buf.truncate(n);
        if n == 0 {
            return Err(FetchError::Stall(Stall::Truncated {
                declared: self.declared,
                received: self.received,
            }));
        }
        self.received += u64::try_from(n).expect("a read fits u64");
        Ok(())
    }

    /// Take up to `max` buffered content bytes, hashing them. Never past
    /// the content: the envelope shares the buffer and is not content.
    fn take_content(&mut self, max: usize) -> &[u8] {
        let content = usize::try_from(self.content_remaining).unwrap_or(usize::MAX);
        let n = self.buffered().len().min(max).min(content);
        let start = self.pos;
        self.pos += n;
        let taken = &self.buf[start..start + n];
        self.digest.update(taken);
        self.content_remaining -= u64::try_from(n).expect("a take fits u64");
        taken
    }

    /// One content byte.
    async fn byte(&mut self) -> Result<u8, FetchError> {
        if self.content_remaining == 0 {
            return Err(FetchError::Malformed(Malformed::FrameShort));
        }
        self.fill().await?;
        Ok(self.take_content(1)[0])
    }

    /// One canonical-LEB128 `u64` of content.
    async fn varint(&mut self) -> Result<u64, FetchError> {
        let mut decoder = VarintDecoder::new();
        loop {
            let byte = self.byte().await?;
            if let Some(value) = decoder
                .push(byte)
                .map_err(|fault| Malformed::Frame(FrameError::Varint(fault)))?
            {
                return Ok(value);
            }
        }
    }

    /// Exactly `len` content bytes into `out` (cleared first).
    async fn segment(&mut self, len: u64, out: &mut Vec<u8>) -> Result<(), FetchError> {
        if len > self.content_remaining {
            return Err(FetchError::Malformed(Malformed::FrameShort));
        }
        out.clear();
        let len = usize::try_from(len).expect("segment within the ceiling");
        out.reserve(len);
        while out.len() < len {
            self.fill().await?;
            let chunk = self.take_content(len - out.len());
            out.extend_from_slice(chunk);
        }
        Ok(())
    }

    /// Consume the rest of the content into the digest.
    async fn drain(&mut self) -> Result<(), FetchError> {
        while self.content_remaining != 0 {
            self.fill().await?;
            self.take_content(BODY_CHUNK);
        }
        Ok(())
    }

    /// The envelope: the declared length's last bytes, not hashed. Only
    /// after the content is spent.
    pub(crate) async fn envelope(&mut self) -> Result<[u8; SIGNATURE_ENVELOPE_LEN], FetchError> {
        debug_assert_eq!(self.content_remaining, 0);
        let mut out = [0u8; SIGNATURE_ENVELOPE_LEN];
        let mut got = 0usize;
        while got < SIGNATURE_ENVELOPE_LEN {
            self.fill().await?;
            let n = self.buffered().len().min(SIGNATURE_ENVELOPE_LEN - got);
            out[got..got + n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
            self.pos += n;
            got += n;
        }
        Ok(out)
    }

    /// Exactly `declared` in hand. The next read decides the response:
    /// EOF completes it, a byte breaks it, silence is a stall.
    pub(crate) async fn close_probe(&mut self) -> Result<(), FetchError> {
        debug_assert_eq!(self.received, self.declared);
        if self.pos < self.buf.len() {
            return Err(FetchError::Malformed(Malformed::Overlength {
                declared: self.declared,
            }));
        }
        let mut probe = [0u8; 1];
        let n = timeout(self.stall, self.stream.read(&mut probe))
            .await
            .map_err(|_| Stall::NoClose)?
            .map_err(Stall::from)?;
        if n != 0 {
            return Err(FetchError::Malformed(Malformed::Overlength {
                declared: self.declared,
            }));
        }
        Ok(())
    }

    /// The delivery digest over every content byte consumed.
    pub(crate) fn finish(self) -> [u8; PASS_DELIVERY_DIGEST_LEN] {
        self.digest.finalize()
    }
}
