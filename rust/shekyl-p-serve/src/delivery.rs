// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Which bytes a pass countersignature digests.
//!
//! The store is read once per response. Each chunk is folded through this
//! type as it is written, and the signature is made over the finished
//! digest and appended. So the signed bytes are the sent bytes by
//! construction, and no more than one chunk of a shard is resident: the
//! serve ceiling stays a count of connections, not a whole-shard memory
//! budget.
//!
//! Signing therefore comes after the body. A signer that fails then cannot
//! change the status — the 200 is already out — so the envelope is written
//! as the refusal trailer in place of the signature. A persona that knows
//! before the first byte that it has no key answers 503 and sends nothing.
//!
//! One fold, rather than a hasher opened by hand at the call site, so the
//! signed bytes are defined once: every body byte, in order, and nothing
//! else — the loop prepends no frame of its own (`SF-D8` amendment
//! 2026-10-08; the `RF-D4` header it used to absorb first is gone). A body
//! that is not exactly the length it was opened at has no digest.
//!
//! # Where the fold runs
//!
//! The fold is a hash over every byte of the shard: software Keccak, tens
//! of milliseconds for a full shard on the floor device. The serve loop
//! runs it on the blocking pool, in the same hop as the store read that
//! produced the chunk ([`read_and_fold`]), so that it does not hold an
//! executor thread away from every other connection's task while it
//! hashes.
//!
//! That is the part of the digest that scales with the shard, and it is
//! the only part that moves. [`BodyDigest::start`] and
//! [`BodyDigest::finish`] run on the connection's task: a fixed few Keccak
//! permutations whatever the shard's size, and less work than a hop to the
//! pool would be.
//!
//! What this module's surface enforces is narrower than "never on the
//! executor", and it is stated exactly so nobody leans on more. The serve
//! loop can start a digest, move it into [`read_and_fold`] and finish it.
//! It cannot advance one: [`BodyDigest::absorb`] is private to this
//! module, and so is [`fold_chunk`], its only caller outside the tests
//! below. So **the hash cannot be separated from the read**: there is no
//! way to read a chunk in one place and fold it in another, which is the
//! shape that put the hash on the executor before. Which thread the
//! combined step runs on is the caller's choice, and the type system does
//! not make it: `write_response` wraps [`read_and_fold`] in
//! `spawn_blocking`, as it always wrapped the store read, and calling it
//! directly on the executor would compile and would block that thread on
//! synchronous store I/O as well as on the hash.

use shekyl_archival_retention::{PassDeliveryHasher, PASS_DELIVERY_DIGEST_LEN, PASS_NONCE_LEN};

use super::WRITE_CHUNK_BYTES;
use crate::provider::{ProviderError, ShardBody};

/// Running digest of the body ahead of the countersignature.
pub(super) struct BodyDigest {
    hasher: PassDeliveryHasher,
    /// The length the body was opened at ([`ShardBody::len`]).
    len: u64,
    /// Bytes absorbed so far.
    absorbed: u64,
}

impl BodyDigest {
    /// Start a digest of a body of `len` bytes under `nonce`.
    pub(super) fn start(len: u64, nonce: &[u8; PASS_NONCE_LEN]) -> Self {
        Self {
            hasher: PassDeliveryHasher::new(nonce),
            len,
            absorbed: 0,
        }
    }

    /// Absorb the next chunk.
    ///
    /// `None` when the chunk would carry the running total past the body's
    /// opened length, or when its length does not fit a `u64`. The digest
    /// is left unchanged in that case, so the caller stops rather than
    /// signing or sending bytes the head did not declare.
    fn absorb(&mut self, chunk: &[u8]) -> Option<()> {
        let len = u64::try_from(chunk.len()).ok()?;
        let absorbed = self.absorbed.checked_add(len)?;
        if absorbed > self.len {
            return None;
        }
        self.hasher.update(chunk);
        self.absorbed = absorbed;
        Some(())
    }

    /// The digest, if the absorbed bytes are exactly the opened length. A
    /// short body is `None`: it is not a prefix someone may sign.
    pub(super) fn finish(self) -> Option<[u8; PASS_DELIVERY_DIGEST_LEN]> {
        if self.absorbed != self.len {
            return None;
        }
        Some(self.hasher.finalize())
    }
}

/// What folding one read of the body into the delivery digest produced.
pub(super) enum Folded {
    /// Bytes inside the declared length, now part of the digest: write them.
    Bytes(Vec<u8>),
    /// The body ended. Whether it ended at the declared length is
    /// [`BodyDigest::finish`]'s to say.
    End,
    /// The store failed part-way.
    StoreFault,
    /// The store yielded a byte past the declared length. Not folded, and
    /// not to be written.
    PastLength,
}

/// Fold one read of the body into the running digest.
///
/// The one place a served byte enters the digest. Its one caller is
/// [`read_and_fold`], which the endpoint runs on the blocking pool and the
/// `BA-T3` compositions run on their own thread, so the gate counts the
/// fold the endpoint runs and not a copy of it. A second digest pass
/// added here moves the gate; there is nowhere else to add one.
fn fold_chunk(running: &mut BodyDigest, chunk: Result<Option<Vec<u8>>, ProviderError>) -> Folded {
    match chunk {
        Ok(Some(bytes)) => match running.absorb(&bytes) {
            Some(()) => Folded::Bytes(bytes),
            None => Folded::PastLength,
        },
        Ok(None) => Folded::End,
        Err(_) => Folded::StoreFault,
    }
}

/// Read the next chunk of the body and fold it into the digest: one step
/// of the send loop, and one blocking-pool hop.
///
/// The read is synchronous store I/O and the fold is CPU-bound hashing,
/// so both belong off the executor and they go together: call this inside
/// `spawn_blocking`. The body and the digest are taken by value and handed
/// back with the result, because the hop owns them while it runs: the
/// caller holds neither across the `await`, and has no other way to
/// advance the digest (see the module docs).
///
/// The chunk size is the serve loop's [`WRITE_CHUNK_BYTES`], read here and
/// not passed in, so the endpoint and the `BA-T3` compositions cannot read
/// at different sizes: the gate would then be counting a different loop.
pub(super) fn read_and_fold(
    mut body: ShardBody,
    mut running: BodyDigest,
) -> (ShardBody, BodyDigest, Folded) {
    let folded = fold_chunk(&mut running, body.next_chunk(WRITE_CHUNK_BYTES));
    (body, running, folded)
}

#[cfg(test)]
mod tests {
    use shekyl_archival_retention::pass_delivery_digest;

    use super::*;

    fn body() -> Vec<u8> {
        (0..5_000u32)
            .map(|i| u8::try_from(i % 251).expect("fits"))
            .collect()
    }

    #[test]
    fn the_digest_is_the_body_at_every_split() {
        let payload = body();
        let len = u64::try_from(payload.len()).unwrap();
        let nonce = [0x03u8; PASS_NONCE_LEN];
        let mut whole = BodyDigest::start(len, &nonce);
        whole.absorb(&payload).expect("payload fits");
        let digest = whole.finish().expect("exact length");
        assert_eq!(
            digest,
            pass_delivery_digest(&nonce, &payload),
            "the fold is the one-shot digest of the bytes ahead of the signature"
        );

        for split in (0..=payload.len()).step_by(97) {
            let mut running = BodyDigest::start(len, &nonce);
            running.absorb(&payload[..split]).expect("prefix fits");
            running.absorb(&payload[split..]).expect("rest fits");
            assert_eq!(running.finish(), Some(digest), "split at {split}");
        }
    }

    #[test]
    fn a_short_body_and_a_long_one_have_no_digest() {
        let payload = body();
        let len = u64::try_from(payload.len()).unwrap();
        let nonce = [0x03u8; PASS_NONCE_LEN];

        let mut short = BodyDigest::start(len, &nonce);
        short
            .absorb(&payload[..payload.len() - 1])
            .expect("prefix fits");
        assert!(short.finish().is_none(), "a short body is not signed");

        let mut long = BodyDigest::start(len, &nonce);
        long.absorb(&payload).expect("exact payload fits");
        assert!(
            long.absorb(&[0]).is_none(),
            "a byte past the declared length is refused before it is absorbed"
        );
    }

    #[test]
    fn an_empty_body_digests_to_the_nonce_alone() {
        let nonce = [0x03u8; PASS_NONCE_LEN];
        let running = BodyDigest::start(0, &nonce);
        assert_eq!(running.finish(), Some(pass_delivery_digest(&nonce, &[])));
    }
}
