// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The serve-credit bundle producer (`ARCHIVAL_SETTLEMENT_WRITER.md` §16,
//! `SO-D12` increment 4c; `ARCHIVAL_SERVE_CREDIT_SPEC.md` §4.2, §5, §7).
//!
//! The witness for block `h` is the daemon that served the template `h`
//! was mined from, whether its built-in miner found the block or an
//! external one on `get_block_template` did (`SCS-P25`: the `0x0C` field
//! already makes the author public). This crate turns the commitment the
//! template drew into a bundle the queue admits:
//!
//! 1. **Keep** the seed and witness key each template drew, in the
//!    [`WitnessRing`], until the block they commit to is on chain or is
//!    never going to be.
//! 2. **Learn the draws** once `h` connects. The ingest connector holds
//!    the drawable memo, so it derives them with the verifier's own
//!    selection (`shekyl_chain_rules::draw_targets`) and hands back the
//!    [`Targets`].
//! 3. **Read** each drawn pair's shard through the one fetch path, with
//!    the challenge nonce, inside `W₂`, at most `K` times ([`plan`],
//!    feature `fetch` for the read itself).
//! 4. **Assemble and sign** the bundle: the revealed seed, both bitmaps,
//!    one record per pass, the witness signature over the commitment.
//! 5. **File** it by `h + W₂ − M`, passes or none. Filing is an offer to
//!    the queue through the chain store's single writer; the queue's
//!    admission is the bundle rule against the tip.
//!
//! [`Producer`] is that sequence as a state machine over plain values: it
//! is told the chain moved, what a block's draws are, and how each read
//! ended, and it says what to learn, what to read and what to file. The
//! ingest crate drives it from the connector's tip and the fetch
//! scheduler.
//!
//! Nothing here is consensus. The one consensus-adjacent rule is the bound
//! `K` ([`shekyl_archival_retention::CHALLENGE_READS`]), which admission
//! enforces and the plan never exceeds.
//!
//! # Secrets
//!
//! The ring holds every witness secret key and seed, in memory only
//! (ruling Q10, 2026-09-16: accept-loss; persist-encrypted REJECTED). Each
//! wipes itself on drop ([`zeroize::ZeroizeOnDrop`]). A restart empties the
//! ring and the in-flight blocks' draws expire in flight; the count's
//! top-up covers them. No secret reaches a log or a `Debug` output, and
//! `scripts/ci/check_bundle_producer_secrets.py` holds that for this
//! crate's format strings.
//!
//! # Constants
//!
//! The schedule's numbers are PROVISIONAL (`ARCHIVAL_SERVE_CREDIT_SPEC.md`
//! §13.2, rule 21): testnet measurement reopens them.

mod outcome;
pub mod plan;
mod producer;
#[cfg(feature = "fetch")]
pub mod read;
mod ring;

pub use outcome::{Answered, ReadKey, ReadOutcome};
pub use producer::{
    DrawTarget, DueRead, Filing, Learn, Lost, Observed, Producer, Recorded, Targets, Window,
};
pub use ring::{DrawFailed, WitnessRing};

use shekyl_types::BlockCount;

/// Consecutive reads of one draw are at least this many blocks apart.
/// PROVISIONAL (§13.2). The spacing is scheduling only: a fresh circuit
/// per read comes from the nonce-derived SOCKS credentials (`SF-D3`).
pub const READ_SPACING: BlockCount = BlockCount::from_raw(30);

/// `M`: a block's bundle is filed by `h + W₂ − M`, so inclusion latency
/// and an ordinary reorg leave it inside its window. PROVISIONAL (§13.2).
pub const FILING_MARGIN: BlockCount = BlockCount::from_raw(30);

/// How far below the tip a template's candidate is kept. A template for
/// height `c` can only be the block at `c`. One that another miner's block
/// displaced can still come back by a reorg; the ring keeps it this many
/// blocks, and a deeper reorg that revives it loses its draws to the
/// count's top-up (Q10's accept-loss). PROVISIONAL.
pub const CANDIDATE_DEPTH: BlockCount = BlockCount::from_raw(16);

/// The most candidates the ring holds; past it the oldest goes first. The
/// template is built 2 to 11 times a block interval (`BA-T35`), so this
/// covers [`CANDIDATE_DEPTH`] blocks at the high end with room to spare.
pub const MAX_CANDIDATES: usize = 192;

/// What one ring entry costs, in bytes: the FN-DSA-1024 secret key (2,305)
/// and its Ed25519 half (32), the witness public key (1,837), the seed
/// (32), and their headers, rounded up. The ring's memory is at most
/// `(MAX_CANDIDATES + W₂) · RING_ENTRY_BYTES`: about 2.9 MiB at the genesis
/// window (`W₂` = 500), for a miner that mined every block of it.
pub const RING_ENTRY_BYTES: usize = 4_352;
