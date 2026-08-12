// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The one pre-decode schema-version gate every persisted block loads through.
//!
//! # Why the gate must run *before* the body decode
//!
//! postcard is not self-describing: fields are written in declaration order with
//! no names, tags, or framing. A release that changes any nested shape — SA-4
//! deleted `PFundingOutputRecord::tx_hash` from the middle of a repeated record,
//! and `TxMetaBlock::attributes` from the middle of a block — shifts every byte
//! that follows. Decoding an *old* blob under the *new* declaration therefore
//! reads stale bytes at the new offsets and fails inside postcard with
//! "bad varint / unexpected end", long before any post-decode `check_version()`
//! can run.
//!
//! That failure mode is the wrong answer twice over. It tells a user whose keys
//! and seed are intact that their wallet is corrupt, and it hides the one
//! diagnostic that names the remedy — refuse with
//! [`WalletLedgerError::UnsupportedBlockVersion`], whose fix is to recreate the
//! rescan-regenerable state cache from the seed (rule 15: refuse, never
//! migrate). The version bump exists precisely to fire on these files; gating
//! after the decode means it never gets the chance.
//!
//! # Why reading the leading varint is sound
//!
//! Every gated block declares its `u32` version as its **first** field, so the
//! version is the first varint of the blob and
//! [`postcard::take_from_bytes`] yields it without touching the rest. That is a
//! structural precondition, not a convention: `leading_version_is_the_schema_version`
//! below pins it for every gated block, so a field reorder fails the test rather
//! than silently turning this gate into a comparison against an unrelated value.
//!
//! Because the prefix *is* the version field, a post-decode `check_version()` on
//! the same bytes cannot disagree with this gate, and loaders do not repeat it.
//! `check_version()` stays public for the aggregator
//! ([`crate::wallet_ledger::WalletLedger::check_all_block_versions`]), which
//! validates already-decoded blocks that never passed through here.
//!
//! [`WalletLedgerError::UnsupportedBlockVersion`]: crate::error::WalletLedgerError::UnsupportedBlockVersion

use crate::error::WalletLedgerError;

/// Refuse a postcard blob whose leading schema version is not `binary`.
///
/// `block` is the block's stable diagnostic name (the same string its
/// [`WalletLedgerError::UnsupportedBlockVersion`] arm carries).
///
/// # Errors
///
/// - [`WalletLedgerError::UnsupportedBlockVersion`] — the blob was written by a
///   different schema version. This is the refusal the caller wants a user to
///   see.
/// - A codec error only when the blob is too short to hold even a varint, i.e.
///   genuinely truncated rather than merely stale.
///
/// [`WalletLedgerError::UnsupportedBlockVersion`]: crate::error::WalletLedgerError::UnsupportedBlockVersion
pub(crate) fn gate_leading_version(
    bytes: &[u8],
    block: &'static str,
    binary: u32,
) -> Result<(), WalletLedgerError> {
    let (file, _rest) = postcard::take_from_bytes::<u32>(bytes)?;
    gate_version(file, block, binary)
}

/// Refuse an already-decoded schema version that is not `binary`.
///
/// The comparison itself, so the pre-decode gate above and every block's
/// post-decode `check_version` share one definition of "supported" and one
/// refusal shape. Each block previously carried its own copy of this
/// four-line `if`; a single owner is what keeps them from drifting.
///
/// # Errors
///
/// [`WalletLedgerError::UnsupportedBlockVersion`] when `file != binary`.
///
/// [`WalletLedgerError::UnsupportedBlockVersion`]: crate::error::WalletLedgerError::UnsupportedBlockVersion
pub(crate) fn gate_version(
    file: u32,
    block: &'static str,
    binary: u32,
) -> Result<(), WalletLedgerError> {
    if file != binary {
        return Err(WalletLedgerError::UnsupportedBlockVersion {
            block,
            file,
            binary,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        bookkeeping_block::{BookkeepingBlock, BOOKKEEPING_BLOCK_VERSION},
        ledger_block::{LedgerBlock, LEDGER_BLOCK_VERSION},
        pending_post_block::{PendingPostBlock, PENDING_POST_VERSION},
        pscan_cursor::{PScanCursor, PSCAN_CURSOR_VERSION},
        pscan_state::{PScanState, PSCAN_STATE_VERSION},
        staking_block::{StakingBlock, STAKING_BLOCK_VERSION},
        sync_state_block::{SyncStateBlock, SYNC_STATE_BLOCK_VERSION},
        tx_meta_block::{TxMetaBlock, TX_META_BLOCK_VERSION},
    };

    /// The structural precondition [`gate_leading_version`] rests on: for every
    /// gated block, the first varint of its postcard encoding **is** its schema
    /// version.
    ///
    /// This is the test that makes the gate safe to share. If someone moves a
    /// block's version field out of first position, the gate would silently
    /// start comparing an unrelated leading value against the version constant —
    /// refusing valid files or admitting stale ones. That reorder fails here
    /// instead, at the one place that states the assumption.
    ///
    /// Each entry serializes a *live* instance (not a hand-built blob) so the
    /// oracle is the real encoder, and asserts on the byte stream rather than on
    /// the struct field.
    #[test]
    fn leading_version_is_the_schema_version() {
        fn assert_leads_with(bytes: &[u8], expected: u32, block: &str) {
            let (leading, _) = postcard::take_from_bytes::<u32>(bytes)
                .unwrap_or_else(|e| panic!("{block}: leading varint must decode: {e}"));
            assert_eq!(
                leading, expected,
                "{block}: first postcard varint must be the schema version — \
                 `gate_leading_version` compares it against the version constant"
            );
        }

        let cases: Vec<(&str, Vec<u8>, u32)> = vec![
            (
                "bookkeeping",
                BookkeepingBlock::empty()
                    .to_postcard_bytes()
                    .expect("encode bookkeeping"),
                BOOKKEEPING_BLOCK_VERSION,
            ),
            (
                "ledger",
                LedgerBlock::empty()
                    .to_postcard_bytes()
                    .expect("encode ledger"),
                LEDGER_BLOCK_VERSION,
            ),
            (
                "pending_post_block",
                PendingPostBlock::empty()
                    .to_postcard_bytes()
                    .expect("encode pending_post"),
                PENDING_POST_VERSION,
            ),
            (
                "pscan_cursor",
                PScanCursor::genesis()
                    .to_postcard_bytes()
                    .expect("encode pscan_cursor"),
                PSCAN_CURSOR_VERSION,
            ),
            (
                "pscan_state",
                PScanState::genesis()
                    .to_postcard_bytes()
                    .expect("encode pscan_state"),
                PSCAN_STATE_VERSION,
            ),
            (
                "staking",
                StakingBlock::empty()
                    .to_postcard_bytes()
                    .expect("encode staking"),
                STAKING_BLOCK_VERSION,
            ),
            (
                "sync_state",
                SyncStateBlock::empty()
                    .to_postcard_bytes()
                    .expect("encode sync_state"),
                SYNC_STATE_BLOCK_VERSION,
            ),
            (
                "tx_meta",
                TxMetaBlock::empty()
                    .to_postcard_bytes()
                    .expect("encode tx_meta"),
                TX_META_BLOCK_VERSION,
            ),
        ];

        for (block, bytes, expected) in &cases {
            assert_leads_with(bytes, *expected, block);
        }
    }

    /// A blob whose leading version differs is refused by version — **not** by
    /// codec error — even when everything after the version is unreadable under
    /// the current declaration.
    ///
    /// The trailing garbage is the point: it stands in for a real stale file,
    /// whose bytes after the version genuinely do not parse under the new field
    /// layout. Before the gate moved ahead of the decode, that case surfaced as
    /// `postcard decode failed: …` — the "your wallet is corrupt" diagnostic on
    /// an intact wallet.
    #[test]
    fn a_stale_blob_is_refused_by_version_not_by_codec_error() {
        let mut stale = postcard::to_allocvec(&(PSCAN_STATE_VERSION - 1)).expect("encode version");
        stale.extend_from_slice(&[0xff; 8]);

        match PScanState::from_postcard_bytes(&stale)
            .expect_err("a prior-version blob must be refused")
        {
            WalletLedgerError::UnsupportedBlockVersion {
                block,
                file,
                binary,
            } => {
                assert_eq!(block, "pscan_state");
                assert_eq!(file, PSCAN_STATE_VERSION - 1);
                assert_eq!(binary, PSCAN_STATE_VERSION);
            }
            other => panic!("expected a version refusal, got {other:?}"),
        }
    }

    /// The gate is a version check, not a well-formedness check: a
    /// current-version blob passes it, and any later failure belongs to the
    /// body decode.
    ///
    /// Negative control for the test above — without this, a gate that refused
    /// *everything* would also pass it.
    #[test]
    fn a_current_version_prefix_passes_the_gate() {
        let current = postcard::to_allocvec(&PSCAN_STATE_VERSION).expect("encode version");
        gate_leading_version(&current, "pscan_state", PSCAN_STATE_VERSION)
            .expect("the current version must pass the gate");
    }
}
