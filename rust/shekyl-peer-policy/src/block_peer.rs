// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What P2P should *do* after a block ingest — the decision the protocol
//! handler used to make by ordering predicates in C++.
//!
//! The announce path and the sync path are different consumers (compact-tx
//! re-request exists only on announce; GET_OBJECTS has no equivalent), so
//! they are different types. An unrecognised action byte is the idle arm
//! of each: do not drop.

use crate::{BlockIngest, DropVerdict};

/// What the announce (tip-adjacent compact-block) path should do.
///
/// Discriminants are the C ABI returned by `shekyl_block_announce_action`.
/// C++ never writes these; it asks the predicates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BlockAnnounceAction {
    /// Already-have / alt-stored / degraded-keep / unclassified success.
    None = 0,
    /// Fluffy payload incomplete. Re-request by index; do not drop.
    ReRequestMissingTxs = 1,
    /// Attributable drop, ordinary score.
    Drop = 2,
    /// Attributable drop, heavier PoW-DoS score.
    DropBadPow = 3,
    /// `handle_*` returned false without a severing drop: our failure.
    OurFailure = 4,
    /// Landed on the main chain: relay.
    Relay = 5,
    /// Parent unknown: request chain history.
    RequestHistory = 6,
}

impl BlockAnnounceAction {
    /// The announce tree, in the order the inherited handler asked it.
    ///
    /// Missing-txs wins even if a drop was also recorded: the compact
    /// path's job is to fetch the rest of a block whose PoW already
    /// passed, not to punish the peer that advertised it. A severing
    /// drop then wins over our-failure / relay / history.
    #[must_use]
    pub const fn from_ingest(
        outcome: BlockIngest,
        drop: DropVerdict,
        handle_returned_ok: bool,
    ) -> Self {
        if outcome.missing_txs() {
            return Self::ReRequestMissingTxs;
        }
        if drop.severs() {
            return if outcome.is_bad_pow() {
                Self::DropBadPow
            } else {
                Self::Drop
            };
        }
        if !handle_returned_ok {
            return Self::OurFailure;
        }
        if outcome.is_added() {
            return Self::Relay;
        }
        if outcome.is_orphaned() {
            return Self::RequestHistory;
        }
        Self::None
    }

    #[must_use]
    pub const fn from_byte(byte: u8) -> Self {
        match byte {
            1 => Self::ReRequestMissingTxs,
            2 => Self::Drop,
            3 => Self::DropBadPow,
            4 => Self::OurFailure,
            5 => Self::Relay,
            6 => Self::RequestHistory,
            _ => Self::None,
        }
    }

    #[must_use]
    pub const fn to_byte(self) -> u8 {
        self as u8
    }

    #[must_use]
    pub const fn re_request_txs(self) -> bool {
        matches!(self, Self::ReRequestMissingTxs)
    }

    #[must_use]
    pub const fn drop_peer(self) -> bool {
        matches!(self, Self::Drop | Self::DropBadPow)
    }

    #[must_use]
    pub const fn heavier_score(self) -> bool {
        matches!(self, Self::DropBadPow)
    }

    #[must_use]
    pub const fn our_failure(self) -> bool {
        matches!(self, Self::OurFailure)
    }

    #[must_use]
    pub const fn relay(self) -> bool {
        matches!(self, Self::Relay)
    }

    #[must_use]
    pub const fn request_history(self) -> bool {
        matches!(self, Self::RequestHistory)
    }
}

/// What the GET_OBJECTS sync path should do with one span block.
///
/// There is no compact-tx re-request here. Missing-txs without a
/// severing drop continues (the next block typically orphans and takes
/// the re-sync arm). A severing drop still severs: sync has no "finish
/// fetching this block" alternative.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BlockSyncAction {
    Continue = 0,
    Drop = 1,
    DropBadPow = 2,
    OrphanResync = 3,
}

impl BlockSyncAction {
    #[must_use]
    pub const fn from_ingest(outcome: BlockIngest, drop: DropVerdict) -> Self {
        if drop.severs() {
            return if outcome.is_bad_pow() {
                Self::DropBadPow
            } else {
                Self::Drop
            };
        }
        if outcome.is_orphaned() {
            return Self::OrphanResync;
        }
        Self::Continue
    }

    #[must_use]
    pub const fn from_byte(byte: u8) -> Self {
        match byte {
            1 => Self::Drop,
            2 => Self::DropBadPow,
            3 => Self::OrphanResync,
            _ => Self::Continue,
        }
    }

    #[must_use]
    pub const fn to_byte(self) -> u8 {
        self as u8
    }

    #[must_use]
    pub const fn drop_peer(self) -> bool {
        matches!(self, Self::Drop | Self::DropBadPow)
    }

    #[must_use]
    pub const fn heavier_score(self) -> bool {
        matches!(self, Self::DropBadPow)
    }

    #[must_use]
    pub const fn orphan_resync(self) -> bool {
        matches!(self, Self::OrphanResync)
    }
}

#[cfg(test)]
mod tests {
    use super::{BlockAnnounceAction, BlockSyncAction};
    use crate::{BlockIngest, DropVerdict};

    const OUTCOMES: [BlockIngest; 9] = [
        BlockIngest::Unclassified,
        BlockIngest::AddedToMainChain,
        BlockIngest::AlreadyExists,
        BlockIngest::Orphaned,
        BlockIngest::MissingTxs,
        BlockIngest::DegradedKeep,
        BlockIngest::AltStored,
        BlockIngest::Rejected,
        BlockIngest::RejectedBadPow,
    ];
    const DROPS: [DropVerdict; 4] = [
        DropVerdict::Unclassified,
        DropVerdict::PolicyOrState,
        DropVerdict::InternalFailure,
        DropVerdict::AttributableForm,
    ];

    #[test]
    fn announce_missing_txs_wins_even_if_the_drop_slot_severs() {
        let action = BlockAnnounceAction::from_ingest(
            BlockIngest::MissingTxs,
            DropVerdict::AttributableForm,
            false,
        );
        assert!(action.re_request_txs());
        assert!(!action.drop_peer());
    }

    #[test]
    fn announce_drops_only_when_the_drop_slot_severs() {
        for outcome in OUTCOMES {
            if outcome.missing_txs() {
                continue;
            }
            for drop in DROPS {
                let action = BlockAnnounceAction::from_ingest(outcome, drop, true);
                assert_eq!(action.drop_peer(), drop.severs(), "{outcome:?} {drop:?}");
                assert_eq!(
                    action.heavier_score(),
                    drop.severs() && outcome.is_bad_pow(),
                    "{outcome:?} {drop:?}"
                );
            }
        }
    }

    #[test]
    fn announce_our_failure_is_not_a_drop() {
        let action = BlockAnnounceAction::from_ingest(
            BlockIngest::Rejected,
            DropVerdict::InternalFailure,
            false,
        );
        assert!(action.our_failure());
        assert!(!action.drop_peer());
    }

    #[test]
    fn announce_added_relays_and_orphaned_requests_history() {
        assert!(BlockAnnounceAction::from_ingest(
            BlockIngest::AddedToMainChain,
            DropVerdict::Unclassified,
            true,
        )
        .relay());
        assert!(BlockAnnounceAction::from_ingest(
            BlockIngest::Orphaned,
            DropVerdict::Unclassified,
            true,
        )
        .request_history());
        assert_eq!(
            BlockAnnounceAction::from_ingest(
                BlockIngest::AltStored,
                DropVerdict::Unclassified,
                true,
            ),
            BlockAnnounceAction::None
        );
    }

    #[test]
    fn announce_predicates_are_exclusive_and_unknown_bytes_are_idle() {
        for byte in u8::MIN..=u8::MAX {
            let action = BlockAnnounceAction::from_byte(byte);
            let hits = [
                action.re_request_txs(),
                action.drop_peer(),
                action.our_failure(),
                action.relay(),
                action.request_history(),
            ]
            .into_iter()
            .filter(|h| *h)
            .count();
            assert!(hits <= 1, "byte {byte} hit {hits} predicates");
            if byte == 0 || byte >= 7 {
                assert_eq!(action, BlockAnnounceAction::None);
                assert_eq!(hits, 0);
            }
        }
    }

    #[test]
    fn sync_missing_txs_without_a_severing_drop_continues() {
        let action =
            BlockSyncAction::from_ingest(BlockIngest::MissingTxs, DropVerdict::Unclassified);
        assert!(!action.drop_peer());
        assert!(!action.orphan_resync());
        assert_eq!(action, BlockSyncAction::Continue);
    }

    #[test]
    fn sync_a_severing_drop_still_severs_during_get_objects() {
        let action =
            BlockSyncAction::from_ingest(BlockIngest::MissingTxs, DropVerdict::AttributableForm);
        assert!(action.drop_peer());
        assert!(!action.orphan_resync());
    }

    #[test]
    fn sync_orphan_without_a_drop_is_resync() {
        let action = BlockSyncAction::from_ingest(BlockIngest::Orphaned, DropVerdict::Unclassified);
        assert!(action.orphan_resync());
        assert!(!action.drop_peer());
    }

    #[test]
    fn sync_unknown_bytes_continue() {
        for byte in 4u8..=u8::MAX {
            let action = BlockSyncAction::from_byte(byte);
            assert_eq!(action, BlockSyncAction::Continue);
            assert!(!action.drop_peer());
            assert!(!action.orphan_resync());
        }
    }

    #[test]
    fn announce_from_ingest_covers_every_named_triple() {
        for outcome in OUTCOMES {
            for drop in DROPS {
                for handle_ok in [true, false] {
                    let expected = if outcome.missing_txs() {
                        BlockAnnounceAction::ReRequestMissingTxs
                    } else if drop.severs() {
                        if outcome.is_bad_pow() {
                            BlockAnnounceAction::DropBadPow
                        } else {
                            BlockAnnounceAction::Drop
                        }
                    } else if !handle_ok {
                        BlockAnnounceAction::OurFailure
                    } else if outcome.is_added() {
                        BlockAnnounceAction::Relay
                    } else if outcome.is_orphaned() {
                        BlockAnnounceAction::RequestHistory
                    } else {
                        BlockAnnounceAction::None
                    };
                    assert_eq!(
                        BlockAnnounceAction::from_ingest(outcome, drop, handle_ok),
                        expected,
                        "{outcome:?} {drop:?} handle_ok={handle_ok}"
                    );
                }
            }
        }
    }

    #[test]
    fn sync_from_ingest_covers_every_named_pair() {
        for outcome in OUTCOMES {
            for drop in DROPS {
                let expected = if drop.severs() {
                    if outcome.is_bad_pow() {
                        BlockSyncAction::DropBadPow
                    } else {
                        BlockSyncAction::Drop
                    }
                } else if outcome.is_orphaned() {
                    BlockSyncAction::OrphanResync
                } else {
                    BlockSyncAction::Continue
                };
                assert_eq!(
                    BlockSyncAction::from_ingest(outcome, drop),
                    expected,
                    "{outcome:?} {drop:?}"
                );
            }
        }
    }
}
